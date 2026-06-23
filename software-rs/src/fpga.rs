// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

use anyhow::{bail, Result};

use crate::usb::{UsbDevice, MAX_COUNT_IN_JTAG_REQUEST};

/// LCMXO2-2000HC の JTAG IDCODE (デバイス識別に使用)
const LCMXO2_2000HC_IDCODE: u32 = 0x012bb043;
/// BIT/JED ファイルの先頭付近に必ず存在するデバイス識別文字列
const BITSTREAM_SIGNATURE: &[u8] = b"LCMXO2-2000HC";
/// JED コンフィグデータの最大サイズ (512 KB)
const MAX_CONFIG_SIZE: usize = 512 * 1024;

/// LCMXO2 JTAG 命令コード (MachXO2 ファミリプログラミングガイドに基づく)
#[allow(dead_code)]
enum Cmd {
    IdcodePub           = 0xe0, // デバイス IDCODE 読み出し
    IscEnableX          = 0x74,
    IscEnable           = 0xc6, // ISC (In-System Configuration) モード開始
    LscCheckBusy        = 0xf0, // 内部処理のビジーフラグ確認
    LscReadStatus       = 0x3c, // ステータスレジスタ読み出し
    IscErase            = 0x0e, // 消去コマンド
    LscEraseTag         = 0xcb,
    LscInitAddress      = 0x46, // アドレスポインタを先頭に初期化
    LscWriteAddress     = 0xb4,
    LscProgIncrNv       = 0x70, // フラッシュに 1 行書き込んでアドレスをインクリメント
    LscInitAddrUfm      = 0x47,
    LscProgTag          = 0xc9,
    IscProgramUsercode  = 0xc2,
    Usercode            = 0xc0,
    LscProgFeature      = 0xe4, // Feature Row 書き込み
    LscReadFeature      = 0xe7, // Feature Row 読み出し (ベリファイ用)
    LscProgFeabits      = 0xf8, // FEABITS 書き込み
    LscReadFeabits      = 0xfb, // FEABITS 読み出し (ベリファイ用)
    LscReadIncrNv       = 0x73, // フラッシュを 1 行読み出してアドレスをインクリメント
    LscReadUfm          = 0xca,
    IscProgramDone      = 0x5e, // プログラミング完了フラグを書く
    LscProgOtp          = 0xf9,
    LscReadOtp          = 0xfa,
    IscDisable          = 0x26, // ISC モード終了
    IscNoop             = 0xff, // NOP (ウェイトやステートマシンのリセットに使用)
    LscRefresh          = 0x79, // 書き込んだコンフィグをリフレッシュ (再ロード)
    IscProgramSecurity  = 0xce,
    IscProgramSecplus   = 0xcf,
    UidcodePub          = 0x19, // デバイス固有の 64ビット Trace ID 読み出し
    LscBitstreamBurst   = 0x7a, // SRAM バースト書き込みモード開始
}

const ISC_ENABLE_SRAM: u8  = 0x00; // ISC_ENABLE の対象: SRAM
const ISC_ENABLE_FLASH: u8 = 0x08; // ISC_ENABLE の対象: フラッシュ

const ISC_ERASE_SRAM: u8    = 1 << 0;
const ISC_ERASE_FEATURE: u8 = 1 << 1;
const ISC_ERASE_CFG: u8     = 1 << 2;
const ISC_ERASE_UFM: u8     = 1 << 3;
/// フラッシュの全不揮発領域を消去するマスク (SRAM は含まない)
const ISC_ERASE_ALL_NV: u8  = ISC_ERASE_FEATURE | ISC_ERASE_CFG | ISC_ERASE_UFM;

const STATUS_BUSY: u32 = 1 << 12; // ステータスレジスタのビジービット
const STATUS_FAIL: u32 = 1 << 13; // ステータスレジスタのエラービット

/// フラッシュ 1 行のサイズ (ビット単位)
const FLASH_ROW_SIZE: usize = 128;

/// JTAG クロックシーケンスをバッファリングして FX2LP に一括送信する。
///
/// `MAX_COUNT_IN_JTAG_REQUEST` に達したら自動的に `sync` を呼んで送信する。
struct JtagState {
    buf: [u8; MAX_COUNT_IN_JTAG_REQUEST],
    count: usize,
}

impl JtagState {
    /// 空のバッファを持つ `JtagState` を生成する。
    fn new() -> Self {
        JtagState { buf: [0u8; MAX_COUNT_IN_JTAG_REQUEST], count: 0 }
    }

    /// 1クロック分の TDI/TMS を内部バッファに積む。
    /// バッファが満杯になったら自動フラッシュする。
    fn clk(&mut self, device: &UsbDevice, tdi: u8, tms: u8) -> Result<()> {
        self.buf[self.count] = (tdi << 1) | tms;
        self.count += 1;
        if self.count == MAX_COUNT_IN_JTAG_REQUEST {
            // バッファが上限に達したのでまとめて送信する
            self.sync(device)?;
        }
        Ok(())
    }

    /// バッファに溜まったクロックシーケンスを USB コントロール転送で送信する。
    fn sync(&mut self, device: &UsbDevice) -> Result<()> {
        if self.count > 0 {
            device.jtag_request(&self.buf, self.count)?;
            self.count = 0;
        }
        Ok(())
    }

    /// JTAG TAP ステートマシンを Test-Logic-Reset へ強制リセットする。
    ///
    /// TMS=1 を 16 クロック送れば任意の状態からリセットできる。
    fn reset(&mut self, device: &UsbDevice) -> Result<()> {
        for _ in 0..16 {
            self.clk(device, 0, 1)?; // TMS=1 でリセット方向へ遷移
        }
        self.clk(device, 0, 0)?; // Run-Test/Idle へ移行
        Ok(())
    }

    /// 命令レジスタ (IR) に 8ビットの命令を書き込む。
    ///
    /// Select-DR → Select-IR → Capture-IR → Shift-IR → Exit1-IR → Update-IR
    /// のステートシーケンスで IR をシフトする。
    fn write_ir(&mut self, device: &UsbDevice, ir: u8) -> Result<()> {
        self.clk(device, 0, 1)?; // Select-DR-Scan
        self.clk(device, 0, 1)?; // Select-IR-Scan
        self.clk(device, 0, 0)?; // Capture-IR
        self.clk(device, 0, 0)?; // Shift-IR
        for i in 0..8u8 {
            // LSB ファースト: 最後のビットで TMS=1 にして Exit1-IR へ
            self.clk(device, (ir >> i) & 1, if i == 7 { 1 } else { 0 })?;
        }
        self.clk(device, 0, 1)?; // Update-IR
        self.clk(device, 0, 0)?; // Run-Test/Idle
        Ok(())
    }

    /// データレジスタ (DR) に `size` ビット書き込む。
    ///
    /// Select-DR → Capture-DR → Shift-DR → Exit1-DR → Update-DR のシーケンス。
    fn write_dr(&mut self, device: &UsbDevice, data: &[u8], size: usize) -> Result<()> {
        self.clk(device, 0, 1)?; // Select-DR-Scan
        self.clk(device, 0, 0)?; // Capture-DR
        self.clk(device, 0, 0)?; // Shift-DR
        for i in 0..size {
            let last = if i == size - 1 { 1 } else { 0 };
            // LSB ファースト: 最後のビットで TMS=1 にして Exit1-DR へ
            self.clk(device, (data[i / 8] >> (i % 8)) & 1, last)?;
        }
        self.clk(device, 0, 1)?; // Update-DR
        self.clk(device, 0, 0)?; // Run-Test/Idle
        Ok(())
    }

    /// データレジスタ (DR) から `size` ビット読み出す。
    ///
    /// TDO サンプリングのためクロックを送る前後で sync を呼び、
    /// ファームウェアから TDO 応答を受け取る。
    fn read_dr(&mut self, device: &UsbDevice, data: &mut [u8], size: usize) -> Result<()> {
        self.clk(device, 0, 1)?; // Select-DR-Scan
        self.clk(device, 0, 0)?; // Capture-DR
        self.clk(device, 0, 0)?; // Shift-DR
        // ここまでの pending クロックを先に送ってから TDO サンプリング開始
        self.sync(device)?;
        for i in 0..size {
            let last = if i == size - 1 { 1 } else { 0 };
            self.clk(device, 0, last)?; // TDO をサンプリングしながらクロック
        }
        // サンプリングクロックを送信してから TDO データを受信
        self.sync(device)?;
        device.jtag_response(data, size)?;
        self.clk(device, 0, 1)?; // Update-DR
        self.clk(device, 0, 0)?; // Run-Test/Idle
        Ok(())
    }

    /// Run-Test/Idle で `count` クロック空打ちする (内部処理のウェイトに使用)。
    fn run(&mut self, device: &UsbDevice, count: usize) -> Result<()> {
        for _ in 0..count {
            self.clk(device, 0, 0)?; // TMS=0 で Run-Test/Idle に留まる
        }
        Ok(())
    }
}

/// JTAG を使った FPGA アクセスを開始する。
///
/// FX2LP の JTAG ブリッジを有効化してタップをリセットし、
/// IDCODE を読んでデバイスが期待通りか確認する。
pub fn enable(device: &UsbDevice) -> Result<()> {
    let mut jtag = JtagState::new();
    // FX2LP の GPIO を JTAG モードに切り替える
    device.jtag_enable(true)?;
    jtag.reset(device)?;
    jtag.sync(device)?;

    let idcode = read_idcode_with(device, &mut jtag)?;
    if idcode != LCMXO2_2000HC_IDCODE {
        bail!("incorrect FPGA IDCODE ({:#010x})", idcode);
    }
    Ok(())
}

/// JTAG アクセスを終了して FX2LP の JTAG ブリッジを無効化する。
pub fn disable(device: &UsbDevice) -> Result<()> {
    let mut jtag = JtagState::new();
    jtag.reset(device)?;
    jtag.sync(device)?;
    // FX2LP の GPIO を通常モードに戻す
    device.jtag_enable(false)?;
    Ok(())
}

/// FPGA デバイス固有の 64ビット Trace ID を読み出す。
///
/// EEPROM へのシリアルナンバー埋め込みで使用する。
pub fn read_traceid(device: &UsbDevice) -> Result<u64> {
    let mut jtag = JtagState::new();
    let mut bytes = [0u8; 8];
    jtag.write_ir(device, Cmd::UidcodePub as u8)?;
    jtag.read_dr(device, &mut bytes, 64)?;
    Ok(u64::from_le_bytes(bytes))
}

/// IDCODE を読み出す内部ヘルパー (既存の `JtagState` を再利用する)。
fn read_idcode_with(device: &UsbDevice, jtag: &mut JtagState) -> Result<u32> {
    let mut bytes = [0u8; 4];
    jtag.write_ir(device, Cmd::IdcodePub as u8)?;
    jtag.read_dr(device, &mut bytes, 32)?;
    // pending クロックをフラッシュしてから値を確定させる
    jtag.sync(device)?;
    Ok(u32::from_le_bytes(bytes))
}

/// BIT ファイルを FPGA の SRAM にロードして即起動する (電源断で消える)。
///
/// SRAM を消去してからバースト転送モードでビットストリームを流し込む。
pub fn program_sram(device: &UsbDevice, data: &[u8]) -> Result<()> {
    if !bitstream_valid(data) {
        bail!("malformed BIT file: device signature not found");
    }

    let mut jtag = JtagState::new();

    // SRAM を対象に ISC モードを開始
    jtag.write_ir(device, Cmd::IscEnable as u8)?;
    jtag.write_dr(device, &[ISC_ENABLE_SRAM], 8)?;
    jtag.run(device, 8)?; // 処理ウェイト

    // 既存の SRAM コンフィグを消去
    jtag.write_ir(device, Cmd::IscErase as u8)?;
    jtag.write_dr(device, &[ISC_ERASE_SRAM], 8)?;
    jtag.run(device, 8)?;

    // バースト書き込みモードに入る
    jtag.write_ir(device, Cmd::LscBitstreamBurst as u8)?;
    jtag.run(device, 8)?;

    // DR-Shift 状態に遷移してビットストリームを MSB ファーストで流し込む
    jtag.clk(device, 0, 1)?; // Select-DR-Scan
    jtag.clk(device, 0, 0)?; // Capture-DR
    jtag.clk(device, 0, 0)?; // Shift-DR
    let size = data.len();
    for i in 0..size {
        for j in (0..8usize).rev() {
            let last = if i == size - 1 && j == 0 { 1 } else { 0 };
            jtag.clk(device, (data[i] >> j) & 1, last)?;
        }
    }
    jtag.clk(device, 0, 1)?; // Update-DR
    jtag.clk(device, 0, 0)?; // Run-Test/Idle
    jtag.run(device, 100)?;  // ロード完了ウェイト

    // ISC モード終了
    jtag.write_ir(device, Cmd::IscDisable as u8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscNoop as u8)?;
    jtag.run(device, 100)?;
    jtag.sync(device)?; // 残りの pending クロックを全て送信
    Ok(())
}

/// FPGA フラッシュの全不揮発領域を消去する。
///
/// SRAM を消去してから Feature/CFG/UFM の各不揮発メモリを消去する。
pub fn erase_flash(device: &UsbDevice) -> Result<()> {
    let mut jtag = JtagState::new();
    erase_flash_with(&mut jtag, device)
}

/// JED ファイルを FPGA フラッシュに書き込む。
///
/// JED ファイルを解析してコンフィグデータ・Feature Row・FEABITS を取り出し、
/// フラッシュを消去してから各領域に書き込み、全て読み返して検証する。
pub fn program_flash(device: &UsbDevice, data: &[u8]) -> Result<()> {
    let mut jtag = JtagState::new();
    let mut config = vec![0u8; MAX_CONFIG_SIZE];
    let mut feabits = 0u16;
    let mut feature = 0u64;

    let config_bits = parse_jed_file(data, &mut config, &mut feabits, &mut feature)?;
    let row_count = config_bits / FLASH_ROW_SIZE;

    println!("Erasing flash");
    erase_flash_with(&mut jtag, device)?;

    // コンフィグデータを 1 行 (128bit = 16 バイト) ずつ書き込む
    println!("Programming configuration data ");
    jtag.write_ir(device, Cmd::LscInitAddress as u8)?; // アドレスポインタをリセット
    jtag.run(device, 8)?;

    for row in 0..row_count {
        jtag.write_ir(device, Cmd::LscProgIncrNv as u8)?; // 1 行書いてアドレス+1
        jtag.write_dr(device, &config[row * 16..], FLASH_ROW_SIZE)?;
        jtag.run(device, 1000)?; // 内部書き込みサイクル完了ウェイト
        poll_busy(&mut jtag, device)?;

        if row % 256 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
    }
    println!();

    // 書き込んだコンフィグデータを読み返してベリファイ
    println!("Verifying configuration data");
    jtag.write_ir(device, Cmd::LscInitAddress as u8)?;
    jtag.run(device, 8)?;
    jtag.write_ir(device, Cmd::LscReadIncrNv as u8)?; // 1 行読んでアドレス+1
    jtag.run(device, 8)?;

    for row in 0..row_count {
        let mut tmp = [0u8; 16];
        jtag.read_dr(device, &mut tmp, FLASH_ROW_SIZE)?;
        jtag.run(device, 8)?;
        if tmp != config[row * 16..row * 16 + 16] {
            bail!("configuration verification failed");
        }
    }

    // Feature Row (デバイス設定の 64ビット) を書き込んでベリファイ
    println!("Programming and verifying Feature Row");
    jtag.write_ir(device, Cmd::LscInitAddress as u8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::LscProgFeature as u8)?;
    jtag.write_dr(device, &feature.to_le_bytes(), 64)?;
    jtag.run(device, 8)?;
    poll_busy(&mut jtag, device)?;

    let mut feature_verify_bytes = [0u8; 8];
    jtag.write_ir(device, Cmd::LscReadFeature as u8)?;
    jtag.read_dr(device, &mut feature_verify_bytes, 64)?;
    jtag.run(device, 8)?;
    if u64::from_le_bytes(feature_verify_bytes) != feature {
        bail!("Feature Row verification failed");
    }

    // FEABITS (Feature ビット設定の 16ビット) を書き込んでベリファイ
    println!("Programming and verifying FEABITS");
    jtag.write_ir(device, Cmd::LscProgFeabits as u8)?;
    jtag.write_dr(device, &feabits.to_le_bytes(), 16)?;
    jtag.run(device, 8)?;
    poll_busy(&mut jtag, device)?;

    let mut feabits_verify_bytes = [0u8; 2];
    jtag.write_ir(device, Cmd::LscReadFeabits as u8)?;
    jtag.run(device, 8)?;
    jtag.read_dr(device, &mut feabits_verify_bytes, 16)?;
    if u16::from_le_bytes(feabits_verify_bytes) != feabits {
        bail!("FEABITS verification failed");
    }

    // プログラミング完了を FPGA に通知してユーザーモードへ移行
    println!("Exiting programming mode");
    jtag.write_ir(device, Cmd::IscProgramDone as u8)?;
    jtag.run(device, 1000)?;
    poll_busy(&mut jtag, device)?;

    jtag.write_ir(device, Cmd::IscDisable as u8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscNoop as u8)?;
    jtag.run(device, 100)?;

    // フラッシュの内容を SRAM に再ロードして動作開始
    jtag.write_ir(device, Cmd::LscRefresh as u8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscNoop as u8)?;
    jtag.run(device, 100)?;
    jtag.sync(device)?; // 残りの pending クロックを全て送信
    Ok(())
}

/// `program_flash` と `erase_flash` で共通する消去シーケンスの実装。
///
/// 既存の `JtagState` を受け取ることで、`program_flash` の途中で
/// 追加の JTAG トランザクションを挟まずに呼べるようにしている。
fn erase_flash_with(jtag: &mut JtagState, device: &UsbDevice) -> Result<()> {
    // SRAM 消去
    jtag.write_ir(device, Cmd::IscEnable as u8)?;
    jtag.write_dr(device, &[ISC_ENABLE_SRAM], 8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscErase as u8)?;
    jtag.write_dr(device, &[ISC_ERASE_SRAM], 8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscNoop as u8)?;

    // 不揮発フラッシュ (CFG/Feature/UFM) 消去
    jtag.write_ir(device, Cmd::IscEnable as u8)?;
    jtag.write_dr(device, &[ISC_ENABLE_FLASH], 8)?;
    jtag.run(device, 8)?;

    jtag.write_ir(device, Cmd::IscErase as u8)?;
    jtag.write_dr(device, &[ISC_ERASE_ALL_NV], 8)?;
    jtag.run(device, 8)?;

    // 消去完了までビジービットをポーリング
    poll_busy(jtag, device)?;
    Ok(())
}

/// フラッシュ書き込み・消去が完了するまでビジービットをポーリングする。
///
/// `LscCheckBusy` でビジービットが落ちたら `LscReadStatus` でエラー確認する。
fn poll_busy(jtag: &mut JtagState, device: &UsbDevice) -> Result<()> {
    loop {
        let mut busy = [1u8];
        jtag.write_ir(device, Cmd::LscCheckBusy as u8)?;
        jtag.read_dr(device, &mut busy, 1)?; // ビジービット 1ビットを読む
        if busy[0] == 0 {
            break; // ビジービット解除 = 処理完了
        }
    }

    // 完了後にステータスレジスタを読んでエラービットを確認する
    let mut status_bytes = [0u8; 4];
    jtag.write_ir(device, Cmd::LscReadStatus as u8)?;
    jtag.read_dr(device, &mut status_bytes, 32)?;
    jtag.run(device, 8)?;

    let status = u32::from_le_bytes(status_bytes);
    if status & STATUS_BUSY != 0 {
        bail!("poll_busy_flag: busy");
    }
    if status & STATUS_FAIL != 0 {
        bail!("poll_busy_flag: fail");
    }
    Ok(())
}

/// BIT/JED ファイルの先頭 1024 バイトにデバイス識別文字列があるか確認する。
fn bitstream_valid(data: &[u8]) -> bool {
    if data.len() < 1024 {
        return false;
    }
    find_bytes(&data[..1024], BITSTREAM_SIGNATURE).is_some()
}

/// JED ファイルを解析してコンフィグビット・Feature Row・FEABITS を取り出す。
///
/// 「L000000」マーカー以降の '0'/'1' 文字列をコンフィグデータに変換し、
/// 「NOTE FEATURE_ROW*」マーカー以降の 80ビット (64bit feature + 16bit feabits) を解析する。
/// 戻り値はコンフィグデータのビット数。
fn parse_jed_file(
    data: &[u8],
    config: &mut Vec<u8>,
    feabits: &mut u16,
    feature: &mut u64,
) -> Result<usize> {
    if !bitstream_valid(data) {
        bail!("malformed JED file: device signature not found");
    }

    let start_text = b"L000000";     // コンフィグデータの開始マーカー
    let fr_text = b"NOTE FEATURE_ROW*"; // Feature Row の開始マーカー

    let start_pos = find_bytes(data, start_text)
        .ok_or_else(|| anyhow::anyhow!("malformed JED file: no 'L000000' found"))?;

    let mut offset = start_pos + start_text.len();
    let mut bit_count = 0usize;

    config.fill(0);

    // '0'/'1' を LSB ファーストでバイト配列に詰める
    while offset < data.len() {
        match data[offset] {
            b'*' => break, // フィールド終端
            b'0' | b'1' => {
                let bit = data[offset] - b'0';
                config[bit_count / 8] |= bit << (bit_count % 8);
                bit_count += 1;
                if bit_count >= MAX_CONFIG_SIZE * 8 {
                    bail!("malformed JED file: configuration data is too big");
                }
            }
            _ => {} // 空白・改行などは無視
        }
        offset += 1;
    }

    if offset == data.len() {
        bail!("malformed JED file: no field terminator found");
    }
    if bit_count % FLASH_ROW_SIZE != 0 {
        bail!("malformed JED file: size of configuration data must be a multiple of 128");
    }

    let fr_pos = find_bytes(data, fr_text)
        .ok_or_else(|| anyhow::anyhow!("malformed JED file: no feature row found"))?;

    offset = fr_pos + fr_text.len();
    *feature = 0;
    *feabits = 0;
    let mut fr_bit_count = 0usize;

    // 先頭 64ビットが feature、続く 16ビットが feabits
    while offset < data.len() {
        match data[offset] {
            b'*' => break,
            b'0' | b'1' => {
                let bit = (data[offset] - b'0') as u64;
                if fr_bit_count >= 64 + 16 {
                    bail!("malformed JED file: feature row data is too big");
                }
                if fr_bit_count < 64 {
                    *feature |= bit << fr_bit_count;
                } else {
                    *feabits |= (bit as u16) << (fr_bit_count - 64);
                }
                fr_bit_count += 1;
            }
            _ => {}
        }
        offset += 1;
    }

    if offset == data.len() {
        bail!("malformed JED file: no field terminator found");
    }
    if fr_bit_count != 64 + 16 {
        bail!("malformed JED file: invalid feature row size");
    }

    Ok(bit_count)
}

/// バイトスライスの中から `needle` が最初に現れる位置を返す。
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
