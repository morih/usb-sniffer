// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

use anyhow::{bail, Result};
use nusb::transfer::{Buffer, Bulk, ControlIn, ControlOut, ControlType, In, Recipient};
use nusb::{Endpoint, MaybeFuture};
use std::time::Duration;

const CPUCS_ADDR: u16 = 0xe600;
const TIMEOUT: Duration = Duration::from_millis(250);
const CTRL_REG_SIZE: u8 = 4;

/// ベンダー固有コマンド番号
const CMD_FX2LP_REQUEST: u8 = 0xa0;
const CMD_I2C_READ: u8      = 0xb0;
const CMD_I2C_WRITE: u8     = 0xb1;
const CMD_JTAG_ENABLE: u8   = 0xc0;
const CMD_JTAG_REQUEST: u8  = 0xc1;
const CMD_JTAG_RESPONSE: u8 = 0xc2;
const CMD_CTRL: u8          = 0xd0;

/// JTAG 1リクエストに収められる最大クロック数 (wValue フィールドの上限)
pub const MAX_COUNT_IN_JTAG_REQUEST: usize = 255;
/// バルク IN エンドポイントアドレス (キャプチャデータ受信)
pub const DATA_ENDPOINT: u8 = 0x82;
/// USB 2.0 High-Speed バルクエンドポイントの最大パケットサイズ
pub const DATA_ENDPOINT_SIZE: usize = 512;
/// 1回のバルク転送で要求するバイト数。FX2LP の AUTOIN しきい値 (512 バイト) の
/// 倍数にする必要がある (ショートパケットが来ないため、必ず満たすまで完了しない)。
///
/// C版と同じく大きく確保する (1MB)。`nusb` 標準の `submit()` ではこのサイズだと
/// 低トラフィック時に長時間 (実測 1〜2秒以上) 完了が来ないが、ベンダ済みの
/// `vendor/nusb` に追加した `submit_with_timeout()` (IOKit の
/// `ReadPipeAsyncTO`/`WritePipeAsyncTO` を使用) により、`CAPTURE_TIMEOUT` で
/// 確実に部分データを取り出せるようになったため、スループット優先でサイズを
/// 大きくしている。
pub const TRANSFER_SIZE: usize = DATA_ENDPOINT_SIZE * 2000; // 1MB (C版と同じ)
/// `data_transfer_loop` で並行して保持するバルク転送の本数 (C版と同じ)。
const TRANSFER_COUNT: usize = 16;
/// バルク転送1本が完了するまでドライバが待つ最大時間。
///
/// IOKit の `ReadPipeAsyncTO`/`WritePipeAsyncTO` にそのまま渡され、ドライバ
/// 自身がこの時間でタイムアウトを判断する (ソフトウェア側の `AbortPipe` とは
/// 異なり、タイムアウト時も `actual_len` が正しく報告される)。C版の
/// `TRANSFER_TIMEOUT` と同じ値。
const CAPTURE_TIMEOUT: Duration = Duration::from_millis(250);
/// コントロールエンドポイント EP0 の最大パケットサイズ
pub const USB_EP0_SIZE: usize = 64;

/// オープン済みの USB インターフェースを保持する構造体。
///
/// すべての USB 通信はこの構造体のメソッドを通じて行う。
/// nusb は libusb を使わず macOS では IOKit を直接使用する。
pub struct UsbDevice {
    pub interface: nusb::Interface,
}

impl UsbDevice {
    /// 接続済みデバイス一覧を走査して VID/PID が一致する最初のデバイスを開く。
    ///
    /// 見つかった場合は `Some(UsbDevice)`、見つからなかった場合は `None` を返す。
    pub fn open(vid: u16, pid: u16) -> Result<Option<Self>> {
        // nusb の API は async-first で `impl MaybeFuture` を返す。
        // `.wait()` を呼ぶことで内部のエグゼキュータを使わず同期的にブロックする
        // (このツールは終始シングルスレッド・同期 I/O で十分なため)。
        let Some(info) = nusb::list_devices().wait()?.find(|d| {
            d.vendor_id() == vid && d.product_id() == pid
        }) else {
            return Ok(None);
        };
        let device = info.open().wait()?;
        // インターフェース 0 を排他的にクレームする。macOS では内部的に
        // IOKit の USBInterfaceOpen() を呼び、必要ならカーネルドライバの
        // デタッチも自動で行われる。
        let interface = device.claim_interface(0).wait()?;
        Ok(Some(UsbDevice { interface }))
    }

    /// ベンダーコントロール OUT 転送の共通ヘルパー。
    ///
    /// FX2LP ファームウェアのベンダーリクエストはすべて
    /// `bmRequestType = Vendor | Device` で統一されているため、ここに集約する。
    fn ctrl_out(&self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        self.interface.control_out(
            ControlOut { control_type: ControlType::Vendor, recipient: Recipient::Device,
                         request, value, index, data },
            TIMEOUT,
        ).wait().map_err(|e| anyhow::anyhow!(e))?; // .wait() で同期実行し、TransferError を anyhow に変換
        Ok(())
    }

    /// ベンダーコントロール IN 転送の共通ヘルパー。
    fn ctrl_in(&self, request: u8, value: u16, index: u16, buf: &mut [u8]) -> Result<()> {
        // nusb 0.2 の control_in() は呼び出し側のバッファではなく Vec<u8> を返す
        // 設計のため、呼び出し元の &mut [u8] にコピーして API の互換性を保つ。
        let data = self.interface.control_in(
            ControlIn { control_type: ControlType::Vendor, recipient: Recipient::Device,
                        request, value, index, length: buf.len() as u16 },
            TIMEOUT,
        ).wait().map_err(|e| anyhow::anyhow!(e))?;
        buf[..data.len()].copy_from_slice(&data);
        Ok(())
    }

    /// FX2LP マイコンをリセット状態にするかリセット解除する。
    ///
    /// `reset = true` で CPU が停止し、`false` で動作を再開する。
    /// CPUCS レジスタ (0xe600) への書き込みで制御する。
    pub fn fx2lp_reset(&self, reset: bool) -> Result<()> {
        self.ctrl_out(CMD_FX2LP_REQUEST, CPUCS_ADDR, 0, &[reset as u8])
    }

    /// FX2LP 内蔵 SRAM の指定アドレスからデータを読み出す。
    pub fn fx2lp_sram_read(&self, addr: u16, data: &mut [u8]) -> Result<()> {
        self.ctrl_in(CMD_FX2LP_REQUEST, addr, 0, data)
    }

    /// FX2LP 内蔵 SRAM の指定アドレスにデータを書き込む。
    pub fn fx2lp_sram_write(&self, addr: u16, data: &[u8]) -> Result<()> {
        self.ctrl_out(CMD_FX2LP_REQUEST, addr, 0, data)
    }

    /// FX2LP 経由で I2C バスに接続された EEPROM からデータを読み出す。
    ///
    /// `addr` は I2C デバイスアドレス (7ビット)。
    /// ファームウェアの規約に従い wValue に `addr | 1` (Read ビット) を渡す。
    pub fn i2c_read(&self, addr: u16, data: &mut [u8]) -> Result<()> {
        self.ctrl_in(CMD_I2C_READ, addr | 1, 0, data)
    }

    /// FX2LP 経由で I2C バスに接続された EEPROM へデータを書き込む。
    pub fn i2c_write(&self, addr: u16, data: &[u8]) -> Result<()> {
        self.ctrl_out(CMD_I2C_WRITE, addr, 0, data)
    }

    /// FX2LP の JTAG ブリッジ機能を有効/無効にする。
    ///
    /// `enable = true` で JTAG ピンが GPIO から JTAG モードに切り替わる。
    pub fn jtag_enable(&self, enable: bool) -> Result<()> {
        self.ctrl_out(CMD_JTAG_ENABLE, enable as u16, 0, &[])
    }

    /// JTAG クロックシーケンスをまとめてファームウェアに送信する。
    ///
    /// `data[i]` は 1クロック分の `(tdi << 1) | tms` 形式。
    /// 4クロック分を 1バイトに 2ビットずつパックしてコントロール転送で送る。
    pub fn jtag_request(&self, data: &[u8], count: usize) -> Result<()> {
        assert!(0 < count && count <= MAX_COUNT_IN_JTAG_REQUEST);
        let mut buf = [0u8; 64];
        // 4クロック/バイトに 2ビットずつパック (TMS=bit0, TDI=bit1)
        for i in 0..count {
            buf[i / 4] |= data[i] << ((i % 4) * 2);
        }
        // wValue にクロック数、データに packed bits を載せて送信
        self.ctrl_out(CMD_JTAG_REQUEST, count as u16, 0, &buf[..(count + 3) / 4])
    }

    /// 直前の JTAG リクエストに対する TDO 応答を読み出す。
    ///
    /// ファームウェアは 4サンプル/バイトの下位ニブル形式で返すので、
    /// ここで 1ビット/サンプルに展開して `data` に格納する。
    pub fn jtag_response(&self, data: &mut [u8], count: usize) -> Result<()> {
        assert!(count <= MAX_COUNT_IN_JTAG_REQUEST);
        let n = (count + 3) / 4;
        let mut buf = [0u8; 64];
        // ファームウェアから packed TDO データを受信
        self.ctrl_in(CMD_JTAG_RESPONSE, 0, 0, &mut buf[..n])?;
        let out_len = (count + 7) / 8;
        data[..out_len].fill(0);
        // 下位ニブルを 1ビット/サンプルに展開
        for i in 0..n {
            data[i / 2] |= (buf[i] & 0x0f) << ((i % 2) * 4);
        }
        Ok(())
    }

    /// FPGA キャプチャロジックの制御レジスタ 1ビットを設定する。
    ///
    /// `index` はビット番号 (`CaptureCtrl::*`)、`value` は設定値。
    /// wValue に `index | (value << CTRL_REG_SIZE)` を詰めて送る。
    pub fn ctrl(&self, index: u8, value: bool) -> Result<()> {
        let v = index as u16 | ((value as u16) << CTRL_REG_SIZE);
        self.ctrl_out(CMD_CTRL, v, 0, &[])
    }

    /// データエンドポイントの `Endpoint` ハンドルを開く。
    ///
    /// nusb 0.2 ではエンドポイント種別 (Bulk/Interrupt) と方向 (In/Out) を
    /// 型パラメータとして指定する。実際のディスクリプタと不一致なら `Err` になる
    /// ため、ここで `DATA_ENDPOINT` (0x82 = EP2 IN) が本当にバルクINかが検証される。
    fn data_endpoint(&self) -> Result<Endpoint<Bulk, In>> {
        Ok(self.interface.endpoint::<Bulk, In>(DATA_ENDPOINT)?)
    }

    /// データエンドポイントに残っている受信済みデータを捨てる。
    ///
    /// キャプチャ開始前に古いデータが残っていないことを保証するために使う。
    /// タイムアウトになったら残りデータなしとみなして終了する。
    pub fn flush_data(&self) -> Result<()> {
        const FLUSH_TIMEOUT: Duration = Duration::from_millis(20);
        let mut ep = self.data_endpoint()?;
        for _ in 0..100 {
            // transfer_blocking() は1回分の submit + wait_next_complete をまとめた
            // 便利関数。タイムアウトすると内部で cancel_all() してから完了を
            // 待ち直すため、呼び出し側は「結果として pending が残らない」ことが
            // 保証される。タイムアウト時は status が TransferError::Cancelled になる。
            let completion = ep.transfer_blocking(Buffer::new(DATA_ENDPOINT_SIZE), FLUSH_TIMEOUT);
            if completion.status.is_err() {
                break; // タイムアウトまたはエラー → これ以上溜まったデータはない
            }
        }
        Ok(())
    }

    /// キャプチャロジックを既知の初期状態にリセットする。
    ///
    /// リセット → 無効化 → テスト無効化の後、Speed0/Speed1 をパルスして
    /// スピードレジスタをクリアする。
    pub fn ctrl_init(&self) -> Result<()> {
        use crate::capture::CaptureCtrl;
        self.ctrl(CaptureCtrl::RESET, true)?;
        self.ctrl(CaptureCtrl::ENABLE, false)?;
        self.ctrl(CaptureCtrl::TEST, false)?;
        // Speed ビットをトグルしてレジスタ値を確定させる
        self.ctrl(CaptureCtrl::SPEED0, true)?;
        self.ctrl(CaptureCtrl::SPEED0, false)?;
        self.ctrl(CaptureCtrl::SPEED1, true)?;
        self.ctrl(CaptureCtrl::SPEED1, false)?;
        Ok(())
    }

    /// データエンドポイントから `TRANSFER_COUNT` 本のバルク転送を並行実行し、
    /// 受信データを `on_data` コールバックに渡し続ける無限ループ。
    ///
    /// `submit_with_timeout` (vendor 済みの nusb に追加した、IOKit
    /// `ReadPipeAsyncTO`/`WritePipeAsyncTO` を使うメソッド) により、各転送は
    /// TRANSFER_SIZE バイト分のデータが自然に蓄積されるか、`CAPTURE_TIMEOUT`
    /// が経過するかのいずれか早い方で完了する。タイムアウト時もドライバが
    /// `actual_len` を正しく報告するため、低トラフィック時でも最大
    /// `CAPTURE_TIMEOUT` の遅延でデータが届く。
    pub fn data_transfer_loop(&self, mut on_data: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut ep = self.data_endpoint()?;

        // TRANSFER_COUNT 本の転送をあらかじめキューに積んでおく (パイプライン化)。
        // どれかが完了する間も残りは並行して進行するので、ホスト側の処理が
        // 完了通知を取りに行くまでの間も USB バス側は転送を続けられる。
        for _ in 0..TRANSFER_COUNT {
            ep.submit_with_timeout(Buffer::new(TRANSFER_SIZE), CAPTURE_TIMEOUT, CAPTURE_TIMEOUT);
        }

        loop {
            // 各転送に IOKit ネイティブのタイムアウトが設定済みなので、
            // ここでの待ち自体には上限を設ける必要がない。
            let completion = ep.wait_next_complete(Duration::MAX)
                .expect("wait_next_complete should not time out with Duration::MAX");

            match completion.status {
                Ok(()) => {}
                // CAPTURE_TIMEOUT による部分完了。actual_len 分のデータは
                // ドライバが正しく報告するので、エラーとしては扱わず
                // そのまま処理する (AbortPipe によるキャンセルとは違い
                // データが失われない)。
                Err(nusb::transfer::TransferError::Cancelled) => {}
                Err(e) => bail!("USB bulk transfer error: {e}"),
            }
            if !completion.buffer.is_empty() {
                on_data(&completion.buffer)?;
            }

            // 消費したスロットを即座に同サイズで再サブミットし、
            // 常に TRANSFER_COUNT 本のパイプラインを維持する。
            ep.submit_with_timeout(Buffer::new(TRANSFER_SIZE), CAPTURE_TIMEOUT, CAPTURE_TIMEOUT);
        }
    }

    /// FPGA が生成するテストパターンを受信して転送速度を計測する。
    ///
    /// テストモードでは FPGA がカウンターベースの疑似乱数列を送出し、
    /// ホスト側で同じ PRNG で期待値を生成して一致を確認する。
    pub fn speed_test(&self) -> Result<()> {
        self.ctrl_init()?;
        self.ctrl(crate::capture::CaptureCtrl::RESET, true)?;
        self.ctrl(crate::capture::CaptureCtrl::TEST, true)?; // テストパターン生成を有効化
        self.flush_data()?;
        self.ctrl(crate::capture::CaptureCtrl::RESET, false)?; // キャプチャロジックを動作開始

        let mut state = SpeedTestState::new();
        self.data_transfer_loop(move |data| {
            state.process(data);
            Ok(())
        })
    }
}

/// 転送速度測定の状態を保持する構造体。
struct SpeedTestState {
    start: std::time::Instant,
    bytes: usize,
    count: u64,
    rand: u16,
}

impl SpeedTestState {
    fn new() -> Self {
        SpeedTestState {
            start: std::time::Instant::now(),
            bytes: 0,
            count: 0,
            rand: 0,
        }
    }

    /// 受信データを PRNG 期待値と照合し、1秒ごとに転送速度を表示する。
    fn process(&mut self, data: &[u8]) {
        let words: &[u16] = bytemuck_cast_slice(data);
        for &word in words {
            let expected = rand16(&mut self.rand);
            assert!(word == expected, "data error during speed test at count {}", self.count);
            self.count += 1;
        }
        self.bytes += data.len();

        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            let speed = self.bytes as f64 / elapsed / 1_000_000.0;
            println!("Transfer rate: {:5.2} MB/s", speed);
            self.bytes = 0;
            self.start = std::time::Instant::now();
        }
    }
}

/// `&[u8]` を `&[u16]` として再解釈する。
///
/// 奇数バイト長の場合、末尾 1バイトは切り捨てる。
fn bytemuck_cast_slice(data: &[u8]) -> &[u16] {
    let len = data.len() / 2;
    let ptr = data.as_ptr() as *const u16;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// 16ビット Xorshift 疑似乱数生成器。
///
/// FPGA 側の実装と同一のアルゴリズムで、テストパターンの期待値を生成する。
/// `state = 0` のとき初期シードとして `0x6c41` を使用する。
fn rand16(state: &mut u16) -> u16 {
    if *state == 0 {
        *state = 0x6c41;
    }
    *state ^= *state << 7;
    *state ^= *state >> 9;
    *state ^= *state << 8;
    *state
}
