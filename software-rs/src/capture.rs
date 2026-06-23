// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

use anyhow::Result;
use std::io::{BufWriter, Write};

use crate::usb::UsbDevice;

/// タイムスタンプ単位: 1 マイクロ秒 (ナノ秒スケール)
const TIME_US: u64 = 1_000;
/// タイムスタンプ単位: 1 ミリ秒 (ナノ秒スケール)
const TIME_MS: u64 = 1_000 * TIME_US;

/// pcapng リンクタイプ: USB 2.0 汎用
const LINKTYPE_USB_2_0: u16            = 288;
/// pcapng リンクタイプ: USB 2.0 Low-Speed
const LINKTYPE_USB_2_0_LOW_SPEED: u16  = 293;
/// pcapng リンクタイプ: USB 2.0 Full-Speed
const LINKTYPE_USB_2_0_FULL_SPEED: u16 = 294;
/// pcapng リンクタイプ: USB 2.0 High-Speed
const LINKTYPE_USB_2_0_HIGH_SPEED: u16 = 295;
/// pcapng リンクタイプ: Wireshark Upper PDU (テキスト情報用)
const LINKTYPE_WIRESHARK_UPPER_PDU: u16 = 252;

/// Wireshark extcap インターフェース識別子
const INTERFACE_NAME: &str = "usb_sniffer";

/// 2 秒間パケットがなければ定期更新メッセージを出力する間隔
const UPDATE_INTERVAL: u64 = 2000 * TIME_MS;

/// データフレームのヘッダバイト数 (固定長プレフィックス)
const DATA_HEADER_SIZE: usize   = 7;
/// ステータスフレームのヘッダバイト数
const STATUS_HEADER_SIZE: usize = 4;
/// フレームバッファ最大サイズ
const DATA_BUF_SIZE: usize      = 2048;
/// フォールドバッファの最大エントリ数
const FOLD_BUF_SIZE: usize      = 256;
/// 1 フレームの最大データサイズ
const MAX_DATA_SIZE: usize      = 1280;

// Byte 0 header bits
/// Byte 0 bit 7: ステータスフレーム識別ビット (0 = status)
const HEADER_STATUS:      u8 = 0x80;
/// Byte 0 bit 6: トグルビット (交互に 0/1 で同期チェック)
const HEADER_TOGGLE:      u8 = 0x40;
/// Byte 0 bit 5: ゼロビット (常に 0; 非零なら同期エラー)
const HEADER_ZERO:        u8 = 0x20;
/// Byte 0 bit 4: タイムスタンプ上位桁のオーバーフロービット
const HEADER_TS_OVERFLOW: u8 = 0x10;

// Byte 3 data frame flags
/// データフレーム Byte 3: ハードウェアバッファオーバーフロー
const HEADER_OVERFLOW:   u8 = 0x08;
/// データフレーム Byte 3: CRC エラー
const HEADER_CRC_ERROR:  u8 = 0x10;
/// データフレーム Byte 3: USB PHY データエラー
const HEADER_DATA_ERROR: u8 = 0x20;

// Byte 3 status frame fields
/// ステータスフレーム Byte 3: ライン状態フィールドのビットオフセット
const HEADER_LS_OFFS:    u8 = 0;
/// ステータスフレーム Byte 3: ライン状態フィールドのビットマスク
const HEADER_LS_MASK:    u8 = 0x0f;
/// ステータスフレーム Byte 3: VBUS 電圧存在フラグ
const HEADER_VBUS:       u8 = 0x10;
/// ステータスフレーム Byte 3: トリガ入力フラグ
const HEADER_TRIGGER:    u8 = 0x20;
/// ステータスフレーム Byte 3: 検出速度フィールドのビットオフセット
const HEADER_SPEED_OFFS: u8 = 6;
/// ステータスフレーム Byte 3: 検出速度フィールドのビットマスク
const HEADER_SPEED_MASK: u8 = 0x03;

/// USB PID: Start-of-Frame
const PID_SOF: u8 = 0xa5;
/// USB PID: IN トークン
const PID_IN:  u8 = 0x69;
/// USB PID: NAK ハンドシェイク
const PID_NAK: u8 = 0x5a;

/// Low/Full-Speed でフォールドをリセットするまでの SOF フレーム数
const FOLD_LIMIT_LS_FS: i32 = 1000;
/// High-Speed でフォールドをリセットするまでの SOF フレーム数
const FOLD_LIMIT_HS: i32    = 8000;

/// Low-Speed キープアライブ検出: 最小継続時間 (ns)
const MIN_KEEPALIVE_DURATION: u64 = 1_000; // 1 us in ns
/// Low-Speed キープアライブ検出: 最大継続時間 (ns)
const MAX_KEEPALIVE_DURATION: u64 = 2_000; // 2 us in ns

/// ライン状態が未知/初期化前であることを示す番兵値
const LS_INVALID: i32 = -1;
/// ライン状態: SE0 (D+ = 0, D- = 0)
const LS_SE0: i32     = 0;
/// ライン状態: J3 (Low-Speed J + 単端レベル 3)
const LS_J3: i32      = 12;

/// ライン状態変化を pcapng に記録するタイムスタンプ差分の閾値
const LS_DELTA_THRESHOLD: u64 = 10 * TIME_MS;

/// FPGA キャプチャコントローラへ送る制御コマンドのインデックス定数。
///
/// USB コントロール転送 (`UsbDevice::ctrl`) の第一引数として使用する。
pub struct CaptureCtrl;

impl CaptureCtrl {
    /// キャプチャ回路全体のリセット
    pub const RESET:  u8 = 0;
    /// キャプチャの有効化/無効化
    pub const ENABLE: u8 = 1;
    /// キャプチャ速度の bit 0
    pub const SPEED0: u8 = 2;
    /// キャプチャ速度の bit 1
    pub const SPEED1: u8 = 3;
    /// 速度テストモードの有効化
    pub const TEST:   u8 = 4;
}

/// キャプチャする USB バス速度。
///
/// `CaptureCtrl::SPEED0` / `SPEED1` ビットに対応する数値をそのまま持つ。
#[derive(Clone, Copy, PartialEq)]
pub enum CaptureSpeed {
    LowSpeed  = 0,
    FullSpeed = 1,
    HighSpeed = 2,
    /// バスリセット検出モード
    Reset     = 3,
}

/// キャプチャ開始条件 (トリガ)。
///
/// トリガ入力ピンの状態変化によってキャプチャを開始するタイミングを制御する。
#[derive(Clone, Copy, PartialEq)]
pub enum CaptureTrigger {
    /// トリガなし、常にキャプチャ有効
    Disabled,
    /// トリガ入力が Low のときキャプチャ有効
    Low,
    /// トリガ入力が High のときキャプチャ有効
    High,
    /// トリガ入力の立ち下がりエッジでキャプチャ開始
    Falling,
    /// トリガ入力の立ち上がりエッジでキャプチャ開始
    Rising,
}

/// フォールドバッファに蓄積するエントリ。
///
/// 空フレームをフォールド (折りたたみ) する際に使用する。
enum FoldEntry {
    /// USB パケット (タイムスタンプとデータ)
    Packet    { ts: u64, data: Vec<u8> },
    /// Low-Speed キープアライブパルス
    Keepalive { ts: u64, _delta: i32 },
}

/// pcapng ブロックを組み立てるビルダ。
///
/// `put_*` メソッドでフィールドを追加し、`send_buffer` でブロック長を
/// 確定させてから `Write` トレイトへ書き出す。
struct PcapngBuf {
    buf: Vec<u8>,
}

impl PcapngBuf {
    /// 空のバッファを作成する。
    fn new() -> Self { PcapngBuf { buf: Vec::with_capacity(4096) } }

    /// リトルエンディアンで 16 ビット値を追記する。
    fn put_half(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// リトルエンディアンで 32 ビット値を追記する。
    fn put_word(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// バイト列をそのまま追記する。
    fn put_data(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// 4 バイトアライメントになるまでゼロでパディングする。
    fn put_pad(&mut self) {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    /// pcapng オプションフィールド (type + length + value) を追記する。
    fn put_option(&mut self, index: u16, s: &str) {
        self.put_half(index);
        self.put_half(s.len() as u16);
        self.put_data(s.as_bytes());
        self.put_pad();
    }

    /// ブロック長フィールドを確定させて `writer` へ書き出し、バッファをクリアする。
    ///
    /// pcapng の仕様上、ブロック長はブロック末尾にも繰り返すため、
    /// `put_word(total)` を末尾に追記してから書き出す。
    fn send_buffer(&mut self, writer: &mut impl Write) -> Result<()> {
        let total = (self.buf.len() + 4) as u32;
        self.put_word(total);
        // Byte 4–7 にブロック長をバックフィル (pcapng 仕様)
        self.buf[4..8].copy_from_slice(&total.to_le_bytes());
        writer.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }
}

/// USB キャプチャの状態マシン。
///
/// FPGA から届くバイトストリームをフレームに組み立て、pcapng 形式で出力する。
/// フレームのフォールド (空フレーム折りたたみ)、ライン状態追跡、
/// タイムスタンプ復元なども担当する。
pub struct CaptureState {
    // State machine
    /// 組み立て中のフレームデータバッファ
    frame: [u8; DATA_BUF_SIZE],
    /// `frame` への書き込み位置
    frame_ptr: usize,
    /// 現在処理中のフレームの期待バイト数
    frame_size: usize,
    /// `true` のとき次に処理するのはフレームヘッダ部
    in_header: bool,
    /// `true` のとき現在のフレームはステータスフレーム
    is_status: bool,
    /// トグルビットの直前値 (同期チェック用)
    toggle: u8,

    // Status tracking
    /// 最後に受信したライン状態値
    ls: i32,
    /// 最後に受信した VBUS 電圧状態 (0=OFF, 1=ON, -1=未初期化)
    vbus: i32,
    /// 最後に受信したトリガ入力状態
    trigger_in: i32,
    /// 最後に検出したバス速度
    detected_speed: i32,
    /// キャプチャが現在有効かどうか
    enabled: bool,

    // Timestamps
    /// タイムスタンプの上位部分 (オーバーフローで +0x100000 ずつ増加)
    ts_int: u64,
    /// 現在のフレームのタイムスタンプ (ns)
    ts: u64,
    /// 最後に pcapng へ書き出したタイムスタンプ (定期更新判定用)
    last_ts: u64,

    // Frame flags
    /// ハードウェアバッファオーバーフロー発生フラグ
    overflow: bool,
    /// CRC エラーフラグ
    crc_error: bool,
    /// USB PHY データエラーフラグ
    data_error: bool,
    /// フレーム継続時間 (未使用)
    _duration: i32,

    // Frame folding
    /// フォールド対象のフレームを一時的に保持するバッファ
    fold_buf: Vec<FoldEntry>,
    /// フォールドカウンタ (折りたたんだ空フレーム数)
    fold_count: i32,

    // Line state
    /// 直前のライン状態値 (変化を検出してから記録するまで保持)
    saved_ls: i32,
    /// 直前のライン状態変化のタイムスタンプ
    saved_ts: u64,

    // Config
    /// キャプチャ速度設定
    speed: CaptureSpeed,
    /// トリガ設定
    trigger: CaptureTrigger,
    /// 空フレームをフォールドするか
    fold_empty: bool,
    /// 残りキャプチャ可能パケット数 (-1 = 無制限)
    limit: i64,

    // pcapng output
    /// pcapng ブロックビルダ
    pcapng: PcapngBuf,
}

impl CaptureState {
    /// キャプチャ状態を初期化して返す。
    pub fn new(speed: CaptureSpeed, trigger: CaptureTrigger, fold_empty: bool, limit: i64) -> Self {
        CaptureState {
            frame: [0u8; DATA_BUF_SIZE],
            frame_ptr: 0,
            frame_size: 0,
            in_header: true,
            is_status: false,
            toggle: 0,
            ls: -1,
            vbus: -1,
            trigger_in: -1,
            detected_speed: -1,
            enabled: false,
            ts_int: 0,
            ts: 0,
            last_ts: 0,
            overflow: false,
            crc_error: false,
            data_error: false,
            _duration: 0,
            fold_buf: Vec::new(),
            fold_count: 0,
            saved_ls: LS_INVALID,
            saved_ts: 0,
            speed,
            trigger,
            fold_empty,
            limit,
            pcapng: PcapngBuf::new(),
        }
    }

    /// pcapng ファイルの先頭に必要な 3 つのヘッダブロックを書き出す。
    ///
    /// Section Header Block (SHB)、USB インターフェース用 IDB、
    /// テキスト情報用 IDB の順に書き出す。
    pub fn write_headers(&mut self, writer: &mut impl Write) -> Result<()> {
        self.write_file_header(writer)?;
        self.write_usb_header(writer)?;
        self.write_info_header(writer)?;
        Ok(())
    }

    /// pcapng Section Header Block (SHB) を書き出す。
    fn write_file_header(&mut self, writer: &mut impl Write) -> Result<()> {
        self.pcapng.put_word(0x0a0d0d0a); // Block Type (SHB)
        self.pcapng.put_word(0);           // Block Length placeholder
        self.pcapng.put_word(0x1a2b3c4d); // Byte Order Magic
        self.pcapng.put_half(1);           // Major Version
        self.pcapng.put_half(0);           // Minor Version
        self.pcapng.put_word(0xffffffff);  // Section Length unknown
        self.pcapng.put_word(0xffffffff);
        self.pcapng.put_option(0x0002, "USB Sniffer by Alex Taradov"); // shb_hardware
        self.pcapng.put_option(0x0000, "");
        self.pcapng.send_buffer(writer)
    }

    /// USB パケットキャプチャ用の Interface Description Block (IDB) を書き出す。
    ///
    /// タイムスタンプ解像度は 9 (= 10^-9 秒 = ナノ秒) に設定する。
    fn write_usb_header(&mut self, writer: &mut impl Write) -> Result<()> {
        let link_type = match self.speed {
            CaptureSpeed::LowSpeed  => LINKTYPE_USB_2_0_LOW_SPEED,
            CaptureSpeed::FullSpeed => LINKTYPE_USB_2_0_FULL_SPEED,
            CaptureSpeed::HighSpeed => LINKTYPE_USB_2_0_HIGH_SPEED,
            CaptureSpeed::Reset     => LINKTYPE_USB_2_0,
        };
        self.pcapng.put_word(1); // IDB
        self.pcapng.put_word(0);
        self.pcapng.put_half(link_type);
        self.pcapng.put_half(0);
        self.pcapng.put_word(0xffff);
        self.pcapng.put_option(0x0002, "usb");
        self.pcapng.put_option(0x0003, "Hardware USB interface");
        self.pcapng.put_half(9); // if_tsresol
        self.pcapng.put_half(1);
        self.pcapng.put_word(9); // nanoseconds
        self.pcapng.put_option(0x0000, "");
        self.pcapng.send_buffer(writer)
    }

    /// テキスト情報 (syslog 形式) 出力用の Interface Description Block (IDB) を書き出す。
    fn write_info_header(&mut self, writer: &mut impl Write) -> Result<()> {
        self.pcapng.put_word(1); // IDB
        self.pcapng.put_word(0);
        self.pcapng.put_half(LINKTYPE_WIRESHARK_UPPER_PDU);
        self.pcapng.put_half(0);
        self.pcapng.put_word(0xffff);
        self.pcapng.put_option(0x0002, "info");
        self.pcapng.put_option(0x0003, "Out of band information");
        self.pcapng.put_half(9);
        self.pcapng.put_half(1);
        self.pcapng.put_word(9);
        self.pcapng.put_option(0x0000, "");
        self.pcapng.send_buffer(writer)
    }

    /// USB パケットを Enhanced Packet Block (EPB) として USB インターフェース (ID=0) に書き出す。
    fn write_packet(&mut self, writer: &mut impl Write, ts: u64, data: &[u8]) -> Result<()> {
        self.pcapng.put_word(6); // EPB
        self.pcapng.put_word(0);
        self.pcapng.put_word(0); // Interface ID
        self.pcapng.put_word((ts >> 32) as u32);
        self.pcapng.put_word(ts as u32);
        self.pcapng.put_word(data.len() as u32);
        self.pcapng.put_word(data.len() as u32);
        self.pcapng.put_data(data);
        self.pcapng.put_pad();
        self.pcapng.put_option(0x0000, "");
        self.pcapng.send_buffer(writer)?;
        self.last_ts = ts;
        Ok(())
    }

    /// テキストメッセージを Wireshark Upper PDU (syslog) 形式で info インターフェース (ID=1) に書き出す。
    fn write_str(&mut self, writer: &mut impl Write, ts: u64, s: &str) -> Result<()> {
        // Wireshark Upper PDU ヘッダ: syslog タグ (type=12, length=6, "syslog", pad)
        static HDR: &[u8] = &[0, 12, 0, 6, b's', b'y', b's', b'l', b'o', b'g', 0, 0, 0, 0];
        let data = s.as_bytes();
        self.pcapng.put_word(6); // EPB
        self.pcapng.put_word(0);
        self.pcapng.put_word(1); // Interface ID (info interface)
        self.pcapng.put_word((ts >> 32) as u32);
        self.pcapng.put_word(ts as u32);
        self.pcapng.put_word((HDR.len() + data.len()) as u32);
        self.pcapng.put_word((HDR.len() + data.len()) as u32);
        self.pcapng.put_data(HDR);
        self.pcapng.put_data(data);
        self.pcapng.put_pad();
        self.pcapng.send_buffer(writer)?;
        self.last_ts = ts;
        Ok(())
    }

    /// ライン状態変化とフォールドバッファを先に書き出してから情報メッセージを記録する。
    fn capture_info(&mut self, writer: &mut impl Write, ts: u64, msg: &str) -> Result<()> {
        self.line_state_event(writer)?;
        self.stop_folding(writer)?;
        self.write_str(writer, ts, msg)?;
        writer.flush()?;
        Ok(())
    }

    /// Low-Speed キープアライブパルスを "Keep-alive" テキストとして書き出す。
    fn write_keepalive(&mut self, writer: &mut impl Write, ts: u64) -> Result<()> {
        self.write_str(writer, ts, "Keep-alive")
    }

    /// 定期更新タイムアウトイベント: キャプチャ中に 2 秒以上パケットがなければ通知する。
    fn timeout_event(&mut self, writer: &mut impl Write) -> Result<()> {
        if self.enabled {
            let ts = self.ts;
            self.capture_info(writer, ts, "Periodic update")?;
        }
        Ok(())
    }

    /// 保存されているライン状態変化を pcapng に書き出してリセットする。
    ///
    /// D+/D- の電圧レベルを J/K/SE0/Undefined に変換してメッセージ化する。
    fn line_state_event(&mut self, writer: &mut impl Write) -> Result<()> {
        if self.saved_ls == LS_INVALID {
            return Ok(());
        }

        let saved_ls = self.saved_ls;
        let saved_ts = self.saved_ts;
        self.saved_ls = LS_INVALID;

        let dp = (saved_ls >> 0) & 3;
        let dm = (saved_ls >> 2) & 3;
        let delta = self.ts.saturating_sub(saved_ts);

        let mut msg = String::from("Line state: ");

        let level = if dp == 0 && dm == 0 {
            msg.push_str("SE0");
            0
        } else if dp == 0 {
            msg.push_str(if self.speed == CaptureSpeed::LowSpeed { "J" } else { "K" });
            dm
        } else if dm == 0 {
            msg.push_str(if self.speed == CaptureSpeed::LowSpeed { "K" } else { "J" });
            dp
        } else {
            use std::fmt::Write as FmtWrite;
            write!(msg, "Undefined (DP={} / DM={})", dp, dm).ok();
            0
        };

        if level == 1 {
            msg.push_str(" [both]");
        } else if level == 2 {
            msg.push_str(" [single]");
        }

        if delta < LS_DELTA_THRESHOLD {
            if delta < TIME_US {
                use std::fmt::Write as FmtWrite;
                write!(msg, " ({:.2} ns)", delta as f32).ok();
            } else if delta < TIME_MS {
                use std::fmt::Write as FmtWrite;
                write!(msg, " ({:.2} us)", delta as f32 / TIME_US as f32).ok();
            } else {
                use std::fmt::Write as FmtWrite;
                write!(msg, " ({:.2} ms)", delta as f32 / TIME_MS as f32).ok();
            }
        }

        self.write_str(writer, saved_ts, &msg)
    }

    /// FPGA から受信したステータスフレームを処理する。
    ///
    /// トリガ入力・VBUS・バス速度・ライン状態の変化を検出してそれぞれイベントを発行する。
    fn status_event(
        &mut self,
        writer: &mut impl Write,
        ls: i32,
        vbus: i32,
        trigger: i32,
        speed: i32,
    ) -> Result<()> {
        if self.trigger_in != trigger {
            let was_enabled = self.enabled;

            self.enabled = match self.trigger {
                CaptureTrigger::Disabled => true,
                CaptureTrigger::Low      => trigger == 0,
                CaptureTrigger::High     => trigger == 1,
                CaptureTrigger::Falling  => self.enabled || (trigger == 0 && self.trigger_in == 1),
                CaptureTrigger::Rising   => self.enabled || (trigger == 1 && self.trigger_in == 0),
            };

            self.trigger_in = trigger;
            let ts = self.ts;
            let msg = format!("Trigger input = {}", trigger);
            self.capture_info(writer, ts, &msg)?;

            if self.enabled && !was_enabled {
                let ts = self.ts;
                self.capture_info(writer, ts, "Starting capture")?;
            } else if was_enabled && !self.enabled {
                let ts = self.ts;
                self.capture_info(writer, ts, "Waiting for a trigger")?;
            }
        }

        if self.vbus != vbus {
            self.vbus = vbus;
            let ts = self.ts;
            let msg = format!("VBUS {}", if vbus != 0 { "ON" } else { "OFF" });
            self.capture_info(writer, ts, &msg)?;
        }

        if self.detected_speed != speed {
            self.detected_speed = speed;
            if self.enabled {
                let ts = self.ts;
                let msg = if speed == CaptureSpeed::Reset as i32 {
                    "--- Bus Reset ---".to_string()
                } else {
                    let names = ["Low-Speed", "Full-Speed", "High-Speed", ""];
                    format!("Detected speed: {}", names[speed as usize])
                };
                self.capture_info(writer, ts, &msg)?;
            }
        }

        if self.ls != ls {
            let delta = self.ts.saturating_sub(self.saved_ts);
            let mut handle = true;

            // Low-Speed キープアライブ: SE0 → J3 の遷移が 1–2 us なら keepalive として処理する
            if self.speed == CaptureSpeed::LowSpeed
                && self.saved_ls == LS_SE0
                && ls == LS_J3
                && delta > MIN_KEEPALIVE_DURATION
                && delta < MAX_KEEPALIVE_DURATION
            {
                let saved_ts = self.saved_ts;
                self.saved_ls = LS_INVALID;
                self.keepalive_event(writer, saved_ts, delta as i32)?;
                handle = false;
            }

            if handle {
                self.line_state_event(writer)?;
                self.saved_ls = ls;
                self.saved_ts = self.ts;
            }

            self.ls = ls;
        }

        Ok(())
    }

    /// フォールドバッファに蓄積されたエントリをすべて書き出してカウンタをリセットする。
    fn stop_folding(&mut self, writer: &mut impl Write) -> Result<()> {
        let count = self.fold_count;
        if count == 0 && self.fold_buf.is_empty() {
            return Ok(());
        }

        let fold_buf = std::mem::take(&mut self.fold_buf);
        self.fold_count = 0;

        if count == 1 {
            let ts = self.ts;
            self.write_str(writer, ts, "Folded empty frame")?;
        } else if count > 1 {
            let ts = self.ts;
            let msg = format!("Folded {} empty frames", count);
            self.write_str(writer, ts, &msg)?;
        }

        for entry in fold_buf {
            match entry {
                FoldEntry::Keepalive { ts, .. }  => self.write_keepalive(writer, ts)?,
                FoldEntry::Packet { ts, data }  => self.write_packet(writer, ts, &data)?,
            }
        }
        Ok(())
    }

    /// USB パケットをフォールドバッファへ追加する。
    fn fold_packet(&mut self, ts: u64, data: &[u8]) {
        self.fold_buf.push(FoldEntry::Packet { ts, data: data.to_vec() });
    }

    /// キープアライブエントリをフォールドバッファへ追加する。
    fn fold_keepalive(&mut self, ts: u64, delta: i32) {
        self.fold_buf.push(FoldEntry::Keepalive { ts, _delta: delta });
    }

    /// キャプチャパケット数上限に達したかチェックし、達していたらプロセスを終了する。
    fn check_capture_limit(&mut self, writer: &mut impl Write) -> Result<()> {
        if self.limit < 0 {
            return Ok(());
        }
        self.limit -= 1;
        if self.limit == 0 {
            let ts = self.ts;
            self.capture_info(writer, ts, "Capture limit reached")?;
            std::process::exit(0);
        }
        Ok(())
    }

    /// Low-Speed キープアライブイベントを処理する。
    ///
    /// フォールドが有効な場合はフォールドバッファと連携して折りたたむ。
    fn keepalive_event(&mut self, writer: &mut impl Write, ts: u64, delta: i32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if !self.fold_empty {
            self.write_keepalive(writer, ts)?;
        } else if !self.fold_buf.is_empty() {
            self.fold_count += 1;
            self.fold_buf.clear();

            if self.fold_count == FOLD_LIMIT_LS_FS {
                self.stop_folding(writer)?;
            }
            self.fold_keepalive(ts, delta);
        } else {
            self.fold_keepalive(ts, delta);
        }

        self.check_capture_limit(writer)
    }

    /// 完成したデータフレームを pcapng へ書き出すか、フォールドバッファに蓄積する。
    ///
    /// SOF / IN / NAK の PID に基づいてフォールド対象かどうかを判定する。
    fn data_event(&mut self, writer: &mut impl Write) -> Result<()> {
        let data_error = self.crc_error || self.data_error;
        let allow_sof = self.speed != CaptureSpeed::LowSpeed;
        let pid = self.frame[0];
        let frame_size = self.frame_size;
        let frame_ts = self.ts;

        if !self.enabled {
            return Ok(());
        }

        self.line_state_event(writer)?;

        if self.overflow || data_error || self.fold_buf.len() == FOLD_BUF_SIZE {
            self.stop_folding(writer)?;
        }

        if self.overflow {
            let ts = self.ts;
            self.capture_info(writer, ts, "Hardware buffer overflow")?;
        }
        if self.data_error {
            let ts = self.ts;
            self.capture_info(writer, ts, "USB PHY error")?;
        }

        let frame_data = self.frame[..frame_size].to_vec();

        if data_error || !self.fold_empty {
            self.write_packet(writer, frame_ts, &frame_data)?;
        } else if !self.fold_buf.is_empty() {
            if pid == PID_IN || pid == PID_NAK {
                self.fold_packet(frame_ts, &frame_data);
            } else if pid == PID_SOF && allow_sof {
                self.fold_count += 1;
                self.fold_buf.clear();

                let limit = if self.speed == CaptureSpeed::HighSpeed {
                    FOLD_LIMIT_HS
                } else {
                    FOLD_LIMIT_LS_FS
                };

                if self.fold_count == limit {
                    self.stop_folding(writer)?;
                }
                self.fold_packet(frame_ts, &frame_data);
            } else {
                self.stop_folding(writer)?;
                self.write_packet(writer, frame_ts, &frame_data)?;
            }
        } else if pid == PID_SOF && allow_sof {
            self.fold_packet(frame_ts, &frame_data);
        } else {
            self.write_packet(writer, frame_ts, &frame_data)?;
        }

        self.check_capture_limit(writer)
    }

    /// プロトコル同期エラーを記録してプロセスを終了する。
    fn desync_error(&mut self, writer: &mut impl Write) -> Result<()> {
        let ts = self.ts;
        self.capture_info(writer, ts, "Error: protocol desynchronization, stopping the capture")?;

        let mut hex = String::new();
        for i in 0..self.frame_size {
            use std::fmt::Write as FmtWrite;
            write!(hex, "{:02x} ", self.frame[i]).ok();
        }
        let msg = format!("Packet header: {}", hex);
        let ts = self.ts;
        self.capture_info(writer, ts, &msg)?;
        std::process::exit(0);
    }

    /// ヘッダのトグルビットとゼロビットを検証する。
    ///
    /// 不正な場合は診断メッセージを出力してから `desync_error` を呼び出す。
    fn check_header(&mut self, writer: &mut impl Write, toggle: u8, zero: u8) -> Result<()> {
        if toggle == self.toggle && zero == 0 {
            return Ok(());
        }
        if toggle != self.toggle {
            let ts = self.ts;
            let msg = format!("Error: received toggle value {}, expected {}", toggle, self.toggle);
            self.capture_info(writer, ts, &msg)?;
        }
        if zero != 0 {
            let ts = self.ts;
            self.capture_info(writer, ts, "Error: zero bit in the header is not zero")?;
        }
        self.desync_error(writer)
    }

    /// データフレームのサイズが有効範囲内かチェックする。
    fn check_data_size(&mut self, writer: &mut impl Write, size: usize) -> Result<()> {
        if DATA_HEADER_SIZE <= size && size <= MAX_DATA_SIZE {
            return Ok(());
        }
        let ts = self.ts;
        let msg = format!("Error: invalid data size ({})", size);
        self.capture_info(writer, ts, &msg)?;
        self.desync_error(writer)
    }

    /// FPGA から届くバイトストリームを 1 バイトずつ状態マシンに通す。
    ///
    /// ヘッダ部を収集したらタイムスタンプを復元し、ステータス/データフレームを判別する。
    /// データ部を収集し終えたら `data_event` を呼び出す。
    fn process_byte(&mut self, writer: &mut impl Write, byte: u8) -> Result<()> {
        if self.in_header && self.frame_ptr == 0 {
            // Byte 0 の bit 7 が 0 ならステータスフレーム
            self.is_status = (byte & HEADER_STATUS) == 0;
            self.frame_size = if self.is_status { STATUS_HEADER_SIZE } else { DATA_HEADER_SIZE };
        }

        self.frame[self.frame_ptr] = byte;
        self.frame_ptr += 1;

        if self.frame_ptr < self.frame_size {
            return Ok(());
        }

        if self.in_header {
            // タイムスタンプ下位 20 ビットを Byte 0[3:0] + Byte 1 + Byte 2 から復元する
            let ts_low = (((self.frame[0] & 0xf) as u32) << 16)
                | ((self.frame[1] as u32) << 8)
                | (self.frame[2] as u32);
            let toggle = if self.frame[0] & HEADER_TOGGLE != 0 { 1 } else { 0 };
            let zero   = if self.frame[0] & HEADER_ZERO   != 0 { 1 } else { 0 };

            self.check_header(writer, toggle, zero)?;

            if self.frame[0] & HEADER_TS_OVERFLOW != 0 {
                // タイムスタンプ上位部がオーバーフロー: 20 ビット分繰り上げ
                self.ts_int += 0x100000;
            }

            // FPGA クロック (60 MHz = 1/6 * 100 ns) → ナノ秒に変換
            self.ts = ((self.ts_int | ts_low as u64) * 100) / 6;
            self.toggle = 1 - toggle;

            if self.ts.saturating_sub(self.last_ts) > UPDATE_INTERVAL {
                self.timeout_event(writer)?;
            }

            if self.is_status {
                let b3 = self.frame[3];
                let ls      = ((b3 >> HEADER_LS_OFFS) & HEADER_LS_MASK) as i32;
                let vbus    = if b3 & HEADER_VBUS    != 0 { 1 } else { 0 };
                let trigger = if b3 & HEADER_TRIGGER != 0 { 1 } else { 0 };
                let speed   = ((b3 >> HEADER_SPEED_OFFS) & HEADER_SPEED_MASK) as i32;
                self.status_event(writer, ls, vbus, trigger, speed)?;
            } else {
                // データフレーム: ペイロードサイズを Byte 3[2:0] + Byte 4 から取得する
                let size = (((self.frame[3] & 0x7) as usize) << 8) | self.frame[4] as usize;
                self.check_data_size(writer, size)?;

                self.frame_size   = size - DATA_HEADER_SIZE;
                self.overflow     = self.frame[3] & HEADER_OVERFLOW   != 0;
                self.crc_error    = self.frame[3] & HEADER_CRC_ERROR  != 0;
                self.data_error   = self.frame[3] & HEADER_DATA_ERROR != 0;
                self._duration    = ((self.frame[5] as i32) << 8) | self.frame[6] as i32;
                self.in_header    = self.frame_size == 0;
            }
        } else {
            self.in_header = true;
            self.data_event(writer)?;
        }

        self.frame_ptr = 0;
        Ok(())
    }

    /// USB バルク転送コールバックから届いたデータチャンクを処理する。
    ///
    /// バイトを 1 つずつ `process_byte` に渡す。
    /// チャンク末尾で flush することで Wireshark がリアルタイムにパケットを受け取れる。
    /// (SIGTERM でプロセスが終了すると BufWriter の Drop は走らないため、
    ///  明示的な flush なしでは Wireshark にパケットが届かない。)
    pub fn process(&mut self, writer: &mut impl Write, data: &[u8]) -> Result<()> {
        for &byte in data {
            self.process_byte(writer, byte)?;
        }
        writer.flush()?;
        Ok(())
    }
}

/// Wireshark extcap プロトコルのクエリに応答する。
///
/// `--extcap-interfaces`, `--extcap-dlts`, `--extcap-config` などの
/// extcap フラグを処理し、Wireshark が期待する形式で標準出力に出力する。
/// extcap クエリを処理した場合は `true` を返し、通常キャプチャには進まない。
pub fn handle_extcap(
    extcap_version: Option<&str>,
    extcap_interfaces: bool,
    extcap_interface: Option<&str>,
    extcap_dlts: bool,
    extcap_config: bool,
) -> bool {
    if let Some(version) = extcap_version {
        if version != "4.0" {
            eprintln!("unsupported extcap version");
        } else {
            println!(
                "extcap {{version=1.0}}{{help=https://github.com/ataradov/usb-sniffer}}{{display=USB Sniffer}}"
            );
        }
    }

    if extcap_interfaces {
        println!("interface {{value={INTERFACE_NAME}}}{{display=USB Sniffer}}");
        return true;
    }

    if let Some(iface) = extcap_interface {
        if iface != INTERFACE_NAME {
            eprintln!("invalid interface, expected {INTERFACE_NAME}");
            return true;
        }
    }

    if extcap_dlts {
        println!("dlt {{number={LINKTYPE_USB_2_0}}}{{name=USB}}{{display=USB}}");
        return true;
    }

    if extcap_config {
        println!("arg {{number=0}}{{call=--speed}}{{display=Capture Speed}}{{tooltip=USB capture speed}}{{type=selector}}");
        println!("value {{arg=0}}{{value=ls}}{{display=Low-Speed}}{{default=false}}");
        println!("value {{arg=0}}{{value=fs}}{{display=Full-Speed}}{{default=true}}");
        println!("value {{arg=0}}{{value=hs}}{{display=High-Speed}}{{default=false}}");
        println!("arg {{number=1}}{{call=--fold}}{{display=Fold empty frames}}{{tooltip=Fold frames that have no data or errors}}{{type=boolflag}}");
        println!("arg {{number=2}}{{call=--trigger}}{{display=Capture Trigger}}{{tooltip=Condition used to start the capture}}{{type=selector}}");
        println!("value {{arg=2}}{{value=disabled}}{{display=Disabled}}{{default=true}}");
        println!("value {{arg=2}}{{value=low}}{{display=Low}}{{default=false}}");
        println!("value {{arg=2}}{{value=high}}{{display=High}}{{default=false}}");
        println!("value {{arg=2}}{{value=falling}}{{display=Falling}}{{default=false}}");
        println!("value {{arg=2}}{{value=rising}}{{display=Rising}}{{default=false}}");
        println!("arg {{number=3}}{{call=--limit}}{{display=Capture Limit}}{{tooltip=Limit the number of captured packets (0 for unlimited)}}{{type=integer}}{{range=0,10000000}}{{default=0}}");
        return true;
    }

    false
}

/// キャプチャを開始してデータを pcapng 形式で `fifo_path` に書き出す。
///
/// FPGA キャプチャ回路をリセット・初期化してから USB バルク転送ループを起動し、
/// 受信データを `CaptureState` で処理して pcapng ファイルへストリーム書き込みする。
pub fn run(
    device: &UsbDevice,
    fifo_path: &str,
    speed: CaptureSpeed,
    trigger: CaptureTrigger,
    limit: i64,
    fold_empty: bool,
) -> Result<()> {
    let file = std::fs::File::create(fifo_path)?;
    let mut writer = BufWriter::new(file);

    // キャプチャ回路を初期状態にリセットしてから速度を設定して有効化する
    device.ctrl_init()?;
    device.ctrl(CaptureCtrl::ENABLE, false)?;
    device.ctrl(CaptureCtrl::RESET, true)?;
    device.flush_data()?;
    device.ctrl(CaptureCtrl::SPEED0, (speed as u8) & 1 != 0)?;
    device.ctrl(CaptureCtrl::SPEED1, (speed as u8) & 2 != 0)?;
    device.ctrl(CaptureCtrl::RESET, false)?;
    device.ctrl(CaptureCtrl::ENABLE, true)?;

    let mut state = CaptureState::new(speed, trigger, fold_empty, limit);
    state.write_headers(&mut writer)?;

    if trigger == CaptureTrigger::Disabled {
        state.capture_info(&mut writer, 0, "Starting capture")?;
        state.enabled = true;
    } else {
        let ts = state.ts;
        state.capture_info(&mut writer, ts, "Waiting for a trigger")?;
    }

    device.data_transfer_loop(move |data| state.process(&mut writer, data))
}
