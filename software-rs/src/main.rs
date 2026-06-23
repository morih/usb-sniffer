// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

mod capture;
mod fpga;
mod fx2lp;
mod usb;

use anyhow::{bail, Result};
use capture::{CaptureSpeed, CaptureTrigger};
use clap::Parser;
use usb::UsbDevice;

const FX2LP_VID: u16   = 0x04b4;
const FX2LP_PID: u16   = 0x8613;
const CAPTURE_VID: u16 = 0x6666;
const CAPTURE_PID: u16 = 0x6620;

/// コマンドラインオプション。
///
/// このバイナリは Wireshark の extcap プラグインとしても、
/// 単体のファームウェア書き込み/テストツールとしても動作する。
/// どちらの用途で呼ばれたかは `main()` 内でフラグの組み合わせから判定する。
#[derive(Parser)]
#[command(name = "usb_sniffer", about = "USB Sniffer")]
struct Cli {
    // Capture
    #[arg(short = 's', long, value_name = "speed",
          help = "Capture speed: ls, fs (default), hs")]
    speed: Option<String>,

    #[arg(short = 'l', long, help = "Fold empty frames")]
    fold: bool,

    #[arg(short = 'n', long, value_name = "number",
          help = "Limit captured packets (0 = unlimited)")]
    limit: Option<i64>,

    #[arg(short = 't', long, value_name = "type",
          help = "Trigger: disabled (default), low, high, falling, rising")]
    trigger: Option<String>,

    #[arg(long, help = "Perform transfer rate test")]
    test: bool,

    // Wireshark extcap
    #[arg(long, value_name = "version")]
    extcap_version: Option<String>,

    #[arg(long)]
    extcap_dlts: bool,

    #[arg(long)]
    extcap_interfaces: bool,

    #[arg(long, value_name = "name")]
    extcap_interface: Option<String>,

    #[arg(long)]
    extcap_config: bool,

    #[arg(short = 'c', long)]
    capture: bool,

    #[arg(short = 'f', long, value_name = "name")]
    fifo: Option<String>,

    // Firmware update
    #[arg(long, value_name = "name", help = "Upload FX2LP firmware into SRAM")]
    mcu_sram: Option<String>,

    #[arg(long, value_name = "name", help = "Program FX2LP firmware into EEPROM")]
    mcu_eeprom: Option<String>,

    #[arg(long, value_name = "name", help = "Upload BIT file into FPGA SRAM")]
    fpga_sram: Option<String>,

    #[arg(long, value_name = "name", help = "Program JED file into FPGA flash")]
    fpga_flash: Option<String>,

    #[arg(long, help = "Erase FPGA flash")]
    fpga_erase: bool,
}

/// anyhow エラーが IO の BrokenPipe かどうかを確認する。
///
/// Wireshark が FIFO の読み取り側を閉じると書き込みが BrokenPipe で失敗する。
/// これは Stop 操作による正常終了なのでエラーとして扱わない。
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>()
            .map(|io_err| io_err.kind() == std::io::ErrorKind::BrokenPipe)
            .unwrap_or(false)
    })
}

/// キャプチャデバイス (VID=0x6666, PID=0x6620) を開いて返す。見つからなければエラー。
fn open_capture_device() -> Result<UsbDevice> {
    UsbDevice::open(CAPTURE_VID, CAPTURE_PID)?
        .ok_or_else(|| anyhow::anyhow!("could not open a capture device"))
}

/// `--speed` 引数の文字列を `CaptureSpeed` 列挙値に変換する。省略時は Full-Speed。
fn parse_speed(s: Option<&str>) -> Result<CaptureSpeed> {
    match s {
        None | Some("fs") => Ok(CaptureSpeed::FullSpeed),
        Some("ls")        => Ok(CaptureSpeed::LowSpeed),
        Some("hs")        => Ok(CaptureSpeed::HighSpeed),
        Some(other)       => bail!("unrecognized capture speed: '{}'", other),
    }
}

/// `--trigger` 引数の文字列を `CaptureTrigger` 列挙値に変換する。省略時は Disabled。
fn parse_trigger(s: Option<&str>) -> Result<CaptureTrigger> {
    match s {
        None | Some("disabled") => Ok(CaptureTrigger::Disabled),
        Some("low")             => Ok(CaptureTrigger::Low),
        Some("high")            => Ok(CaptureTrigger::High),
        Some("falling")         => Ok(CaptureTrigger::Falling),
        Some("rising")          => Ok(CaptureTrigger::Rising),
        Some(other)             => bail!("unrecognized capture trigger: '{}'", other),
    }
}

/// エントリポイント。CLI 引数を解析し、該当する処理を1つだけ実行する。
///
/// 各分岐は早期 `return` で抜けるため、複数のフラグが同時に指定されても
/// 上から優先順位順に1つだけが実行される (extcap > capture > test > ...)。
fn main() -> Result<()> {
    let cli = Cli::parse();

    // Wireshark は起動時に複数回 (--extcap-interfaces, --extcap-config 等) を
    // 別プロセスとして呼び出して構成情報を尋ねる。ここで処理して即終了する。
    if capture::handle_extcap(
        cli.extcap_version.as_deref(),
        cli.extcap_interfaces,
        cli.extcap_interface.as_deref(),
        cli.extcap_dlts,
        cli.extcap_config,
    ) {
        return Ok(());
    }

    let capture_speed   = parse_speed(cli.speed.as_deref())?;
    let capture_trigger = parse_trigger(cli.trigger.as_deref())?;
    let capture_limit   = cli.limit.unwrap_or(-1);

    if cli.capture {
        if let Some(ref fifo) = cli.fifo {
            // Wireshark が extcap を実際にキャプチャ実行するために呼ぶパス。
            // FIFO に pcapng を書き続け、Stop が押されるまでブロックする。
            let device = open_capture_device()?;
            match capture::run(&device, fifo, capture_speed, capture_trigger, capture_limit, cli.fold) {
                Ok(()) => {}
                // Wireshark が Stop を押してパイプを閉じた場合は正常終了として扱う
                Err(ref e) if is_broken_pipe(e) => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
    }

    if cli.test {
        // FPGA のテストパターン生成機能を使い、実機の USB スループットを計測する
        // (キャプチャ対象の USB トラフィックは不要)。
        eprintln!("Starting speed test");
        let device = open_capture_device()?;
        device.speed_test()?;
        return Ok(());
    }

    if let Some(ref name) = cli.mcu_sram {
        // 工場出荷時の未初期化 FX2LP (VID/PID がデフォルトの Cypress 値) に
        // ファームウェアを SRAM 経由で一時的に書き込む。EEPROM がまだ無い、
        // または壊れている状態からの復旧/初回セットアップで使う。
        let data = std::fs::read(name)?;
        let device = UsbDevice::open(FX2LP_VID, FX2LP_PID)?
            .ok_or_else(|| anyhow::anyhow!("could not open unconfigured FX2LP device"))?;
        println!("Uploading {} bytes into the FX2LP SRAM", data.len());
        fx2lp::sram_upload(&device, &data)?;
        println!("...done");
        return Ok(());
    }

    if let Some(ref name) = cli.mcu_eeprom {
        // EEPROM 書き込みは、すでに動作中のキャプチャデバイス (VID/PID が
        // sniffer 自身の値) に対して行う。FPGA の TraceID をシリアル番号として
        // 読み出し、バイナリ中のプレースホルダ文字列を実値に置き換えてから書く。
        let device = open_capture_device()?;
        fpga::enable(&device)?;
        let traceid = fpga::read_traceid(&device)? & 0x00ff_ffff_ffff_ffff;
        fpga::disable(&device)?;

        let mut data = std::fs::read(name)?;
        let placeholder = b"[-----SN-----]";
        let pos = data.windows(placeholder.len())
            .position(|w| w == placeholder)
            .ok_or_else(|| anyhow::anyhow!("provided binary does not include a serial number placeholder"))?;
        let sn_str = format!("{:014x}", traceid);
        data[pos..pos + sn_str.len()].copy_from_slice(sn_str.as_bytes());
        println!("Programming {} bytes into the FX2LP EEPROM (SN: {})", data.len(), sn_str);
        fx2lp::eeprom_upload(&device, &data)?;
        println!("...done");
        return Ok(());
    }

    if let Some(ref name) = cli.fpga_sram {
        // FPGA の SRAM (揮発性) に直接ビットストリームを書き込む。電源を切ると
        // 消えるため、開発中の動作確認に向いている。
        let data = std::fs::read(name)?;
        let device = open_capture_device()?;
        println!("Uploading FPGA SRAM");
        fpga::enable(&device)?;
        fpga::program_sram(&device, &data)?;
        fpga::disable(&device)?;
        println!("...done");
        return Ok(());
    }

    if let Some(ref name) = cli.fpga_flash {
        // FPGA 外付けの不揮発フラッシュに JED ファイルを書き込む。
        // 電源を切っても保持され、次回起動時に FPGA が自動でロードする。
        let data = std::fs::read(name)?;
        let device = open_capture_device()?;
        println!("Programming FPGA flash");
        fpga::enable(&device)?;
        fpga::program_flash(&device, &data)?;
        fpga::disable(&device)?;
        println!("...done");
        return Ok(());
    }

    if cli.fpga_erase {
        let device = open_capture_device()?;
        println!("Erasing FPGA flash");
        fpga::enable(&device)?;
        fpga::erase_flash(&device)?;
        fpga::disable(&device)?;
        println!("...done");
        return Ok(());
    }

    Ok(())
}
