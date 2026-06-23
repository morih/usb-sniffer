// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

use anyhow::{bail, Result};
use std::thread;
use std::time::Duration;

use crate::usb::{UsbDevice, USB_EP0_SIZE};

/// FX2LP が I2C で接続している EEPROM のデバイスアドレス (7ビット)
const EEPROM_ADDR: u16 = 0xa2;
/// EEPROM の書き込みページサイズ。実際のチップは 64 バイトだがファームウェアのプロトコル上 32 バイトが上限
const EEPROM_PAGE_SIZE: usize = 32;
/// FX2LP の SRAM/EEPROM サイズ (16 KB)
const FX2LP_SIZE: usize = 16384;
/// EEPROM ブートイメージのヘッダサイズ (FX2LP ブートローダ仕様に基づく)
const FX2LP_HEADER: usize = 12;
/// EEPROM ブートイメージのフッタサイズ (ジャンプ命令 5 バイト)
const FX2LP_FOOTER: usize = 5;

/// FX2LP ファームウェアを内蔵 SRAM に書き込んで即実行する。
///
/// CPU をリセットしてから 64 バイト単位で書き込み・読み返し検証を行い、
/// 最後にリセットを解除してファームウェアを起動する。
pub fn sram_upload(device: &UsbDevice, data: &[u8]) -> Result<()> {
    if data.len() > FX2LP_SIZE {
        bail!("sram_upload: file is too big");
    }

    // CPU を停止してから書き込む (実行中に書くと動作が不定になる)
    device.fx2lp_reset(true)?;

    let mut addr: u16 = 0;
    let mut remaining = data;

    while !remaining.is_empty() {
        let chunk_size = remaining.len().min(USB_EP0_SIZE);
        let chunk = &remaining[..chunk_size];

        // EP0 コントロール転送でチャンクを SRAM へ書き込む
        device.fx2lp_sram_write(addr, chunk)?;

        // 書き込み直後に読み返してデータ一致を確認する
        let mut verify = vec![0u8; chunk_size];
        device.fx2lp_sram_read(addr, &mut verify)?;

        if chunk != verify.as_slice() {
            bail!("sram_upload: verification failed");
        }

        addr += chunk_size as u16;
        remaining = &remaining[chunk_size..];
    }

    // リセット解除でファームウェアが起動する
    device.fx2lp_reset(false)?;
    Ok(())
}

/// FX2LP ファームウェアを I2C EEPROM に書き込む。
///
/// FX2LP ブートローダが読み込める形式のヘッダ/フッタを付加してから
/// 32 バイトページ単位で書き込み・読み返し検証を行う。
/// 書き込み後は電源再投入で EEPROM からブートするようになる。
pub fn eeprom_upload(device: &UsbDevice, data: &[u8]) -> Result<()> {
    let data_size = data.len();

    // ヘッダ + データ + フッタをページサイズの倍数に切り上げる
    let padded_size = ((FX2LP_HEADER + data_size + FX2LP_FOOTER) + (EEPROM_PAGE_SIZE - 1))
        & !(EEPROM_PAGE_SIZE - 1);

    if padded_size > FX2LP_SIZE {
        bail!("eeprom_upload: file is too big");
    }

    // EEPROM イメージバッファを 0xff (未使用領域のデフォルト値) で初期化
    let mut buf = vec![0xffu8; FX2LP_SIZE];

    // FX2LP ブートローダヘッダを構築 (AN65974 仕様)
    buf[0] = 0xc2;             // C2 ロードタイプ (EEPROM ブート)
    buf[7] = 1;                // I2C クロック: 400 kHz
    buf[8] = (data_size >> 8) as u8;
    buf[9] = data_size as u8;  // ファームウェアサイズ (ビッグエンディアン)
    buf[10] = 0;               // ターゲットアドレス上位
    buf[11] = 0;               // ターゲットアドレス下位 (0x0000 = SRAM 先頭)

    buf[FX2LP_HEADER..FX2LP_HEADER + data_size].copy_from_slice(data);

    // フッタ: CPU に対して実行開始アドレス 0x0000 へのジャンプ命令
    let footer_offset = FX2LP_HEADER + data_size;
    buf[footer_offset + 0] = 0x80;
    buf[footer_offset + 1] = 0x01;
    buf[footer_offset + 2] = 0xe6;
    buf[footer_offset + 3] = 0x00;
    buf[footer_offset + 4] = 0x00;

    let mut addr: usize = 0;
    let mut remaining = padded_size;

    while remaining > 0 {
        // 1ページ書き込む (内部で 7ms ウェイトを入れる)
        eeprom_write(device, addr, &buf[addr..addr + EEPROM_PAGE_SIZE])?;

        // 書き込み直後に読み返してページ単位で検証する
        let mut verify = [0u8; EEPROM_PAGE_SIZE];
        eeprom_read(device, addr, &mut verify)?;

        if buf[addr..addr + EEPROM_PAGE_SIZE] != verify {
            bail!("eeprom_upload: verification failed");
        }

        addr += EEPROM_PAGE_SIZE;
        remaining -= EEPROM_PAGE_SIZE;
    }

    Ok(())
}

/// EEPROM の指定アドレスから `data.len()` バイト読み出す。
///
/// I2C のランダムリード手順: アドレスを Write で送ってから Read に切り替える。
fn eeprom_read(device: &UsbDevice, addr: usize, data: &mut [u8]) -> Result<()> {
    eeprom_request_valid(addr, data.len())?;
    // 読み出し先アドレスをビッグエンディアンで送信 (アドレスポインタのセット)
    let addr_bytes = [(addr >> 8) as u8, addr as u8];
    device.i2c_write(EEPROM_ADDR, &addr_bytes)?;
    // アドレス指定後に読み出し
    device.i2c_read(EEPROM_ADDR, data)?;
    Ok(())
}

/// EEPROM の指定アドレスへ最大 1ページ分のデータを書き込む。
///
/// アドレス (2バイト) + データをまとめて I2C Write で送る。
/// EEPROM の内部書き込みサイクルを待つために 7ms スリープする。
fn eeprom_write(device: &UsbDevice, addr: usize, data: &[u8]) -> Result<()> {
    eeprom_request_valid(addr, data.len())?;
    // [addr_high, addr_low, data...] を 1回の I2C Write で送る
    let mut buf = vec![0u8; 2 + data.len()];
    buf[0] = (addr >> 8) as u8;
    buf[1] = addr as u8;
    buf[2..].copy_from_slice(data);
    device.i2c_write(EEPROM_ADDR, &buf)?;
    // EEPROM の内部書き込みサイクル完了を待つ (データシート上最大 5ms、余裕を持って 7ms)
    thread::sleep(Duration::from_millis(7));
    Ok(())
}

/// EEPROM アクセスのパラメータが有効かチェックする。
///
/// - アドレスが FX2LP_SIZE 未満
/// - アドレスがページ境界にアライン済み
/// - サイズが 1ページ以内
fn eeprom_request_valid(addr: usize, size: usize) -> Result<()> {
    if addr >= FX2LP_SIZE || (addr % EEPROM_PAGE_SIZE) != 0 || size > EEPROM_PAGE_SIZE {
        bail!("eeprom: invalid request (addr={:#x}, size={})", addr, size);
    }
    Ok(())
}
