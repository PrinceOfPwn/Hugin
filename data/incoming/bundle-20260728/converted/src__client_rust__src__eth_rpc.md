# eth_rpc

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/eth_rpc.rs` |
| **Lines** | 195 |
| **Cards** | T019-networking, T020-crypto |
| **Role** | Ethereum JSON-RPC client |

## Public API

### `rpc_call` (line 23)
```rust
pub fn rpc_call(method: &str, params: &Value, rpcs: &[&str]) -> anyhow::Result<Value>
```
Make a JSON-RPC call with fallback across multiple RPC endpoints.
Tries each endpoint until one succeeds.

### `get_nonce` (line 67)
```rust
pub fn get_nonce(address: &str, rpcs: &[&str]) -> anyhow::Result<u64>
```
Get the current nonce (transaction count) for an address.

### `get_gas_price` (line 77)
```rust
pub fn get_gas_price(rpcs: &[&str]) -> anyhow::Result<u64>
```
Get the current gas price in wei.

### `send_raw_transaction` (line 89)
```rust
pub fn send_raw_transaction(raw_tx: &str, rpcs: &[&str]) -> anyhow::Result<String>
```
Broadcast a signed raw transaction. Returns tx hash.

### `get_logs` (line 100)
```rust
pub fn get_logs(
```
Get event logs from a contract.

### `get_block_number` (line 122)
```rust
pub fn get_block_number(rpcs: &[&str]) -> anyhow::Result<u64>
```
Get the current block number.

### `get_balance` (line 133)
```rust
pub fn get_balance(address: &str, rpcs: &[&str]) -> anyhow::Result<u64>
```

### `sign_and_send` (line 145)
```rust
pub fn sign_and_send(
```
Sign, broadcast a transaction, and return the tx hash.
Handles nonce, gas price, and gas limit automatically.

## Internal Functions

- `sepolia_rpcs_is_not_empty` (line 169)
- `all_sepolia_rpc_urls_use_https` (line 174)
- `no_duplicate_sepolia_rpc_urls` (line 185)

## Key Dependencies

- `use serde_json::{json, Value};`
- `use tracing::{info, warn};`
- `use super::*;`

## Full Source

```rust
// Blocking Ethereum JSON-RPC helpers for the Rust client.
//
// Uses reqwest::blocking (already in Cargo.toml) to interact with
// Sepolia testnet nodes. Mirrors the RPC patterns in server/blockchain.py.

use serde_json::{json, Value};
use tracing::{info, warn};

/// Default Sepolia RPC endpoints (matching server/blockchain.py _FALLBACK_RPCS).
pub const SEPOLIA_RPCS: &[&str] = &[
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc.sepolia.org",
    "https://rpc2.sepolia.org",
    "https://sepolia.gateway.tenderly.co",
    "https://1rpc.io/sepolia",
    "https://endpoints.omniatech.io/v1/eth/sepolia/public",
    "https://eth-sepolia.public.blastapi.io",
    "https://sepolia.drpc.org",
];

/// Make a JSON-RPC call with fallback across multiple RPC endpoints.
/// Tries each endpoint until one succeeds.
pub fn rpc_call(method: &str, params: &Value, rpcs: &[&str]) -> anyhow::Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let mut last_err = String::new();
    for rpc_url in rpcs {
        match client
            .post(*rpc_url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
        {
            Ok(resp) => {
                if let Ok(text) = resp.text() {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("result").is_some() {
                            return Ok(json);
                        }
                        if let Some(err) = json.get("error") {
                            last_err = format!("[{}] {}", rpc_url, err);
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                last_err = format!("[{}] {}", rpc_url, e);
                continue;
            }
        }
    }
    anyhow::bail!("RPC {} failed on all endpoints: {}", method, last_err)
}

/// Get the current nonce (transaction count) for an address.
pub fn get_nonce(address: &str, rpcs: &[&str]) -> anyhow::Result<u64> {
    let resp = rpc_call("eth_getTransactionCount", &json!([address, "pending"]), rpcs)?;
    let hex = resp["result"]
        .as_str()
        .unwrap_or("0x0")
        .trim_start_matches("0x");
    Ok(u64::from_str_radix(hex, 16).unwrap_or(0))
}

/// Get the current gas price in wei.
pub fn get_gas_price(rpcs: &[&str]) -> anyhow::Result<u64> {
    let resp = rpc_call("eth_gasPrice", &json!([]), rpcs)?;
    let hex = resp["result"]
        .as_str()
        .unwrap_or("0x3B9ACA00")
        .trim_start_matches("0x");
    let price = u64::from_str_radix(hex, 16).unwrap_or(1_000_000_000);
    // Floor at 1 gwei (matching server/blockchain.py)
    Ok(price.max(1_000_000_000))
}

/// Broadcast a signed raw transaction. Returns tx hash.
pub fn send_raw_transaction(raw_tx: &str, rpcs: &[&str]) -> anyhow::Result<String> {
    let resp = rpc_call("eth_sendRawTransaction", &json!([raw_tx]), rpcs)?;
    if let Some(hash) = resp["result"].as_str() {
        Ok(hash.to_string())
    } else {
        let err = resp.get("error").cloned().unwrap_or(json!("unknown error"));
        anyhow::bail!("sendRawTransaction failed: {}", err)
    }
}

/// Get event logs from a contract.
pub fn get_logs(
    contract: &str,
    topics: &[&str],
    from_block: &str,
    to_block: &str,
    rpcs: &[&str],
) -> anyhow::Result<Vec<Value>> {
    let topics_json: Vec<Value> = topics.iter().map(|t| json!(t)).collect();
    let params = json!([{
        "address": contract,
        "fromBlock": from_block,
        "toBlock": "latest",
        "topics": topics_json,
    }]);
    let resp = rpc_call("eth_getLogs", &params, rpcs)?;
    match resp["result"].as_array() {
        Some(logs) => Ok(logs.clone()),
        None => Ok(vec![]),
    }
}

/// Get the current block number.
pub fn get_block_number(rpcs: &[&str]) -> anyhow::Result<u64> {
    let resp = rpc_call("eth_blockNumber", &json!([]), rpcs)?;
    let hex = resp["result"]
        .as_str()
        .unwrap_or("0x0")
        .trim_start_matches("0x");
    Ok(u64::from_str_radix(hex, 16).unwrap_or(0))
}

/// Check ETH balance for an address (in wei).
#[allow(dead_code)]
pub fn get_balance(address: &str, rpcs: &[&str]) -> anyhow::Result<u64> {
    let resp = rpc_call("eth_getBalance", &json!([address, "latest"]), rpcs)?;
    let hex = resp["result"]
        .as_str()
        .unwrap_or("0x0")
        .trim_start_matches("0x");
    // u64 can hold up to ~18 ETH in wei, enough for testnet
    Ok(u64::from_str_radix(hex, 16).unwrap_or(0))
}

/// Sign, broadcast a transaction, and return the tx hash.
/// Handles nonce, gas price, and gas limit automatically.
pub fn sign_and_send(
    to: &[u8],
    calldata: &[u8],
    private_key: &[u8; 32],
    nonce: u64,
    rpcs: &[&str],
    chain_id: u64,
) -> anyhow::Result<String> {
    let gas_price = get_gas_price(rpcs)?;
    // Gas limit: 100K base + 48 per calldata byte (EIP-7623 safe bound)
    let gas_limit = 100_000u64 + calldata.len() as u64 * 48;

    let raw_tx = crate::eth_tx::sign_transaction(
        nonce, gas_price, gas_limit, to, 0, calldata, private_key, chain_id,
    )?;

    send_raw_transaction(&raw_tx, rpcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sepolia_rpcs_is_not_empty() {
        assert!(!SEPOLIA_RPCS.is_empty(), "SEPOLIA_RPCS must contain at least one endpoint");
    }

    #[test]
    fn all_sepolia_rpc_urls_use_https() {
        for url in SEPOLIA_RPCS {
            assert!(
                url.starts_with("https://"),
                "Expected HTTPS URL, got: {}",
                url
            );
        }
    }

    #[test]
    fn no_duplicate_sepolia_rpc_urls() {
        let mut seen = std::collections::HashSet::new();
        for url in SEPOLIA_RPCS {
            assert!(
                seen.insert(*url),
                "Duplicate RPC URL found: {}",
                url
            );
        }
    }
}

```