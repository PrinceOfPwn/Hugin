---
id: T-022
name: Network and Protocol Suite
category: networking
tier: mixed
mitre: [T1071, T1071.001, T1090, T1090.002, T1090.003, T1571, T1132, T1105, T1106, T1572, T1108]
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-021]
enables: [T-023, T-019]
vault_references:
  - src/client_rust/src/juubi.rs
  - src/client_rust/src/juubi_chain.rs
  - src/client_rust/src/kamui.rs
implements:
  - file: src/client_rust/src/kamui.rs
    key_functions: [KamuiManager::new, set_ws_sender, enable, disable, handle_tcp_open, handle_tcp_data, handle_tcp_close, handle_tcp_pause, handle_tcp_resume, handle_udp_bind, handle_udp_data, handle_udp_close, handle_chain_data, register_chain, unregister_chain, close_all, stream_stats, udp_relay_stats, chain_stats, tcp_read_task, tcp_write_task, send_ws_msg, send_ws_static, dispatch, handle_raw_tcp_data, handle_raw_tcp_close, handle_raw_tcp_pause, handle_raw_tcp_resume, handle_raw_udp_bind, handle_raw_udp_data, handle_raw_udp_close, handle_raw_chain_data, get_manager, shutdown]
    key_structs: [KamuiManager, KamuiStream, KamuiUdpRelay, KamuiChainStream, TcpOpenPayload, TcpClosePayload, StreamIdPayload, UdpBindPayload, RelayIdPayload, ChainOpenPayload, ChainClosePayload]
    key_constants: [MSG_KAMUI_TCP_DATA, MSG_KAMUI_TCP_OPEN, MSG_KAMUI_TCP_CLOSE, MSG_KAMUI_TCP_PAUSE, MSG_KAMUI_TCP_RESUME, MSG_KAMUI_TCP_ERROR, MSG_KAMUI_UDP_BIND, MSG_KAMUI_UDP_DATA, MSG_KAMUI_UDP_CLOSE, MSG_KAMUI_CHAIN_DATA, TCP_READ_BUF_SIZE, INBOUND_CHANNEL_CAPACITY, CONNECT_TIMEOUT_SECS]
    lines_of_interest:
      - "L1-L17: Module docstring + protocol constant declarations (0x30-0x35)"
      - "L36-L38: MSG_KAMUI_CHAIN_DATA (0x39) for multi-hop relay"
      - "L40-L46: TCP_READ_BUF_SIZE=32768, INBOUND_CHANNEL_CAPACITY=256, CONNECT_TIMEOUT_SECS=10"
      - "L48-L54: build_message() — 5-byte header [type][4B len BE][payload]"
      - "L56-L62: build_tcp_data() — [4B stream_id BE][data] payload envelope"
      - "L90-L116: KamuiStream struct (inbound_tx, abort_handle, resume_notify, paused, bytes_up/down)"
      - "L118-L127: KamuiManager struct (streams, udp_relays, chain_streams, ws_tx, enabled)"
      - "L142-L213: handle_tcp_open() — tokio::time::timeout + TCP_NODELAY + into_split + tokio::select! spawn"
      - "L215-L243: handle_tcp_data() — mpsc::try_send + TrySendError::Full/Closed handling"
      - "L245-L260: handle_tcp_close() — drop(inbound_tx) + abort_handle.abort()"
      - "L262-L272: handle_tcp_pause() — AtomicBool::store(true, SeqCst)"
      - "L274-L285: handle_tcp_resume() — AtomicBool::store(false) + resume_notify.notify_one()"
      - "L301-L357: handle_udp_bind() — UdpSocket::bind(0.0.0.0:port) + 65536-byte recv loop spawn"
      - "L359-L373: handle_udp_data() — send_to(127.0.0.1:dst_port) via relay socket"
      - "L393-L413: handle_chain_data() — chain_stream_id → target_stream_id lookup, fallback to direct"
      - "L415-L425: register_chain() — KamuiChainStream{chain_stream_id, target_stream_id}"
      - "L469-L493: close_all() — drain streams+relays+chains via streams.drain()"
      - "L517-L554: tcp_read_task() — backpressure gate `while paused.load() { resume_notify.notified().await }`"
      - "L556-L579: tcp_write_task() — `while let Some(data) = inbound_rx.recv().await` write_all"
      - "L595-L653: dispatch() — top-level cmd_type match router for KAMUI_*"
      - "L824-L847: handle_raw_tcp_data() — binary frame parser [4B stream_id BE][data]"
      - "L898-L916: shutdown() — close_all + clear_ws_sender + AtomicBool::store(false)"
      - "L920-L928: KAMUI OnceLock singleton + get_manager()"
  - file: src/client_rust/src/juubi.rs
    key_functions: [JuubiState::new, build_hello, handle_auth_challenge, handle_peer_list, handle_open, handle_ack, handle_data, handle_failover, handle_close, hmac_sha256, sha256]
    key_structs: [JuubiState]
    key_constants: [MSG_JUUBI_HELLO, MSG_JUUBI_AUTH_RESP]
    lines_of_interest:
      - "L1-L10: Module docstring — relay state + HMAC auth"
      - "L12-L15: imports from crate::protocol (build_message, MSG_JUUBI_HELLO, MSG_JUUBI_AUTH_RESP)"
      - "L17-L27: JuubiState struct (enabled, can_relay, max_streams, outbound_streams, inbound_streams, last_peer_list, authenticated, secret_token, wallet_address)"
      - "L29-L55: JuubiState::new() — env-driven config (JUUBI_SECRET, JUUBI_ENABLED, JUUBI_CAN_RELAY, JUUBI_MAX_STREAMS) + JuubiChainState::new().wallet_address()"
      - "L57-L68: build_hello() — JSON {juubiVersion, canRelay, maxStreams, capabilities:[socks5], clientId, walletAddress}"
      - "L70-L74: handle_auth_challenge() — hmac_sha256(nonce, &secret_token)"
      - "L76-L86: handle_peer_list() — serde_json::from_slice<Vec<Value>>"
      - "L88-L98: handle_open() — u32::from_be_bytes stream_id parse, insert empty Vec"
      - "L100-L106: handle_ack() — debug log only"
      - "L108-L118: handle_data() — append to inbound_streams[stream_id]"
      - "L120-L135: handle_failover() — atomic migration old_id → new_id (inbound + outbound HashMap swaps)"
      - "L137-L145: handle_close() — remove from both maps"
      - "L148-L178: hmac_sha256() — block_size=64, ipad 0x36, opad 0x5c, key padding, XOR"
      - "L180-L260: sha256() — pure Rust SHA-256 w/ Wrapping<u32>, K[64] constants, 0x80 padding"
  - file: src/client_rust/src/juubi_chain.rs
    key_functions: [JuubiChainState::new, is_configured, rpcs, rpc_refs, wallet_address, client_hash, update_config, next_nonce, send_tx, poll_raven_commands, parse_raven_message, post_response, register_peer, discover_peers, parse_peer_registered, poll_peer_messages, parse_peer_message, send_peer_message, start_p2p_tunnel, connect_to_peer, extract_cloudflare_url]
    key_structs: [JuubiChainState, ChainPeer, RavenCommand, PeerMessage]
    key_constants: [EVENT_MESSAGE, EVENT_PEER_REGISTERED, EVENT_PEER_MESSAGE, SEPOLIA_CHAIN_ID]
    lines_of_interest:
      - "L20-L22: EVENT_MESSAGE topic hash 0xafb4ccb... (RavenC2 Message(uint256,address,bytes))"
      - "L24-L26: EVENT_PEER_REGISTERED topic hash (JuubiRegistry PeerRegistered(bytes32,uint256))"
      - "L28-L30: EVENT_PEER_MESSAGE topic hash (JuubiRegistry PeerMessage(bytes32,bytes32,bytes))"
      - "L50-L80: JuubiChainState struct (contract_address, raven_contract, rpc_url, wallet_key[32], encryption_key[32], registered, known_peers, last_raven_block, last_registry_block, local_nonce, poll_interval_secs, xor_key)"
      - "L82-L137: new() — env-driven config (JUUBI_CHAIN_ENABLED, JUUBI_CONTRACT_ADDRESS, RAVEN_CONTRACT_ADDRESS/SEPOLIA_CONTRACT_ADDRESS, JUUBI_RPC_URL/SEPOLIA_RPC_URL, JUUBI_CHAIN_KEY hex→32B, JUUBI_ENCRYPTION_KEY, XOR_KEY, JUUBI_P2P_METHOD=cloudflared, CHAIN_POLL_INTERVAL_SECS=30)"
      - "L91-L102: wallet_key generation fallback — rand::thread_rng().fill_bytes() if JUUBI_CHAIN_KEY absent"
      - "L139-L145: is_configured() gate — enabled && !rpc_url.is_empty() && (contract or raven set)"
      - "L147-L157: rpcs() — primary RPC + eth_rpc::SEPOLIA_RPCS fallbacks w/ dedup"
      - "L178-L183: wallet_address() — eth_tx::derive_address(&wallet_key) → eth_tx::address_to_hex"
      - "L185-L190: client_hash() — eth_tx::keccak256(wallet_addr_bytes) used as on-chain identity"
      - "L208-L219: next_nonce() — chain_nonce.max(local_nonce + 1) collision avoidance"
      - "L221-L241: send_tx() — eth_rpc::sign_and_send() w/ 'nonce too low' detection + retry"
      - "L272-L309: poll_raven_commands() — eth_rpc::get_block_number + eth_rpc::get_logs(raven_contract, [EVENT_MESSAGE], from_hex, 'latest'), 5000-block windows"
      - "L311-L373: parse_raven_message() — ABI bytes decode (offset 32B + length 32B + content), optional XOR decode w/ xor_key, TUNNEL| prefix filter"
      - "L375-L387: post_response() — eth_tx::encode_post_open(data) → send_tx"
      - "L395-L426: register_peer() — XOR endpoint w/ encryption_key[32], eth_tx::encode_register_peer(client_hash, encrypted_endpoint, 0x01)"
      - "L428-L470: discover_peers() — eth_getLogs for EVENT_PEER_REGISTERED, last_registry_block cursor"
      - "L493-L535: poll_peer_messages() — eth_getLogs filtered by topic[2] = my client_hash"
      - "L537-L573: parse_peer_message() — ABI decode PeerMessage (from_hash, to_hash, data)"
      - "L576-L589: send_peer_message() — eth_tx::encode_send_message(to_hash, data)"
      - "L597-L626: start_p2p_tunnel() — spawn cloudflared tunnel --url http://localhost:PORT, parse stderr for trycloudflare.com"
      - "L632-L641: extract_cloudflare_url() — find 'https://' substring + trycloudflare.com/cloudflare heuristic"
min_windows: "Windows 10 1809+"
needs_admin: no
tags: [socks5, peer-relay, blockchain, ethereum, secp256k1, hmac-sha256, cloudflared, multi-hop, backpressure, abi-decode, eip-155, json-rpc, rfb, hvnc, malleable-c2, http-poll, nt-sockets, byovd]
---

# Network and Protocol Suite — Operator Playbook

## TL;DR

The T-022 suite is the implant's *post-compromise lifeline* — a bundle of C2 transports that let `client_rust` survive DNS blocklists, sinkhole IPs, and burned infrastructure. Three of the components are fully implemented in the analyzed files: **Kamui** (`kamui.rs`) is a tokio-driven SOCKS5/TCP/UDP/chain relay engine with cooperative backpressure; **Juubi** (`juubi.rs`) is the relay-state machine with HMAC-SHA256 auth (hand-rolled, no `sha2` crate); and **JuubiChain** (`juubi_chain.rs`) is a full Ethereum Sepolia C2 fallback that polls the `RavenC2` and `JuubiRegistry` contracts via raw JSON-RPC, signs EIP-155 transactions without `ethers-rs`, and pivots to `cloudflared` quick tunnels for P2P. Use Kamui for in-network pivoting; use JuubiChain when the operator's WebSocket C2 falls — the chain becomes the out-of-band command channel.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `src/client_rust/src/kamui.rs` | SOCKS5 + TCP/UDP/chain relay engine (client side) | `KamuiManager`, `dispatch()`, `handle_raw_tcp_data()`, `get_manager()`, `shutdown()`, MSG_KAMUI_* constants | ~960 lines |
| `src/client_rust/src/juubi.rs` | Peer-relay state container + HMAC-SHA256 challenge/response + pure Rust SHA-256 | `JuubiState`, `hmac_sha256()`, `sha256()`, `build_hello()`, `handle_auth_challenge()`, `handle_failover()` | ~260 lines |
| `src/client_rust/src/juubi_chain.rs` | On-chain peer discovery + C2 polling + EIP-155 TX signing + cloudflared P2P tunnel | `JuubiChainState`, `poll_raven_commands()`, `register_peer()`, `send_peer_message()`, `start_p2p_tunnel()` | ~640 lines + ~600 test lines |

> ⚠️ The card also lists `hvnc.rs`, `vnc_server.rs`, `henge.rs`, `rikudo.rs`, `http_poll_transport.rs`, `discovery.rs`, `nt_sockets.rs`, and `byovd.rs`. 

## How It Works

### Kamui (SOCKS5 / TCP / UDP / chain relay)

1. **Engine bootstrap.** The server sends a JSON `MSG_COMMAND` (0x10) with `cmd_type = "KAMUI_START"`. `dispatch()` (L595) calls `KamuiManager::set_ws_sender(ws_tx.clone())` (L131) — wiring the engine's outbound path to the existing WebSocket. `enable()` (L138) atomically flips `enabled: AtomicBool` true.
2. **Stream open.** Server sends `KAMUI_TCP_OPEN` payload `{stream_id, host, port}`. `handle_tcp_open()` (L142) does `tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(format!("{}:{}", host, port)))`. On success, `tcp_stream.set_nodelay(true)` (L172) disables Nagle. `into_split()` yields `OwnedReadHalf` + `OwnedWriteHalf`.
3. **Bidirectional task.** An `mpsc::channel::<Vec<u8>>(256)` (L177) is the WS→TCP bridge. A single `tokio::spawn` (L196) runs `tcp_read_task` (TCP→WS) and `tcp_write_task` (WS→TCP) inside `tokio::select!` — when either completes, the other is dropped, and the `streams` HashMap entry is removed.
4. **Server → client (TCP write).** Binary `MSG_KAMUI_TCP_DATA` (0x30) frames arrive. `handle_raw_tcp_data()` (L824) parses `[4B stream_id BE][data]`. `handle_tcp_data()` (L215) does `inbound_tx.try_send(data)`. On `Full` it sends `TCP_CLOSE` with reason `"inbound buffer overflow"` then closes. On `Closed` it sends `TCP_CLOSE` with reason `"stream closed"`.
5. **Client → server (TCP read).** `tcp_read_task` (L517) reads 32KB chunks, frames them with `build_tcp_data()` as `[0x30][4B len BE][4B stream_id BE][data]`, and pushes through `ws_tx`. `bytes_up` AtomicU64 is bumped with `fetch_add(n, Relaxed)`.
6. **Backpressure.** Server sends `KAMUI_TCP_PAUSE` → `handle_tcp_pause()` (L262) sets `paused.store(true, SeqCst)`. The read task enters `while paused.load(SeqCst) { resume_notify.notified().await }` — non-busy wait via tokio's `Notify`. `KAMUI_TCP_RESUME` → `handle_tcp_resume()` (L274) flips the flag false and `notify_one()` wakes the read task.
7. **UDP relay.** `KAMUI_UDP_BIND` → `handle_udp_bind()` (L301) binds `UdpSocket::bind("0.0.0.0:port")`, spawns a task with `buf = vec![0u8; 65536]` (max UDP datagram), and forwards each datagram as `[0x37][4B len][4B relay_id BE][2B src_port BE][data]` via `build_udp_data()`. Inbound data from server arrives as `MSG_KAMUI_UDP_DATA` (0x37), parsed by `handle_raw_udp_data()` (L874), and sent via `relay.socket.send_to(data, "127.0.0.1:dst_port")`.
8. **Multi-hop chains.** `KamuiChainStream { chain_stream_id, target_stream_id }` (L84) is a virtual→real mapping. `handle_chain_data()` (L393) looks up `chain_stream_id` → `target_stream_id`, falls back to treating `chain_stream_id` as the direct stream_id if no mapping exists. `register_chain()` (L415) and `unregister_chain()` (L427) manage the HashMap.
9. **Cleanup.** `close_all()` (L469) drains `streams`, `udp_relays`, and `chain_streams` via `HashMap::drain()` and `abort_handle.abort()` on each. `shutdown()` (L898) calls `close_all()` + `clear_ws_sender()` + flips `enabled` to false.

### Juubi (relay state + HMAC auth)

1. **Hello frame.** `JuubiState::build_hello()` (L57) constructs a JSON blob `{juubiVersion:1, canRelay, maxStreams, capabilities:["socks5"], clientId, walletAddress}` and frames it as `MSG_JUUBI_HELLO`. `walletAddress` comes from `JuubiChainState::wallet_address()` (cross-module dependency).
2. **Auth challenge.** Server sends a nonce. `handle_auth_challenge()` (L70) computes `hmac_sha256(nonce, &self.secret_token)` — the secret_token defaults to `"raven-juubi-default"` from env var `JUUBI_SECRET` if unset. The 32-byte MAC is framed as `MSG_JUUBI_AUTH_RESP`.
3. **Peer list.** `handle_peer_list()` (L76) parses a `Vec<serde_json::Value>` and stashes it in `last_peer_list`.
4. **Stream lifecycle.** `handle_open()` (L88) parses `[4B stream_id BE]` and inserts an empty `Vec<u8>` into `inbound_streams`. `handle_data()` (L108) appends bytes. `handle_ack()` (L100) is a debug-only no-op. `handle_close()` (L137) removes from both maps.
5. **Failover.** `handle_failover()` (L120) parses two stream_ids from `[4B old_id BE][4B new_id BE]`, removes the entry under `old_id`, and reinserts it under `new_id` in both `inbound_streams` and `outbound_streams`. This is **not** atomic — a small race window exists between remove and insert.

### JuubiChain (on-chain C2 over Ethereum Sepolia)

1. **Wallet setup.** `JuubiChainState::new()` (L82) reads `JUUBI_CHAIN_KEY` hex → 32 bytes for `wallet_key`. If absent, `rand::thread_rng().fill_bytes(&mut wallet_key)` generates a fresh key. `wallet_address()` (L178) calls `eth_tx::derive_address(&wallet_key)` (secp256k1 pubkey → keccak256 → last 20 bytes). `client_hash()` (L185) is `keccak256(wallet_address_bytes)` — used as the on-chain identity (bytes32).
2. **RPC selection.** `rpcs()` (L147) returns the configured primary RPC + `eth_rpc::SEPOLIA_RPCS` fallbacks, deduped. `rpc_refs()` (L161) borrows them as `&str` slices for eth_rpc calls.
3. **TX signing.** `send_tx()` (L221) calls `next_nonce()` (L208) → `eth_rpc::get_nonce()` from chain, then `nonce = chain_nonce.max(local_nonce + 1)` to avoid collisions. `eth_rpc::sign_and_send(to, calldata, &wallet_key, nonce, rpcs, eth_tx::SEPOLIA_CHAIN_ID)` does the EIP-155 signing. On `"nonce too low"` the local_nonce cache is cleared and the TX is retried once with a fresh nonce.
4. **Command polling.** `poll_raven_commands()` (L272) calls `eth_rpc::get_block_number()` then `eth_rpc::get_logs(raven_contract, [EVENT_MESSAGE], from_hex, "latest", rpcs)`. First poll looks back 1000 blocks; subsequent polls cap at 5000-block windows. Each log is parsed by `parse_raven_message()` (L311).
5. **ABI decode.** `parse_raven_message()` extracts `msg_id` from `topics[1]`, `sender` from `topics[2]` (last 20 bytes), and ABI-decodes the `data` field: offset(32B) + length(32B) + content. The content is optionally XOR-decoded with `xor_key` if non-empty. Messages prefixed `"TUNNEL|"` are filtered out (those are for discovery, not commands).
6. **Response posting.** `post_response()` (L375) calls `eth_tx::encode_post_open(data)` to build calldata for `RavenC2.postOpen(bytes)` then submits via `send_tx()`.
7. **Peer discovery.** `discover_peers()` (L428) polls `EVENT_PEER_REGISTERED` logs, parses `client_hash` from `topics[1]` and `timestamp` from `data`. Existing peers are updated in place; new peers are appended to `known_peers`.
8. **Peer messaging.** `poll_peer_messages()` (L493) filters `eth_getLogs` by `topic[2] = client_hash` (the "to" field). `send_peer_message()` (L576) builds `eth_tx::encode_send_message(to_hash, data)` calldata for `JuubiRegistry.sendMessage(bytes32,bytes,bytes)` and submits.
9. **P2P tunnel.** `start_p2p_tunnel()` (L597) spawns `cloudflared tunnel --url http://localhost:{local_port}` with stderr piped. It reads lines via `std::io::BufReader` and calls `extract_cloudflare_url()` (L632) which finds the first `https://` substring containing `trycloudflare.com` or `cloudflare`. The extracted URL is stored in `p2p_tunnel_url` and announced on-chain via `register_peer()`.

## Code Architecture

### Call graph (top-down)

```
main.rs (MSG_COMMAND 0x10 dispatcher)
  └─ kamui::dispatch(cmd_type, payload, ws_tx)
       ├─ KamuiManager::enable() / set_ws_sender()         [KAMUI_START]
       ├─ KamuiManager::disable()                          [KAMUI_STOP]
       ├─ KamuiManager::stream_stats() / udp_relay_stats() / chain_stats()  [KAMUI_STATUS]
       ├─ KamuiManager::handle_tcp_open(stream_id, host, port)
       │    └─ tokio::spawn → tokio::select! { tcp_read_task | tcp_write_task }
       ├─ KamuiManager::handle_tcp_close(stream_id)
       ├─ KamuiManager::handle_tcp_pause / handle_tcp_resume(stream_id)
       ├─ KamuiManager::handle_udp_bind(relay_id, bind_port)
       ├─ KamuiManager::handle_udp_close(relay_id)
       ├─ KamuiManager::register_chain / unregister_chain()
       └─ KamuiManager::disable() → close_all()

main.rs (raw binary 0x30-0x39 dispatcher)
  ├─ kamui::handle_raw_tcp_data()   → KamuiManager::handle_tcp_data
  ├─ kamui::handle_raw_tcp_close()  → KamuiManager::handle_tcp_close
  ├─ kamui::handle_raw_tcp_pause()  → KamuiManager::handle_tcp_pause
  ├─ kamui::handle_raw_tcp_resume() → KamuiManager::handle_tcp_resume
  ├─ kamui::handle_raw_udp_bind()   → KamuiManager::handle_udp_bind
  ├─ kamui::handle_raw_udp_data()   → KamuiManager::handle_udp_data
  ├─ kamui::handle_raw_udp_close()  → KamuiManager::handle_udp_close
  └─ kamui::handle_raw_chain_data() → KamuiManager::handle_chain_data

juubi_chain::JuubiChainState::new() ← juubi::JuubiState::new()
  └─ eth_tx::derive_address()        [T-021 crypto]
  └─ eth_tx::keccak256()
  └─ eth_rpc::SEPOLIA_RPCS[]

juubi_chain::poll_raven_commands()
  └─ eth_rpc::get_block_number()     [T-021/T-022 boundary]
  └─ eth_rpc::get_logs(raven_contract, [EVENT_MESSAGE], ...)
  └─ parse_raven_message()           (ABI decode + optional XOR)

juubi_chain::register_peer()
  └─ eth_tx::encode_register_peer(client_hash, encrypted_endpoint, 0x01)
  └─ send_tx() → eth_rpc::sign_and_send()  [EIP-155]

juubi_chain::start_p2p_tunnel()
  └─ std::process::Command::new("cloudflared").args(["tunnel", "--url", ...])
  └─ BufReader::lines() → extract_cloudflare_url()
```

### Data flow

- **Command path (JSON):** Server WS frame → `MSG_COMMAND` (0x10) → `dispatch()` matches `cmd_type` → JSON `serde_json::from_str::<TcpOpenPayload>()` → `KamuiManager::*_open()`.
- **Binary path (TCP data):** Server WS frame `MSG_KAMUI_TCP_DATA` (0x30) → `handle_raw_tcp_data()` parses `[4B stream_id BE][data]` → `handle_tcp_data(stream_id, data)` → `inbound_tx.try_send(data)` → `tcp_write_task` consumes via `inbound_rx.recv().await` → `tcp_writer.write_all(&data).await`.
- **Reverse path:** TCP socket read → `tcp_read_task` → `build_tcp_data(stream_id, &buf[..n])` → `ws_tx.send(msg)` via `send_ws_static()`.
- **Chain data:** Server sends `MSG_KAMUI_CHAIN_DATA` (0x39) with `[4B chain_stream_id BE][data]` → `handle_chain_data()` looks up `chain_streams[chain_stream_id].target_stream_id` → forwards to `handle_tcp_data(target_stream_id, data)`.
- **On-chain commands:** Operator → `RavenC2.postMessage(uint256,address,bytes)` TX → emitted as `Message` event → client `poll_raven_commands()` → `eth_getLogs` → `parse_raven_message()` → `RavenCommand { msg_id, sender, data, text, block }` returned to caller (likely main.rs C2 loop).
- **On-chain responses:** Client output → `post_response(data)` → `eth_tx::encode_post_open(data)` → `send_tx()` → `RavenC2.postOpen(bytes)`.

### Type hierarchy

```
KamuiManager {                          // top-level manager (Arc'd via OnceLock)
    streams: Arc<Mutex<HashMap<u32, KamuiStream>>>,
    udp_relays: Arc<Mutex<HashMap<u32, KamuiUdpRelay>>>,
    chain_streams: Arc<Mutex<HashMap<u32, KamuiChainStream>>>,
    ws_tx: Arc<Mutex<Option<UnboundedSender<Vec<u8>>>>>,
    enabled: Arc<AtomicBool>,
}

KamuiStream {                           // one TCP connection
    stream_id: u32,
    target: String,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    abort_handle: JoinHandle<()>,
    resume_notify: Arc<Notify>,
    paused: Arc<AtomicBool>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
}

KamuiUdpRelay {                         // one UDP listener
    relay_id: u32,
    socket: Arc<UdpSocket>,
    abort_handle: JoinHandle<()>,
}

KamuiChainStream { chain_stream_id, target_stream_id }

JuubiState {                            // relay state + HMAC auth
    enabled, can_relay, max_streams, authenticated: bool/u8,
    outbound_streams: HashMap<u32, String>,
    inbound_streams: HashMap<u32, Vec<u8>>,
    last_peer_list: Vec<Value>,
    secret_token: Vec<u8>,
    wallet_address: String,
}

JuubiChainState {                       // on-chain C2 state
    contract_address, raven_contract, rpc_url: String,
    wallet_key: [u8; 32],
    encryption_key: [u8; 32],
    registered, enabled: bool,
    known_peers: Vec<ChainPeer>,
    last_raven_block, last_registry_block: u64,
    local_nonce: Option<u64>,
    poll_interval_secs: u64,
    xor_key: Vec<u8>,
    p2p_method: String,
    p2p_tunnel_url: Option<String>,
}

RavenCommand { msg_id, sender, data, text, block }
PeerMessage { from_hash, to_hash, data, block }
ChainPeer { client_hash, endpoint, capabilities, last_seen }
```

### Feature gates

No `#[cfg(feature = ...)]` gates in any of the three analyzed files. The suite is **always compiled** when `client_rust` is built. The runtime gating is via env vars: `JUUBI_ENABLED`, `JUUBI_CHAIN_ENABLED`, `JUUBI_CAN_RELAY`, `JUUBI_MAX_STREAMS`, `JUUBI_SECRET`, `JUUBI_CONTRACT_ADDRESS`, `RAVEN_CONTRACT_ADDRESS` / `SEPOLIA_CONTRACT_ADDRESS`, `JUUBI_RPC_URL` / `SEPOLIA_RPC_URL`, `JUUBI_CHAIN_KEY`, `JUUBI_ENCRYPTION_KEY`, `XOR_KEY`, `JUUBI_P2P_METHOD`, `CHAIN_POLL_INTERVAL_SECS`.

## Operational Profile

### When to Use

- **Kamui** — Post-compromise lateral movement when you need to proxy RDP/SSH/HTTP through the compromised host. Use for SSH tunneling, internal web app pivoting, MSSQL access from a beachhead.
- **Juubi** — When the operator infrastructure supports peer-relay routing and you want clients to mesh-connect through each other (asymmetric egress hardening).
- **JuubiChain** — **Last-resort C2 fallback** when the WebSocket C2 server is down, sinkholed, or actively blocked. Operators post commands on-chain as `RavenC2.postMessage()` TXs; clients poll `eth_getLogs` and execute. Blockchain history is censorship-resistant — short of the operator losing their wallet key or Sepolia itself going down, the channel stays alive.

### When NOT to Use

- **Kamui** on hosts where multiple outbound TCP connections to arbitrary ports will trigger EDR network behavioral rules. The 32KB read buffer + many concurrent streams is a fingerprint.
- **Juubi** with default `JUUBI_SECRET="raven-juubi-default"` — that secret is in the source code, anyone with the binary can forge auth responses.
- **JuubiChain** when OPSEC forbids on-chain traces. Sepolia is a public testnet — all TXs are visible to anyone. Wallet addresses used once are correlated forever. Also avoid if gas costs are an issue (Sepolia faucet dependency).
- **cloudflared P2P tunnel** in air-gapped environments — `trycloudflare.com` requires outbound HTTPS to Cloudflare edge.

### Kill Chain Position

Example chain:

```
T-022 (Kamui SOCKS5) ← pivot through beachhead
   ↳ T-022 (Juubi peer-relay) ← mesh with other clients
        ↳ T-022 (JuubiChain) ← on-chain C2 fallback
             ↳ T-023 (Client Capabilities: screen capture, keylogger) ← execute on target
                  ↳ T-019 (Edo Dead Drop) ← dead-drop exfil if chain C2 also burned
```

Standalone positioning: T-022 sits at the **C2 transport** layer between T-023 (client capabilities) and T-019 (Edo dead drop). It's the redundant path that keeps T-023 alive when primary infrastructure is burned.

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` blocks

**None** in any of the three files. This is purely safe Rust — the danger lives in the protocol surface and the cryptographic correctness, not in pointer manipulation. Operators modifying these files don't need to worry about memory unsafety, but they *do* need to worry about:

- HMAC-SHA256 correctness (the hand-rolled `sha256()` is bit-exact RFC 6234 but easy to typo)
- ABI decoding correctness (manual hex parsing in `parse_raven_message`)
- Stream ID race conditions in `handle_failover()` (see Edge Cases)

### `core::arch::asm!` usage

**None.** These are high-level networking files, not syscall stubs. The asm work happens in `dark_crystal/crowd` (T-001 RecycledGate, T-002 VEH Gate).

### FFI patterns

No direct FFI to Windows APIs in these files. The only external binary interaction is `std::process::Command::new("cloudflared")` in `juubi_chain.rs::start_p2p_tunnel()` (L605):

```rust
let mut child = std::process::Command::new("cloudflared")
    .args(["tunnel", "--url", &format!("http://localhost:{}", local_port)])
    .stderr(std::process::Stdio::piped())
    .stdout(std::process::Stdio::null())
    .spawn()?;
```

The child's stderr is consumed line-by-line via `std::io::BufReader::new(stderr).lines()` until a `trycloudflare.com` URL is found or the stream ends. **The child is never explicitly killed** — when the function returns and `child` drops, the OS reaps it on Windows only if the parent exits cleanly; otherwise cloudflared may persist as an orphan. 

### Initialization patterns

- **OnceLock singleton** (kamui.rs L920-L928):
  ```rust
  static KAMUI: OnceLock<Arc<KamuiManager>> = OnceLock::new();
  pub fn get_manager() -> Arc<KamuiManager> {
      KAMUI.get_or_init(|| Arc::new(KamuiManager::new())).clone()
  }
  ```
  Provides shared ownership across async tasks without `lazy_static!`. Lifetime is process-wide.

- **Env-var driven config** (juubi_chain.rs L82-L137): every field is read from env vars at `new()` time. No config file. Operators must inject env vars before spawning the client (typically via the dropper's payload_cfg).

- **Random key fallback** (juubi_chain.rs L107-L110):
  ```rust
  if wallet_key == [0u8; 32] {
      use rand::RngCore;
      rand::thread_rng().fill_bytes(&mut wallet_key);
  }
  ```
  If `JUUBI_CHAIN_KEY` is unset, a fresh secp256k1 private key is generated. **OPSEC warning**: this generated key has no persistence — restarting the client creates a new identity, losing all on-chain registration history. 

### Error handling

- `anyhow::Result<String>` for all TX-sending functions (`send_tx`, `post_response`, `register_peer`, `send_peer_message`, `start_p2p_tunnel`). Errors propagate via `?` and `anyhow::bail!`.
- `Option<RavenCommand>` / `Option<PeerMessage>` for log parsers (`parse_raven_message`, `parse_peer_registered`, `parse_peer_message`) — return `None` on any decode failure (too-short data, missing topics, hex parse failure).
- `Result<Ok(stream) | Ok(Err(io::Error)) | Err(Elapsed)>` for TCP connect timeout in `handle_tcp_open` (kamui.rs L160-L178) — three-way match: connect OK, connect error, or timeout.
- `mpsc::error::TrySendError<T>` matched in `handle_tcp_data` (L219-L233) for `Full` vs `Closed` distinction.
- Errors are logged via `tracing::{warn, debug}` but **not surfaced** to the server except via `build_tcp_error()` for the connect path. Silent failures in `discover_peers`, `poll_peer_messages`, `poll_raven_commands` make operator debugging hard.

### Memory layout

- `KamuiStream` (kamui.rs L90-L116): ~120 bytes base + Arc clones for `resume_notify`, `paused`, `bytes_up`, `bytes_down` (each Arc is 8 bytes pointer + atomic). The `inbound_tx` is 8 bytes. The `abort_handle` (JoinHandle) is ~16 bytes. Total per-stream overhead: ~150 bytes + the mpsc channel buffer (256 * sizeof(Vec<u8>) ≈ 8KB on 64-bit).
- `JuubiChainState` (juubi_chain.rs L50-L80): ~400 bytes base (three Strings for contracts/rpc, two `[u8; 32]` arrays, a Vec<ChainPeer> for known_peers which grows unboundedly, a Vec<u8> for xor_key).
- UDP recv buffer (kamui.rs L389): `vec![0u8; 65536]` per relay — 64KB stack-allocated in the spawned task.

### Syscall / RPC numbers

Not directly relevant — these are userspace networking files. The interesting "magic numbers" are:

- **Ethereum event topic hashes** (juubi_chain.rs L20-L30):
  - `EVENT_MESSAGE = 0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df` — keccak256("Message(uint256,address,bytes)")
  - `EVENT_PEER_REGISTERED = 0xa71e3eca649102f38f810c3fb9d85f180efe68d43390273cf4599b9c696670a1` — keccak256("PeerRegistered(bytes32,uint256)")
  - `EVENT_PEER_MESSAGE = 0xe73cfe82c71a5ae5c0bb1cee2315e1761f4ff2afe3e8c18b8f2b4a0a140c9f8f` — keccak256("PeerMessage(bytes32,bytes32,bytes)")
- **Kamui message types** (kamui.rs L19-L36): 0x30-0x39 — see `key_constants` above.
- **Sepolia chain ID** (from `eth_tx::SEPOLIA_CHAIN_ID`, not defined in these files): 11155111.
- **First-poll lookback** (juubi_chain.rs L285): `current_block.saturating_sub(1000)` for RavenC2, `saturating_sub(5000)` for JuubiRegistry.
- **Block window cap** (juubi_chain.rs L293): `current_block.min(from_block + 5000)`.

## Cross-References Found in Code

- `juubi.rs:14` → imports `crate::protocol::{build_message, MSG_JUUBI_HELLO, MSG_JUUBI_AUTH_RESP}` — depends on T-022 protocol layer (`src/protocol.rs`)
- `juubi.rs:40` → calls `crate::juubi_chain::JuubiChainState::new()` and `.wallet_address()` — depends on T-022 `juubi_chain.rs`
- `juubi_chain.rs:14` → imports `crate::eth_tx` — depends on T-021 (Crypto & Obfuscation, "Pure Rust EIP-155 TX signing")
- `juubi_chain.rs:15` → imports `crate::eth_rpc` — depends on T-021/T-022 (Crypto & Obfuscation, "Ethereum JSON-RPC client")
- `juubi_chain.rs:155-157` → references `eth_rpc::SEPOLIA_RPCS` constant array — T-021 dependency
- `juubi_chain.rs:184` → calls `eth_tx::derive_address()` (secp256k1 → keccak256) — T-021 dependency
- `juubi_chain.rs:189` → calls `eth_tx::keccak256()` — T-021 dependency
- `juubi_chain.rs:380, 420, 584` → calls `eth_tx::encode_post_open`, `encode_register_peer`, `encode_send_message` for ABI calldata construction — T-021 dependency
- `juubi_chain.rs:234` → calls `eth_rpc::sign_and_send(..., eth_tx::SEPOLIA_CHAIN_ID)` — T-021 dependency
- `kamui.rs:693` → references `crate::protocol::MSG_CMD_OUTPUT` — depends on T-022 protocol layer
- `kamui.rs:898-L916` → `shutdown()` is intended to be called from a higher-level cleanup, likely in T-023 (`commands.rs` ClientState teardown)
- The card references these **not-analyzed** files: `hvnc.rs` (T-022 HVNC), `vnc_server.rs` (T-022 VNC/RFB), `henge.rs` (T-022 Malleable C2), `rikudo.rs` (T-022 multi-chain vault), `http_poll_transport.rs` (T-022 HTTP poll), `discovery.rs` (T-022 server discovery), `crowd/src/experimental/evasion/nt_sockets.rs` (T-022 NT sockets via AFD driver), `crowd/src/byovd.rs` (T-022/T-018 BYOVD). The `discovery.rs` file uses the same AES-GCM → XOR → ROT13 cascade mentioned in T-021 (Crypto), confirming the networking ↔ crypto module boundary.

## Edge Cases & Failure Modes

1. **"Nonce too low" on Ethereum TX submission**
   - Triggered when local nonce cache is stale (e.g. another TX from same wallet was mined between `get_nonce` and `send_tx`).
   - `send_tx()` (juubi_chain.rs L228-L237) catches the error string, clears `self.local_nonce = None`, calls `next_nonce()` again, retries `sign_and_send` once.
   - **Symptom**: First attempt fails, second attempt succeeds (usually). If both fail, the function returns the error to caller, no further retry.

2. **Inbound mpsc channel full (backpressure burst)**
   - Triggered when server sends data faster than the TCP write task can drain.
   - `handle_tcp_data()` (kamui.rs L219) gets `TrySendError::Full`, sends `TCP_CLOSE` with reason `"inbound buffer overflow"`, and closes the stream.
   - **Symptom**: Stream drops unexpectedly during high-throughput transfer (e.g. HTTP file download through proxy).
   - **Workaround**: increase `INBOUND_CHANNEL_CAPACITY` (L41) from 256 to 1024+. Better: implement proper flow control via `KAMUI_TCP_PAUSE` on the server side when the queue hits 80%.

3. **UDP datagram exceeds 65536 bytes**
   - Triggered when local application sends a jumbo datagram (rare on standard networks, common on loopback with offload).
   - The recv buffer (kamui.rs L389) is `vec![0u8; 65536]` — recv_from will truncate silently.
   - **Symptom**: Application sees corrupted/incomplete datagrams.
   - **Workaround**: increase to 65536 (already max for IPv4) — fundamentally a UDP limitation, not fixable.

4. **cloudflared not in PATH**
   - Triggered on hosts without cloudflared installed.
   - `start_p2p_tunnel()` (juubi_chain.rs L605) returns `Err(anyhow!("Failed to spawn cloudflared: {}", e))`.
   - **Symptom**: P2P tunnel establishment fails, peer relay degraded to direct TCP only.
   - **Workaround**: ship cloudflared.exe alongside the implant, or fall back to `nt_sockets.rs` HTTP polling (T-022 NT sockets, not analyzed here).

5. **cloudflared stderr doesn't emit `trycloudflare.com` URL**
   - Triggered when cloudflared hits a network error, rate limit, or auth failure.
   - The for-loop (juubi_chain.rs L617-L623) consumes stderr until EOF without finding a URL.
   - `tunnel_url.ok_or_else(|| anyhow!("cloudflared did not emit a tunnel URL"))` returns the error.
   - **Symptom**: `start_p2p_tunnel()` returns Err, caller must handle.
   - **Workaround**: spawn with retries, or use a fixed cloudflared named tunnel with pre-registered credentials.

6. **WebSocket disconnect during active TCP relay**
   - Triggered when the C2 WS drops mid-stream.
   - `send_ws_static()` (kamui.rs L574) returns `false` because `tx.send(msg).is_err()`. The read task's `if !Self::send_ws_static(...) { break }` exits the loop.
   - The select! in handle_tcp_open's spawn catches the read task's completion, the write task is dropped, the stream is removed from the map.
   - **Symptom**: All Kamui streams die gracefully on WS loss. The client's main loop must reconnect WS and re-issue `KAMUI_START` to resume.
   - **Workaround**: persist stream metadata (target host:port pairs) so the server can re-establish streams automatically after reconnect.

7. **Duplicate stream_id**
   - Triggered when server reuses a stream_id (e.g. after a reconnect).
   - `handle_tcp_open()` (kamui.rs L150-L157) checks `streams.contains_key(&stream_id)`, drops the lock, calls `handle_tcp_close(stream_id)` to tear down the old stream, then proceeds.
   - **Symptom**: Brief blip in service for that stream_id; new connection succeeds.
   - **Workaround**: server should use monotonically increasing stream_ids to avoid ambiguity.

8. **TUNNEL| prefix messages on-chain**
   - Triggered when the operator's discovery system writes tunnel URLs to RavenC2.
   - `parse_raven_message()` (juubi_chain.rs L366-L372) checks `text.starts_with("TUNNEL|")` and returns `None`.
   - **Symptom**: these messages are silently skipped — not surfaced as commands. Operator's intent was discovery, not command execution, so this is by design.
   - **Workaround**: none needed. Document that TUNNEL| prefix is reserved for discovery.

9. **`parse_raven_message` on too-short data**
   - Triggered by malformed or partially-decoded ABI data.
   - `raw_data.len() < 128` check (juubi_chain.rs L327) returns `None`.
   - **Symptom**: log entry silently dropped. No error surfaced.
   - **Workaround**: add debug logging to count dropped logs for diagnostics.

10. **`handle_failover()` race condition**
    - Triggered when data arrives for `old_id` between the `inbound_streams.remove(&old_id)` and `inbound_streams.insert(new_id, data)` calls.
    - The two operations are not in a single transaction (juubi.rs L130-L134).
    - **Symptom**: small window where data for old_id is dropped (no entry exists).
    - **Workaround**: hold a Mutex during the migration, or use a single `HashMap` entry swap.

## OPSEC Notes

### Artifacts left by Kamui

- **Multiple outbound TCP connections** from the client host to arbitrary IPs/ports. Easy for a SOC to flag — host suddenly talks to many internal systems on non-standard ports.
- **`TCP_NODELAY` enabled** on every relayed socket (kamui.rs L172). Disables Nagle's algorithm — produces smaller, more frequent packets. Behavioral signature: traffic pattern looks like proxied interactive sessions.
- **65536-byte UDP socket buffers** on `0.0.0.0:{port}` — local port bindings visible in `netstat -ano`. SOCKS5 UDP relay signature.
- **Spawned tokio tasks** show up as additional threads in the client process — `Process Explorer` will show extra threads with `ntdll.dll!NtDeviceIoControlFile` stack traces (AFD for sockets).

### Artifacts left by JuubiChain

- **Ethereum transactions on Sepolia testnet** — public, permanent, indexed by every block explorer. Wallet address correlation is forever. The `RavenC2.Message` event topic `0xafb4ccb...` is fingerprintable — defenders watching Sepolia for that topic hash will catch every command post.
- **`TUNNEL|https://*.trycloudflare.com` plaintext** in on-chain message data when XOR_KEY is unset (default is empty vec per `unwrap_or_default()`). Anyone scraping RavenC2 logs can extract tunnel URLs.
- **cloudflared child process** — visible in process tree as `cloudflared.exe tunnel --url http://localhost:PORT`. Cloudflare's `trycloudflare.com` subdomain in DNS query logs is a hard IOC.
- **Random wallet generation fallback** (juubi_chain.rs L107-L110) — if `JUUBI_CHAIN_KEY` isn't set, a new wallet is generated on every restart. Registration history is lost, but worse: each restart creates a new `PeerRegistered` event on-chain, bloating the audit trail.

### Cleanup

- `KamuiManager::close_all()` (kamui.rs L469) drains streams/relays/chains and aborts all tasks. Called by `disable()` and `shutdown()`.
- `clear_ws_sender()` (kamui.rs L134) releases the WS sender handle.
- No cleanup for cloudflared child process — see "Variant Ideas" #4.
- No on-chain cleanup (transactions are immutable).
- No PEB unlinking or process hollowing — these are network-only files.

### Telemetry emission

- `tracing::{info, warn, debug}` calls are sprinkled throughout. In a production build with `tracing_subscriber` initialized, these emit structured logs that may end up in Windows Event Log or stdout. 

## Reusable Patterns

### Pattern: OnceLock + Arc Singleton Manager

- **Use when**: a stateful resource manager (network, threads, devices) needs to be reachable from multiple call sites without explicit threading through arguments.
- **Code ref**: `kamui.rs:get_manager()` (L920-L928)
- **How**: `static KAMUI: OnceLock<Arc<KamuiManager>> = OnceLock::new();` lazily initialized via `get_or_init`. Returns an `Arc` clone — cheap to share across async tasks. Lifetime is process-wide; the manager is never dropped.

### Pattern: `tokio::select!` for Bidirectional Relay

- **Use when**: two async tasks must run until either finishes, with the survivor cancelled.
- **Code ref**: `kamui.rs:handle_tcp_open()` spawned task (L196-L210)
- **How**:
  ```rust
  tokio::select! {
      _ = read_fut => { /* read task done */ }
      _ = write_fut => { /* write task done */ }
  }
  ```
  The first to complete cancels the other via the implicit `drop` of the unselected future.

### Pattern: AtomicBool + Notify for Cooperative Backpressure

- **Use when**: producer should pause without busy-waiting; consumer should wake immediately on resume.
- **Code ref**: `kamui.rs:tcp_read_task()` (L517-L524) + `handle_tcp_resume()` (L274-L285)
- **How**:
  ```rust
  while paused.load(std::sync::atomic::Ordering::SeqCst) {
      resume_notify.notified().await;
  }
  ```
  Atomic flag is cheap to read; `Notify::notified()` parks the task without spinning. Resume side: `paused.store(false, SeqCst); resume_notify.notify_one();`

### Pattern: `mpsc::try_send` + Graceful Close on Full

- **Use when**: bounded channel where overflow should kill the stream rather than block the producer.
- **Code ref**: `kamui.rs:handle_tcp_data()` (L215-L243)
- **How**: `match stream.inbound_tx.try_send(data) { Ok(()) => {}, Err(Full(_)) => close_with("inbound buffer overflow"), Err(Closed(_)) => close_with("stream closed") }`. Prevents OOM, surfaces failures to peer as explicit close frames.

### Pattern: Pure Rust Crypto (no `sha2` crate)

- **Use when**: dependency minimization, supply chain hardening, or compile-time crypto agility.
- **Code ref**: `juubi.rs:sha256()` (L182-L260)
- **How**: `Wrapping<u32>` for overflow safety, `K[64]` constants inlined, manual 0x80 + zero padding to 64-byte boundary + 8-byte big-endian length. ~80 lines of code, no external deps. Trade-off: harder to audit, easy to typo a rotation constant.

### Pattern: Nonce Cache with Chain Max

- **Use when**: concurrent in-flight transactions to the same Ethereum address need nonce coordination.
- **Code ref**: `juubi_chain.rs:next_nonce()` (L208-L219)
- **How**:
  ```rust
  let chain_nonce = eth_rpc::get_nonce(&addr, rpcs)?;
  let nonce = match self.local_nonce {
      Some(local) => chain_nonce.max(local + 1),
      None => chain_nonce,
  };
  self.local_nonce = Some(nonce);
  ```
  Local cache prevents collisions across concurrent `send_tx` calls within the same block window.

### Pattern: External Binary stderr Line Scanner

- **Use when**: leveraging a system tool whose output format is informal (logs, not structured).
- **Code ref**: `juubi_chain.rs:start_p2p_tunnel()` (L597-L626) + `extract_cloudflare_url()` (L632-L641)
- **How**: spawn child with `stderr(Stdio::piped())`, wrap in `BufReader`, iterate `.lines()`, substring-match for the URL pattern. No regex, no parser combinator — just `str::find("https://")` + `char::is_whitespace` boundary detection. Fragile but works for cloudflared's stable log format.

### Pattern: Env-Var Driven Config (No Config File)

- **Use when**: dropper needs to inject config post-compile without recompiling.
- **Code ref**: `juubi_chain.rs:new()` (L82-L137) — 15+ env vars covering every tunable field.
- **How**: each field is `std::env::var("KEY").unwrap_or_default()` or `.unwrap_or(fallback)`. The dropper sets env vars in the spawned child process before `CreateProcess`. No on-disk config file = no forensic config artifact. Trade-off: env vars are visible in `Process Hacker → Properties → Environment`.
