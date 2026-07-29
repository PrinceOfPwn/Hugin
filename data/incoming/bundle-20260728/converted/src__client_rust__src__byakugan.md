# Byakugan (白眼) — 360° network reconnaissance engine (client side).

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/byakugan.rs` |
| **Lines** | 1385 |
| **Cards** | T023-client-capabilities, T021-patterns |
| **Role** | Network recon (ARP, TCP, AD enum), OnceLock cancellation pattern |

## Purpose

Byakugan (白眼) — 360° network reconnaissance engine (client side).

Handles: ARP scan, TCP port scan, banner grab, AD enumeration, passive discovery.

Message types (client → server):
0x40 MSG_BYAKUGAN_SCAN_RESULT: JSON {scan_id, scan_type, data}
0x41 MSG_BYAKUGAN_HOST:        JSON {scan_id, host: {ip, mac, hostname, ...}}
0x42 MSG_BYAKUGAN_ERROR:       JSON {scan_id, error}

## Constants

- `MSG_BYAKUGAN_SCAN_RESULT`: `u8` = `0x40`
- `MSG_BYAKUGAN_HOST`: `u8` = `0x41`
- `MSG_BYAKUGAN_ERROR`: `u8` = `0x42`
- `PORT_SCAN_BATCH_SIZE`: `usize` = `100`
- `PORT_SCAN_TIMEOUT_MS`: `u64` = `2000`
- `BANNER_GRAB_TIMEOUT_MS`: `u64` = `3000`
- `MAX_BANNER_BYTES`: `usize` = `1024`
- `DEFAULT_PASSIVE_DURATION_SECS`: `u64` = `30`
- `PASSIVE_POLL_INTERVAL_SECS`: `u64` = `5`

## Types

### struct `ArpScanRequest` (line 70)

### struct `PortScanRequest` (line 77)

### struct `BannerGrabRequest` (line 89)

### struct `AdEnumRequest` (line 96)

### struct `PassiveRequest` (line 101)

### struct `CancelRequest` (line 112)

## Public API

### `cancel` (line 50)
```rust
pub fn cancel(scan_id: u32)
```

### `is_cancelled` (line 56)
```rust
pub fn is_cancelled(scan_id: u32) -> bool
```

### `clear` (line 60)
```rust
pub fn clear(scan_id: u32)
```

## Internal Functions

- `get` (line 46)
- `default_port_range` (line 84)
- `default_passive_duration` (line 107)
- `build_message` (line 118)
- `build_error` (line 126)
- `build_host_msg` (line 134)
- `build_scan_result` (line 142)
- `get_probe_for_port` — Returns probe bytes appropriate for common ports. (line 368)
- `parse_arp_output` — Parse `arp -a` output into a list of host objects. (line 657)
- `parse_arp_line_windows` — Parse a single Windows-format ARP line. (line 682)
- `parse_arp_line_unix` — Parse a single Unix-format ARP line. (line 717)
- `parse_local_interfaces` — Parse local interface info from ipconfig /all (Windows) or ip addr (Unix). (line 756)
- `extract_after_colon` — Extract value after the last colon in a line. (line 832)
- `parse_nltest_output` (line 844)
- `parse_net_user_output` — Parse `net user /domain` or `net group "Domain Admins" /domain` output. (line 871)
- `parse_net_group_output` — Parse `net group /domain` output. Groups are prefixed with *. (line 904)
- `parse_nbtstat_output` (line 936)
- `parse_port_range` — Parse a port range string like "1-1024" or "80" into (start, end). (line 964)
- `guess_service` — Guess the service name for a well-known port. (line 984)
- `test_parse_port_range_valid` (line 1130)
- `test_parse_port_range_invalid` (line 1139)
- `test_guess_service` (line 1148)
- `test_parse_arp_line_windows` (line 1158)
- `test_parse_arp_line_windows_broadcast` (line 1169)
- `test_parse_arp_line_unix` (line 1176)
- `test_parse_arp_line_unix_unknown_host` (line 1187)
- `test_parse_arp_line_unix_incomplete` (line 1197)
- `test_parse_arp_output_mixed` (line 1204)
- `test_parse_arp_output_unix` (line 1219)
- `test_parse_net_user_output` (line 1232)
- `test_parse_net_group_output` (line 1249)
- `test_extract_after_colon` (line 1267)
- `test_build_message_format` (line 1281)
- `test_build_error` (line 1291)
- `test_build_host_msg` (line 1302)
- `test_build_scan_result` (line 1314)
- `test_get_probe_for_port` (line 1327)
- `test_cancel_registry` (line 1336)
- `test_parse_local_interfaces_windows` (line 1346)

## Key Dependencies

- `use serde::Deserialize;`
- `use tracing::{debug, error, info, warn};`
- `use tokio::io::{AsyncReadExt, AsyncWriteExt};`
- `use super::*;`

## Full Source

```rust
//! Byakugan (白眼) — 360° network reconnaissance engine (client side).
//!
//! Handles: ARP scan, TCP port scan, banner grab, AD enumeration, passive discovery.
//!
//! Message types (client → server):
//!   0x40 MSG_BYAKUGAN_SCAN_RESULT: JSON {scan_id, scan_type, data}
//!   0x41 MSG_BYAKUGAN_HOST:        JSON {scan_id, host: {ip, mac, hostname, ...}}
//!   0x42 MSG_BYAKUGAN_ERROR:       JSON {scan_id, error}

use serde::Deserialize;
use std::collections::HashSet;
use tracing::{debug, error, info, warn};

// --- Protocol constants ---

pub const MSG_BYAKUGAN_SCAN_RESULT: u8 = 0x40;
pub const MSG_BYAKUGAN_HOST: u8 = 0x41;
pub const MSG_BYAKUGAN_ERROR: u8 = 0x42;

/// Max concurrent TCP connections during port scan.
const PORT_SCAN_BATCH_SIZE: usize = 100;

/// TCP connect timeout for port scanning.
const PORT_SCAN_TIMEOUT_MS: u64 = 2000;

/// Banner grab read timeout.
const BANNER_GRAB_TIMEOUT_MS: u64 = 3000;

/// Max banner bytes to read.
const MAX_BANNER_BYTES: usize = 1024;

/// Default passive discovery duration.
const DEFAULT_PASSIVE_DURATION_SECS: u64 = 30;

/// Passive discovery poll interval.
const PASSIVE_POLL_INTERVAL_SECS: u64 = 5;

// --- Cancellation registry (OnceLock-based, no external deps) ---

mod cancel_registry {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static CANCELLED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

    fn get() -> &'static Mutex<HashSet<u32>> {
        CANCELLED.get_or_init(|| Mutex::new(HashSet::new()))
    }

    pub fn cancel(scan_id: u32) {
        if let Ok(mut set) = get().lock() {
            set.insert(scan_id);
        }
    }

    pub fn is_cancelled(scan_id: u32) -> bool {
        get().lock().map(|set| set.contains(&scan_id)).unwrap_or(false)
    }

    pub fn clear(scan_id: u32) {
        if let Ok(mut set) = get().lock() {
            set.remove(&scan_id);
        }
    }
}

// --- Request structs ---

#[derive(Debug, Deserialize)]
struct ArpScanRequest {
    scan_id: u32,
    #[serde(default)]
    target_subnet: String,
}

#[derive(Debug, Deserialize)]
struct PortScanRequest {
    scan_id: u32,
    target_host: String,
    #[serde(default = "default_port_range")]
    port_range: String,
}

fn default_port_range() -> String {
    "1-1024".to_string()
}

#[derive(Debug, Deserialize)]
struct BannerGrabRequest {
    scan_id: u32,
    target_host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct AdEnumRequest {
    scan_id: u32,
}

#[derive(Debug, Deserialize)]
struct PassiveRequest {
    scan_id: u32,
    #[serde(default = "default_passive_duration")]
    duration_secs: u64,
}

fn default_passive_duration() -> u64 {
    DEFAULT_PASSIVE_DURATION_SECS
}

#[derive(Debug, Deserialize)]
struct CancelRequest {
    scan_id: u32,
}

// --- Message builders ---

fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(msg_type);
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

fn build_error(scan_id: u32, error: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "scan_id": scan_id,
        "error": error,
    });
    build_message(MSG_BYAKUGAN_ERROR, json.to_string().as_bytes())
}

fn build_host_msg(scan_id: u32, host: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::json!({
        "scan_id": scan_id,
        "host": host,
    });
    build_message(MSG_BYAKUGAN_HOST, json.to_string().as_bytes())
}

fn build_scan_result(scan_id: u32, scan_type: &str, data: serde_json::Value) -> Vec<u8> {
    let json = serde_json::json!({
        "scan_id": scan_id,
        "scan_type": scan_type,
        "data": data,
    });
    build_message(MSG_BYAKUGAN_SCAN_RESULT, json.to_string().as_bytes())
}

// ===================================================================
// ARP Scan
// ===================================================================

async fn handle_arp_scan(req: ArpScanRequest) -> Vec<Vec<u8>> {
    let scan_id = req.scan_id;
    info!("[byakugan] ARP scan: scan_id={}, subnet={}", scan_id, req.target_subnet);
    cancel_registry::clear(scan_id);

    let mut replies = Vec::new();

    // Run arp -a and ipconfig/ifconfig
    let arp_output = run_system_command("arp", &["-a"]).await;
    let hosts = parse_arp_output(&arp_output);

    // Also gather local interface info
    #[cfg(target_os = "windows")]
    let ifconfig_output = run_system_command("ipconfig", &["/all"]).await;
    #[cfg(not(target_os = "windows"))]
    let ifconfig_output = run_system_command("ip", &["addr"]).await;

    let local_info = parse_local_interfaces(&ifconfig_output);

    for host in &hosts {
        if cancel_registry::is_cancelled(scan_id) {
            info!("[byakugan] ARP scan {} cancelled", scan_id);
            replies.push(build_error(scan_id, "cancelled"));
            cancel_registry::clear(scan_id);
            return replies;
        }

        replies.push(build_host_msg(scan_id, host));
    }

    let summary = serde_json::json!({
        "hosts": hosts,
        "hosts_found": hosts.len(),
        "local_interfaces": local_info,
    });
    replies.push(build_scan_result(scan_id, "arp_scan", summary));

    info!("[byakugan] ARP scan {}: {} hosts found", scan_id, hosts.len());
    cancel_registry::clear(scan_id);
    replies
}

// ===================================================================
// Port Scan
// ===================================================================

async fn handle_port_scan(req: PortScanRequest) -> Vec<Vec<u8>> {
    let scan_id = req.scan_id;
    let target = req.target_host.clone();
    info!(
        "[byakugan] Port scan: scan_id={}, target={}, range={}",
        scan_id, target, req.port_range
    );
    cancel_registry::clear(scan_id);

    let (start_port, end_port) = match parse_port_range(&req.port_range) {
        Some(range) => range,
        None => {
            return vec![build_error(
                scan_id,
                &format!("invalid port range: {}", req.port_range),
            )];
        }
    };

    let mut replies = Vec::new();
    let mut open_ports: Vec<serde_json::Value> = Vec::new();
    let mut scanned_count: u32 = 0;

    let total_ports = (end_port - start_port + 1) as usize;
    let mut port = start_port;

    while port <= end_port {
        if cancel_registry::is_cancelled(scan_id) {
            info!("[byakugan] Port scan {} cancelled at port {}", scan_id, port);
            replies.push(build_error(scan_id, "cancelled"));
            cancel_registry::clear(scan_id);
            return replies;
        }

        // Build a batch of ports to scan concurrently
        let batch_end = std::cmp::min(port + PORT_SCAN_BATCH_SIZE as u16, end_port + 1);
        let mut tasks = Vec::with_capacity(PORT_SCAN_BATCH_SIZE);

        for p in port..batch_end {
            let host = target.clone();
            tasks.push(tokio::spawn(async move {
                scan_single_port(&host, p).await
            }));
        }

        for (i, task) in tasks.into_iter().enumerate() {
            let p = port + i as u16;
            match task.await {
                Ok(true) => {
                    let service = guess_service(p);
                    let host_info = serde_json::json!({
                        "ip": target,
                        "port": p,
                        "state": "open",
                        "service": service,
                    });
                    replies.push(build_host_msg(scan_id, &host_info));
                    open_ports.push(host_info);
                }
                Ok(false) => {}
                Err(e) => {
                    debug!("[byakugan] Port scan task error for port {}: {}", p, e);
                }
            }
        }

        scanned_count += (batch_end - port) as u32;
        port = batch_end;
    }

    let summary = serde_json::json!({
        "target": target,
        "port_range": req.port_range,
        "ports_scanned": scanned_count,
        "total_ports": total_ports,
        "open_ports": open_ports,
        "open_count": open_ports.len(),
    });
    replies.push(build_scan_result(scan_id, "port_scan", summary));

    info!(
        "[byakugan] Port scan {}: {}/{} ports open on {}",
        scan_id,
        open_ports.len(),
        total_ports,
        target
    );
    cancel_registry::clear(scan_id);
    replies
}

async fn scan_single_port(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    let timeout = std::time::Duration::from_millis(PORT_SCAN_TIMEOUT_MS);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

// ===================================================================
// Banner Grab
// ===================================================================

async fn handle_banner_grab(req: BannerGrabRequest) -> Vec<Vec<u8>> {
    let scan_id = req.scan_id;
    let target = req.target_host.clone();
    let port = req.port;
    info!(
        "[byakugan] Banner grab: scan_id={}, target={}:{}",
        scan_id, target, port
    );

    let addr = format!("{}:{}", target, port);
    let timeout = std::time::Duration::from_millis(BANNER_GRAB_TIMEOUT_MS);

    // Connect
    let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return vec![build_error(
                scan_id,
                &format!("connect to {}:{} failed: {}", target, port, e),
            )];
        }
        Err(_) => {
            return vec![build_error(
                scan_id,
                &format!("connect to {}:{} timed out", target, port),
            )];
        }
    };

    // Send probe based on port
    let probe = get_probe_for_port(port);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = stream;

    // Send probe if applicable
    if !probe.is_empty() {
        if let Err(e) = stream.write_all(&probe).await {
            return vec![build_error(scan_id, &format!("probe send failed: {}", e))];
        }
    }

    // Read response (banner)
    let mut buf = vec![0u8; MAX_BANNER_BYTES];
    let banner = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
        Ok(Ok(_)) => "(empty response)".to_string(),
        Ok(Err(e)) => format!("(read error: {})", e),
        Err(_) => "(no response within timeout)".to_string(),
    };

    let result = serde_json::json!({
        "target": target,
        "port": port,
        "banner": banner,
        "banner_bytes": banner.len(),
        "service": guess_service(port),
    });
    vec![build_scan_result(scan_id, "banner_grab", result)]
}

/// Returns probe bytes appropriate for common ports.
fn get_probe_for_port(port: u16) -> Vec<u8> {
    match port {
        80 | 8080 | 8000 | 8888 => b"GET / HTTP/1.0\r\nHost: target\r\n\r\n".to_vec(),
        443 | 8443 => Vec::new(), // TLS — don't send plaintext probe
        21 => Vec::new(),         // FTP sends banner on connect
        22 => Vec::new(),         // SSH sends banner on connect
        25 | 587 => b"EHLO probe\r\n".to_vec(),
        110 => Vec::new(),        // POP3 sends banner on connect
        143 => Vec::new(),        // IMAP sends banner on connect
        3306 => Vec::new(),       // MySQL sends banner on connect
        5432 => Vec::new(),       // PostgreSQL sends banner on connect
        6379 => b"PING\r\n".to_vec(), // Redis
        27017 => Vec::new(),      // MongoDB
        _ => Vec::new(),          // Default: wait for server to speak first
    }
}

// ===================================================================
// AD Enumeration
// ===================================================================

#[cfg(target_os = "windows")]
async fn handle_ad_enum(req: AdEnumRequest) -> Vec<Vec<u8>> {
    let scan_id = req.scan_id;
    info!("[byakugan] AD enumeration: scan_id={}", scan_id);
    cancel_registry::clear(scan_id);

    let mut ad_data = serde_json::Map::new();

    // 1. Domain controller
    let dc_output = run_system_command("nltest", &["/dsgetdc:"]).await;
    ad_data.insert("domain_controller".to_string(), serde_json::json!({
        "raw": dc_output.trim(),
        "parsed": parse_nltest_output(&dc_output),
    }));

    if cancel_registry::is_cancelled(scan_id) {
        cancel_registry::clear(scan_id);
        return vec![build_error(scan_id, "cancelled")];
    }

    // 2. Domain info from systeminfo
    let domain_output = run_piped_command("systeminfo", &[], "findstr", &["/B", "/C:Domain"]).await;
    ad_data.insert("domain_info".to_string(), serde_json::json!(domain_output.trim()));

    if cancel_registry::is_cancelled(scan_id) {
        cancel_registry::clear(scan_id);
        return vec![build_error(scan_id, "cancelled")];
    }

    // 3. Domain users
    let users_output = run_system_command("net", &["user", "/domain"]).await;
    let users = parse_net_user_output(&users_output);
    ad_data.insert("domain_users".to_string(), serde_json::json!({
        "count": users.len(),
        "users": users,
    }));

    if cancel_registry::is_cancelled(scan_id) {
        cancel_registry::clear(scan_id);
        return vec![build_error(scan_id, "cancelled")];
    }

    // 4. Domain groups
    let groups_output = run_system_command("net", &["group", "/domain"]).await;
    let groups = parse_net_group_output(&groups_output);
    ad_data.insert("domain_groups".to_string(), serde_json::json!({
        "count": groups.len(),
        "groups": groups,
    }));

    if cancel_registry::is_cancelled(scan_id) {
        cancel_registry::clear(scan_id);
        return vec![build_error(scan_id, "cancelled")];
    }

    // 5. Domain Admins
    let admins_output = run_system_command("net", &["group", "Domain Admins", "/domain"]).await;
    let admins = parse_net_user_output(&admins_output);
    ad_data.insert("domain_admins".to_string(), serde_json::json!({
        "count": admins.len(),
        "users": admins,
    }));

    let result = serde_json::Value::Object(ad_data);
    let mut replies = Vec::new();
    replies.push(build_scan_result(scan_id, "ad_enum", result));

    info!("[byakugan] AD enumeration {} complete", scan_id);
    cancel_registry::clear(scan_id);
    replies
}

#[cfg(not(target_os = "windows"))]
async fn handle_ad_enum(req: AdEnumRequest) -> Vec<Vec<u8>> {
    warn!("[byakugan] AD enumeration requires Windows");
    vec![build_error(req.scan_id, "AD enumeration requires Windows")]
}

// ===================================================================
// Passive Discovery
// ===================================================================

async fn handle_passive_discovery(req: PassiveRequest) -> Vec<Vec<u8>> {
    let scan_id = req.scan_id;
    let duration_secs = if req.duration_secs == 0 {
        DEFAULT_PASSIVE_DURATION_SECS
    } else {
        req.duration_secs.min(600) // Cap at 10 minutes
    };

    info!(
        "[byakugan] Passive discovery: scan_id={}, duration={}s",
        scan_id, duration_secs
    );
    cancel_registry::clear(scan_id);

    let mut replies = Vec::new();
    let mut known_hosts: HashSet<String> = HashSet::new();
    let start = std::time::Instant::now();
    let duration = std::time::Duration::from_secs(duration_secs);

    // Initial ARP scan
    let arp_output = run_system_command("arp", &["-a"]).await;
    let initial_hosts = parse_arp_output(&arp_output);
    for host in &initial_hosts {
        let ip = host.get("ip").and_then(|v| v.as_str()).unwrap_or("");
        if !ip.is_empty() {
            known_hosts.insert(ip.to_string());
            replies.push(build_host_msg(scan_id, host));
        }
    }

    // Windows: also try nbtstat
    #[cfg(target_os = "windows")]
    {
        let nbt_output = run_system_command("nbtstat", &["-n"]).await;
        let nbt_info = parse_nbtstat_output(&nbt_output);
        if !nbt_info.is_empty() {
            for entry in &nbt_info {
                replies.push(build_host_msg(scan_id, entry));
            }
        }
    }

    // Poll ARP table periodically for new hosts
    while start.elapsed() < duration {
        if cancel_registry::is_cancelled(scan_id) {
            info!("[byakugan] Passive discovery {} cancelled", scan_id);
            replies.push(build_error(scan_id, "cancelled"));
            cancel_registry::clear(scan_id);
            return replies;
        }

        tokio::time::sleep(std::time::Duration::from_secs(PASSIVE_POLL_INTERVAL_SECS)).await;

        let arp_output = run_system_command("arp", &["-a"]).await;
        let current_hosts = parse_arp_output(&arp_output);

        for host in &current_hosts {
            let ip = host.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            if !ip.is_empty() && !known_hosts.contains(ip) {
                known_hosts.insert(ip.to_string());
                info!("[byakugan] Passive discovery {}: new host {}", scan_id, ip);
                replies.push(build_host_msg(scan_id, host));
            }
        }
    }

    let summary = serde_json::json!({
        "duration_secs": duration_secs,
        "total_hosts_discovered": known_hosts.len(),
        "hosts": known_hosts.iter().collect::<Vec<&String>>(),
    });
    replies.push(build_scan_result(scan_id, "passive_discovery", summary));

    info!(
        "[byakugan] Passive discovery {}: {} hosts in {}s",
        scan_id,
        known_hosts.len(),
        duration_secs
    );
    cancel_registry::clear(scan_id);
    replies
}

// ===================================================================
// Cancel
// ===================================================================

async fn handle_cancel(req: CancelRequest) {
    info!("[byakugan] Cancel: scan_id={}", req.scan_id);
    cancel_registry::cancel(req.scan_id);
}

// ===================================================================
// System command execution helpers
// ===================================================================

/// Run a system command via tokio::process::Command and return stdout as a string.
/// Returns an empty string on failure (does not propagate errors).
async fn run_system_command(program: &str, args: &[&str]) -> String {
    match tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
        Err(e) => {
            debug!(
                "[byakugan] Command '{}' failed: {}",
                program, e
            );
            String::new()
        }
    }
}

/// Run two commands piped together: `cmd1 args1 | cmd2 args2`.
/// Falls back to running cmd1 only if piping is not feasible.
#[cfg(target_os = "windows")]
async fn run_piped_command(
    _cmd1: &str,
    _args1: &[&str],
    _cmd2: &str,
    _args2: &[&str],
) -> String {
    // On Windows, use cmd /C to run the piped command
    let full_cmd = format!(
        "{} {} | {} {}",
        _cmd1,
        _args1.join(" "),
        _cmd2,
        _args2.join(" ")
    );
    match tokio::process::Command::new("cmd")
        .args(["/C", &full_cmd])
        .output()
        .await
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
        Err(e) => {
            debug!("[byakugan] Piped command failed: {}", e);
            String::new()
        }
    }
}

#[cfg(not(target_os = "windows"))]
async fn run_piped_command(
    cmd1: &str,
    args1: &[&str],
    cmd2: &str,
    args2: &[&str],
) -> String {
    let full_cmd = format!(
        "{} {} | {} {}",
        cmd1,
        args1.join(" "),
        cmd2,
        args2.join(" ")
    );
    match tokio::process::Command::new("sh")
        .args(["-c", &full_cmd])
        .output()
        .await
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
        Err(e) => {
            debug!("[byakugan] Piped command failed: {}", e);
            String::new()
        }
    }
}

// ===================================================================
// Output parsers
// ===================================================================

/// Parse `arp -a` output into a list of host objects.
/// Handles both Windows and Unix formats.
///
/// Windows format:
///   Interface: 192.168.1.100 --- 0xa
///     Internet Address      Physical Address      Type
///     192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
///
/// Unix format:
///   ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
fn parse_arp_output(output: &str) -> Vec<serde_json::Value> {
    let mut hosts = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try Windows format: IP whitespace MAC whitespace Type
        if let Some(host) = parse_arp_line_windows(trimmed) {
            hosts.push(host);
            continue;
        }

        // Try Unix format: ? (IP) at MAC ...
        if let Some(host) = parse_arp_line_unix(trimmed) {
            hosts.push(host);
        }
    }

    hosts
}

/// Parse a single Windows-format ARP line.
fn parse_arp_line_windows(line: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let ip = parts[0];
    let mac = parts[1];

    // Validate IP: must contain dots and start with a digit
    if !ip.contains('.') || !ip.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return None;
    }

    // Validate MAC: must contain dashes or colons
    if !mac.contains('-') && !mac.contains(':') {
        return None;
    }

    // Skip broadcast/multicast entries
    if mac == "ff-ff-ff-ff-ff-ff" || mac == "ff:ff:ff:ff:ff:ff" {
        return None;
    }

    let entry_type = parts.get(2).copied().unwrap_or("unknown");

    Some(serde_json::json!({
        "ip": ip,
        "mac": mac.replace('-', ":"),
        "hostname": "",
        "type": entry_type,
    }))
}

/// Parse a single Unix-format ARP line.
fn parse_arp_line_unix(line: &str) -> Option<serde_json::Value> {
    // Format: hostname (IP) at MAC [type] on iface
    // or:     ? (IP) at MAC [type] on iface
    if !line.contains(" at ") {
        return None;
    }

    // Extract IP from parentheses
    let ip_start = line.find('(')?;
    let ip_end = line.find(')')?;
    if ip_end <= ip_start + 1 {
        return None;
    }
    let ip = &line[ip_start + 1..ip_end];

    // Extract hostname (before the parenthesis)
    let hostname = line[..ip_start].trim();
    let hostname = if hostname == "?" { "" } else { hostname };

    // Extract MAC (after "at ")
    let after_at = &line[line.find(" at ")? + 4..];
    let mac = after_at
        .split_whitespace()
        .next()
        .unwrap_or("");

    if mac == "(incomplete)" || mac.is_empty() {
        return None;
    }

    Some(serde_json::json!({
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "type": "dynamic",
    }))
}

/// Parse local interface info from ipconfig /all (Windows) or ip addr (Unix).
fn parse_local_interfaces(output: &str) -> Vec<serde_json::Value> {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_ip = String::new();
    let mut current_mac = String::new();
    let mut current_mask = String::new();
    let mut current_gateway = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Windows: adapter headers end with ':'
        if !trimmed.is_empty() && !trimmed.starts_with(' ') && line.ends_with(':') {
            // Flush previous
            if !current_name.is_empty() && !current_ip.is_empty() {
                interfaces.push(serde_json::json!({
                    "name": current_name,
                    "ip": current_ip,
                    "mac": current_mac,
                    "subnet_mask": current_mask,
                    "gateway": current_gateway,
                }));
            }
            current_name = trimmed.trim_end_matches(':').to_string();
            current_ip = String::new();
            current_mac = String::new();
            current_mask = String::new();
            current_gateway = String::new();
            continue;
        }

        // Windows keys (handle English and common locales)
        if trimmed.contains("IPv4 Address") || trimmed.contains("IPv4") {
            if let Some(val) = extract_after_colon(trimmed) {
                current_ip = val.trim_end_matches("(Preferred)").trim().to_string();
            }
        } else if trimmed.contains("Physical Address") || trimmed.contains("Direcci") {
            if let Some(val) = extract_after_colon(trimmed) {
                current_mac = val.replace('-', ":").to_string();
            }
        } else if trimmed.contains("Subnet Mask") || trimmed.contains("scara") {
            if let Some(val) = extract_after_colon(trimmed) {
                current_mask = val.to_string();
            }
        } else if trimmed.contains("Default Gateway") || trimmed.contains("Puerta de enlace") {
            if let Some(val) = extract_after_colon(trimmed) {
                if !val.is_empty() {
                    current_gateway = val.to_string();
                }
            }
        }

        // Unix: look for inet lines
        if trimmed.starts_with("inet ") && !trimmed.starts_with("inet6") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                current_ip = parts[1].to_string();
            }
        }
    }

    // Flush last
    if !current_name.is_empty() && !current_ip.is_empty() {
        interfaces.push(serde_json::json!({
            "name": current_name,
            "ip": current_ip,
            "mac": current_mac,
            "subnet_mask": current_mask,
            "gateway": current_gateway,
        }));
    }

    interfaces
}

/// Extract value after the last colon in a line.
fn extract_after_colon(line: &str) -> Option<String> {
    let pos = line.rfind(':')?;
    let val = line[pos + 1..].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Parse nltest /dsgetdc: output for domain controller info.
#[cfg(target_os = "windows")]
fn parse_nltest_output(output: &str) -> serde_json::Value {
    let mut info = serde_json::Map::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("DC:") {
            info.insert("dc".to_string(), serde_json::json!(val.trim().trim_start_matches('\\')));
        } else if let Some(val) = trimmed.strip_prefix("Address:") {
            info.insert("address".to_string(), serde_json::json!(val.trim().trim_start_matches('\\')));
        } else if let Some(val) = trimmed.strip_prefix("Dom Guid:") {
            info.insert("domain_guid".to_string(), serde_json::json!(val.trim()));
        } else if let Some(val) = trimmed.strip_prefix("Dom Name:") {
            info.insert("domain_name".to_string(), serde_json::json!(val.trim()));
        } else if let Some(val) = trimmed.strip_prefix("Forest Name:") {
            info.insert("forest_name".to_string(), serde_json::json!(val.trim()));
        } else if let Some(val) = trimmed.strip_prefix("Dc Site Name:") {
            info.insert("dc_site".to_string(), serde_json::json!(val.trim()));
        } else if let Some(val) = trimmed.strip_prefix("Our Site Name:") {
            info.insert("our_site".to_string(), serde_json::json!(val.trim()));
        }
    }

    serde_json::Value::Object(info)
}

/// Parse `net user /domain` or `net group "Domain Admins" /domain` output.
/// Extracts usernames from the columnar output format.
fn parse_net_user_output(output: &str) -> Vec<String> {
    let mut users = Vec::new();
    let mut in_user_section = false;

    for line in output.lines() {
        let trimmed = line.trim();

        // The separator line marks the start of the user list
        if trimmed.starts_with("------") {
            in_user_section = true;
            continue;
        }

        // "The command completed successfully" marks the end
        if trimmed.starts_with("The command completed") || trimmed.starts_with("Se ha completado") {
            break;
        }

        if in_user_section && !trimmed.is_empty() {
            // Users are listed in columns separated by whitespace
            for name in trimmed.split_whitespace() {
                let cleaned = name.trim();
                if !cleaned.is_empty() {
                    users.push(cleaned.to_string());
                }
            }
        }
    }

    users
}

/// Parse `net group /domain` output. Groups are prefixed with *.
fn parse_net_group_output(output: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut in_group_section = false;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("------") {
            in_group_section = true;
            continue;
        }

        if trimmed.starts_with("The command completed") || trimmed.starts_with("Se ha completado") {
            break;
        }

        if in_group_section && !trimmed.is_empty() {
            // Groups are prefixed with *
            if let Some(name) = trimmed.strip_prefix('*') {
                groups.push(name.trim().to_string());
            } else {
                // Some locales don't use * prefix
                groups.push(trimmed.to_string());
            }
        }
    }

    groups
}

/// Parse nbtstat -n output for NetBIOS names.
#[cfg(target_os = "windows")]
fn parse_nbtstat_output(output: &str) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        // NetBIOS name table lines look like:
        //   HOSTNAME       <00>  UNIQUE      Registered
        if trimmed.contains('<') && trimmed.contains('>') {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0];
                let suffix = parts[1]; // e.g. <00>
                let nbt_type = parts.get(2).copied().unwrap_or("unknown");
                entries.push(serde_json::json!({
                    "ip": "",
                    "mac": "",
                    "hostname": name,
                    "netbios_suffix": suffix,
                    "netbios_type": nbt_type,
                }));
            }
        }
    }

    entries
}

/// Parse a port range string like "1-1024" or "80" into (start, end).
fn parse_port_range(range: &str) -> Option<(u16, u16)> {
    let trimmed = range.trim();
    if let Some(pos) = trimmed.find('-') {
        let start: u16 = trimmed[..pos].trim().parse().ok()?;
        let end: u16 = trimmed[pos + 1..].trim().parse().ok()?;
        if start == 0 || end == 0 || start > end {
            return None;
        }
        Some((start, end))
    } else {
        // Single port
        let port: u16 = trimmed.parse().ok()?;
        if port == 0 {
            return None;
        }
        Some((port, port))
    }
}

/// Guess the service name for a well-known port.
fn guess_service(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmp-trap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd",
        465 => "smtps",
        514 => "syslog",
        515 => "printer",
        587 => "submission",
        593 => "http-rpc-epmap",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1434 => "mssql-m",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        3268 => "globalcatalog",
        3269 => "globalcatalog-ssl",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        5985 => "winrm",
        5986 => "winrm-ssl",
        6379 => "redis",
        6667 => "irc",
        8000 => "http-alt",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9090 => "zeus-admin",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

// ===================================================================
// Dispatch: called from main.rs to route BYAKUGAN_* commands
// ===================================================================

/// Parse and dispatch a Byakugan command. Returns messages to send back.
pub async fn dispatch(cmd_type: &str, payload: &str) -> Vec<Vec<u8>> {
    match cmd_type {
        "BYAKUGAN_ARP_SCAN" => {
            match serde_json::from_str::<ArpScanRequest>(payload) {
                Ok(req) => handle_arp_scan(req).await,
                Err(e) => {
                    error!("[byakugan] ARP_SCAN parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "BYAKUGAN_PORT_SCAN" => {
            match serde_json::from_str::<PortScanRequest>(payload) {
                Ok(req) => handle_port_scan(req).await,
                Err(e) => {
                    error!("[byakugan] PORT_SCAN parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "BYAKUGAN_BANNER_GRAB" => {
            match serde_json::from_str::<BannerGrabRequest>(payload) {
                Ok(req) => handle_banner_grab(req).await,
                Err(e) => {
                    error!("[byakugan] BANNER_GRAB parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "BYAKUGAN_AD_ENUM" => {
            match serde_json::from_str::<AdEnumRequest>(payload) {
                Ok(req) => handle_ad_enum(req).await,
                Err(e) => {
                    error!("[byakugan] AD_ENUM parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "BYAKUGAN_PASSIVE" => {
            match serde_json::from_str::<PassiveRequest>(payload) {
                Ok(req) => handle_passive_discovery(req).await,
                Err(e) => {
                    error!("[byakugan] PASSIVE parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "BYAKUGAN_CANCEL" => {
            match serde_json::from_str::<CancelRequest>(payload) {
                Ok(req) => {
                    handle_cancel(req).await;
                    Vec::new()
                }
                Err(e) => {
                    error!("[byakugan] CANCEL parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        _ => {
            warn!("[byakugan] Unknown command: {}", cmd_type);
            vec![build_error(0, &format!("unknown command: {}", cmd_type))]
        }
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range_valid() {
        assert_eq!(parse_port_range("1-1024"), Some((1, 1024)));
        assert_eq!(parse_port_range("80-443"), Some((80, 443)));
        assert_eq!(parse_port_range("22"), Some((22, 22)));
        assert_eq!(parse_port_range(" 8080 "), Some((8080, 8080)));
        assert_eq!(parse_port_range("1-65535"), Some((1, 65535)));
    }

    #[test]
    fn test_parse_port_range_invalid() {
        assert_eq!(parse_port_range(""), None);
        assert_eq!(parse_port_range("abc"), None);
        assert_eq!(parse_port_range("0-100"), None);
        assert_eq!(parse_port_range("1024-80"), None);
        assert_eq!(parse_port_range("0"), None);
    }

    #[test]
    fn test_guess_service() {
        assert_eq!(guess_service(22), "ssh");
        assert_eq!(guess_service(80), "http");
        assert_eq!(guess_service(443), "https");
        assert_eq!(guess_service(3389), "rdp");
        assert_eq!(guess_service(3306), "mysql");
        assert_eq!(guess_service(12345), "unknown");
    }

    #[test]
    fn test_parse_arp_line_windows() {
        let line = "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic";
        let result = parse_arp_line_windows(line.trim());
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val["ip"], "192.168.1.1");
        assert_eq!(val["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(val["type"], "dynamic");
    }

    #[test]
    fn test_parse_arp_line_windows_broadcast() {
        let line = "  255.255.255.255       ff-ff-ff-ff-ff-ff     static";
        let result = parse_arp_line_windows(line.trim());
        assert!(result.is_none(), "broadcast entries should be filtered");
    }

    #[test]
    fn test_parse_arp_line_unix() {
        let line = "gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0";
        let result = parse_arp_line_unix(line);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val["ip"], "192.168.1.1");
        assert_eq!(val["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(val["hostname"], "gateway");
    }

    #[test]
    fn test_parse_arp_line_unix_unknown_host() {
        let line = "? (10.0.0.5) at 11:22:33:44:55:66 [ether] on wlan0";
        let result = parse_arp_line_unix(line);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val["ip"], "10.0.0.5");
        assert_eq!(val["hostname"], "");
    }

    #[test]
    fn test_parse_arp_line_unix_incomplete() {
        let line = "? (192.168.1.50) at (incomplete) on eth0";
        let result = parse_arp_line_unix(line);
        assert!(result.is_none(), "incomplete entries should be filtered");
    }

    #[test]
    fn test_parse_arp_output_mixed() {
        let output = "\
Interface: 192.168.1.100 --- 0xa
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.2           11-22-33-44-55-66     dynamic
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
";
        let hosts = parse_arp_output(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.1.1");
        assert_eq!(hosts[1]["ip"], "192.168.1.2");
    }

    #[test]
    fn test_parse_arp_output_unix() {
        let output = "\
? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0
gateway (192.168.1.254) at 11:22:33:44:55:66 [ether] on en0
? (192.168.1.50) at (incomplete) on en0
";
        let hosts = parse_arp_output(output);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.1.1");
        assert_eq!(hosts[1]["ip"], "192.168.1.254");
    }

    #[test]
    fn test_parse_net_user_output() {
        let output = "\
User accounts for \\\\DOMAIN

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
john.doe                 jane.smith               svc_backup
The command completed successfully.
";
        let users = parse_net_user_output(output);
        assert_eq!(users.len(), 6);
        assert!(users.contains(&"Administrator".to_string()));
        assert!(users.contains(&"john.doe".to_string()));
        assert!(users.contains(&"svc_backup".to_string()));
    }

    #[test]
    fn test_parse_net_group_output() {
        let output = "\
Group Accounts for \\\\DOMAIN

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Users
The command completed successfully.
";
        let groups = parse_net_group_output(output);
        assert_eq!(groups.len(), 4);
        assert!(groups.contains(&"Domain Admins".to_string()));
        assert!(groups.contains(&"Domain Users".to_string()));
    }

    #[test]
    fn test_extract_after_colon() {
        assert_eq!(
            extract_after_colon("IPv4 Address. . . . . . . . . . . : 192.168.1.100"),
            Some("192.168.1.100".to_string())
        );
        assert_eq!(
            extract_after_colon("Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF"),
            Some("AA-BB-CC-DD-EE-FF".to_string())
        );
        assert_eq!(extract_after_colon("No colon here"), None);
        assert_eq!(extract_after_colon("Empty:"), None);
    }

    #[test]
    fn test_build_message_format() {
        let msg = build_message(MSG_BYAKUGAN_HOST, b"test");
        assert_eq!(msg.len(), 5 + 4);
        assert_eq!(msg[0], 0x41);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len, 4);
        assert_eq!(&msg[5..], b"test");
    }

    #[test]
    fn test_build_error() {
        let msg = build_error(42, "something went wrong");
        assert_eq!(msg[0], MSG_BYAKUGAN_ERROR);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let payload_str = std::str::from_utf8(&msg[5..5 + len]).unwrap();
        let v: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(v["scan_id"], 42);
        assert_eq!(v["error"], "something went wrong");
    }

    #[test]
    fn test_build_host_msg() {
        let host = serde_json::json!({"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"});
        let msg = build_host_msg(7, &host);
        assert_eq!(msg[0], MSG_BYAKUGAN_HOST);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let payload_str = std::str::from_utf8(&msg[5..5 + len]).unwrap();
        let v: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(v["scan_id"], 7);
        assert_eq!(v["host"]["ip"], "10.0.0.1");
    }

    #[test]
    fn test_build_scan_result() {
        let data = serde_json::json!({"hosts_found": 5});
        let msg = build_scan_result(1, "arp_scan", data);
        assert_eq!(msg[0], MSG_BYAKUGAN_SCAN_RESULT);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let payload_str = std::str::from_utf8(&msg[5..5 + len]).unwrap();
        let v: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(v["scan_id"], 1);
        assert_eq!(v["scan_type"], "arp_scan");
        assert_eq!(v["data"]["hosts_found"], 5);
    }

    #[test]
    fn test_get_probe_for_port() {
        assert!(!get_probe_for_port(80).is_empty());
        assert!(!get_probe_for_port(8080).is_empty());
        assert!(get_probe_for_port(22).is_empty()); // SSH sends banner first
        assert!(get_probe_for_port(443).is_empty()); // TLS
        assert!(!get_probe_for_port(6379).is_empty()); // Redis PING
    }

    #[test]
    fn test_cancel_registry() {
        cancel_registry::clear(999);
        assert!(!cancel_registry::is_cancelled(999));
        cancel_registry::cancel(999);
        assert!(cancel_registry::is_cancelled(999));
        cancel_registry::clear(999);
        assert!(!cancel_registry::is_cancelled(999));
    }

    #[test]
    fn test_parse_local_interfaces_windows() {
        let output = "\
Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit
   Physical Address. . . . . . . . . : 00-50-56-C0-00-08
   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
";
        let ifaces = parse_local_interfaces(output);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0]["ip"], "192.168.1.100");
        assert_eq!(ifaces[0]["mac"], "00:50:56:C0:00:08");
        assert_eq!(ifaces[0]["gateway"], "192.168.1.1");
    }

    #[tokio::test]
    async fn test_dispatch_unknown_command() {
        let replies = dispatch("BYAKUGAN_UNKNOWN", "{}").await;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0][0], MSG_BYAKUGAN_ERROR);
    }

    #[tokio::test]
    async fn test_dispatch_cancel() {
        let replies = dispatch("BYAKUGAN_CANCEL", r#"{"scan_id": 123}"#).await;
        assert!(replies.is_empty());
        assert!(cancel_registry::is_cancelled(123));
        cancel_registry::clear(123);
    }

    #[tokio::test]
    async fn test_dispatch_parse_error() {
        let replies = dispatch("BYAKUGAN_ARP_SCAN", "not json").await;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0][0], MSG_BYAKUGAN_ERROR);
    }
}

```