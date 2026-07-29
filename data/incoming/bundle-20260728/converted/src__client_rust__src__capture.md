# capture

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/capture.rs` |
| **Lines** | 590 |
| **Cards** | T023-client-capabilities |
| **Role** | DXGI screen capture |
| **Unsafe blocks** | 7 |

## Types

### struct `RawFrame` (line 8)
Captured frame as raw RGBA bytes with dimensions.

### struct `DxgiCapture` (line 137)

### struct `GdiCapture` (line 315)

### enum `ScreenCapturer` (line 485)
Screen capturer that tries DXGI first, falls back to GDI.

### struct `ScreenCapturer` (line 547)

## Public API

### `to_jpeg` (line 21)
```rust
pub fn to_jpeg(&self, quality: u8) -> Result<Vec<u8>>
```
Encode the raw frame to JPEG bytes at the given quality (0-100).

Uses `image::codecs::jpeg::JpegEncoder` directly with the quality
parameter so the caller controls compression level.  A pre-allocated
output buffer avoids repeated heap allocations across frames.

### `to_jpeg_with_scratch` (line 28)
```rust
pub fn to_jpeg_with_scratch(
```
Same as `to_jpeg`, but reuses a caller-owned RGB scratch buffer.
This removes one large allocation from the hot path.

### `fast_hash` (line 59)
```rust
pub fn fast_hash(&self) -> u64
```
Compute a fast hash of this frame for change detection (Task 6).

Samples three horizontal strips (top row, middle row, bottom row) and
returns a 64-bit sum.  This is intentionally cheap — ~3 * width * 4
bytes read vs the full frame — and sufficient to detect that *something*
changed without computing a full-frame hash every cycle.

### `bgra_or_rgba_to_rgb` (line 90)
```rust
pub fn bgra_or_rgba_to_rgb(data: &[u8], is_bgra: bool) -> Vec<u8>
```

### `bgra_or_rgba_to_rgb_into` (line 97)
```rust
pub fn bgra_or_rgba_to_rgb_into(data: &[u8], is_bgra: bool, out: &mut Vec<u8>)
```

### `new` (line 151)
```rust
pub fn new(monitor_index: u32) -> Result<Self>
```
Try to create a DXGI capture context for the given monitor index.

### `capture_frame` (line 217)
```rust
pub fn capture_frame(&mut self) -> Result<Option<RawFrame>>
```
Capture a single frame. Returns `Ok(None)` when no new DXGI frame is
available yet, which is a normal condition for unchanged desktops.

### `capture_frame_with_timeout` (line 221)
```rust
pub fn capture_frame_with_timeout(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>>
```

### `new` (line 330)
```rust
pub fn new(monitor_index: u32) -> Self
```

### `capture_frame` (line 382)
```rust
pub fn capture_frame(&mut self) -> Result<RawFrame>
```

### `new` (line 491)
```rust
pub fn new(monitor_index: u32) -> Self
```

### `width` (line 504)
```rust
pub fn width(&self) -> u32
```

### `height` (line 511)
```rust
pub fn height(&self) -> u32
```

### `is_event_driven` (line 518)
```rust
pub fn is_event_driven(&self) -> bool
```

### `capture_frame` (line 522)
```rust
pub fn capture_frame(&mut self) -> Result<Option<RawFrame>>
```

### `capture_frame_with_timeout` (line 526)
```rust
pub fn capture_frame_with_timeout(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>>
```

### `new` (line 553)
```rust
pub fn new(_monitor_index: u32) -> Self
```

### `width` (line 556)
```rust
pub fn width(&self) -> u32 { self.width }
```

### `height` (line 557)
```rust
pub fn height(&self) -> u32 { self.height }
```

### `is_event_driven` (line 558)
```rust
pub fn is_event_driven(&self) -> bool { false }
```

### `capture_frame` (line 559)
```rust
pub fn capture_frame(&mut self) -> Result<Option<RawFrame>>
```

### `capture_frame_with_timeout` (line 562)
```rust
pub fn capture_frame_with_timeout(&mut self, _timeout_ms: u32) -> Result<Option<RawFrame>>
```

### `capture_jpeg` (line 574)
```rust
pub fn capture_jpeg(monitor_index: u32, quality: u8) -> Result<Vec<u8>>
```
Capture a JPEG frame from the given monitor index at the given quality.
This is a convenience function that creates a temporary capturer.

## Internal Functions

- `get_or_create_staging` (line 282)
- `ensure_resources` (line 349)
- `drop` (line 446)
- `draw_visible_cursor` (line 458)

## Key Dependencies

- `use anyhow::{Context, Result};`
- `use tracing::{debug, info, warn};`
- `use image::codecs::jpeg::JpegEncoder;`
- `use image::ColorType;`
- `use super::*;`
- `use windows::Win32::{`
- `use windows::core::Interface;`
- `use super::*;`

## Full Source

```rust
// Screen capture: DXGI Desktop Duplication (primary, 60+ FPS) with GDI fallback.
// Encodes frames as JPEG using the image crate (JpegEncoder with explicit quality).

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

/// Captured frame as raw RGBA bytes with dimensions.
pub struct RawFrame {
    pub data: Vec<u8>, // RGBA or BGRA raw pixels
    pub width: u32,
    pub height: u32,
    pub is_bgra: bool,
}

impl RawFrame {
    /// Encode the raw frame to JPEG bytes at the given quality (0-100).
    ///
    /// Uses `image::codecs::jpeg::JpegEncoder` directly with the quality
    /// parameter so the caller controls compression level.  A pre-allocated
    /// output buffer avoids repeated heap allocations across frames.
    pub fn to_jpeg(&self, quality: u8) -> Result<Vec<u8>> {
        let mut rgb_scratch = Vec::new();
        self.to_jpeg_with_scratch(quality, &mut rgb_scratch)
    }

    /// Same as `to_jpeg`, but reuses a caller-owned RGB scratch buffer.
    /// This removes one large allocation from the hot path.
    pub fn to_jpeg_with_scratch(
        &self,
        quality: u8,
        rgb_scratch: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        use image::codecs::jpeg::JpegEncoder;
        use image::ColorType;

        // Convert BGRA or RGBA → tightly-packed RGB (no alpha channel)
        bgra_or_rgba_to_rgb_into(&self.data, self.is_bgra, rgb_scratch);

        // Pre-allocate output buffer at ~half the raw RGB size — typical JPEG
        // for screen content compresses around 3-6x.
        let raw_size = (self.width * self.height * 3) as usize;
        let mut buf = std::io::Cursor::new(Vec::with_capacity(raw_size / 4));

        // JpegEncoder::encode() works directly on raw pixel bytes — no need
        // to construct an intermediate DynamicImage, saving an allocation.
        let mut encoder = JpegEncoder::new_with_quality(&mut buf, quality);
        encoder.encode(rgb_scratch, self.width, self.height, ColorType::Rgb8)
            .context("JPEG encoding failed")?;

        Ok(buf.into_inner())
    }

    /// Compute a fast hash of this frame for change detection (Task 6).
    ///
    /// Samples three horizontal strips (top row, middle row, bottom row) and
    /// returns a 64-bit sum.  This is intentionally cheap — ~3 * width * 4
    /// bytes read vs the full frame — and sufficient to detect that *something*
    /// changed without computing a full-frame hash every cycle.
    pub fn fast_hash(&self) -> u64 {
        if self.data.is_empty() || self.width == 0 || self.height == 0 {
            return 0;
        }
        let stride = self.width as usize * 4;
        let rows = [
            0usize,
            (self.height as usize / 2) * stride,
            (self.height as usize - 1) * stride,
        ];
        let mut sum: u64 = 0;
        for row_start in rows {
            let row_end = (row_start + stride).min(self.data.len());
            if row_end <= row_start { continue; }
            let row = &self.data[row_start..row_end];
            let mut i = 0;
            while i + 8 <= row.len() {
                let chunk = u64::from_le_bytes(row[i..i+8].try_into().unwrap());
                sum = sum.wrapping_add(chunk);
                i += 8;
            }
            for &b in &row[i..] {
                sum = sum.wrapping_add(b as u64);
            }
        }
        sum
    }
}

/// Convert BGRA or RGBA raw pixels to tightly-packed RGB.
#[inline]
pub fn bgra_or_rgba_to_rgb(data: &[u8], is_bgra: bool) -> Vec<u8> {
    let mut rgb = Vec::new();
    bgra_or_rgba_to_rgb_into(data, is_bgra, &mut rgb);
    rgb
}

#[inline]
pub fn bgra_or_rgba_to_rgb_into(data: &[u8], is_bgra: bool, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(data.len() / 4 * 3);
    if is_bgra {
        for chunk in data.chunks(4) {
            out.push(chunk[2]); // R (from BGRA[2])
            out.push(chunk[1]); // G
            out.push(chunk[0]); // B
        }
    } else {
        for chunk in data.chunks(4) {
            out.push(chunk[0]); // R
            out.push(chunk[1]); // G
            out.push(chunk[2]); // B
        }
    }
}

// ============================================================
// Platform-specific capture implementations
// ============================================================

#[cfg(windows)]
pub mod win {
    use super::*;
    use windows::Win32::{
        Foundation::*,
        Graphics::{
            Direct3D::*,
            Direct3D11::*,
            Dxgi::{Common::*, *},
            Gdi::*,
        },
        UI::WindowsAndMessaging::*,
    };
    #[allow(unused_imports)]
    use windows::core::Interface;

    // ---- DXGI Desktop Duplication ----

    pub struct DxgiCapture {
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        duplication: IDXGIOutputDuplication,
        staging: Option<ID3D11Texture2D>,
        pub width: u32,
        pub height: u32,
        monitor_index: u32,
    }

    unsafe impl Send for DxgiCapture {}

    impl DxgiCapture {
        /// Try to create a DXGI capture context for the given monitor index.
        pub fn new(monitor_index: u32) -> Result<Self> {
            unsafe {
                // Create DXGI factory to enumerate adapters
                let factory: IDXGIFactory1 = windows::Win32::Graphics::Dxgi::CreateDXGIFactory1()
                    .context("CreateDXGIFactory1 failed")?;

                // Get first adapter
                let adapter: IDXGIAdapter = factory.EnumAdapters(0)
                    .context("EnumAdapters(0) failed — no GPU found")?;

                // Create D3D11 device with the explicit adapter
                let mut device: Option<ID3D11Device> = None;
                let mut context: Option<ID3D11DeviceContext> = None;
                let feature_levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1];

                D3D11CreateDevice(
                    Some(&adapter),
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE(0),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    Some(&feature_levels),
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
                .context("D3D11CreateDevice failed")?;

                let device = device.context("D3D11 device is None")?;
                let context = context.context("D3D11 context is None")?;

                // Get output from adapter
                let output: IDXGIOutput = adapter
                    .EnumOutputs(monitor_index)
                    .context("EnumOutputs failed — invalid monitor index")?;

                let output1: IDXGIOutput1 = output.cast().context("Cast to IDXGIOutput1 failed")?;

                let duplication: IDXGIOutputDuplication = output1
                    .DuplicateOutput(&device)
                    .context("DuplicateOutput failed")?;

                let mut desc = DXGI_OUTDUPL_DESC::default();
                duplication.GetDesc(&mut desc);
                let width = desc.ModeDesc.Width;
                let height = desc.ModeDesc.Height;

                info!(
                    "DXGI capture ready: monitor={} {}x{}",
                    monitor_index, width, height
                );

                Ok(DxgiCapture {
                    device,
                    context,
                    duplication,
                    staging: None,
                    width,
                    height,
                    monitor_index,
                })
            }
        }

        /// Capture a single frame. Returns `Ok(None)` when no new DXGI frame is
        /// available yet, which is a normal condition for unchanged desktops.
        pub fn capture_frame(&mut self) -> Result<Option<RawFrame>> {
            self.capture_frame_with_timeout(100)
        }

        pub fn capture_frame_with_timeout(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>> {
            unsafe {
                let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
                let mut desktop_resource: Option<IDXGIResource> = None;

                let timeout_ms = timeout_ms.max(1);
                match self.duplication.AcquireNextFrame(timeout_ms, &mut frame_info, &mut desktop_resource) {
                    Ok(()) => {}
                    Err(e) => {
                        // DXGI timeout is expected when the desktop has not changed.
                        if e.code() == DXGI_ERROR_WAIT_TIMEOUT {
                            return Ok(None);
                        }
                        return Err(e).context("AcquireNextFrame failed");
                    }
                }

                let resource = desktop_resource.context("Desktop resource is None")?;
                let texture: ID3D11Texture2D = resource.cast().context("Cast to Texture2D failed")?;

                // Create or reuse staging texture
                let staging = self.get_or_create_staging()?;

                // Copy to staging (upcast Texture2D → Resource for CopyResource)
                {
                    let staging_res: ID3D11Resource = staging.cast().context("staging cast to ID3D11Resource failed")?;
                    let texture_res: ID3D11Resource = texture.cast().context("texture cast to ID3D11Resource failed")?;
                    self.context.CopyResource(&staging_res, &texture_res);
                }

                // Map staging texture to read CPU-side
                let staging_for_map: ID3D11Resource = staging.cast().context("staging map cast failed")?;
                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                self.context
                    .Map(&staging_for_map, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                    .context("ID3D11DeviceContext::Map failed")?;

                let row_pitch = mapped.RowPitch as usize;
                let total = row_pitch * self.height as usize;
                let slice = std::slice::from_raw_parts(mapped.pData as *const u8, total);

                // Copy out row by row (row_pitch may be padded)
                let stride = self.width as usize * 4;
                let mut data = Vec::with_capacity(stride * self.height as usize);
                for row in 0..self.height as usize {
                    let start = row * row_pitch;
                    data.extend_from_slice(&slice[start..start + stride]);
                }

                self.context.Unmap(&staging_for_map, 0);
                self.duplication.ReleaseFrame().ok();

                Ok(Some(RawFrame {
                    data,
                    width: self.width,
                    height: self.height,
                    is_bgra: true,
                }))
            }
        }

        fn get_or_create_staging(&mut self) -> Result<ID3D11Texture2D> {
            if let Some(ref s) = self.staging {
                return Ok(s.clone());
            }
            let desc = D3D11_TEXTURE2D_DESC {
                Width: self.width,
                Height: self.height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging = None;
            unsafe {
                self.device
                    .CreateTexture2D(&desc, None, Some(&mut staging))
                    .context("CreateTexture2D (staging) failed")?;
            }
            let staging = staging.context("CreateTexture2D returned None")?;
            self.staging = Some(staging.clone());
            Ok(staging)
        }
    }

    // ---- GDI Fallback Capture ----

    pub struct GdiCapture {
        pub width: u32,
        pub height: u32,
        left: i32,
        top: i32,
        screen_dc: HDC,
        mem_dc: HDC,
        bmp: HBITMAP,
        old_bmp: HGDIOBJ,
        initialized: bool,
    }

    unsafe impl Send for GdiCapture {}

    impl GdiCapture {
        pub fn new(monitor_index: u32) -> Self {
            let (left, top, width, height) = crate::sysinfo_collect::get_monitor_rect(monitor_index);
            let mut cap = GdiCapture {
                width,
                height,
                left,
                top,
                screen_dc: HDC(0),
                mem_dc: HDC(0),
                bmp: HBITMAP(0),
                old_bmp: HGDIOBJ(0),
                initialized: false,
            };
            if let Err(e) = cap.ensure_resources() {
                warn!("GDI capturer init deferred: {}", e);
            }
            cap
        }

        fn ensure_resources(&mut self) -> Result<()> {
            unsafe {
                if self.initialized {
                    return Ok(());
                }

                self.screen_dc = GetDC(HWND(0));
                if self.screen_dc.is_invalid() {
                    anyhow::bail!("GetDC failed");
                }

                self.mem_dc = CreateCompatibleDC(self.screen_dc);
                if self.mem_dc.is_invalid() {
                    ReleaseDC(HWND(0), self.screen_dc);
                    self.screen_dc = HDC(0);
                    anyhow::bail!("CreateCompatibleDC failed");
                }

                self.bmp = CreateCompatibleBitmap(self.screen_dc, self.width as i32, self.height as i32);
                if self.bmp.0 == 0 {
                    DeleteDC(self.mem_dc);
                    ReleaseDC(HWND(0), self.screen_dc);
                    self.mem_dc = HDC(0);
                    self.screen_dc = HDC(0);
                    anyhow::bail!("CreateCompatibleBitmap failed");
                }

                self.old_bmp = SelectObject(self.mem_dc, self.bmp);
                self.initialized = true;
                Ok(())
            }
        }

        pub fn capture_frame(&mut self) -> Result<RawFrame> {
            unsafe {
                self.ensure_resources()?;

                // BitBlt from screen to memory DC
                BitBlt(
                    self.mem_dc,
                    0,
                    0,
                    self.width as i32,
                    self.height as i32,
                    self.screen_dc,
                    self.left,
                    self.top,
                    SRCCOPY,
                )
                .context("BitBlt failed")?;

                // Keep the viewer cursor-visible path aligned with the GDI
                // capturer from the C# client. We only do this in the GDI path
                // because it is inexpensive and does not interfere with DXGI's
                // desktop duplication state machine.
                draw_visible_cursor(self.mem_dc, self.left, self.top, self.width, self.height);

                // Get bitmap bits (BGRA format)
                let mut bmi = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: self.width as i32,
                        biHeight: -(self.height as i32), // negative = top-down
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };

                let mut data = vec![0u8; (self.width * self.height * 4) as usize];
                let lines = GetDIBits(
                    self.mem_dc,
                    self.bmp,
                    0,
                    self.height,
                    Some(data.as_mut_ptr() as *mut _),
                    &mut bmi,
                    DIB_RGB_COLORS,
                );

                if lines == 0 {
                    anyhow::bail!("GetDIBits failed");
                }

                Ok(RawFrame {
                    data,
                    width: self.width,
                    height: self.height,
                    is_bgra: true,
                })
            }
        }
    }

    impl Drop for GdiCapture {
        fn drop(&mut self) {
            unsafe {
                if self.initialized {
                    let _ = SelectObject(self.mem_dc, self.old_bmp);
                    let _ = DeleteObject(self.bmp);
                    let _ = DeleteDC(self.mem_dc);
                    let _ = ReleaseDC(HWND(0), self.screen_dc);
                }
            }
        }
    }

    fn draw_visible_cursor(target_dc: HDC, monitor_left: i32, monitor_top: i32, width: u32, height: u32) {
        unsafe {
            let mut cursor_info = CURSORINFO {
                cbSize: std::mem::size_of::<CURSORINFO>() as u32,
                ..Default::default()
            };

            if GetCursorInfo(&mut cursor_info).is_err() || cursor_info.flags != CURSOR_SHOWING {
                return;
            }

            let cursor_x = cursor_info.ptScreenPos.x - monitor_left;
            let cursor_y = cursor_info.ptScreenPos.y - monitor_top;

            if cursor_x < 0
                || cursor_y < 0
                || cursor_x >= width as i32
                || cursor_y >= height as i32
            {
                return;
            }

            let _ = DrawIcon(target_dc, cursor_x, cursor_y, cursor_info.hCursor);
        }
    }

    /// Screen capturer that tries DXGI first, falls back to GDI.
    pub enum ScreenCapturer {
        Dxgi(DxgiCapture),
        Gdi(GdiCapture),
    }

    impl ScreenCapturer {
        pub fn new(monitor_index: u32) -> Self {
            match DxgiCapture::new(monitor_index) {
                Ok(d) => {
                    info!("Using DXGI capture for monitor {}", monitor_index);
                    ScreenCapturer::Dxgi(d)
                }
                Err(e) => {
                    warn!("DXGI capture unavailable ({}), falling back to GDI", e);
                    ScreenCapturer::Gdi(GdiCapture::new(monitor_index))
                }
            }
        }

        pub fn width(&self) -> u32 {
            match self {
                ScreenCapturer::Dxgi(d) => d.width,
                ScreenCapturer::Gdi(g) => g.width,
            }
        }

        pub fn height(&self) -> u32 {
            match self {
                ScreenCapturer::Dxgi(d) => d.height,
                ScreenCapturer::Gdi(g) => g.height,
            }
        }

        pub fn is_event_driven(&self) -> bool {
            matches!(self, ScreenCapturer::Dxgi(_))
        }

        pub fn capture_frame(&mut self) -> Result<Option<RawFrame>> {
            self.capture_frame_with_timeout(100)
        }

        pub fn capture_frame_with_timeout(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>> {
            match self {
                ScreenCapturer::Dxgi(d) => match d.capture_frame_with_timeout(timeout_ms) {
                    Ok(Some(f)) => Ok(Some(f)),
                    Ok(None) => Ok(None),
                    Err(e) => {
                        debug!("DXGI frame error ({}), trying GDI fallback", e);
                        let mut gdi = GdiCapture::new(d.monitor_index);
                        gdi.capture_frame().map(Some)
                    }
                },
                ScreenCapturer::Gdi(g) => g.capture_frame().map(Some),
            }
        }
    }
}

#[cfg(not(windows))]
pub mod win {
    use super::*;

    pub struct ScreenCapturer {
        pub width: u32,
        pub height: u32,
    }

    impl ScreenCapturer {
        pub fn new(_monitor_index: u32) -> Self {
            ScreenCapturer { width: 1920, height: 1080 }
        }
        pub fn width(&self) -> u32 { self.width }
        pub fn height(&self) -> u32 { self.height }
        pub fn is_event_driven(&self) -> bool { false }
        pub fn capture_frame(&mut self) -> Result<Option<RawFrame>> {
            self.capture_frame_with_timeout(100)
        }
        pub fn capture_frame_with_timeout(&mut self, _timeout_ms: u32) -> Result<Option<RawFrame>> {
            // Return a blank frame on non-Windows
            let data = vec![0u8; (self.width * self.height * 4) as usize];
            Ok(Some(RawFrame { data, width: self.width, height: self.height, is_bgra: false }))
        }
    }
}

pub use win::ScreenCapturer;

/// Capture a JPEG frame from the given monitor index at the given quality.
/// This is a convenience function that creates a temporary capturer.
pub fn capture_jpeg(monitor_index: u32, quality: u8) -> Result<Vec<u8>> {
    #[cfg(windows)]
    let frame = {
        let mut capturer = win::GdiCapture::new(monitor_index);
        capturer.capture_frame()?
    };

    #[cfg(not(windows))]
    let frame = {
        let mut capturer = ScreenCapturer::new(monitor_index);
        capturer
            .capture_frame()?
            .ok_or_else(|| anyhow::anyhow!("No frame available"))?
    };

    frame.to_jpeg(quality)
}

```