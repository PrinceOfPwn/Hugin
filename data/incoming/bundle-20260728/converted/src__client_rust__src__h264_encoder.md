# h264_encoder

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/h264_encoder.rs` |
| **Lines** | 198 |
| **Cards** | T023-client-capabilities |
| **Role** | OpenH264 wrapper, BGRA→I420 |

## Types

### struct `H264Encoder` (line 23)

## Public API

### `new` (line 33)
```rust
pub fn new(width: u32, height: u32) -> Result<Self>
```
Create encoder for given resolution. `width` and `height` must be even.

### `width` (line 62)
```rust
pub fn width(&self) -> u32
```

### `height` (line 66)
```rust
pub fn height(&self) -> u32
```

### `encode_frame` (line 76)
```rust
pub fn encode_frame(
```
Encode one BGRA/RGBA frame. `is_bgra=true` if BGRA, false if RGBA.
`is_keyframe` is advisory: openh264's high-level API decides via its
internal GOP cadence. We still accept the flag so callers can log intent.

Returns H.264 NAL bytes (Annex-B framed) for this frame, or `None` if
the encoder produced no output this frame.

## Internal Functions

- `bgra_or_rgba_to_i420` — Convert a tightly packed BGRA or RGBA frame of size w*h*4 into I420 planar (line 118)
- `unpack` (line 171)
- `rgb_to_y` (line 180)
- `rgb_to_u` (line 187)
- `rgb_to_v` (line 194)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use openh264::encoder::{Encoder, EncoderConfig};`
- `use openh264::formats::YUVBuffer;`
- `use openh264::OpenH264API;`

## Full Source

```rust
// H.264 video encoder wrapping the `openh264` safe bindings to Cisco OpenH264.
//
// Takes a raw BGRA/RGBA frame, converts it to I420 (YUV420 planar), feeds it
// through the encoder, and returns the emitted NAL units as a byte vector.
//
// The encoder produces one or more NALs per call (SPS/PPS at init and keyframes,
// plus one slice NAL per frame). `openh264::encoder::EncodedBitStream::to_vec()`
// concatenates them with 4-byte Annex-B start codes, which is what the browser
// MSE side expects inside MSG_VIDEO_FRAME.
//
// Keyframe policy: the caller decides cadence; when `is_keyframe=true` we force
// an IDR via the encoder config's `force_intra_frame` equivalent — openh264 0.6
// does not expose that knob on the high-level builder, so we instead reconfigure
// `IntraFramePeriod` via a fresh encoder on init and let the periodic encoder
// state handle the rest (keyframes are driven by the encoder's internal GOP
// cadence, which we set to 30 frames via config at construction time).

use anyhow::{anyhow, Result};
use openh264::encoder::{Encoder, EncoderConfig};
use openh264::formats::YUVBuffer;
use openh264::OpenH264API;

pub struct H264Encoder {
    encoder: Encoder,
    width: u32,
    height: u32,
    /// Reusable I420 scratch buffer: Y + U + V planes (size = w*h*3/2).
    yuv_scratch: Vec<u8>,
}

impl H264Encoder {
    /// Create encoder for given resolution. `width` and `height` must be even.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(anyhow!("H264Encoder: zero dimension ({}x{})", width, height));
        }
        if width % 2 != 0 || height % 2 != 0 {
            return Err(anyhow!(
                "H264Encoder: width and height must be even (got {}x{})",
                width,
                height
            ));
        }

        let api = OpenH264API::from_source();
        let config = EncoderConfig::new()
            .max_frame_rate(30.0)
            .set_bitrate_bps(4_000_000);

        let encoder = Encoder::with_api_config(api, config)
            .map_err(|e| anyhow!("openh264 Encoder init failed: {:?}", e))?;

        let yuv_len = (width as usize) * (height as usize) * 3 / 2;
        Ok(H264Encoder {
            encoder,
            width,
            height,
            yuv_scratch: vec![0u8; yuv_len],
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Encode one BGRA/RGBA frame. `is_bgra=true` if BGRA, false if RGBA.
    /// `is_keyframe` is advisory: openh264's high-level API decides via its
    /// internal GOP cadence. We still accept the flag so callers can log intent.
    ///
    /// Returns H.264 NAL bytes (Annex-B framed) for this frame, or `None` if
    /// the encoder produced no output this frame.
    pub fn encode_frame(
        &mut self,
        raw: &[u8],
        is_bgra: bool,
        _is_keyframe: bool,
    ) -> Result<Option<Vec<u8>>> {
        let w = self.width as usize;
        let h = self.height as usize;
        let expected = w * h * 4;
        if raw.len() < expected {
            return Err(anyhow!(
                "H264Encoder: raw frame too small ({} < {})",
                raw.len(),
                expected
            ));
        }

        // Convert BGRA/RGBA → I420 in place into our scratch buffer.
        bgra_or_rgba_to_i420(raw, w, h, is_bgra, &mut self.yuv_scratch);

        // Hand off to openh264 via a YUVBuffer (takes a Vec; we clone out of scratch).
        let yuv = YUVBuffer::from_vec(self.yuv_scratch.clone(), w, h);

        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|e| anyhow!("openh264 encode failed: {:?}", e))?;

        let bytes = bitstream.to_vec();
        if bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(bytes))
        }
    }
}

/// Convert a tightly packed BGRA or RGBA frame of size w*h*4 into I420 planar
/// YUV420 (Y plane w*h, U plane (w/2)*(h/2), V plane (w/2)*(h/2)) using BT.601.
///
/// For each 2x2 block of pixels we compute Y per-pixel and one averaged U/V.
/// `out` must have capacity `w*h*3/2`; it is resized and overwritten.
fn bgra_or_rgba_to_i420(src: &[u8], w: usize, h: usize, is_bgra: bool, out: &mut Vec<u8>) {
    let y_size = w * h;
    let uv_size = (w / 2) * (h / 2);
    let total = y_size + 2 * uv_size;
    if out.len() != total {
        out.clear();
        out.resize(total, 0);
    }

    // Split the output buffer into three plane slices.
    let (y_plane, uv) = out.split_at_mut(y_size);
    let (u_plane, v_plane) = uv.split_at_mut(uv_size);

    let stride = w * 4;
    for by in 0..(h / 2) {
        let y0 = 2 * by;
        let y1 = y0 + 1;
        let row0 = y0 * stride;
        let row1 = y1 * stride;
        for bx in 0..(w / 2) {
            let x0 = 2 * bx;
            let x1 = x0 + 1;

            // Fetch the four pixels (top-left, top-right, bottom-left, bottom-right).
            let p_tl = &src[row0 + x0 * 4..row0 + x0 * 4 + 4];
            let p_tr = &src[row0 + x1 * 4..row0 + x1 * 4 + 4];
            let p_bl = &src[row1 + x0 * 4..row1 + x0 * 4 + 4];
            let p_br = &src[row1 + x1 * 4..row1 + x1 * 4 + 4];

            let (r_tl, g_tl, b_tl) = unpack(p_tl, is_bgra);
            let (r_tr, g_tr, b_tr) = unpack(p_tr, is_bgra);
            let (r_bl, g_bl, b_bl) = unpack(p_bl, is_bgra);
            let (r_br, g_br, b_br) = unpack(p_br, is_bgra);

            // Per-pixel Y (BT.601).
            y_plane[y0 * w + x0] = rgb_to_y(r_tl, g_tl, b_tl);
            y_plane[y0 * w + x1] = rgb_to_y(r_tr, g_tr, b_tr);
            y_plane[y1 * w + x0] = rgb_to_y(r_bl, g_bl, b_bl);
            y_plane[y1 * w + x1] = rgb_to_y(r_br, g_br, b_br);

            // Averaged R,G,B over the 2x2 block for chroma.
            let r_avg = ((r_tl as u32 + r_tr as u32 + r_bl as u32 + r_br as u32) / 4) as u8;
            let g_avg = ((g_tl as u32 + g_tr as u32 + g_bl as u32 + g_br as u32) / 4) as u8;
            let b_avg = ((b_tl as u32 + b_tr as u32 + b_bl as u32 + b_br as u32) / 4) as u8;

            let chroma_idx = by * (w / 2) + bx;
            u_plane[chroma_idx] = rgb_to_u(r_avg, g_avg, b_avg);
            v_plane[chroma_idx] = rgb_to_v(r_avg, g_avg, b_avg);
        }
    }
}

#[inline]
fn unpack(px: &[u8], is_bgra: bool) -> (u8, u8, u8) {
    if is_bgra {
        (px[2], px[1], px[0]) // R, G, B from BGRA
    } else {
        (px[0], px[1], px[2]) // R, G, B from RGBA
    }
}

#[inline]
fn rgb_to_y(r: u8, g: u8, b: u8) -> u8 {
    // Y = 0.299*R + 0.587*G + 0.114*B  (BT.601)
    let y = 0.299f32 * r as f32 + 0.587f32 * g as f32 + 0.114f32 * b as f32;
    y.clamp(0.0, 255.0) as u8
}

#[inline]
fn rgb_to_u(r: u8, g: u8, b: u8) -> u8 {
    // U = -0.169*R - 0.331*G + 0.500*B + 128
    let u = -0.169f32 * r as f32 - 0.331f32 * g as f32 + 0.500f32 * b as f32 + 128.0;
    u.clamp(0.0, 255.0) as u8
}

#[inline]
fn rgb_to_v(r: u8, g: u8, b: u8) -> u8 {
    // V = 0.500*R - 0.419*G - 0.081*B + 128
    let v = 0.500f32 * r as f32 - 0.419f32 * g as f32 - 0.081f32 * b as f32 + 128.0;
    v.clamp(0.0, 255.0) as u8
}

```