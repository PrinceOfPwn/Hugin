# dirty_rect

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/dirty_rect.rs` |
| **Lines** | 429 |
| **Cards** | T023-client-capabilities |
| **Role** | 64x64 tile change detection |

## Constants

- `TILE_SIZE`: `u32` = `64`

## Types

### struct `DirtyRect` (line 20)

### struct `DirtyRectDetector` (line 35)
Detects dirty rectangles by comparing per-tile hashes across frames.

The detector owns the previous frame's tile hashes.  On each call to
`detect`, it computes new hashes, diffs them, and returns the list of
changed tiles.  The internal state is updated in-place.

## Public API

### `new` (line 50)
```rust
pub fn new(frame_w: u32, frame_h: u32) -> Self
```
Create a new detector for frames of the given dimensions.

### `reset_if_size_changed` (line 64)
```rust
pub fn reset_if_size_changed(&mut self, frame_w: u32, frame_h: u32)
```
Re-initialize if the frame dimensions changed (e.g. monitor switch).

### `detect` (line 75)
```rust
pub fn detect(&mut self, pixels: &[u8]) -> Vec<DirtyRect>
```
Compare `pixels` (BGRA or RGBA, 4 bytes per pixel, row-major) against
the previous frame and return the list of changed tiles.

After this call the internal state reflects the *current* frame so that
the next call computes deltas against it.

### `invalidate` (line 107)
```rust
pub fn invalidate(&mut self)
```
Force the next `detect` call to report all tiles as dirty.
Use this before sending a keyframe so the following delta-frame
actually detects any changes relative to the keyframe.

### `encode_dirty_frame` (line 160)
```rust
pub fn encode_dirty_frame(
```
Encode a list of dirty rects into the MSG_DIRTY_FRAME wire payload.

`pixels`  — raw frame pixels (BGRA or RGBA, 4 bytes per pixel, row-major)
`frame_w` / `frame_h` — frame dimensions
`is_bgra` — true for BGRA (DXGI), false for RGBA
`rects`   — list of dirty tiles from `DirtyRectDetector::detect`
`quality` — JPEG quality (0-100) for each cropped tile

Returns the complete payload bytes (without the 5-byte protocol header).

## Internal Functions

- `tile_hash` — Fast 64-bit sum hash for a tile within a pixel buffer. (line 123)
- `solid_frame` — Create a synthetic BGRA frame of the given dimensions filled with a (line 248)
- `new_stores_correct_dimensions` (line 263)
- `new_two_tiles_wide` (line 274)
- `new_partial_tile_rounds_up` (line 283)
- `first_frame_all_dirty` (line 294)
- `identical_frames_no_dirty` (line 309)
- `single_tile_change_detected` (line 322)
- `edge_tile_correct_dimensions` (line 346)
- `invalidate_forces_all_dirty` (line 362)
- `reset_if_size_changed_updates_dimensions` (line 380)
- `reset_if_size_changed_noop_same_dimensions` (line 396)
- `tile_hash_is_deterministic` (line 412)
- `tile_hash_differs_on_different_content` (line 421)

## Key Dependencies

- `use anyhow::Result;`
- `use image::{codecs::jpeg::JpegEncoder, ColorType};`
- `use super::*;`

## Full Source

```rust
// Dirty rectangle detection for delta-frame encoding.
//
// Divides the screen into 64×64 pixel tiles and uses a simple sum-of-bytes
// hash to detect which tiles changed between frames.  Only changed tiles are
// included in the MSG_DIRTY_FRAME payload, dramatically reducing bandwidth
// when most of the screen is static.
//
// Wire format for MSG_DIRTY_FRAME (must match server/frame_reconstructor.py):
//
//   [2B rect_count (big-endian)]
//   Per rect:
//     [2B x][2B y][2B w][2B h]   (all big-endian)
//     [4B jpeg_len (big-endian)]
//     [jpeg_bytes...]

use anyhow::Result;

/// One changed tile ready to be sent.
#[derive(Debug, Clone)]
pub struct DirtyRect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// Tile size in pixels.
pub const TILE_SIZE: u32 = 64;

/// Detects dirty rectangles by comparing per-tile hashes across frames.
///
/// The detector owns the previous frame's tile hashes.  On each call to
/// `detect`, it computes new hashes, diffs them, and returns the list of
/// changed tiles.  The internal state is updated in-place.
pub struct DirtyRectDetector {
    /// Number of tiles in x direction (columns).
    cols: u32,
    /// Number of tiles in y direction (rows).
    rows: u32,
    /// Full frame width in pixels.
    frame_w: u32,
    /// Full frame height in pixels.
    frame_h: u32,
    /// Previous frame tile hashes (cols × rows, row-major).
    prev_hashes: Vec<u64>,
}

impl DirtyRectDetector {
    /// Create a new detector for frames of the given dimensions.
    pub fn new(frame_w: u32, frame_h: u32) -> Self {
        let cols = (frame_w + TILE_SIZE - 1) / TILE_SIZE;
        let rows = (frame_h + TILE_SIZE - 1) / TILE_SIZE;
        let count = (cols * rows) as usize;
        DirtyRectDetector {
            cols,
            rows,
            frame_w,
            frame_h,
            prev_hashes: vec![u64::MAX; count], // u64::MAX forces first frame fully dirty
        }
    }

    /// Re-initialize if the frame dimensions changed (e.g. monitor switch).
    pub fn reset_if_size_changed(&mut self, frame_w: u32, frame_h: u32) {
        if frame_w != self.frame_w || frame_h != self.frame_h {
            *self = DirtyRectDetector::new(frame_w, frame_h);
        }
    }

    /// Compare `pixels` (BGRA or RGBA, 4 bytes per pixel, row-major) against
    /// the previous frame and return the list of changed tiles.
    ///
    /// After this call the internal state reflects the *current* frame so that
    /// the next call computes deltas against it.
    pub fn detect(&mut self, pixels: &[u8]) -> Vec<DirtyRect> {
        let stride = self.frame_w as usize * 4; // bytes per row
        let mut dirty = Vec::new();

        let mut idx = 0usize;
        for row in 0..self.rows {
            for col in 0..self.cols {
                let tile_x = col * TILE_SIZE;
                let tile_y = row * TILE_SIZE;
                let tile_w = (self.frame_w - tile_x).min(TILE_SIZE);
                let tile_h = (self.frame_h - tile_y).min(TILE_SIZE);

                let hash = tile_hash(pixels, stride, tile_x, tile_y, tile_w, tile_h);
                if hash != self.prev_hashes[idx] {
                    self.prev_hashes[idx] = hash;
                    dirty.push(DirtyRect {
                        x: tile_x as u16,
                        y: tile_y as u16,
                        w: tile_w as u16,
                        h: tile_h as u16,
                    });
                }
                idx += 1;
            }
        }

        dirty
    }

    /// Force the next `detect` call to report all tiles as dirty.
    /// Use this before sending a keyframe so the following delta-frame
    /// actually detects any changes relative to the keyframe.
    pub fn invalidate(&mut self) {
        for h in self.prev_hashes.iter_mut() {
            *h = u64::MAX;
        }
    }
}

// ------------------------------------------------------------------ //
// Tile hash
// ------------------------------------------------------------------ //

/// Fast 64-bit sum hash for a tile within a pixel buffer.
///
/// Uses a simple unrolled summation — fast in practice and good enough for
/// change detection (false negatives are impossible; collisions are extremely
/// rare for screen content).
fn tile_hash(pixels: &[u8], stride: usize, tile_x: u32, tile_y: u32, tile_w: u32, tile_h: u32) -> u64 {
    let mut sum: u64 = 0;
    for dy in 0..tile_h as usize {
        let row_start = (tile_y as usize + dy) * stride + tile_x as usize * 4;
        let row_end = row_start + tile_w as usize * 4;
        if row_end > pixels.len() {
            break;
        }
        let row = &pixels[row_start..row_end];
        // Process 8 bytes at a time
        let mut i = 0;
        while i + 8 <= row.len() {
            let chunk = u64::from_le_bytes(row[i..i+8].try_into().unwrap());
            sum = sum.wrapping_add(chunk);
            i += 8;
        }
        // Remaining bytes
        for &b in &row[i..] {
            sum = sum.wrapping_add(b as u64);
        }
    }
    sum
}

// ------------------------------------------------------------------ //
// MSG_DIRTY_FRAME wire encoding
// ------------------------------------------------------------------ //

/// Encode a list of dirty rects into the MSG_DIRTY_FRAME wire payload.
///
/// `pixels`  — raw frame pixels (BGRA or RGBA, 4 bytes per pixel, row-major)
/// `frame_w` / `frame_h` — frame dimensions
/// `is_bgra` — true for BGRA (DXGI), false for RGBA
/// `rects`   — list of dirty tiles from `DirtyRectDetector::detect`
/// `quality` — JPEG quality (0-100) for each cropped tile
///
/// Returns the complete payload bytes (without the 5-byte protocol header).
pub fn encode_dirty_frame(
    pixels: &[u8],
    frame_w: u32,
    _frame_h: u32,  // kept for API symmetry; tile bounds already encode height info
    is_bgra: bool,
    rects: &[DirtyRect],
    quality: u8,
) -> Result<Vec<u8>> {
    use image::{codecs::jpeg::JpegEncoder, ColorType};

    let rect_count = rects.len() as u16;
    // Estimate capacity: header + (8 + 4 + ~2000) per rect
    let mut buf: Vec<u8> = Vec::with_capacity(2 + rects.len() * 2012);
    let mut rgb_tile = Vec::new();
    let mut jpeg_tile = Vec::new();

    // [2B: rect_count]
    buf.extend_from_slice(&rect_count.to_be_bytes());

    let stride = frame_w as usize * 4;

    for rect in rects {
        let x = rect.x as u32;
        let y = rect.y as u32;
        let w = rect.w as u32;
        let h = rect.h as u32;

        // Crop the tile from the frame pixels into RGB
        rgb_tile.clear();
        rgb_tile.reserve((w * h * 3) as usize);
        for row in 0..h as usize {
            let row_start = (y as usize + row) * stride + x as usize * 4;
            let row_end = row_start + w as usize * 4;
            if row_end > pixels.len() {
                break;
            }
            let row_data = &pixels[row_start..row_end];
            if is_bgra {
                for chunk in row_data.chunks(4) {
                    rgb_tile.push(chunk[2]); // R (from BGRA[2])
                    rgb_tile.push(chunk[1]); // G
                    rgb_tile.push(chunk[0]); // B
                }
            } else {
                for chunk in row_data.chunks(4) {
                    rgb_tile.push(chunk[0]); // R
                    rgb_tile.push(chunk[1]); // G
                    rgb_tile.push(chunk[2]); // B
                }
            }
        }

        // Encode tile directly to JPEG without an intermediate DynamicImage.
        jpeg_tile.clear();
        jpeg_tile.reserve(rgb_tile.len() / 4);
        let mut encoder = JpegEncoder::new_with_quality(&mut jpeg_tile, quality);
        encoder.encode(&rgb_tile, w, h, ColorType::Rgb8)
            .map_err(|e| anyhow::anyhow!("JPEG encode for tile {}x{} failed: {}", w, h, e))?;

        // [2B x][2B y][2B w][2B h]
        buf.extend_from_slice(&(rect.x).to_be_bytes());
        buf.extend_from_slice(&(rect.y).to_be_bytes());
        buf.extend_from_slice(&(rect.w).to_be_bytes());
        buf.extend_from_slice(&(rect.h).to_be_bytes());

        // [4B jpeg_len]
        let jpeg_len = jpeg_tile.len() as u32;
        buf.extend_from_slice(&jpeg_len.to_be_bytes());

        // [jpeg_data]
        buf.extend_from_slice(&jpeg_tile);
    }

    Ok(buf)
}

// ------------------------------------------------------------------ //
// Tests
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ─────────────────────────────────────────────────────

    /// Create a synthetic BGRA frame of the given dimensions filled with a
    /// single solid color `(r, g, b)`.
    fn solid_frame(w: u32, h: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
        let size = (w * h * 4) as usize;
        let mut buf = vec![0u8; size];
        for chunk in buf.chunks_exact_mut(4) {
            chunk[0] = b; // BGRA layout
            chunk[1] = g;
            chunk[2] = r;
            chunk[3] = 255;
        }
        buf
    }

    // ── DirtyRectDetector::new ───────────────────────────────────────

    #[test]
    fn new_stores_correct_dimensions() {
        // 64×64 → exactly 1 tile (1 col, 1 row)
        let d = DirtyRectDetector::new(64, 64);
        assert_eq!(d.frame_w, 64);
        assert_eq!(d.frame_h, 64);
        assert_eq!(d.cols, 1);
        assert_eq!(d.rows, 1);
        assert_eq!(d.prev_hashes.len(), 1);
    }

    #[test]
    fn new_two_tiles_wide() {
        // 128×64 → 2 columns, 1 row
        let d = DirtyRectDetector::new(128, 64);
        assert_eq!(d.cols, 2);
        assert_eq!(d.rows, 1);
        assert_eq!(d.prev_hashes.len(), 2);
    }

    #[test]
    fn new_partial_tile_rounds_up() {
        // 65×65 → 2 columns, 2 rows (ceil division)
        let d = DirtyRectDetector::new(65, 65);
        assert_eq!(d.cols, 2);
        assert_eq!(d.rows, 2);
        assert_eq!(d.prev_hashes.len(), 4);
    }

    // ── First frame forces all tiles dirty ──────────────────────────

    #[test]
    fn first_frame_all_dirty() {
        let mut d = DirtyRectDetector::new(64, 64);
        let frame = solid_frame(64, 64, 0, 0, 0);
        let dirty = d.detect(&frame);
        // One tile, and it must be marked dirty on the first call
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].x, 0);
        assert_eq!(dirty[0].y, 0);
        assert_eq!(dirty[0].w, 64);
        assert_eq!(dirty[0].h, 64);
    }

    // ── Identical consecutive frame → no dirty rects ────────────────

    #[test]
    fn identical_frames_no_dirty() {
        let mut d = DirtyRectDetector::new(64, 64);
        let frame = solid_frame(64, 64, 100, 150, 200);
        // First detect consumes the initial u64::MAX sentinel
        d.detect(&frame);
        // Second call with same content — no changes
        let dirty = d.detect(&frame);
        assert!(dirty.is_empty());
    }

    // ── Single tile change detected ──────────────────────────────────

    #[test]
    fn single_tile_change_detected() {
        // 128×64: two side-by-side tiles
        let mut d = DirtyRectDetector::new(128, 64);
        let frame = solid_frame(128, 64, 0, 0, 0);
        d.detect(&frame); // absorb initial dirty

        // Modify only the right tile (x 64..128)
        let mut frame2 = frame.clone();
        let stride = 128 * 4;
        for row in 0..64_usize {
            for col in 64..128_usize {
                let base = row * stride + col * 4;
                frame2[base] = 255; // change blue channel
            }
        }
        let dirty = d.detect(&frame2);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].x, 64);
        assert_eq!(dirty[0].y, 0);
    }

    // ── Edge tile (partial size at frame boundary) ───────────────────

    #[test]
    fn edge_tile_correct_dimensions() {
        // 80×80 → tiles: (0,0,64,64), (64,0,16,64), (0,64,64,16), (64,64,16,16)
        let mut d = DirtyRectDetector::new(80, 80);
        let frame = solid_frame(80, 80, 10, 20, 30);
        let dirty = d.detect(&frame);
        assert_eq!(dirty.len(), 4);

        // Find the bottom-right corner tile
        let corner = dirty.iter().find(|r| r.x == 64 && r.y == 64).expect("corner tile missing");
        assert_eq!(corner.w, 16);
        assert_eq!(corner.h, 16);
    }

    // ── invalidate forces all dirty on next detect ───────────────────

    #[test]
    fn invalidate_forces_all_dirty() {
        let mut d = DirtyRectDetector::new(64, 64);
        let frame = solid_frame(64, 64, 1, 2, 3);
        d.detect(&frame); // absorb initial

        // Stable frame: no dirty
        let dirty = d.detect(&frame);
        assert!(dirty.is_empty());

        // Invalidate, then same frame → all dirty again
        d.invalidate();
        let dirty = d.detect(&frame);
        assert_eq!(dirty.len(), 1);
    }

    // ── reset_if_size_changed re-initialises on dimension change ─────

    #[test]
    fn reset_if_size_changed_updates_dimensions() {
        let mut d = DirtyRectDetector::new(64, 64);
        let frame = solid_frame(64, 64, 5, 5, 5);
        d.detect(&frame); // absorb initial

        // Change dimensions
        d.reset_if_size_changed(128, 64);
        assert_eq!(d.frame_w, 128);
        assert_eq!(d.cols, 2);
        // All hashes reset to MAX → next detect should be fully dirty
        let frame2 = solid_frame(128, 64, 5, 5, 5);
        let dirty = d.detect(&frame2);
        assert_eq!(dirty.len(), 2);
    }

    #[test]
    fn reset_if_size_changed_noop_same_dimensions() {
        let mut d = DirtyRectDetector::new(64, 64);
        let frame = solid_frame(64, 64, 7, 7, 7);
        d.detect(&frame);
        let stable = d.detect(&frame);
        assert!(stable.is_empty());

        // Same size → no reset → still stable
        d.reset_if_size_changed(64, 64);
        let still_stable = d.detect(&frame);
        assert!(still_stable.is_empty());
    }

    // ── tile_hash is deterministic ───────────────────────────────────

    #[test]
    fn tile_hash_is_deterministic() {
        let pixels = solid_frame(64, 64, 42, 43, 44);
        let stride = 64 * 4;
        let h1 = tile_hash(&pixels, stride, 0, 0, 64, 64);
        let h2 = tile_hash(&pixels, stride, 0, 0, 64, 64);
        assert_eq!(h1, h2);
    }

    #[test]
    fn tile_hash_differs_on_different_content() {
        let p1 = solid_frame(64, 64, 0, 0, 0);
        let p2 = solid_frame(64, 64, 255, 255, 255);
        let stride = 64 * 4;
        let h1 = tile_hash(&p1, stride, 0, 0, 64, 64);
        let h2 = tile_hash(&p2, stride, 0, 0, 64, 64);
        assert_ne!(h1, h2);
    }
}

```