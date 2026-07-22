#!/usr/bin/env python3
import binascii
import math
import struct
import zlib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "hugin" / "assets" / "raven-source.png"
ASSETS = SOURCE.parent


def paeth(a, b, c):
    estimate = a + b - c
    distances = (abs(estimate - a), abs(estimate - b), abs(estimate - c))
    return (a, b, c)[distances.index(min(distances))]


def decode_png(path):
    payload = path.read_bytes()
    if payload[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG")
    chunks = []
    offset = 8
    while offset < len(payload):
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        kind = payload[offset + 4 : offset + 8]
        chunks.append((kind, payload[offset + 8 : offset + 8 + length]))
        offset += length + 12
    header = next(data for kind, data in chunks if kind == b"IHDR")
    width, height, depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", header)
    if depth != 8 or color_type not in {2, 6} or interlace:
        raise ValueError("Expected a non-interlaced 8-bit RGB/RGBA PNG")
    channels = 3 if color_type == 2 else 4
    stride = width * channels
    raw = zlib.decompress(b"".join(data for kind, data in chunks if kind == b"IDAT"))
    rows = []
    previous = bytearray(stride)
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        row = bytearray(raw[cursor : cursor + stride])
        cursor += stride
        for index in range(stride):
            left = row[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 1:
                row[index] = (row[index] + left) & 255
            elif filter_type == 2:
                row[index] = (row[index] + up) & 255
            elif filter_type == 3:
                row[index] = (row[index] + ((left + up) // 2)) & 255
            elif filter_type == 4:
                row[index] = (row[index] + paeth(left, up, upper_left)) & 255
            elif filter_type != 0:
                raise ValueError(f"Unsupported PNG filter {filter_type}")
        previous = row
        rgba = bytearray(width * 4)
        for x in range(width):
            source_index = x * channels
            target_index = x * 4
            rgba[target_index : target_index + 3] = row[source_index : source_index + 3]
            rgba[target_index + 3] = row[source_index + 3] if channels == 4 else 255
        rows.append(rgba)
    return width, height, rows


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)


def encode_png(path, width, height, pixels):
    scanlines = b"".join(b"\x00" + bytes(pixels[y * width * 4 : (y + 1) * width * 4]) for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    payload = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(scanlines, 9)) + chunk(b"IEND", b"")
    path.write_bytes(payload)


def fit_alpha(pixel, background, foreground):
    vector = tuple(foreground[index] - background[index] for index in range(3))
    denominator = sum(value * value for value in vector)
    alpha = sum((pixel[index] - background[index]) * vector[index] for index in range(3)) / denominator
    return max(0.0, min(1.0, alpha))


def extract_layers(width, height, rows):
    background = tuple(rows[0][:3])
    colors = Counter()
    for row in rows:
        for x in range(width):
            rgb = tuple(row[x * 4 : x * 4 + 3])
            if rgb[0] > 100 and rgb[0] > rgb[1] * 1.8 and rgb[0] > rgb[2] * 1.8:
                colors[rgb] += 1
    red = colors.most_common(1)[0][0]
    black = (0, 0, 0)
    combined = bytearray(width * height * 4)
    red_layer = bytearray(width * height * 4)
    black_layer = bytearray(width * height * 4)
    visible = []
    for y, row in enumerate(rows):
        for x in range(width):
            source_index = x * 4
            target_index = (y * width + x) * 4
            rgb = tuple(row[source_index : source_index + 3])
            is_red = rgb[0] > 55 and rgb[0] > rgb[1] * 1.55 and rgb[0] > rgb[2] * 1.55
            foreground = red if is_red else black
            alpha = fit_alpha(rgb, background, foreground)
            alpha = 0.0 if alpha < 0.045 else min(1.0, (alpha - 0.045) / 0.82)
            if alpha <= 0:
                continue
            output_rgb = rgb if alpha > 0.92 else foreground
            output_alpha = round(alpha * 255)
            pixel = bytes((*output_rgb, output_alpha))
            combined[target_index : target_index + 4] = pixel
            layer = red_layer if is_red else black_layer
            layer[target_index : target_index + 4] = pixel
            visible.append((x, y))
    if not visible:
        raise ValueError("No raven pixels survived background removal")
    return combined, red_layer, black_layer, visible


def square_crop(width, height, pixels, visible, padding_ratio=0.055):
    left = min(x for x, _ in visible)
    right = max(x for x, _ in visible)
    top = min(y for _, y in visible)
    bottom = max(y for _, y in visible)
    padding = math.ceil(max(right - left + 1, bottom - top + 1) * padding_ratio)
    side = max(right - left + 1, bottom - top + 1) + padding * 2
    center_x = (left + right) / 2
    center_y = (top + bottom) / 2
    origin_x = round(center_x - side / 2)
    origin_y = round(center_y - side / 2)
    output = bytearray(side * side * 4)
    for target_y in range(side):
        source_y = origin_y + target_y
        if source_y < 0 or source_y >= height:
            continue
        for target_x in range(side):
            source_x = origin_x + target_x
            if source_x < 0 or source_x >= width:
                continue
            source_index = (source_y * width + source_x) * 4
            target_index = (target_y * side + target_x) * 4
            output[target_index : target_index + 4] = pixels[source_index : source_index + 4]
    return side, output


def complete_red_moon(width, height, pixels):
    visible = []
    colors = Counter()
    for y in range(height):
        for x in range(width):
            index = (y * width + x) * 4
            if pixels[index + 3] > 220:
                visible.append((x, y))
                colors[tuple(pixels[index : index + 3])] += 1
    top = min(y for _, y in visible)
    bottom = max(y for _, y in visible)
    right = max(x for x, _ in visible)
    radius = (bottom - top) / 2
    center_x = right - radius
    center_y = (top + bottom) / 2
    red = colors.most_common(1)[0][0]
    for y in range(max(0, math.floor(center_y - radius - 1)), min(height, math.ceil(center_y + radius + 1))):
        for x in range(max(0, math.floor(center_x - radius - 1)), min(width, math.ceil(center_x + radius + 1))):
            distance = math.hypot(x + 0.5 - center_x, y + 0.5 - center_y)
            coverage = max(0.0, min(1.0, radius + 0.5 - distance))
            index = (y * width + x) * 4
            if coverage > 0:
                pixels[index : index + 4] = bytes((*red, max(pixels[index + 3], round(coverage * 255))))


def resize_rgba(source_size, pixels, target_size):
    output = bytearray(target_size * target_size * 4)
    scale = source_size / target_size
    for y in range(target_size):
        source_y = (y + 0.5) * scale - 0.5
        y0 = max(0, min(source_size - 1, math.floor(source_y)))
        y1 = min(source_size - 1, y0 + 1)
        fy = source_y - math.floor(source_y)
        for x in range(target_size):
            source_x = (x + 0.5) * scale - 0.5
            x0 = max(0, min(source_size - 1, math.floor(source_x)))
            x1 = min(source_size - 1, x0 + 1)
            fx = source_x - math.floor(source_x)
            samples = ((x0, y0, (1 - fx) * (1 - fy)), (x1, y0, fx * (1 - fy)), (x0, y1, (1 - fx) * fy), (x1, y1, fx * fy))
            alpha = sum((pixels[(sy * source_size + sx) * 4 + 3] / 255) * weight for sx, sy, weight in samples)
            target_index = (y * target_size + x) * 4
            output[target_index + 3] = round(alpha * 255)
            if alpha == 0:
                continue
            for channel in range(3):
                premultiplied = sum(
                    pixels[(sy * source_size + sx) * 4 + channel]
                    * (pixels[(sy * source_size + sx) * 4 + 3] / 255)
                    * weight
                    for sx, sy, weight in samples
                )
                output[target_index + channel] = round(premultiplied / alpha)
    return output


def main():
    width, height, rows = decode_png(SOURCE)
    combined, red, black, visible = extract_layers(width, height, rows)
    complete_red_moon(width, height, red)
    size, combined = square_crop(width, height, combined, visible)
    _, red = square_crop(width, height, red, visible)
    _, black = square_crop(width, height, black, visible)
    encode_png(ASSETS / "raven-mark.png", size, size, combined)
    encode_png(ASSETS / "raven-red.png", size, size, red)
    encode_png(ASSETS / "raven-black.png", size, size, black)
    encode_png(ASSETS / "favicon.png", 32, 32, resize_rgba(size, combined, 32))
    print(f"Raven assets generated: source={width}x{height} mark={size}x{size} favicon=32x32")


if __name__ == "__main__":
    main()
