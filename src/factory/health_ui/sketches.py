"""Fail-closed handling for clinician sketch captures.

The browser supplies a PNG data URL.  This module accepts only a bounded PNG,
derives its dimensions and digest from the bytes, and returns an immutable
asset.  It does not interpret, OCR, resize, or send the image anywhere.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import zlib

from factory.health_ui.documents import SketchAsset

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PNG_BYTES = 2_000_000
MAX_DIMENSION = 4096
MAX_PIXELS = 8_000_000


class InvalidSketch(ValueError):
    """The submitted capture is not a safe, bounded PNG."""


def decode_png(data_url: str) -> tuple[SketchAsset, bytes]:
    """Validate a PNG data URL and return its immutable record and bytes."""

    prefix = "data:image/png;base64,"
    if not data_url.startswith(prefix):
        raise InvalidSketch("a sketch must be a PNG image")
    encoded = data_url[len(prefix):]
    if not encoded or len(encoded) > ((MAX_PNG_BYTES + 2) // 3) * 4 + 8:
        raise InvalidSketch("the sketch image is empty or too large")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSketch("the sketch image is not valid base64") from exc
    if len(payload) > MAX_PNG_BYTES:
        raise InvalidSketch("the sketch image is too large")
    width, height = png_dimensions(payload)
    canonical = base64.b64encode(payload).decode("ascii")
    return (
        SketchAsset(
            png_base64=canonical,
            digest=hashlib.sha256(payload).hexdigest(),
            width=width,
            height=height,
        ),
        payload,
    )


def png_dimensions(payload: bytes) -> tuple[int, int]:
    """Validate the PNG chunk framing and return trusted IHDR dimensions."""

    if len(payload) < 33 or not payload.startswith(PNG_SIGNATURE):
        raise InvalidSketch("the sketch image is not a PNG")
    position = 8
    width = height = 0
    channels = 0
    idat = bytearray()
    saw_idat = saw_iend = False
    chunk_number = 0
    while position + 12 <= len(payload):
        length = struct.unpack(">I", payload[position:position + 4])[0]
        if length > MAX_PNG_BYTES or position + 12 + length > len(payload):
            raise InvalidSketch("the sketch PNG has an invalid chunk length")
        kind = payload[position + 4:position + 8]
        data_start = position + 8
        data_end = data_start + length
        data = payload[data_start:data_end]
        expected_crc = struct.unpack(">I", payload[data_end:data_end + 4])[0]
        actual_crc = binascii.crc32(kind + data) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise InvalidSketch("the sketch PNG has a corrupt chunk")
        if chunk_number == 0:
            if kind != b"IHDR" or length != 13:
                raise InvalidSketch("the sketch PNG has no valid IHDR header")
            width, height = struct.unpack(">II", data[:8])
            bit_depth, colour, compression, filtering, interlace = data[8:13]
            if (bit_depth, colour) not in {(8, 2), (8, 6)}:
                raise InvalidSketch("the sketch PNG has an unsupported pixel format")
            if compression != 0 or filtering != 0 or interlace != 0:
                raise InvalidSketch("the sketch PNG uses an unsupported encoding")
            channels = 3 if colour == 2 else 4
        elif kind == b"IHDR":
            raise InvalidSketch("the sketch PNG has more than one IHDR header")
        elif kind not in {b"IDAT", b"IEND"}:
            # Canvas captures need no metadata. Keeping arbitrary ancillary
            # chunks would persist information that the clinician cannot see
            # in the sketch preview (for example comments or location data).
            raise InvalidSketch("the sketch PNG has an unsupported chunk")
        if kind == b"IDAT":
            saw_idat = True
            idat.extend(data)
        if kind == b"IEND":
            if length != 0:
                raise InvalidSketch("the sketch PNG has an invalid end chunk")
            saw_iend = True
            position = data_end + 4
            break
        position = data_end + 4
        chunk_number += 1
    if not saw_idat or not saw_iend or position != len(payload):
        raise InvalidSketch("the sketch PNG is incomplete")
    if width < 1 or height < 1:
        raise InvalidSketch("the sketch dimensions are invalid")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise InvalidSketch("the sketch dimensions are too large")
    if width * height > MAX_PIXELS:
        raise InvalidSketch("the sketch has too many pixels")
    expected = height * (1 + width * channels)
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(bytes(idat), expected + 1)
        if len(pixels) > expected or decoder.unconsumed_tail:
            raise InvalidSketch("the sketch PNG image data is too large")
        pixels += decoder.flush()
    except zlib.error as exc:
        raise InvalidSketch("the sketch PNG has invalid image data") from exc
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(pixels) != expected):
        raise InvalidSketch("the sketch PNG image data has the wrong size")
    row_bytes = 1 + width * channels
    if any(pixels[offset] > 4 for offset in range(0, expected, row_bytes)):
        raise InvalidSketch("the sketch PNG has an invalid scanline filter")
    return width, height


def asset_bytes(asset: SketchAsset) -> bytes:
    """Decode a previously validated asset and re-check its binding."""

    try:
        payload = base64.b64decode(asset.png_base64, validate=True)
    except (binascii.Error, ValueError) as exc:  # corrupt durable state
        raise InvalidSketch("stored sketch data is corrupt") from exc
    width, height = png_dimensions(payload)
    if (width, height) != (asset.width, asset.height):
        raise InvalidSketch("stored sketch dimensions do not match")
    if hashlib.sha256(payload).hexdigest() != asset.digest:
        raise InvalidSketch("stored sketch digest does not match")
    return payload
