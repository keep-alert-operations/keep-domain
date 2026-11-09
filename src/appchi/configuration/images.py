"""Uploaded dashboard images: file-header checks and limits (REV-62).

The server reads only each file's own header with the standard library. It finds the
real type and pixel size, never decodes or re-encodes the image, and serves the bytes
with the type found here, ``nosniff`` and a sandbox content security policy.
"""

import struct

MEDIA_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")
MAX_BYTES = 5 * 1024 * 1024
MAX_SIDE = 8000
TENANT_QUOTA = 500 * 1024 * 1024
# Never-used uploads older than this are removed, a bounded batch per later upload.
UNUSED_AFTER_HOURS = 24
UNUSED_BATCH = 50

_PNG = b"\x89PNG\r\n\x1a\n"
# JPEG start-of-frame markers carry the frame size; C4, C8 and CC are other segments.
_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


class InvalidImage(ValueError):
    """The bytes are not a supported image within the limits."""


def _png(data):
    if len(data) < 24 or data[12:16] != b"IHDR":
        raise InvalidImage("PNG header is incomplete")
    return struct.unpack(">II", data[16:24])


def _gif(data):
    if len(data) < 10:
        raise InvalidImage("GIF header is incomplete")
    return struct.unpack("<HH", data[6:10])


def _jpeg(data):
    position = 2
    while position + 4 <= len(data):
        if data[position] != 0xFF:
            raise InvalidImage("JPEG segment is malformed")
        marker = data[position + 1]
        if marker == 0xFF:  # fill byte
            position += 1
            continue
        if marker in (0x01, *range(0xD0, 0xD8)):  # markers without a length
            position += 2
            continue
        if marker in (0xD9, 0xDA):
            break
        (length,) = struct.unpack(">H", data[position + 2 : position + 4])
        if length < 2:
            raise InvalidImage("JPEG segment is malformed")
        if marker in _SOF:
            if position + 9 > len(data):
                break
            height, width = struct.unpack(">HH", data[position + 5 : position + 9])
            return width, height
        position += 2 + length
    raise InvalidImage("JPEG frame size not found")


def _webp(data):
    if len(data) < 30:
        raise InvalidImage("WebP header is incomplete")
    (riff,) = struct.unpack("<I", data[4:8])
    if riff + 8 > len(data) or riff < 4:
        raise InvalidImage("WebP file is truncated")
    chunk = data[12:16]
    if chunk == b"VP8 ":
        if data[23:26] != b"\x9d\x01\x2a":
            raise InvalidImage("WebP frame is malformed")
        width, height = struct.unpack("<HH", data[26:30])
        return width & 0x3FFF, height & 0x3FFF
    if chunk == b"VP8L":
        if data[20] != 0x2F:
            raise InvalidImage("WebP frame is malformed")
        b0, b1, b2, b3 = data[21:25]
        width = 1 + (b0 | (b1 & 0x3F) << 8)
        height = 1 + (b1 >> 6 | b2 << 2 | (b3 & 0x0F) << 10)
        return width, height
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
        return width, height
    raise InvalidImage("WebP chunk is not supported")


def inspect(data):
    """Return ``(media_type, width, height)`` for a supported image, else raise."""
    if not data:
        raise InvalidImage("The file is empty")
    if len(data) > MAX_BYTES:
        raise InvalidImage("The file exceeds 5 MiB")
    if data.startswith(_PNG):
        media, (width, height) = "image/png", _png(data)
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        media, (width, height) = "image/gif", _gif(data)
    elif data.startswith(b"\xff\xd8\xff"):
        media, (width, height) = "image/jpeg", _jpeg(data)
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        media, (width, height) = "image/webp", _webp(data)
    else:
        raise InvalidImage("Use a PNG, JPEG, GIF or WebP image")
    if not (1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE):
        raise InvalidImage(f"Images can be at most {MAX_SIDE:,} pixels on each side")
    return media, width, height
