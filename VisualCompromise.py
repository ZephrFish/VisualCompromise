#!/usr/bin/env python3
"""VisualCompromise: hide a file inside an image.

Usage:
    python VisualCompromise.py encode <input_file> <carrier_image> [-o output] [-e b64|b32]
        [-m auto|lsb|jpeg|canvas] [--bit 0-7] [--channel r|g|b|all] [--grid N] [--js-exec]
    python VisualCompromise.py decode <encoded_image> [-o output_file]

Three embedding methods share the same base64/base32 payload:

lsb    The payload is written one bit per RGB channel byte into the LSBs of the
       carrier and saved as PNG (JPEG is lossy and would destroy the LSBs).
       Header layout (big-endian):
           magic "VC01" (4) | payload length (uint32, 4) | encoding flag (1)

jpeg   The payload is split across JPEG COM (comment, FF FE) markers inserted
       after SOI. Pixel data is untouched and the output is a valid JPEG.
       Per-chunk header (big-endian, 13 bytes, then the chunk data):
           magic "VC01" (4) | total encoded length (uint32, 4) | encoding flag (1)
           | chunk_index (uint16, 2) | total_chunks (uint16, 2)

canvas Configurable LSB placement: a chosen bit-plane (--bit, 0 to 7), colour
       channel (--channel, r/g/b, or all for a redundant majority-vote read)
       and pixel spacing (--grid, every Nth pixel) instead of lsb's fixed
       bit-0/every-byte scheme. A 7-byte VC02 preamble, written with the same
       fixed scheme as lsb so decode can read it without being told the
       parameters, records bit/channel/grid ahead of the VC01-headed payload,
       which is then written using those parameters. Output is always PNG, as
       with lsb. Also writes a standalone <output>.decoder.html that decodes
       the image client-side via <canvas>/getImageData, with no server or
       Python involved. Ported from the configurable bit-plane/channel/grid
       mechanism and canvas decode technique in Saumil Shah's Stegosploit
       (python-stegosploit, https://github.com/amichael7/python-stegosploit,
       HITB/BlackHat 2015); that project's bundled IE CVE-2014-0282 exploit
       payload is not part of this port. --js-exec is opt-in only: it makes
       the generated decoder page run the decoded payload as JavaScript on
       load, for research/demo exploit-delivery use, and is labelled visibly
       on the page; it is never the default.

decode tries the JPEG COM method first, then whole-image LSB, then the VC02
canvas preamble.

@decision DEC-VC-001
@title Single script with length header, PNG output and i*8+bit indexing
@status accepted
@rationale Replaces EncodeThatPic.py / DecodeThatPic.py, which (1) overlapped
  bit writes by indexing i..i+7 per byte, (2) saved as JPEG so LSBs were lost,
  (3) had no length header so the decoder read the whole image, and
  (4) hardcoded the output path.

@decision DEC-VC-003
@title Add JPEG COM-marker method alongside LSB; decoder auto-detects
@status accepted
@rationale LSB cannot survive JPEG output, yet the tool targets JPEG carriers.
  COM markers live in the JPEG container, leave pixels bit-identical, and keep
  the file a valid JPEG. Same VC01 magic is reused; the decoder checks COM
  markers first (cheap byte scan) and falls back to pixel LSBs. Trade-off: COM
  data is trivially visible to a hex dump or `strings` and is stripped by any
  re-encode or metadata scrubber, whereas LSB-in-PNG is less obvious.

@decision DEC-VC-004
@title Canvas method is additive, not a replacement for lsb
@status accepted
@rationale lsb's fixed bit-0/every-byte scheme is simpler and higher capacity.
  Stegosploit's value is configurability (a bit/channel/grid trade-off between
  capacity and detectability) and a no-server browser decoder. Both are new
  capabilities layered alongside lsb, not a replacement for it; lsb remains
  the default for anyone who just wants maximum capacity.

@decision DEC-VC-005
@title VC02 preamble reuses the fixed LSB scheme instead of a new reader
@status accepted
@rationale The canvas payload's own bit/channel/grid parameters must be known
  before they can be used to read the payload, so they cannot be stored using
  themselves. A small fixed-scheme (bit0, sequential-byte) preamble with a
  distinct VC02 magic lets decode() reuse the existing
  _embed_payload/_extract_bytes primitives instead of a second reader, at the
  cost of a few bytes of carrier capacity ahead of the canvas payload.
"""
import argparse
import base64
import html
import os
import struct
import sys

from PIL import Image

MAGIC = b"VC01"
HEADER_SIZE = 9
ENC_B64 = 0
ENC_B32 = 1
CHUNK_HEADER_SIZE = 13
COM_MAX_BODY = 65533  # 16-bit length field (65535) minus the 2 length bytes
CHUNK_DATA_MAX = COM_MAX_BODY - CHUNK_HEADER_SIZE  # 65520
ENCODERS = {"b64": (ENC_B64, base64.b64encode), "b32": (ENC_B32, base64.b32encode)}

# ---------------------------------------------------------------- canvas method
PREAMBLE_MAGIC = b"VC02"
PREAMBLE_SIZE = 7  # magic(4) + bit(1) + channel_code(1) + grid(1)
PREAMBLE_FLAT_BYTES = PREAMBLE_SIZE * 8  # 56: flat RGB bytes touched (bit 0) by the preamble
# First pixel index the preamble never touches, not even partially. The preamble occupies
# flat RGB byte indices 0..55 (56 bytes); pixel 18 only has its first two (of three) bytes
# touched, so the canvas payload conservatively starts at the next whole pixel: ceil(56/3) = 19.
CANVAS_START_PIXEL = -(-PREAMBLE_FLAT_BYTES // 3)
CANVAS_CHANNELS = {"r": 0, "g": 1, "b": 2, "all": 3}

BANNER = """
╦  ╦╦╔═╗╦ ╦╔═╗╦    ╔═╗╔═╗╔╦╗╔═╗╦═╗╔═╗╔╦╗╦╔═╗╔═╗
╚╗╔╝║╚═╗║ ║╠═╣║    ║  ║ ║║║║╠═╝╠╦╝║ ║║║║║╚═╗║╣
 ╚╝ ╩╚═╝╚═╝╩ ╩╩═╝  ╚═╝╚═╝╩ ╩╩  ╩╚═╚═╝╩ ╩╩╚═╝╚═╝
    JPEG COM + LSB + Canvas Steganography · github.com/ZephrFish/VisualCompromise
"""
DECODERS = {ENC_B64: base64.b64decode, ENC_B32: base64.b32decode}


def _extract_bytes(img_data, start, count):
    """Read `count` payload bytes from the LSBs, beginning at payload byte `start`."""
    result = bytearray(count)
    for i in range(count):
        val = 0
        for bit in range(8):
            idx = (start + i) * 8 + bit
            val = (val << 1) | (img_data[idx] & 1)
        result[i] = val
    return bytes(result)


def _embed_payload(img_data, payload):
    """Write payload into the LSBs of img_data (a bytearray), 8 pixel bytes per byte."""
    for i, byte_val in enumerate(payload):
        for bit in range(8):
            idx = i * 8 + bit
            img_data[idx] = (img_data[idx] & 0xFE) | ((byte_val >> (7 - bit)) & 1)


def _is_jpeg(data):
    """True if data starts with the JPEG SOI marker."""
    return data[:2] == b"\xff\xd8"


def _jpeg_embed(carrier_bytes, payload, enc_flag=ENC_B64):
    """Embed encoded `payload` into JPEG COM markers. Returns modified JPEG bytes.

    `payload` is the already base64/base32 encoded data; `enc_flag` records which.
    Markers are inserted directly after SOI, ahead of APP/frame markers.
    """
    if not _is_jpeg(carrier_bytes):
        raise ValueError("Carrier is not a JPEG file (missing SOI marker)")
    total = max(1, -(-len(payload) // CHUNK_DATA_MAX))
    if total > 0xFFFF:
        raise ValueError("Payload too large for JPEG COM chunking")
    markers = bytearray()
    for idx in range(total):
        chunk = payload[idx * CHUNK_DATA_MAX:(idx + 1) * CHUNK_DATA_MAX]
        body = (MAGIC + struct.pack(">IBHH", len(payload), enc_flag, idx, total)
                + chunk)
        markers += b"\xff\xfe" + struct.pack(">H", len(body) + 2) + body
    return carrier_bytes[:2] + bytes(markers) + carrier_bytes[2:]


def _jpeg_com_bodies(jpeg_bytes):
    """Yield the body of each COM marker found before the scan data (SOS)."""
    i, n = 2, len(jpeg_bytes)
    while i + 1 < n:
        if jpeg_bytes[i] != 0xFF:
            return  # lost sync; not a well-formed header segment run
        marker = jpeg_bytes[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker in (0xDA, 0xD9):  # SOS / EOI: header segments are over
            return
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:  # standalone, no length
            i += 2
            continue
        if i + 4 > n:
            return
        length = struct.unpack(">H", jpeg_bytes[i + 2:i + 4])[0]
        if length < 2 or i + 2 + length > n:
            return
        if marker == 0xFE:
            yield jpeg_bytes[i + 4:i + 2 + length]
        i += 2 + length


def _jpeg_extract(jpeg_bytes):
    """Extract payload from JPEG COM markers. Returns (encoded_data, enc_flag) or None.

    None means no VC01 COM marker is present. Raises ValueError if markers are
    present but inconsistent or incomplete (missing chunk, length mismatch).
    """
    if not _is_jpeg(jpeg_bytes):
        return None
    chunks, meta = {}, None
    for body in _jpeg_com_bodies(jpeg_bytes):
        if body[:4] != MAGIC or len(body) < CHUNK_HEADER_SIZE:
            continue
        length, flag, idx, total = struct.unpack(">IBHH", body[4:CHUNK_HEADER_SIZE])
        if meta is None:
            meta = (length, flag, total)
        elif meta != (length, flag, total):
            raise ValueError("Inconsistent VisualCompromise chunk headers")
        if idx >= total:
            raise ValueError(f"Chunk index {idx} out of range (total {total})")
        chunks[idx] = body[CHUNK_HEADER_SIZE:]
    if meta is None:
        return None
    length, flag, total = meta
    if flag not in DECODERS:
        raise ValueError(f"Unknown encoding flag: {flag}")
    missing = [i for i in range(total) if i not in chunks]
    if missing:
        raise ValueError(f"Missing JPEG chunks: {missing}")
    data = b"".join(chunks[i] for i in range(total))
    if len(data) != length:
        raise ValueError("Reassembled length does not match header (corrupt JPEG)")
    return data, flag


def _write_bytes(path, data):
    """Write data to path, truncating/creating as needed."""
    with open(path, "wb") as f:
        f.write(data)


def _canvas_positions(width, height, grid, start_x=0, start_y=0):
    """Yield (x, y) pixel coordinates in the Stegosploit canvas traversal order.

    Row-major, stepping x by `grid` and wrapping to x=0/y+=grid once x overflows
    width, mirroring the source project's imagedecode.js readBitstream loop
    exactly (x = 0 on wrap, not x -= width) so Python-written images decode
    correctly with that same traversal in a browser.
    """
    x, y = start_x, start_y
    while y < height:
        yield x, y
        x += grid
        if x >= width:
            x = 0
            y += grid


def _canvas_get_bit(pixels, width, x, y, bit, channel):
    """Read one bit at (x, y) on the chosen bit-plane/channel from a flat RGB buffer."""
    n = (y * width + x) * 3
    r = (pixels[n] >> bit) & 1
    g = (pixels[n + 1] >> bit) & 1
    b = (pixels[n + 2] >> bit) & 1
    if channel == 0:
        return r
    if channel == 1:
        return g
    if channel == 2:
        return b
    return round((r + g + b) / 3)  # "all": redundant majority-vote, matches imagedecode.js


def _canvas_set_bit(pixels, width, x, y, bit, channel, value):
    """Write one bit at (x, y) on the chosen bit-plane/channel into a flat RGB buffer.

    channel 3 ("all") writes the bit redundantly to all three of R, G and B so
    the majority-vote read in _canvas_get_bit recovers it even if comparing a
    single channel would be ambiguous after re-compression elsewhere.
    """
    n = (y * width + x) * 3
    mask = 1 << bit
    offsets = (0, 1, 2) if channel == 3 else (channel,)
    for offset in offsets:
        if value:
            pixels[n + offset] |= mask
        else:
            pixels[n + offset] &= (~mask) & 0xFF


def _canvas_capacity_bits(width, height, grid, start_x, start_y):
    """Total bit-positions the canvas traversal can visit from (start_x, start_y)."""
    return sum(1 for _ in _canvas_positions(width, height, grid, start_x, start_y))


def _canvas_embed_payload(pixels, width, height, bit, channel, grid, start_x, start_y, payload):
    """Write payload (header+data) via the canvas bit/channel/grid traversal, MSB-first."""
    positions = _canvas_positions(width, height, grid, start_x, start_y)
    for byte_val in payload:
        for shift in range(7, -1, -1):
            try:
                x, y = next(positions)
            except StopIteration:
                raise ValueError(
                    "Payload too large for the chosen canvas bit/channel/grid parameters"
                )
            _canvas_set_bit(pixels, width, x, y, bit, channel, (byte_val >> shift) & 1)


def _canvas_read_bytes(positions, pixels, width, bit, channel, count):
    """Read `count` bytes (MSB-first) from an in-progress canvas positions iterator."""
    result = bytearray(count)
    for i in range(count):
        val = 0
        for _ in range(8):
            try:
                x, y = next(positions)
            except StopIteration:
                raise ValueError("Image too small for the canvas-method header/payload")
            val = (val << 1) | _canvas_get_bit(pixels, width, x, y, bit, channel)
        result[i] = val
    return bytes(result)


def _canvas_extract_payload(pixels, width, height, bit, channel, grid, start_x, start_y):
    """Read the VC01 header+data payload via the canvas traversal. Returns (data, flag)."""
    positions = _canvas_positions(width, height, grid, start_x, start_y)
    header = _canvas_read_bytes(positions, pixels, width, bit, channel, HEADER_SIZE)
    if header[:4] != MAGIC:
        raise ValueError("No VisualCompromise canvas payload found (bad VC01 magic)")
    length = struct.unpack(">I", header[4:8])[0]
    flag = header[8]
    data = _canvas_read_bytes(positions, pixels, width, bit, channel, length)
    return data, flag


def _resolve_method(method, carrier_is_jpeg, output):
    """Pick "jpeg" or "lsb". auto: lsb for a .png output, else jpeg iff carrier is JPEG."""
    if method != "auto":
        return method
    if output and os.path.splitext(output)[1].lower() == ".png":
        return "lsb"
    return "jpeg" if carrier_is_jpeg else "lsb"


def encode(input_file, carrier, output=None, enc="b64", method="auto",
           bit=0, channel="all", grid=1, js_exec=False):
    """Embed input_file into carrier. Returns the output path.

    method: "jpeg" (COM markers, JPEG out), "lsb" (pixel LSBs, PNG out),
    "canvas" (configurable bit/channel/grid LSB, PNG out, plus a companion
    browser decoder) or "auto" (jpeg for a JPEG carrier unless the output path
    ends in .png; never resolves to canvas, which is explicit-only).

    bit/channel/grid/js_exec only apply to method="canvas"; passing a
    non-default value for any of them with another method raises ValueError.
    """
    if method not in ("auto", "jpeg", "lsb", "canvas"):
        raise ValueError(f"Unknown method: {method}")
    canvas_flags_at_default = (bit == 0 and channel == "all" and grid == 1 and js_exec is False)
    if method != "canvas" and not canvas_flags_at_default:
        raise ValueError("--bit/--channel/--grid/--js-exec only apply to -m canvas")

    flag, encoder = ENCODERS[enc]
    with open(input_file, "rb") as f:
        encoded = encoder(f.read())
    with open(carrier, "rb") as f:
        carrier_bytes = f.read()
    method = _resolve_method(method, _is_jpeg(carrier_bytes), output)

    if method == "canvas":
        if not 0 <= bit <= 7:
            raise ValueError("--bit must be between 0 and 7")
        if channel not in CANVAS_CHANNELS:
            raise ValueError(f"Unknown channel: {channel}")
        if not 1 <= grid <= 255:
            raise ValueError("--grid must be between 1 and 255 (stored as one byte)")
        channel_code = CANVAS_CHANNELS[channel]

        img = Image.open(carrier).convert("RGB")
        width, height = img.size
        pixels = bytearray(img.tobytes())

        preamble_capacity = len(pixels) // 8
        if preamble_capacity < PREAMBLE_SIZE:
            raise ValueError(
                f"Carrier too small for canvas preamble: need {PREAMBLE_SIZE} bytes, "
                f"carrier holds {preamble_capacity}"
            )
        preamble = PREAMBLE_MAGIC + bytes([bit, channel_code, grid])
        _embed_payload(pixels, preamble)

        if width == 0:
            raise ValueError("Carrier has zero width")
        start_x = CANVAS_START_PIXEL % width
        start_y = CANVAS_START_PIXEL // width
        if start_y >= height:
            raise ValueError("Carrier too small to hold a canvas-method payload after the preamble")

        payload = MAGIC + struct.pack(">I", len(encoded)) + bytes([flag]) + encoded
        capacity_bits = _canvas_capacity_bits(width, height, grid, start_x, start_y)
        if capacity_bits < len(payload) * 8:
            raise ValueError(
                f"Payload too large for canvas bit={bit}/channel={channel}/grid={grid}: "
                f"need {len(payload) * 8} bit-positions, carrier holds {capacity_bits}"
            )
        _canvas_embed_payload(pixels, width, height, bit, channel_code, grid, start_x, start_y, payload)

        output = output or "encoded_image.png"
        root, ext = os.path.splitext(output)
        if ext.lower() != ".png":
            print(f"Warning: canvas data needs lossless output; saving as {root}.png", file=sys.stderr)
            output = root + ".png"
        Image.frombytes("RGB", img.size, bytes(pixels)).save(output, format="PNG")
        print(f"Encoded {len(encoded)} bytes ({enc}) into {output} via canvas "
              f"bit={bit}/channel={channel}/grid={grid} "
              f"({len(payload) * 8}/{capacity_bits} bit-positions used)")

        decoder_path = _write_canvas_decoder_html(output, bit, channel_code, grid, js_exec)
        print(f"Wrote companion browser decoder: {decoder_path}")
        return output

    if method == "jpeg":
        output = output or "encoded_image.jpg"
        result = _jpeg_embed(carrier_bytes, encoded, flag)
        with open(output, "wb") as f:
            f.write(result)
        print(f"Encoded {len(encoded)} bytes ({enc}) into {output} via JPEG COM markers")
        return output

    payload = MAGIC + struct.pack(">I", len(encoded)) + bytes([flag]) + encoded
    img = Image.open(carrier).convert("RGB")
    pixels = bytearray(img.tobytes())
    capacity = len(pixels) // 8
    if capacity < len(payload):
        raise ValueError(
            f"Payload too large: need {len(payload)} bytes, carrier holds {capacity}"
        )
    _embed_payload(pixels, payload)

    output = output or "encoded_image.png"
    root, ext = os.path.splitext(output)
    if ext.lower() != ".png":
        print(f"Warning: LSB data needs lossless output; saving as {root}.png", file=sys.stderr)
        output = root + ".png"
    Image.frombytes("RGB", img.size, bytes(pixels)).save(output, format="PNG")
    print(f"Encoded {len(encoded)} bytes ({enc}) into {output} "
          f"({len(payload)}/{capacity} bytes of capacity used)")
    return output


def decode(encoded_image, output=None):
    """Extract the hidden file from encoded_image.

    Tries, in order: JPEG COM markers, whole-image LSB (VC01 magic at byte 0),
    then the canvas method (VC02 preamble at byte 0, then VC01 via the
    bit/channel/grid it records). Returns the output path.
    """
    output = output or "decoded_output"
    with open(encoded_image, "rb") as f:
        raw = f.read()
    found = _jpeg_extract(raw)
    if found is not None:
        data = DECODERS[found[1]](found[0])
        _write_bytes(output, data)
        print(f"Decoded {len(data)} bytes to {output} (JPEG COM)")
        return output

    img = Image.open(encoded_image).convert("RGB")
    width, height = img.size
    pixels = img.tobytes()
    flat_capacity = len(pixels) // 8

    if flat_capacity >= HEADER_SIZE:
        header = _extract_bytes(pixels, 0, HEADER_SIZE)
        if header[:4] == MAGIC:
            length = struct.unpack(">I", header[4:8])[0]
            flag = header[8]
            if flag not in DECODERS:
                raise ValueError(f"Unknown encoding flag: {flag}")
            if flat_capacity - HEADER_SIZE < length:
                raise ValueError("Header length exceeds image capacity (corrupt or modified image)")
            data = DECODERS[flag](_extract_bytes(pixels, HEADER_SIZE, length))
            _write_bytes(output, data)
            print(f"Decoded {len(data)} bytes to {output} (LSB)")
            return output

    if flat_capacity >= PREAMBLE_SIZE:
        preamble = _extract_bytes(pixels, 0, PREAMBLE_SIZE)
        if preamble[:4] == PREAMBLE_MAGIC:
            bit, channel_code, grid = preamble[4], preamble[5], preamble[6]
            if not (0 <= bit <= 7) or channel_code not in (0, 1, 2, 3) or grid < 1:
                raise ValueError("Corrupt VC02 canvas preamble")
            if width == 0:
                raise ValueError("Image has zero width")
            start_x = CANVAS_START_PIXEL % width
            start_y = CANVAS_START_PIXEL // width
            if start_y >= height:
                raise ValueError("Image too small to contain a canvas-method payload")
            encoded_payload, flag = _canvas_extract_payload(
                pixels, width, height, bit, channel_code, grid, start_x, start_y
            )
            if flag not in DECODERS:
                raise ValueError(f"Unknown encoding flag: {flag}")
            data = DECODERS[flag](encoded_payload)
            _write_bytes(output, data)
            print(f"Decoded {len(data)} bytes to {output} (canvas)")
            return output

    raise ValueError(
        "No VisualCompromise data found (no JPEG COM chunks, bad LSB magic, no VC02 canvas preamble)"
    )


def _bit_type(value):
    """argparse type for --bit: an int in 0..7."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid bit value: {value!r}")
    if not 0 <= ivalue <= 7:
        raise argparse.ArgumentTypeError("--bit must be between 0 and 7")
    return ivalue


def _grid_type(value):
    """argparse type for --grid: an int in 1..255 (fits the VC02 preamble's one byte)."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid grid value: {value!r}")
    if not 1 <= ivalue <= 255:
        raise argparse.ArgumentTypeError("--grid must be between 1 and 255")
    return ivalue


def _canvas_decoder_html(image_filename, bit, channel_code, grid, js_exec):
    """Build the standalone browser decoder page for a canvas-encoded image.

    Mirrors, in JavaScript, the exact Python read path: a fixed bit0/sequential
    byte VC02 preamble read over the canvas's RGBA ImageData (mapped back to the
    3-bytes-per-pixel flat indexing _extract_bytes uses), then a VC01 header+data
    payload read via the bit/channel/grid traversal _canvas_positions implements.
    No external scripts; everything needed (including a small RFC4648 base32
    decoder) is inline.

    js_exec gates two genuinely different generated pages, not one page with a
    runtime flag: when False, the "run decoded bytes as code" branch and its
    on-page warning text are never written into the HTML at all (verified by
    the test suite), not merely disabled. See @decision DEC-VC-004/005 and
    MASTER_PLAN.md REQ-NOGO-002/REQ-P1-001: exploit-delivery execution is
    opt-in, explicit, and always visibly labelled on the page it appears on.
    """
    warning_html = ""
    result_script = """
      var textBox = document.getElementById("result");
      var dlLink = document.getElementById("download");
      var printable = bytes.every(function (b) {
        return (b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13;
      });
      if (printable) {
        textBox.textContent = bytes.map(function (b) { return String.fromCharCode(b); }).join("");
      } else {
        textBox.textContent = "(binary payload, " + bytes.length + " bytes; use the download link)";
      }
      var blob = new Blob([new Uint8Array(bytes)]);
      dlLink.href = URL.createObjectURL(blob);
      dlLink.download = "decoded_payload";
      dlLink.style.display = "inline";
"""
    if js_exec:
        warning_html = (
            '<p class="warning"><strong>VisualCompromise canvas decoder '
            "&mdash; research/demo exploit-delivery mode:</strong> this page "
            "executes the decoded payload as JavaScript.</p>"
        )
        # Opt-in only (--js-exec at encode time): runs the decoded bytes as code,
        # mirroring python-stegosploit's decoder.html technique. Never emitted
        # into the default page; see the function docstring and DEC-VC-004/005.
        result_script = """
      var execStr = bytes.map(function (b) { return String.fromCharCode(b); }).join("");
      document.getElementById("result").textContent =
        "Executing " + bytes.length + " decoded bytes as JavaScript (--js-exec mode).";
      /* eslint-disable-next-line no-new-func */
      (Function(execStr))();
"""

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>VisualCompromise canvas decoder</title>
<style>
  body {{ font-family: monospace; background: #111; color: #ddd; padding: 1.5em; }}
  .warning {{ background: #4a1414; color: #fff; padding: 0.75em; border: 1px solid #a33; }}
  #result {{ white-space: pre-wrap; word-break: break-all; background: #000; padding: 0.75em;
             border: 1px solid #333; min-height: 2em; }}
  #download {{ display: none; color: #6cf; }}
  canvas {{ display: none; }}
</style>
</head>
<body>
<h1>VisualCompromise canvas decoder</h1>
{warning_html}
<p>Source image: <code>{html.escape(image_filename)}</code></p>
<img id="imgsrc" src="{html.escape(image_filename)}">
<canvas id="work"></canvas>
<div id="result">(decoding...)</div>
<a id="download" href="#">Download decoded payload</a>

<script>
// ---- fixed scheme (mirrors Python _extract_bytes): bit 0, sequential bytes,
// over the flat 3-bytes-per-pixel RGB stream _embed_payload/_extract_bytes assume.
// getImageData is always RGBA (4 bytes/pixel), so a flat RGB index must be remapped:
// pixelIndex = flatIdx // 3, channelInPixel = flatIdx % 3, RGBA byte = pixelIndex*4 + channelInPixel.
function flatBit(pix, flatIdx) {{
  var pixelIndex = Math.floor(flatIdx / 3);
  var channelInPixel = flatIdx % 3;
  return pix[pixelIndex * 4 + channelInPixel] & 1;
}}
function readFixedBytes(pix, start, count) {{
  var out = new Uint8Array(count);
  for (var i = 0; i < count; i++) {{
    var val = 0;
    for (var b = 0; b < 8; b++) {{
      val = (val << 1) | flatBit(pix, (start + i) * 8 + b);
    }}
    out[i] = val;
  }}
  return out;
}}

// ---- canvas scheme (mirrors Python _canvas_positions/_canvas_get_bit): configurable
// bit-plane/channel, grid-stepped row-major traversal, straight over RGBA ImageData
// (the source project's native 4-bytes-per-pixel layout; no remapping needed here).
function canvasPositions(width, height, grid, startX, startY) {{
  var x = startX, y = startY;
  return {{
    next: function () {{
      if (y >= height) return null;
      var pos = [x, y];
      x += grid;
      if (x >= width) {{ x = 0; y += grid; }}
      return pos;
    }}
  }};
}}
function canvasGetBit(pix, width, x, y, bitLayer, channel) {{
  var n = (y * width + x) * 4;
  var r = (pix[n] >> bitLayer) & 1;
  var g = (pix[n + 1] >> bitLayer) & 1;
  var b = (pix[n + 2] >> bitLayer) & 1;
  if (channel === 0) return r;
  if (channel === 1) return g;
  if (channel === 2) return b;
  return Math.round((r + g + b) / 3);  // "all": redundant majority-vote
}}
function canvasReadBytes(iter, pix, width, bitLayer, channel, count) {{
  var out = new Uint8Array(count);
  for (var i = 0; i < count; i++) {{
    var val = 0;
    for (var b = 0; b < 8; b++) {{
      var pos = iter.next();
      if (pos === null) throw new Error("image too small for canvas payload");
      val = (val << 1) | canvasGetBit(pix, width, pos[0], pos[1], bitLayer, channel);
    }}
    out[i] = val;
  }}
  return out;
}}

// RFC4648 base32, matching Python's base64.b32encode alphabet/padding.
function b32decode(s) {{
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  s = s.replace(/=+$/, "");
  var bits = "";
  for (var i = 0; i < s.length; i++) {{
    var val = alphabet.indexOf(s[i].toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }}
  var out = [];
  for (var i = 0; i + 8 <= bits.length; i += 8) {{
    out.push(parseInt(bits.substr(i, 8), 2));
  }}
  return out;
}}
function b64decode(s) {{
  var bin = atob(s);
  var out = [];
  for (var i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i));
  return out;
}}

var CANVAS_START_PIXEL = {CANVAS_START_PIXEL};
var PREAMBLE_SIZE = {PREAMBLE_SIZE};
var HEADER_SIZE = {HEADER_SIZE};

function decodeFromImage(img) {{
  var canvas = document.getElementById("work");
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  var ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0);
  var imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  var pix = imageData.data;
  var width = canvas.width, height = canvas.height;

  var preamble = readFixedBytes(pix, 0, PREAMBLE_SIZE);
  var magicStr = String.fromCharCode(preamble[0], preamble[1], preamble[2], preamble[3]);
  if (magicStr !== "VC02") {{
    throw new Error("No VC02 canvas preamble found in this image");
  }}
  var bitLayer = preamble[4], channel = preamble[5], grid = preamble[6];

  var startX = CANVAS_START_PIXEL % width;
  var startY = Math.floor(CANVAS_START_PIXEL / width);
  var iter = canvasPositions(width, height, grid, startX, startY);

  var header = canvasReadBytes(iter, pix, width, bitLayer, channel, HEADER_SIZE);
  var headerMagic = String.fromCharCode(header[0], header[1], header[2], header[3]);
  if (headerMagic !== "VC01") {{
    throw new Error("No VC01 payload found after the VC02 preamble");
  }}
  var length = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];
  length = length >>> 0;
  var encFlag = header[8];
  var data = canvasReadBytes(iter, pix, width, bitLayer, channel, length);

  var encStr = String.fromCharCode.apply(null, data);
  var bytes = (encFlag === 1) ? b32decode(encStr) : b64decode(encStr);
  return bytes;
}}

var imgEl = document.getElementById("imgsrc");
function run() {{
  try {{
    var bytes = decodeFromImage(imgEl);
{result_script}  }} catch (e) {{
    document.getElementById("result").textContent = "Decode failed: " + e.message;
  }}
}}
if (imgEl.complete && imgEl.naturalWidth) {{
  run();
}} else {{
  imgEl.onload = run;
  imgEl.onerror = function () {{
    document.getElementById("result").textContent = "Failed to load " + imgEl.src;
  }};
}}
</script>
</body>
</html>
"""


def _write_canvas_decoder_html(image_output_path, bit, channel_code, grid, js_exec):
    """Write the companion <output>.decoder.html next to image_output_path. Returns its path."""
    root, _ext = os.path.splitext(image_output_path)
    decoder_path = root + ".decoder.html"
    html = _canvas_decoder_html(os.path.basename(image_output_path), bit, channel_code, grid, js_exec)
    with open(decoder_path, "w", encoding="utf-8") as f:
        f.write(html)
    return decoder_path


def main(argv=None):
    print(BANNER)
    parser = argparse.ArgumentParser(description="Hide files in JPEG COM markers or image LSBs.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encode", help="embed a file in a carrier image")
    p_enc.add_argument("input_file")
    p_enc.add_argument("carrier_image")
    p_enc.add_argument("-o", "--output", default=None,
                       help="output path (default: encoded_image.jpg for jpeg, .png for lsb/canvas)")
    p_enc.add_argument("-e", "--encoding", choices=["b64", "b32"], default="b64")
    p_enc.add_argument("-m", "--method", choices=["auto", "lsb", "jpeg", "canvas"], default="auto",
                       help="auto: jpeg for a JPEG carrier unless output is .png; "
                            "lsb: PNG output; jpeg: COM markers, JPEG output; "
                            "canvas: configurable bit/channel/grid LSB, PNG output (explicit only)")
    p_enc.add_argument("--bit", type=_bit_type, default=0,
                       help="canvas method: bit-plane to use, 0-7 (default 0)")
    p_enc.add_argument("--channel", choices=["r", "g", "b", "all"], default="all",
                       help="canvas method: colour channel, or all for a redundant "
                            "majority-vote read (default all)")
    p_enc.add_argument("--grid", type=_grid_type, default=1,
                       help="canvas method: pixel step between consecutive bits (default 1)")
    p_enc.add_argument("--js-exec", action="store_true", default=False,
                       help="canvas method: generate a decoder page that executes the "
                            "decoded payload as JavaScript on load (research/demo only, "
                            "opt-in, never the default)")

    p_dec = sub.add_parser("decode", help="extract a file from an encoded image")
    p_dec.add_argument("encoded_image")
    p_dec.add_argument("-o", "--output", default="decoded_output",
                       help="output file path (default: decoded_output)")

    args = parser.parse_args(argv)
    try:
        if args.command == "encode":
            encode(args.input_file, args.carrier_image, args.output, args.encoding, args.method,
                   args.bit, args.channel, args.grid, args.js_exec)
        else:
            decode(args.encoded_image, args.output)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
