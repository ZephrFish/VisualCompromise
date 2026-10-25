# Visual Compromise

Hide a file inside an image using JPEG COM markers, pixel LSBs, or a configurable canvas-based LSB
scheme with its own browser decoder. Decode auto-detects which method was used.

| Method   | Output | Pixels changed      | Survives re-encode   | Flag needed       |
|----------|--------|----------------------|------------------------|--------------------|
| `jpeg`   | JPEG   | No                   | No                     | No (auto)          |
| `lsb`    | PNG    | Yes, imperceptibly   | Yes, while lossless    | No (auto)          |
| `canvas` | PNG    | Yes, imperceptibly   | Yes, while lossless    | Yes, `-m canvas`   |

## Usage

```
python VisualCompromise.py encode <input_file> <carrier_image> [-o output] [-e b64|b32]
    [-m auto|lsb|jpeg|canvas] [--bit 0-7] [--channel r|g|b|all] [--grid N] [--js-exec]
python VisualCompromise.py decode <encoded_image> [-o output_file]
```

```
python VisualCompromise.py encode secret.txt photo.jpg -o hidden.jpg         # JPEG COM
python VisualCompromise.py encode secret.txt photo.jpg -m lsb -o hidden.png  # LSB
python VisualCompromise.py encode secret.txt photo.jpg -m canvas -o hidden.png --bit 2 --channel r --grid 2
python VisualCompromise.py decode hidden.jpg -o recovered.txt
```

- `-e` encodes the payload as base64 (default) or base32.
- `-m auto` picks `lsb` for a `.png` output, else `jpeg`. `canvas` always needs `-m canvas` explicitly.
- `-o` sets the output path; `lsb` and `canvas` always write PNG regardless of the extension given.
- `jpeg` capacity is about 65535 chunks of 65520 bytes. `lsb` capacity is roughly `width * height * 3 / 8` bytes.

All three methods share a `VC01` magic header; see the `VisualCompromise.py` docstring for the byte layout.

## Canvas method

A configurable variant of `lsb`: pick a bit-plane (`--bit`, 0 to 7, default 0), a colour channel
(`--channel`, `r`/`g`/`b`, or `all` for a redundant majority-vote read, default `all`), and a pixel
spacing (`--grid`, every Nth pixel, default 1). Lower capacity than `lsb`, but harder to fingerprint.

`encode -m canvas` writes a `<output>.decoder.html` alongside the image, a dependency-free page that
decodes the payload in a browser via `<canvas>`/`getImageData`, no Python needed. It shows the result
as text or a download link. `--js-exec` instead makes it run the decoded payload as JavaScript on
load, a labelled research/demo mode, never the default.

Serve the image and decoder page over a local HTTP server (`python -m http.server`) rather than
opening the HTML file directly; browsers handle canvas pixel access from `file://` images inconsistently.

Ported from Saumil Shah's Stegosploit (`python-stegosploit`, https://github.com/amichael7/python-stegosploit,
HITB/BlackHat 2015): the configurable bit/channel/grid mechanism and canvas decoder, not its bundled
IE CVE-2014-0282 exploit payload.

## Setup

```
pip install -r requirements.txt
```
