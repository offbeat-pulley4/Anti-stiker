# Anti-Stiker

Detects and neutralizes **"kill sticker"** `.tgs` files before AyuGram (or
any Telegram-Desktop-based client) has a chance to render them and crash.

## What's a kill sticker?

A `.tgs` sticker is a gzip-compressed [Lottie](https://airbnb.io/lottie/)
animation (JSON). Telegram-family clients render it with `rlottie` without
validating the numbers inside. A crafted file can put an absurd value in a
field the renderer trusts blindly — e.g. a polystar `"pt"` (points) count of
`1e38` — and the client hangs, exhausts memory, and gets killed by the OS
(hence "kill sticker"). No chat connection is even required: opening or
dragging such a file into the client is enough. This repo's
`tests/fixtures/kill_sticker.tgs` is exactly such a file (a real,
reproducible PoC), used here as a regression fixture.

Other known variants this tool also catches: circular/deeply-nested
precomposition references (recursion bombs), oversized layer/asset/keyframe
counts, gzip bombs, and non-finite (`NaN`/`Infinity`) numeric literals.

## What this does — and doesn't — protect

- **Does**: catch the file *before* you feed it to AyuGram — dragging a
  `.tgs` in manually, importing a downloaded sticker pack, or forwarding a
  file you received outside of Telegram (Downloads folder, USB stick, etc).
  This is the exact vector the local crash relies on.
- **Doesn't**: intercept stickers received live inside a chat. AyuGram
  (like upstream Telegram Desktop) never writes those to disk as plain
  `.tgs` files — they go straight into its internal cache database. Doing
  real-time in-chat interception would require a patch to AyuGram's own
  source (see "Upstream fix" below), not an external tool.

## Install

Python 3.10+, no third-party dependencies.

```sh
git clone <this repo>
cd Anti-stiker
python3 -m antistiker --version
```

## Usage

Scan a single file or a whole folder of stickers:

```sh
python3 -m antistiker scan path/to/sticker.tgs
python3 -m antistiker scan ~/Downloads
```

Exit code is `0` if everything scanned SAFE, `1` if anything was flagged.
Add `--json` for machine-readable output.

Repair a flagged file instead of just deleting it (clamps hostile numbers,
cuts circular references, re-gzips):

```sh
python3 -m antistiker sanitize suspicious.tgs suspicious.cleaned.tgs
```

Run a background guard that watches your Downloads folder (or any
directories you name) and automatically quarantines anything malicious the
moment it lands there — before you get a chance to open it in AyuGram:

```sh
python3 -m antistiker guard                      # watches Downloads by default
python3 -m antistiker guard --dir ~/Telegram --dir ~/Downloads
python3 -m antistiker guard --once                # one-shot scan, no loop
```

Flagged files are moved into `~/.antistiker/quarantine/` (override with
`--quarantine-dir`) along with the reason, logged to stdout.

### Run the guard at login (Linux, systemd --user)

```sh
mkdir -p ~/.config/systemd/user
cp install/antistiker-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now antistiker-guard.service
```

On Windows/macOS, add `python3 -m antistiker guard` to your usual
login-startup mechanism (Task Scheduler / Login Items).

## How detection works

`antistiker/tgs_scan.py` decompresses the file with a hard size cap (so a
gzip bomb can't exhaust memory while merely being *scanned*), parses the
JSON while rejecting non-finite literals, then walks the whole document
iteratively (never recursively — a hostile tree can't blow the scanner's own
stack) checking:

- every numeric leaf is finite and within a sane magnitude
- polystar `pt`/`ir`/`or` fields specifically, since that's the field the
  reference PoC abuses
- layer/asset/shape/keyframe counts stay within sane limits
- the precomposition reference graph has no cycles and isn't absurdly deep

Each file gets a verdict: `SAFE`, `SUSPICIOUS` (unusual but not dangerous,
e.g. non-512x512 canvas), or `MALICIOUS`.

## Upstream fix

The durable fix is for AyuGram/Telegram Desktop's vendored `rlottie` to
bounds-check fields like polystar point count before using them, so this
class of file can never reach a renderer at all — this tool is a stopgap
that doesn't require rebuilding the client. If you build AyuGram from
source, the fix belongs in the Lottie property parsing code, clamping
values the same way `antistiker/sanitize.py` does here.

## Tests

```sh
pip install pytest
python3 -m pytest tests/ -v
```
