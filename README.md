# Anti-Stiker

Detects and neutralizes **"kill sticker"** `.tgs` files before AyuGram (or
any Telegram-family client) has a chance to render them and crash.

**AyuGram Desktop** has no plugin system — it's a compiled C++/Qt app with
no runtime plugin API. **AyuGram for Android (AyuGram4A)** does: it carries
exteraGram's Python plugin engine (Chaquopy + Xposed-style method hooking),
even though AyuGram4A's own README says it drops exteraGram's other
proprietary features. Three things live here as a result:

1. **`android-plugin/antistiker.plugin`** — a real, installable plugin for
   AyuGram4A/exteraGram. It hooks the exact native call that decodes a
   `.tgs` and blocks the malicious ones *before* the decoder ever sees
   them. See `android-plugin/README.md` to install it.
2. **`patches/`** — a source patch for AyuGram4A that fixes the underlying
   bug at its root, in their vendored `rlottie` (see `patches/README.md`).
   Only useful if you build the client from source yourself.
3. **`antistiker/`** — a pure-Python scanner/sanitizer (stdlib only) you can
   run **in Termux on the phone itself**, or on desktop, to check a `.tgs`
   file before opening or importing it anywhere.

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

## What protects what

- **`android-plugin/`** catches stickers received live inside a chat too —
  it hooks the actual decode call in AyuGram4A itself, so it doesn't matter
  how the file got onto the device.
- **`antistiker/`** (the scanner) only catches files *before* you feed them
  to a client yourself — dragging a `.tgs` in manually, importing a
  downloaded sticker pack, or forwarding a file you received outside of
  Telegram (Downloads folder, USB stick, etc). It has no hook into any
  client's internals, so it can't see stickers arriving live in a chat —
  that's what the plugin (Android) or the patch (Desktop, if you build from
  source) are for.

## Install the Android plugin

See `android-plugin/README.md`. Short version: open `antistiker.plugin`
inside AyuGram4A like any other plugin, tap Install, enable it.

## Install the scanner

Python 3.10+, no third-party dependencies. Works the same on a desktop OS
or in [Termux](https://termux.dev/) on Android.

```sh
git clone <this repo>
cd Anti-stiker
python3 -m antistiker --version
```

On Android (Termux): `pkg install python git`, then the same three
commands. Point `scan`/`guard` at wherever your downloaded stickers land
(usually `~/storage/downloads` after `termux-setup-storage`).

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

## The real fix: `patches/`

The scanner is a stopgap that doesn't require rebuilding the client. The
durable fix is for AyuGram's vendored `rlottie` to bounds-check hostile
fields (like polystar point count) before using them, so this class of
file can never reach the renderer at all.

`patches/ayugram4a-kill-sticker-rlottie.patch` does exactly that — traced
and verified against [AyuGram/AyuGram4A](https://github.com/AyuGram/AyuGram4A):
the reference PoC's `"pt": 1e38` flows unchecked into a `size_t` cast in
`vpath.cpp`'s `addPolystar()`, which evaluates to `SIZE_MAX` and blows up
the allocation that follows. See `patches/README.md` for the full trace,
how to apply it, and how to propose it upstream so every AyuGram4A user
gets the fix, not just your own build.

## Tests

```sh
pip install pytest
python3 -m pytest tests/ -v               # scanner/sanitizer
python3 -m pytest android-plugin/tests/ -v # plugin logic, against fakes of the real SDK
```
