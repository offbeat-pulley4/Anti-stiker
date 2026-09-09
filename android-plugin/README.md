# Anti-Stiker plugin (AyuGram4A / exteraGram)

A real in-app plugin that blocks the "kill sticker" crash before it happens
— not a scanner you run separately, an actual hook inside AyuGram itself.

## Install

1. Open `antistiker.plugin` from wherever you saved it (chat, file manager,
   Downloads...) inside AyuGram, the same way you install any other plugin
   from [exteraStore](https://exterastore.app/plugins) or a `.plugin` file
   someone sent you.
2. Tap **Install**, then **Enable after installation**.
3. Optional: in the plugin's settings, toggle whether you want a bulletin
   notification every time it blocks something (on by default).

Requires client version 11.9.1+ (same floor as other exteraGram/AyuGram
plugins).

## What it actually does

It hooks every constructor of `org.telegram.ui.Components.RLottieDrawable`
— the class AyuGram builds *right before* handing a `.tgs` file to the
native `rlottie` decoder — and, just before that happens, reads the file
(or inline JSON) about to be decoded and runs it through the same
validation logic as `antistiker/tgs_scan.py` in the root of this repo:
finite/bounded numeric checks, the specific polystar `pt`/`ir`/`or` bound
the reference PoC abuses, layer/asset/keyframe bombs, and circular
precomposition references.

If a file matches a known crash pattern, the plugin swaps the constructor's
argument for a tiny inert placeholder animation *before* the original
constructor runs — so the native parser that actually crashes never sees
the attacker's bytes at all. The original file itself is left untouched on
disk; only the in-memory argument going into that one constructor call is
replaced. A bulletin notification tells you it happened.

This is a "before" hook (`MethodHook.before_hooked_method`), the same
Xposed-style API `hook_method`/`hook_all_constructors` other exteraGram
plugins use for reflection-based hooking (see e.g.
`premium.plugin` in `The-MoonTg-project/extera-plugins` for another example
of this pattern) — it's not sending anything over the network, not reading
your messages, and doesn't touch any other class or method.

## Honesty about what wasn't verified here

This was written and unit-tested (see `tests/`) against the *documented*
plugin SDK — the real type stubs from the `exteragram-utils` package on
PyPI, and the actual constructor signatures traced in AyuGram4A's own
source (`TMessagesProj/src/main/java/org/telegram/ui/Components/
RLottieDrawable.java`). What it was **not** tested against is a real
AyuGram install: this environment has no Android device/emulator and no
access to the closed-source Chaquopy/Xposed runtime the plugin actually
executes under. The logic itself (decompression, parsing, bounds, hook
argument substitution) is verified by `tests/test_plugin_logic.py` against
fakes shaped to match the real SDK -- but the fakes can't catch a mismatch
between this and the *actual* runtime behavior (e.g. if a future client
version renames/removes `RLottieDrawable`, or if `hook_all_constructors`
behaves subtly differently than its type stub implies).

Please test it on your own install against `../tests/fixtures/
kill_sticker.tgs` before trusting it as your only line of defense, and
keep an eye on the log line it prints (`[Anti-Stiker] loaded, watching
RLottieDrawable constructors`) to confirm the hook actually attached.

## Tests

```sh
pip install pytest
python3 -m pytest android-plugin/tests/ -v
```

These run the plugin's validation and hook-mutation logic directly (via
fakes of the SDK modules in `tests/stubs/`), including a regression check
against the real `kill_sticker.tgs` PoC in this repo.
