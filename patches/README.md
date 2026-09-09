# AyuGram4A source patch

`ayugram4a-kill-sticker-rlottie.patch` fixes the actual crash at its root, in
AyuGram's own vendored `rlottie`. It applies against
[AyuGram/AyuGram4A](https://github.com/AyuGram/AyuGram4A)
commit `7013145676d36d82ee13c02a89f72097b7490dcd` (the HEAD of the default
branch as of 2026-09-09).

## The bug, traced

`tests/fixtures/kill_sticker.tgs` in this repo sets a polystar shape's
`"pt"` (point count) to `1e38`. That value flows, unchecked, from
`LottieParserImpl::parsePolystarObject()`
(`TMessagesProj/jni/rlottie/src/lottie/lottieparser.cpp`) into
`LOTPolystarItem::updatePath()`
(`TMessagesProj/jni/rlottie/src/lottie/lottieitem.cpp:1272`), which passes it
straight to `VPath::VPathData::addPolystar()`
(`TMessagesProj/jni/rlottie/src/vector/vpath.cpp:512`). There:

```cpp
size_t numPoints = size_t(ceilf(points) * 2);
...
reserve(numPoints + 2, numPoints + 3);
```

Casting a `float` that large to `size_t` is undefined behavior. In practice
it evaluates to `SIZE_MAX`:

```
$ g++ -O2 -o repro repro.cpp && ./repro
UNCLAMPED numPoints (would be passed to reserve()/loop) = 18446744073709551615
CLAMPED points = 1000.000000 -> numPoints = 2000 (safe, bounded allocation)
```

`reserve()` then tries to allocate storage for ~2^64 points, which either
throws/aborts immediately or gets the process OOM-killed by the OS —
the "kill sticker" crash. No chat connection needed: opening the file
locally is enough, since it's the same code path used for previews.

## The fix

Clamp `points`, `innerRadius`, and `outerRadius` to sane, finite ranges at
the one place every polystar/polygon path gets built
(`LOTPolystarItem::updatePath`), before they can reach the unchecked
`size_t` cast. This is the only call site of `addPolystar`/`addPolygon` in
the codebase, so it closes the bug completely without touching the
geometry code itself.

## Applying it

```sh
git clone https://github.com/AyuGram/AyuGram4A
cd AyuGram4A
git apply /path/to/Anti-stiker/patches/ayugram4a-kill-sticker-rlottie.patch
# then build as usual (Android Studio, or ./gradlew assembleRelease) —
# this touches native (JNI) code, so it needs the NDK toolchain the
# project already depends on.
```

This patch was verified against the reference PoC by isolating the exact
cast (`repro.cpp` above) — not by a full Android build, which needs the NDK
toolchain and wasn't available in the environment this was written in.
Please test a debug build against `tests/fixtures/kill_sticker.tgs` before
shipping it.

## Upstreaming

This is a real bug in a project you don't control the repo for — if you
want it fixed for every AyuGram4A user (not just your own build), the
highest-leverage move is opening a PR against
[AyuGram/AyuGram4A](https://github.com/AyuGram/AyuGram4A) with this patch,
or filing an issue with the PoC and the trace above.
