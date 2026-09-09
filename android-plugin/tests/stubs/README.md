Minimal fakes of the real exteraGram/AyuGram4A plugin SDK modules
(`android_utils`, `base_plugin`, `hook_utils`, `file_utils`, `java.io`,
`ui.bulletin`, `ui.settings`), shaped to match the official type stubs
published as `exteragram-utils` on PyPI.

These exist so `../antistiker.plugin`'s validation/hook logic can be
exercised by plain pytest, without a real Android device or the (closed
source) Chaquopy/Xposed runtime the plugin actually runs under at install
time. They intentionally implement just enough behavior to drive the code
paths under test (e.g. `MethodHook.before_hooked_method` mutating
`param.args`) -- they are not a full SDK reimplementation.
