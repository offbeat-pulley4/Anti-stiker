import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader

STUBS = os.path.join(os.path.dirname(__file__), "stubs")
PLUGIN_FILE = os.path.join(os.path.dirname(__file__), "..", "antistiker.plugin")
FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "fixtures")

sys.path.insert(0, STUBS)

_loader = SourceFileLoader("antistiker_plugin", PLUGIN_FILE)
_spec = importlib.util.spec_from_loader("antistiker_plugin", _loader)
plugin = importlib.util.module_from_spec(_spec)
_loader.exec_module(plugin)

JFile = sys.modules["java.io"].File


class FakeParam:
    def __init__(self, args):
        self.args = list(args)


def test_kill_sticker_bytes_flagged():
    raw = open(os.path.join(FIXTURES, "kill_sticker.tgs"), "rb").read()
    reason = plugin.check_tgs_bytes(raw)
    assert reason is not None
    assert "pt" in reason or "polystar" in reason


def test_safe_sticker_bytes_pass():
    raw = open(os.path.join(FIXTURES, "safe_sticker.tgs"), "rb").read()
    assert plugin.check_tgs_bytes(raw) is None


def test_hook_swaps_malicious_file_arg():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()
    assert p.placeholder_path and os.path.exists(p.placeholder_path)

    hook = plugin.BlockKillStickerHook(p)
    kill_path = os.path.join(FIXTURES, "kill_sticker.tgs")
    param = FakeParam([JFile(kill_path), 512, 512])
    hook.before_hooked_method(param)

    assert param.args[0].getAbsolutePath() == p.placeholder_path
    # the placeholder itself must be a well-formed, safe .tgs
    assert plugin.check_tgs_bytes(open(p.placeholder_path, "rb").read()) is None


def test_hook_leaves_safe_file_arg_untouched():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()

    hook = plugin.BlockKillStickerHook(p)
    safe_path = os.path.join(FIXTURES, "safe_sticker.tgs")
    param = FakeParam([JFile(safe_path), 512, 512])
    hook.before_hooked_method(param)

    assert param.args[0].getAbsolutePath() == safe_path


def test_hook_ignores_non_tgs_file_args():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()

    hook = plugin.BlockKillStickerHook(p)
    param = FakeParam([JFile("/tmp/something.png"), 100, 100])
    hook.before_hooked_method(param)

    assert param.args[0].getAbsolutePath() == "/tmp/something.png"


def test_truncated_or_empty_file_is_inconclusive_not_blocked():
    # RLottieDrawable can be constructed before FileLoader finishes writing
    # the file to disk. A partially-written/empty file must NOT be treated
    # as malicious -- that would silently replace legitimate stickers.
    assert plugin.check_tgs_bytes(b"") is None
    assert plugin.check_tgs_bytes(b"not gzip at all") is None
    # a truncated gzip stream (valid header, cut off mid-payload)
    good = open(os.path.join(FIXTURES, "safe_sticker.tgs"), "rb").read()
    assert plugin.check_tgs_bytes(good[: len(good) // 2]) is None


def test_hook_leaves_unreadable_file_arg_untouched():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()

    partial_path = os.path.join(FIXTURES, "_partial_download.tgs")
    with open(partial_path, "wb") as f:
        f.write(b"")  # simulates FileLoader having created but not yet written the file
    try:
        hook = plugin.BlockKillStickerHook(p)
        param = FakeParam([JFile(partial_path), 512, 512])
        hook.before_hooked_method(param)
        assert param.args[0].getAbsolutePath() == partial_path
    finally:
        os.remove(partial_path)


def test_gzip_bomb_is_still_blocked():
    huge_json = b'{"pad":"' + b"0" * (9 * 1024 * 1024) + b'"}'
    buf = __import__("io").BytesIO()
    with __import__("gzip").GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(huge_json)
    assert plugin.check_tgs_bytes(buf.getvalue()) is not None


def test_hook_swaps_malicious_inline_json_arg():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()

    hook = plugin.BlockKillStickerHook(p)
    malicious_json = (
        '{"v":"5.7.4","fr":30,"ip":0,"op":30,"w":512,"h":512,"assets":[],'
        '"layers":[{"ty":4,"shapes":[{"ty":"sr","pt":{"a":0,"k":1e38},'
        '"ir":{"a":0,"k":1},"or":{"a":0,"k":1}}]}]}'
    )
    param = FakeParam([None, malicious_json, 512, 512])
    hook.before_hooked_method(param)

    assert param.args[1] == plugin.SAFE_PLACEHOLDER_JSON
