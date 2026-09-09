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


def test_notifications_off_by_default():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()
    plugin.BulletinHelper.calls.clear()

    hook = plugin.BlockKillStickerHook(p)
    kill_path = os.path.join(FIXTURES, "kill_sticker.tgs")
    hook.before_hooked_method(FakeParam([JFile(kill_path), 512, 512]))

    assert plugin.BulletinHelper.calls == []


def test_notification_deduped_per_path_when_enabled():
    p = plugin.AntiStikerPlugin()
    p.on_plugin_load()
    p.get_setting = lambda key, default=None: True  # force notifications on
    plugin.BulletinHelper.calls.clear()

    hook = plugin.BlockKillStickerHook(p)
    kill_path = os.path.join(FIXTURES, "kill_sticker.tgs")

    # RLottieDrawable gets rebuilt repeatedly for the same on-disk file
    # (view recycling / scrolling) -- the same file should only bulletin once.
    hook.before_hooked_method(FakeParam([JFile(kill_path), 512, 512]))
    hook.before_hooked_method(FakeParam([JFile(kill_path), 512, 512]))
    hook.before_hooked_method(FakeParam([JFile(kill_path), 512, 512]))

    assert len(plugin.BulletinHelper.calls) == 1


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
