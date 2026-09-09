class BasePlugin:
    def __init__(self): pass
    def get_setting(self, k, d=None): return d

    def hook_all_constructors(self, cls, hook):
        # The real base_plugin.py (base_plugin.py:570 in the traceback that
        # motivated this stub) calls cls.getName() -- if `cls` is Chaquopy's
        # raw class proxy instead of a real java.lang.Class, that raises
        # AttributeError there. Calling it here makes that regression fail
        # a test instead of only showing up as "plugin won't enable" on a
        # real device.
        cls.getName()
        return []

    def unhook_method(self, u): pass

class MethodHook:
    def before_hooked_method(self, param): pass
    def after_hooked_method(self, param): pass
