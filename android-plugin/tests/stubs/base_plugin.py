class BasePlugin:
    def __init__(self): pass
    def get_setting(self, k, d=None): return d
    def hook_all_constructors(self, cls, hook): return []
    def unhook_method(self, u): pass

class MethodHook:
    def before_hooked_method(self, param): pass
    def after_hooked_method(self, param): pass
