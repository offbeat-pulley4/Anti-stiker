class FakeJavaClass:
    """Stands in for the real java.lang.Class reflection object returned by
    jclass(name).getClass() -- opaque here since our fake
    hook_all_constructors() doesn't call anything on it."""
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class FakeClassProxy:
    """Stands in for Chaquopy's own static class proxy (what jclass()
    itself returns) -- distinct from FakeJavaClass on purpose, mirroring
    the real SDK where the two are not interchangeable (see the
    getName/AttributeError bug this stub exists to catch a regression of)."""
    def __init__(self, name):
        self.name = name

    def getClass(self):
        return FakeJavaClass(self.name)


def jclass(name):
    return FakeClassProxy(name)
