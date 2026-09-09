class BulletinHelper:
    calls = []

    @classmethod
    def show_error(cls, msg, fragment=None):
        print("BULLETIN:", msg)
        cls.calls.append(msg)
