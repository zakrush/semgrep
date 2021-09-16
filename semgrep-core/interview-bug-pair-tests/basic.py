class A:
    def __init__(self):
        # ruleid: return-in-init
        return None


class B:
    def __init__(self):
        # ok: return-in-init
        self.inited = True
