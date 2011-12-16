class CommandError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        RuntimeError.__init__(self, message)
