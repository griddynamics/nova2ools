import sys

from functools import wraps

class CommandError(RuntimeError):
    def __init__(self, status, message):
        RuntimeError.__init__(self, message, status)

    def status(self):
        return self.args[1]

    def message(self):
        return self.args[0]

def handle_command_error(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            function(*args, **kwargs)
        except CommandError, e:
            sys.stderr.write("Error: {0}\n".format(e.message()))
            sys.exit(e.status())
    return wrapper
