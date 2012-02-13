import random

# Default symbols to use for passwords. Avoids visually confusing characters.
DEFAULT_PASSWORD_SYMBOLS = ('23456789'
                            'ABCDEFGHJKLMNPQRSTUVWXYZ'
                            'abcdefghijkmnopqrstuvwxyz')


def generate_password(length=20, symbols=DEFAULT_PASSWORD_SYMBOLS):
    """Generate a random password from the supplied symbols.
    """
    r = random.SystemRandom()
    return ''.join([r.choice(symbols) for _i in xrange(length)])