__author__ = 'pshkitin'

import random
import sys

def print_item(info, format="{key:16}: {value}"):
    """Pass list of tuples to set approriate printing order"""
    print_table(({'key': key, 'value': value} for key, value in info), format)

def print_dict(info, format):
    sys.stdout.write(format.format(**info))
    sys.stdout.write("\n")

def print_table(rows, format):
    for row in rows:
        print_dict(row, format)

# Default symbols to use for passwords. Avoids visually confusing characters.
DEFAULT_PASSWORD_SYMBOLS = ('23456789'
                            'ABCDEFGHJKLMNPQRSTUVWXYZ'
                            'abcdefghijkmnopqrstuvwxyz')


def generate_password(length=20, symbols=DEFAULT_PASSWORD_SYMBOLS):
    """Generate a random password from the supplied symbols.
    """
    r = random.SystemRandom()
    return ''.join([r.choice(symbols) for _i in xrange(length)])