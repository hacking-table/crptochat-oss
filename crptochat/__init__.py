"""crptochat - chat de terminal com criptografia ponta a ponta."""

__version__ = "1.10.0"

try:  # written by the release build so a binary can tell which commit it is
    from ._build import COMMIT as __build__
except ImportError:
    __build__ = ""
