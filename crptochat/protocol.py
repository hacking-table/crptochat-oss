"""Wire protocol: one JSON object per line over TCP/TLS.

The server only ever sees routing metadata (who, which channel) and opaque
base64 blobs. Everything inside ``body`` is encrypted end to end.
"""

from __future__ import annotations

import base64
import json
import re

PROTO_VERSION = 1
DEFAULT_PORT = 7777

MAX_LINE = 256 * 1024          # hard cap for a single frame
MAX_BODY = 64 * 1024           # cap for an encrypted body (base64 chars)
MAX_CHANNEL_MEMBERS = 200
MAX_CHANNELS_PER_USER = 50

GUEST_PREFIX = "anon-"       # reserved for anonymous (unregistered) sessions

NICK_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")
CHAN_RE = re.compile(r"^#[a-z0-9_\-]{1,32}$")


class ProtocolError(Exception):
    pass


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str, length: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise ProtocolError("expected base64 string")
    try:
        data = base64.b64decode(text, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ProtocolError("invalid base64") from exc
    if length is not None and len(data) != length:
        raise ProtocolError("unexpected length")
    return data


def encode(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def decode(line: bytes) -> dict:
    try:
        obj = json.loads(line)
    except Exception as exc:
        raise ProtocolError("invalid json") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
        raise ProtocolError("invalid frame")
    return obj


def valid_nick(nick) -> bool:
    return isinstance(nick, str) and bool(NICK_RE.match(nick))


def valid_chan(chan) -> bool:
    return isinstance(chan, str) and bool(CHAN_RE.match(chan))


MAX_TTL = 30 * 86400            # longest disappearing-message timer: 30 days
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """'90s', '10m', '1h', '7d' -> seconds; 'off' / '0' -> 0."""
    text = str(text).strip().lower()
    if text in ("off", "0", "não", "nao", "-"):
        return 0
    number, unit = text[:-1], text[-1:]
    if unit.isdigit():
        number, unit = text, "s"
    if not number.isdigit() or unit not in _UNITS or int(number) <= 0:
        raise ValueError(text)
    seconds = int(number) * _UNITS[unit]
    if seconds > MAX_TTL:
        raise ValueError(text)
    return seconds


def format_duration(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def is_guest_nick(nick: str) -> bool:
    return nick.lower().startswith(GUEST_PREFIX)
