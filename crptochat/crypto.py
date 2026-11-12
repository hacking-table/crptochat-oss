"""Cryptographic building blocks.

Primitives (all from the `cryptography` library, no home-made ciphers):
  * Ed25519            long-term identity of a nickname (signatures)
  * X25519             per-session key agreement (thrown away on disconnect)
  * ChaCha20-Poly1305  authenticated encryption
  * HKDF-SHA256        key derivation
  * HMAC-SHA256        symmetric hash ratchet for channel messages
  * scrypt             passphrase stretching (identity file, private channels)
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

SCRYPT_N = 2 ** 15
PAD_BLOCK = 64
ZERO_NONCE = b"\x00" * 12
MAX_CHAIN_SKIP = 2000


class CryptoError(Exception):
    """Decryption / verification failure."""


# --------------------------------------------------------------- key helpers

def ed_generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed_from_seed(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def ed_seed(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def ed_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x_generate() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x_pub(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(key: Ed25519PrivateKey, message: bytes) -> bytes:
    return key.sign(message)


def verify(pub: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


FP_ITERATIONS = 5200


@functools.lru_cache(maxsize=1024)
def _fp_digits(ik: bytes) -> tuple[str, ...]:
    # Iterated hash (as in Signal's safety numbers): makes searching for a
    # key whose fingerprint merely looks similar much more expensive.
    digest = b"crptochat-fp-v2" + ik
    for _ in range(FP_ITERATIONS):
        digest = hashlib.sha512(digest + ik).digest()
    return tuple(f"{int.from_bytes(digest[i * 5:i * 5 + 5], 'big') % 100000:05d}" for i in range(6))


def fingerprint(ik: bytes) -> str:
    """Fingerprint of an identity key: 6 groups of 5 digits (~100 bits)."""
    return " ".join(_fp_digits(ik))


def safety_number(ik_a: bytes, ik_b: bytes) -> str:
    """Number shared by two people: both see the same 12 groups, whoever asks.
    If the server swapped either key, the two sides see different numbers."""
    lo, hi = sorted((ik_a, ik_b))
    return " ".join(_fp_digits(lo) + _fp_digits(hi))


def legacy_fingerprint(ik: bytes) -> str:
    """Hex fingerprint shown by older clients, for comparing with them."""
    digest = hashlib.sha256(b"crptochat-fp-v1" + ik).hexdigest().upper()[:20]
    return " ".join(digest[i:i + 4] for i in range(0, 20, 4))


def guest_nick(ik: bytes) -> str:
    """Nickname of an anonymous session: derived from its throwaway key, so
    nobody can pick someone else's and everyone can check it."""
    return "anon-" + hashlib.sha256(b"crptochat-guest-v1" + ik).hexdigest()[:8]


# ------------------------------------------------------------------- KDFs

def hkdf(key: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def scrypt_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def channel_secrets(passphrase: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive (auth, psk, history key) for a private channel from its password.

    One scrypt (N=2^15, r=8, p=1) with the channel's own random salt, then
    HKDF with a different label for each key:
    ``auth`` is shown to the server as an access token (it stores only a hash);
    ``psk`` never leaves the clients and wraps the sender keys, so that even a
    server that injects a fake member cannot read a private channel;
    ``hkey`` encrypts the optional stored history (see history_seal).
    """
    master = scrypt_key(passphrase, salt)
    return (hkdf(master, b"crptochat-chan-auth-v1"), hkdf(master, b"crptochat-chan-psk-v1"),
            hkdf(master, b"crptochat-chan-history-v1"))


def channel_keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    """(auth, psk) for a private channel (see channel_secrets)."""
    return channel_secrets(passphrase, salt)[:2]


# ------------------------------------------------- private-channel history
#
# A copy of each message, encrypted with the channel's history key (derived
# from the password) and signed by the sender's identity, so that whoever
# knows the password can read the last messages even after joining later.
# The epoch changes when the password changes, so old copies no longer open.

def _history_aad(chan: str, epoch: int) -> bytes:
    return b"crptochat-hist-v1|" + chan.encode() + b"|" + str(epoch).encode()


def history_signed(chan: str, epoch: int, nick: str, ts: int, text: str, line_id: str) -> bytes:
    """What the author signs: channel, epoch, author, time, a random id unique
    to this line (so a copy replayed by someone else is recognised) and the text."""
    return b"crptochat-hist-sig-v2|" + _history_aad(chan, epoch) + b"|" + nick.lower().encode() + b"|" \
        + str(ts).encode() + b"|" + line_id.encode() + b"|" + text.encode()


def history_seal(hkey: bytes, chan: str, epoch: int, plaintext: bytes) -> bytes:
    return seal(hkey, pad(plaintext), _history_aad(chan, epoch))


def history_open(hkey: bytes, chan: str, epoch: int, blob: bytes) -> bytes:
    return unpad(unseal(hkey, blob, _history_aad(chan, epoch)))


def auth_verifier(auth: bytes) -> bytes:
    """What the server stores for a private channel."""
    return hashlib.sha256(b"crptochat-verifier-v1" + auth).digest()


# ----------------------------------------------------------- signed messages

def auth_message(nonce: bytes, nick: str, dh: bytes) -> bytes:
    return b"crptochat-auth-v1|" + nonce + b"|" + nick.encode() + b"|" + dh


def dh_message(nick: str, dh: bytes) -> bytes:
    return b"crptochat-dh-v1|" + nick.lower().encode() + b"|" + dh


# ------------------------------------------------------------------- AEAD

def pad(data: bytes) -> bytes:
    """ISO/IEC 7816-4 padding to hide exact message length."""
    data += b"\x80"
    return data + b"\x00" * (-len(data) % PAD_BLOCK)


def unpad(data: bytes) -> bytes:
    idx = data.rfind(b"\x80")
    if idx < 0 or any(data[idx + 1:]):
        raise CryptoError("bad padding")
    return data[:idx]


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 28:
        raise CryptoError("short ciphertext")
    try:
        return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise CryptoError("decryption failed") from exc


def pair_key(my_dh: X25519PrivateKey, their_dh: bytes, ik_a: bytes, ik_b: bytes) -> bytes:
    """Session key between two users, bound to both identity keys."""
    try:
        shared = my_dh.exchange(X25519PublicKey.from_public_bytes(their_dh))
    except ValueError as exc:
        raise CryptoError("bad dh key") from exc
    lo, hi = sorted((ik_a, ik_b))
    return hkdf(shared, b"crptochat-pair-v1|" + lo + hi)


# ------------------------------------------------- channel sender-key ratchet

class Chain:
    """Symmetric hash ratchet. Each message uses a fresh key; old keys are
    unrecoverable, so someone who joins later cannot decrypt earlier traffic."""

    __slots__ = ("ck", "n")

    def __init__(self, ck: bytes | None = None, n: int = 0):
        self.ck = ck if ck is not None else os.urandom(32)
        self.n = n

    def step(self) -> tuple[int, bytes]:
        mk = hmac.new(self.ck, b"\x01", hashlib.sha256).digest()
        n = self.n
        self.ck = hmac.new(self.ck, b"\x02", hashlib.sha256).digest()
        self.n += 1
        return n, mk

    def copy(self) -> "Chain":
        return Chain(self.ck, self.n)


def _msg_aad(chan: str, sender: str, n: int) -> bytes:
    return b"crptochat-msg-v1|" + chan.encode() + b"|" + sender.lower().encode() + b"|" + struct.pack(">I", n)


def channel_encrypt(chain: Chain, signer: Ed25519PrivateKey, chan: str, sender: str, plaintext: bytes) -> bytes:
    n, mk = chain.step()
    aad = _msg_aad(chan, sender, n)
    ct = ChaCha20Poly1305(mk).encrypt(ZERO_NONCE, pad(plaintext), aad)
    return struct.pack(">I", n) + sign(signer, aad + ct) + ct


def channel_decrypt(chain: Chain, sender_ik: bytes, chan: str, sender: str, body: bytes) -> bytes:
    """Decrypt and advance ``chain``. The chain is untouched on failure."""
    if len(body) < 4 + 64 + 16:
        raise CryptoError("short message")
    n = struct.unpack(">I", body[:4])[0]
    sig, ct = body[4:68], body[68:]
    aad = _msg_aad(chan, sender, n)
    if not verify(sender_ik, sig, aad + ct):
        raise CryptoError("bad signature")
    if n < chain.n:
        raise CryptoError("replayed or old message")
    if n - chain.n > MAX_CHAIN_SKIP:
        raise CryptoError("chain gap too large")
    work = chain.copy()
    while work.n < n:
        work.step()
    _, mk = work.step()
    try:
        plaintext = unpad(ChaCha20Poly1305(mk).decrypt(ZERO_NONCE, ct, aad))
    except InvalidTag as exc:
        raise CryptoError("decryption failed") from exc
    chain.ck, chain.n = work.ck, work.n
    return plaintext


# ------------------------------------------ direct-message ratchet (v2)
#
# Root: the pairwise key of the current sessions (each side's X25519 session
# key is fresh per login and signed by its identity key). From it, one hash
# ratchet per direction: every envelope uses a new message key and the chain
# moves on, so keys of envelopes already handled are gone. Body layout:
#     0x02 | n (4 bytes) | ChaCha20-Poly1305(mk_n, zero nonce, pad(plaintext))

DM_V2 = 0x02


def dm_chains(root: bytes, my_ik: bytes, peer_ik: bytes) -> tuple[Chain, Chain]:
    """(sending, receiving) chains for this pair of sessions."""
    send = hkdf(root, b"crptochat-dm-chain-v2|" + my_ik + peer_ik)
    recv = hkdf(root, b"crptochat-dm-chain-v2|" + peer_ik + my_ik)
    return Chain(send), Chain(recv)


def _dm_aad(sender: str, recipient: str, n: int) -> bytes:
    return (b"crptochat-dm-v2|" + sender.lower().encode() + b"|" + recipient.lower().encode()
            + b"|" + struct.pack(">I", n))


def dm_encrypt(chain: Chain, sender: str, recipient: str, plaintext: bytes) -> bytes:
    n, mk = chain.step()
    ct = ChaCha20Poly1305(mk).encrypt(ZERO_NONCE, pad(plaintext), _dm_aad(sender, recipient, n))
    return bytes([DM_V2]) + struct.pack(">I", n) + ct


def dm_decrypt(chain: Chain, sender: str, recipient: str, body: bytes) -> bytes:
    """Decrypt and advance ``chain``; on any failure the chain is untouched."""
    if len(body) < 5 + 16 or body[0] != DM_V2:
        raise CryptoError("not a v2 direct envelope")
    n = struct.unpack(">I", body[1:5])[0]
    if n < chain.n:
        raise CryptoError("replayed or old direct message")
    if n - chain.n > MAX_CHAIN_SKIP:
        raise CryptoError("chain gap too large")
    work = chain.copy()
    while work.n < n:          # envelopes lost in between (e.g. refused by the relay)
        work.step()
    _, mk = work.step()
    try:
        plaintext = unpad(ChaCha20Poly1305(mk).decrypt(ZERO_NONCE, body[5:], _dm_aad(sender, recipient, n)))
    except InvalidTag as exc:
        raise CryptoError("decryption failed") from exc
    chain.ck, chain.n = work.ck, work.n
    return plaintext


# ---------------------------------------------------------- file stream AEAD

FILE_CHUNK = 64 * 1024


def file_encrypt_chunk(key: bytes, index: int, chunk: bytes, last: bool) -> bytes:
    nonce = struct.pack(">4xQ", index)
    return ChaCha20Poly1305(key).encrypt(nonce, chunk, b"\x01" if last else b"\x00")


def file_decrypt_chunk(key: bytes, index: int, blob: bytes, last: bool) -> bytes:
    nonce = struct.pack(">4xQ", index)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, blob, b"\x01" if last else b"\x00")
    except InvalidTag as exc:
        raise CryptoError("file chunk authentication failed") from exc
