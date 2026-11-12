"""Local state of the client: identity keys, pinned keys and preferences.

Nothing here ever contains message history: conversations only exist in RAM.
"""

from __future__ import annotations

import json
import os

from . import crypto, vault
from .protocol import b64d, b64e


def config_dir() -> str:
    base = os.environ.get("CRPTOCHAT_HOME")
    if not base:
        base = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "crptochat")
    os.makedirs(os.path.join(base, "identities"), mode=0o700, exist_ok=True)
    return base


def _write_private(path: str, data: dict, sync: bool = False) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1)
        if sync:
            fh.flush()
            os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read(path: str, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


class BadPassphrase(Exception):
    pass


def _sealed(nick: str, seed: bytes, passphrase: str) -> dict:
    """The stored form of an identity: the 32-byte seed sealed with a key from
    the passphrase (scrypt, fresh salt), bound to the nickname."""
    salt = os.urandom(16)
    key = crypto.scrypt_key(passphrase, salt)
    blob = crypto.seal(key, seed, b"crptochat-identity|" + nick.lower().encode())
    return {"v": 1, "nick": nick, "salt": b64e(salt), "key": b64e(blob)}


def _unseal(data: dict, passphrase: str) -> bytes:
    key = crypto.scrypt_key(passphrase, b64d(data["salt"]))
    try:
        return crypto.unseal(key, b64d(data["key"]), b"crptochat-identity|" + data["nick"].lower().encode())
    except crypto.CryptoError as exc:
        raise BadPassphrase() from exc


class Identity:
    """An Ed25519 key pair bound to a nickname, encrypted at rest.

    The encrypted key lives in a file (config directory by default, or any
    other directory such as a removable drive) or in a password vault
    (``source``, see vault.py).
    """

    def __init__(self, nick: str, key, file: str | None = None, source: dict | None = None):
        self.nick = nick
        self.key = key
        self.ik = crypto.ed_pub(key)
        self.file = file
        self.source = source
        self.is_new = False

    @property
    def location(self) -> str:
        return vault.describe(self.source) if self.source else (self.file or "memória")

    @staticmethod
    def path(nick: str, key_dir: str | None = None) -> str:
        folder = os.path.expanduser(key_dir) if key_dir else os.path.join(config_dir(), "identities")
        return os.path.join(folder, nick.lower() + ".json")

    @classmethod
    def exists(cls, nick: str, key_dir: str | None = None, source: dict | None = None) -> bool:
        if source:
            return vault.exists(source, nick)
        return os.path.exists(cls.path(nick, key_dir))

    @staticmethod
    def list() -> list[str]:
        out = []
        folder = os.path.join(config_dir(), "identities")
        for name in sorted(os.listdir(folder)):
            if name.endswith(".json"):
                out.append(_read(os.path.join(folder, name), {}).get("nick") or name[:-5])
        return out

    @classmethod
    def create(cls, nick: str, passphrase: str, key_dir: str | None = None,
               source: dict | None = None) -> "Identity":
        path = None if source else cls.path(nick, key_dir)
        if cls.exists(nick, key_dir, source):
            raise FileExistsError(vault.describe(source) if source else path)
        ident = cls(nick, crypto.ed_generate(), path, source)
        ident.is_new = True
        data = _sealed(nick, crypto.ed_seed(ident.key), passphrase)
        if source:
            vault.write(source, nick, json.dumps(data, separators=(",", ":")))
        else:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            _write_private(path, data)
        return ident

    @classmethod
    def load(cls, nick: str, passphrase: str, key_dir: str | None = None,
             source: dict | None = None) -> "Identity":
        path = None if source else cls.path(nick, key_dir)
        if source:
            text = vault.read(source, nick)
            try:
                data = json.loads(text) if text else None
            except ValueError:
                raise vault.VaultError("o cofre devolveu algo que não é uma chave do crptochat") from None
        else:
            # a password change interrupted halfway leaves the new copy next to it
            data = _read(path, None) or _read(path + ".new", None)
        if not data:
            raise FileNotFoundError(vault.describe(source) if source else path)
        seed = _unseal(data, passphrase)
        return cls(data["nick"], crypto.ed_from_seed(seed), path, source)

    def change_passphrase(self, old: str, new: str) -> str:
        """Re-encrypt the stored key with a new passphrase (new salt). The key
        itself does not change: same nick, same fingerprint, nobody sees a key
        change. ``old`` is checked against what is stored, not against memory.

        Files are rewritten in place (same size, so the old bytes are
        overwritten; best effort on flash/SSD), with a complete copy written
        first so an interruption never leaves the key unreadable. Returns where
        the key is."""
        if not self.file and not self.source:
            raise ValueError("esta identidade não fica guardada (sessão anônima): não há senha para trocar")
        if old == new:
            raise ValueError("a senha nova é igual à atual")
        if self.source:
            text = vault.read(self.source, self.nick)
            try:
                stored = json.loads(text) if text else None
            except ValueError:
                stored = None
        else:
            stored = _read(self.file, None)
        if not stored:
            raise FileNotFoundError(self.location)
        seed = _unseal(stored, old)                       # BadPassphrase if wrong
        if crypto.ed_pub(crypto.ed_from_seed(seed)) != self.ik:
            raise ValueError("a chave guardada não é a desta sessão: nada foi alterado")
        data = _sealed(stored["nick"], seed, new)

        if self.source:
            vault.write(self.source, self.nick, json.dumps(data, separators=(",", ":")))
            back = vault.read(self.source, self.nick)
            try:
                ok = back is not None and _unseal(json.loads(back), new) == seed
            except (ValueError, BadPassphrase):
                ok = False
            if not ok:
                raise vault.VaultError("o cofre gravou algo que não confere; a senha antiga pode ainda valer")
            return self.location

        spare = self.file + ".new"
        _write_private(spare, data, sync=True)            # complete copy first
        if _unseal(_read(spare, {}), new) != seed:
            os.remove(spare)
            raise OSError("a cópia nova não confere; nada foi alterado")
        payload = json.dumps(data, indent=1).encode()
        with open(self.file, "r+b") as fh:                # overwrite the old bytes in place
            fh.write(payload)
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())
        os.remove(spare)
        return self.file

    @staticmethod
    def _wipe_file(path: str, size: int) -> None:
        with open(path, "r+b") as fh:
            fh.write(b"\0" * size)
            fh.flush()
            os.fsync(fh.fileno())
        os.remove(path)

    @classmethod
    def relocate(cls, nick: str, src_dir: str | None = None, src_source: dict | None = None,
                 dest_dir: str | None = None, dest_source: dict | None = None) -> str | None:
        """Move the encrypted key between files and vaults, without needing the
        passphrase. The copy is read back and compared before the original is
        destroyed (files are overwritten with zeros first; best effort on
        flash/SSD). Returns the new file path, or None for a vault."""
        if src_source:
            raw = vault.read(src_source, nick)
        else:
            try:
                with open(cls.path(nick, src_dir)) as fh:
                    raw = fh.read()
            except FileNotFoundError:
                raw = None
        if not raw:
            raise FileNotFoundError(vault.describe(src_source) if src_source else cls.path(nick, src_dir))
        data = json.loads(raw)
        if cls.exists(nick, dest_dir, dest_source):
            raise FileExistsError(vault.describe(dest_source) if dest_source else cls.path(nick, dest_dir))

        if dest_source:
            vault.write(dest_source, nick, json.dumps(data, separators=(",", ":")))
            back = vault.read(dest_source, nick)
            dest = None
        else:
            dest = cls.path(nick, dest_dir)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=1)
                fh.flush()
                os.fsync(fh.fileno())
            with open(dest) as fh:
                back = fh.read()
        try:
            same = back is not None and json.loads(back) == data
        except ValueError:
            same = False
        if not same:
            raise vault.VaultError("a cópia foi gravada, mas não consegui conferi-la; a chave original foi mantida")

        if src_source:
            vault.delete(src_source, nick)
        else:
            cls._wipe_file(cls.path(nick, src_dir), len(raw.encode()))
        return dest

    @classmethod
    def move(cls, nick: str, dest_dir: str, src_dir: str | None = None) -> str:
        return cls.relocate(nick, src_dir=src_dir, dest_dir=dest_dir)

    def delete(self) -> None:
        try:
            if self.source:
                vault.delete(self.source, self.nick)
            else:
                os.remove(self.file or self.path(self.nick))
        except OSError:
            pass


class Store:
    """Trust-on-first-use pins for users and servers, plus preferences."""

    def __init__(self, server_id: str):
        self.server_id = server_id
        self._users_path = os.path.join(config_dir(), "known_users.json")
        self._servers_path = os.path.join(config_dir(), "known_servers.json")
        self._users = _read(self._users_path, {})

    # --- users -----------------------------------------------------------
    def check_user(self, nick: str, ik: bytes) -> str:
        """Returns 'new', 'ok' or 'mismatch'. New keys are pinned (TOFU).

        A different key is never adopted silently: it is kept as *pending*
        (so the warning survives a restart) until the user accepts it."""
        table = self._users.setdefault(self.server_id, {})
        entry = table.get(nick.lower())
        if entry is None:
            table[nick.lower()] = {"nick": nick, "ik": b64e(ik), "verified": False}
            _write_private(self._users_path, self._users)
            return "new"
        if entry["ik"] == b64e(ik):
            return "ok"
        if entry.get("pending") != b64e(ik):
            entry["pending"] = b64e(ik)
            _write_private(self._users_path, self._users)
        return "mismatch"

    def pinned(self, nick: str) -> bytes | None:
        entry = self._users.get(self.server_id, {}).get(nick.lower())
        return b64d(entry["ik"]) if entry else None

    def pending(self, nick: str) -> bytes | None:
        entry = self._users.get(self.server_id, {}).get(nick.lower())
        return b64d(entry["pending"]) if entry and entry.get("pending") else None

    def accept_key(self, nick: str, ik: bytes, verified: bool = False) -> None:
        """Replace the pinned key after the user confirmed the change."""
        table = self._users.setdefault(self.server_id, {})
        table[nick.lower()] = {"nick": nick, "ik": b64e(ik), "verified": verified}
        _write_private(self._users_path, self._users)

    def is_verified(self, nick: str) -> bool:
        return bool(self._users.get(self.server_id, {}).get(nick.lower(), {}).get("verified"))

    def set_verified(self, nick: str, value: bool = True) -> bool:
        entry = self._users.get(self.server_id, {}).get(nick.lower())
        if not entry:
            return False
        entry["verified"] = value
        _write_private(self._users_path, self._users)
        return True

    # --- disappearing messages in direct conversations ----------------------
    def dm_ttl(self, nick: str) -> int:
        data = _read(os.path.join(config_dir(), "dm_ttl.json"), {})
        value = data.get(self.server_id, {}).get(nick.lower(), 0)
        return value if isinstance(value, int) else 0

    def set_dm_ttl(self, nick: str, seconds: int) -> None:
        path = os.path.join(config_dir(), "dm_ttl.json")
        data = _read(path, {})
        table = data.setdefault(self.server_id, {})
        if seconds:
            table[nick.lower()] = int(seconds)
        else:
            table.pop(nick.lower(), None)
        _write_private(path, data)

    # --- friends ---------------------------------------------------------
    # Kept on this machine only: the server never stores who your friends are.
    def friends(self) -> list[str]:
        data = _read(os.path.join(config_dir(), "friends.json"), {})
        return sorted(data.get(self.server_id, []), key=str.lower)

    def set_friend(self, nick: str, on: bool = True) -> bool:
        path = os.path.join(config_dir(), "friends.json")
        data = _read(path, {})
        current = [n for n in data.get(self.server_id, []) if n.lower() != nick.lower()]
        changed = on or len(current) != len(data.get(self.server_id, []))
        if on:
            current.append(nick)
        data[self.server_id] = current
        _write_private(path, data)
        return changed

    # --- servers ---------------------------------------------------------
    def server_pin(self) -> str | None:
        return _read(self._servers_path, {}).get(self.server_id)

    def pin_server(self, fingerprint: str | None) -> None:
        data = _read(self._servers_path, {})
        if fingerprint is None:
            data.pop(self.server_id, None)
        else:
            data[self.server_id] = fingerprint
        _write_private(self._servers_path, data)


def load_prefs() -> dict:
    return _read(os.path.join(config_dir(), "config.json"), {})


def save_prefs(prefs: dict) -> None:
    _write_private(os.path.join(config_dir(), "config.json"), prefs)
