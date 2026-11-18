"""Messages for someone who is offline (client side).

PreKeyStore keeps this client's prekeys (private parts) on disk, sealed with a
key derived from the identity key, so they open only after the identity is
unlocked. Mailbox publishes the public parts, leaves envelopes for offline
contacts and opens what was left for us while we were away.

What the server holds: the public prekeys and, for each stored envelope, the
recipient, the time and the opaque envelope (see crypto, "offline messages").
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from . import crypto
from .protocol import ProtocolError, b64d, b64e, valid_nick
from .store import config_dir

SPK_ROTATE = 7 * 86400          # a new signed prekey every week...
SPK_KEEP = 22 * 86400           # ...and the retired ones kept while mail sealed to them may wait
OPK_LOW = 25                    # top up the one-time keys below this...
OPK_TARGET = 100                # ...to this many
BATCH_TTL = 3600                # one sending batch (one bundle) per contact for at most this long
MAIL_KINDS = ("dm", "ttl", "ci")    # what may travel through the mailbox


class MailboxError(Exception):
    def __init__(self, msg: str, code: str = "mailbox"):
        super().__init__(msg)
        self.code = code


class PreKeyStore:
    """This client's private prekeys for one server and one nick, sealed at rest."""

    def __init__(self, identity, server_id: str):
        self.identity = identity
        tag = hashlib.sha256(f"{server_id}|{identity.nick.lower()}".encode()).hexdigest()[:24]
        folder = os.path.join(config_dir(), "prekeys")
        os.makedirs(folder, mode=0o700, exist_ok=True)
        self.path = os.path.join(folder, tag + ".bin")
        self._key = crypto.hkdf(crypto.ed_seed(identity.key),
                                b"crptochat-prekeys-v1|" + server_id.encode() + b"|" + identity.nick.lower().encode())
        self.data = self._load()

    def _fresh(self) -> dict:
        return {"spk": None, "old": [], "opks": {}, "next": 1, "seen": {}}

    def _load(self) -> dict:
        try:
            with open(self.path, "rb") as fh:
                blob = fh.read()
            data = json.loads(crypto.unseal(self._key, blob, b"crptochat-prekeys-v1"))
            if not isinstance(data, dict) or "opks" not in data:
                raise ValueError
            return data
        except (OSError, ValueError, crypto.CryptoError):
            # missing or unreadable (another identity with the same nick, for
            # instance): start over; mail sealed to the old keys cannot be opened
            return self._fresh()

    def save(self) -> None:
        blob = crypto.seal(self._key, json.dumps(self.data).encode(), b"crptochat-prekeys-v1")
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def _new_id(self) -> int:
        key_id = int(self.data["next"])
        self.data["next"] = key_id + 1
        return key_id

    def rotate(self, now: float | None = None) -> bool:
        """New signed prekey if there is none or it is a week old; forget retired
        ones once nothing sealed to them can still be waiting. True if changed."""
        now = now or time.time()
        changed = False
        spk = self.data["spk"]
        if spk is None or now - spk["t"] > SPK_ROTATE:
            if spk is not None:
                self.data["old"].append({**spk, "retired": now})
            key = crypto.x_generate()
            self.data["spk"] = {"id": self._new_id(), "priv": b64e(crypto.x_private_bytes(key)), "t": now}
            changed = True
        kept = [old for old in self.data["old"] if now - old["retired"] < SPK_KEEP]
        if len(kept) != len(self.data["old"]):
            self.data["old"], changed = kept, True
        # a one-time key handed out long ago whose mail never came: nothing sealed
        # to it can still be waiting on the server
        stale = [key_id for key_id, entry in self.data["opks"].items() if now - entry["t"] > SPK_KEEP]
        for key_id in stale:
            del self.data["opks"][key_id]
        changed = changed or bool(stale)
        expired = [tag for tag, until in self.data["seen"].items() if until < now]
        for tag in expired:
            del self.data["seen"][tag]
        return changed or bool(expired)

    def signed_prekey(self) -> tuple[int, bytes, bytes]:
        """(id, public key, signature) of the current signed prekey."""
        spk = self.data["spk"]
        pub = crypto.x_pub(crypto.x_from_private(b64d(spk["priv"])))
        sig = crypto.sign(self.identity.key, crypto.spk_message(self.identity.nick, spk["id"], pub))
        return spk["id"], pub, sig

    def new_onetime(self, count: int) -> list[list]:
        out = []
        for _ in range(max(0, count)):
            key = crypto.x_generate()
            key_id = self._new_id()
            self.data["opks"][str(key_id)] = {"k": b64e(crypto.x_private_bytes(key)), "t": time.time()}
            out.append([key_id, b64e(crypto.x_pub(key))])
        return out

    def forget_onetime(self, ids) -> None:
        """Drop one-time keys the server no longer has (handed out or never stored)."""
        for key_id in ids:
            self.data["opks"].pop(str(key_id), None)

    def spk_private(self, key_id: int):
        for spk in [self.data["spk"]] + self.data["old"]:
            if spk and spk["id"] == key_id:
                return crypto.x_from_private(b64d(spk["priv"]))
        return None

    def opk_private(self, key_id: int):
        entry = self.data["opks"].get(str(key_id))
        return crypto.x_from_private(b64d(entry["k"])) if entry else None

    def seen(self, tag: str) -> bool:
        return tag in self.data["seen"]

    def mark_seen(self, tag: str, until: float) -> None:
        self.data["seen"][tag] = until


class Mailbox:
    def __init__(self, client):
        self.client = client
        self.store: PreKeyStore | None = None
        self.out: dict[str, dict] = {}      # sending batches per contact (RAM only)
        self.busy = False

    @property
    def available(self) -> bool:
        c = self.client
        return not c.guest and "mailbox" in c.server_caps and bool(c.server_limits.get("mail_days", 1))

    # ---------------------------------------------------------- publishing

    async def sync(self) -> None:
        """After each login: publish prekeys, then open what is waiting."""
        if not self.available or self.busy:
            return
        self.busy = True
        try:
            if self.store is None:
                self.store = PreKeyStore(self.client.identity, self.client.store.server_id)
            await self._publish()
            await self._receive()
        finally:
            self.busy = False

    async def _publish(self) -> None:
        store = self.store
        status = await self.client.request({"t": "prekey_status"})
        rotated = store.rotate()
        req: dict = {"t": "prekeys"}
        if rotated or status.get("spk_id") != store.data["spk"]["id"]:
            spk_id, pub, sig = store.signed_prekey()
            req.update(spk_id=spk_id, spk=b64e(pub), spk_sig=b64e(sig))
        have = int(status.get("opks") or 0)
        if status.get("spk_id") is None or have < OPK_LOW:
            req["opks"] = store.new_onetime(OPK_TARGET - have)
        if len(req) > 1:
            store.save()               # private parts on disk before the public ones go out
            await self.client.request(req)
        elif rotated:
            store.save()

    # ------------------------------------------------------------- sending

    async def send(self, peer, inner: dict) -> dict:
        """Leave ``inner`` for ``peer``, who is offline. Raises MailboxError."""
        c = self.client
        if not self.available:
            raise MailboxError(f"{peer.nick} está offline e este servidor não guarda mensagens", "offline")
        if inner.get("k") not in MAIL_KINDS:
            raise MailboxError("isso não pode ser deixado para quem está offline", "offline")
        if not peer.trusted:
            raise MailboxError(f"a chave de {peer.nick} mudou e ainda não foi aceita: /verify {peer.nick}", "untrusted")
        batch = self.out.get(peer.key)
        if batch is None or time.time() - batch["t"] > BATCH_TTL or batch["ik"] != peer.ik:
            batch = self.out[peer.key] = await self._bundle(peer)
        payload = json.dumps(inner)
        ts = int(time.time())
        header = batch["prefix"] + batch["chain"].n.to_bytes(4, "big")
        sig = crypto.sign(c.identity.key, crypto.mail_signed(header, peer.nick, c.nick, ts, payload))
        plain = json.dumps({"f": c.nick, "ts": ts, "m": payload, "s": b64e(sig)}).encode()
        body = crypto.mail_encrypt(batch["chain"], batch["prefix"], peer.nick, plain)
        reply = await c.request({"t": "mail", "to": peer.nick, "body": b64e(body)})
        return reply

    async def _bundle(self, peer) -> dict:
        reply = await self.client.request({"t": "prekey_bundle", "nick": peer.nick})
        try:
            ik = b64d(reply["user"]["ik"], 32)
            spk_id, spk, sig = int(reply["spk_id"]), b64d(reply["spk"], 32), b64d(reply["spk_sig"], 64)
            opk = reply.get("opk")
            opk_id, opk_pub = (int(opk["id"]), b64d(opk["k"], 32)) if opk else (None, None)
        except (ProtocolError, KeyError, TypeError, ValueError) as exc:
            raise MailboxError("pacote de prekeys inválido") from exc
        if ik != peer.ik:
            raise MailboxError(f"o servidor apresentou outra chave para {peer.nick}: nada foi enviado", "untrusted")
        if not crypto.verify(peer.ik, sig, crypto.spk_message(peer.nick, spk_id, spk)):
            raise MailboxError(f"a prekey de {peer.nick} não tem assinatura válida: nada foi enviado", "untrusted")
        prefix, sk = crypto.mail_start(peer.ik, spk_id, spk, opk_id, opk_pub)
        return {"prefix": prefix, "chain": crypto.Chain(sk), "t": time.time(), "ik": peer.ik}

    # ----------------------------------------------------------- receiving

    async def _receive(self) -> None:
        c = self.client
        store = self.store
        for _ in range(20):
            reply = await c.request({"t": "mail_fetch"})
            items = reply.get("mail") or []
            if not items:
                return
            secrets: dict[tuple, bytes] = {}
            used: set[int] = set()
            done = []
            for item in items:
                try:
                    mail_id = int(item["id"])
                except (KeyError, TypeError, ValueError):
                    continue
                done.append(mail_id)
                try:
                    await self._open(item, secrets, used)
                except (crypto.CryptoError, ProtocolError, MailboxError, KeyError, TypeError, ValueError) as exc:
                    c.sys(f"uma mensagem deixada enquanto você estava offline não pôde ser aberta ({exc})", "warn")
            # one-time keys are used once: forget them before telling the server
            store.forget_onetime(used)
            store.save()
            await c.request({"t": "mail_ack", "ids": done})
            if not reply.get("more"):
                break
        if self.store and len(self.store.data["opks"]) < OPK_LOW:
            await self._publish()

    async def _open(self, item: dict, secrets: dict, used: set) -> None:
        c = self.client
        store = self.store
        body = b64d(item["body"])
        ek, spk_id, opk_id, n = crypto.mail_parse(body)
        tag = hashlib.sha256(body[:crypto.MAIL_HEADER]).hexdigest()
        if store.seen(tag):
            return                              # the server handed it out again
        key = (ek, spk_id, opk_id)
        sk = secrets.get(key)
        if sk is None:
            spk = store.spk_private(spk_id)
            opk = store.opk_private(opk_id) if opk_id is not None else None
            if spk is None or (opk_id is not None and opk is None):
                raise MailboxError("as prekeys dela já expiraram ou foram usadas")
            sk = secrets[key] = crypto.mail_secret(c.identity.ik, ek, spk_id, spk, opk_id, opk)
            if opk_id is not None:
                used.add(opk_id)
        plain = json.loads(crypto.mail_decrypt(sk, c.nick, body))
        sender, ts, payload, sig = plain["f"], int(plain["ts"]), str(plain["m"]), b64d(plain["s"], 64)
        if not valid_nick(sender) or sender.lower() == c.key:
            raise MailboxError("remetente inválido")
        peer = await c.resolve(sender)
        if not peer.trusted:
            raise MailboxError(f"a chave de {peer.nick} mudou e ainda não foi aceita (/verify {peer.nick})")
        if not crypto.verify(peer.ik, sig, crypto.mail_signed(body[:crypto.MAIL_HEADER], c.nick, sender, ts, payload)):
            raise MailboxError(f"assinatura de {peer.nick} inválida")
        inner = json.loads(payload)
        if not isinstance(inner, dict) or inner.get("k") not in MAIL_KINDS:
            return
        store.mark_seen(tag, time.time() + crypto_seen_ttl(c))
        c._on_inner(peer, inner, sent=ts)


def crypto_seen_ttl(client) -> float:
    """How long a stored envelope id is remembered (to refuse it if handed out again)."""
    days = client.server_limits.get("mail_days") or 14
    try:
        return float(days) * 86400 + 86400
    except (TypeError, ValueError):
        return 15 * 86400
