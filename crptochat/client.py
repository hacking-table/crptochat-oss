"""Client engine: networking, end-to-end encryption and channel state.

This module has no UI. It reports everything through ``on_event(kind, data)``
so that it can be driven by the TUI or by tests.

Encryption model
----------------
* Every login creates a fresh X25519 key, signed by the nickname's Ed25519
  identity. Two users derive a pairwise key from it ("direct" envelopes).
  The key dies with the session, so recorded traffic cannot be decrypted
  later even if an identity key leaks.
* In a channel each member owns a *sender chain* (hash ratchet). The chain
  key is handed to the other members through pairwise envelopes. Chains are
  replaced whenever someone leaves, and newcomers only get the current state,
  so they cannot read what was said before they joined.
* Private channels add a passphrase-derived key (never sent to the server)
  that wraps the chain keys.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import ssl
import time

from . import __version__, crypto
from .crypto import Chain, CryptoError
from .p2p import FileTransfers
from .relayfile import RelayFiles
from .protocol import (
    MAX_BODY,
    MAX_LINE,
    MAX_TTL,
    ProtocolError,
    b64d,
    b64e,
    decode,
    encode,
    is_guest_nick,
    valid_chan,
    valid_nick,
)
from .store import Identity, Store

MAX_TEXT = 4000
CLIENT_CAPS = ["dmr", "file2"]   # advertised to peers inside direct envelopes
AUDIO_CHUNK = 20_000        # raw bytes per relayed envelope
MAX_AUDIO = 1_500_000
MAX_AUDIO_PARTIAL = 8       # clips being received at the same time
AUDIO_BUCKET = 4            # clips are padded to a multiple of this many envelopes
MAX_PENDING = 200


class ChatError(Exception):
    def __init__(self, msg: str, code: str = "error"):
        super().__init__(msg)
        self.code = code


class FatalError(ChatError):
    """Errors that reconnecting will not fix."""


class NeedPassphrase(ChatError):
    def __init__(self, chan: str):
        super().__init__(f"{chan} é privado: senha necessária", "need_pass")
        self.chan = chan


class Peer:
    def __init__(self, nick: str, ik: bytes):
        self.nick = nick
        self.key = nick.lower()
        self.ik = ik
        self.dh: bytes | None = None
        self.trusted = True
        self.warned = False
        self.pending_ik: bytes | None = None   # key presented by the server that differs from the pinned one
        # Direct-envelope state, one entry per *root* (pairwise key of a pair of
        # sessions). Bound to the root's value, never to the object holding it:
        # if the server swaps their session key and later restores it, the same
        # root comes back and its chains continue instead of restarting at n=0.
        self._states: dict[bytes, dict] = {}
        self._burned: set[bytes] = set()        # evicted roots: never reused
        self._cur: dict = {"dmr": False, "got_v2": False, "caps": None}
        self.hello: asyncio.Event | None = None
        self.dropped = False                    # told the user we refused a message from them
        self.guest = False
        self.role = "user"      # role on the server: user, mod or admin
        self.away = False
        self._pair: tuple[bytes, bytes] | None = None

    # what the current pair of sessions agreed on (see _states)
    @property
    def dmr(self) -> bool:
        """Their current session speaks ratcheted (v2) direct envelopes."""
        return self._cur["dmr"]

    @dmr.setter
    def dmr(self, value: bool) -> None:
        self._cur["dmr"] = value

    @property
    def got_v2(self) -> bool:
        """They already sent us a v2 envelope in this pair of sessions."""
        return self._cur["got_v2"]

    @property
    def caps(self) -> set[str] | None:
        """What their client advertised in this pair of sessions (None: unknown yet)."""
        return self._cur.get("caps")

    @caps.setter
    def caps(self, value: set[str] | None) -> None:
        self._cur["caps"] = value


class _SeenIds:
    """A bounded set of history line ids (oldest forgotten first)."""

    def __init__(self, limit: int = 5000):
        self.limit = limit
        self._ids: dict[str, None] = {}

    def __contains__(self, item) -> bool:
        return item in self._ids

    def add(self, item: str) -> None:
        self._ids[item] = None
        while len(self._ids) > self.limit:
            del self._ids[next(iter(self._ids))]


class Channel:
    def __init__(self, name: str, private: bool, auth: bytes | None, psk: bytes | None,
                 hkey: bytes | None = None, epoch: int = 0):
        self.name = name
        self.private = private
        self.auth = auth
        self.psk = psk
        self.hkey = hkey        # private channels: key of the stored history (from the password)
        self.epoch = epoch      # bumped by the server whenever the password changes
        self.joined = True
        self.roles: dict[str, str] = {}     # nick.lower() -> owner | op | voice
        self.policy: dict = {}
        self.members: dict[str, Peer] = {}
        self.chain = Chain()
        self.recv: dict[str, Chain] = {}
        self.pending: list[tuple[str, bytes]] = []


class ChatClient:
    def __init__(self, host: str, port: int, identity: Identity, store: Store, on_event,
                 tls: bool = True, pin: str | None = None, reg_token: str | None = None,
                 p2p_port: int = 0, p2p_host: str | None = None, download_dir: str | None = None,
                 guest: bool = False):
        self.host, self.port = host, port
        self.identity = identity
        self.store = store
        self.on_event = on_event
        self.tls = tls
        self.pin = pin
        self.reg_token = reg_token
        self.guest = guest
        self.nick = crypto.guest_nick(identity.ik) if guest else identity.nick
        self.key = self.nick.lower()
        self.role = "user"
        self.away = False
        self.server_repo: str | None = None
        self.server_caps: set[str] = set()     # features announced by the server (empty: older server)
        self.server_limits: dict = {}
        self.away_text = ""
        self._away_told: set[str] = set()
        self.server_name = ""
        self.online = False
        self.channels: dict[str, Channel] = {}
        self.peers: dict[str, Peer] = {}
        self.local_ip = ""
        self.public_ip = ""
        self.relay = RelayFiles(self)
        self._history_seen: dict[str, _SeenIds] = {}   # per channel, survives reconnects
        self.files = FileTransfers(self, p2p_port, p2p_host,
                                   download_dir or os.path.expanduser("~/Downloads/crptochat"))
        self._dh = None
        self._writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, tuple[asyncio.Future, object]] = {}
        self._next_id = 0
        self._closing = False
        self._kicked = ""
        self._tasks: set[asyncio.Task] = set()
        self._audio_rx: dict[tuple, dict] = {}

    # ------------------------------------------------------------- helpers

    def emit(self, kind: str, **data) -> None:
        try:
            self.on_event(kind, data)
        except Exception:  # the UI must never be able to kill the engine
            pass

    def sys(self, text: str, level: str = "info", buffer: str | None = None) -> None:
        self.emit("system", text=text, level=level, buffer=buffer)

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            exc = task.exception()
            if isinstance(exc, (ChatError, CryptoError, ProtocolError, OSError)):
                self.sys(str(exc) or exc.__class__.__name__, "err")
            else:
                self.sys(f"erro interno: {exc!r}", "err")

    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(self.identity.ik)

    # ---------------------------------------------------------- connection

    async def run(self) -> None:
        delay = 1
        while not self._closing:
            self.emit("status", state="connecting")
            try:
                reader = await self._connect()
            except FatalError as exc:
                self.emit("fatal", code=exc.code, text=str(exc))
                return
            except ssl.SSLError as exc:
                self.sys(f"falha TLS: {exc.reason or exc} (se o servidor roda sem TLS, use --no-tls)", "err")
            except (OSError, asyncio.TimeoutError, ProtocolError, ChatError, asyncio.IncompleteReadError) as exc:
                self.sys(f"falha na conexão: {exc or exc.__class__.__name__}", "err")
            else:
                delay = 1
                self.online = True
                self.emit("status", state="online")
                self.spawn(self._rejoin())
                ping = asyncio.create_task(self._ping_loop())
                try:
                    await self._read_loop(reader)
                except (OSError, ProtocolError, asyncio.IncompleteReadError, ValueError):
                    pass
                finally:
                    ping.cancel()
                    self._on_disconnect()
                if self._kicked:
                    self.emit("fatal", code="kicked", text=f"sessão encerrada: {self._kicked}")
                    return
            if self._closing:
                return
            self.emit("status", state="offline", retry=delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

    async def _connect(self) -> asyncio.StreamReader:
        ctx = None
        if self.tls:
            # Self-signed certificates are expected; trust comes from pinning
            # the certificate fingerprint (TOFU), like SSH host keys.
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ctx, limit=MAX_LINE), 15)
        try:
            if self.tls:
                der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest()
                pinned = self.pin or self.store.server_pin()
                if pinned is None:
                    self.store.pin_server(fp)
                    self.sys(f"certificado do servidor fixado (TOFU): {fp}", "warn")
                elif pinned.lower().replace(":", "") != fp:
                    raise FatalError(
                        "o certificado TLS do servidor MUDOU (possível interceptação). "
                        f"Esperado {pinned}, recebido {fp}. Se a troca for legítima use --reset-pin.", "pin")
                elif self.store.server_pin() is None:
                    self.store.pin_server(fp)
            welcome = decode(await asyncio.wait_for(reader.readline(), 15))
            if welcome.get("t") == "err":
                if welcome.get("code") == "banned":       # reconnecting will not help
                    raise FatalError(str(welcome.get("msg") or "endereço banido")[:200], "banned")
                # e.g. too many connections from this address: transient, retry later
                raise ChatError(str(welcome.get("msg") or "o servidor recusou a conexão")[:200],
                                str(welcome.get("code") or "refused"))
            if welcome.get("t") != "welcome":
                raise ProtocolError("resposta inesperada do servidor")
            nonce = b64d(welcome.get("nonce"))
            self._dh = crypto.x_generate()
            dh = crypto.x_pub(self._dh)
            writer.write(encode({
                "t": "auth", "id": 0, "nick": self.nick, "ik": b64e(self.identity.ik), "dh": b64e(dh),
                "sig": b64e(crypto.sign(self.identity.key, crypto.auth_message(nonce, self.nick, dh))),
                "dh_sig": b64e(crypto.sign(self.identity.key, crypto.dh_message(self.nick, dh))),
                "reg_token": self.reg_token, "guest": self.guest, "ver": __version__,
            }))
            reply = decode(await asyncio.wait_for(reader.readline(), 15))
            if reply.get("t") == "err":
                raise FatalError(str(reply.get("msg")), str(reply.get("code")))
            if reply.get("t") != "ok":
                raise ProtocolError("resposta inesperada do servidor")
        except BaseException:
            writer.close()
            raise
        self.nick = reply.get("nick") or self.nick
        self.role = str(reply.get("role") or "user")
        if self.guest:
            self.sys(f"sessão anônima: você é {self.nick} só enquanto estiver conectado; nada foi registrado", "ok")
        if self.away:
            writer.write(encode({"t": "away", "on": True}))
        self.server_name = str(welcome.get("server") or self.host)[:40]
        self.public_ip = str(welcome.get("your_ip") or "")
        sockname = writer.get_extra_info("sockname")
        self.local_ip = sockname[0] if sockname else ""
        self._writer = writer
        for peer in self.peers.values():
            # our session key is new: every old root (and its chain keys) is gone for good
            peer._pair, peer._states, peer._burned = None, {}, set()
            peer._cur = {"dmr": False, "got_v2": False, "caps": None}
        if reply.get("registered"):
            self.sys(f"nickname '{self.nick}' registrado permanentemente neste servidor", "ok")
            self.sys("guarde bem sua senha: sem a chave local este nick nunca mais poderá ser usado", "warn")
        motd = str(welcome.get("motd") or "")[:500]
        caps = welcome.get("caps")
        self.server_caps = {c for c in caps if isinstance(c, str)} if isinstance(caps, list) else set()
        limits = welcome.get("limits")
        self.server_limits = limits if isinstance(limits, dict) else {}
        repo = welcome.get("client_repo")
        self.server_repo = repo if isinstance(repo, str) and len(repo) < 120 else None
        self.emit("welcome", server=self.server_name, motd=motd)
        return reader

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                self._send({"t": "ping"})
            except ChatError:
                return

    def _on_disconnect(self) -> None:
        self.online = False
        for tr in list(self.relay.transfers.values()):
            if tr.state in ("offered", "active"):
                self.relay._fail(tr, "conexão com o servidor perdida", tell_server=False)
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        self._writer = None
        for fut, _ in self._pending.values():
            if not fut.done():
                fut.set_exception(ChatError("conexão perdida", "offline"))
        self._pending.clear()
        for ch in self.channels.values():
            ch.joined = False
            ch.members.clear()
            ch.recv.clear()
            ch.pending.clear()
            self.emit("members", chan=ch.name)
        for peer in self.peers.values():
            peer.dh = None

    async def _rejoin(self) -> None:
        for ch in list(self.channels.values()):
            try:
                await self.join(ch.name, _keys=(ch.auth, ch.psk, ch.hkey))
            except ChatError as exc:
                self.sys(f"não foi possível voltar para {ch.name}: {exc}", "err")

    async def close(self) -> None:
        self._closing = True
        await self.files.close()
        for task in list(self._tasks):
            task.cancel()
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass

    # -------------------------------------------------------------- wire

    def _send(self, obj: dict) -> None:
        if not self._writer:
            raise ChatError("você está offline", "offline")
        self._writer.write(encode(obj))

    async def request(self, obj: dict, hook=None, timeout: float = 15) -> dict:
        self._next_id += 1
        rid = self._next_id
        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = (fut, hook)
        try:
            self._send({**obj, "id": rid})
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise ChatError("o servidor não respondeu", "timeout") from None
        finally:
            self._pending.pop(rid, None)

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        handlers = {
            "ok": self._on_reply, "err": self._on_reply, "msg": self._on_msg, "direct": self._on_direct,
            "member_join": self._on_member_join, "member_leave": self._on_member_leave,
            "chan_role": self._on_chan_role, "kicked_from": self._on_kicked_from, "policy": self._on_policy,
            "file_go": lambda m: self.relay.on_go(m), "file_chunk": lambda m: self.relay.on_chunk(m),
            "file_ack": lambda m: self.relay.on_ack(m), "file_cancel": lambda m: self.relay.on_cancel(m),
            "away": self._on_away, "notice": self._on_notice, "ratelimit": self._on_ratelimit, "client_repo": self._on_client_repo, "invited": self._on_invited, "role": self._on_role,
        }
        while True:
            line = await reader.readline()
            if not line:
                return
            msg = decode(line)
            if msg["t"] in ("kicked", "banned"):
                self._kicked = str(msg.get("msg") or "sessão encerrada pelo servidor")[:300]
                return
            handler = handlers.get(msg["t"])
            if handler is None:
                continue
            try:
                handler(msg)
            except (ProtocolError, CryptoError, KeyError, TypeError, ValueError, AttributeError):
                # A hostile server or peer must not be able to crash us.
                continue

    def _on_reply(self, msg: dict) -> None:
        entry = self._pending.get(msg.get("id"))
        if entry is None:
            # Refusals of fire-and-forget frames (a message in a moderated
            # channel, slow mode...). "offline" is just a key sent to someone
            # who left meanwhile.
            if msg["t"] == "err" and msg.get("code") not in ("offline", None):
                self.sys(f"não entregue: {str(msg.get('msg'))[:200]}", "warn")
            return
        fut, hook = entry
        if fut.done():
            return
        if msg["t"] == "err":
            fut.set_exception(ChatError(str(msg.get("msg")), str(msg.get("code"))))
            return
        if hook:
            try:
                hook(msg)
            except (ProtocolError, CryptoError, KeyError, TypeError, ValueError) as exc:
                fut.set_exception(ChatError(f"resposta inválida do servidor: {exc}"))
                return
        fut.set_result(msg)

    # --------------------------------------------------------------- peers

    def _learn(self, user: dict) -> Peer:
        """Validate a user record handed out by the (untrusted) server."""
        nick = user["nick"]
        if not valid_nick(nick) or nick.lower() == self.key:
            raise ProtocolError("bad user record")
        ik = b64d(user["ik"], 32)
        peer = self.peers.get(nick.lower())
        if peer is None:
            peer = self.peers[nick.lower()] = Peer(nick, ik)
        peer.guest = is_guest_nick(nick)
        peer.role = user.get("role") if user.get("role") in ("mod", "admin") else "user"
        if "dh" in user:
            peer.away = bool(user.get("away"))
        if peer.guest:
            # Anonymous nicks are derived from the key itself, so there is
            # nothing to pin: the name is only valid for that exact key.
            if nick != crypto.guest_nick(ik):
                raise ProtocolError("forged guest nick")
            status = "ok"
        else:
            status = self.store.check_user(nick, ik)
        if status == "mismatch":
            # Keep the pinned key; nothing is encrypted to, or accepted from,
            # the new one until the user checks it and runs /verify.
            peer.ik = self.store.pinned(nick) or peer.ik
            peer.pending_ik = ik
            peer.trusted, peer.dh, peer._pair = False, None, None
            if not peer.warned:
                peer.warned = True
                self.emit("key_changed", nick=nick, old=peer.ik, new=ik)
            return peer
        peer.ik, peer.trusted, peer.pending_ik = ik, True, None
        if user.get("dh") is not None:
            dh = b64d(user["dh"], 32)
            if not crypto.verify(ik, b64d(user.get("dh_sig"), 64), crypto.dh_message(nick, dh)):
                peer.trusted, peer.dh, peer._pair = False, None, None
                self.sys(f"ALERTA: chave de sessão de {nick} com assinatura inválida; usuário ignorado", "err")
                return peer
            if dh != peer.dh:
                # their session changed: v2 support is re-learned for it (they may
                # be on an older client now), unless this exact root was seen before
                peer.dh, peer._pair = dh, None
                if self._dh is not None:
                    try:
                        self._pair_key(peer)
                    except CryptoError:
                        pass
        return peer

    async def resolve(self, nick: str) -> Peer:
        if not valid_nick(nick):
            raise ChatError("nickname inválido")
        if nick.lower() == self.key:
            raise ChatError("esse é você")
        reply = await self.request({"t": "whois", "nick": nick})
        try:
            peer = self._learn(reply["user"])
        except (ProtocolError, KeyError, TypeError) as exc:
            raise ChatError("registro de usuário inválido") from exc
        if not reply.get("online"):
            peer.dh = None
        return peer

    def _usable(self, peer: Peer) -> Peer:
        if not peer.trusted:
            raise ChatError(f"a chave de {peer.nick} mudou e ainda não foi aceita: mensagens bloqueadas. "
                            f"Confira por outro meio e use /verify {peer.nick}", "untrusted")
        if not peer.dh:
            raise ChatError(f"{peer.nick} está offline", "offline")
        return peer

    MAX_ROOTS = 32

    def _pair_key(self, peer: Peer) -> bytes:
        if peer._pair is None or peer._pair[0] != peer.dh:
            root = crypto.pair_key(self._dh, peer.dh, self.identity.ik, peer.ik)
            peer._pair = (peer.dh, root)
            state = peer._states.get(root)
            if state is None:
                if hashlib.sha256(root).digest() in peer._burned:
                    raise CryptoError("chave de sessão reaproveitada: recusada")
                send, recv = crypto.dm_chains(root, self.identity.ik, peer.ik)
                # a new pair of sessions: nothing is known about their client yet
                state = {"dmr": False, "got_v2": False, "caps": None, "send": send, "recv": recv}
                peer._states[root] = state
                while len(peer._states) > self.MAX_ROOTS:
                    old = next(iter(peer._states))
                    del peer._states[old]
                    peer._burned.add(hashlib.sha256(old).digest())
            peer._cur = state
        return peer._pair[1]

    def _chains(self, peer: Peer) -> tuple:
        """(root, sending chain, receiving chain) of the current pair of sessions."""
        root = self._pair_key(peer)
        return root, peer._cur["send"], peer._cur["recv"]

    def _direct_frame(self, peer: Peer, inner: dict) -> dict:
        self._pair_key(peer)          # selects the state of the current pair of sessions
        if peer.dmr:
            _, send, _ = self._chains(peer)
            body = crypto.dm_encrypt(send, self.key, peer.key, json.dumps(inner).encode())
        else:
            # Older peer, or not known yet: v1 envelope, advertising that we
            # speak v2 (older clients ignore the extra field).
            inner = {**inner, "cv": CLIENT_CAPS}
            aad = b"crptochat-direct-v1|" + self.key.encode() + b"|" + peer.key.encode()
            body = crypto.seal(self._pair_key(peer), crypto.pad(json.dumps(inner).encode()), aad)
        return {"t": "direct", "to": peer.nick, "body": b64e(body)}

    def send_direct(self, peer: Peer, inner: dict) -> None:
        self._send(self._direct_frame(self._usable(peer), inner))

    # ------------------------------------------------------------ channels

    async def list_channels(self) -> list[dict]:
        return (await self.request({"t": "list"}))["channels"]

    async def create(self, chan: str, passphrase: str | None = None) -> None:
        if not valid_chan(chan):
            raise ChatError("nome de canal inválido: use #nome (minúsculas, números, _ e -)")
        keys = None
        req = {"t": "create", "chan": chan, "private": passphrase is not None}
        if passphrase is not None:
            salt = os.urandom(16)
            keys = await asyncio.to_thread(crypto.channel_secrets, passphrase, salt)
            req.update(salt=b64e(salt), verifier=b64e(crypto.auth_verifier(keys[0])))
        await self.request(req)
        await self.join(chan, _keys=keys)

    async def join(self, chan: str, passphrase: str | None = None, _keys=None) -> None:
        if not valid_chan(chan):
            raise ChatError("nome de canal inválido: use #nome (minúsculas, números, _ e -)")
        existing = self.channels.get(chan)
        if existing and existing.joined:
            raise ChatError(f"você já está em {chan}")
        info = await self.request({"t": "chaninfo", "chan": chan})
        auth = psk = hkey = None
        if info.get("private"):
            if _keys and _keys[0]:
                auth, psk, hkey = (tuple(_keys) + (None,))[:3]
            elif passphrase is None:
                raise NeedPassphrase(chan)
            else:
                auth, psk, hkey = await asyncio.to_thread(crypto.channel_secrets, passphrase,
                                                          b64d(info.get("salt"), 16))

        def hook(reply: dict) -> None:
            # Runs inside the read loop, so the channel exists before any
            # sender key addressed to us is processed.
            epoch = reply.get("epoch")
            ch = Channel(chan, bool(info.get("private")), auth, psk, hkey,
                         epoch if isinstance(epoch, int) and not isinstance(epoch, bool) else 0)
            ch.policy = dict(reply.get("policy") or {})
            ch.roles = {str(n).lower(): str(r) for n, r in dict(reply.get("roles") or {}).items()}
            for user in reply["members"]:
                try:
                    peer = self._learn(user)
                except (ProtocolError, KeyError, TypeError):
                    continue
                ch.members[peer.key] = peer
            self.channels[chan] = ch
            for peer in ch.members.values():
                self._send_chain(ch, peer)
            self.emit("joined", chan=chan, private=ch.private)
            self.emit("members", chan=chan)
            history = reply.get("history")
            if isinstance(history, list) and history and ch.hkey:
                self.spawn(self._load_history(ch, history[:1000]))

        await self.request({"t": "join", "chan": chan, "auth": b64e(auth) if auth else None}, hook=hook)

    async def leave(self, chan: str) -> None:
        ch = self.channels.get(chan)
        if not ch:
            raise ChatError("você não está neste canal")
        if ch.joined and self.online:
            try:
                await self.request({"t": "leave", "chan": chan})
            except ChatError:
                pass
        self.channels.pop(chan, None)
        self.emit("left", chan=chan)

    def _wrap_key(self, ch: Channel) -> bytes:
        return crypto.hkdf(ch.psk, b"crptochat-sk-wrap-v1|" + ch.name.encode())

    def _send_chain(self, ch: Channel, peer: Peer) -> None:
        if not peer.trusted or not peer.dh:
            return
        ck = ch.chain.ck
        if ch.private:
            ck = crypto.seal(self._wrap_key(ch), ck, self.key.encode())
        try:
            self.send_direct(peer, {"k": "sk", "chan": ch.name, "ck": b64e(ck), "n": ch.chain.n})
        except (ChatError, CryptoError):
            pass

    def _on_member_join(self, msg: dict) -> None:
        ch = self.channels.get(msg["chan"])
        if not ch or not ch.joined:
            return
        peer = self._learn(msg["user"])
        ch.members[peer.key] = peer
        ch.roles.pop(peer.key, None)
        if msg.get("role"):
            ch.roles[peer.key] = str(msg["role"])
        ch.recv.pop(peer.key, None)
        self._send_chain(ch, peer)
        self.emit("member_join", chan=ch.name, nick=peer.nick, trusted=peer.trusted)
        self.emit("members", chan=ch.name)

    def _on_member_leave(self, msg: dict) -> None:
        ch = self.channels.get(msg["chan"])
        if not ch or not ch.joined:
            return
        peer = ch.members.pop(str(msg["nick"]).lower(), None)
        if not peer:
            return
        ch.recv.pop(peer.key, None)
        # Whoever left still knows our old chain: start a new one.
        ch.chain = Chain()
        for other in ch.members.values():
            self._send_chain(ch, other)
        self.emit("member_leave", chan=ch.name, nick=peer.nick, kicked=msg.get("kicked"))
        self.emit("members", chan=ch.name)

    def send_message(self, chan: str, text: str) -> None:
        ch = self.channels.get(chan)
        if not ch or not ch.joined:
            raise ChatError("você não está conectado a este canal")
        if ch.policy.get("moderated") and self.power(chan) < 1:
            raise ChatError(f"{chan} está moderado: só quem tem voz (+), operadores (@) e o dono (~) podem falar",
                            "moderated")
        text = text[:MAX_TEXT]
        ttl = self.ttl_for(chan)
        payload = {"x": text, "ttl": ttl} if ttl else {"x": text}
        copy, line_id = self._history_copy(ch, text)
        if line_id:
            payload["hid"] = line_id          # lets members skip this line when the history comes later
        body = crypto.channel_encrypt(ch.chain, self.identity.key, chan, self.nick,
                                      json.dumps(payload).encode())
        encoded = b64e(body)
        if len(encoded) > self.max_body():
            raise ChatError("mensagem grande demais para este servidor", "too_big")
        frame = {"t": "msg", "chan": chan, "body": encoded}
        if copy:
            frame["h"] = copy
            self._seen_history(chan).add(line_id)
        self._send(frame)
        self.emit("message", buffer=chan, nick=self.nick, text=text, mine=True, ttl=ttl)
        if line_id and not copy:
            self.emit("system", text="esta mensagem não entrou no histórico do canal: passou do tamanho máximo "
                                     f"guardado ({self.history_body() // 1024} KiB); quem entrar depois não a verá",
                      level="warn", buffer=chan)

    def _on_msg(self, msg: dict) -> None:
        ch = self.channels.get(msg["chan"])
        sender = str(msg["from"]).lower()
        if not ch or sender not in ch.members:
            return
        body = b64d(msg["body"])
        if sender not in ch.recv:
            # The sender key may still be on its way.
            if len(ch.pending) < MAX_PENDING:
                ch.pending.append((sender, body))
            return
        self._deliver(ch, ch.members[sender], body)

    def _deliver(self, ch: Channel, peer: Peer, body: bytes) -> None:
        try:
            plain = crypto.channel_decrypt(ch.recv[peer.key], peer.ik, ch.name, peer.nick, body)
            payload = json.loads(plain)
            if "a" in payload:
                self._on_audio_chunk(ch.name, peer, payload["a"])
                return
            text = str(payload["x"])[:MAX_TEXT]
            ttl = self._effective_ttl(payload.get("ttl"), ch.policy.get("ttl"))
        except (CryptoError, ProtocolError, ValueError, KeyError, TypeError):
            return
        if isinstance(payload.get("hid"), str):
            self._seen_history(ch.name).add(payload["hid"][:64])      # already seen live
        self.emit("message", buffer=ch.name, nick=peer.nick, text=text, mine=False, ttl=ttl)

    # -------------------------------------------------- direct envelopes

    def _on_direct(self, msg: dict) -> None:
        sender = msg["from"]
        if not valid_nick(sender):
            return
        body = b64d(msg["body"])
        peer = self.peers.get(sender.lower())
        if peer and peer.trusted and peer.dh:
            try:
                self._open_direct(peer, body)
                return
            except CryptoError:
                pass  # maybe they reconnected with a new session key
        self.spawn(self._direct_slow(sender, body))

    async def _direct_slow(self, sender: str, body: bytes) -> None:
        try:
            peer = await self.resolve(sender)
            if not peer.trusted and peer.pending_ik and not peer.dropped:
                peer.dropped = True
                self.sys(f"mensagens de {peer.nick} estão sendo recusadas: a chave dele mudou e você ainda "
                         f"não aceitou (/verify {peer.nick})", "err", "@" + peer.nick)
            if peer.trusted and peer.dh:
                self._open_direct(peer, body)
        except (ChatError, CryptoError, ProtocolError, KeyError, TypeError, ValueError):
            pass

    def _open_direct(self, peer: Peer, body: bytes) -> None:
        plain = None
        root = self._pair_key(peer)
        if body[:1] == bytes([crypto.DM_V2]):
            try:
                _, _, recv = self._chains(peer)
                plain = crypto.dm_decrypt(recv, peer.key, self.key, body)
                peer._cur["dmr"] = peer._cur["got_v2"] = True
            except CryptoError:
                plain = None    # a v1 nonce can start with the same byte: try v1 below
        if plain is None:
            if peer.got_v2:
                # Once they spoke v2 in these sessions, v1 from them is refused:
                # v1 has no replay protection, so it could only be a replay.
                raise CryptoError("envelope v1 depois de v2: recusado")
            aad = b"crptochat-direct-v1|" + peer.key.encode() + b"|" + self.key.encode()
            plain = crypto.unpad(crypto.unseal(root, body, aad))
        try:
            inner = json.loads(plain)
            kind = inner["k"]
        except (ValueError, KeyError, TypeError):
            return
        if isinstance(inner.get("cv"), list):
            peer.caps = {c for c in inner["cv"] if isinstance(c, str)}
            if "dmr" in peer.caps:
                peer.dmr = True     # from now on we answer with ratcheted envelopes
        if kind == "hi":
            # capability probe: answer once, saying what we speak
            if peer.hello is not None:
                peer.hello.set()
            if not inner.get("r"):
                try:
                    self.send_direct(peer, {"k": "hi", "r": 1, "cv": CLIENT_CAPS})
                except (ChatError, CryptoError):
                    pass
            return
        if kind == "sk":
            self._on_sender_key(peer, inner)
        elif kind == "skr":
            # "please send me your channel key again" (after accepting a new key)
            ch = self.channels.get(inner.get("chan"))
            if ch and peer.key in ch.members:
                self._send_chain(ch, peer)
        elif kind == "dm" and "a" in inner:
            try:
                self._on_audio_chunk("@" + peer.nick, peer, inner["a"])
            except (ProtocolError, ValueError, KeyError, TypeError):
                pass
        elif kind == "dm":
            if self.away and not inner.get("auto") and peer.key not in self._away_told:
                # Like IRC's away, but the text goes end to end and each
                # person is told only once.
                self._away_told.add(peer.key)
                note = "[ausente] " + (self.away_text or "não estou no teclado agora")
                try:
                    self.send_direct(peer, {"k": "dm", "x": note, "auto": True})
                except (ChatError, CryptoError):
                    pass
            ttl = self._effective_ttl(inner.get("ttl"), self.dm_ttl(peer.nick))
            self.emit("message", buffer="@" + peer.nick, nick=peer.nick, text=str(inner.get("x"))[:MAX_TEXT],
                      mine=False, ttl=ttl)
        elif kind == "ttl":
            # disappearing messages for this conversation, agreed end to end
            seconds = inner.get("s")
            if isinstance(seconds, int) and not isinstance(seconds, bool) and 0 <= seconds <= MAX_TTL:
                self.store.set_dm_ttl(peer.nick, seconds)
                self.emit("dm_ttl", nick=peer.nick, seconds=seconds, by=peer.nick)
        elif kind in ("fo2", "fx2"):
            self.relay.handle(peer, inner)
        elif kind in ("fo", "fr", "fx"):
            self.files.handle(peer, inner)

    def _on_sender_key(self, peer: Peer, inner: dict) -> None:
        ch = self.channels.get(inner.get("chan"))
        if not ch or peer.key not in ch.members:
            return
        try:
            ck = b64d(inner["ck"])
            if ch.private:
                ck = crypto.unseal(self._wrap_key(ch), ck, peer.key.encode())
            n = int(inner["n"])
            if len(ck) != 32 or n < 0:
                return
        except (ProtocolError, CryptoError, KeyError, TypeError, ValueError):
            if ch.private:
                self.sys(f"{peer.nick} enviou uma chave que não abre com a senha de {ch.name} "
                         "(senha diferente ou servidor malicioso); mensagens dele ficarão ilegíveis",
                         "warn", ch.name)
            return
        ch.recv[peer.key] = Chain(ck, n)
        waiting = [body for sender, body in ch.pending if sender == peer.key]
        ch.pending = [item for item in ch.pending if item[0] != peer.key]
        for body in waiting:
            self._deliver(ch, peer, body)

    async def send_dm(self, nick: str, text: str) -> str:
        peer = self._usable(await self.resolve(nick))
        text = text[:MAX_TEXT]
        ttl = self.dm_ttl(peer.nick)
        inner = {"k": "dm", "x": text, "ttl": ttl} if ttl else {"k": "dm", "x": text}
        await self.request(self._direct_frame(peer, inner))
        self.emit("message", buffer="@" + peer.nick, nick=self.nick, text=text, mine=True, ttl=ttl)
        return peer.nick

    # --------------------------------------------------------- voice messages

    async def send_audio(self, target: str, data: bytes, seconds: float) -> None:
        """Send a voice clip to a channel ("#name") or a user ("@nick").

        The clip travels through the relay like any message: split into
        end-to-end encrypted envelopes, never stored anywhere on the way.
        """
        if not 0 < len(data) <= MAX_AUDIO:
            raise ChatError("áudio vazio ou grande demais")
        clip = os.urandom(8).hex()
        # Pad to a multiple of AUDIO_BUCKET full-size envelopes: the relay sees
        # that something bulky went by, but not how long the recording is.
        blob = len(data).to_bytes(4, "big") + data
        blob += os.urandom(-len(blob) % (AUDIO_CHUNK * AUDIO_BUCKET))
        chunks = [blob[i:i + AUDIO_CHUNK] for i in range(0, len(blob), AUDIO_CHUNK)]
        peer = ch = None
        if target.startswith("@"):
            peer = self._usable(await self.resolve(target[1:]))
            target = "@" + peer.nick
        else:
            ch = self.channels.get(target)
            if not ch or not ch.joined:
                raise ChatError("você não está conectado a este canal")
        ttl = self.ttl_for(target)
        for index, chunk in enumerate(chunks):
            part = {"id": clip, "i": index, "n": len(chunks), "s": round(seconds, 1), "d": b64e(chunk)}
            if ttl:
                part["ttl"] = ttl
            if peer:
                frame = self._direct_frame(peer, {"k": "dm", "a": part})
                if index == len(chunks) - 1:
                    await self.request(frame)   # confirms the peer was still online
                else:
                    self._send(frame)
            else:
                body = crypto.channel_encrypt(ch.chain, self.identity.key, ch.name, self.nick,
                                              json.dumps({"a": part}).encode())
                self._send({"t": "msg", "chan": ch.name, "body": b64e(body)})
            if index % 8 == 7:
                await asyncio.sleep(0.25)       # stay under the relay's rate limit
        self.emit("audio", buffer=target, nick=self.nick, data=data, seconds=seconds, mine=True, ttl=ttl)

    def _on_audio_chunk(self, buffer: str, peer: Peer, part: dict) -> None:
        clip, index, total = str(part["id"])[:32], int(part["i"]), int(part["n"])
        chunk = b64d(part["d"])
        if not 0 < total <= MAX_AUDIO // AUDIO_CHUNK + AUDIO_BUCKET or len(chunk) > AUDIO_CHUNK:
            return
        key = (buffer, peer.key, clip)
        state = self._audio_rx.get(key)
        if state is None:
            if index != 0:
                return
            mine = [k for k in self._audio_rx if k[1] == peer.key]
            for stale in mine[:max(0, len(mine) - MAX_AUDIO_PARTIAL + 1)]:
                del self._audio_rx[stale]
            state = self._audio_rx[key] = {"parts": [], "total": total}
        if index != len(state["parts"]) or total != state["total"]:
            del self._audio_rx[key]             # out of order or inconsistent: drop the clip
            return
        state["parts"].append(chunk)
        if len(state["parts"]) == total:
            del self._audio_rx[key]
            seconds = max(0.0, min(float(part.get("s") or 0), 600.0))
            blob = b"".join(state["parts"])
            size = int.from_bytes(blob[:4], "big")
            if not 0 < size <= len(blob) - 4:
                return
            ch = self.channels.get(buffer)
            local = ch.policy.get("ttl") if ch else self.dm_ttl(peer.nick)
            self.emit("audio", buffer=buffer, nick=peer.nick, data=blob[4:4 + size],
                      seconds=seconds, mine=False, ttl=self._effective_ttl(part.get("ttl"), local))

    # ------------------------------------------------- roles and moderation

    RANK = {"voice": 1, "op": 2, "owner": 3}

    def power(self, chan: str, key: str | None = None) -> int:
        """3 owner, 2 op, 1 voice, 0 nothing (server staff outranks channel roles)."""
        ch = self.channels.get(chan)
        if key is None or key == self.key:
            role, key = self.role, self.key
        else:
            peer = self.peers.get(key)
            role = peer.role if peer else "user"
        own = self.RANK.get(ch.roles.get(key), 0) if ch else 0
        return 3 if role == "admin" else max(own, 2 if role == "mod" else 0)

    def _on_chan_role(self, msg: dict) -> None:
        ch = self.channels.get(msg["chan"])
        if not ch:
            return
        nick, role = str(msg["nick"]), msg.get("role")
        if role in self.RANK:
            ch.roles[nick.lower()] = role
        else:
            ch.roles.pop(nick.lower(), None)
        self.emit("chan_role", chan=ch.name, nick=nick, role=role, by=str(msg.get("by") or ""))
        self.emit("members", chan=ch.name)

    def _on_kicked_from(self, msg: dict) -> None:
        ch = self.channels.pop(msg["chan"], None)
        if ch:
            self.emit("kicked_from", chan=ch.name, by=str(msg.get("by") or ""), banned=bool(msg.get("banned")),
                      reason=str(msg.get("msg") or "")[:200])

    def _on_policy(self, msg: dict) -> None:
        ch = self.channels.get(msg["chan"])
        if ch:
            old, ch.policy = ch.policy, dict(msg["policy"])
            changed = {k: v for k, v in ch.policy.items() if old.get(k) != v}
            self.emit("policy", chan=ch.name, policy=ch.policy, changed=changed, by=str(msg.get("by") or ""))

    def _on_away(self, msg: dict) -> None:
        peer = self.peers.get(str(msg["nick"]).lower())
        if peer:
            peer.away = bool(msg.get("away"))
            for ch in self.channels.values():
                if peer.key in ch.members:
                    self.emit("members", chan=ch.name)

    def _on_ratelimit(self, msg: dict) -> None:
        action = msg.get("action") if msg.get("action") in ("warn", "mute") else "warn"
        seconds = msg.get("seconds") if isinstance(msg.get("seconds"), int) else 0
        self.emit("ratelimit", action=action, seconds=seconds, text=str(msg.get("msg") or "")[:200])

    def max_body(self) -> int:
        """Largest envelope the server accepts (older servers: the protocol cap)."""
        value = self.server_limits.get("max_body")
        return value if isinstance(value, int) and 0 < value <= MAX_BODY else MAX_BODY

    def _on_client_repo(self, msg: dict) -> None:
        repo = msg.get("repo")
        self.server_repo = repo if isinstance(repo, str) and len(repo) < 120 else None
        self.emit("client_repo", repo=self.server_repo)

    def _on_notice(self, msg: dict) -> None:
        self.emit("notice", text=str(msg.get("text"))[:500])

    def _on_invited(self, msg: dict) -> None:
        self.emit("invited", chan=str(msg["chan"]), by=str(msg.get("by") or ""))

    def _on_role(self, msg: dict) -> None:
        self.role = str(msg.get("role") or "user")
        self.emit("role", role=self.role)

    async def set_role(self, chan: str, nick: str, role: str | None) -> dict:
        return await self.request({"t": "chan_role", "chan": chan, "nick": nick, "role": role})

    async def kick(self, chan: str, nick: str) -> dict:
        return await self.request({"t": "kick", "chan": chan, "nick": nick})

    async def chan_ban(self, chan: str, nick: str, on: bool = True) -> dict:
        return await self.request({"t": "chan_ban", "chan": chan, "nick": nick, "on": on})

    async def chan_bans(self, chan: str) -> list[str]:
        return (await self.request({"t": "chan_bans", "chan": chan}))["bans"]

    async def chan_roles(self, chan: str) -> list[list[str]]:
        return (await self.request({"t": "chan_roles", "chan": chan}))["roles"]

    async def set_policy(self, chan: str, **changes) -> dict:
        return (await self.request({"t": "policy", "chan": chan, "set": changes}))["policy"]

    async def invite(self, chan: str, nick: str) -> dict:
        return await self.request({"t": "invite", "chan": chan, "nick": nick})

    async def server_kick(self, nick: str) -> dict:
        return await self.request({"t": "gkick", "nick": nick})

    async def server_ban(self, nick: str, minutes: int = 0, reason: str = "", ip: bool = False) -> dict:
        return await self.request({"t": "gban", "nick": nick, "minutes": minutes, "reason": reason, "ip": ip})

    async def server_unban(self, nick: str) -> dict:
        return await self.request({"t": "gunban", "nick": nick})

    # ---------------------------------------------------- away and presence

    async def set_away(self, text: str | None) -> None:
        """``text`` None means back. The text never reaches the server: it is
        sent end to end to whoever writes to us while we are away."""
        self.away = text is not None
        self.away_text = (text or "")[:300]
        self._away_told.clear()
        if self.online:
            await self.request({"t": "away", "on": self.away})

    async def presence(self, nicks: list[str]) -> dict[str, str]:
        """{nick_lower: 'on' | 'away'} for the nicks that are online."""
        if not nicks:
            return {}
        reply = await self.request({"t": "presence", "nicks": nicks[:200]})
        return {str(n).lower(): str(v) for n, v in dict(reply.get("online") or {}).items()}

    # ------------------------------------------------------- identity keys

    async def accept_key(self, nick: str, expected: bytes, verified: bool = False) -> Peer:
        """Adopt a changed identity key after the user confirmed it out of band.

        ``expected`` is the key whose fingerprint the user was shown. If the
        pending key changed meanwhile (the server presented yet another one),
        nothing is accepted: the user has to look at the new one first."""
        peer = self.peers.get(nick.lower())
        if not peer or not peer.pending_ik:
            raise ChatError(f"a chave de {nick} não mudou")
        if not hmac.compare_digest(peer.pending_ik, expected):
            raise ChatError(f"a chave pendente de {peer.nick} mudou de novo desde que foi mostrada; nada foi "
                            f"aceito. Confira a nova com /verify {peer.nick}", "pending_changed")
        self.store.accept_key(peer.nick, expected, verified)
        peer.ik, peer.pending_ik, peer.warned, peer.dropped = expected, None, False, False
        peer = await self.resolve(peer.nick)        # fresh, signed session key under the new identity
        for ch in self.channels.values():
            if ch.joined and peer.key in ch.members:
                ch.recv.pop(peer.key, None)
                self._send_chain(ch, peer)
                try:   # their key was dropped while they were untrusted: ask again
                    self.send_direct(peer, {"k": "skr", "chan": ch.name})
                except (ChatError, CryptoError):
                    pass
        return peer

    # -------------------------------------------------- disappearing messages

    @staticmethod
    def _effective_ttl(*values) -> int:
        """The shortest timer that applies (the sender's and our own view)."""
        valid = [v for v in values if isinstance(v, int) and not isinstance(v, bool) and 0 < v <= MAX_TTL]
        return min(valid) if valid else 0

    def dm_ttl(self, nick: str) -> int:
        return self.store.dm_ttl(nick)

    def ttl_for(self, buffer: str) -> int:
        if buffer.startswith("#"):
            ch = self.channels.get(buffer)
            return self._effective_ttl(ch.policy.get("ttl") if ch else 0)
        if buffer.startswith("@"):
            return self.dm_ttl(buffer[1:])
        return 0

    async def set_channel_ttl(self, chan: str, seconds: int) -> dict:
        if self.server_caps and "ttl" not in self.server_caps:
            raise ChatError("este servidor ainda não suporta mensagens temporárias em canais")
        return await self.set_policy(chan, ttl=seconds)

    async def set_dm_ttl(self, nick: str, seconds: int) -> str:
        """Agree on a timer with the other person (end to end; the server never knows)."""
        peer = self._usable(await self.resolve(nick))
        await self.request(self._direct_frame(peer, {"k": "ttl", "s": seconds}))
        self.store.set_dm_ttl(peer.nick, seconds)
        self.emit("dm_ttl", nick=peer.nick, seconds=seconds, by=self.nick)
        return peer.nick

    # ----------------------------------------------------------- capabilities

    async def peer_supports(self, peer: Peer, cap: str, timeout: float = 4.0) -> bool:
        """Ask a peer's client what it speaks, once per session (1.0.0 never answers)."""
        if peer.caps is None:
            peer.hello = asyncio.Event()
            try:
                self.send_direct(peer, {"k": "hi", "cv": CLIENT_CAPS})
                await asyncio.wait_for(peer.hello.wait(), timeout)
            except (asyncio.TimeoutError, ChatError, CryptoError):
                peer.caps = set()
            finally:
                peer.hello = None
        return cap in (peer.caps or set())

    # ------------------------------------------- history of private channels

    def history_on(self, ch: Channel) -> bool:
        return bool(ch.private and ch.hkey and ch.policy.get("history") and "history" in self.server_caps)

    def history_body(self) -> int:
        value = self.server_limits.get("history_body")
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 12 * 1024

    def _seen_history(self, chan: str) -> dict:
        """Ids of history lines already shown (live or from an earlier join),
        kept across reconnections so the same block is not shown twice."""
        return self._history_seen.setdefault(chan, _SeenIds())

    def _history_copy(self, ch: Channel, text: str) -> tuple[str | None, str | None]:
        """A copy for the channel's stored history: encrypted with the key that
        comes from the channel password, signed by our identity. Returns (copy, id);
        copy is None (with an id) when it is too big for the server to keep."""
        if not self.history_on(ch):
            return None, None
        ts = int(time.time())
        line_id = b64e(os.urandom(12))
        sig = crypto.sign(self.identity.key, crypto.history_signed(ch.name, ch.epoch, self.nick, ts, text, line_id))
        entry = {"n": self.nick, "ik": b64e(self.identity.ik), "ts": ts, "id": line_id, "x": text, "s": b64e(sig)}
        copy = b64e(crypto.history_seal(ch.hkey, ch.name, ch.epoch, json.dumps(entry).encode()))
        return (copy if len(copy) <= self.history_body() else None), line_id

    def _open_history(self, ch: Channel, item: dict) -> dict | None:
        try:
            epoch = int(item["epoch"])
            entry = json.loads(crypto.history_open(ch.hkey, ch.name, epoch, b64d(item["h"])))
            nick, ts, text = str(entry["n"]), int(entry["ts"]), str(entry["x"])[:MAX_TEXT]
            ik = b64d(entry["ik"], 32)
            line_id = str(entry["id"])
            if not valid_nick(nick) or not 8 <= len(line_id) <= 64:
                return None
            # whoever uploaded the copy (the server records it) must be its author:
            # a member cannot post someone else's signed line as if it were new
            if str(item.get("from") or "").lower() != nick.lower():
                return None
            # a line re-encrypted by the owner after a password change keeps the epoch it
            # was signed in; only rows the server marks as re-encrypted may do that
            signed_epoch = int(entry.get("e", epoch))
            if signed_epoch != epoch and not (item.get("re") is True and signed_epoch < epoch):
                return None
            if not crypto.verify(ik, b64d(entry["s"], 64),
                                 crypto.history_signed(ch.name, signed_epoch, nick, ts, text, line_id)):
                return None
        except (CryptoError, ProtocolError, KeyError, TypeError, ValueError):
            return None
        expires = item.get("expires")
        return {"nick": nick, "ik": ik, "ts": ts, "text": text, "id": line_id,
                "expires": expires if isinstance(expires, int) else 0}

    async def _load_history(self, ch: Channel, items: list) -> None:
        """Decrypt the stored history and check who really wrote each line: the
        signature must match the key we pinned for that nick (or the one the
        server's registry gives for it, which is then pinned like any first contact)."""
        out = []
        seen = self._seen_history(ch.name)
        for item in items:
            entry = self._open_history(ch, item) if isinstance(item, dict) else None
            if entry is None or entry["id"] in seen:
                continue                       # invalid, a duplicate, or already shown
            seen.add(entry["id"])
            nick, ik = entry["nick"], entry["ik"]
            if nick.lower() == self.key:
                trusted = ik == self.identity.ik
            elif is_guest_nick(nick):
                trusted = nick == crypto.guest_nick(ik)
            else:
                pinned = self.store.pinned(nick)
                if pinned is None:
                    try:
                        pinned = (await self.resolve(nick)).ik
                    except ChatError:
                        pinned = None
                trusted = pinned == ik
            entry["verified"] = trusted
            out.append(entry)
        if out:
            self.emit("history", chan=ch.name, entries=out)

    async def change_password(self, chan: str, passphrase: str, reencrypt: bool = False) -> dict:
        """Owner only. New salt (so a new key for everything), new epoch; the old
        history is deleted unless ``reencrypt``, in which case we re-encrypt it
        here, with the new key, before handing it back."""
        ch = self.channels.get(chan)
        if not ch or not ch.private:
            raise ChatError("só canais privados têm senha")
        salt = os.urandom(16)
        auth, psk, hkey = await asyncio.to_thread(crypto.channel_secrets, passphrase, salt)
        new_epoch = ch.epoch + 1
        rows = []
        if reencrypt and ch.hkey:
            dump = await self.request({"t": "history_dump", "chan": chan})
            for row in dump.get("rows") or []:
                try:
                    plain = crypto.history_open(ch.hkey, chan, int(row["epoch"]), b64d(row["h"]))
                    entry = json.loads(plain)
                    # the signature covers the epoch: re-sign is impossible for others'
                    # lines, so keep the original epoch inside the entry for checking
                    # (a row re-encrypted before keeps the epoch it was first signed in)
                    entry["e"] = int(entry["e"]) if row.get("re") and "e" in entry else int(row["epoch"])
                    blob = crypto.history_seal(hkey, chan, new_epoch, json.dumps(entry).encode())
                    rows.append({"id": row["id"], "h": b64e(blob)})
                except (CryptoError, ProtocolError, KeyError, TypeError, ValueError):
                    continue
        reply = await self.request({"t": "chan_pass", "chan": chan, "salt": b64e(salt),
                                    "verifier": b64e(crypto.auth_verifier(auth)), "reencrypt": rows})
        ch.auth, ch.psk, ch.hkey = auth, psk, hkey
        ch.epoch = int(reply.get("epoch") or new_epoch)
        ch.chain = Chain()                                    # nobody else is in the channel now
        return reply
