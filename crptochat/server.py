"""crptochat relay server.

The server is a blind relay. It knows:
  * the nickname registry (nick -> Ed25519 public key), kept forever so a
    nickname can never be reused by someone else;
  * the channel registry (name, open/private, salt, access verifier);
  * who is online and in which channel (RAM only).

It never sees plaintext, never holds a decryption key and never writes a
message or a file to disk. Files do not pass through it at all.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import hmac
import json
import re
import os
import sqlite3
import ssl
import sys
import time
from collections import Counter, deque

from . import __version__
from . import crypto
from .ratelimit import Bucket, Limits, SessionLimits, Strikes, recall, remember
from .protocol import (
    DEFAULT_PORT,
    GUEST_PREFIX,
    MAX_BODY,
    MAX_CHANNEL_MEMBERS,
    MAX_CHANNELS_PER_USER,
    MAX_LINE,
    MAX_TTL,
    PROTO_VERSION,
    ProtocolError,
    b64d,
    b64e,
    decode,
    encode,
    is_guest_nick,
    valid_chan,
    valid_nick,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    nick_lower TEXT PRIMARY KEY,
    nick       TEXT NOT NULL,
    ik         BLOB NOT NULL,
    created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
    name     TEXT PRIMARY KEY,
    private  INTEGER NOT NULL,
    salt     BLOB,
    verifier BLOB,
    created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chan_roles (
    chan       TEXT NOT NULL,
    nick_lower TEXT NOT NULL,
    role       TEXT NOT NULL,
    PRIMARY KEY (chan, nick_lower)
);
CREATE TABLE IF NOT EXISTS chan_bans (
    chan       TEXT NOT NULL,
    nick_lower TEXT NOT NULL,
    PRIMARY KEY (chan, nick_lower)
);
CREATE TABLE IF NOT EXISTS ip_bans (
    ip_hash TEXT PRIMARY KEY,
    until   INTEGER NOT NULL,
    reason  TEXT,
    label   TEXT,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    chan    TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    epoch   INTEGER NOT NULL,
    blob    BLOB NOT NULL,
    sender  TEXT NOT NULL DEFAULT '',
    reenc   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS history_chan ON history (chan, id);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB
);
"""

# Columns added after the first release (existing databases are upgraded).
MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE users ADD COLUMN banned_until INTEGER",   # NULL = not banned, 0 = forever
    "ALTER TABLE users ADD COLUMN ban_reason TEXT",
    "ALTER TABLE channels ADD COLUMN policy TEXT",
    "ALTER TABLE channels ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0",   # bumped when the password changes
    "ALTER TABLE history ADD COLUMN sender TEXT NOT NULL DEFAULT ''",      # who uploaded the copy (nick.lower())
    "ALTER TABLE history ADD COLUMN reenc INTEGER NOT NULL DEFAULT 0",     # re-encrypted by the owner on /chanpass
]

# Optional features this server speaks, announced in the welcome frame so
# that newer clients can adapt to older servers and the other way round.
CAPS = {"ratelimit", "ttl", "relayfile", "history"}
HISTORY_BODY = 12 * 1024        # base64 chars of one history copy (text only)

FILE_CHUNK_B64 = 96 * 1024      # a 64 KiB encrypted chunk, base64, with room to spare
FILE_WINDOW = 16                # chunks a sender may have in flight before an ack
FILE_PENDING_TTL = 900          # an offer not accepted within this time is dropped

AUTH_TIMEOUT = 30
IDLE_TIMEOUT = 180
TEXT_ONLY_BODY = 8000      # base64 chars; voice clips use ~27k per envelope

GLOBAL_ROLES = ("user", "mod", "admin")
# Channel roles, IRC style: ~owner  @op  +voice. "member" only matters for
# invite-only channels (it means "allowed in").
CHAN_RANK = {"member": 0, "voice": 1, "op": 2, "owner": 3}
DEFAULT_POLICY = {
    "noanon": False,     # anonymous (unregistered) users cannot join
    "moderated": False,  # only voice/op/owner can speak
    "invite": False,     # only invited nicks (or people with a role) can join
    "textonly": False,   # blocks bulky envelopes such as voice messages
    "slow": 0,           # seconds each person must wait between messages
    "limit": 0,          # maximum people in the channel (0 = server default)
    "ttl": 0,            # disappearing messages: seconds a message lives (0 = forever)
    "history": 0,        # private channels only: days the encrypted history is kept (0 = off)
    "history_anon": False,  # anonymous members also receive the history when joining
}


class Refuse(Exception):
    """Request refused; sent back to the client as an error frame."""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


class Session:
    def __init__(self, server: "Server", reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=4000)
        self.nonce = os.urandom(32)
        self.nick: str | None = None
        self.key: str | None = None      # nick.lower()
        self.ik = b""
        self.dh = b""
        self.dh_sig = b""
        self.guest = False
        self.role = "user"               # global role
        self.away = False
        self.channels: set[str] = set()
        self.last_msg: dict[str, float] = {}
        self.closed = False
        self.frames = Bucket(server.limits, "frame_rate", "frame_burst")
        self.rl: SessionLimits | None = None      # per-kind buckets, set at login
        self.strikes = Strikes(server.limits)
        self.client_version = ""
        self.queued = 0                  # bytes waiting in self.queue
        peer = writer.get_extra_info("peername")
        self.ip = peer[0] if peer else "?"

    def send(self, obj: dict) -> None:
        if self.closed:
            return
        data = encode(obj)
        # bounded in bytes, not only in frames: a peer that does not read its
        # socket cannot make the server hold an unbounded amount for it
        if self.queued + len(data) > self.server.limits["out_queue_kb"] * 1024:
            self.server.counters["slow_closed"] += 1
            self.close()
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            self.server.counters["slow_closed"] += 1
            self.close()
            return
        self.queued += len(data)
        self.server.counters["bytes_out"] += len(data)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # Wake the writer loop even if the queue is full.
        while True:
            try:
                self.queue.put_nowait(None)
                break
            except asyncio.QueueFull:
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass

    async def writer_loop(self) -> None:
        try:
            while True:
                data = await self.queue.get()
                if data is None:
                    break
                self.writer.write(data)
                await self.writer.drain()
                self.queued -= len(data)
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self.closed = True
            try:
                self.writer.close()
            except Exception:
                pass

    def public(self) -> dict:
        out = {"nick": self.nick, "ik": b64e(self.ik), "dh": b64e(self.dh), "dh_sig": b64e(self.dh_sig)}
        if self.guest:
            out["guest"] = True
        if self.role != "user":
            out["role"] = self.role
        if self.away:
            out["away"] = True
        return out


class Server:
    def __init__(self, data_dir: str, name: str = "crptochat", motd: str = "",
                 reg_token: str | None = None, reg_limit: int | None = None, allow_guests: bool = True):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self.data_dir = data_dir
        self.name = name
        self.motd = motd
        self.reg_token = reg_token
        self.allow_guests = allow_guests
        self.db = sqlite3.connect(os.path.join(data_dir, "registry.db"))
        # deleted rows are overwritten with zeros: expired history really goes away
        self.db.execute("PRAGMA secure_delete = ON")
        self.db.executescript(SCHEMA)
        for statement in MIGRATIONS:
            try:
                self.db.execute(statement)
            except sqlite3.OperationalError:
                pass  # column already there
        if not self.db.execute("SELECT 1 FROM channels WHERE name='#lobby'").fetchone():
            self.db.execute("INSERT INTO channels (name, private, created) VALUES ('#lobby', 0, ?)",
                            (int(time.time()),))
        row = self.db.execute("SELECT value FROM meta WHERE key='ip_salt'").fetchone()
        if not row:
            row = (os.urandom(32),)
            self.db.execute("INSERT INTO meta VALUES ('ip_salt', ?)", row)
        self._ip_salt = bytes(row[0])
        row = self.db.execute("SELECT value FROM meta WHERE key='ratelimit'").fetchone()
        try:
            stored = json.loads(row[0]) if row else {}
        except (ValueError, TypeError):
            stored = {}
        self.limits = Limits(stored if isinstance(stored, dict) else {})
        if reg_limit is not None:      # command-line override, not persisted
            self.limits.set("reg_per_hour", reg_limit)
        self.transfers: dict[str, dict] = {}     # relayed files in flight (memory only)
        self.ip_conns: dict[str, int] = {}
        self.ip_msg: dict[str, Bucket] = {}
        # What an address did, kept for a while after its last connection
        # closes, so reconnecting does not wipe its strikes or its counters.
        self.ip_memory: dict[str, dict] = {}
        self.ip_left: dict[str, float] = {}
        row = self.db.execute("SELECT value FROM meta WHERE key='client_repo'").fetchone()
        self.client_repo = row[0] if row else None    # where clients should look for updates
        self.db.commit()
        self.sessions: dict[str, Session] = {}
        self.members: dict[str, dict[str, Session]] = {}
        self.reg_log: dict[str, list[float]] = {}
        self._policies: dict[str, dict] = {}
        # Channel bans of anonymous users: they have no account to ban, so the
        # address is kept (in RAM only, never shown) until the server restarts.
        self.chan_guest_bans: dict[str, dict[str, str]] = {}
        # Aggregate counters for the operator dashboard. Numbers only: no
        # nickname, channel name, address or content is ever recorded here.
        self.counters = dict.fromkeys(
            ("accepted", "auth_ok", "auth_fail", "registered", "chan_msgs", "directs", "deliveries",
             "bytes_in", "bytes_out", "refused", "rate_limited", "kicks", "bans",
             "rl_warn", "rl_mute", "rl_kick", "conn_refused", "file_bytes", "files", "slow_closed",
             "internal_errors"), 0)
        # when each limit fired and how (warn/mute/kick/refused), for the health panel
        self.rl_events: deque[tuple[float, str]] = deque(maxlen=20000)
        self.started = time.time()
        self.open_conns = 0
        self.peak_sessions = 0
        self.tls = False
        self._server: asyncio.AbstractServer | None = None

    # ------------------------------------------------------------ lifecycle

    async def start(self, host: str, port: int, ssl_ctx: ssl.SSLContext | None = None) -> int:
        self.tls = ssl_ctx is not None
        self.purge_history()
        self._purger = asyncio.create_task(self._purge_loop())
        self._server = await asyncio.start_server(self._handle, host, port, ssl=ssl_ctx, limit=MAX_LINE)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if getattr(self, "_purger", None):
            self._purger.cancel()
        if self._server:
            self._server.close()
        for sess in list(self.sessions.values()):
            sess.close()
        if self._server:
            await self._server.wait_closed()
        self.db.close()

    # ----------------------------------------------------------- connection

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sess = Session(self, reader, writer)
        wtask = asyncio.create_task(sess.writer_loop())
        cap = self.limits["conns_per_ip"]
        if cap and self.ip_conns.get(sess.ip, 0) >= cap:
            self.counters["conn_refused"] += 1
            sess.send({"t": "err", "code": "too_many_conns",
                       "msg": "conexões demais a partir deste endereço; tente de novo mais tarde"})
            sess.close()
            try:
                await asyncio.wait_for(wtask, 2)
            except (asyncio.TimeoutError, Exception):
                wtask.cancel()
            return
        banned = self._ip_ban(sess.ip)
        if banned is not None:
            # checked before anything else: a banned address gets no session at all,
            # so it cannot flood pre-auth frames into a (shorter) flood ban either
            self.counters["conn_refused"] += 1
            sess.send({"t": "err", "code": "banned", "msg": self._ban_text(*banned)})
            sess.close()
            try:
                await asyncio.wait_for(wtask, 2)
            except (asyncio.TimeoutError, Exception):
                wtask.cancel()
            return
        self.ip_conns[sess.ip] = self.ip_conns.get(sess.ip, 0) + 1
        self._forget_old_addresses()
        memory = self.ip_memory.get(sess.ip)
        if memory:
            recall(sess.strikes, memory)
        self.open_conns += 1
        self.counters["accepted"] += 1
        try:
            sess.send({"t": "welcome", "v": PROTO_VERSION, "server": self.name, "motd": self.motd,
                       "nonce": b64e(sess.nonce), "your_ip": sess.ip,
                       "reg_token": bool(self.reg_token), "guests": self.allow_guests,
                       "client_repo": self.client_repo, "caps": sorted(CAPS),
                       "limits": self.public_limits()})
            while not sess.closed:
                timeout = IDLE_TIMEOUT if sess.nick else AUTH_TIMEOUT
                line = await asyncio.wait_for(reader.readline(), timeout)
                if not line:
                    break
                self.counters["bytes_in"] += len(line)
                msg = decode(line)
                rid = msg.get("id")
                try:
                    if not sess.frames.take():
                        self._flood(sess, "rate", "devagar: limite de taxa excedido")
                    reply = self._dispatch(sess, msg)
                    if rid is not None:
                        sess.send({"t": "ok", "id": rid, **(reply or {})})
                except Refuse as exc:
                    self.counters["refused"] += 1      # rate_limited is counted once, in _flood
                    sess.send({"t": "err", "id": rid, "code": exc.code, "msg": exc.msg})
                except Exception as exc:  # noqa: BLE001 - a bug must not take the server down
                    # A frame the handlers did not expect. Only the kind of frame and the
                    # error type are logged (never content), and the connection is closed
                    # because the handler may have stopped halfway.
                    self.counters["internal_errors"] += 1
                    print(f"  erro interno ao tratar '{str(msg.get('t'))[:32]}': {type(exc).__name__}",
                          file=sys.stderr)
                    sess.send({"t": "err", "id": rid, "code": "internal", "msg": "erro interno; conexão encerrada"})
                    break
        except (ProtocolError, asyncio.TimeoutError, ValueError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            self.open_conns -= 1
            left = self.ip_conns.get(sess.ip, 1) - 1
            if left > 0:
                self.ip_conns[sess.ip] = left
            else:
                self.ip_conns.pop(sess.ip, None)
            if sess.strikes.times or sess.strikes.muted_until:
                self._remember_address(sess)
            self.ip_left[sess.ip] = time.monotonic()
            self._drop(sess)
            sess.close()
            try:
                await asyncio.wait_for(wtask, 2)
            except (asyncio.TimeoutError, Exception):
                wtask.cancel()

    def _drop(self, sess: Session) -> None:
        for tid, tr in list(self.transfers.items()):
            if sess in (tr["from"], tr["to"]):
                self._end_transfer(tid, "a outra pessoa desconectou", notify=sess)
        for chan in list(sess.channels):
            self._leave(sess, chan)
        if sess.key and self.sessions.get(sess.key) is sess:
            del self.sessions[sess.key]

    # ---------------------------------------------------------- rate limits

    def public_limits(self) -> dict:
        """What clients may know to stay under the limits."""
        lim = self.limits
        return {"max_body": lim.max_body(), "msg_rate": lim["msg_rate"], "msg_burst": lim["msg_burst"],
                "anon_msg_rate": lim["anon_msg_rate"], "anon_msg_burst": lim["anon_msg_burst"],
                "file_max": int(lim["file_max_mb"] * 1024 * 1024), "file_kbps": lim["file_kbps"],
                "anon_file_kbps": lim["anon_file_kbps"], "file_window": FILE_WINDOW,
                "history_body": HISTORY_BODY}

    # ------------------------------------------------------- relayed files
    #
    # The server only pipes encrypted chunks between two sessions: nothing is
    # forwarded before the recipient accepts, nothing is written to disk, and
    # the sender may only have FILE_WINDOW chunks in flight, so memory stays
    # bounded. File names, keys and hashes travel end to end, never here.

    def _end_transfer(self, tid: str, why: str, notify: Session | None = None) -> None:
        tr = self.transfers.pop(tid, None)
        if not tr:
            return
        for side in (tr["from"], tr["to"]):
            if side is not notify:
                side.send({"t": "file_cancel", "tid": tid, "msg": why})

    def _transfer(self, sess: Session, tid, side: str) -> dict:
        tr = self.transfers.get(tid) if isinstance(tid, str) else None
        if not tr or tr[side] is not sess:
            raise Refuse("no_transfer", "transferência desconhecida ou já encerrada")
        return tr

    def _op_file_open(self, sess: Session, msg: dict) -> dict:
        tid, to, size = msg.get("tid"), msg.get("to"), msg.get("size")
        cap = int(self.limits["file_max_mb"] * 1024 * 1024)
        if not cap:
            raise Refuse("denied", "este servidor não aceita arquivos pelo servidor; use /send --p2p")
        if not (isinstance(tid, str) and re.fullmatch(r"[0-9a-f]{32}", tid)) or not valid_nick(to):
            raise Refuse("bad_request", "transferência inválida")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise Refuse("bad_request", "tamanho inválido")
        if size > cap:
            raise Refuse("too_big", f"arquivo grande demais para este servidor (máximo {self.limits['file_max_mb']:g} MiB)")
        now = time.monotonic()
        for old in [k for k, t in self.transfers.items() if not t["accepted"] and now - t["at"] > FILE_PENDING_TTL]:
            self._end_transfer(old, "a oferta expirou")
        if tid in self.transfers:
            raise Refuse("bad_request", "transferência repetida")
        mine = sum(1 for t in self.transfers.values() if t["from"] is sess)
        if mine >= self.limits["file_concurrent"]:
            raise Refuse("limit", "transferências simultâneas demais; espere uma terminar")
        other = self.sessions.get(to.lower())
        if not other or other is sess:
            raise Refuse("offline", f"{to} está offline")
        self.transfers[tid] = {"from": sess, "to": other, "size": size, "accepted": False, "next": 0,
                               "acked": -1, "at": now, "sent": 0}
        return {"tid": tid}

    def _op_file_accept(self, sess: Session, msg: dict) -> dict:
        tr = self._transfer(sess, msg.get("tid"), "to")
        if tr["accepted"]:
            raise Refuse("state", "transferência já aceita")
        tr["accepted"] = True
        tr["from"].send({"t": "file_go", "tid": msg["tid"], "nick": sess.nick})
        return {}

    def _op_file_chunk(self, sess: Session, msg: dict) -> None:
        tid, index, data = msg.get("tid"), msg.get("i"), msg.get("d")
        tr = self._transfer(sess, tid, "from")
        if not tr["accepted"]:
            raise Refuse("not_accepted", "a outra pessoa ainda não aceitou o arquivo")
        if index != tr["next"] or not isinstance(data, str) or len(data) > FILE_CHUNK_B64:
            self._end_transfer(tid, "bloco fora de ordem ou grande demais")
            raise Refuse("bad_request", "bloco inválido")
        if index - tr["acked"] > FILE_WINDOW:
            self._end_transfer(tid, "o remetente não respeitou a janela de envio")
            raise Refuse("bad_request", "janela de envio excedida")
        tr["sent"] += len(data) * 3 // 4
        if tr["sent"] > tr["size"] + 16 * (tr["size"] // (64 * 1024) + 2) + 64:
            self._end_transfer(tid, "o arquivo é maior que o anunciado")
            raise Refuse("too_big", "o arquivo é maior que o anunciado")
        if not sess.rl.file.take(len(data) * 3 / 4 / 1024):
            self._end_transfer(tid, "limite de banda para arquivos excedido")
            raise Refuse("rate", "limite de banda para arquivos excedido")
        if tr["to"].queued > self.limits["out_queue_kb"] * 1024 / 2:
            # the receiver confirms but does not read: stop feeding it before its queue fills
            self._end_transfer(tid, "quem recebe não está lendo os dados")
            raise Refuse("slow", "quem recebe não está lendo os dados")
        tr["next"] += 1
        self.counters["file_bytes"] += len(data) * 3 // 4
        last = bool(msg.get("last"))
        tr["to"].send({"t": "file_chunk", "tid": tid, "i": index, "last": last, "d": data})
        if last:
            tr["done"] = True

    def _op_file_ack(self, sess: Session, msg: dict) -> None:
        tid, index = msg.get("tid"), msg.get("i")
        tr = self._transfer(sess, tid, "to")
        if not isinstance(index, int) or isinstance(index, bool) or not tr["acked"] < index < tr["next"]:
            return
        tr["acked"] = index
        tr["from"].send({"t": "file_ack", "tid": tid, "i": index, "ok": bool(msg.get("ok"))})
        if msg.get("ok") and tr.get("done"):
            self.transfers.pop(tid, None)
            self.counters["files"] += 1

    def _op_file_cancel(self, sess: Session, msg: dict) -> None:
        tid = msg.get("tid")
        tr = self.transfers.get(tid) if isinstance(tid, str) else None
        if tr and sess in (tr["from"], tr["to"]):
            self._end_transfer(tid, str(msg.get("msg") or "cancelado")[:100], notify=sess)

    def _forget_old_addresses(self) -> None:
        keep = self.limits["ip_memory"]
        now = time.monotonic()
        # strikes expire by age, even while other people on the same address stay connected
        for ip in [ip for ip, mem in self.ip_memory.items() if now - mem["at"] > keep]:
            del self.ip_memory[ip]
        # the shared message counter lives while the address is connected, then for ip_memory
        for ip in [ip for ip, left in self.ip_left.items() if now - left > keep and ip not in self.ip_conns]:
            self.ip_left.pop(ip, None)
            self.ip_msg.pop(ip, None)

    def _flood(self, sess: Session, code: str, text: str) -> None:
        """A limit was broken: escalate (warn, mute, kick) and refuse the request."""
        action = sess.strikes.hit()
        self.counters["rate_limited"] += 1
        self.rl_events.append((time.time(), action or "refused"))
        if action == "kick":
            self.counters["rl_kick"] += 1
            self.counters["kicks"] += 1
            minutes = self.limits["flood_ban_minutes"]
            text = "desconectado por flood (limites de taxa excedidos)"
            if minutes:
                # a short address ban, so the flood does not just resume on reconnect
                label = sess.nick or "sem-login-" + self._ip_hash(sess.ip)[:8]
                self._extend_ip_ban(sess.ip, int(time.time() + minutes * 60), "flood", label)
                self.counters["bans"] += 1
                text += f"; este endereço fica bloqueado por {minutes:g} min"
            self._disconnect(sess, {"t": "kicked", "msg": text})
        elif action == "mute":
            self.counters["rl_mute"] += 1
            seconds = int(self.limits["mute_seconds"])
            sess.send({"t": "ratelimit", "action": "mute", "seconds": seconds,
                       "msg": f"você está silenciado por {seconds}s por excesso de mensagens"})
        elif action == "warn":
            self.counters["rl_warn"] += 1
            sess.send({"t": "ratelimit", "action": "warn",
                       "msg": "aviso: você está enviando rápido demais; se continuar, será silenciado"})
        raise Refuse(code, text)

    def _check_body(self, body) -> None:
        if not isinstance(body, str):
            raise Refuse("bad_request", "mensagem inválida")
        if len(body) > min(MAX_BODY, self.limits.max_body()):
            raise Refuse("too_big", f"mensagem grande demais (máximo {int(self.limits['max_body_kb'])} KiB cifrados)")

    def _rate_envelope(self, sess: Session, body: str, kind: str) -> None:
        """Bulky envelopes (voice) are limited by size; small ones by count."""
        rl = sess.rl
        if len(body) > TEXT_ONLY_BODY:
            if not rl.bulk.take(len(body) / 1024):
                self._flood(sess, "rate", "devagar: muitos dados em pouco tempo")
            return
        if kind == "direct":
            if not rl.direct.take():
                self._flood(sess, "rate", "devagar: mensagens diretas demais em pouco tempo")
            return
        if not rl.msg.take():
            self._flood(sess, "rate", "devagar: mensagens demais em pouco tempo")
        if sess.guest:
            ip = self.ip_msg.get(sess.ip)
            if ip is None:
                ip = self.ip_msg[sess.ip] = Bucket(self.limits, "anon_ip_msg_rate", "anon_ip_msg_burst")
            if not ip.take():
                self._flood(sess, "rate", "devagar: mensagens anônimas demais a partir deste endereço")

    def _disconnect(self, sess: Session, frame: dict) -> None:
        """Tell a client why, then cut it off."""
        sess.send(frame)
        self._drop(sess)
        sess.close()

    # ------------------------------------------------------------- dispatch

    # Fields that name things (channels, nicks, transfers) must be strings when
    # present: a list or dict there would reach set lookups and SQL as garbage.
    STRING_FIELDS = ("chan", "nick", "to", "tid", "target", "name", "role", "reason", "msg", "text", "repo")

    def _dispatch(self, sess: Session, msg: dict) -> dict | None:
        t = msg["t"]
        for field in self.STRING_FIELDS:
            value = msg.get(field)
            if value is not None and not isinstance(value, str):
                raise Refuse("bad_request", f"campo {field} inválido")
        if t == "ping":
            return {}
        if t == "auth":
            try:
                reply = self._auth(sess, msg)
            except Refuse:
                self.counters["auth_fail"] += 1
                raise
            self.counters["auth_ok"] += 1
            self.counters["registered"] += int(reply["registered"])
            self.peak_sessions = max(self.peak_sessions, len(self.sessions))
            return reply
        if not sess.nick:
            raise Refuse("unauth", "autentique-se primeiro")
        handler = getattr(self, "_op_" + t, None)
        if handler is None:
            raise Refuse("unknown", "comando desconhecido")
        return handler(sess, msg)

    # ----------------------------------------------------------------- bans

    def _ip_hash(self, ip: str) -> str:
        # Addresses are never stored in clear, only as a keyed hash.
        return hmac.new(self._ip_salt, ip.encode(), hashlib.sha256).hexdigest()

    def _ip_ban(self, ip: str) -> tuple[str, int] | None:
        """(reason, until) of an active ban on this address; until 0 = forever."""
        row = self.db.execute("SELECT until, reason FROM ip_bans WHERE ip_hash=?", (self._ip_hash(ip),)).fetchone()
        if not row:
            return None
        if row[0] and row[0] < time.time():
            self.db.execute("DELETE FROM ip_bans WHERE ip_hash=?", (self._ip_hash(ip),))
            self.db.commit()
            return None
        return row[1] or "", row[0]

    def _ip_banned(self, ip: str) -> str | None:
        ban = self._ip_ban(ip)
        return None if ban is None else ban[0]

    def _extend_ip_ban(self, ip: str, until: int, reason: str, label: str) -> None:
        """Automatic bans only ever lengthen: an existing ban that lasts longer
        (or forever, until 0) is kept as it is, label and reason included."""
        key = self._ip_hash(ip)
        row = self.db.execute("SELECT until FROM ip_bans WHERE ip_hash=?", (key,)).fetchone()
        if row is None:
            self.db.execute("INSERT INTO ip_bans VALUES (?,?,?,?,?)", (key, until, reason, label, int(time.time())))
        elif row[0] != 0 and (until == 0 or until > row[0]):
            self.db.execute("UPDATE ip_bans SET until=? WHERE ip_hash=?", (until, key))
        self.db.commit()

    def _remember_address(self, sess: Session) -> None:
        """Add this session's strikes to what its address already did (never
        replace: the last session to leave must not wipe the others')."""
        mine = remember(sess.strikes)
        old = self.ip_memory.get(sess.ip)
        if old and time.monotonic() - old["at"] <= self.limits["ip_memory"]:
            mine["times"] = sorted(set(old["times"]) | set(mine["times"]))
            mine["muted_until"] = max(old["muted_until"], mine["muted_until"])
            mine["warned"] = old["warned"] or mine["warned"]
        self.ip_memory[sess.ip] = {**mine, "at": time.monotonic()}

    @staticmethod
    def _ban_text(reason: str | None, until: int | None) -> str:
        text = "você foi banido deste servidor"
        if until:
            text += time.strftime(" até %d/%m/%Y %H:%M", time.localtime(until))
        return text + (f": {reason}" if reason else "")

    def ban(self, nick: str, minutes: int = 0, reason: str = "", ip: bool = False) -> dict:
        """Ban a nickname (and optionally the address it is using right now)."""
        key = nick.lower()
        until = int(time.time() + minutes * 60) if minutes else 0
        reason = reason[:200]
        row = self.db.execute("SELECT nick FROM users WHERE nick_lower=?", (key,)).fetchone()
        sess = self.sessions.get(key)
        if not row and not sess:
            raise Refuse("no_user", f"'{nick}' não é um nick registrado nem está online")
        if not row and not ip:
            ip = True  # an anonymous user can only be banned by address
        if row:
            self.db.execute("UPDATE users SET banned_until=?, ban_reason=? WHERE nick_lower=?", (until, reason, key))
        banned_ip = False
        if ip and sess:
            self.db.execute("INSERT OR REPLACE INTO ip_bans VALUES (?,?,?,?,?)",
                            (self._ip_hash(sess.ip), until, reason, row[0] if row else sess.nick, int(time.time())))
            banned_ip = True
        self.db.commit()
        self.counters["bans"] += 1
        if sess:
            self._disconnect(sess, {"t": "banned", "msg": self._ban_text(reason, until)})
        return {"nick": row[0] if row else nick, "ip": banned_ip, "until": until, "online": bool(sess)}

    def unban(self, nick: str) -> dict:
        key = nick.lower()
        cur = self.db.execute("UPDATE users SET banned_until=NULL, ban_reason=NULL "
                              "WHERE nick_lower=? AND banned_until IS NOT NULL", (key,))
        ips = self.db.execute("DELETE FROM ip_bans WHERE lower(label)=?", (key,)).rowcount
        self.db.commit()
        if not cur.rowcount and not ips:
            raise Refuse("no_ban", f"'{nick}' não está banido")
        return {"nick": nick, "ip": ips}

    # ----------------------------------------------------------------- auth

    def _auth(self, sess: Session, msg: dict) -> dict:
        if sess.nick:
            raise Refuse("state", "já autenticado")
        ip_reason = self._ip_banned(sess.ip)
        if ip_reason is not None:
            raise Refuse("banned", self._ban_text(ip_reason, None))
        nick = msg.get("nick")
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido (3-20 caracteres: letras, números, _ e -)")
        try:
            ik = b64d(msg.get("ik"), 32)
            dh = b64d(msg.get("dh"), 32)
            sig = b64d(msg.get("sig"), 64)
            dh_sig = b64d(msg.get("dh_sig"), 64)
        except ProtocolError:
            raise Refuse("bad_auth", "autenticação malformada")
        if not crypto.verify(ik, sig, crypto.auth_message(sess.nonce, nick, dh)):
            raise Refuse("bad_auth", "assinatura inválida")
        if not crypto.verify(ik, dh_sig, crypto.dh_message(nick, dh)):
            raise Refuse("bad_auth", "assinatura inválida")

        key = nick.lower()
        guest = bool(msg.get("guest"))
        version = msg.get("ver")
        # only a plain version number is kept (it is shown, aggregated, to the operator)
        sess.client_version = version if isinstance(version, str) and VERSION_RE.fullmatch(version) else ""
        registered = False
        role = "user"
        if guest:
            # Anonymous access: nothing is registered. The nickname is derived
            # from the throwaway key, so it cannot collide with or imitate anyone.
            if not self.allow_guests:
                raise Refuse("no_guests", "este servidor não aceita acesso anônimo: registre um nickname")
            if nick != crypto.guest_nick(ik):
                raise Refuse("bad_nick", "nickname anônimo inválido")
            same_ip = sum(1 for s in self.sessions.values() if s.guest and s.ip == sess.ip)
            if same_ip >= self.limits["anon_per_ip"]:
                raise Refuse("limit", "muitas sessões anônimas a partir deste endereço")
        else:
            if is_guest_nick(nick):
                raise Refuse("bad_nick", f"nicks começando com '{GUEST_PREFIX}' são reservados para acesso anônimo")
            row = self.db.execute("SELECT nick, ik, role, banned_until, ban_reason FROM users WHERE nick_lower=?",
                                  (key,)).fetchone()
            if row:
                if not hmac.compare_digest(bytes(row[1]), ik):
                    raise Refuse("nick_taken", "este nickname já está registrado com outra chave")
                nick, role = row[0], row[2]
                if row[3] is not None:
                    if row[3] == 0 or row[3] > time.time():
                        raise Refuse("banned", self._ban_text(row[4], row[3]))
                    self.db.execute("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE nick_lower=?", (key,))
                    self.db.commit()
            else:
                if self.reg_token is not None and not hmac.compare_digest(
                        str(msg.get("reg_token") or "").encode(), self.reg_token.encode()):
                    raise Refuse("reg_token", "este servidor exige um token de registro válido")
                now = time.time()
                recent = [ts for ts in self.reg_log.get(sess.ip, []) if now - ts < 3600]
                if self.limits["reg_per_hour"] and len(recent) >= self.limits["reg_per_hour"]:
                    raise Refuse("reg_limit", "muitos registros a partir deste endereço, tente mais tarde")
                recent.append(now)
                self.reg_log[sess.ip] = recent
                self.db.execute("INSERT INTO users (nick_lower, nick, ik, created) VALUES (?,?,?,?)",
                                (key, nick, ik, int(now)))
                self.db.commit()
                registered = True

        old = self.sessions.get(key)
        if old is not None:
            self._disconnect(old, {"t": "kicked", "msg": "sessão substituída por um novo login"})
        sess.nick, sess.key, sess.ik, sess.dh, sess.dh_sig = nick, key, ik, dh, dh_sig
        sess.guest, sess.role = guest, role
        sess.rl = SessionLimits(self.limits, guest)
        self.sessions[key] = sess
        return {"nick": nick, "registered": registered, "role": role, "guest": guest}

    # ---------------------------------------------------------------- users

    def _op_whois(self, sess: Session, msg: dict) -> dict:
        nick = msg.get("nick")
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido")
        other = self.sessions.get(nick.lower())
        if other:
            return {"user": other.public(), "online": True}
        row = self.db.execute("SELECT nick, ik, role FROM users WHERE nick_lower=?", (nick.lower(),)).fetchone()
        if not row:
            raise Refuse("no_user", f"nickname '{nick}' não existe")
        user = {"nick": row[0], "ik": b64e(bytes(row[1]))}
        if row[2] != "user":
            user["role"] = row[2]
        return {"user": user, "online": False}

    def _op_direct(self, sess: Session, msg: dict) -> None:
        to, body = msg.get("to"), msg.get("body")
        if not valid_nick(to):
            raise Refuse("bad_request", "mensagem inválida")
        self._check_body(body)
        self._rate_envelope(sess, body, "direct")
        other = self.sessions.get(to.lower())
        if not other:
            raise Refuse("offline", f"{to} está offline")
        self.counters["directs"] += 1
        other.send({"t": "direct", "from": sess.nick, "body": body})

    def _op_away(self, sess: Session, msg: dict) -> dict:
        # Only the flag reaches the server; the away text travels end to end.
        away = bool(msg.get("on"))
        if away != sess.away:
            sess.away = away
            seen = {sess}
            for chan in sess.channels:
                for other in self.members.get(chan, {}).values():
                    if other not in seen:
                        seen.add(other)
                        other.send({"t": "away", "nick": sess.nick, "away": away})
        return {"away": away}

    def _op_presence(self, sess: Session, msg: dict) -> dict:
        nicks = msg.get("nicks")
        if not isinstance(nicks, list) or len(nicks) > 200:
            raise Refuse("bad_request", "lista inválida")
        online = {}
        for nick in nicks:
            other = self.sessions.get(nick.lower()) if valid_nick(nick) else None
            if other:
                online[other.nick] = "away" if other.away else "on"
        return {"online": online}

    def _staff(self, sess: Session, admin: bool = False) -> None:
        if sess.role != "admin" and (admin or sess.role != "mod"):
            raise Refuse("denied", "apenas a moderação do servidor pode fazer isso")

    def _staff_target(self, sess: Session, nick) -> str:
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido")
        if nick.lower() == sess.key:
            raise Refuse("denied", "não em você mesmo")
        row = self.db.execute("SELECT role FROM users WHERE nick_lower=?", (nick.lower(),)).fetchone()
        target_role = row[0] if row else "user"
        if target_role == "admin" or (target_role == "mod" and sess.role != "admin"):
            raise Refuse("denied", "você não pode agir sobre alguém da moderação")
        return nick

    def _op_gkick(self, sess: Session, msg: dict) -> dict:
        self._staff(sess)
        nick = self._staff_target(sess, msg.get("nick"))
        other = self.sessions.get(nick.lower())
        if not other:
            raise Refuse("offline", f"{nick} está offline")
        self.counters["kicks"] += 1
        self._disconnect(other, {"t": "kicked", "msg": f"desconectado pela moderação ({sess.nick})"})
        return {"nick": other.nick}

    def _op_gban(self, sess: Session, msg: dict) -> dict:
        self._staff(sess)
        nick = self._staff_target(sess, msg.get("nick"))
        minutes = msg.get("minutes") or 0
        if not isinstance(minutes, int) or not 0 <= minutes <= 60 * 24 * 3650:
            raise Refuse("bad_request", "duração inválida")
        return self.ban(nick, minutes, str(msg.get("reason") or ""), bool(msg.get("ip")))

    def _op_gunban(self, sess: Session, msg: dict) -> dict:
        self._staff(sess)
        nick = msg.get("nick")
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido")
        return self.unban(nick)

    # ------------------------------------------------------- channel access

    def _chan_row(self, chan):
        if not valid_chan(chan):
            raise Refuse("bad_chan", "nome de canal inválido (#nome, minúsculas, números, _ e -)")
        return self.db.execute("SELECT private, salt, verifier FROM channels WHERE name=?", (chan,)).fetchone()

    def policy(self, chan: str) -> dict:
        if chan not in self._policies:
            row = self.db.execute("SELECT policy FROM channels WHERE name=?", (chan,)).fetchone()
            policy = dict(DEFAULT_POLICY)
            if row and row[0]:
                try:
                    policy.update({k: v for k, v in json.loads(row[0]).items() if k in DEFAULT_POLICY})
                except ValueError:
                    pass
            self._policies[chan] = policy
        return self._policies[chan]

    def chan_role(self, chan: str, key: str) -> str | None:
        row = self.db.execute("SELECT role FROM chan_roles WHERE chan=? AND nick_lower=?", (chan, key)).fetchone()
        return row[0] if row else None

    def _set_chan_role(self, chan: str, key: str, role: str | None) -> None:
        if role is None:
            self.db.execute("DELETE FROM chan_roles WHERE chan=? AND nick_lower=?", (chan, key))
        else:
            self.db.execute("INSERT OR REPLACE INTO chan_roles VALUES (?,?,?)", (chan, key, role))
        self.db.commit()

    def _power(self, sess: Session, chan: str) -> int:
        """What a session may do in a channel: 3 owner, 2 op, 1 voice, 0 nothing.
        Server admins rank as owner everywhere and moderators as op."""
        if sess.role == "admin":
            return 3
        own = -1 if sess.guest else CHAN_RANK.get(self.chan_role(chan, sess.key), -1)
        return max(own if own > 0 else 0, 2 if sess.role == "mod" else 0)

    def _shown_role(self, sess: Session, chan: str) -> str | None:
        role = None if sess.guest else self.chan_role(chan, sess.key)
        return role if role in ("owner", "op", "voice") else None

    def _need(self, sess: Session, chan, power: int) -> None:
        if chan not in sess.channels:
            raise Refuse("state", "você não está neste canal")
        if self._power(sess, chan) < power:
            raise Refuse("denied", "apenas o dono do canal pode fazer isso" if power >= 3
                         else "apenas operadores do canal podem fazer isso")

    def _chan_send(self, chan: str, frame: dict, skip: Session | None = None) -> None:
        for other in self.members.get(chan, {}).values():
            if other is not skip:
                other.send(frame)

    def _op_chaninfo(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        row = self._chan_row(chan)
        if not row:
            raise Refuse("no_chan", "canal não existe (crie com /create)")
        return {"private": bool(row[0]), "salt": b64e(bytes(row[1])) if row[1] else None,
                "policy": self.policy(chan), "epoch": self.epoch(chan)}

    def _op_create(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        if sess.guest:
            raise Refuse("denied", "usuários anônimos não podem criar canais: registre um nickname")
        if not sess.rl.join.take():
            self._flood(sess, "rate", "devagar: canais demais em pouco tempo")
        if self._chan_row(chan):
            raise Refuse("chan_exists", "já existe um canal com esse nome")
        private = bool(msg.get("private"))
        salt = verifier = None
        if private:
            try:
                salt = b64d(msg.get("salt"), 16)
                verifier = b64d(msg.get("verifier"), 32)
            except ProtocolError:
                raise Refuse("bad_request", "parâmetros do canal privado inválidos")
        self.db.execute("INSERT INTO channels (name, private, salt, verifier, created) VALUES (?,?,?,?,?)",
                        (chan, int(private), salt, verifier, int(time.time())))
        self._set_chan_role(chan, sess.key, "owner")
        return {"chan": chan, "private": private}

    def _op_join(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        if not sess.rl.join.take():
            self._flood(sess, "rate", "devagar: entradas em canais demais em pouco tempo")
        row = self._chan_row(chan)
        if not row:
            raise Refuse("no_chan", "canal não existe (crie com /create)")
        if chan in sess.channels:
            raise Refuse("state", "você já está neste canal")
        if len(sess.channels) >= MAX_CHANNELS_PER_USER:
            raise Refuse("limit", "limite de canais atingido")
        policy = self.policy(chan)
        power = self._power(sess, chan)
        role = None if sess.guest else self.chan_role(chan, sess.key)
        if power < 2:
            if sess.guest:
                if sess.ip in self.chan_guest_bans.get(chan, {}).values():
                    raise Refuse("banned_chan", "você foi banido deste canal")
                if policy["noanon"]:
                    raise Refuse("denied", "este canal não aceita usuários anônimos: registre um nickname")
            elif self.db.execute("SELECT 1 FROM chan_bans WHERE chan=? AND nick_lower=?", (chan, sess.key)).fetchone():
                raise Refuse("banned_chan", "você foi banido deste canal")
            if policy["invite"] and role is None:
                raise Refuse("denied", "este canal é só para convidados")
        if row[0]:
            try:
                auth = b64d(msg.get("auth"), 32)
            except ProtocolError:
                raise Refuse("denied", "senha do canal necessária")
            if not hmac.compare_digest(crypto.auth_verifier(auth), bytes(row[2])):
                raise Refuse("denied", "senha do canal incorreta")
        members = self.members.setdefault(chan, {})
        cap = min(policy["limit"] or MAX_CHANNEL_MEMBERS, MAX_CHANNEL_MEMBERS)
        if len(members) >= cap and power < 2:
            raise Refuse("limit", "canal lotado")
        current = [m.public() for m in members.values()]
        shown = self._shown_role(sess, chan)
        roles = {m.nick: r for m in members.values() if (r := self._shown_role(m, chan))}
        if shown:
            roles[sess.nick] = shown
        for other in members.values():
            other.send({"t": "member_join", "chan": chan, "user": sess.public(), "role": shown})
        members[sess.key] = sess
        sess.channels.add(chan)
        reply = {"chan": chan, "private": bool(row[0]), "members": current, "roles": roles, "policy": policy}
        if row[0]:
            reply["epoch"] = self.epoch(chan)
            reply["history"] = self.history_for(sess, chan)
        return reply

    def _leave(self, sess: Session, chan: str, kicked_by: str | None = None) -> None:
        members = self.members.get(chan)
        sess.channels.discard(chan)
        sess.last_msg.pop(chan, None)
        if not members or members.pop(sess.key, None) is None:
            return
        frame = {"t": "member_leave", "chan": chan, "nick": sess.nick}
        if kicked_by:
            frame["kicked"] = kicked_by
        for other in members.values():
            other.send(frame)
        if not members:
            del self.members[chan]

    def _op_leave(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        if chan not in sess.channels:
            raise Refuse("state", "você não está neste canal")
        self._leave(sess, chan)
        return {"chan": chan}

    def _op_list(self, sess: Session, msg: dict) -> dict:
        out = []
        for name, private in self.db.execute("SELECT name, private FROM channels ORDER BY name"):
            # Private channels are only listed to people already inside.
            if private and name not in sess.channels:
                continue
            out.append({"name": name, "private": bool(private), "members": len(self.members.get(name, {}))})
        return {"channels": out}

    def _op_msg(self, sess: Session, msg: dict) -> None:
        chan, body = msg.get("chan"), msg.get("body")
        if chan not in sess.channels:
            raise Refuse("bad_request", "mensagem inválida")
        self._check_body(body)
        muted = sess.strikes.muted
        if muted:
            # keeps counting: insisting while muted ends in a kick
            self._flood(sess, "muted", f"você está silenciado por mais {int(muted) + 1}s")
        self._rate_envelope(sess, body, "msg")
        policy = self.policy(chan)
        if policy["moderated"] or policy["slow"] or policy["textonly"]:
            # The server cannot read messages; these rules only look at who is
            # sending, how often and how large the envelope is.
            power = self._power(sess, chan)
            if policy["moderated"] and power < 1:
                raise Refuse("moderated", f"{chan} está moderado: só quem tem voz pode falar")
            if power < 2:
                if policy["textonly"] and len(body) > TEXT_ONLY_BODY:
                    raise Refuse("textonly", f"{chan} só aceita texto (áudio e mensagens enormes estão bloqueados)")
                if policy["slow"]:
                    now = time.monotonic()
                    wait = policy["slow"] - (now - sess.last_msg.get(chan, -1e9))
                    if wait > 0:
                        raise Refuse("slow", f"{chan} está em modo lento: aguarde {int(wait) + 1}s")
                    sess.last_msg[chan] = now
        if "h" in msg:
            self._store_history(sess, chan, msg["h"])      # encrypted copy, kept only if history is on
        frame = {"t": "msg", "chan": chan, "from": sess.nick, "body": body}
        self.counters["chan_msgs"] += 1
        for other in self.members.get(chan, {}).values():
            if other is not sess:
                self.counters["deliveries"] += 1
                other.send(frame)

    # --------------------------------------------------- channel moderation

    def _chan_target(self, sess: Session, chan: str, nick) -> tuple[str, Session | None, int]:
        """Resolve a moderation target and make sure it ranks below the actor."""
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido")
        key = nick.lower()
        if key == sess.key:
            raise Refuse("denied", "não em você mesmo")
        other = self.members.get(chan, {}).get(key)
        if other:
            rank = self._power(other, chan)
        else:
            row = self.db.execute("SELECT role FROM users WHERE nick_lower=?", (key,)).fetchone()
            if not row:
                raise Refuse("no_user", f"'{nick}' não está no canal nem é um nick registrado")
            rank = 3 if row[0] == "admin" else max(CHAN_RANK.get(self.chan_role(chan, key), 0),
                                                   2 if row[0] == "mod" else 0)
        if rank >= self._power(sess, chan):
            raise Refuse("denied", "você não pode agir sobre alguém com cargo igual ou maior que o seu")
        return key, other, rank

    def _op_chan_role(self, sess: Session, msg: dict) -> dict:
        chan, role = msg.get("chan"), msg.get("role")
        if role not in ("owner", "op", "voice", "member", None):
            raise Refuse("bad_request", "cargo inválido")
        # Ops hand out voice; only the owner makes or unmakes ops.
        self._need(sess, chan, 2)
        key, other, rank = self._chan_target(sess, chan, msg.get("nick"))
        if role in ("owner", "op") or rank >= 2:
            self._need(sess, chan, 3)
        row = self.db.execute("SELECT nick FROM users WHERE nick_lower=?", (key,)).fetchone()
        if not row:
            raise Refuse("denied", "cargos só podem ser dados a nicks registrados")
        nick = row[0]
        if role == "owner":
            # Ownership is transferred, not shared.
            for (old,) in self.db.execute("SELECT nick_lower FROM chan_roles WHERE chan=? AND role='owner'",
                                          (chan,)).fetchall():
                self._set_chan_role(chan, old, "op")
                old_sess = self.sessions.get(old)
                self._chan_send(chan, {"t": "chan_role", "chan": chan, "nick": old_sess.nick if old_sess else old,
                                       "role": "op", "by": sess.nick})
        self._set_chan_role(chan, key, role)
        self._chan_send(chan, {"t": "chan_role", "chan": chan, "nick": nick,
                               "role": role if role != "member" else None, "by": sess.nick})
        return {"nick": nick, "role": role}

    def _op_kick(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        self._need(sess, chan, 2)
        _, other, _ = self._chan_target(sess, chan, msg.get("nick"))
        if not other:
            raise Refuse("state", "essa pessoa não está no canal")
        self.counters["kicks"] += 1
        other.send({"t": "kicked_from", "chan": chan, "by": sess.nick})
        self._leave(other, chan, kicked_by=sess.nick)
        return {"nick": other.nick}

    def _op_chan_ban(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        self._need(sess, chan, 2)
        nick = msg.get("nick")
        if not msg.get("on", True):
            if not valid_nick(nick):
                raise Refuse("bad_nick", "nickname inválido")
            removed = self.db.execute("DELETE FROM chan_bans WHERE chan=? AND nick_lower=?",
                                      (chan, nick.lower())).rowcount
            removed += self.chan_guest_bans.get(chan, {}).pop(nick.lower(), None) is not None
            self.db.commit()
            if not removed:
                raise Refuse("no_ban", f"{nick} não está banido de {chan}")
            return {"nick": nick, "on": False}
        key, other, _ = self._chan_target(sess, chan, nick)
        if other and other.guest:
            self.chan_guest_bans.setdefault(chan, {})[key] = other.ip
        else:
            self.db.execute("INSERT OR IGNORE INTO chan_bans VALUES (?,?)", (chan, key))
            self.db.execute("DELETE FROM chan_roles WHERE chan=? AND nick_lower=?", (chan, key))
            self.db.commit()
        self.counters["bans"] += 1
        if other:
            other.send({"t": "kicked_from", "chan": chan, "by": sess.nick, "banned": True})
            self._leave(other, chan, kicked_by=sess.nick)
        return {"nick": other.nick if other else nick, "on": True}

    def _op_chan_bans(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        self._need(sess, chan, 2)
        nicks = [r[0] for r in self.db.execute("SELECT nick_lower FROM chan_bans WHERE chan=? ORDER BY 1", (chan,))]
        return {"bans": nicks + sorted(self.chan_guest_bans.get(chan, {}))}

    def _op_chan_roles(self, sess: Session, msg: dict) -> dict:
        chan = msg.get("chan")
        if chan not in sess.channels:
            raise Refuse("state", "você não está neste canal")
        rows = self.db.execute("SELECT u.nick, r.role FROM chan_roles r JOIN users u USING (nick_lower) "
                               "WHERE r.chan=? ORDER BY r.role, u.nick", (chan,)).fetchall()
        return {"roles": [[nick, role] for nick, role in rows]}

    def set_policy(self, chan: str, changes: dict) -> dict:
        policy = dict(self.policy(chan))
        if changes.get("history"):
            row = self.db.execute("SELECT private FROM channels WHERE name=?", (chan,)).fetchone()
            if not row or not row[0]:
                raise Refuse("bad_request", "histórico só existe em canais privados (a chave vem da senha do canal)")
        for name, value in changes.items():
            if name not in DEFAULT_POLICY:
                raise Refuse("bad_request", f"política desconhecida: {name}")
            if isinstance(DEFAULT_POLICY[name], bool):
                policy[name] = bool(value)
            else:
                top = {"slow": 3600, "ttl": MAX_TTL,
                       "history": int(self.limits["history_max_days"])}.get(name, MAX_CHANNEL_MEMBERS)
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= top:
                    raise Refuse("bad_request", f"valor inválido para {name} (0 a {top})")
                policy[name] = value
        self.db.execute("UPDATE channels SET policy=? WHERE name=?", (json.dumps(policy), chan))
        if not policy["history"]:
            self.db.execute("DELETE FROM history WHERE chan=?", (chan,))      # off means gone
        elif policy["history"] < dict(self._policies.get(chan) or {}).get("history", 0):
            limit = int(time.time()) + policy["history"] * 86400
            self.db.execute("UPDATE history SET expires=MIN(expires, ?) WHERE chan=?", (limit, chan))
        self.db.commit()
        self._policies[chan] = policy
        if not policy["history"] or "history" in changes:
            self.purge_history()
        return policy

    # --------------------------------------------- private-channel history

    def epoch(self, chan: str) -> int:
        row = self.db.execute("SELECT epoch FROM channels WHERE name=?", (chan,)).fetchone()
        return row[0] if row else 0

    def purge_history(self) -> int:
        """Really delete expired history (secure_delete overwrites the pages), and
        apply lowered limits to every channel (off the message path)."""
        cur = self.db.execute("DELETE FROM history WHERE expires <= ?", (int(time.time()),))
        self.db.commit()
        removed = cur.rowcount
        for (chan,) in self.db.execute("SELECT DISTINCT chan FROM history").fetchall():
            removed += self.trim_history(chan)
        return removed

    async def _purge_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                self.purge_history()
            except sqlite3.Error:
                pass

    def _store_history(self, sess: Session, chan: str, copy) -> None:
        policy = self.policy(chan)
        if not policy["history"] or not isinstance(copy, str) or len(copy) > HISTORY_BODY:
            return
        if sess.guest and not policy["history_anon"]:
            return                     # throwaway identities only write where they may also read
        try:
            blob = b64d(copy)
        except ProtocolError:
            return
        now = int(time.time())
        expires = now + policy["history"] * 86400
        if policy["ttl"]:
            expires = min(expires, now + policy["ttl"])
        self.db.execute("INSERT INTO history (chan, ts, expires, epoch, blob, sender) VALUES (?,?,?,?,?,?)",
                        (chan, now, expires, self.epoch(chan), blob, sess.key))
        self.trim_history(chan)

    @staticmethod
    def _history_group(sender: str) -> str:
        """Who counts as one sender for the history quotas. All anonymous
        identities together are one: they are free and disposable, so counting
        them apart would let a crowd of one-line identities erase everyone else."""
        return "anon" if is_guest_nick(sender) else sender

    def trim_history(self, chan: str) -> int:
        """Apply history_per_sender and history_keep_msgs to one channel in a single
        pass and a single DELETE. Over the channel limit, lines come out of the
        biggest groups first (each loses its oldest), never simply the oldest lines
        of the channel, so flooding with many accounts only pushes the flooders out."""
        rows = self.db.execute("SELECT id, sender FROM history WHERE chan=? ORDER BY id DESC", (chan,)).fetchall()
        groups: dict[str, list[int]] = {}
        for ident, sender in rows:                       # each group newest first
            groups.setdefault(self._history_group(sender), []).append(ident)
        per_group = int(self.limits["history_per_sender"])
        keep = int(self.limits["history_keep_msgs"])
        quota = {g: min(len(ids), per_group) for g, ids in groups.items()}
        if sum(quota.values()) > keep:
            # water-filling: the largest level t such that sum(min(q, t)) <= keep;
            # the room left goes one line each to the groups above t whose oldest
            # kept line is newest (the same order as removing one line at a time)
            low, high = 0, max(quota.values())
            while low < high:
                mid = (low + high + 1) // 2
                if sum(min(q, mid) for q in quota.values()) <= keep:
                    low = mid
                else:
                    high = mid - 1
            level = {g: min(q, low) for g, q in quota.items()}
            room = keep - sum(level.values())
            above = sorted((g for g, q in quota.items() if q > low), key=lambda g: groups[g][low], reverse=True)
            for g in above[:room]:
                level[g] += 1
            quota = level
        doomed = [ident for g, ids in groups.items() for ident in ids[quota[g]:]]
        for start in range(0, len(doomed), 500):
            chunk = doomed[start:start + 500]
            # only the "?" placeholders are formatted in; the ids go as parameters
            self.db.execute(f"DELETE FROM history WHERE id IN ({','.join('?' * len(chunk))})", chunk)  # nosec B608
        self.db.commit()
        return len(doomed)

    def history_for(self, sess: Session, chan: str) -> list[dict]:
        policy = self.policy(chan)
        if not policy["history"] or (sess.guest and not policy["history_anon"]):
            return []
        now = int(time.time())
        limit = int(self.limits["history_max_msgs"])
        # round robin between senders, newest first: each round takes the next newest
        # line of every sender that still has one. Copies the server cannot check (it
        # has no key) never crowd out anyone: a sender with few lines always gets them
        # in before one with many gets a second, third... slot
        rows = self.db.execute("SELECT id, ts, expires, epoch, blob, sender, reenc FROM history "
                               "WHERE chan=? AND expires > ? AND epoch=? ORDER BY id DESC",
                               (chan, now, self.epoch(chan))).fetchall()
        by_sender: dict[str, list] = {}
        for row in rows:                         # anonymous identities share one queue
            by_sender.setdefault(self._history_group(row[5]), []).append(row)
        queues = list(by_sender.values())        # each newest first; senders by their newest line
        chosen: list = []
        depth = 0
        while len(chosen) < limit and queues:
            queues = [q for q in queues if len(q) > depth]
            for queue in queues[:limit - len(chosen)]:
                chosen.append(queue[depth])
            depth += 1
        chosen.sort(key=lambda row: row[0])
        return [{"ts": ts, "expires": exp, "epoch": ep, "h": b64e(bytes(blob)), "from": sender, "re": bool(reenc)}
                for _, ts, exp, ep, blob, sender, reenc in chosen]

    def _op_history_dump(self, sess: Session, msg: dict) -> dict:
        """Everything stored for the channel, for the owner to re-encrypt on a password change."""
        chan = msg.get("chan")
        self._need(sess, chan, 3)
        rows = self.db.execute("SELECT id, epoch, blob, sender, reenc FROM history WHERE chan=? AND expires > ?",
                               (chan, int(time.time()))).fetchall()
        return {"rows": [{"id": i, "epoch": e, "h": b64e(bytes(b)), "from": s, "re": bool(r)}
                         for i, e, b, s, r in rows]}

    def _op_chan_pass(self, sess: Session, msg: dict) -> dict:
        """The owner changes the password: new salt and verifier, new epoch. Old
        history is deleted unless the owner re-encrypted it with the new key, and
        everyone else leaves the channel and must come back with the new password."""
        chan = msg.get("chan")
        self._need(sess, chan, 3)
        row = self._chan_row(chan)
        if not row or not row[0]:
            raise Refuse("bad_request", "só canais privados têm senha")
        try:
            salt = b64d(msg.get("salt"), 16)
            verifier = b64d(msg.get("verifier"), 32)
        except ProtocolError:
            raise Refuse("bad_request", "parâmetros da nova senha inválidos")
        epoch = self.epoch(chan) + 1
        kept = 0
        for item in msg.get("reencrypt") or []:
            try:
                blob = b64d(item["h"])
                ident = int(item["id"])
            except (KeyError, TypeError, ValueError, ProtocolError):
                continue
            if len(item["h"]) <= HISTORY_BODY:
                # marked as re-encrypted: only these may carry a line signed in an older epoch
                kept += self.db.execute("UPDATE history SET blob=?, epoch=?, reenc=1 WHERE id=? AND chan=?",
                                        (blob, epoch, ident, chan)).rowcount
        self.db.execute("DELETE FROM history WHERE chan=? AND epoch<?", (chan, epoch))
        self.db.execute("UPDATE channels SET salt=?, verifier=?, epoch=? WHERE name=?", (salt, verifier, epoch, chan))
        self.db.commit()
        for other in list(self.members.get(chan, {}).values()):
            if other is not sess:
                other.send({"t": "kicked_from", "chan": chan, "by": sess.nick,
                            "msg": "a senha do canal mudou: entre de novo com a nova senha"})
                self._leave(other, chan, kicked_by=sess.nick)
        return {"epoch": epoch, "kept": kept}

    def _op_policy(self, sess: Session, msg: dict) -> dict:
        chan, changes = msg.get("chan"), msg.get("set")
        if chan not in sess.channels:
            raise Refuse("state", "você não está neste canal")
        if not changes:
            return {"policy": self.policy(chan)}
        self._need(sess, chan, 2)
        if not isinstance(changes, dict):
            raise Refuse("bad_request", "políticas inválidas")
        policy = self.set_policy(chan, changes)
        self._chan_send(chan, {"t": "policy", "chan": chan, "policy": policy, "by": sess.nick})
        return {"policy": policy}

    def _op_invite(self, sess: Session, msg: dict) -> dict:
        chan, nick = msg.get("chan"), msg.get("nick")
        self._need(sess, chan, 2)
        if not valid_nick(nick):
            raise Refuse("bad_nick", "nickname inválido")
        row = self.db.execute("SELECT nick FROM users WHERE nick_lower=?", (nick.lower(),)).fetchone()
        if not row:
            raise Refuse("no_user", "só nicks registrados podem ser convidados")
        if self.chan_role(chan, nick.lower()) is None:
            self._set_chan_role(chan, nick.lower(), "member")
        self.db.execute("DELETE FROM chan_bans WHERE chan=? AND nick_lower=?", (chan, nick.lower()))
        self.db.commit()
        other = self.sessions.get(nick.lower())
        if other:
            other.send({"t": "invited", "chan": chan, "by": sess.nick})
        return {"nick": row[0], "online": bool(other)}

    # ----------------------------------------------------- admin (console)

    def admin(self, req: dict) -> dict:
        """Requests from the local admin console (see admin.py). Trusted: the
        socket is only reachable by the user that runs the server."""
        op = req.get("op")
        handler = getattr(self, "_admin_" + str(op), None)
        if handler is None:
            return {"error": f"operação desconhecida: {op}"}
        try:
            return {"ok": True, **(handler(req) or {})}
        except Refuse as exc:
            return {"error": exc.msg}
        except (KeyError, TypeError, ValueError) as exc:
            return {"error": f"pedido inválido: {exc}"}

    def _admin_overview(self, req: dict) -> dict:
        count = lambda sql: self.db.execute(sql).fetchone()[0]  # noqa: E731
        return {
            "name": self.name, "uptime": int(time.time() - self.started), "guests_allowed": self.allow_guests,
            "online": len(self.sessions), "guests": sum(1 for s in self.sessions.values() if s.guest),
            "nicks": count("SELECT COUNT(*) FROM users"),
            "staff": count("SELECT COUNT(*) FROM users WHERE role != 'user'"),
            "banned": count("SELECT COUNT(*) FROM users WHERE banned_until IS NOT NULL"),
            "ip_bans": count("SELECT COUNT(*) FROM ip_bans"),
            "channels": count("SELECT COUNT(*) FROM channels"), "active_channels": len(self.members),
        }

    def _admin_health(self, req: dict) -> dict:
        """Operational health, aggregated: counts only, no nick, address or content."""
        now = time.time()
        count = lambda sql, *a: self.db.execute(sql, a).fetchone()[0]  # noqa: E731
        sessions = list(self.sessions.values())
        versions = Counter(s.client_version or "antiga (não informa)" for s in sessions)
        recent = {"10min": Counter(), "1h": Counter()}
        for when, action in self.rl_events:
            if now - when <= 3600:
                recent["1h"][action] += 1
                if now - when <= 600:
                    recent["10min"][action] += 1
        c = self.counters
        return {"health": {
            "version": __version__, "uptime": int(now - self.started), "tls": self.tls,
            "online": {"registered": sum(1 for s in sessions if not s.guest),
                       "anonymous": sum(1 for s in sessions if s.guest),
                       "peak": self.peak_sessions, "connections": self.open_conns},
            "channels": {"total": count("SELECT COUNT(*) FROM channels"),
                         "private": count("SELECT COUNT(*) FROM channels WHERE private=1"),
                         "active": len(self.members),
                         "with_history": sum(1 for (name,) in self.db.execute("SELECT name FROM channels")
                                             if self.policy(name).get("history")),
                         "history_rows": count("SELECT COUNT(*) FROM history")},
            "bans": {"users": count("SELECT COUNT(*) FROM users WHERE banned_until IS NOT NULL "
                                    "AND (banned_until = 0 OR banned_until > ?)", int(now)),
                     "addresses": count("SELECT COUNT(*) FROM ip_bans WHERE until = 0 OR until > ?", int(now)),
                     "channel": count("SELECT COUNT(*) FROM chan_bans")
                     + sum(len(v) for v in self.chan_guest_bans.values())},
            "ratelimit": {"total": {"refused": c["rate_limited"], "warn": c["rl_warn"], "mute": c["rl_mute"],
                                    "kick": c["rl_kick"], "conn_refused": c["conn_refused"]},
                          "10min": dict(recent["10min"]), "1h": dict(recent["1h"])},
            "transfers": len(self.transfers),
            "versions": dict(sorted(versions.items())),
        }}

    def _user_row(self, row) -> dict:
        nick, role, until, reason, created = row
        sess = self.sessions.get(nick.lower())
        return {"nick": nick, "role": role, "online": bool(sess), "away": bool(sess and sess.away),
                "banned": until is not None, "banned_until": until, "ban_reason": reason, "created": created,
                "channels": sorted(sess.channels) if sess else []}

    def _admin_users(self, req: dict) -> dict:
        query = f"%{str(req.get('query') or '').lower()}%"
        rows = self.db.execute("SELECT nick, role, banned_until, ban_reason, created FROM users "
                               "WHERE nick_lower LIKE ? ORDER BY nick_lower LIMIT 500", (query,)).fetchall()
        users = [self._user_row(r) for r in rows]
        if req.get("filter") == "online":
            users = [u for u in users if u["online"]]
        elif req.get("filter") == "staff":
            users = [u for u in users if u["role"] != "user"]
        elif req.get("filter") == "banned":
            users = [u for u in users if u["banned"]]
        guests = [{"nick": s.nick, "role": "anônimo", "online": True, "away": s.away, "banned": False,
                   "channels": sorted(s.channels)} for s in self.sessions.values() if s.guest
                  and str(req.get("query") or "").lower() in s.key] if req.get("filter") in (None, "online") else []
        return {"users": users + guests}

    def _admin_user(self, req: dict) -> dict:
        nick = str(req["nick"])
        row = self.db.execute("SELECT nick, role, banned_until, ban_reason, created FROM users WHERE nick_lower=?",
                              (nick.lower(),)).fetchone()
        if not row:
            sess = self.sessions.get(nick.lower())
            if not sess:
                raise Refuse("no_user", f"'{nick}' não existe")
            return {"user": {"nick": sess.nick, "role": "anônimo", "online": True, "away": sess.away,
                             "banned": False, "channels": sorted(sess.channels), "chan_roles": []}}
        user = self._user_row(row)
        user["chan_roles"] = [list(r) for r in self.db.execute(
            "SELECT chan, role FROM chan_roles WHERE nick_lower=? ORDER BY chan", (nick.lower(),))]
        return {"user": user}

    def _admin_role(self, req: dict) -> dict:
        nick, role = str(req["nick"]), req["role"]
        if role not in GLOBAL_ROLES:
            raise Refuse("bad_request", f"cargo inválido (use {', '.join(GLOBAL_ROLES)})")
        cur = self.db.execute("UPDATE users SET role=? WHERE nick_lower=?", (role, nick.lower()))
        self.db.commit()
        if not cur.rowcount:
            raise Refuse("no_user", f"'{nick}' não é um nick registrado")
        sess = self.sessions.get(nick.lower())
        if sess:
            sess.role = role
            sess.send({"t": "role", "role": role})
        return {"nick": nick, "role": role, "online": bool(sess)}

    def _admin_ban(self, req: dict) -> dict:
        return self.ban(str(req["nick"]), int(req.get("minutes") or 0), str(req.get("reason") or ""),
                        bool(req.get("ip")))

    def _admin_unban(self, req: dict) -> dict:
        return self.unban(str(req["nick"]))

    def _admin_kick(self, req: dict) -> dict:
        sess = self.sessions.get(str(req["nick"]).lower())
        if not sess:
            raise Refuse("offline", f"{req['nick']} está offline")
        self.counters["kicks"] += 1
        self._disconnect(sess, {"t": "kicked", "msg": "desconectado pela administração do servidor"})
        return {"nick": sess.nick}

    def _admin_bans(self, req: dict) -> dict:
        users = [{"nick": n, "until": u, "reason": r} for n, u, r in self.db.execute(
            "SELECT nick, banned_until, ban_reason FROM users WHERE banned_until IS NOT NULL ORDER BY nick_lower")]
        ips = [{"label": label, "until": u, "reason": r} for label, u, r in self.db.execute(
            "SELECT label, until, reason FROM ip_bans ORDER BY created")]
        return {"users": users, "ips": ips}

    def _admin_channels(self, req: dict) -> dict:
        out = []
        for name, private in self.db.execute("SELECT name, private FROM channels ORDER BY name"):
            owner = self.db.execute("SELECT u.nick FROM chan_roles r JOIN users u USING (nick_lower) "
                                    "WHERE r.chan=? AND r.role='owner'", (name,)).fetchone()
            active = [k for k, v in self.policy(name).items() if v]
            out.append({"name": name, "private": bool(private), "online": len(self.members.get(name, {})),
                        "owner": owner[0] if owner else None, "policy": active})
        return {"channels": out}

    def _admin_channel(self, req: dict) -> dict:
        chan = str(req["chan"])
        row = self._chan_row(chan)
        if not row:
            raise Refuse("no_chan", "canal não existe")
        roles = [list(r) for r in self.db.execute(
            "SELECT u.nick, r.role FROM chan_roles r JOIN users u USING (nick_lower) WHERE r.chan=? "
            "ORDER BY r.role, u.nick", (chan,))]
        bans = [r[0] for r in self.db.execute("SELECT nick_lower FROM chan_bans WHERE chan=?", (chan,))]
        return {"channel": {"name": chan, "private": bool(row[0]), "policy": self.policy(chan), "roles": roles,
                            "bans": bans + sorted(self.chan_guest_bans.get(chan, {})),
                            "online": [m.nick for m in self.members.get(chan, {}).values()],
                            "epoch": self.epoch(chan),
                            "history_rows": self.db.execute("SELECT COUNT(*) FROM history WHERE chan=?",
                                                            (chan,)).fetchone()[0]}}

    def _admin_chan_role(self, req: dict) -> dict:
        chan, nick, role = str(req["chan"]), str(req["nick"]), req.get("role")
        if not self._chan_row(chan):
            raise Refuse("no_chan", "canal não existe")
        if role not in ("owner", "op", "voice", "member", None):
            raise Refuse("bad_request", "cargo inválido (owner, op, voice, member ou none)")
        row = self.db.execute("SELECT nick FROM users WHERE nick_lower=?", (nick.lower(),)).fetchone()
        if not row:
            raise Refuse("no_user", f"'{nick}' não é um nick registrado")
        if role == "owner":
            self.db.execute("UPDATE chan_roles SET role='op' WHERE chan=? AND role='owner'", (chan,))
        self._set_chan_role(chan, nick.lower(), role)
        self._chan_send(chan, {"t": "chan_role", "chan": chan, "nick": row[0],
                               "role": role if role != "member" else None, "by": "servidor"})
        return {"chan": chan, "nick": row[0], "role": role}

    def _admin_chan_policy(self, req: dict) -> dict:
        chan = str(req["chan"])
        if not self._chan_row(chan):
            raise Refuse("no_chan", "canal não existe")
        policy = self.set_policy(chan, dict(req["set"]))
        self._chan_send(chan, {"t": "policy", "chan": chan, "policy": policy, "by": "servidor"})
        return {"policy": policy}

    def _admin_chan_unban(self, req: dict) -> dict:
        chan, nick = str(req["chan"]), str(req["nick"]).lower()
        removed = self.db.execute("DELETE FROM chan_bans WHERE chan=? AND nick_lower=?", (chan, nick)).rowcount
        removed += self.chan_guest_bans.get(chan, {}).pop(nick, None) is not None
        self.db.commit()
        if not removed:
            raise Refuse("no_ban", "esse nick não está banido do canal")
        return {"chan": chan, "nick": nick}

    def _admin_update_repo(self, req: dict) -> dict:
        """Release repository suggested to clients. Clients never switch to it
        without their user's confirmation, and they check signatures anyway."""
        if "repo" in req:
            repo = req["repo"]
            if repo in (None, "", "none"):
                self.db.execute("DELETE FROM meta WHERE key='client_repo'")
                repo = None
            else:
                repo = str(repo)
                from .update import valid_source
                if not valid_source(repo):   # https:// or github:owner/name, never http:// or a local path
                    raise Refuse("bad_request", "use https://… (ex.: https://crptochat.acpt.app.br/downloads/) "
                                                "ou github:dono/repositório")
                self.db.execute("INSERT OR REPLACE INTO meta VALUES ('client_repo', ?)", (repo,))
            self.db.commit()
            self.client_repo = repo
            for sess in self.sessions.values():
                sess.send({"t": "client_repo", "repo": repo})
        return {"repo": self.client_repo}

    def _admin_ratelimit(self, req: dict) -> dict:
        from .ratelimit import DEFAULTS, SETTINGS
        try:
            if "set" in req:
                for name, value in dict(req["set"]).items():
                    if name in ("file_burst_kb", "anon_file_burst_kb") and 0 <= float(value) < 128:
                        raise Refuse("bad_request", f"{name} precisa ser pelo menos 128: cada bloco de "
                                                    "arquivo cifrado tem 64 KiB")
                    if name == "out_queue_kb" and 0 <= float(value) < 1024:
                        raise Refuse("bad_request", "out_queue_kb precisa ser pelo menos 1024 (1 MiB)")
                    if name == "max_body_kb" and 0 <= float(value) < 32:
                        raise Refuse("bad_request", "max_body_kb precisa ser pelo menos 32: cada envelope de "
                                                    "áudio cifrado tem cerca de 27 KiB")
                    self.limits.set(str(name), value)
            if "reset" in req:
                self.limits.reset(None if req["reset"] in (None, "all") else str(req["reset"]))
        except KeyError as exc:
            raise Refuse("bad_request", f"limite desconhecido: {exc.args[0]}") from None
        except (ValueError, TypeError):
            raise Refuse("bad_request", "valor inválido (use um número maior ou igual a zero)") from None
        if "set" in req or "reset" in req:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES ('ratelimit', ?)", (json.dumps(self.limits.changed()),))
            self.db.commit()
        c = self.counters
        return {"limits": dict(self.limits.values), "defaults": DEFAULTS,
                "descriptions": {k: d for k, (_, d) in SETTINGS.items()},
                "stats": {"refused": c["rate_limited"], "warn": c["rl_warn"], "mute": c["rl_mute"],
                          "kick": c["rl_kick"], "conn_refused": c["conn_refused"]}}

    def _admin_guests(self, req: dict) -> dict:
        self.allow_guests = bool(req["on"])
        return {"guests_allowed": self.allow_guests}

    def _admin_notice(self, req: dict) -> dict:
        text = str(req["text"])[:500]
        for sess in self.sessions.values():
            sess.send({"t": "notice", "text": text})
        return {"sent": len(self.sessions)}


# ------------------------------------------------------------------ TLS

def ensure_cert(data_dir: str) -> tuple[str, str]:
    """Create a long-lived self-signed certificate on first run."""
    cert_path = os.path.join(data_dir, "tls_cert.pem")
    key_path = os.path.join(data_dir, "tls_key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crptochat")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def cert_fingerprint(cert_path: str) -> str:
    with open(cert_path, "rb") as fh:
        der = ssl.PEM_cert_to_DER_cert(fh.read().decode())
    return hashlib.sha256(der).hexdigest()


def make_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


# ------------------------------------------------------------------ CLI

VERSION_RE = re.compile(r"\d{1,3}(\.\d{1,4}){0,3}")
BANNER = "\033[38;5;199m▓▒░\033[0m \033[1;38;5;51mCRPTOCHAT\033[0m \033[38;5;199m░▒▓\033[0m relay v" + __version__


async def _amain(args) -> None:
    server = Server(args.data, name=args.name, motd=args.motd, reg_token=args.reg_token,
                    reg_limit=args.reg_limit, allow_guests=not args.no_guests)
    ssl_ctx = None
    print(BANNER)
    if not args.no_tls:
        cert, key = (args.cert, args.key) if args.cert and args.key else ensure_cert(args.data)
        ssl_ctx = make_ssl_context(cert, key)
        print(f"  TLS 1.3 ativo · fingerprint do certificado (SHA-256):\n  \033[38;5;51m{cert_fingerprint(cert)}\033[0m")
    else:
        print("  \033[38;5;214mTLS desativado\033[0m: o conteúdo continua E2EE, mas metadados trafegam em claro")
    port = await server.start(args.host, args.port, ssl_ctx)
    print(f"  escutando em {args.host}:{port} · dados em {os.path.abspath(args.data)}")
    feed = None
    if not args.no_stats:
        from .stats import StatsFeed, socket_path
        feed = StatsFeed(server, socket_path(args.data))
        try:
            await feed.start()
            print(f"  painel do operador: \033[38;5;51mcrptochat-dash --data {args.data}\033[0m (só contagens agregadas)")
        except OSError as exc:
            feed = None
            print(f"  painel indisponível: {exc}")
    print("  o servidor não armazena mensagens nem arquivos; apenas nicks e canais.")
    admin_sock = None
    try:
        from .admin import AdminSocket, socket_path as admin_path
        admin_sock = AdminSocket(server, admin_path(args.data))
        await admin_sock.start()
        print(f"  administração (cargos, banimentos): \033[38;5;51mcrptochat-admin --data {args.data}\033[0m")
    except OSError as exc:
        admin_sock = None
        print(f"  console de administração indisponível: {exc}")
    print("  acesso anônimo: " + ("permitido" if server.allow_guests else "bloqueado (--no-guests)"))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    print("\n  encerrando...")
    if feed:
        await feed.stop()
    if admin_sock:
        await admin_sock.stop()
    await server.stop()


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="crptochat-server", description="Servidor relay do crptochat (cego: só encaminha blobs cifrados)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""\
administração com o servidor no ar (mesmo --data):
  crptochat-admin --data DIR                      console interativo
  crptochat-admin --data DIR ratelimit            limites anti-flood (set NOME VALOR, reset all)
  crptochat-dash  --data DIR                      painel de uso (só contagens)
""")
    ap.add_argument("--host", default="0.0.0.0",  # nosec B104
                    help="endereço de escuta (padrão: 0.0.0.0)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"porta TCP (padrão: {DEFAULT_PORT})")
    ap.add_argument("--data", default="./crptochat-data", help="diretório do registro de nicks/canais e do certificado")
    ap.add_argument("--name", default="crptochat", help="nome exibido do servidor")
    ap.add_argument("--motd", default="", help="mensagem do dia")
    ap.add_argument("--no-tls", action="store_true", help="desativa TLS (não recomendado)")
    ap.add_argument("--cert", help="certificado TLS próprio (PEM)")
    ap.add_argument("--key", help="chave do certificado TLS próprio (PEM)")
    ap.add_argument("--reg-token", default=os.environ.get("CRPTOCHAT_REG_TOKEN"),
                    help="exige este token para registrar novos nicks (ou env CRPTOCHAT_REG_TOKEN)")
    ap.add_argument("--no-stats", action="store_true", help="não cria o socket local do painel (crptochat-dash)")
    ap.add_argument("--no-guests", action="store_true", help="recusa acesso anônimo (só nicks registrados)")
    ap.add_argument("--reg-limit", type=int, default=None,
                    help="nicks novos por IP por hora (0 = sem limite); sem a opção vale o configurado no "
                         "console (ratelimit set reg_per_hour N), padrão 5")
    args = ap.parse_args(argv)
    try:
        asyncio.run(_amain(args))
    except OSError as exc:
        sys.exit(f"erro: {exc}")


if __name__ == "__main__":
    main()
