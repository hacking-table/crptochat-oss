"""Files sent through the relay (the default; /send --p2p keeps the direct mode).

    sender                     server (memory only)              recipient
      │ file_open(id, to, size) ─▶ remembers the pair
      │ E2E offer {name, size, sha256, key, ttl} ──────────────────▶ /accept: picks a folder
      │                          ◀── file_accept(id)
      │ ◀── file_go(id)
      │ file_chunk(id, i, d) ───▶ forwards to the recipient ───────▶ decrypts, writes .part
      │ ◀── file_ack(id, i) ◀──── relays ack ◀─────────────────────── every few chunks
      │                                                               last: size + SHA-256 checked

The file key, name and hash travel inside the end-to-end encrypted offer;
the server only sees opaque chunks and their count. Nothing reaches the
recipient before it accepts, and the server never writes anything to disk.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import time

from . import crypto
from .crypto import FILE_CHUNK, CryptoError
from .protocol import MAX_TTL

OFFER_TTL = 900               # an offer not accepted in 15 min expires
ACK_EVERY = 4
DEFAULT_WINDOW = 16
_BAD = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]')
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def safe_name(name: str) -> str:
    """A file name that is safe to create anywhere: no directories, no traversal,
    no control or shell-hostile characters, no hidden or reserved names."""
    name = str(name).replace("\\", "/").rsplit("/", 1)[-1]
    name = _BAD.sub("_", name).strip().lstrip(".").strip()
    if name.split(".")[0].lower() in _RESERVED:
        name = "_" + name
    return name[:200] or "arquivo"


def unique_path(folder: str, name: str) -> str:
    folder = os.path.realpath(os.path.expanduser(folder))
    base, ext = os.path.splitext(name)
    path, count = os.path.join(folder, name), 1
    while os.path.exists(path) or os.path.exists(path + ".part"):
        path = os.path.join(folder, f"{base}.{count}{ext}")
        count += 1
    if os.path.dirname(os.path.realpath(path)) != folder:      # belt and braces against traversal
        raise ValueError("caminho fora da pasta escolhida")
    return path


class RelayTransfer:
    def __init__(self, tid: str, peer, name: str, size: int, sha: str, key: bytes, outgoing: bool):
        self.id, self.peer, self.name, self.size, self.sha, self.key = tid, peer, name, size, sha, key
        self.outgoing = outgoing
        self.state = "offered"        # offered -> active -> done | failed
        self.path = ""                # source (outgoing) or final destination (incoming)
        self.part = ""
        self.chan = None
        self.ttl = 0
        self.expires = time.time() + OFFER_TTL
        self.done = 0
        self.index = 0
        self.acked = -1
        self.hasher = hashlib.sha256()
        self.fh = None
        self.wake = asyncio.Event()

    @property
    def short(self) -> str:
        return self.id[:6]


class RelayFiles:
    def __init__(self, client):
        self.client = client
        self.transfers: dict[str, RelayTransfer] = {}

    # ------------------------------------------------------------ helpers

    def _note(self, tr: RelayTransfer, text: str, level: str = "info") -> None:
        buffer = tr.chan or "@" + tr.peer.nick
        self.client.sys(f"[arquivo {tr.short}] {text}", level, buffer)

    def _progress(self, tr: RelayTransfer) -> None:
        self.client.emit("transfer", id=tr.short, name=tr.name, nick=tr.peer.nick, done=tr.done,
                         total=tr.size, outgoing=tr.outgoing, state=tr.state)

    def _fail(self, tr: RelayTransfer, why: str, tell_server: bool = True) -> None:
        if tr.state in ("done", "failed"):
            return
        tr.state = "failed"
        if tr.fh:
            tr.fh.close()
            tr.fh = None
        if tr.part:
            try:
                os.remove(tr.part)
            except OSError:
                pass
        tr.wake.set()
        if tell_server and self.client.online:
            try:
                self.client._send({"t": "file_cancel", "tid": tr.id, "msg": why[:100]})
            except Exception:
                pass
        self._note(tr, f"transferência encerrada: {why}", "err")
        self._progress(tr)

    def pending(self) -> list[RelayTransfer]:
        now = time.time()
        return [t for t in self.transfers.values() if not t.outgoing and t.state == "offered" and t.expires > now]

    def find(self, short: str | None) -> RelayTransfer | None:
        found = [t for t in self.pending() if not short or t.id.startswith(short.lower())]
        return found[-1] if found else None

    def limits(self) -> tuple[int, float, int]:
        """(max size, KiB/s, window) as announced by the server, which is not
        trusted: anything that is not a sane number falls back to a default."""
        lim = self.client.server_limits

        def number(key, default, low, high):
            value = lim.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
                return default
            return min(max(value, low), high)

        kbps = number("anon_file_kbps" if self.client.guest else "file_kbps", 2048, 1, 10 ** 6)
        window = int(number("file_window", DEFAULT_WINDOW, 1, 64))
        return int(number("file_max", 0, 0, 2 ** 40)), float(kbps), window

    # ------------------------------------------------------------- sending

    async def offer(self, target: str, path: str) -> list[str]:
        """Offer a file to a nick or to every capable member of a channel."""
        from .client import ChatError
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise ChatError(f"arquivo não encontrado: {path}")
        if "relayfile" not in self.client.server_caps:
            raise ChatError("este servidor não repassa arquivos; use /send --p2p (expõe seu IP ao outro lado)")
        size = os.path.getsize(path)
        cap, _, _ = self.limits()
        if cap and size > cap:
            raise ChatError(f"arquivo grande demais para este servidor (máximo {cap // (1024 * 1024)} MiB)")
        if target.startswith("#"):
            ch = self.client.channels.get(target)
            if not ch or not ch.joined:
                raise ChatError(f"você não está em {target}")
            peers = [p for p in ch.members.values() if p.trusted and p.dh]
            ttl = self.client.ttl_for(target)
        else:
            peers = [self.client._usable(await self.client.resolve(target))]
            ttl = self.client.ttl_for("@" + peers[0].nick)
        sha = await asyncio.to_thread(_sha256_file, path)
        sent, old = [], []
        for peer in peers:
            if not await self.client.peer_supports(peer, "file2"):
                old.append(peer.nick)
                continue
            tr = RelayTransfer(os.urandom(16).hex(), peer, safe_name(os.path.basename(path)), size, sha,
                               os.urandom(32), outgoing=True)
            tr.path, tr.ttl = path, ttl
            tr.chan = target if target.startswith("#") else None
            await self.client.request({"t": "file_open", "tid": tr.id, "to": peer.nick, "size": size})
            self.transfers[tr.id] = tr
            offer = {"k": "fo2", "id": tr.id, "name": tr.name, "size": size, "sha": sha,
                     "key": base64.b64encode(tr.key).decode()}
            if tr.chan:
                offer["chan"] = tr.chan
            if ttl:
                offer["ttl"] = ttl
            self.client.send_direct(peer, offer)
            sent.append(peer.nick)
        where = target if target.startswith("#") else "@" + peers[0].nick
        if sent:
            self.client.sys(f"oferta de '{os.path.basename(path)}' ({_human(size)}) enviada a {', '.join(sent)}; "
                            "o arquivo só sai quando cada pessoa aceitar", "ok", where)
        if old:
            self.client.sys(f"sem envio para {', '.join(old)}: versão antiga, sem arquivos pelo servidor "
                            f"(/send --p2p funciona com eles, mas expõe seu IP)", "warn", where)
        if not sent and not old:
            raise ChatError("ninguém para receber neste canal")
        return sent

    async def _stream(self, tr: RelayTransfer) -> None:
        """Send the file once the recipient accepted, paced to the server's limits."""
        _, kbps, window = self.limits()
        rate = max(1.0, kbps * 1024 * 0.9)            # stay just under the server's bucket
        tr.state = "active"
        started = time.monotonic()
        try:
            with open(tr.path, "rb") as fh:
                chunk = fh.read(FILE_CHUNK)
                while tr.state == "active":
                    nxt = fh.read(FILE_CHUNK)
                    last = not nxt
                    while tr.index - tr.acked > window and tr.state == "active":
                        tr.wake.clear()
                        await asyncio.wait_for(tr.wake.wait(), 60)
                    if tr.state != "active":
                        return
                    blob = crypto.file_encrypt_chunk(tr.key, tr.index, chunk, last)
                    ahead = (tr.done + len(chunk)) / rate - (time.monotonic() - started)
                    if ahead > 0:
                        await asyncio.sleep(ahead)
                    self.client._send({"t": "file_chunk", "tid": tr.id, "i": tr.index, "last": last,
                                       "d": base64.b64encode(blob).decode()})
                    tr.index += 1
                    tr.done += len(chunk)
                    if tr.index % 8 == 0 or last:
                        self._progress(tr)
                    if last:
                        break
                    chunk = nxt
        except asyncio.TimeoutError:
            self._fail(tr, "o destinatário parou de confirmar o recebimento")
        except OSError as exc:
            self._fail(tr, f"erro lendo o arquivo: {exc.strerror or exc}")

    # ----------------------------------------------------------- receiving

    def handle(self, peer, inner: dict) -> None:
        """End-to-end envelopes: an offer, or the other side giving up."""
        kind, tid = inner.get("k"), inner.get("id")
        if not isinstance(tid, str) or not re.fullmatch(r"[0-9a-f]{32}", tid):
            return
        if kind == "fx2":
            tr = self.transfers.get(tid)
            if tr and tr.peer.key == peer.key:
                self._fail(tr, f"{peer.nick} recusou ou cancelou", tell_server=False)
            return
        if kind != "fo2" or tid in self.transfers or len(self.transfers) > 500:
            return
        try:
            size, sha = int(inner["size"]), str(inner["sha"])
            key = base64.b64decode(inner["key"], validate=True)
        except (KeyError, TypeError, ValueError):
            return
        if size < 0 or len(key) != 32 or not re.fullmatch(r"[0-9a-f]{64}", sha):
            return
        tr = RelayTransfer(tid, peer, safe_name(inner.get("name") or "arquivo"), size, sha, key, outgoing=False)
        chan = inner.get("chan")
        tr.chan = chan if isinstance(chan, str) and chan in self.client.channels else None
        ttl = self.client._effective_ttl(inner.get("ttl"), self.client.ttl_for(tr.chan or "@" + peer.nick))
        tr.ttl = ttl
        tr.expires = time.time() + (min(ttl, OFFER_TTL) if ttl else OFFER_TTL)
        self.transfers[tid] = tr
        self.client.emit("file_offer", id=tr.short, nick=peer.nick, name=tr.name, size=size,
                         buffer=tr.chan or "@" + peer.nick, ttl=ttl, relay=True)

    async def accept(self, short: str | None, folder: str) -> RelayTransfer:
        from .client import ChatError
        tr = self.find(short)
        if not tr:
            raise ChatError("nenhuma oferta de arquivo pendente (ela pode ter expirado)")
        folder = os.path.expanduser(folder or self.client.files.download_dir)
        try:
            os.makedirs(folder, exist_ok=True)
            tr.path = unique_path(folder, tr.name)
            tr.part = tr.path + ".part"
            tr.fh = open(tr.part, "xb")
        except (OSError, ValueError) as exc:
            raise ChatError(f"não foi possível usar {folder}: {exc}") from None
        tr.state = "active"
        try:
            await self.client.request({"t": "file_accept", "tid": tr.id})
        except ChatError as exc:
            self._fail(tr, str(exc), tell_server=False)
            raise
        self._note(tr, f"recebendo '{tr.name}' em {tr.path} pelo servidor (cifrado ponta a ponta)…")
        return tr

    async def reject(self, short: str | None) -> None:
        from .client import ChatError
        tr = self.find(short)
        if not tr:
            raise ChatError("nenhuma oferta de arquivo pendente")
        tr.state = "failed"
        self.client._send({"t": "file_cancel", "tid": tr.id, "msg": "recusado"})
        try:
            self.client.send_direct(tr.peer, {"k": "fx2", "id": tr.id})
        except Exception:
            pass
        self._note(tr, "oferta recusada")

    # ----------------------------------------------------- server frames

    def on_go(self, msg: dict) -> None:
        tr = self.transfers.get(msg.get("tid"))
        if tr and tr.outgoing and tr.state == "offered":
            self._note(tr, f"{tr.peer.nick} aceitou; enviando '{tr.name}' pelo servidor…")
            self.client.spawn(self._stream(tr))

    def on_ack(self, msg: dict) -> None:
        tr = self.transfers.get(msg.get("tid"))
        if not tr or not tr.outgoing or not isinstance(msg.get("i"), int):
            return
        tr.acked = max(tr.acked, msg["i"])
        tr.wake.set()
        if msg.get("ok") and tr.state == "active":
            tr.state = "done"
            self._progress(tr)
            self._note(tr, f"'{tr.name}' entregue a {tr.peer.nick} e conferido por ele", "ok")

    def on_cancel(self, msg: dict) -> None:
        tr = self.transfers.get(msg.get("tid"))
        if tr:
            self._fail(tr, str(msg.get("msg") or "cancelado")[:100], tell_server=False)

    def on_chunk(self, msg: dict) -> None:
        tr = self.transfers.get(msg.get("tid"))
        if not tr or tr.outgoing or tr.state != "active" or not tr.fh:
            return
        try:
            if msg.get("i") != tr.index:
                raise CryptoError("bloco fora de ordem")
            last = bool(msg.get("last"))
            chunk = crypto.file_decrypt_chunk(tr.key, tr.index, base64.b64decode(msg["d"], validate=True), last)
            tr.done += len(chunk)
            if tr.done > tr.size:
                raise CryptoError("o arquivo é maior que o anunciado")
            tr.fh.write(chunk)
            tr.hasher.update(chunk)
        except (CryptoError, KeyError, TypeError, ValueError, OSError) as exc:
            self._fail(tr, str(exc) or "bloco inválido")
            return
        tr.index += 1
        if last:
            tr.fh.close()
            tr.fh = None
            if tr.done != tr.size or tr.hasher.hexdigest() != tr.sha:
                self._fail(tr, "o arquivo chegou diferente do anunciado (tamanho ou SHA-256 não conferem)")
                return
            os.replace(tr.part, tr.path)
            tr.part = ""
            tr.state = "done"
            self.client._send({"t": "file_ack", "tid": tr.id, "i": tr.index - 1, "ok": True})
            self._progress(tr)
            note = f"recebido e conferido (SHA-256): {tr.path} ({_human(tr.size)})"
            if tr.ttl:
                note += f" · será apagado do disco em {_duration(tr.ttl)} (mensagens temporárias)"
                self.client.spawn(self._expire(tr))
            self._note(tr, note, "ok")
            return
        if tr.index % ACK_EVERY == 0:
            self.client._send({"t": "file_ack", "tid": tr.id, "i": tr.index - 1})
            if tr.index % 8 == 0:
                self._progress(tr)

    async def _expire(self, tr: RelayTransfer) -> None:
        await asyncio.sleep(min(tr.ttl, MAX_TTL))
        try:
            os.remove(tr.path)
            self._note(tr, f"'{tr.name}' apagado do disco: o tempo das mensagens temporárias acabou", "info")
        except OSError:
            pass


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _human(n: int) -> str:
    from .p2p import human_size
    return human_size(n)


def _duration(seconds: int) -> str:
    from .protocol import format_duration
    return format_duration(seconds)
