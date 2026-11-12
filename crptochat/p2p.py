"""Peer-to-peer file transfer.

The file never touches the server. The server only relays (inside the usual
end-to-end encrypted envelope) a small offer containing a one-time key and
the sender's addresses. The receiver then opens a direct TCP connection to
the sender; if that is not possible (NAT/firewall) the roles are inverted and
the sender connects to the receiver. The byte stream itself is encrypted in
64 KiB ChaCha20-Poly1305 chunks with the one-time key.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time

from . import crypto
from .crypto import FILE_CHUNK, CryptoError
from .protocol import ProtocolError, b64d, b64e

CONNECT_TIMEOUT = 4
OFFER_TTL = 900
ACK = b"\x06"


class Transfer:
    def __init__(self, tid: bytes, peer, name: str, size: int, key: bytes, outgoing: bool, path: str = ""):
        self.id = tid
        self.peer = peer
        self.name = name
        self.size = size
        self.key = key
        self.outgoing = outgoing
        self.path = path
        self.state = "offered"      # offered -> (waiting) -> active -> done/failed
        self.addrs: list[str] = []
        self.port = 0
        self.created = time.monotonic()

    @property
    def hex(self) -> str:
        return self.id.hex()[:6]


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def safe_name(name: str) -> str:
    name = os.path.basename(str(name).replace("\\", "/"))
    name = "".join(c for c in name if c.isprintable() and c not in '/\x00').lstrip(".").strip()
    return name[:200] or "arquivo"


class FileTransfers:
    def __init__(self, client, port: int, host: str | None, download_dir: str):
        self.client = client
        self.port_pref = port
        self.host_pref = host
        self.download_dir = download_dir
        self.transfers: dict[bytes, Transfer] = {}
        self._listener: asyncio.AbstractServer | None = None
        self._port = 0

    # ----------------------------------------------------------- plumbing

    async def close(self) -> None:
        if self._listener:
            self._listener.close()
            self._listener = None

    async def _listen(self) -> int:
        if not self._listener:
            # direct transfers (--p2p only) need to be reachable by the peer; open only while offering
            self._listener = await asyncio.start_server(self._on_conn, "0.0.0.0", self.port_pref)  # nosec B104
            self._port = self._listener.sockets[0].getsockname()[1]
        return self._port

    def _candidates(self) -> list[str]:
        if self.host_pref:
            return [self.host_pref]
        out = []
        for addr in (self.client.local_ip, self.client.public_ip):
            if addr and addr not in out:
                out.append(addr)
        return out

    def _note(self, tr: Transfer, text: str, level: str = "info") -> None:
        self.client.sys(f"[arquivo {tr.hex}] {text}", level, "@" + tr.peer.nick)

    def _progress(self, tr: Transfer, done: int) -> None:
        self.client.emit("transfer", id=tr.hex, name=tr.name, nick=tr.peer.nick, done=done,
                         total=tr.size, outgoing=tr.outgoing, state=tr.state)

    def _fail(self, tr: Transfer, reason: str, notify: bool = True) -> None:
        if tr.state in ("done", "failed"):
            return
        tr.state = "failed"
        self._note(tr, f"transferência falhou: {reason}", "err")
        self._progress(tr, 0)
        if notify:
            try:
                self.client.send_direct(tr.peer, {"k": "fx", "id": tr.id.hex(), "why": reason[:100]})
            except Exception:
                pass

    def _pick(self, short: str | None, outgoing: bool = False) -> Transfer:
        from .client import ChatError
        now = time.monotonic()
        found = [t for t in self.transfers.values()
                 if t.outgoing == outgoing and t.state == "offered" and now - t.created < OFFER_TTL
                 and (not short or t.id.hex().startswith(short.lower()))]
        if not found:
            raise ChatError("nenhuma oferta de arquivo pendente")
        return found[-1]

    # -------------------------------------------------------------- sender

    async def offer(self, nick: str, path: str) -> None:
        from .client import ChatError
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise ChatError(f"arquivo não encontrado: {path}")
        peer = self.client._usable(await self.client.resolve(nick))
        port = await self._listen()
        tr = Transfer(os.urandom(16), peer, safe_name(path), os.path.getsize(path), os.urandom(32), True, path)
        self.transfers[tr.id] = tr
        await self.client.request(self.client._direct_frame(peer, {
            "k": "fo", "id": tr.id.hex(), "name": tr.name, "size": tr.size, "key": b64e(tr.key),
            "addrs": self._candidates(), "port": port}))
        self._note(tr, f"oferta enviada para {peer.nick}: {tr.name} ({human_size(tr.size)}); "
                       "aguardando aceite. O arquivo irá direto entre as máquinas (P2P).")

    async def _send_stream(self, tr: Transfer, reader, writer) -> None:
        tr.state = "active"
        self._note(tr, f"conexão direta estabelecida, enviando {tr.name}…")
        try:
            sent = index = 0
            last_emit = 0.0
            with open(tr.path, "rb") as fh:
                chunk = fh.read(FILE_CHUNK)
                while True:
                    nxt = fh.read(FILE_CHUNK)
                    last = not nxt
                    blob = crypto.file_encrypt_chunk(tr.key, index, chunk, last)
                    writer.write(bytes([last]) + struct.pack(">I", len(blob)) + blob)
                    await writer.drain()
                    sent += len(chunk)
                    index += 1
                    if time.monotonic() - last_emit > 0.2:
                        last_emit = time.monotonic()
                        self._progress(tr, sent)
                    if last:
                        break
                    chunk = nxt
            if await asyncio.wait_for(reader.readexactly(1), 120) != ACK:
                raise OSError("o destinatário não confirmou o recebimento")
            tr.state = "done"
            self._progress(tr, sent)
            self._note(tr, f"{tr.name} entregue a {tr.peer.nick} ({human_size(sent)})", "ok")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            self._fail(tr, str(exc) or "conexão interrompida", notify=False)
        finally:
            writer.close()

    async def _reverse_connect(self, tr: Transfer, addrs: list[str], port: int) -> None:
        for addr in addrs:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                continue
            writer.write(tr.id)
            await self._send_stream(tr, reader, writer)
            return
        self._fail(tr, "sem rota direta entre as duas máquinas (NAT/firewall dos dois lados). "
                       "Libere uma porta com --p2p-port ou use uma VPN/rede comum.")

    # ------------------------------------------------------------ receiver

    async def accept(self, short: str | None = None) -> None:
        tr = self._pick(short)
        tr.state = "connecting"
        self._note(tr, "conectando diretamente ao remetente…")
        for addr in tr.addrs:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, tr.port), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                continue
            writer.write(tr.id)
            await self._recv_stream(tr, reader, writer)
            return
        # Could not reach the sender: ask them to connect to us instead.
        try:
            port = await self._listen()
            tr.state = "waiting"
            self.client.send_direct(tr.peer, {"k": "fr", "id": tr.id.hex(),
                                              "addrs": self._candidates(), "port": port})
        except Exception as exc:
            self._fail(tr, str(exc))
            return
        self._note(tr, "remetente inalcançável; tentando conexão reversa…")
        deadline = time.monotonic() + CONNECT_TIMEOUT * 4 + 5
        while tr.state == "waiting" and time.monotonic() < deadline:
            await asyncio.sleep(0.2)
        if tr.state == "waiting":
            self._fail(tr, "sem rota direta entre as duas máquinas (NAT/firewall dos dois lados). "
                           "Libere uma porta com --p2p-port ou use uma VPN/rede comum.")

    async def reject(self, short: str | None = None) -> None:
        tr = self._pick(short)
        tr.state = "failed"
        self.client.send_direct(tr.peer, {"k": "fx", "id": tr.id.hex(), "why": "recusado"})
        self._note(tr, "oferta recusada")

    def _dest_path(self, name: str) -> str:
        os.makedirs(self.download_dir, exist_ok=True)
        base, ext = os.path.splitext(name)
        path = os.path.join(self.download_dir, name)
        count = 1
        while os.path.exists(path) or os.path.exists(path + ".part"):
            path = os.path.join(self.download_dir, f"{base}.{count}{ext}")
            count += 1
        return path

    async def _recv_stream(self, tr: Transfer, reader, writer) -> None:
        tr.state = "active"
        dest = self._dest_path(tr.name)
        part = dest + ".part"
        ok = False
        try:
            got = index = 0
            last_emit = 0.0
            with open(part, "wb") as fh:
                while True:
                    head = await asyncio.wait_for(reader.readexactly(5), 60)
                    last, length = bool(head[0]), struct.unpack(">I", head[1:])[0]
                    if length > FILE_CHUNK + 16:
                        raise CryptoError("bloco grande demais")
                    blob = await asyncio.wait_for(reader.readexactly(length), 60)
                    chunk = crypto.file_decrypt_chunk(tr.key, index, blob, last)
                    got += len(chunk)
                    if got > tr.size:
                        raise CryptoError("arquivo maior que o anunciado")
                    fh.write(chunk)
                    index += 1
                    if time.monotonic() - last_emit > 0.2:
                        last_emit = time.monotonic()
                        self._progress(tr, got)
                    if last:
                        break
            if got != tr.size:
                raise CryptoError("tamanho diferente do anunciado")
            os.replace(part, dest)
            ok = True
            writer.write(ACK)
            await writer.drain()
            tr.state = "done"
            tr.path = dest
            self._progress(tr, got)
            self._note(tr, f"recebido e verificado: {dest} ({human_size(got)})", "ok")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, CryptoError) as exc:
            self._fail(tr, str(exc) or "conexão interrompida", notify=False)
        finally:
            writer.close()
            if not ok:
                try:
                    os.remove(part)
                except OSError:
                    pass

    # ----------------------------------------------------------- incoming

    async def _on_conn(self, reader, writer) -> None:
        try:
            tid = await asyncio.wait_for(reader.readexactly(16), 10)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return
        tr = self.transfers.get(tid)
        if tr and tr.outgoing and tr.state == "offered":
            await self._send_stream(tr, reader, writer)
        elif tr and not tr.outgoing and tr.state == "waiting":
            await self._recv_stream(tr, reader, writer)
        else:
            writer.close()

    @staticmethod
    def _endpoints(inner: dict) -> tuple[list[str], int]:
        addrs, port = inner.get("addrs"), inner.get("port")
        if not isinstance(addrs, list) or not isinstance(port, int) or not 0 < port < 65536:
            raise ProtocolError("bad endpoints")
        clean = [a for a in addrs[:8] if isinstance(a, str) and 0 < len(a) < 256 and a.isprintable() and " " not in a]
        return clean, port

    def handle(self, peer, inner: dict) -> None:
        """Process a file-signalling envelope (already authenticated as ``peer``)."""
        try:
            tid = bytes.fromhex(inner["id"])
            if len(tid) != 16:
                return
            kind = inner["k"]
            if kind == "fo":
                if tid in self.transfers or len(self.transfers) > 500:
                    return
                size = inner["size"]
                if not isinstance(size, int) or size < 0:
                    return
                tr = Transfer(tid, peer, safe_name(inner["name"]), size, b64d(inner["key"], 32), False)
                tr.addrs, tr.port = self._endpoints(inner)
                self.transfers[tid] = tr
                self._note(tr, f"{peer.nick} quer enviar '{tr.name}' ({human_size(size)}). "
                               f"/accept {tr.hex} para receber via P2P (expõe seu IP a {peer.nick}) "
                               f"ou /reject {tr.hex}", "warn")
                self.client.emit("file_offer", id=tr.hex, nick=peer.nick, name=tr.name, size=size)
                return
            tr = self.transfers.get(tid)
            if not tr or tr.peer.key != peer.key:
                return
            if kind == "fr" and tr.outgoing and tr.state == "offered":
                addrs, port = self._endpoints(inner)
                tr.state = "connecting"
                self._note(tr, "destinatário não alcançou esta máquina; tentando conexão reversa…")
                self.client.spawn(self._reverse_connect(tr, addrs, port))
            elif kind == "fx" and tr.state not in ("done", "failed", "active"):
                tr.state = "failed"
                self._note(tr, f"{peer.nick} cancelou: {str(inner.get('why') or '')[:100]}", "warn")
        except (KeyError, TypeError, ValueError, ProtocolError):
            return
