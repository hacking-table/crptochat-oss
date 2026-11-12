"""Proves a built client binary really works.

    python packaging/smoke_binary.py dist/crptochat

Starts a throwaway server from the source tree, drives the binary inside a
pseudo-terminal (register, join #lobby, send a message, quit) and checks
that a second, source-based client decrypts what the binary sent.
"""

import asyncio
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time

from crptochat.client import ChatClient
from crptochat.server import Server, ensure_cert, make_ssl_context
from crptochat.store import Identity, Store

TOKEN = "binary-says-hello"


def drive(binary: str, port: int, home: str) -> tuple[int, bytes]:
    env = dict(os.environ, TERM="xterm-256color", COLUMNS="110", LINES="32",
               CRPTOCHAT_HOME=home, CRPTOCHAT_PASSPHRASE="smoke")
    pid, fd = pty.fork()
    if pid == 0:
        # CI-only smoke test: `binary` is the artifact this workflow just built (checked
        # in main() to be an executable file) and env is built right above; no user
        # input reaches this call.
        os.execve(binary, [binary, f"127.0.0.1:{port}", "-n", "binario", "-j", "#lobby"],  # nosemgrep
                  env)
    seen = b""

    def pump(seconds: float) -> None:
        nonlocal seen
        end = time.time() + seconds
        while time.time() < end:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    seen += os.read(fd, 65536)
                except OSError:
                    return

    pump(8)
    os.write(fd, TOKEN.encode() + b"\r")
    pump(2)
    os.write(fd, b"/quit\r")
    deadline = time.time() + 10
    status = None
    while time.time() < deadline:
        pump(0.2)
        done, raw = os.waitpid(pid, os.WNOHANG)
        if done:
            status = os.waitstatus_to_exitcode(raw)
            break
    if status is None:
        os.kill(pid, 9)
        status = -9
    return status, seen


async def main(binary: str) -> None:
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        raise SystemExit(f"não é um executável: {binary}")
    version = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=60)
    assert version.returncode == 0 and version.stdout.strip(), version
    print("versão do binário:", version.stdout.strip())

    tmp = tempfile.mkdtemp(prefix="crptochat-smoke-")
    os.environ["CRPTOCHAT_HOME"] = os.path.join(tmp, "peer")
    server = Server(os.path.join(tmp, "srv"), reg_limit=0)
    port = await server.start("127.0.0.1", 0, make_ssl_context(*ensure_cert(os.path.join(tmp, "srv"))))
    events = []
    peer = ChatClient("127.0.0.1", port, Identity.create("observador", "smoke"), Store("smoke"),
                      lambda kind, data: events.append((kind, data)))
    task = asyncio.create_task(peer.run())
    try:
        for _ in range(200):
            if peer.online:
                break
            await asyncio.sleep(0.05)
        await peer.join("#lobby")
        status, seen = await asyncio.to_thread(drive, binary, port, os.path.join(tmp, "bin"))
        got = [d for k, d in events if k == "message" and d["nick"] == "binario" and d["text"] == TOKEN]
        assert status == 0, f"o binário saiu com código {status}"
        assert got, "a mensagem enviada pelo binário não chegou (ou não foi decifrada) no outro cliente"
        assert os.path.exists(os.path.join(tmp, "bin", "identities", "binario.json")), "identidade não criada"
        print("ok: o binário registrou um nick, entrou no canal e o outro cliente decifrou a mensagem")
    finally:
        await peer.close()
        task.cancel()
        await server.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main(os.path.abspath(sys.argv[1])))
