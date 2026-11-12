"""Self-test for operators and for the deploy pipeline.

    python -m crptochat.selftest
        Starts a throwaway server and throwaway clients on loopback, inside a
        temporary directory, and exercises the whole stack: TLS, registration,
        open and private channels, direct messages, voice clips, P2P files,
        nickname protection and the stats feed. Nothing touches a real server.

    python -m crptochat.selftest --probe HOST[:PORT] [--stats DATA_DIR]
        Checks a running server without registering anything: TLS handshake,
        welcome frame, refusal of unauthenticated commands and, optionally,
        the operator stats socket.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import ssl
import sys
import tempfile

from . import __version__, crypto
from .protocol import DEFAULT_PORT, MAX_LINE, PROTO_VERSION, decode, encode


class Failed(Exception):
    pass


def ok(text: str) -> None:
    print(f"  ok    {text}", flush=True)


async def until(cond, what: str, timeout: float = 10) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not cond():
        if asyncio.get_running_loop().time() > deadline:
            raise Failed(what)
        await asyncio.sleep(0.02)


async def full(tmp: str) -> None:
    os.environ["CRPTOCHAT_HOME"] = os.path.join(tmp, "cfg")
    from .client import ChatClient, ChatError
    from .server import Server, ensure_cert, make_ssl_context
    from .stats import StatsFeed, socket_path
    from .store import Identity, Store

    data = os.path.join(tmp, "srv")
    server = Server(data, reg_limit=0)
    port = await server.start("127.0.0.1", 0, make_ssl_context(*ensure_cert(data)))
    feed = StatsFeed(server, socket_path(data))
    await feed.start()
    clients = []

    async def connect(nick, identity=None, guest=False):
        events = []
        client = ChatClient("127.0.0.1", port, identity or Identity.create(nick, "selftest"),
                            Store(f"selftest:{nick}"), lambda kind, d: events.append((kind, d)),
                            download_dir=os.path.join(tmp, "dl-" + nick), guest=guest)
        client.events = events
        clients.append((client, asyncio.create_task(client.run())))
        await until(lambda: client.online or any(k == "fatal" for k, _ in events), f"login de {nick}")
        return client

    def got(client, kind, **match):
        return [d for k, d in client.events if k == kind and all(d.get(a) == b for a, b in match.items())]

    try:
        alice, bob = await connect("alice"), await connect("bob")
        if not (alice.online and bob.online):
            raise Failed("login/registro")
        ok("TLS 1.3, registro e login de dois clientes")

        await alice.join("#lobby")
        await bob.join("#lobby")
        await until(lambda: "alice" in bob.channels["#lobby"].recv, "troca de chaves no canal")
        alice.send_message("#lobby", "selftest-open")
        await until(lambda: got(bob, "message", text="selftest-open"), "mensagem em canal aberto")
        ok("canal aberto cifrado ponta a ponta")

        await alice.create("#selftest", "selftest-passphrase")
        try:
            await bob.join("#selftest", "wrong")
            raise Failed("canal privado aceitou senha errada")
        except ChatError:
            pass
        await bob.join("#selftest", "selftest-passphrase")
        await until(lambda: "alice" in bob.channels["#selftest"].recv, "troca de chaves no canal privado")
        alice.send_message("#selftest", "selftest-private")
        await until(lambda: got(bob, "message", text="selftest-private"), "mensagem em canal privado")
        ok("canal privado: senha errada recusada, mensagem entregue")

        await alice.set_policy("#selftest", history=1)
        await until(lambda: bob.channels["#selftest"].policy.get("history") == 1, "política de histórico")
        await bob.leave("#selftest")                  # what bob sees live is not shown again as history
        alice.send_message("#selftest", "selftest-history")
        await until(lambda: server.db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 1, "histórico guardado")
        if b"selftest-history" in b"".join(bytes(r[0]) for r in server.db.execute("SELECT blob FROM history")):
            raise Failed("histórico guardado em claro no servidor")
        await bob.join("#selftest", "selftest-passphrase")
        await until(lambda: [e for d in got(bob, "history") for e in d["entries"]
                             if e["text"] == "selftest-history" and e["verified"]], "histórico cifrado entregue")
        await alice.set_policy("#selftest", history=0)
        if server.db.execute("SELECT COUNT(*) FROM history").fetchone()[0]:
            raise Failed("histórico não foi apagado ao desligar")
        ok("histórico de canal privado: só cifrado no servidor, assinado e apagado ao desligar")

        await bob.send_dm("alice", "selftest-dm")
        await until(lambda: got(alice, "message", text="selftest-dm"), "mensagem direta")
        ok("mensagem direta")

        clip = b"RIFF\0\0\0\0WAVE" + os.urandom(50_000)
        await alice.send_audio("#lobby", clip, 3.0)
        await until(lambda: got(bob, "audio", data=clip), "mensagem de voz")
        ok("mensagem de voz (envelopes de tamanho fixo)")

        payload = os.urandom(200_000)
        src = os.path.join(tmp, "payload.bin")
        with open(src, "wb") as fh:
            fh.write(payload)
        await alice.files.offer("bob", src)
        await until(lambda: got(bob, "file_offer"), "oferta de arquivo")
        await bob.files.accept()
        transfer = next(iter(bob.files.transfers.values()))
        await until(lambda: transfer.state in ("done", "failed"), "transferência P2P", 20)
        if transfer.state != "done" or open(transfer.path, "rb").read() != payload:
            raise Failed("arquivo P2P corrompido ou não entregue")
        ok("arquivo P2P direto entre clientes")

        before = sorted(os.listdir(data))
        await alice.relay.offer("bob", src)
        await until(lambda: [d for d in got(bob, "file_offer") if d.get("relay")], "oferta de arquivo pelo servidor")
        offer = [d for d in got(bob, "file_offer") if d.get("relay")][0]
        rtr = await bob.relay.accept(offer["id"], os.path.join(tmp, "relay-dl"))
        await until(lambda: rtr.state in ("done", "failed"), "arquivo pelo servidor", 20)
        if rtr.state != "done" or open(rtr.path, "rb").read() != payload or sorted(os.listdir(data)) != before:
            raise Failed("arquivo pelo servidor corrompido, não entregue ou gravado no servidor")
        ok("arquivo pelo servidor: cifrado, conferido e sem nada gravado no servidor")

        thief = await connect("ALICE", Identity("ALICE", crypto.ed_generate()))
        if thief.online or [d["code"] for d in got(thief, "fatal")] != ["nick_taken"]:
            raise Failed("nickname pôde ser reutilizado por outra chave")
        ok("nickname registrado não pode ser reutilizado")

        anon = await connect(crypto.guest_nick(crypto.ed_pub(crypto.ed_generate())),
                             Identity("anon", crypto.ed_generate()), guest=True)
        if not anon.online or not anon.nick.startswith("anon-"):
            raise Failed("acesso anônimo")
        await alice.set_policy("#selftest", noanon=True)
        try:
            await anon.join("#selftest")
            raise Failed("canal com noanon aceitou um anônimo")
        except ChatError:
            pass
        await alice.set_role("#selftest", "bob", "op")
        await until(lambda: bob.channels["#selftest"].roles.get("bob") == "op", "cargo de operador")
        await anon.join("#lobby")
        await until(lambda: anon.key in bob.channels["#lobby"].members, "anônimo no canal")
        ok("anônimos, cargos de canal e políticas")

        for i in range(8):                      # anonymous flood: burst (5) passes, then warn and mute
            try:
                anon.send_message("#lobby", f"flood {i}")
            except ChatError:
                break
        await until(lambda: [d["action"] for d in got(anon, "ratelimit")] == ["warn", "mute"], "anti-flood")
        ok("anti-flood: aviso e mute para quem excede o limite")

        from .admin import AdminSocket, socket_path as admin_path
        admin = AdminSocket(server, admin_path(data))
        await admin.start()
        reader, writer = await asyncio.open_unix_connection(admin.path)
        writer.write(b'{"op": "ban", "nick": "bob", "minutes": 5, "reason": "selftest"}\n')
        reply = json.loads(await reader.readline())
        writer.close()
        await admin.stop()
        await until(lambda: got(bob, "fatal"), "banimento pelo console")
        if not reply.get("ok") or "banido" not in got(bob, "fatal")[0]["text"]:
            raise Failed("console de administração")
        ok("console de administração: banimento aplicado")

        health = server._admin_health({})["health"]
        if health["online"]["anonymous"] != 1 or health["versions"].get(__version__, 0) < 1 \
                or any(word in json.dumps(health) for word in ("alice", "bob", "selftest", "lobby", "127.0.0.1")):
            raise Failed("painel de saúde com contagens erradas ou dados identificáveis")
        ok("painel de saúde: online, bans, limites e versões, só em contagens")

        await asyncio.sleep(1.1)
        reader, writer = await asyncio.open_unix_connection(feed.path)
        raw = (await reader.readline()).decode()
        writer.close()
        snap = json.loads(raw)
        if snap["conn"]["auth"] != 2 or snap["conn"]["guests"] != 1 or any(word in raw for word in ("alice", "bob", "selftest", "lobby", "127.0.0.1")):
            raise Failed("painel do operador com dados errados ou identificáveis")
        ok("painel do operador: só contagens, nenhum nome")

    finally:
        for client, task in clients:
            await client.close()
            task.cancel()
        await feed.stop()
        await server.stop()


async def probe(target: str, tls: bool, stats_dir: str | None) -> None:
    host, sep, port = target.rpartition(":")
    host, port = (host, int(port)) if sep and port.isdigit() else (target, DEFAULT_PORT)
    ctx = None
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, limit=MAX_LINE), 10)
    try:
        if tls:
            tls_obj = writer.get_extra_info("ssl_object")
            fingerprint = hashlib.sha256(tls_obj.getpeercert(binary_form=True)).hexdigest()
            if tls_obj.version() != "TLSv1.3":
                raise Failed(f"TLS inesperado: {tls_obj.version()}")
            ok(f"{host}:{port} responde em TLS 1.3 · fingerprint {fingerprint}")
        welcome = decode(await asyncio.wait_for(reader.readline(), 10))
        if welcome.get("t") != "welcome" or welcome.get("v") != PROTO_VERSION:
            raise Failed(f"resposta inesperada: {welcome}")
        ok(f"protocolo v{welcome['v']} · servidor '{welcome.get('server')}'")
        writer.write(encode({"t": "list", "id": 1}))
        reply = decode(await asyncio.wait_for(reader.readline(), 10))
        if reply.get("code") != "unauth":
            raise Failed("o servidor respondeu a um comando sem autenticação")
        ok("comandos sem autenticação são recusados")
    finally:
        writer.close()
    if stats_dir:
        from .stats import socket_path
        sreader, swriter = await asyncio.wait_for(asyncio.open_unix_connection(socket_path(stats_dir)), 10)
        snap = json.loads(await asyncio.wait_for(sreader.readline(), 10))
        swriter.close()
        if snap.get("version") != __version__:
            raise Failed(f"versão em execução {snap.get('version')} != {__version__}")
        ok(f"painel: v{snap['version']} · uptime {snap['uptime']}s · {snap['conn']['auth']} sessões · "
           f"{snap['chan']['registered']} canais · {snap['nicks']['registered']} nicks")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m crptochat.selftest", description="Autoteste do crptochat")
    ap.add_argument("--probe", metavar="HOST[:PORTA]", help="verifica um servidor em execução sem registrar nada")
    ap.add_argument("--no-tls", action="store_true", help="com --probe: o servidor roda sem TLS")
    ap.add_argument("--stats", metavar="DIR", help="com --probe: confere também o socket do painel em DIR")
    args = ap.parse_args(argv)
    tmp = tempfile.mkdtemp(prefix="crptochat-selftest-")
    try:
        if args.probe:
            print(f"crptochat {__version__} · verificando {args.probe}")
            asyncio.run(asyncio.wait_for(probe(args.probe, not args.no_tls, args.stats), 30))
        else:
            print(f"crptochat {__version__} · autoteste completo em ambiente descartável")
            asyncio.run(asyncio.wait_for(full(tmp), 90))
    except Failed as exc:
        sys.exit(f"  FALHA {exc}")
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        sys.exit(f"  FALHA {exc.__class__.__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("  tudo certo")


if __name__ == "__main__":
    main()
