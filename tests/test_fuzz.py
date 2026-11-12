"""Protocol fuzzing: hostile frames must be refused, never crash a handler,
leak state or affect anyone else."""

import asyncio
import json
import os
import random
import traceback

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.protocol import MAX_LINE, b64e
from crptochat.ratelimit import DEFAULTS
from crptochat.server import Refuse


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


FIELDS = ["chan", "nick", "body", "h", "set", "tid", "i", "d", "to", "size", "name", "salt", "verifier",
          "reencrypt", "epoch", "msg", "minutes", "reason", "ip", "role", "private", "auth", "last", "ok",
          "text", "away", "seconds", "repo", "ttl", "kind", "target", "value", "id", "from", "sig", "ik", "dh",
          "dh_sig", "guest", "reg_token", "ver", "query", "policy", "history", "rows"]


# CI runs a longer campaign on schedule: CRPTOCHAT_FUZZ_SCALE=10 means 10x the rounds.
SCALE = max(1, int(os.environ.get("CRPTOCHAT_FUZZ_SCALE", "1")))


def hostile(r: random.Random):
    """Mostly plausible values (to get deep into the handlers), some garbage."""
    plausible = ["#lobby", "#cofre", "#nao-existe", "alice", "bob", "carol", "anon-00000000", "op", "owner",
                 "member", "none", "x", "", b64e(os.urandom(16)), b64e(os.urandom(32)), b64e(os.urandom(64)),
                 b64e(os.urandom(r.randrange(0, 2000))), 0, 1, 3, 16, 65536, True, False, None]
    garbage = [-1, -2 ** 70, 2 ** 63, 1.5, float("inf"), float("nan"), "x" * 70000, "\x00‮﻿",
               "../../etc/passwd", "'; DROP TABLE users; --", "%s%s%n", [], [1, "a", None], {}, {"a": {"b": [1]}},
               {"history": "x", "slow": -5, "ttl": 10 ** 12, "limit": True},
               [{"id": "1", "h": "zz"}, {"id": 2 ** 64, "h": None}], "ﾟ" * 500]
    return r.choice(plausible if r.random() < 0.6 else garbage)


async def fuzz_handlers(h, sessions, seed: int, rounds: int) -> list:
    """Calls the dispatcher directly with random frames; anything but a Refuse is a bug."""
    r = random.Random(seed)
    ops = sorted(n[4:] for n in dir(h.server) if n.startswith("_op_")) + ["auth", "ping", "nope"]
    bugs = []
    for n in range(rounds):
        sess = r.choice([s for s in sessions if not s.closed] or [None])
        if sess is None:
            break
        msg = {"t": r.choice(ops)}
        for field in r.sample(FIELDS, r.randrange(0, 7)):
            msg[field] = hostile(r)
        try:
            h.server._dispatch(sess, msg)
        except Refuse:
            pass
        except Exception as exc:  # noqa: BLE001
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            bugs.append((msg["t"], type(exc).__name__, f"{os.path.basename(frame.filename)}:{frame.lineno}",
                         repr(msg)[:200]))
        if n % 100 == 0:
            await asyncio.sleep(0)
    return bugs


def no_limits(server):
    for name in DEFAULTS:
        if name.endswith(("_rate", "_burst", "_kbps", "_burst_kb", "_per_min", "_per_hour")) \
                or name in ("warn_after", "mute_after", "kick_after"):
            server.limits.set(name, 1e6)


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_handlers_refuse_hostile_frames_without_crashing(home, seed):
    async def main():
        async with Harness(home) as h:
            no_limits(h.server)
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.create("#cofre", "senha-forte-1")
            await alice.set_policy("#cofre", history=1)
            await alice.join("#lobby")
            await bob.join("#lobby")
            sessions = [h.server.sessions["alice"], h.server.sessions["bob"]]
            bugs = await fuzz_handlers(h, sessions, seed, 4000 * SCALE)
            assert not bugs, "\n".join(map(str, bugs[:20]))
            # the server keeps working for real clients afterwards (fresh users and channel:
            # the fuzzer may legitimately have kicked bob, changed #lobby's policies, etc.)
            carol, dave = await h.client("carol"), await h.client("dave")
            await carol.create("#saude")
            await dave.join("#saude")
            await until(lambda: "dave" in carol.channels["#saude"].recv)
            dave.send_message("#saude", "ainda de pé")
            await until(lambda: ("dave", "ainda de pé") in messages(carol, "#saude"))
            assert h.server.counters["internal_errors"] == 0
    run(main())


async def raw(h, payload: bytes, read: bool = True) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", h.port, limit=MAX_LINE * 2)
    await reader.readline()                                            # welcome
    writer.write(payload)
    await writer.drain()
    out = b""
    if read:
        try:
            out = await asyncio.wait_for(reader.read(65536), 2)
        except (asyncio.TimeoutError, ConnectionError):
            pass
    writer.close()
    return out


def test_garbage_on_the_wire_before_and_after_login(home):
    async def main():
        async with Harness(home) as h:
            alice = await h.client("alice")
            await alice.join("#lobby")
            baseline = h.server.open_conns
            r = random.Random(7)
            payloads = [
                os.urandom(4096) + b"\n",
                b"isto nao e json\n",
                b"[1,2,3]\n", b"\"string\"\n", b"null\n", b"{}\n", b'{"t": 5}\n', b'{"t": null}\n',
                b"[" * 200000 + b"]" * 200000 + b"\n",                     # recursion bomb
                b'{"t": "auth", "nick": ' + b'"' + b"a" * (MAX_LINE + 10) + b'"}\n',   # longer than a frame
                b'{"t": "join", "chan": "#lobby"}\n' * 50,                 # commands before login
                b'{"t": "auth", "nick": "alice", "ik": "AAAA", "dh": [], "sig": {}, "dh_sig": 1}\n',
                b'{"t": "\xff\xfe"}\n',
                b"\x00" * 1000 + b"\n",
                b"",                                                        # connect and say nothing
            ] + [bytes(r.randrange(256) for _ in range(r.randrange(1, 300))) + b"\n" for _ in range(40)]
            for payload in payloads:
                await raw(h, payload)
            await until(lambda: h.server.open_conns == baseline, 10)
            assert set(h.server.sessions) == {"alice"}                  # nothing half-registered
            assert h.server.counters["internal_errors"] == 0
            # and real users are unaffected
            bob = await h.client("bob")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].recv)
            bob.send_message("#lobby", "tudo certo")
            await until(lambda: ("bob", "tudo certo") in messages(alice, "#lobby"))
    run(main())


def test_an_unexpected_handler_error_is_contained(home, capsys):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")

            def boom(sess, msg):
                raise RuntimeError("segredo-do-payload")

            h.server._op_away = boom
            alice._send({"t": "away", "id": 99, "text": "conteudo-privado"})
            await until(lambda: not alice.online or "alice" not in h.server.sessions, 5)
            assert h.server.counters["internal_errors"] == 1
            assert "bob" in h.server.sessions                           # nobody else affected
    run(main())
    err = capsys.readouterr().err
    assert "erro interno ao tratar 'away': RuntimeError" in err
    assert "segredo" not in err and "conteudo-privado" not in err       # no content in the log


def test_tls_is_1_3_only(home):
    import ssl

    async def main():
        async with Harness(home, tls=True) as h:
            ok = ssl.create_default_context()
            ok.check_hostname = False
            ok.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port, ssl=ok)
            assert writer.get_extra_info("ssl_object").version() == "TLSv1.3"
            writer.close()
            old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            old.check_hostname = False
            old.verify_mode = ssl.CERT_NONE
            old.maximum_version = ssl.TLSVersion.TLSv1_2
            with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                await asyncio.open_connection("127.0.0.1", h.port, ssl=old)
    run(main())


def test_a_malicious_server_cannot_break_the_client_with_its_limits(home):
    from crptochat.relayfile import DEFAULT_WINDOW

    async def main():
        async with Harness(home) as h:
            alice = await h.client("alice")
            for hostile_limits in ({"file_kbps": "abc", "file_window": [1], "file_max": {}},
                                   {"file_kbps": float("nan"), "file_window": -5, "file_max": -1},
                                   {"file_kbps": 10 ** 30, "file_window": 10 ** 9, "file_max": True},
                                   {"max_body": "x", "history_body": [], "file_kbps": 0}):
                alice.server_limits = hostile_limits
                cap, kbps, window = alice.relay.limits()
                assert 0 <= cap <= 2 ** 40 and 1 <= kbps <= 10 ** 6 and 1 <= window <= 64
                assert 0 < alice.max_body() and 0 < alice.history_body()
            alice.server_limits = {}
            assert alice.relay.limits()[2] == DEFAULT_WINDOW
    run(main())


@pytest.mark.parametrize("seed", [11, 12])
def test_client_handlers_survive_a_hostile_server(home, seed):
    """Frames a malicious server could send to a client: never an unexpected exception."""
    from crptochat.crypto import CryptoError
    from crptochat.protocol import ProtocolError

    expected = (ProtocolError, CryptoError, KeyError, TypeError, ValueError, AttributeError)  # what _read_loop drops

    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.create("#cofre", "senha-forte-1")
            await alice.join("#lobby")
            await bob.join("#lobby")
            c = alice
            handlers = {"msg": c._on_msg, "direct": c._on_direct, "member_join": c._on_member_join,
                        "member_leave": c._on_member_leave, "chan_role": c._on_chan_role,
                        "kicked_from": c._on_kicked_from, "policy": c._on_policy, "file_go": c.relay.on_go,
                        "file_chunk": c.relay.on_chunk, "file_ack": c.relay.on_ack, "file_cancel": c.relay.on_cancel,
                        "away": c._on_away, "notice": c._on_notice, "ratelimit": c._on_ratelimit,
                        "client_repo": c._on_client_repo, "invited": c._on_invited, "role": c._on_role,
                        "ok": c._on_reply, "err": c._on_reply}
            loop_errors = []
            asyncio.get_running_loop().set_exception_handler(lambda loop, ctx: loop_errors.append(ctx))
            r = random.Random(seed)
            extra = ["members", "roles", "changed", "by", "kicked", "banned", "data", "online"]
            bugs = []
            for n in range(5000 * SCALE):
                t = r.choice(list(handlers))
                msg = {"t": t}
                for field in r.sample(FIELDS + extra, r.randrange(0, 7)):
                    msg[field] = hostile(r)
                try:
                    handlers[t](msg)
                except expected:
                    pass
                except Exception as exc:  # noqa: BLE001
                    bugs.append((t, type(exc).__name__, repr(msg)[:160]))
                if n % 100 == 0:
                    await asyncio.sleep(0)
            await asyncio.sleep(0.5)
            assert not bugs, bugs[:10]
            assert not loop_errors, loop_errors[:5]
            assert alice.online
    run(main())
