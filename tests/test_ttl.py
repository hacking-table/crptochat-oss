"""Etapa 3: disappearing messages, per channel (/mode +t) and per direct conversation (/ttl)."""

import asyncio
import json
import os

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatError
from crptochat.protocol import MAX_TTL, b64e, format_duration, parse_duration
from crptochat.store import Identity, Store


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def ttls(client, buffer):
    return [d.get("ttl", 0) for k, d in client.events if k == "message" and d["buffer"] == buffer and not d["mine"]]


def test_durations():
    assert [parse_duration(t) for t in ("30s", "10m", "1h", "7d", "45", "off", "0")] == [30, 600, 3600, 604800, 45, 0, 0]
    for bad in ("1y", "-5m", "abc", "m", "31d", "0m", ""):
        with pytest.raises(ValueError):
            parse_duration(bad)
    assert [format_duration(s) for s in (30, 600, 3600, 86400, 90)] == ["30s", "10m", "1h", "1d", "90s"]
    assert parse_duration("30d") == MAX_TTL


def test_channel_ttl_is_a_policy_announced_to_everyone(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.create("#efemero")
            await bob.join("#efemero")
            await until(lambda: "bob" in alice.channels["#efemero"].recv and "alice" in bob.channels["#efemero"].recv)
            assert "ttl" in alice.server_caps
            with pytest.raises(ChatError):
                await bob.set_channel_ttl("#efemero", 3600)                 # only operators
            await alice.set_channel_ttl("#efemero", 3600)
            await until(lambda: bob.channels["#efemero"].policy.get("ttl") == 3600)
            assert [d["changed"] for k, d in bob.events if k == "policy"] == [{"ttl": 3600}]
            with pytest.raises(ChatError):
                await alice.set_channel_ttl("#efemero", MAX_TTL + 1)

            alice.send_message("#efemero", "some em uma hora")
            await until(lambda: ttls(bob, "#efemero"))
            assert ttls(bob, "#efemero") == [3600]

            # the sender's timer travels inside the ciphertext: the shorter one wins
            bob.channels["#efemero"].policy["ttl"] = 60                     # bob's (stale) view
            alice.send_message("#efemero", "outra")
            await until(lambda: len(ttls(bob, "#efemero")) == 2)
            assert ttls(bob, "#efemero")[-1] == 60
            assert not any("some em uma hora" in frame for frame in h.wire)  # end to end as usual

            # persisted on the server, like every policy
            del h.server._policies["#efemero"]
            assert h.server.policy("#efemero")["ttl"] == 3600
            await alice.set_channel_ttl("#efemero", 0)
            await until(lambda: bob.channels["#efemero"].policy.get("ttl") == 0)
    run(main())


def test_messages_from_older_clients_follow_the_local_policy(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.create("#c")
            await bob.join("#c")
            await until(lambda: "bob" in alice.channels["#c"].recv)
            await alice.set_channel_ttl("#c", 120)
            await until(lambda: bob.channels["#c"].policy.get("ttl") == 120)
            # an older sender knows nothing about TTL: no "ttl" field in its payload
            ch = bob.channels["#c"]
            body = crypto.channel_encrypt(ch.chain, bob.identity.key, "#c", "bob", json.dumps({"x": "velho"}).encode())
            bob._send({"t": "msg", "chan": "#c", "body": b64e(body)})
            await until(lambda: ttls(alice, "#c"))
            assert ttls(alice, "#c") == [120]
    run(main())


def test_direct_conversation_timer_is_agreed_end_to_end(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.set_dm_ttl("bob", 600)
            await until(lambda: bob.dm_ttl("alice") == 600)
            assert alice.dm_ttl("bob") == 600
            assert [d["by"] for k, d in bob.events if k == "dm_ttl"] == ["alice"]
            assert not any('"ttl"' in f for f in h.wire if '"t": "direct"' in f and "600" in f)  # opaque to the server
            await alice.send_dm("bob", "efêmera")
            await bob.send_dm("alice", "também")
            await until(lambda: ttls(bob, "@alice") and ttls(alice, "@bob"))
            assert ttls(bob, "@alice") == [600] and ttls(alice, "@bob") == [600]
            assert Store(f"127.0.0.1:{h.port}:bob").dm_ttl("alice") == 600      # survives a restart
            await bob.set_dm_ttl("alice", 0)
            await until(lambda: alice.dm_ttl("bob") == 0)
    run(main())


def test_messages_disappear_from_the_interface(home):
    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.tui import ChatApp

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        events = []
        bob = ChatClient("127.0.0.1", port, Identity.create("bob", "pw"), Store("b"),
                         lambda k, d: events.append((k, d)), tls=False)
        btask = asyncio.create_task(bob.run())
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"),
                                            Store(f"127.0.0.1:{port}"), ev, tls=False))
        async with app.run_test(size=(130, 36)) as pilot:
            async def wait(cond, timeout=8):
                for _ in range(int(timeout / 0.02)):
                    if cond():
                        return
                    await pilot.pause(0.02)
                raise AssertionError("condition not reached")

            async def line(text):
                app.input.value = text
                await pilot.press("enter")
                await pilot.pause(0.05)

            def shown(name):
                return [l.plain for l in app.buffers[name].lines]

            await wait(lambda: app.client.online and bob.online)
            await line("/create #efemero")
            await wait(lambda: app.current == "#efemero")
            await bob.join("#efemero")
            await wait(lambda: "bob" in app.client.channels["#efemero"].recv)
            await line("/mode #efemero +t 2s")
            await wait(lambda: app.client.channels["#efemero"].policy.get("ttl") == 2)
            assert "⏱ mensagens somem em 2s" in app.query_one("#center").border_title
            await line("/mode")
            assert any("+t 2s" in l for l in shown("#efemero"))
            await line("esta vai sumir")
            bob.send_message("#efemero", "esta também")
            await wait(lambda: any("esta também" in l for l in shown("#efemero")))
            assert any("esta vai sumir" in l and "⏱2s" in l for l in shown("#efemero"))
            await wait(lambda: not any("esta" in l for l in shown("#efemero")), timeout=6)
            assert not any("esta" in str(line) for line in app.log_w.lines)        # gone from the screen too

            await line("/mode #efemero -t")
            await wait(lambda: not app.client.channels["#efemero"].policy.get("ttl"))
            await line("esta fica")
            await asyncio.sleep(1.5)
            assert any("esta fica" in l for l in shown("#efemero"))

            # direct conversation, including a voice clip held in memory
            await line("/ttl bob 1s")
            await wait(lambda: bob.dm_ttl("neo") == 1)
            await bob.send_audio("@neo", b"RIFF\0\0\0\0WAVE" + os.urandom(2000), 1.0)
            await wait(lambda: app.clips)
            await wait(lambda: not app.clips, timeout=6)
            assert not any("áudio" in l for l in shown("@bob"))
            await line("/mode #efemero +t 99d")
            assert any("tempo inválido" in l for l in shown(app.current))
            await line("/quit")
        await bob.close()
        btask.cancel()
        await server.stop()
    asyncio.run(main())
