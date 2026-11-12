"""End-to-end tests: a real server and real client engines on localhost."""

import asyncio
import json
import os

import pytest

from crptochat import crypto
from crptochat.client import ChatClient, ChatError, NeedPassphrase
from crptochat.protocol import b64d, decode, encode
from crptochat.server import Server, ensure_cert, make_ssl_context
from crptochat.store import BadPassphrase, Identity, Store


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)  # keep the tests fast
    return tmp_path


class Harness:
    def __init__(self, tmp_path, tls=False):
        self.tmp = tmp_path
        self.tls = tls
        self.clients = []
        self.wire = []  # every frame that went through the server

    async def __aenter__(self):
        self.server = Server(str(self.tmp / "srv"), reg_limit=0)
        dispatch = self.server._dispatch

        def spy(sess, msg):
            self.wire.append(json.dumps(msg))
            return dispatch(sess, msg)

        self.server._dispatch = spy
        ctx = make_ssl_context(*ensure_cert(str(self.tmp / "srv"))) if self.tls else None
        self.port = await self.server.start("127.0.0.1", 0, ctx)
        return self

    async def __aexit__(self, *exc):
        for client, task in self.clients:
            await client.close()
            task.cancel()
        await self.server.stop()

    async def client(self, nick, identity=None, **kw):
        ident = identity or Identity.create(nick, "pw")
        events = []
        client = ChatClient("127.0.0.1", self.port, ident, Store(f"127.0.0.1:{self.port}:{nick}"),
                            lambda kind, data: events.append((kind, data)), tls=self.tls,
                            download_dir=str(self.tmp / f"dl-{nick}"), **kw)
        client.events = events
        task = asyncio.create_task(client.run())
        self.clients.append((client, task))
        await until(lambda: client.online or any(k == "fatal" for k, _ in events))
        return client


async def until(cond, timeout=5):
    deadline = asyncio.get_running_loop().time() + timeout
    while not cond():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


def messages(client, buffer=None):
    return [(d["nick"], d["text"]) for k, d in client.events
            if k == "message" and not d["mine"] and (buffer is None or d["buffer"] == buffer)]


def run(coro):
    asyncio.run(coro)


def test_channel_messages_are_e2e(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = [await h.client(n) for n in ("alice", "Bob", "carol")]
            await alice.join("#lobby")
            await bob.join("#lobby")
            await carol.join("#lobby")
            await until(lambda: len(alice.channels["#lobby"].members) == 2)
            alice.send_message("#lobby", "segredo do neon 🔐")
            bob.send_message("#lobby", "recebido")
            await until(lambda: len(messages(carol)) == 2)
            assert messages(bob) == [("alice", "segredo do neon 🔐")]
            assert messages(carol) == [("alice", "segredo do neon 🔐"), ("Bob", "recebido")]
            # The server relayed only ciphertext.
            assert not any("segredo" in frame or "recebido" in frame for frame in h.wire)
            assert sum('"t": "msg"' in frame for frame in h.wire) == 2
    run(main())


def test_late_joiner_cannot_read_history_and_keys_rotate_on_leave(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].members)
            alice.send_message("#lobby", "antes")
            await until(lambda: messages(bob))
            old_bodies = [b64d(json.loads(f)["body"]) for f in h.wire if '"t": "msg"' in f]

            carol = await h.client("carol")
            await carol.join("#lobby")
            await until(lambda: "alice" in carol.channels["#lobby"].recv)
            chain = carol.channels["#lobby"].recv["alice"]
            with pytest.raises(crypto.CryptoError):  # ratchet already moved past it
                crypto.channel_decrypt(chain.copy(), alice.identity.ik, "#lobby", "alice", old_bodies[0])

            before = alice.channels["#lobby"].chain.ck
            await carol.leave("#lobby")
            await until(lambda: "carol" not in alice.channels["#lobby"].members)
            assert alice.channels["#lobby"].chain.ck != before
            alice.send_message("#lobby", "depois")
            await until(lambda: len(messages(bob)) == 2)
            assert messages(carol) == []
    run(main())


def test_private_channel(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, eve = await h.client("alice"), await h.client("bob"), await h.client("eve")
            await alice.create("#ops", "correct horse")
            with pytest.raises(NeedPassphrase):
                await bob.join("#ops")
            with pytest.raises(ChatError):
                await eve.join("#ops", "wrong")
            await bob.join("#ops", "correct horse")
            await until(lambda: "bob" in alice.channels["#ops"].recv and "alice" in bob.channels["#ops"].recv)
            alice.send_message("#ops", "alvo confirmado")
            await until(lambda: messages(bob))
            assert messages(bob) == [("alice", "alvo confirmado")]
            # hidden from outsiders, and the passphrase never crossed the wire
            assert "#ops" not in [c["name"] for c in await eve.list_channels()]
            assert "#ops" in [c["name"] for c in await bob.list_channels()]
            assert not any("correct horse" in frame for frame in h.wire)

            # A malicious server that lets eve in still cannot give her the keys.
            row = h.server.db.execute("SELECT verifier FROM channels WHERE name='#ops'").fetchone()
            auth, psk = crypto.channel_keys("wrong", b"0" * 16)
            h.server.db.execute("UPDATE channels SET verifier=? WHERE name='#ops'", (crypto.auth_verifier(auth),))
            await eve.join("#ops", _keys=(auth, psk))
            await until(lambda: "eve" in alice.channels["#ops"].members)
            alice.send_message("#ops", "ainda secreto")
            await until(lambda: len(messages(bob)) == 2)
            await asyncio.sleep(0.1)
            assert messages(eve) == []
            assert row is not None
    run(main())


def test_direct_messages_and_offline(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("BOB", "oi em privado")
            await until(lambda: messages(bob, "@alice"))
            assert messages(bob, "@alice") == [("alice", "oi em privado")]
            await bob.send_dm("alice", "resposta")
            await until(lambda: messages(alice, "@bob"))
            assert not any("privado" in f or "resposta" in f for f in h.wire)
            with pytest.raises(ChatError):
                await alice.send_dm("ghost", "x")
    run(main())


def test_nick_is_permanent_and_cannot_be_reused(home):
    async def main():
        async with Harness(home) as h:
            ident = Identity.create("neo", "pw")
            neo = await h.client("neo", identity=ident)
            assert neo.online
            await neo.close()
            await until(lambda: "neo" not in h.server.sessions)

            # Same nick (any casing), different key: refused forever.
            thief = Identity("NEO", crypto.ed_generate())
            fake = await h.client("NEO", identity=thief)
            assert not fake.online
            assert [d["code"] for k, d in fake.events if k == "fatal"] == ["nick_taken"]

            # The legitimate owner can always come back.
            again = await h.client("neo", identity=Identity.load("neo", "pw"))
            assert again.online
            with pytest.raises(BadPassphrase):
                Identity.load("neo", "nope")
    run(main())


def test_identity_key_change_is_detected(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.resolve("bob")
            # The server swaps bob's key for one it controls.
            mallory = crypto.ed_generate()
            sess = h.server.sessions["bob"]
            sess.ik = crypto.ed_pub(mallory)
            sess.dh_sig = crypto.sign(mallory, crypto.dh_message("bob", sess.dh))
            with pytest.raises(ChatError) as err:
                await alice.send_dm("bob", "x")
            assert err.value.code == "untrusted"
            changed = [d for k, d in alice.events if k == "key_changed"]
            assert len(changed) == 1 and changed[0]["new"] == crypto.ed_pub(mallory)
    run(main())


def test_reconnect_rejoins_channels(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.create("#sec", "pw")
            await bob.join("#sec", "pw")
            await until(lambda: "bob" in alice.channels["#sec"].recv)
            h.server.sessions["bob"].close()
            await until(lambda: not bob.online)
            await until(lambda: bob.online and bob.channels["#sec"].joined
                        and "bob" in alice.channels["#sec"].recv, timeout=10)
            await until(lambda: "alice" in bob.channels["#sec"].recv)
            alice.send_message("#sec", "de volta")
            await until(lambda: messages(bob))
    run(main())


@pytest.mark.parametrize("reverse", [False, True])
def test_p2p_file_transfer(home, reverse):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            src = home / "payload.bin"
            data = os.urandom(300_000)
            src.write_bytes(data)
            await alice.files.offer("bob", str(src))
            await until(lambda: any(k == "file_offer" for k, _ in bob.events))
            if reverse:  # pretend the sender is behind NAT
                next(iter(bob.files.transfers.values())).addrs = []
            await bob.files.accept()
            tr = next(iter(bob.files.transfers.values()))
            await until(lambda: tr.state == "done")
            assert open(tr.path, "rb").read() == data
            await until(lambda: next(iter(alice.files.transfers.values())).state == "done")
            # Nothing but small signalling envelopes went through the server.
            assert sum(len(f) for f in h.wire) < 20_000
    run(main())


def test_tls_pinning(home):
    async def main():
        async with Harness(home, tls=True) as h:
            alice = await h.client("alice")
            assert alice.online
            assert Store(f"127.0.0.1:{h.port}:alice").server_pin()
            bad = await h.client("bob", pin="00" * 32)
            assert not bad.online
            assert [d["code"] for k, d in bad.events if k == "fatal"] == ["pin"]
    run(main())


def test_server_rejects_garbage(home):
    async def main():
        async with Harness(home) as h:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            assert decode(await reader.readline())["t"] == "welcome"
            writer.write(encode({"t": "join", "id": 1, "chan": "#lobby"}))
            assert decode(await reader.readline())["code"] == "unauth"
            writer.write(b"not json\n")
            assert await reader.readline() == b""
    run(main())


def test_key_on_removable_drive(home):
    usb = home / "usb"
    usb.mkdir()
    ident = Identity.create("neo", "pw", str(usb))
    assert ident.file == str(usb / "neo.json") and not Identity.exists("neo")
    assert Identity.load("neo", "pw", str(usb)).ik == ident.ik

    local = Identity.create("trinity", "pw")
    other = home / "usb2"
    dest = Identity.move("trinity", str(other))
    assert dest == str(other / "trinity.json") and not Identity.exists("trinity")
    assert Identity.load("trinity", "pw", str(other)).ik == local.ik
    with pytest.raises(FileExistsError):
        Identity.create("trinity", "pw", str(other))


def test_operator_stats_expose_no_identities(home):
    from crptochat.dash import render
    from crptochat.stats import StatsFeed, socket_path

    async def main():
        async with Harness(home) as h:
            feed = StatsFeed(h.server, socket_path(str(home / "srv")))
            await feed.start()
            alice, bob = await h.client("alice_secret"), await h.client("bob_secret")
            await alice.create("#hidden-name", "passphrase!")
            await bob.join("#hidden-name", "passphrase!")
            await alice.join("#lobby")
            await until(lambda: "bob_secret" in alice.channels["#hidden-name"].recv)
            alice.send_message("#hidden-name", "conteudo-sigiloso")
            await alice.send_dm("bob_secret", "outro-segredo")
            await until(lambda: len(messages(bob)) == 2)
            await asyncio.sleep(1.2)

            assert oct(os.stat(feed.path).st_mode & 0o777) == "0o600"
            reader, writer = await asyncio.open_unix_connection(feed.path)
            raw = (await reader.readline()).decode()
            writer.close()
            snap = json.loads(raw)
            assert snap["conn"]["auth"] == 2 and snap["conn"]["open"] == 2 and snap["conn"]["peak"] == 2
            assert snap["nicks"] == {"registered": 2, "new": 2}
            assert snap["chan"]["registered"] == 2 and snap["chan"]["private"] == 1
            assert snap["chan"]["active"] == 2 and snap["chan"]["largest"] == 2
            assert snap["chan"]["buckets"] == [1, 1, 0, 0]
            assert snap["traffic"]["chan_msgs"] == 1 and snap["traffic"]["directs"] >= 3
            assert snap["res"]["rss"] > 0 and snap["hist"]["auth"]

            frame = render(snap, 110)
            for leak in ("alice", "bob", "secret", "hidden", "lobby", "127.0.0.1", "sigiloso", "segredo"):
                assert leak not in raw and leak not in frame
            await feed.stop()
            assert not os.path.exists(feed.path)
    run(main())
