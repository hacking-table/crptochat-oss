"""Anonymous access, roles, bans, channel policies, away and the admin console."""

import asyncio
import json
import os

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatError
from crptochat.protocol import b64d, b64e, decode, encode
from crptochat.store import Identity, Store


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


async def guest(h, **kw):
    ident = Identity("guest", crypto.ed_generate())
    return await h.client(crypto.guest_nick(ident.ik), identity=ident, guest=True, **kw)


def events(client, kind):
    return [d for k, d in client.events if k == kind]


def warned(client, text):
    return any(k == "system" and text in d["text"] for k, d in client.events)


async def refused(coro, code=None):
    with pytest.raises(ChatError) as err:
        await coro
    if code:
        assert err.value.code == code, err.value.code
    return err.value


def test_anonymous_access(home):
    async def main():
        async with Harness(home) as h:
            alice, anon = await h.client("alice"), await guest(h)
            assert anon.online and anon.guest and anon.nick.startswith("anon-")
            assert anon.nick == crypto.guest_nick(anon.identity.ik)
            await alice.join("#lobby")
            await anon.join("#lobby")
            await until(lambda: anon.key in alice.channels["#lobby"].recv and "alice" in anon.channels["#lobby"].recv)
            anon.send_message("#lobby", "oi, sou anônimo")
            alice.send_message("#lobby", "bem-vindo")
            await until(lambda: messages(alice) and messages(anon))
            assert messages(alice) == [(anon.nick, "oi, sou anônimo")]
            assert alice.channels["#lobby"].members[anon.key].guest

            # nothing about the guest was stored, on the server or by peers
            assert h.server.db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
            assert anon.key not in json.dumps(alice.store._users)
            assert not os.path.exists(Identity.path(anon.nick))

            await refused(anon.create("#mine"), "denied")

            # the reserved prefix cannot be registered, and a guest cannot pick a name
            squatter = await h.client("anon-deadbeef")
            assert [d["code"] for d in events(squatter, "fatal")] == ["bad_nick"]
            key, dh = crypto.ed_generate(), crypto.x_pub(crypto.x_generate())
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            nonce = b64d(decode(await reader.readline())["nonce"])
            writer.write(encode({
                "t": "auth", "id": 1, "guest": True, "nick": "anon-deadbeef", "ik": b64e(crypto.ed_pub(key)),
                "dh": b64e(dh), "sig": b64e(crypto.sign(key, crypto.auth_message(nonce, "anon-deadbeef", dh))),
                "dh_sig": b64e(crypto.sign(key, crypto.dh_message("anon-deadbeef", dh)))}))
            assert decode(await reader.readline())["code"] == "bad_nick"
            writer.close()

            h.server.allow_guests = False
            blocked = await guest(h)
            assert [d["code"] for d in events(blocked, "fatal")] == ["no_guests"]
    run(main())


def test_channel_roles_kick_and_ban(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = [await h.client(n) for n in ("alice", "bob", "carol")]
            await alice.create("#ops")
            await bob.join("#ops")
            await carol.join("#ops")
            await until(lambda: len(alice.channels["#ops"].members) == 2)
            assert alice.channels["#ops"].roles == {"alice": "owner"} == carol.channels["#ops"].roles
            assert alice.power("#ops") == 3 and bob.power("#ops") == 0

            await refused(bob.set_role("#ops", "carol", "voice"), "denied")   # not an op yet
            await alice.set_role("#ops", "bob", "op")
            await until(lambda: carol.channels["#ops"].roles.get("bob") == "op")
            await bob.set_role("#ops", "carol", "voice")                      # ops hand out voice
            await until(lambda: alice.channels["#ops"].roles.get("carol") == "voice")
            await refused(bob.set_role("#ops", "carol", "op"), "denied")      # only the owner makes ops
            await refused(bob.kick("#ops", "alice"), "denied")                # cannot act upwards
            await refused(carol.kick("#ops", "bob"), "denied")

            await until(lambda: "carol" in alice.channels["#ops"].recv)
            before = alice.channels["#ops"].chain.ck
            await bob.kick("#ops", "carol")
            await until(lambda: "#ops" not in carol.channels)
            assert events(carol, "kicked_from")[-1]["by"] == "bob"
            await until(lambda: "carol" not in alice.channels["#ops"].members)
            assert alice.channels["#ops"].chain.ck != before        # keys rotated: she reads nothing more
            assert events(alice, "member_leave")[-1]["kicked"] == "bob"
            alice.send_message("#ops", "sem a carol")
            await until(lambda: ("alice", "sem a carol") in messages(bob))
            assert ("alice", "sem a carol") not in messages(carol)

            await carol.join("#ops")                                 # a kick is not a ban
            await until(lambda: "carol" in alice.channels["#ops"].members)
            await bob.chan_ban("#ops", "carol")
            await until(lambda: "#ops" not in carol.channels)
            await refused(carol.join("#ops"), "banned_chan")
            assert await bob.chan_bans("#ops") == ["carol"]
            await bob.chan_ban("#ops", "carol", on=False)
            await carol.join("#ops")
            assert "carol" not in carol.channels["#ops"].roles      # the ban removed her voice

            # roles survive leaving and coming back; ownership is transferred, not shared
            await bob.leave("#ops")
            await bob.join("#ops")
            assert bob.channels["#ops"].roles["bob"] == "op"
            await alice.set_role("#ops", "bob", "owner")
            await until(lambda: carol.channels["#ops"].roles.get("alice") == "op")
            assert carol.channels["#ops"].roles["bob"] == "owner"
            assert sorted(map(tuple, await carol.chan_roles("#ops"))) == [("alice", "op"), ("bob", "owner")]
    run(main())


def test_channel_policies(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = [await h.client(n) for n in ("alice", "bob", "carol")]
            anon = await guest(h)
            await alice.create("#pol")
            await bob.join("#pol")
            await until(lambda: "bob" in alice.channels["#pol"].recv and "alice" in bob.channels["#pol"].recv)
            await refused(bob.set_policy("#pol", noanon=True), "denied")      # only operators
            await refused(alice.set_policy("#pol", bogus=True))

            await alice.set_policy("#pol", noanon=True)
            await until(lambda: bob.channels["#pol"].policy.get("noanon"))
            assert events(bob, "policy")[-1]["changed"] == {"noanon": True}
            await refused(anon.join("#pol"), "denied")
            await alice.set_policy("#pol", noanon=False)
            await anon.join("#pol")

            # moderated: refused locally for people without voice, enforced by the server too
            await alice.set_policy("#pol", moderated=True)
            await until(lambda: bob.channels["#pol"].policy["moderated"])
            with pytest.raises(ChatError):
                bob.send_message("#pol", "posso?")
            bob._send({"t": "msg", "chan": "#pol", "body": "AAAA"})
            await until(lambda: warned(bob, "moderado"))
            await alice.set_role("#pol", "bob", "voice")
            await until(lambda: bob.channels["#pol"].roles.get("bob") == "voice")
            bob.send_message("#pol", "agora sim")
            await until(lambda: ("bob", "agora sim") in messages(alice))
            await alice.set_policy("#pol", moderated=False)

            # slow mode and text-only look at timing and size, never at content
            await alice.set_policy("#pol", slow=30, textonly=True)
            await until(lambda: bob.channels["#pol"].policy["slow"] == 30)
            bob.send_message("#pol", "um")
            bob.send_message("#pol", "dois")
            await until(lambda: warned(bob, "modo lento"))
            await asyncio.sleep(0.1)
            assert [t for n, t in messages(alice) if n == "bob"] == ["agora sim", "um"]
            alice.send_message("#pol", "operadores não esperam")
            alice.send_message("#pol", "nem aqui")
            await until(lambda: ("alice", "nem aqui") in messages(bob))
            await alice.set_policy("#pol", slow=0)
            await bob.send_audio("#pol", b"RIFF\0\0\0\0WAVE" + os.urandom(30_000), 2.0)
            await until(lambda: warned(bob, "só aceita texto"))
            assert not events(alice, "audio")
            await alice.set_policy("#pol", textonly=False)

            # invite-only and member limit
            await alice.set_policy("#pol", invite=True)
            await refused(carol.join("#pol"), "denied")
            await alice.invite("#pol", "carol")
            await until(lambda: events(carol, "invited"))
            await carol.join("#pol")
            await carol.leave("#pol")
            await alice.set_policy("#pol", invite=False, limit=3)
            await refused(carol.join("#pol"), "limit")

            # policies persist and are told to whoever asks
            assert (await carol.request({"t": "chaninfo", "chan": "#pol"}))["policy"]["limit"] == 3
            del h.server._policies["#pol"]
            assert h.server.policy("#pol")["limit"] == 3
    run(main())


def test_anonymous_user_banned_from_channel_cannot_just_reconnect(home):
    async def main():
        async with Harness(home) as h:
            alice, anon = await h.client("alice"), await guest(h)
            await alice.create("#room")
            await anon.join("#room")
            await until(lambda: anon.key in alice.channels["#room"].members)
            await alice.chan_ban("#room", anon.nick)
            await until(lambda: "#room" not in anon.channels)
            again = await guest(h)                       # new key, new anonymous nick, same address
            assert again.nick != anon.nick
            await refused(again.join("#room"), "banned_chan")
            await again.join("#lobby")                   # only that channel is closed to them
            await alice.chan_ban("#room", anon.nick, on=False)
            await again.join("#room")
    run(main())


def test_server_roles_and_bans(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = [await h.client(n) for n in ("alice", "bob", "carol")]
            await refused(bob.server_ban("carol"), "denied")
            assert h.server.admin({"op": "role", "nick": "BOB", "role": "mod"})["ok"]
            await until(lambda: bob.role == "mod")
            assert h.server.admin({"op": "role", "nick": "alice", "role": "admin"})["ok"]
            await until(lambda: alice.role == "admin")
            assert "error" in h.server.admin({"op": "role", "nick": "ghost", "role": "mod"})
            assert "error" in h.server.admin({"op": "role", "nick": "bob", "role": "god"})

            # staff outrank channel roles: admin as owner, moderator as operator
            await carol.create("#carol")
            await alice.join("#carol")
            await bob.join("#carol")
            await until(lambda: carol.peers.get("alice") and carol.peers["alice"].role == "admin")
            assert carol.power("#carol", "alice") == 3 and carol.power("#carol", "bob") == 2
            await refused(carol.kick("#carol", "alice"), "denied")    # nobody outranks a server admin
            await carol.kick("#carol", "bob")                         # but an owner rules over a moderator
            await until(lambda: "#carol" not in bob.channels)
            await bob.join("#carol")
            await refused(bob.server_ban("alice"), "denied")          # a mod cannot touch an admin
            await bob.set_policy("#carol", slow=5)

            await bob.server_ban("carol", minutes=60, reason="spam")
            await until(lambda: events(carol, "fatal"))
            assert "banido" in events(carol, "fatal")[0]["text"] and "spam" in events(carol, "fatal")[0]["text"]
            back = await h.client("carol", identity=carol.identity)
            assert [d["code"] for d in events(back, "fatal")] == ["banned"]

            # an expired ban lifts itself
            h.server.db.execute("UPDATE users SET banned_until=1 WHERE nick_lower='carol'")
            assert (await h.client("carol", identity=carol.identity)).online
            h.server.ban("carol")
            await alice.server_unban("carol")
            carol2 = await h.client("carol", identity=carol.identity)
            assert carol2.online

            await alice.server_kick("carol")
            await until(lambda: events(carol2, "fatal"))

            # address ban: stored only as a keyed hash, and it blocks new sessions
            dave = await h.client("dave")
            h.server.ban("dave", ip=True, reason="evasão")
            rows = h.server.db.execute("SELECT ip_hash FROM ip_bans").fetchall()
            assert len(rows) == 1 and "127.0.0.1" not in rows[0][0]
            await until(lambda: events(dave, "fatal"))
            blocked = await guest(h)
            assert [d["code"] for d in events(blocked, "fatal")] == ["banned"]
            assert h.server.admin({"op": "unban", "nick": "dave"})["ip"] == 1
            assert (await guest(h)).online
    run(main())


def test_away_and_presence(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "alice" in bob.channels["#lobby"].members)
            assert await bob.presence(["ALICE", "ghost"]) == {"alice": "on"}

            await alice.set_away("fui tomar café ☕")
            await until(lambda: bob.peers["alice"].away)
            assert await bob.presence(["alice"]) == {"alice": "away"}
            await bob.send_dm("alice", "tá aí?")
            await bob.send_dm("alice", "alô?")
            await until(lambda: len(messages(alice, "@bob")) == 2)
            await asyncio.sleep(0.1)
            assert messages(bob, "@alice") == [("alice", "[ausente] fui tomar café ☕")]   # told once
            assert not any("café" in frame for frame in h.wire)                             # text is end to end

            await alice.set_away(None)
            await until(lambda: not bob.peers["alice"].away)
            await bob.send_dm("alice", "voltou?")
            await until(lambda: len(messages(alice, "@bob")) == 3)
            await asyncio.sleep(0.1)
            assert len(messages(bob, "@alice")) == 1

            # a newcomer learns who is away from the member list
            await bob.set_away("")
            carol = await h.client("carol")
            await carol.join("#lobby")
            assert carol.channels["#lobby"].members["bob"].away
    run(main())


def test_friends_are_stored_only_locally(home):
    store = Store("srv:1")
    assert store.set_friend("Trinity") and store.set_friend("morpheus")
    store.set_friend("trinity")                 # no duplicates, case-insensitive
    assert store.friends() == ["morpheus", "trinity"]
    assert Store("srv:2").friends() == []       # per server
    assert store.set_friend("TRINITY", False) and not store.set_friend("nobody", False)
    assert Store("srv:1").friends() == ["morpheus"]


def test_admin_console_over_the_socket(home):
    from crptochat.admin import AdminError, AdminSocket, Console, Link, parse_duration, socket_path

    assert parse_duration("30m") == 30 and parse_duration("12h") == 720 and parse_duration("7d") == 10080
    assert parse_duration("perm") == 0
    with pytest.raises(AdminError):
        parse_duration("soon")

    async def main():
        async with Harness(home) as h:
            sock = AdminSocket(h.server, socket_path(str(home / "srv")))
            await sock.start()
            assert oct(os.stat(sock.path).st_mode & 0o777) == "0o600"
            alice, bob = await h.client("alice"), await h.client("bob")
            anon = await guest(h)
            await alice.create("#staff")
            out = []

            def console(*argv):
                out.clear()
                link = Link(sock.path)
                try:
                    Console(link, out.append).run(list(argv))
                finally:
                    link.sock.close()
                return "\n".join(out)

            call = lambda *argv: asyncio.to_thread(console, *argv)  # noqa: E731

            text = await call("status")
            assert "online" in text and "anônimos: 1" in text
            text = await call("users", "online")
            assert "alice" in text and "bob" in text and anon.nick in text and "127.0.0.1" not in text

            await call("role", "alice", "admin")
            await until(lambda: alice.role == "admin")
            assert "admin" in await call("user", "alice")
            assert "owner" in await call("user", "alice") and "#staff" in "\n".join(out)

            await call("ban", "bob", "7d", "flood", "no", "lobby")
            await until(lambda: events(bob, "fatal"))
            assert "flood no lobby" in events(bob, "fatal")[0]["text"]
            assert "bob" in await call("bans") and "flood no lobby" in "\n".join(out)
            assert "BANIDO" in await call("users", "banned")
            await call("unban", "bob")
            assert (await h.client("bob", identity=bob.identity)).online

            await call("policy", "#staff", "slow", "10")
            await call("policy", "#staff", "noanon", "on")
            await until(lambda: alice.channels["#staff"].policy.get("noanon"))
            assert alice.channels["#staff"].policy["slow"] == 10
            await call("chanrole", "#staff", "bob", "op")
            text = await call("chan", "#staff")
            assert "noanon" in text and "bob" in text and "op" in text
            assert "#staff" in await call("channels") and "alice" in "\n".join(out)

            await call("notice", "manutenção", "às", "22h")
            await until(lambda: events(alice, "notice"))
            assert events(alice, "notice")[0]["text"] == "manutenção às 22h"

            await call("guests", "off")
            assert not h.server.allow_guests
            await call("kick", anon.nick)
            await until(lambda: events(anon, "fatal"))

            for bad in (("role", "ghost", "mod"), ("ban", "ghost"), ("nope",), ("role", "alice")):
                with pytest.raises(AdminError):
                    await call(*bad)
            await sock.stop()
            assert not os.path.exists(sock.path)
    run(main())
