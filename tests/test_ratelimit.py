"""Etapa 2: rate limits, escalation (warn -> mute -> kick), per-IP caps and simple load tests."""

import asyncio
import json
import os
import time

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatError
from crptochat.protocol import b64d, b64e, decode, encode
from crptochat.ratelimit import DEFAULTS, Bucket, Limits, Strikes
from crptochat.store import Identity


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


def fatal_codes(client):
    return [d["code"] for d in events(client, "fatal")]


# ------------------------------------------------------------------ units

def test_bucket_and_strikes_units():
    limits = Limits({"msg_rate": 2, "msg_burst": 3, "bogus": 9, "msg_rate_typo": -1})
    assert "bogus" not in limits.values and limits["msg_rate"] == 2
    bucket = Bucket(limits, "msg_rate", "msg_burst")
    assert [bucket.take() for _ in range(4)] == [True, True, True, False]
    bucket.stamp -= 1.0                                   # one second later: two more tokens
    assert [bucket.take() for _ in range(3)] == [True, True, False]
    limits.set("msg_rate", 0)
    limits.set("msg_burst", 0)
    assert all(bucket.take() for _ in range(100))          # 0/0 disables the limit

    strikes = Strikes(Limits({"warn_after": 1, "mute_after": 3, "kick_after": 5, "mute_seconds": 30}))
    assert [strikes.hit() for _ in range(5)] == ["warn", None, "mute", None, "kick"]
    assert strikes.muted > 25
    old = Strikes(Limits({"strike_window": 10}))
    old.hit()
    old.times[0] -= 11                                     # outside the window: forgotten
    assert old.hit() is None and len(old.times) == 1
    with pytest.raises(KeyError):
        limits.set("nope", 1)
    with pytest.raises(ValueError):
        limits.set("msg_rate", -1)
    assert set(Limits().values) == set(DEFAULTS)


# ------------------------------------------------------------- escalation

def test_anonymous_flooder_is_warned_muted_then_kicked(home):
    async def main():
        async with Harness(home) as h:
            alice = await h.client("alice")
            flooder = await guest(h)
            await alice.join("#lobby")
            await flooder.join("#lobby")
            await until(lambda: flooder.key in alice.channels["#lobby"].recv
                        and "alice" in flooder.channels["#lobby"].recv)
            for i in range(40):
                try:
                    flooder.send_message("#lobby", f"spam {i}")
                except ChatError:
                    break
                await asyncio.sleep(0.005)
            await until(lambda: fatal_codes(flooder))
            assert "flood" in events(flooder, "fatal")[0]["text"]
            actions = [d["action"] for d in events(flooder, "ratelimit")]
            assert actions == ["warn", "mute"]
            got = [t for n, t in messages(alice) if n == flooder.nick]
            assert got == [f"spam {i}" for i in range(int(DEFAULTS["anon_msg_burst"]))]   # the burst got through
            c = h.server.counters
            assert c["rl_warn"] == 1 and c["rl_mute"] == 1 and c["rl_kick"] == 1
            alice.send_message("#lobby", "o canal continua normal")         # nobody else was affected
            assert alice.online
    run(main())


def test_registered_users_have_more_room_and_mutes_expire(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("mute_seconds", 0.4)
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].recv and "alice" in bob.channels["#lobby"].recv)
            for i in range(int(DEFAULTS["msg_burst"])):                     # a whole burst is fine
                bob.send_message("#lobby", f"ok {i}")
            await until(lambda: len(messages(alice)) == DEFAULTS["msg_burst"])
            assert not events(bob, "ratelimit")
            for i in range(3):                                              # then: warn, -, mute
                bob.send_message("#lobby", f"demais {i}")
            await until(lambda: [d["action"] for d in events(bob, "ratelimit")] == ["warn", "mute"])
            await asyncio.sleep(0.8)                                        # mute over, bucket refilled
            bob.send_message("#lobby", "voltei")
            await until(lambda: ("bob", "voltei") in messages(alice))
            assert bob.online and not fatal_codes(bob)
    run(main())


def test_voice_is_limited_by_size_not_taken_for_flood(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].recv)
            clip = b"RIFF\0\0\0\0WAVE" + os.urandom(150_000)               # 8 bulky envelopes
            await bob.send_audio("#lobby", clip, 9.0)
            for i in range(5):
                bob.send_message("#lobby", f"texto {i}")
            await until(lambda: events(alice, "audio") and len(messages(alice)) == 5)
            assert not events(bob, "ratelimit")
    run(main())


def test_joins_are_limited_for_anonymous_users(home):
    async def main():
        async with Harness(home) as h:
            owner = await h.client("owner")
            for i in range(14):
                await owner.create(f"#c{i}")
            anon = await guest(h)
            joined = refused = 0
            for i in range(14):
                try:
                    await anon.join(f"#c{i}")
                    joined += 1
                except ChatError as exc:
                    assert exc.code == "rate"
                    refused += 1
                    if not anon.online:
                        break
            assert joined == DEFAULTS["anon_join_burst"] and refused >= 1
    run(main())


# ------------------------------------------------------------ per address

def test_per_ip_message_bucket_counts_every_session(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("anon_ip_msg_rate", 0.01)
            h.server.limits.set("anon_ip_msg_burst", 8)
            alice = await h.client("alice")
            await alice.join("#lobby")
            anons = [await guest(h) for _ in range(4)]
            for anon in anons:
                await anon.join("#lobby")
            await until(lambda: all(a.key in alice.channels["#lobby"].recv for a in anons))
            for round_ in range(3):                                         # 12 messages, 3 each
                for anon in anons:
                    anon.send_message("#lobby", f"{anon.nick} {round_}")
            await until(lambda: sum(len(events(a, "ratelimit")) for a in anons) >= 1)
            await asyncio.sleep(0.2)
            assert len([1 for n, _ in messages(alice) if n.startswith("anon-")]) == 8   # each below its own limit
    run(main())


def test_simultaneous_connections_per_ip(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("conns_per_ip", 3)
            first = [await h.client(n) for n in ("ana", "bia", "cris")]
            assert all(c.online for c in first)
            extra = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", h.port), 5)
            frame = decode(await extra[0].readline())
            assert frame == {"t": "err", "code": "too_many_conns", "msg": frame["msg"]}
            assert await extra[0].readline() == b""                         # and the socket is closed
            assert h.server.counters["conn_refused"] == 1
            await first[0].close()
            await until(lambda: h.server.ip_conns.get("127.0.0.1") == 2)
            late = await h.client("davi")
            assert late.online                                             # a slot was freed
    run(main())


def test_anonymous_sessions_and_new_nicks_per_ip(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("anon_per_ip", 2)
            h.server.limits.set("reg_per_hour", 2)
            a, b, c = await guest(h), await guest(h), await guest(h)
            assert a.online and b.online and fatal_codes(c) == ["limit"]
            x, y, z = await h.client("xis"), await h.client("ypsilon"), await h.client("zeta")
            assert x.online and y.online and fatal_codes(z) == ["reg_limit"]
            again = await h.client("xis", identity=x.identity)            # existing nicks still log in
            assert again.online
    run(main())


def test_max_message_size(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            assert alice.max_body() == 64 * 1024                            # announced in the welcome
            assert h.server.admin({"op": "ratelimit", "set": {"max_body_kb": 31}}).get("error")
            assert h.server.admin({"op": "ratelimit", "set": {"max_body_kb": 40}})["ok"]
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            welcome = decode(await reader.readline())
            assert welcome["limits"]["max_body"] == 40 * 1024 and "ratelimit" in welcome["caps"]
            writer.close()
            with pytest.raises(ChatError) as err:
                await alice.request({"t": "direct", "to": "bob", "body": "A" * (40 * 1024 + 4)})
            assert err.value.code == "too_big"
            await alice.send_dm("bob", "pequena passa")
            await until(lambda: messages(bob, "@alice"))
    run(main())


# ----------------------------------------------------------------- admin

def test_admin_console_show_set_reset_and_persistence(home):
    from crptochat.admin import AdminError, AdminSocket, Console, Link, socket_path
    from crptochat.server import Server

    async def main():
        async with Harness(home) as h:
            sock = AdminSocket(h.server, socket_path(str(home / "srv")))
            await sock.start()
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
            text = await call("ratelimit")
            assert "anon_msg_rate" in text and "mute_after" in text and "recusas" in text
            await call("ratelimit", "set", "anon_msg_rate", "0.5")
            assert h.server.limits["anon_msg_rate"] == 0.5
            assert "*" in await call("ratelimit", "show") and "padrão 1" in "\n".join(out)
            for bad in (("ratelimit", "set", "nope", "1"), ("ratelimit", "set", "msg_rate", "-2"),
                        ("ratelimit", "set", "msg_rate", "abc"), ("ratelimit", "dance")):
                with pytest.raises(AdminError):
                    await call(*bad)
            await sock.stop()
        again = Server(str(home / "srv"))                                    # survives a restart
        assert again.limits["anon_msg_rate"] == 0.5
        again.admin({"op": "ratelimit", "reset": "all"})
        assert Server(str(home / "srv")).limits["anon_msg_rate"] == DEFAULTS["anon_msg_rate"]
        again.db.close()
    run(main())


# ------------------------------------------------------------------- load

def test_load_many_users_within_limits_all_delivered(home):
    """30 people chatting at a normal pace: nothing is refused, everything arrives."""
    async def main():
        async with Harness(home) as h:
            observer = await h.client("observador")
            await observer.join("#lobby")
            people = [await h.client(f"user{i:02d}") for i in range(30)]
            await asyncio.gather(*(p.join("#lobby") for p in people))
            await until(lambda: all(p.key in observer.channels["#lobby"].recv for p in people), timeout=20)
            started = time.monotonic()
            for round_ in range(5):
                for p in people:
                    p.send_message("#lobby", f"{p.nick} {round_}")
                await asyncio.sleep(0.05)
            await until(lambda: len(messages(observer)) == 150, timeout=20)
            elapsed = time.monotonic() - started
            assert h.server.counters["rate_limited"] == 0
            assert elapsed < 10, elapsed
    run(main())


def test_load_flooders_do_not_starve_everyone_else(home):
    """While anonymous flooders hammer the relay, normal users keep talking."""
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            floods = [await guest(h) for _ in range(5)]
            for f in floods:
                await f.join("#lobby")
            await until(lambda: all(f.key in alice.channels["#lobby"].recv for f in floods)
                        and "bob" in alice.channels["#lobby"].recv)

            async def flood(client):
                for i in range(200):
                    if not client.online:
                        return
                    try:
                        client.send_message("#lobby", "x" * 200)
                    except ChatError:
                        return
                    await asyncio.sleep(0)

            tasks = [asyncio.create_task(flood(f)) for f in floods]
            for i in range(10):
                bob.send_message("#lobby", f"bob {i}")
                await asyncio.sleep(0.15)
            await asyncio.gather(*tasks)
            await until(lambda: len([1 for n, _ in messages(alice) if n == "bob"]) == 10, timeout=10)
            await until(lambda: all(fatal_codes(f) for f in floods), timeout=10)
            flood_seen = len([1 for n, _ in messages(alice) if n.startswith("anon-")])
            assert flood_seen <= 5 * DEFAULTS["anon_msg_burst"]
            assert bob.online and not events(bob, "ratelimit")
    run(main())


# ------------------------------------------- memory per address, flood ban

async def flood_until(client, chan, stop, limit=60):
    for i in range(limit):
        if stop() or not client.online:
            return
        try:
            client.send_message(chan, f"spam {i}")
        except ChatError:
            return
        await asyncio.sleep(0.01)


def test_reconnecting_does_not_wipe_strikes_or_mute(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("flood_ban_minutes", 0)
            alice = await h.client("alice")
            await alice.join("#lobby")
            first = await guest(h)
            await first.join("#lobby")
            await until(lambda: first.key in alice.channels["#lobby"].recv and "alice" in first.channels["#lobby"].recv)
            await flood_until(first, "#lobby", lambda: any(d["action"] == "mute" for d in events(first, "ratelimit")))
            await until(lambda: any(d["action"] == "mute" for d in events(first, "ratelimit")))
            await first.close()
            await until(lambda: first.key not in h.server.sessions)

            again = await guest(h)                                   # new throwaway identity, same address
            await again.join("#lobby")
            await until(lambda: "alice" in again.channels["#lobby"].recv)
            again.send_message("#lobby", "sou novo, juro")
            await until(lambda: any("silenciado" in d["text"] for k, d in again.events if k == "system"))
            assert ("anon", "sou novo, juro") not in [(n[:4], t) for n, t in messages(alice)]
    run(main())


def test_flood_kick_bans_the_address_for_a_few_minutes(home):
    async def main():
        async with Harness(home) as h:
            alice = await h.client("alice")
            await alice.join("#lobby")
            flooder = await guest(h)
            await flooder.join("#lobby")
            await until(lambda: "alice" in flooder.channels["#lobby"].recv)
            await flood_until(flooder, "#lobby", lambda: bool(fatal_codes(flooder)))
            await until(lambda: fatal_codes(flooder))
            assert "bloqueado por 5 min" in events(flooder, "fatal")[0]["text"]
            row = h.server.db.execute("SELECT until, reason, label FROM ip_bans").fetchone()
            assert row[1] == "flood" and row[2] == flooder.nick and 280 < row[0] - time.time() <= 300
            back = await guest(h)                                    # same address: refused while it lasts
            assert fatal_codes(back) == ["banned"]
            assert alice.online                                      # already-connected sessions keep going
            assert h.server.admin({"op": "unban", "nick": flooder.nick})["ip"] == 1
            assert (await guest(h)).online
    run(main())


def test_flood_ban_can_be_turned_off_and_memory_expires(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("flood_ban_minutes", 0)
            h.server.limits.set("ip_memory", 0.3)
            alice = await h.client("alice")
            await alice.join("#lobby")
            flooder = await guest(h)
            await flooder.join("#lobby")
            await until(lambda: "alice" in flooder.channels["#lobby"].recv)
            await flood_until(flooder, "#lobby", lambda: bool(fatal_codes(flooder)))
            await until(lambda: fatal_codes(flooder))
            assert h.server.db.execute("SELECT COUNT(*) FROM ip_bans").fetchone()[0] == 0
            await asyncio.sleep(0.5)                                  # memory is gone
            fresh = await guest(h)
            assert fresh.online
            await fresh.join("#lobby")
            await until(lambda: "alice" in fresh.channels["#lobby"].recv)
            fresh.send_message("#lobby", "limpo")
            await until(lambda: any(t == "limpo" for _, t in messages(alice)))
            assert not events(fresh, "ratelimit")
    run(main())


def test_rate_limited_counter_counts_each_refusal_once(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("kick_after", 0)
            h.server.limits.set("mute_after", 0)
            alice = await h.client("alice")
            await alice.join("#lobby")
            n = int(DEFAULTS["msg_burst"]) + 4
            for i in range(n):
                alice.send_message("#lobby", f"m{i}")
            await until(lambda: sum(1 for k, d in alice.events if k == "system" and "não entregue" in d["text"]) == 4)
            assert h.server.counters["rate_limited"] == 4
    run(main())


# ------------------------------------------------------- review fixes (#6)

def test_banned_address_is_refused_before_the_welcome_and_never_shortened(home):
    async def main():
        async with Harness(home) as h:
            srv = h.server
            key = srv._ip_hash("127.0.0.1")
            srv.db.execute("INSERT INTO ip_bans VALUES (?,?,?,?,?)", (key, 0, "ataque", "veterano", int(time.time())))
            srv.db.commit()
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            frame = decode(await reader.readline())
            assert frame["t"] == "err" and frame["code"] == "banned" and "ataque" in frame["msg"]
            try:                                                     # pre-auth flood goes nowhere:
                for _ in range(600):                                 # the socket is already closed
                    writer.write(encode({"t": "ping"}))
                await writer.drain()
                assert await reader.readline() == b""
            except ConnectionError:
                pass
            writer.close()
            row = srv.db.execute("SELECT until, reason, label FROM ip_bans").fetchone()
            assert row == (0, "ataque", "veterano")                  # still permanent, same label
            client = await guest(h)
            assert fatal_codes(client) == ["banned"]                 # a fatal error: no reconnect loop

            # automatic bans only lengthen
            srv._extend_ip_ban("127.0.0.1", int(time.time()) + 300, "flood", "outro")
            assert srv.db.execute("SELECT until, label FROM ip_bans").fetchone() == (0, "veterano")
            srv.db.execute("UPDATE ip_bans SET until=?", (int(time.time()) + 3600,))
            srv._extend_ip_ban("127.0.0.1", int(time.time()) + 300, "flood", "outro")
            assert srv.db.execute("SELECT until FROM ip_bans").fetchone()[0] > time.time() + 3000
            srv._extend_ip_ban("127.0.0.1", 0, "flood", "outro")
            assert srv.db.execute("SELECT until, label FROM ip_bans").fetchone() == (0, "veterano")
            assert srv.admin({"op": "unban", "nick": "veterano"})["ip"] == 1
            assert (await guest(h)).online
    run(main())


def test_pre_auth_flood_gets_a_ban_that_can_be_lifted(home):
    async def main():
        async with Harness(home) as h:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            assert decode(await reader.readline())["t"] == "welcome"
            for _ in range(int(DEFAULTS["frame_burst"]) + 20):
                writer.write(encode({"t": "ping"}))
            await writer.drain()
            frames = []
            while True:
                line = await asyncio.wait_for(reader.readline(), 5)
                if not line:
                    break
                frames.append(decode(line))
            assert frames[-1]["t"] == "kicked" and "bloqueado por 5 min" in frames[-1]["msg"]
            label = h.server.db.execute("SELECT label FROM ip_bans").fetchone()[0]
            assert label.startswith("sem-login-") and "127.0.0.1" not in label
            assert "sem-login-" in json.dumps(h.server.admin({"op": "bans"}))
            assert h.server.admin({"op": "unban", "nick": label})["ip"] == 1
    run(main())


def test_address_memory_adds_up_every_session(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("flood_ban_minutes", 0)
            a, b = await guest(h), await guest(h)
            for _ in range(4):
                h.server.sessions[a.key].strikes.hit()
            h.server.sessions[b.key].strikes.hit()
            await a.close()
            await until(lambda: a.key not in h.server.sessions)
            await b.close()                                          # the last one to leave had just 1
            await until(lambda: b.key not in h.server.sessions)
            assert len(h.server.ip_memory["127.0.0.1"]["times"]) == 5
            c = await guest(h)
            assert len(h.server.sessions[c.key].strikes.times) == 5
            assert h.server.sessions[c.key].strikes.hit() == "kick"   # the 6th, counted across sessions
    run(main())
