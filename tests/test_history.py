"""Etapa 6: encrypted history for private channels (off by default, per channel)."""

import asyncio
import json
import time

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatError, NeedPassphrase
from crptochat.protocol import b64d, b64e
from crptochat.store import Identity


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def history(client, chan):
    return [(e["nick"], e["text"], e["verified"]) for k, d in client.events if k == "history" and d["chan"] == chan
            for e in d["entries"]]


def stored(h, chan="#cofre"):
    return h.server.db.execute("SELECT id, ts, expires, epoch, blob FROM history WHERE chan=?", (chan,)).fetchall()


async def private_room(h, *nicks, days=7):
    owner = await h.client(nicks[0])
    await owner.create("#cofre", "senha-forte-1")
    if days:
        await owner.set_policy("#cofre", history=days)
    others = []
    for nick in nicks[1:]:
        c = await h.client(nick)
        await c.join("#cofre", "senha-forte-1")
        others.append(c)
    return owner, others


def test_key_derivation_is_split_by_purpose():
    salt = b"s" * 16
    auth, psk, hkey = crypto.channel_secrets("senha", salt)
    assert len({auth, psk, hkey}) == 3
    assert crypto.channel_keys("senha", salt) == (auth, psk)                    # older code path unchanged
    assert crypto.channel_secrets("senha", b"t" * 16)[2] != hkey                 # salt per channel
    blob = crypto.history_seal(hkey, "#a", 0, b"oi")
    assert crypto.history_open(hkey, "#a", 0, blob) == b"oi"
    for chan, epoch in (("#b", 0), ("#a", 1)):                                   # bound to channel and epoch
        with pytest.raises(crypto.CryptoError):
            crypto.history_open(hkey, chan, epoch, blob)


def test_off_by_default_and_only_for_private_channels(home):
    async def main():
        async with Harness(home) as h:
            alice = await h.client("alice")
            assert "history" in alice.server_caps
            await alice.create("#aberto")
            with pytest.raises(ChatError) as err:
                await alice.set_policy("#aberto", history=7)
            assert "privados" in str(err.value)
            await alice.create("#cofre", "senha-forte-1")
            assert alice.channels["#cofre"].policy["history"] == 0
            alice.send_message("#cofre", "não fica guardado")
            await asyncio.sleep(0.2)
            assert stored(h) == []
            assert not any('"h"' in w for w in h.wire)                            # no copy is even sent
            with pytest.raises(ChatError):
                await alice.set_policy("#cofre", history=10_000)                  # above history_max_days
    run(main())


def test_server_only_keeps_ciphertext_and_members_get_verified_history(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            alice.send_message("#cofre", "segredo guardado")
            await until(lambda: ("alice", "segredo guardado") in messages(bob, "#cofre"))
            bob.send_message("#cofre", "resposta do bob")
            await until(lambda: len(stored(h)) == 2)
            dump = h.server.db.execute("SELECT * FROM history").fetchall()
            assert b"segredo" not in repr(dump).encode() and b"resposta" not in repr(dump).encode()
            assert all("segredo" not in w for w in h.wire)

            carol = await h.client("carol")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("alice", "segredo guardado", True), ("bob", "resposta do bob", True)]
            exp = [e["expires"] for k, d in carol.events if k == "history" for e in d["entries"]]
            assert all(time.time() + 6 * 86400 < x <= time.time() + 7 * 86400 + 5 for x in exp)
    run(main())


def insert(h, blob, sender, epoch=0, reenc=0):
    now = int(time.time())
    h.server.db.execute("INSERT INTO history (chan, ts, expires, epoch, blob, sender, reenc) VALUES (?,?,?,?,?,?,?)",
                        ("#cofre", now, now + 3600, epoch, bytes(blob), sender, reenc))
    h.server.db.commit()


def forged(ch, author, signer, text, epoch=0, line_id="AAAAAAAAAAAAAAAA", **extra):
    ts = int(time.time())
    entry = {"n": author, "ik": b64e(crypto.ed_pub(signer)), "ts": ts, "id": line_id, "x": text,
             "s": b64e(crypto.sign(signer, crypto.history_signed("#cofre", extra.get("e", epoch), author, ts,
                                                                   text, line_id)))}
    entry.update(extra)
    return crypto.history_seal(ch.hkey, "#cofre", epoch, json.dumps(entry).encode())


def test_replayed_forged_and_garbled_lines_are_refused(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            alice.send_message("#cofre", "original")
            await until(lambda: len(stored(h)) == 1)
            row = stored(h)[0]
            assert h.server.db.execute("SELECT sender FROM history").fetchone()[0] == "alice"
            ch = bob.channels["#cofre"]
            insert(h, bytes(row[4][:-1]) + b"\0", "alice")                      # garbled by the server
            insert(h, row[4], "bob")                    # bob re-posts alice's signed line as his upload
            insert(h, row[4], "alice")                  # the same line twice: shown once
            insert(h, forged(ch, "alice", bob.identity.key, "alice disse isso?"), "bob")   # claims to be alice
            # a server that lies about the uploader still can't make bob's key pass for alice's
            insert(h, forged(ch, "alice", bob.identity.key, "mentira", line_id="BBBBBBBBBBBBBBBB"), "alice")
            # an old-epoch line wrapped by a member (not re-encrypted by the owner on /chanpass)
            insert(h, forged(ch, "alice", alice.identity.key, "velha", line_id="CCCCCCCCCCCCCCCC", e=-1), "alice")
            carol = await h.client("carol")
            await carol.resolve("alice")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            await asyncio.sleep(0.2)
            assert history(carol, "#cofre") == [("alice", "original", True), ("alice", "mentira", False)]
    run(main())


def test_one_sender_cannot_push_the_others_out(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("history_max_msgs", 8)
            h.server.limits.set("history_per_sender", 5)
            h.server.limits.set("msg_burst", 100)
            alice, (bob,) = await private_room(h, "alice", "bob")
            alice.send_message("#cofre", "importante")
            await until(lambda: len(stored(h)) == 1)
            for i in range(30):                         # bob floods (valid or garbage, the server can't tell)
                bob._send({"t": "msg", "chan": "#cofre", "body": b64e(b"\0" * 64), "h": b64e(b"lixo" * 8)})
            await until(lambda: len(stored(h)) == 6)
            await asyncio.sleep(0.2)
            senders = [r[0] for r in h.server.db.execute("SELECT sender FROM history ORDER BY id")]
            assert senders.count("bob") == 5 and senders.count("alice") == 1    # per-sender quota
            carol = await h.client("carol")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("alice", "importante", True)]
            delivered = h.server.history_for(h.server.sessions["carol"], "#cofre")
            assert [d["from"] for d in delivered].count("alice") == 1
    run(main())


def test_history_is_not_shown_again_on_reconnect_nor_for_lines_seen_live(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            alice.send_message("#cofre", "ao vivo")
            await until(lambda: ("alice", "ao vivo") in messages(bob, "#cofre"))
            await bob.leave("#cofre")
            alice.send_message("#cofre", "enquanto bob estava fora")
            await until(lambda: len(stored(h)) == 2)
            await bob.join("#cofre", "senha-forte-1")
            await until(lambda: history(bob, "#cofre"))
            assert history(bob, "#cofre") == [("alice", "enquanto bob estava fora", True)]
            # the connection drops and comes back: no second history block
            h.server.sessions["bob"].close()
            await until(lambda: not bob.online)
            await until(lambda: bob.online and bob.channels.get("#cofre") and bob.channels["#cofre"].joined, 15)
            await asyncio.sleep(0.3)
            assert len([k for k, d in bob.events if k == "history"]) == 1
    run(main())


def test_too_big_for_the_history_warns_the_sender(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            assert alice.history_body() == 12 * 1024
            alice.send_message("#cofre", "é" * 3000)          # \u00e9 in JSON: ~24 KiB once sealed
            await until(lambda: ("alice", "é" * 3000) in messages(bob, "#cofre"))
            assert stored(h) == []
            assert any(k == "system" and "não entrou no histórico" in d["text"] for k, d in alice.events)
    run(main())


def test_expiry_really_deletes_and_ttl_wins(home):
    async def main():
        async with Harness(home) as h:
            alice, _ = await private_room(h, "alice", days=3)
            await alice.set_policy("#cofre", ttl=60)
            alice.send_message("#cofre", "curto")
            await until(lambda: len(stored(h)) == 1)
            assert stored(h)[0][2] <= time.time() + 61                            # the shorter one applies
            h.server.db.execute("UPDATE history SET expires=1")
            assert h.server.purge_history() == 1 and stored(h) == []
            # lowering the days shortens what is already stored; turning it off deletes it
            await alice.set_policy("#cofre", ttl=0)
            alice.send_message("#cofre", "longo")
            await until(lambda: len(stored(h)) == 1)
            await alice.set_policy("#cofre", history=1)
            assert stored(h)[0][2] <= time.time() + 86400 + 1
            await alice.set_policy("#cofre", history=0)
            assert stored(h) == []
            secure = h.server.db.execute("PRAGMA secure_delete").fetchone()[0]
            assert secure == 1
    run(main())


def test_only_the_last_messages_are_handed_out(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("history_max_msgs", 3)
            h.server.limits.set("history_keep_msgs", 5)
            alice, _ = await private_room(h, "alice")
            for i in range(8):
                alice.send_message("#cofre", f"m{i}")
            await until(lambda: len(stored(h)) == 5)
            await asyncio.sleep(0.2)
            assert len(stored(h)) == 5                                            # keep limit on the server
            bob = await h.client("bob")
            await bob.join("#cofre", "senha-forte-1")
            await until(lambda: history(bob, "#cofre"))
            assert [t for _, t, _ in history(bob, "#cofre")] == ["m5", "m6", "m7"]
    run(main())


def test_anonymous_users_only_get_history_when_allowed(home):
    async def main():
        async with Harness(home) as h:
            alice, _ = await private_room(h, "alice")
            alice.send_message("#cofre", "para registrados")
            await until(lambda: len(stored(h)) == 1)
            ident = Identity("guest", crypto.ed_generate())
            anon = await h.client(crypto.guest_nick(ident.ik), identity=ident, guest=True)
            await anon.join("#cofre", "senha-forte-1")
            await asyncio.sleep(0.3)
            assert history(anon, "#cofre") == []
            await anon.leave("#cofre")
            await alice.set_policy("#cofre", history_anon=True)
            await anon.join("#cofre", "senha-forte-1")
            await until(lambda: history(anon, "#cofre"))
    run(main())


def test_password_change_rotates_the_key(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            alice.send_message("#cofre", "antes da troca")
            await until(lambda: len(stored(h)) == 1)
            old_hkey = alice.channels["#cofre"].hkey
            reply = await alice.change_password("#cofre", "senha-nova-22")
            assert reply["epoch"] == 1 and stored(h) == []                       # default: old history gone
            assert alice.channels["#cofre"].hkey != old_hkey
            await until(lambda: "#cofre" not in bob.channels)                    # bob was put out
            assert any(k == "kicked_from" and "senha" in d["reason"] for k, d in bob.events)
            with pytest.raises(ChatError):
                await bob.join("#cofre", "senha-forte-1")                        # old password refused
            await bob.join("#cofre", "senha-nova-22")
            alice.send_message("#cofre", "depois da troca")
            await until(lambda: ("alice", "depois da troca") in messages(bob, "#cofre"))
            await until(lambda: len(stored(h)) == 1)
            assert stored(h)[0][3] == 1
            with pytest.raises(crypto.CryptoError):                              # old key can't read the new
                crypto.history_open(old_hkey, "#cofre", 1, bytes(stored(h)[0][4]))
    run(main())


def test_password_change_with_reencryption_keeps_history_readable(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            bob.send_message("#cofre", "linha do bob")
            await until(lambda: len(stored(h)) == 1)
            old_hkey = alice.channels["#cofre"].hkey
            with pytest.raises(ChatError):
                await bob.change_password("#cofre", "tentativa-do-bob")          # only the owner
            reply = await alice.change_password("#cofre", "senha-nova-22", reencrypt=True)
            assert reply["kept"] == 1 and stored(h)[0][3] == 1
            with pytest.raises(crypto.CryptoError):
                crypto.history_open(old_hkey, "#cofre", 1, bytes(stored(h)[0][4]))
            carol = await h.client("carol")
            with pytest.raises(NeedPassphrase):
                await carol.join("#cofre")
            await carol.join("#cofre", "senha-nova-22")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("bob", "linha do bob", True)]   # bob's signature still checks
    run(main())


def test_old_clients_and_servers_are_unaffected(home):
    async def main():
        async with Harness(home) as h:
            alice, (bob,) = await private_room(h, "alice", "bob")
            # a 1.0.0-style frame (no "h") is relayed but never stored
            bob._send({"t": "msg", "chan": "#cofre", "body": b64e(b"\0" * 32)})
            await asyncio.sleep(0.2)
            assert stored(h) == []
            # a client talking to a server without the capability never sends copies
            alice.server_caps = set(alice.server_caps) - {"history"}
            alice.send_message("#cofre", "sem cópia")
            await until(lambda: ("alice", "sem cópia") in messages(bob, "#cofre"))
            assert stored(h) == []
            # the join reply for an old client still has the same fields plus extras it ignores
            info = await bob.request({"t": "chaninfo", "chan": "#cofre"})
            assert info["private"] and b64d(info["salt"], 16)
    run(main())


def test_history_in_the_interface(home):
    from textual.widgets import OptionList

    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.store import Store
    from crptochat.tui import ChatApp, ChoiceScreen, PassScreen

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        events = []
        bob = ChatClient("127.0.0.1", port, Identity.create("bob", "pw"), Store("b"),
                         lambda k, d: events.append((k, d)), tls=False)
        bob.events = events
        btask = asyncio.create_task(bob.run())
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"),
                                            Store(f"127.0.0.1:{port}"), ev, tls=False))
        async with app.run_test(size=(130, 40)) as pilot:
            async def wait(cond):
                for _ in range(400):
                    if cond():
                        return
                    await pilot.pause(0.02)
                raise AssertionError("condition not reached")

            async def line(text):
                app.input.value = text
                await pilot.press("enter")
                await pilot.pause(0.05)

            def shown(name):
                return " ".join(l.plain for l in app.buffers[name].lines)

            await wait(lambda: app.client.online and bob.online)
            await app.client.create("#cofre", "senha-forte-1")
            await wait(lambda: app.current == "#cofre")
            assert "HISTÓRICO" not in str(app.query_one("#center").border_title)
            await line("/mode +h 3")
            await wait(lambda: "HISTÓRICO LIGADO (3 d)" in str(app.query_one("#center").border_title))
            assert "guarda o histórico CIFRADO" in str(app.query_one("#center").border_subtitle)
            assert "HISTÓRICO LIGADO em #cofre" in shown("#cofre")

            await bob.join("#cofre", "senha-forte-1")
            bob.send_message("#cofre", "guardado pelo bob")
            await wait(lambda: "guardado pelo bob" in shown("#cofre"))

            # rejoining shows what was said meanwhile, apart, with the signature mark
            await line("/leave")
            bob.send_message("#cofre", "enquanto neo estava fora")
            await asyncio.sleep(0.3)
            await app.client.join("#cofre", "senha-forte-1")
            await wait(lambda: "fim do histórico" in shown("#cofre"))
            text = shown("#cofre")
            assert "histórico guardado (cifrado)" in text and "✓ enquanto neo estava fora" in text
            assert "✓ guardado pelo bob" not in text                              # already seen live

            # password change: new password twice, then choose to re-encrypt
            await line("/chanpass")
            await wait(lambda: isinstance(app.screen, PassScreen))
            for _ in range(2):
                await pilot.press(*"senha-nova-22")
                await pilot.press("enter")
            await wait(lambda: isinstance(app.screen, ChoiceScreen))
            options = app.screen.query_one(OptionList)
            options.highlighted = options.get_option_index("keep")
            await pilot.press("enter")
            await wait(lambda: "re-cifradas" in shown("#cofre"))
            await wait(lambda: "#cofre" not in bob.channels)
            await line("/mode -h")
            await wait(lambda: "histórico desligado" in shown("#cofre"))
            assert "HISTÓRICO" not in str(app.query_one("#center").border_title)
            await line("/quit")
        await bob.close()
        btask.cancel()
        await server.stop()
    asyncio.run(main())


async def anons(h, n):
    out = []
    for _ in range(n):
        ident = Identity("guest", crypto.ed_generate())
        c = await h.client(crypto.guest_nick(ident.ik), identity=ident, guest=True)
        await c.join("#cofre", "senha-forte-1")
        out.append(c)
    return out


def flood(h, client, n):
    """What the server would store if ``client`` got ``n`` copies through (bypasses rate limits)."""
    sess = h.server.sessions[client.key]
    for i in range(n):
        h.server._store_history(sess, "#cofre", b64e(b"lixo-%d" % i * 4))


def test_anonymous_users_do_not_write_history_unless_allowed(home):
    async def main():
        async with Harness(home) as h:
            alice, _ = await private_room(h, "alice")
            guests = await anons(h, 5)
            for g in guests:
                flood(h, g, 200)
            guests[0].send_message("#cofre", "anônimo")
            await asyncio.sleep(0.2)
            assert stored(h) == []
    run(main())


def test_five_anonymous_floods_do_not_erase_the_real_history(home):
    async def main():
        async with Harness(home) as h:
            alice, _ = await private_room(h, "alice")
            await alice.set_policy("#cofre", history_anon=True)
            for i in range(3):
                alice.send_message("#cofre", f"real {i}")
            await until(lambda: len(stored(h)) == 3)
            for g in await anons(h, 5):
                flood(h, g, 200)                                   # 1000 more: the channel limit
            senders = [r[0] for r in h.server.db.execute("SELECT sender FROM history")]
            # all anonymous identities together count as one sender: 200 lines between them
            assert len(senders) == 203 and senders.count("alice") == 3
            carol = await h.client("carol")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("alice", f"real {i}", True) for i in range(3)]
    run(main())


def test_four_registered_floods_do_not_take_every_slot(home):
    async def main():
        async with Harness(home) as h:
            alice, others = await private_room(h, "alice", "mal1", "mal2", "mal3", "mal4")
            for i in range(3):
                alice.send_message("#cofre", f"real {i}")
            await until(lambda: len(stored(h)) == 3)
            for c in others:
                flood(h, c, 200)
            delivered = h.server.history_for(h.server.sessions["alice"], "#cofre")
            froms = [d["from"] for d in delivered]
            assert len(froms) == 100 and froms.count("alice") == 3
            assert all(froms.count(c.key) in (24, 25) for c in others)   # the rest is split evenly
            carol = await h.client("carol")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("alice", f"real {i}", True) for i in range(3)]
    run(main())


def test_many_one_line_anonymous_identities_do_not_erase_the_real_history(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("history_keep_msgs", 50)
            alice, _ = await private_room(h, "alice")
            await alice.set_policy("#cofre", history_anon=True)
            for i in range(3):
                alice.send_message("#cofre", f"real {i}")
            await until(lambda: len(stored(h)) == 3)
            # 60 throwaway identities, one line each (as if reconnecting with a new key every time)
            for n in range(60):
                nick = crypto.guest_nick(crypto.ed_pub(crypto.ed_generate()))
                fake = type("S", (), {"key": nick.lower(), "guest": True})()
                h.server._store_history(fake, "#cofre", b64e(b"lixo-%d" % n * 4))
            senders = [r[0] for r in h.server.db.execute("SELECT sender FROM history")]
            assert len(senders) == 50 and senders.count("alice") == 3
            delivered = h.server.history_for(h.server.sessions["alice"], "#cofre")
            assert [d["from"] for d in delivered].count("alice") == 3
            carol = await h.client("carol")
            await carol.join("#cofre", "senha-forte-1")
            await until(lambda: history(carol, "#cofre"))
            assert history(carol, "#cofre") == [("alice", f"real {i}", True) for i in range(3)]
    run(main())


def test_lowering_the_limit_trims_in_one_go(home):
    async def main():
        async with Harness(home) as h:
            h.server.limits.set("history_keep_msgs", 5000)
            h.server.limits.set("history_per_sender", 5000)
            alice, _ = await private_room(h, "alice")
            now = int(time.time())
            rows = [("#cofre", now, now + 3600, 0, b"x" * 64, "alice" if i % 50 else "bob") for i in range(5000)]
            h.server.db.executemany("INSERT INTO history (chan, ts, expires, epoch, blob, sender) "
                                    "VALUES (?,?,?,?,?,?)", rows)
            h.server.db.commit()
            h.server.limits.set("history_keep_msgs", 100)
            started = time.perf_counter()
            removed = h.server.purge_history()                       # the periodic cleanup applies it
            elapsed = time.perf_counter() - started
            assert removed == 4900 and len(stored(h)) == 100
            assert elapsed < 0.5, elapsed
            senders = [r[0] for r in h.server.db.execute("SELECT sender FROM history")]
            assert senders.count("bob") == 50                        # the small sender keeps everything
    run(main())
