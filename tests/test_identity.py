"""Etapa 1: readable fingerprints, TOFU with a blocking key-change flow, verified marks."""

import asyncio

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import ChatError
from crptochat.store import Identity, Store


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def test_fingerprint_and_safety_number():
    a, b = crypto.ed_pub(crypto.ed_generate()), crypto.ed_pub(crypto.ed_generate())
    fp = crypto.fingerprint(a)
    groups = fp.split()
    assert len(groups) == 6 and all(len(g) == 5 and g.isdigit() for g in groups)
    assert crypto.fingerprint(a) == fp != crypto.fingerprint(b)            # stable, and per key
    # both people see the same number, whoever computes it
    assert crypto.safety_number(a, b) == crypto.safety_number(b, a)
    assert len(crypto.safety_number(a, b).split()) == 12
    assert crypto.safety_number(a, b) != crypto.safety_number(a, crypto.ed_pub(crypto.ed_generate()))
    assert len(crypto.legacy_fingerprint(a).split()) == 5                  # what pre-1.1 clients show


def test_tofu_store_keeps_the_pinned_key_and_remembers_the_change(home):
    store = Store("srv")
    old, new = b"\x01" * 32, b"\x02" * 32
    assert store.check_user("Bob", old) == "new"
    assert store.check_user("bob", old) == "ok" and store.pending("bob") is None
    store.set_verified("bob")
    assert store.check_user("bob", new) == "mismatch"
    assert store.pinned("bob") == old and store.pending("bob") == new    # never silently adopted
    assert Store("srv").pending("bob") == new                              # survives a restart
    store.accept_key("bob", new)
    assert store.check_user("bob", new) == "ok" and not store.is_verified("bob")   # verification resets


def swap_key(h, nick):
    """What a malicious server would do: hand out a key it controls for `nick`."""
    mallory = crypto.ed_generate()
    sess = h.server.sessions[nick]
    sess.ik = crypto.ed_pub(mallory)
    sess.dh_sig = crypto.sign(mallory, crypto.dh_message(nick, sess.dh))
    return mallory


def test_changed_key_blocks_both_directions_until_accepted(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "antes")
            await until(lambda: messages(bob, "@alice"))
            alice.store.set_verified("bob")

            # bob reinstalls: same nick, new identity key (the server re-registers it)
            await bob.close()
            await until(lambda: "bob" not in h.server.sessions)
            h.server.db.execute("DELETE FROM users WHERE nick_lower='bob'")
            bob2 = await h.client("bob", identity=Identity.create("bob", "pw2", str(home / "new")))
            await until(lambda: bob2.online)

            with pytest.raises(ChatError) as err:                              # alice → bob blocked
                await alice.send_dm("bob", "para a chave nova")
            assert err.value.code == "untrusted" and "/verify bob" in str(err.value)
            changed = [d for k, d in alice.events if k == "key_changed"]
            assert len(changed) == 1 and changed[0]["new"] == bob2.identity.ik
            assert alice.peers["bob"].ik == bob.identity.ik                    # still the pinned key

            # bob2 → alice is dropped too, and alice is told once
            await bob2.send_dm("alice", "oi, sou eu")
            await bob2.send_dm("alice", "de novo")
            await asyncio.sleep(0.3)
            assert ("bob", "oi, sou eu") not in messages(alice, "@bob")
            assert sum("estão sendo recusadas" in d["text"] for k, d in alice.events if k == "system") == 1

            # after checking out of band, alice accepts: verification is reset, DMs flow again
            await alice.accept_key("bob", bob2.identity.ik)
            assert alice.peers["bob"].trusted and not alice.store.is_verified("bob")
            assert alice.store.pinned("bob") == bob2.identity.ik
            await alice.send_dm("bob", "agora sim")
            await until(lambda: ("alice", "agora sim") in messages(bob2, "@alice"))
            with pytest.raises(ChatError):
                await alice.accept_key("bob", bob2.identity.ik)                # nothing pending anymore
    run(main())


def test_accepting_restores_the_channel_keys(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.resolve("bob")
            swap_key(h, "bob")
            await alice.join("#lobby")
            await bob.join("#lobby")
            await until(lambda: "bob" in alice.channels["#lobby"].members)
            await asyncio.sleep(0.2)
            assert alice.peers["bob"].pending_ik
            assert "bob" not in alice.channels["#lobby"].recv                  # bob's channel key was refused

            # alice decides to accept (here the "new" key is the server's: that is
            # exactly what /verify is for; we only check the mechanics)
            h.server.sessions["bob"].ik = bob.identity.ik                       # server stops lying
            h.server.sessions["bob"].dh_sig = crypto.sign(bob.identity.key,
                                                           crypto.dh_message("bob", h.server.sessions["bob"].dh))
            alice.peers["bob"].pending_ik = bob.identity.ik
            await alice.accept_key("bob", bob.identity.ik)
            await until(lambda: "bob" in alice.channels["#lobby"].recv)        # re-requested with "skr"
            bob.send_message("#lobby", "de volta ao canal")
            await until(lambda: ("bob", "de volta ao canal") in messages(alice, "#lobby"))
    run(main())


def test_verify_flow_in_the_interface(home):
    from textual.widgets import OptionList

    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.tui import ChatApp, ChoiceScreen

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        events = []
        bob = ChatClient("127.0.0.1", port, Identity.create("bob", "pw"), Store("b"),
                         lambda k, d: events.append((k, d)), tls=False)
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

            async def choose(ident):
                await wait(lambda: isinstance(app.screen, ChoiceScreen))
                options = app.screen.query_one(OptionList)
                options.highlighted = options.get_option_index(ident)
                await pilot.press("enter")
                await wait(lambda: not app.in_dialog)

            def shown(name="console"):
                return " ".join(l.plain for l in app.buffers[name].lines)

            await wait(lambda: app.client.online and bob.online)
            await line("/whois bob")
            fp = crypto.fingerprint(bob.identity.ik)
            assert fp in shown() and "número de segurança" in shown()
            safety = crypto.safety_number(app.client.identity.ik, bob.identity.ik).split()
            assert " ".join(safety[:6]) in shown() and " ".join(safety[6:]) in shown()

            await line("/verify bob")
            await choose("yes")
            assert app.client.store.is_verified("bob")
            await line("/query bob")
            await wait(lambda: app.current == "@bob")
            assert "@bob ✓" in str(app.query_one("#buffers").render())

            # the server swaps bob's key: strong alert, blocked, ⚠ everywhere
            swap_key(type("H", (), {"server": server})(), "bob")
            app.client.peers["bob"].dh = None
            await line("mensagem para a chave nova")
            await wait(lambda: "ALERTA DE SEGURANÇA" in shown("@bob"))
            assert "MUDOU" in shown("console") and "bloqueadas" in shown("@bob")
            assert not any(k == "message" for k, d in events)
            assert "@bob ⚠" in str(app.query_one("#buffers").render())
            assert "CHAVE MUDOU" in str(app.query_one("#members").render())

            # /verify: "keep" leaves it blocked, "accept" adopts it without ✓
            await line("/verify bob")
            await choose("keep")
            assert app.client.peers["bob"].pending_ik
            await line("/verify bob")
            await choose("accept")
            assert not app.client.peers["bob"].pending_ik and not app.client.store.is_verified("bob")
            assert "⚠" not in str(app.query_one("#buffers").render())
            await line("/quit")
        await bob.close()
        btask.cancel()
        await server.stop()
    asyncio.run(main())


def test_accept_refuses_if_the_pending_key_changed_after_it_was_shown(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.resolve("bob")
            first = swap_key(h, "bob")
            await alice.resolve("bob")
            shown = alice.peers["bob"].pending_ik
            assert shown == crypto.ed_pub(first)
            # while the user reads the dialog, the server presents another key
            second = swap_key(h, "bob")
            await alice.resolve("bob")
            assert alice.peers["bob"].pending_ik == crypto.ed_pub(second)
            with pytest.raises(ChatError) as err:
                await alice.accept_key("bob", shown)
            assert err.value.code == "pending_changed"
            assert alice.store.pinned("bob") == bob.identity.ik            # nothing was accepted
            assert not alice.peers["bob"].trusted
            with pytest.raises(ChatError):
                await alice.accept_key("bob", b"\x00" * 32)               # nor a key never shown
    run(main())
