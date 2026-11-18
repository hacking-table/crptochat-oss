"""Replies, reactions, edits, deletions and (opt-in) read receipts."""

import asyncio

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import client as client_mod
from crptochat import crypto


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def events(client, kind):
    return [d for k, d in client.events if k == kind]


async def lobby(alice, bob):
    await alice.join("#lobby")
    await bob.join("#lobby")
    await until(lambda: bob.key in alice.channels["#lobby"].recv and alice.key in bob.channels["#lobby"].recv)


def test_annotations_in_a_channel(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await lobby(alice, bob)
            mid = alice.send_message("#lobby", "reunião às 15h")
            await until(lambda: messages(bob))
            got = events(bob, "message")[-1]
            assert got["mid"] == mid and got["reply"] is None

            target = {"id": mid, "n": "alice", "text": "reunião às 15h"}
            await bob.annotate("#lobby", "reply", target, "pode ser às 16h?")
            await bob.annotate("#lobby", "react", target, "👍")
            await until(lambda: events(alice, "react"))
            reply = [d for d in events(alice, "message") if d["nick"] == "bob"][0]
            assert reply["text"] == "pode ser às 16h?"
            assert reply["reply"] == {"id": mid, "n": "alice", "q": "reunião às 15h"}
            assert events(alice, "react")[0] == {"buffer": "#lobby", "nick": "bob", "target": mid, "emoji": "👍"}

            await alice.annotate("#lobby", "edit", target, "reunião às 16h")
            await alice.annotate("#lobby", "delete", target)
            await until(lambda: events(bob, "delete"))
            assert events(bob, "edit")[0] == {"buffer": "#lobby", "nick": "alice", "target": mid,
                                              "text": "reunião às 16h"}
            assert events(bob, "delete")[0] == {"buffer": "#lobby", "nick": "alice", "target": mid}
            # none of these show up as new messages for a current client
            assert [t for n, t in messages(bob) if n == "alice"] == ["reunião às 15h"]
    run(main())


def test_older_clients_see_a_readable_fallback(home, monkeypatch):
    async def main():
        async with Harness(home) as h:
            alice, old = await h.client("alice"), await h.client("antigo")
            await lobby(alice, old)
            mid = alice.send_message("#lobby", "bom dia")
            await until(lambda: messages(old))
            monkeypatch.setattr(client_mod, "_annotations", lambda *a: None)    # a client without the feature
            target = {"id": mid, "n": "alice", "text": "bom dia"}
            for kind, value in (("react", "👍"), ("edit", "bom dia a todos"), ("delete", "")):
                await alice.annotate("#lobby", kind, target, value)
            await until(lambda: len(messages(old)) == 4)
            assert [t for _, t in messages(old)][1:] == ["👍 (reagiu a “bom dia”)", "[editou] bom dia a todos",
                                                         "[apagou uma mensagem]"]
    run(main())


def test_direct_messages_and_read_receipts(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            await alice.send_dm("bob", "oi")
            await until(lambda: messages(bob, "@alice"))
            mid = events(bob, "message")[-1]["mid"]
            assert mid and events(alice, "message")[-1]["mid"] == mid

            bob.send_read("alice", [mid])                  # off by default: nothing is sent
            alice.receipts = True
            await asyncio.sleep(0.2)
            assert not events(alice, "read")

            bob.receipts = True
            bob.send_read("alice", [mid])
            await until(lambda: events(alice, "read"))
            assert events(alice, "read")[0] == {"buffer": "@bob", "nick": "bob", "ids": [mid]}

            alice.receipts = False                         # whoever turned them off does not see them either
            bob.send_read("alice", [mid])
            await bob.annotate("@alice", "react", {"id": mid, "n": "alice", "text": "oi"}, "❤️")
            await until(lambda: events(alice, "react"))
            assert len(events(alice, "read")) == 1
    run(main())


def test_the_interface(home):
    from test_tui_features import World, lines, type_line
    from test_tui_features import until as ui_until

    async def main():
        world = World(home)
        app = await world.start()
        async with app.run_test(size=(130, 40)) as pilot:
            await ui_until(pilot, lambda: app.client.online)
            trinity = await world.peer("trinity")
            await type_line(pilot, "/join #lobby")
            await ui_until(pilot, lambda: app.current == "#lobby")
            await trinity.join("#lobby")
            await ui_until(pilot, lambda: "trinity" in app.client.channels["#lobby"].recv
                           and "neo" in trinity.channels["#lobby"].recv)

            mid = trinity.send_message("#lobby", "alguém viu o coelho branco?")
            await ui_until(pilot, lambda: any("coelho branco" in line for line in lines(app)))
            await type_line(pilot, "/react +1")
            await type_line(pilot, "/reply trinity vi sim, na festa")
            await ui_until(pilot, lambda: any("vi sim, na festa" in line and "↪ trinity" in line for line in lines(app)))
            await ui_until(pilot, lambda: any(k == "react" for k, _ in trinity.events))
            assert [d["emoji"] for k, d in trinity.events if k == "react"] == ["👍"]

            # trinity reacts to my reply, edits and deletes her own message
            target = {"id": mid, "n": "trinity", "text": "alguém viu o coelho branco?"}
            mine = app.buffers["#lobby"].last(True)
            await trinity.annotate("#lobby", "react", {"id": mine[0], "n": "neo", "text": "x"}, "🔥")
            await trinity.annotate("#lobby", "edit", target, "alguém viu o coelho BRANCO?")
            await ui_until(pilot, lambda: any("coelho BRANCO? (editada)" in line for line in lines(app)))
            await ui_until(pilot, lambda: any("vi sim, na festa" in line and "🔥 trinity" in line for line in lines(app)))
            await trinity.annotate("#lobby", "delete", target)
            await ui_until(pilot, lambda: any("mensagem apagada" in line for line in lines(app)))
            assert not any("coelho" in line and "↪" not in line for line in lines(app))

            # nobody edits someone else's message
            await type_line(pilot, "hora de acordar")
            mine = app.buffers["#lobby"].last(True)
            await trinity.annotate("#lobby", "edit", {"id": mine[0], "n": "neo", "text": "x"}, "forjado")
            await asyncio.sleep(0.2)
            assert not any("forjado" in line for line in lines(app))

            # my own edit and delete
            await type_line(pilot, "/edit hora de acordar, Neo")
            await ui_until(pilot, lambda: any("hora de acordar, Neo (editada)" in line for line in lines(app)))
            await type_line(pilot, "/del")
            await ui_until(pilot, lambda: sum("mensagem apagada" in line for line in lines(app)) == 2)

            # read receipts, only when both turned them on
            await type_line(pilot, "/receipts on")
            trinity.receipts = True
            await type_line(pilot, "/msg trinity me liga")
            await ui_until(pilot, lambda: app.current == "@trinity" or "@trinity" in app.buffers)
            await ui_until(pilot, lambda: [d for k, d in trinity.events if k == "message" and d["buffer"] == "@neo"])
            got = [d for k, d in trinity.events if k == "message" and d["buffer"] == "@neo"][-1]
            trinity.send_read("neo", [got["mid"]])
            await ui_until(pilot, lambda: any("me liga" in line and "✓✓" in line for line in lines(app, "@trinity")))
            await type_line(pilot, "/quit")
        await world.stop()
    asyncio.run(main())
