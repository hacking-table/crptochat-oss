"""The new interface features, driven through the real TUI against a real server."""

import asyncio
import os

import pytest
from textual.widgets import OptionList

from crptochat import crypto, themes, tui
from crptochat.client import ChatClient
from crptochat.server import Server
from crptochat.store import Identity, Store, load_prefs
from crptochat.tui import ChatApp, ChoiceScreen, FormScreen


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    yield tmp_path
    tui.set_palette(themes.DEFAULT)


async def until(pilot, cond, timeout=8):
    deadline = asyncio.get_running_loop().time() + timeout
    while not cond():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await pilot.pause(0.02)


def text(widget) -> str:
    return str(widget.render())


def lines(app, name=None):
    return [line.plain for line in app.buffers[name or app.current].lines]


class World:
    """A server, a few scripted peers and the app under test."""

    def __init__(self, home):
        self.home = home
        self.peers = {}

    async def start(self, app_nick="neo", guest=False):
        self.server = Server(str(self.home / "srv"), reg_limit=0)
        self.port = await self.server.start("127.0.0.1", 0)
        ident = Identity("anon", crypto.ed_generate()) if guest else Identity.create(app_nick, "pw")
        self.app = ChatApp(lambda ev: ChatClient("127.0.0.1", self.port, ident, Store(f"127.0.0.1:{self.port}"), ev,
                                                 tls=False, guest=guest))
        return self.app

    async def peer(self, nick):
        events = []
        client = ChatClient("127.0.0.1", self.port, Identity.create(nick, "pw"), Store("p-" + nick),
                            lambda k, d: events.append((k, d)), tls=False)
        client.events = events
        self.peers[nick] = (client, asyncio.create_task(client.run()))
        for _ in range(400):
            if client.online:
                break
            await asyncio.sleep(0.01)
        return client

    async def stop(self):
        for client, task in self.peers.values():
            await client.close()
            task.cancel()
        await self.server.stop()


async def choose(pilot, app, ident):
    await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
    screen = app.screen
    options = screen.query_one(OptionList)
    options.highlighted = options.get_option_index(ident)
    await pilot.press("enter")
    await until(pilot, lambda: app.screen is not screen)


async def type_line(pilot, line):
    pilot.app.input.value = line
    await pilot.press("enter")
    await pilot.pause(0.05)


def test_themes_preview_apply_and_persist(home):
    async def main():
        world = World(home)
        app = await world.start()
        async with app.run_test(size=(120, 36)) as pilot:
            await until(pilot, lambda: app.client.online)
            await type_line(pilot, "/join #lobby")
            await until(pilot, lambda: app.current == "#lobby")
            await type_line(pilot, "uma linha antes da troca")
            neon = themes.palette("neon")[0]
            assert app.get_css_variables()["cc-bg"] == neon["BG"]

            # menu: arrows preview live, Esc restores the previous theme
            await pilot.press("escape")
            await choose(pilot, app, "theme")
            await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
            options = app.screen.query_one(OptionList)
            options.highlighted = options.get_option_index("matrix")
            await pilot.pause(0.1)
            assert tui.THEME == "matrix" and tui.CYAN == themes.palette("matrix")[0]["CYAN"]
            await pilot.press("escape")
            await until(pilot, lambda: not app.in_dialog)
            assert tui.THEME == "neon" and "theme" not in load_prefs()

            # applying recolours what is already on screen, the CSS and the prefs
            await pilot.press("escape")
            await choose(pilot, app, "theme")
            await choose(pilot, app, "synthwave")
            synth = themes.palette("synthwave")[0]
            assert tui.THEME == "synthwave" and load_prefs()["theme"] == "synthwave"
            assert app.get_css_variables()["cc-bg"] == synth["BG"]
            old_colours = set(themes.palette("neon")[0].values()) | set(themes.palette("neon")[1])
            for buf in app.buffers.values():
                for line in buf.lines:
                    styles = [str(line.style)] + [str(span.style) for span in line.spans]
                    assert not any(colour in style for style in styles for colour in old_colours), line.plain

            await type_line(pilot, "/theme papel")
            assert tui.THEME == "papel" and not themes.is_dark("papel")
            await type_line(pilot, "/theme inexistente")
            assert any("tema desconhecido" in line for line in lines(app))
            await type_line(pilot, "/quit")

        # a new session starts with the saved theme
        app2 = ChatApp(lambda ev: ChatClient("127.0.0.1", world.port, Identity.create("trinity", "pw"),
                                             Store("x"), ev, tls=False))
        assert tui.THEME == "papel"
        async with app2.run_test(size=(100, 30)) as pilot:
            assert app2.get_css_variables()["cc-bg"] == themes.palette("papel")[0]["BG"]
            await type_line(pilot, "/quit")
        await world.stop()
    asyncio.run(main())


def test_every_theme_is_complete():
    for name in themes.THEMES:
        slots, nicks = themes.palette(name)
        colours = list(slots.values()) + nicks
        assert len(nicks) == 10 and set(slots) == set(themes.SLOTS)
        assert len(set(colours)) == len(colours), name          # needed for live recolouring
        assert all(len(c) == 7 and c.startswith("#") for c in colours)


def test_friends_away_and_roles_in_the_interface(home):
    async def main():
        world = World(home)
        app = await world.start()
        async with app.run_test(size=(130, 40)) as pilot:
            await until(pilot, lambda: app.client.online)
            trinity = await world.peer("trinity")

            # friends: added by command, shown in the sidebar with presence
            await type_line(pilot, "/friend add ghost")
            assert any("não existe" in line for line in lines(app))
            await type_line(pilot, "/friend add Trinity")
            await until(pilot, lambda: app.presence.get("trinity") == "on")
            assert app.client.store.friends() == ["trinity"]
            assert "amigos" in text(app.query_one("#buffers")) and "trinity" in text(app.query_one("#buffers"))
            await trinity.set_away("almoçando")
            await app.poll_presence()
            assert app.presence["trinity"] == "away"
            await trinity.close()
            world.peers["trinity"][1].cancel()
            await until(pilot, lambda: "trinity" not in world.server.sessions)
            await app.poll_presence()
            assert "seu amigo trinity saiu" in " ".join(lines(app, tui.CONSOLE))

            # clicking a friend opens the conversation
            app.switch(tui.CONSOLE)
            row = app.query_one("#buffers").rows.index("@trinity")
            await pilot.click("#buffers", offset=(4, row + 1))
            await until(pilot, lambda: app.current == "@trinity")

            # away: badge, then back
            await type_line(pilot, "/away reunião")
            await until(pilot, lambda: app.client.away)
            assert "AUSENTE" in text(app.query_one("#topbar"))
            await type_line(pilot, "/back")
            await until(pilot, lambda: not app.client.away)

            # roles in the member list and moderation through the menu
            bob = await world.peer("bob")
            await type_line(pilot, "/create #ops")
            await until(pilot, lambda: app.current == "#ops")
            await bob.join("#ops")
            await until(pilot, lambda: "bob" in app.client.channels["#ops"].members)
            members = text(app.query_one("#members"))
            assert "~neo" in members and "bob" in members
            await pilot.press("escape")
            await choose(pilot, app, "mod")
            await choose(pilot, app, "bob")
            await choose(pilot, app, "op")
            await until(pilot, lambda: bob.channels["#ops"].roles.get("bob") == "op")
            await until(pilot, lambda: "@bob" in text(app.query_one("#members")))
            assert any("bob agora é operador" in line for line in lines(app))

            # policies through the menu: toggles and numbers
            await pilot.press("escape")
            await choose(pilot, app, "policy")
            await choose(pilot, app, "noanon")
            await until(pilot, lambda: bob.channels["#ops"].policy.get("noanon"))
            await pilot.press("escape")
            await choose(pilot, app, "policy")
            await choose(pilot, app, "slow")
            await until(pilot, lambda: isinstance(app.screen, FormScreen))
            app.screen.query_one("#f0").value = "15"
            await pilot.press("enter")
            await until(pilot, lambda: bob.channels["#ops"].policy.get("slow") == 15)
            await type_line(pilot, "/policy")
            assert any("slow" in line and "15" in line for line in lines(app))

            # kick through a command, ban through the menu
            await type_line(pilot, "/deop bob")
            await until(pilot, lambda: "bob" not in app.client.channels["#ops"].roles)
            await type_line(pilot, "/kick bob")
            await until(pilot, lambda: "#ops" not in bob.channels)
            await bob.join("#ops")
            await until(pilot, lambda: "bob" in app.client.channels["#ops"].members)
            await pilot.press("escape")
            await choose(pilot, app, "mod")
            await choose(pilot, app, "bob")
            await choose(pilot, app, "ban")
            await until(pilot, lambda: "#ops" not in bob.channels)
            await type_line(pilot, "/bans")
            assert any("bob" in line for line in lines(app))

            # someone without a role is told why
            await type_line(pilot, "/join #lobby")
            await until(pilot, lambda: app.current == "#lobby")
            await type_line(pilot, "/kick bob")
            assert any("operadores" in line for line in lines(app))

            # server staff only
            await pilot.press("escape")
            await choose(pilot, app, "staff")
            assert any("equipe do servidor" in line for line in lines(app))
            world.server.admin({"op": "role", "nick": "neo", "role": "admin"})
            await until(pilot, lambda: app.client.role == "admin")
            assert "ADMIN" in text(app.query_one("#topbar"))
            await type_line(pilot, "/gban bob 7d flood")
            await until(pilot, lambda: any(k == "fatal" for k, _ in bob.events))

            world.server.admin({"op": "notice", "text": "reinício às 22h"})
            await until(pilot, lambda: any("AVISO DO SERVIDOR" in line for line in lines(app, tui.CONSOLE)))
            await type_line(pilot, "/quit")
        await world.stop()
    asyncio.run(main())


def test_anonymous_session_in_the_interface(home):
    async def main():
        world = World(home)
        app = await world.start(guest=True)
        async with app.run_test(size=(120, 36)) as pilot:
            await until(pilot, lambda: app.client.online)
            assert app.client.nick.startswith("anon-") and "ANÔNIMO" in text(app.query_one("#topbar"))
            await type_line(pilot, "/create #meu")
            assert any("anônimos não podem criar" in line for line in lines(app))
            await type_line(pilot, "/friends")
            assert any("nick registrado" in line for line in lines(app))
            await type_line(pilot, "/join #lobby")
            await until(pilot, lambda: app.current == "#lobby")
            await type_line(pilot, "/quit")
        assert not os.listdir(os.path.join(str(home / "cfg"), "identities"))
        await world.stop()
    asyncio.run(main())
