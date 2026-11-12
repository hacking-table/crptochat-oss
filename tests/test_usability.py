"""Etapa 7: desktop notifications on mention/DM and /search over local history."""

import asyncio

import pytest

from crptochat import crypto, notify
from crptochat.client import ChatClient
from crptochat.server import Server
from crptochat.store import Identity, Store, load_prefs


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def which_all(name):
    return "/usr/bin/" + name


HOSTILE = "\x1b]0;pwn\x07$(rm -rf ~)`id`\"; '‮\n-- --help"


def test_sanitize_strips_escapes_bidi_and_newlines():
    text = notify.sanitize(HOSTILE, 200)
    assert "\x1b" not in text and "\x07" not in text and "‮" not in text and "\n" not in text
    assert notify.sanitize("a" * 500, 10) == "a" * 9 + "…"


def test_commands_never_go_through_a_shell():
    linux, env = notify.command("t-" + HOSTILE, HOSTILE, "linux", which_all)
    assert linux[0] == "/usr/bin/notify-send" and "--" in linux and env == {}
    assert linux.index("--") < len(linux) - 2                     # title and body after "--"
    mac, _ = notify.command("t", HOSTILE, "darwin", which_all)
    assert mac[0] == "/usr/bin/osascript" and mac[-1] == notify.sanitize(HOSTILE, notify.BODY_MAX)
    assert all(HOSTILE[:5] not in part for part in mac[:-2])         # text is an argument, not script
    win, wenv = notify.command("t", HOSTILE, "win32", which_all, exists=lambda p: True)
    assert win[0].lower().endswith(r"system32\windowspowershell\v1.0\powershell.exe")
    assert not any("rm -rf" in part for part in win)
    # never a PATH lookup on Windows: a powershell.exe planted in a user folder is not used
    assert notify.command("t", "b", "win32", lambda name: "C:\\Users\\x\\powershell.exe",
                          exists=lambda p: False) is None
    assert "rm -rf" in wenv["CRPTOCHAT_NOTIFY_BODY"]                 # only via the environment
    assert notify.command("t", "b", "linux", lambda name: None) is None   # no notifier: silently nothing


def test_notify_send_body_markup_is_escaped():
    argv, _ = notify.command("t", '<b>x</b> & <a href="http://evil">clique</a><img src="file:///etc/passwd">',
                             "linux", which_all)
    body = argv[-1]
    assert "<" not in body and ">" not in body and "&amp;" in body and "&lt;a href" in body


def test_notifier_hides_text_by_default_and_rate_limits(monkeypatch):
    monkeypatch.setattr(notify, "backend", lambda platform=None, which=None, exists=None: ["/usr/bin/notify-send"])
    monkeypatch.setattr(notify.sys, "platform", "linux")
    calls = []
    n = notify.Notifier(runner=lambda argv, env: calls.append(argv), gap=60)
    assert n.message("@bob", "bob", "senha do cofre: 1234", False)
    assert "1234" not in " ".join(calls[0]) and "bob" in " ".join(calls[0])
    assert not n.message("@bob", "bob", "de novo", False)            # same conversation, too soon
    assert n.message("#ops", "ana", "neo: olha", True)                # another one is fine
    assert "mencionou" in " ".join(calls[1])
    n.preview = True
    n.gap = 0
    n.message("@bob", "bob", "agora com texto", False)
    assert "agora com texto" in calls[-1]
    n.enabled = False
    assert not n.message("@bob", "bob", "desligado", False)


def test_notifications_and_search_in_the_interface(home, no_desktop_notifications, monkeypatch):
    from textual.widgets import Input, OptionList

    from crptochat.tui import ChatApp, SearchScreen

    monkeypatch.setattr(notify, "backend", lambda platform=None, which=None, exists=None: ["/usr/bin/notify-send"])
    monkeypatch.setattr(notify.sys, "platform", "linux")
    sent = no_desktop_notifications

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        bob = ChatClient("127.0.0.1", port, Identity.create("bob", "pw"), Store("b"), lambda k, d: None, tls=False)
        btask = asyncio.create_task(bob.run())
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"),
                                            Store(f"127.0.0.1:{port}"), ev, tls=False), autojoin=["#lobby"])
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

            await wait(lambda: app.client.online and bob.online and "#lobby" in app.buffers)
            await bob.join("#lobby")
            await wait(lambda: "bob" in app.client.channels["#lobby"].recv)

            # a plain channel message in the window you're looking at: nothing
            bob.send_message("#lobby", "bom dia a todos")
            await wait(lambda: "bom dia" in shown("#lobby"))
            assert sent == []
            # a DM while you're in #lobby: notified, without the text
            await bob.send_dm("neo", "a senha é Ação-42")
            await wait(lambda: "@bob" in app.buffers and "Ação-42" in shown("@bob"))
            await wait(lambda: len(sent) == 1)
            assert "bob" in " ".join(sent[0][0]) and "Ação-42" not in " ".join(sent[0][0])
            # a mention in the current window while the terminal is not focused
            app.term_focused = False
            bob.send_message("#lobby", "neo, reunião às 15h")
            await wait(lambda: len(sent) == 2)
            assert "mencionou" in " ".join(sent[1][0])
            app.term_focused = True

            # /notify off is remembered
            await line("/notify off")
            assert load_prefs()["notify"] is False
            await bob.send_dm("neo", "outra")
            await wait(lambda: "outra" in shown("@bob"))
            await pilot.pause(0.1)
            assert len(sent) == 2
            await line("/notify on")
            await line("/notify preview on")
            assert load_prefs()["notify_preview"] is True and "tela de bloqueio" in shown("#lobby")

            # /search: accent- and case-insensitive, across windows, jumps to the line
            await line("/search acao")
            await wait(lambda: isinstance(app.screen, SearchScreen))
            assert [b for b, _ in app.screen.found] == ["@bob"]
            app.screen.query_one("#query", Input).value = "REUNIAO"
            await pilot.pause(0.1)
            assert [b for b, _ in app.screen.found] == ["#lobby"]
            await pilot.press("escape")
            await wait(lambda: not app.in_dialog)

            await line("/query bob")
            await wait(lambda: app.current == "@bob")
            await pilot.press("ctrl+f")
            await wait(lambda: isinstance(app.screen, SearchScreen))
            await pilot.press(*"bom dia")
            await pilot.pause(0.1)
            await pilot.press("down")
            assert app.screen.query_one(OptionList).has_focus
            await pilot.press("enter")
            await wait(lambda: app.current == "#lobby" and not app.in_dialog)
            assert any(l.text.startswith("▶") and "bom dia" in l.text for l in app.log_w.lines)
            assert not any(l.plain.startswith("▶") for l in app.buffers["#lobby"].lines)   # buffer untouched

            # nothing about the search ever reached the server
            await line("/quit")
        await bob.close()
        btask.cancel()
        await server.stop()
    asyncio.run(main())
