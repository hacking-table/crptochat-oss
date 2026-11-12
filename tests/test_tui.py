"""Drives the real TUI (headless) against a real server."""

import asyncio
import os

import pytest

from crptochat import crypto
from crptochat.client import ChatClient
from crptochat.server import Server
from crptochat.store import Identity, Store
from crptochat.tui import ChatApp, PassScreen, clean


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


async def until(pilot, cond, timeout=8):
    deadline = asyncio.get_running_loop().time() + timeout
    while not cond():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await pilot.pause(0.02)


async def type_line(pilot, text):
    pilot.app.input.value = text
    await pilot.press("enter")
    await pilot.pause(0.05)


def lines(app, name):
    return [line.plain for line in app.buffers[name].lines]


def test_clean_strips_escape_sequences():
    assert "\x1b" not in clean("oi\x1b[2J\x07‮!")
    assert clean("a\nb") == "a b"


def test_full_session(home):
    async def main():
        server = Server(str(home / "srv"), motd="bem-vindo à matrix", reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        events = []
        trinity = ChatClient("127.0.0.1", port, Identity.create("trinity", "pw"), Store("t"),
                             lambda k, d: events.append((k, d)), tls=False, download_dir=str(home / "dl-t"))
        ttask = asyncio.create_task(trinity.run())

        def factory(on_event):
            return ChatClient("127.0.0.1", port, Identity.create("neo", "pw"), Store("n"), on_event,
                              tls=False, download_dir=str(home / "dl-n"))

        app = ChatApp(factory, autojoin=["#lobby"])
        async with app.run_test(size=(120, 34)) as pilot:
            await until(pilot, lambda: "#lobby" in app.buffers and trinity.online)
            assert app.current == "#lobby"
            await trinity.join("#lobby")
            await until(pilot, lambda: "trinity" in app.client.channels["#lobby"].recv)

            await type_line(pilot, "wake up, trinity")
            trinity.send_message("#lobby", "neo: follow the white rabbit \x1b[31m")
            await until(pilot, lambda: any("white rabbit" in l for l in lines(app, "#lobby")))
            assert any(k == "message" and d["text"] == "wake up, trinity" for k, d in events)
            assert not any("\x1b" in l for l in lines(app, "#lobby"))

            # private channel through the passphrase dialog
            await type_line(pilot, "/create #ops privado")
            await until(pilot, lambda: isinstance(app.screen, PassScreen))
            for _ in range(2):
                await pilot.press(*"zion-mainframe")
                await pilot.press("enter")
            await until(pilot, lambda: app.current == "#ops")
            await trinity.join("#ops", "zion-mainframe")
            await until(pilot, lambda: "trinity" in app.client.channels["#ops"].recv)
            await type_line(pilot, "canal seguro")
            await until(pilot, lambda: any(d.get("buffer") == "#ops" for k, d in events if k == "message"))

            # direct message opens a new window with an unread counter
            await trinity.send_dm("neo", "só entre nós")
            await until(pilot, lambda: "@trinity" in app.buffers)
            assert app.buffers["@trinity"].unread == 1
            await pilot.press("ctrl+n")
            assert app.current == "@trinity" and app.buffers["@trinity"].unread == 0
            await type_line(pilot, "entendido")
            await until(pilot, lambda: any(d.get("buffer") == "@neo" for k, d in events if k == "message"))

            # tab completion, history, commands
            app.input.value = "/wh"
            await pilot.press("tab")
            assert app.input.value == "/who "
            await pilot.press("tab")
            assert app.input.value == "/whois "
            app.input.value = ""
            await pilot.press("up")
            assert app.input.value == "entendido"
            app.input.value = ""
            await type_line(pilot, "/list")
            await until(pilot, lambda: any("#ops" in l for l in lines(app, "@trinity")))
            await type_line(pilot, "/verify trinity")       # opens a confirmation dialog
            from textual.widgets import OptionList

            from crptochat.tui import ChoiceScreen
            await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
            options = app.screen.query_one(OptionList)
            options.highlighted = options.get_option_index("yes")
            await pilot.press("enter")
            await until(pilot, lambda: app.client.store.is_verified("trinity"))
            await type_line(pilot, "/nada")
            assert any("comando desconhecido" in l for l in lines(app, "@trinity"))

            # p2p file: trinity -> neo, accepted from the UI
            src = home / "plans.bin"
            src.write_bytes(os.urandom(200_000))
            await trinity.files.offer("neo", str(src))
            await until(pilot, lambda: any("/accept" in l for l in lines(app, "@trinity")))
            await type_line(pilot, "/accept")
            await until(pilot, lambda: (home / "dl-n" / "plans.bin").exists())
            assert (home / "dl-n" / "plans.bin").read_bytes() == src.read_bytes()

            # clicking the window list switches buffers
            await pilot.click("#buffers", offset=(4, 3))
            assert app.current == "#lobby"

            shot = os.environ.get("CRPTOCHAT_SHOT")
            if shot:
                await pilot.pause(0.2)
                app.save_screenshot(shot)
            await type_line(pilot, "/leave")
            await until(pilot, lambda: "#lobby" not in app.buffers)
            await type_line(pilot, "/quit")
        await trinity.close()
        ttask.cancel()
        await server.stop()
    asyncio.run(main())


def test_interactive_menu(home):
    from textual.widgets import OptionList

    from crptochat.store import load_prefs
    from crptochat.tui import ChoiceScreen, FormScreen

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        events = []
        trinity = ChatClient("127.0.0.1", port, Identity.create("trinity", "pw"), Store("t"),
                             lambda k, d: events.append((k, d)), tls=False, download_dir=str(home / "dl-t"))
        ttask = asyncio.create_task(trinity.run())
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"), Store("n"), ev,
                                            tls=False, download_dir=str(home / "dl-n")))

        async with app.run_test(size=(120, 40)) as pilot:
            async def choose(ident):
                await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
                screen = app.screen
                options = screen.query_one(OptionList)
                options.highlighted = options.get_option_index(ident)
                await pilot.press("enter")
                await until(pilot, lambda: app.screen is not screen)

            async def fill(text):
                await until(pilot, lambda: isinstance(app.screen, FormScreen))
                screen = app.screen
                screen.query_one("#f0").value = text
                await pilot.press("enter")
                await pilot.pause(0.05)
                return screen

            async def menu(ident):
                await pilot.press("escape")
                await choose(ident)

            await until(pilot, lambda: app.client.online and trinity.online)

            # Esc opens the menu, Esc closes it, and it cannot be stacked
            await pilot.press("escape")
            await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
            await pilot.press("escape")
            await until(pilot, lambda: not app.in_dialog)

            # join from the channel list
            await menu("join")
            await choose("#lobby")
            await until(pilot, lambda: app.current == "#lobby")

            # create a private channel: name form (rejects bad names) -> passphrase dialog
            await menu("create_priv")
            form = await fill("Nome Inválido!")
            assert app.screen is form
            await fill("ops")
            await until(pilot, lambda: isinstance(app.screen, PassScreen))
            for _ in range(2):
                await pilot.press(*"zion-mainframe")
                await pilot.press("enter")
            await until(pilot, lambda: app.current == "#ops")
            assert app.client.channels["#ops"].private

            # direct message: no known nicks yet, so it asks for one
            await menu("dm")
            await fill("trinity")
            await until(pilot, lambda: app.current == "@trinity")

            # verify trinity's fingerprint, picking her from the list
            await menu("verify")
            await choose("trinity")
            await choose("yes")
            assert app.client.store.is_verified("trinity")

            # send a file through the menu; trinity gets the offer
            src = home / "dump.bin"
            src.write_bytes(os.urandom(50_000))
            await menu("send")
            await choose("trinity")
            form = await fill(str(home / "nope.bin"))
            assert app.screen is form
            await fill(str(src))
            await choose("relay")                     # through the server (the default)
            await until(pilot, lambda: any(k == "file_offer" and d.get("relay") for k, d in events))

            # receive a file through the menu
            await trinity.files.offer("neo", str(src))
            await until(pilot, lambda: any(not t.outgoing for t in app.client.files.transfers.values()))
            tid = next(t.id.hex() for t in app.client.files.transfers.values() if not t.outgoing)
            await menu("files")
            await choose(tid)
            await choose("accept")
            await until(pilot, lambda: (home / "dl-n" / "dump.bin").exists())

            # move the key to a "pendrive"
            usb = home / "usb"
            usb.mkdir()
            old = app.client.identity.file
            await menu("movekey")
            await choose("__custom__")
            await fill(str(usb))
            await choose("yes")
            await until(pilot, lambda: (usb / "neo.json").exists())
            assert not os.path.exists(old)
            assert app.client.identity.file == str(usb / "neo.json")
            assert load_prefs()["key_dirs"]["neo"] == str(usb)
            assert Identity.load("neo", "pw", str(usb)).ik == app.client.identity.ik

            shot = os.environ.get("CRPTOCHAT_SHOT")
            if shot:
                await pilot.press("f1")
                await until(pilot, lambda: isinstance(app.screen, ChoiceScreen))
                await pilot.pause(0.2)
                app.save_screenshot(shot)
                await pilot.press("escape")
            await menu("leave")
            await until(pilot, lambda: "@trinity" not in app.buffers)
            await menu("quit")
        await trinity.close()
        ttask.cancel()
        await server.stop()
    asyncio.run(main())


def test_voice_messages(home, monkeypatch):
    """Real ffmpeg/Opus encoding (synthetic tone instead of a microphone) and a fake speaker."""
    import shutil

    from crptochat.audio import sniff
    from crptochat.store import load_prefs

    played = home / "played"
    if shutil.which("ffmpeg"):
        monkeypatch.setenv("CRPTOCHAT_REC_CMD",
                           "ffmpeg -hide_banner -loglevel error -nostdin -y -re -f lavfi -i sine=frequency=440 "
                           "-ac 1 -ar 16000 -c:a libopus -b:a 20k {out}")
        monkeypatch.setenv("CRPTOCHAT_REC_FMT", "ogg")
    else:
        monkeypatch.setenv("CRPTOCHAT_REC_CMD", "sh -c 'printf RIFF0000WAVE%0100d 0 > {out}; exec sleep 60'")
    monkeypatch.setenv("CRPTOCHAT_PLAY_CMD", f"cp {{file}} {played}")
    # a private runtime dir: the leftover check below must not see the temp
    # files of another test run going on at the same time (shared /dev/shm)
    runtime = home / "runtime"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        wire = []
        dispatch = server._dispatch
        server._dispatch = lambda sess, msg: (wire.append(msg), dispatch(sess, msg))[1]
        port = await server.start("127.0.0.1", 0)
        events = []
        trinity = ChatClient("127.0.0.1", port, Identity.create("trinity", "pw"), Store("t"),
                             lambda k, d: events.append((k, d)), tls=False)
        ttask = asyncio.create_task(trinity.run())
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"), Store("n"), ev,
                                            tls=False), autojoin=["#lobby"])

        def clips():
            return [d for k, d in events if k == "audio"]

        async with app.run_test(size=(120, 34)) as pilot:
            await until(pilot, lambda: "#lobby" in app.buffers and trinity.online)
            await trinity.join("#lobby")
            await until(pilot, lambda: "trinity" in app.client.channels["#lobby"].recv)

            has_ffmpeg = bool(shutil.which("ffmpeg"))
            if not has_ffmpeg:
                # masking fails closed without ffmpeg: recording is refused...
                await pilot.press("f2")
                await pilot.pause(0.3)
                assert not app.recorder.active
                assert any("ffmpeg" in l for l in lines(app, "#lobby"))
                await type_line(pilot, "/voice natural")  # ...until the user opts out

            # channel: F2 starts, Enter on an empty line sends
            await pilot.press("f2")
            await until(pilot, lambda: app.recorder.active)
            await pilot.pause(1.6)
            assert "REC" in str(app.query_one("#transfer").render())
            await pilot.press("enter")
            await until(pilot, lambda: clips(), timeout=15)
            clip = clips()[0]
            assert clip["buffer"] == "#lobby" and clip["nick"] == "neo" and sniff(clip["data"])
            assert clip["seconds"] >= 1.5 and not app.recorder.active
            assert any("áudio" in l and "/play 1" in l for l in lines(app, "#lobby"))
            raw = clip["data"]
            # the relay only ever saw ciphertext: neither the container header nor
            # any slice of the clip appears in what it relayed (checked on the
            # decoded bytes; random base64 contains "OggS" by chance too often)
            import base64
            relayed = b"".join(base64.b64decode(m["body"]) for m in wire if m.get("t") in ("msg", "direct"))
            assert relayed and raw[:4] == b"OggS" or sniff(raw) == "wav"
            assert not any(raw[i:i + 24] in relayed for i in range(0, len(raw) - 24, 997))

            # anonymity: voice is masked by default, no metadata, and the relay
            # only sees a fixed-size burst (4 full envelopes), not the real length
            assert app.voice_mask == has_ffmpeg
            bodies = [len(m["body"]) for m in wire if m["t"] == "msg"]
            assert len(bodies) == 4 and len(set(bodies)) == 1
            if shutil.which("ffprobe"):
                import array
                import math
                import subprocess
                probe = home / "clip.ogg"
                probe.write_bytes(raw)
                tags = subprocess.run(["ffprobe", "-loglevel", "error", "-show_entries",
                                       "format_tags:stream_tags", str(probe)], capture_output=True, text=True).stdout
                assert [t for t in tags.splitlines() if t.startswith("TAG:")] == ["TAG:encoder=Lavc libopus"]
                # the 440 Hz input tone must not survive as the dominant pitch
                pcm = array.array("h", subprocess.run(
                    ["ffmpeg", "-loglevel", "error", "-i", str(probe), "-f", "s16le", "-ac", "1", "-ar", "16000", "-"],
                    capture_output=True).stdout)[4000:8000]

                def power(freq):
                    return abs(sum(v * complex(math.cos(2 * math.pi * freq * i / 16000),
                                               -math.sin(2 * math.pi * freq * i / 16000)) for i, v in enumerate(pcm)))
                assert max(range(100, 1000, 5), key=power) not in range(425, 460)

            # /voice natural is an explicit, remembered choice
            await type_line(pilot, "/voice mascarada")
            await type_line(pilot, "/voice natural")
            assert not app.voice_mask and load_prefs()["voice"] == "natural"
            await type_line(pilot, "/voice mascarada")
            assert app.voice_mask and load_prefs()["voice"] == "mask"
            if not has_ffmpeg:
                await type_line(pilot, "/voice natural")

            # Esc cancels a recording instead of opening the menu
            await type_line(pilot, "/rec")
            await until(pilot, lambda: app.recorder.active)
            await pilot.press("escape")
            await until(pilot, lambda: not app.recorder.active)
            assert not app.in_dialog and len(clips()) == 1

            # direct message, multi-chunk clip, then playback from the UI
            big = b"RIFF" + b"\0\0\0\0" + b"WAVE" + os.urandom(70_000)
            await trinity.send_audio("@neo", big, 9.0)
            await until(pilot, lambda: "@trinity" in app.buffers and len(app.clips) == 2)
            await type_line(pilot, "/play")
            await until(pilot, lambda: played.exists() and played.read_bytes() == big)
            await type_line(pilot, "/play 1")
            await until(pilot, lambda: played.read_bytes() == raw)

            # garbage that is not audio never reaches the clip list
            await trinity.send_audio("@neo", b"#!/bin/sh\nrm -rf ~\n" * 10, 1.0)
            await pilot.pause(0.3)
            assert len(app.clips) == 2

            assert not [f for f in os.listdir(runtime) if f.startswith("crptochat-")]
            await type_line(pilot, "/quit")
        await trinity.close()
        ttask.cancel()
        await server.stop()
    asyncio.run(main())
