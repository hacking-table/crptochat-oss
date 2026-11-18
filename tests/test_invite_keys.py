"""Generated channel passwords and invitations that carry the channel's keys."""

import asyncio
import re

import pytest
from test_e2e import Harness, messages, run, until

from crptochat import crypto
from crptochat.client import NeedPassphrase
from crptochat.protocol import b64e


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def test_random_passphrase():
    seen = {crypto.random_passphrase() for _ in range(200)}
    assert len(seen) == 200
    for pw in seen:
        assert re.fullmatch(r"[a-z2-7]{4}(-[a-z2-7]{4}){5}-[a-z2-7]{2}", pw), pw
        assert len(pw.replace("-", "")) * 5 >= 128                  # 26 base32 chars = 130 bits


def test_invite_carries_the_keys_end_to_end(home):
    async def main():
        async with Harness(home) as h:
            alice, bob, carol = await h.client("alice"), await h.client("bob"), await h.client("carol")
            password = crypto.random_passphrase()
            await alice.create("#cofre", password)
            with pytest.raises(NeedPassphrase):
                await bob.join("#cofre")

            reply = await alice.invite("#cofre", "bob")
            assert reply["keys_sent"]
            await until(lambda: "#cofre" in bob.invites)
            assert any(k == "invite_keys" and d == {"chan": "#cofre", "by": "alice"} for k, d in bob.events)
            await bob.join("#cofre")                                   # no password typed
            assert "#cofre" not in bob.invites                         # used once, then forgotten
            await until(lambda: "bob" in alice.channels["#cofre"].recv and "alice" in bob.channels["#cofre"].recv)
            alice.send_message("#cofre", "bem-vindo ao cofre")
            await until(lambda: messages(bob, "#cofre"))
            assert messages(bob, "#cofre") == [("alice", "bem-vindo ao cofre")]

            # neither the password nor the keys the server must not have crossed the
            # wire in clear (auth is the access token the server checks, by design)
            ch = alice.channels["#cofre"]
            for secret in (password, b64e(ch.psk), b64e(ch.hkey)):
                assert not any(secret in frame for frame in h.wire)

            # a stale invitation (password changed since) falls back to asking
            await alice.invite("#cofre", "carol")
            await until(lambda: "#cofre" in carol.invites)
            await alice.change_password("#cofre", crypto.random_passphrase())
            with pytest.raises(NeedPassphrase):
                await carol.join("#cofre")
            assert "#cofre" not in carol.invites

            # open channels need no keys: nothing is sent
            await alice.create("#aberto")
            assert not (await alice.invite("#aberto", "carol"))["keys_sent"]
    run(main())


def test_invitation_keys_are_validated(home):
    async def main():
        async with Harness(home) as h:
            alice, bob = await h.client("alice"), await h.client("bob")
            peer = await alice.resolve("bob")
            for bad in ({"k": "ci", "chan": "nao-e-canal", "a": "", "p": ""},
                        {"k": "ci", "chan": "#x", "a": "AAAA", "p": "AAAA"},
                        {"k": "ci", "chan": "#x"}):
                await alice.request(alice._direct_frame(peer, bad))
            await alice.send_dm("bob", "fim")
            await until(lambda: messages(bob, "@alice"))
            assert bob.invites == {}
            # a flood of invitations keeps only the most recent ones
            key = b"\x01" * 32
            for i in range(30):
                await alice.request(alice._direct_frame(peer, {"k": "ci", "chan": f"#c{i}", "a": b64e(key),
                                                               "p": b64e(key)}))
            await until(lambda: "#c29" in bob.invites)
            assert len(bob.invites) == 20 and "#c0" not in bob.invites
    run(main())


def test_generated_password_voicemask_and_voice_role_in_the_interface(home):
    from test_tui_features import World, lines, type_line
    from test_tui_features import until as ui_until

    async def main():
        world = World(home)
        app = await world.start()
        async with app.run_test(size=(130, 40)) as pilot:
            await ui_until(pilot, lambda: app.client.online)
            natural = await world.peer("natural")             # a nick that is also a /voice word

            await type_line(pilot, "/create #cofre privado gerar")
            await ui_until(pilot, lambda: app.current == "#cofre")
            shown = [line for line in lines(app) if "senha gerada para #cofre" in line]
            assert len(shown) == 1
            password = shown[0].split(": ", 1)[1].strip()
            assert re.fullmatch(r"[a-z2-7]{4}(-[a-z2-7]{4}){5}-[a-z2-7]{2}", password)

            await type_line(pilot, "/invite natural")
            assert any("a chave do canal foi junto" in line for line in lines(app))
            await ui_until(pilot, lambda: "#cofre" in natural.invites)
            await natural.join("#cofre")
            await ui_until(pilot, lambda: "natural" in app.client.channels["#cofre"].members)

            # in the channel, /voice natural gives the member called natural voice...
            mask = app.voice_mask
            await type_line(pilot, "/voice natural")
            await ui_until(pilot, lambda: natural.channels["#cofre"].roles.get("natural") == "voice")
            assert app.voice_mask == mask
            # ...and the disguise has its own command
            await type_line(pilot, "/voicemask off")
            assert not app.voice_mask
            await type_line(pilot, "/voicemask on")
            assert app.voice_mask

            # /chanpass gerar rotates to a new generated password
            await type_line(pilot, "/chanpass gerar")
            await ui_until(pilot, lambda: len([line for line in lines(app) if "senha gerada para #cofre" in line]) == 2)
            await ui_until(pilot, lambda: "#cofre" not in natural.channels)
            await type_line(pilot, "/quit")
        await world.stop()
    asyncio.run(main())
