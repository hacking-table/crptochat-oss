"""Key storage in password vaults, against the real `pass` + GnuPG."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from crptochat import crypto, vault
from crptochat.store import BadPassphrase, Identity, load_prefs

PASS = {"vault": "pass"}
needs_pass = pytest.mark.skipif(not (shutil.which("pass") and shutil.which("gpg")), reason="pass/gpg not installed")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


@pytest.fixture
def store(home, monkeypatch):
    """A throwaway GPG identity and an initialised password store."""
    gnupg = tempfile.mkdtemp(prefix="gpg")  # short path: agent sockets have a length limit
    os.chmod(gnupg, 0o700)
    monkeypatch.setenv("GNUPGHOME", gnupg)
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(home / "pass-store"))
    quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "crptochat-test", "default", "default", "never"], **quiet)
    subprocess.run(["pass", "init", "crptochat-test"], **quiet)
    yield home / "pass-store"
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(gnupg, ignore_errors=True)


@needs_pass
def test_key_created_and_loaded_from_pass(store):
    ident = Identity.create("Neo", "pw", source=PASS)
    assert (store / "crptochat" / "neo.gpg").exists()
    assert not Identity.exists("neo") and ident.file is None
    assert "pass" in ident.location

    stored = subprocess.run(["pass", "show", "crptochat/neo"], capture_output=True, text=True).stdout
    blob = json.loads(stored)
    assert blob["nick"] == "Neo" and crypto.ed_seed(ident.key).hex() not in stored  # still passphrase-encrypted

    assert Identity.load("neo", "pw", source=PASS).ik == ident.ik
    with pytest.raises(BadPassphrase):
        Identity.load("neo", "wrong", source=PASS)
    with pytest.raises(FileExistsError):  # never overwrite a key already in the vault
        Identity.create("neo", "other", source=PASS)
    assert Identity.load("neo", "pw", source=PASS).ik == ident.ik

    ident.delete()
    assert not Identity.exists("neo", source=PASS)


@needs_pass
def test_move_between_file_and_vault(store):
    ident = Identity.create("trinity", "pw")
    local = ident.file
    assert Identity.relocate("trinity", dest_source=PASS) is None
    assert not os.path.exists(local) and Identity.exists("trinity", source=PASS)
    assert Identity.load("trinity", "pw", source=PASS).ik == ident.ik

    usb = store.parent / "usb"
    back = Identity.relocate("trinity", src_source=PASS, dest_dir=str(usb))
    assert back == str(usb / "trinity.json") and not Identity.exists("trinity", source=PASS)
    assert Identity.load("trinity", "pw", str(usb)).ik == ident.ik

    # destination already holds a key: nothing moves, nothing is lost
    Identity.create("trinity", "another", source=PASS)
    with pytest.raises(FileExistsError):
        Identity.relocate("trinity", src_dir=str(usb), dest_source=PASS)
    assert Identity.load("trinity", "pw", str(usb)).ik == ident.ik


def test_original_is_kept_when_the_copy_cannot_be_verified(home):
    ident = Identity.create("morpheus", "pw")
    blackhole = {"read": "false", "write": "true"}  # accepts the write, never gives it back
    with pytest.raises(vault.VaultError):
        Identity.relocate("morpheus", dest_source=blackhole)
    assert Identity.load("morpheus", "pw").ik == ident.ik


def test_custom_commands_and_passphrase_command(home):
    box = home / "box"
    box.mkdir()
    spec = {"read": f"cat {box}/{{nick}}.blob", "write": f"tee {box}/{{nick}}.blob"}
    ident = Identity.create("Cypher", "pw", source=spec)
    assert (box / "cypher.blob").exists()
    assert Identity.load("cypher", "pw", source=spec).ik == ident.ik
    with pytest.raises(vault.VaultError):  # read-only configuration cannot store a new key
        Identity.create("tank", "pw", source={"read": f"cat {box}/tank.blob", "write": None})

    secret = home / "secret.txt"
    secret.write_text("correct horse\nsecond line\n")
    assert vault.passphrase_from(f"cat {secret}", "neo") == "correct horse"
    with pytest.raises(vault.VaultError):
        vault.passphrase_from("false", "neo")
    with pytest.raises(vault.VaultError):
        vault.parse("vault:lastpass")


@needs_pass
def test_cli_move_to_vault_and_refuse_when_unreachable(store, monkeypatch):
    env = dict(os.environ, CRPTOCHAT_PASSPHRASE="pw")
    ident = Identity.create("smith", "pw")

    def cli(*args):
        return subprocess.run([sys.executable, "-m", "crptochat.cli", "127.0.0.1:1", "-n", "smith", *args],
                              env=env, capture_output=True, text=True, timeout=60)

    moved = cli("--move-key", "vault:pass")
    assert moved.returncode == 0, moved.stderr
    assert load_prefs()["key_sources"] == {"smith": PASS} and "smith" not in load_prefs().get("key_dirs", {})
    assert Identity.load("smith", "pw", source=PASS).ik == ident.ik

    # vault gone (locked / other machine): stop, never offer to create a new key
    env["PASSWORD_STORE_DIR"] = str(store.parent / "elsewhere")
    gone = cli()
    assert gone.returncode != 0 and "não está acessível" in gone.stderr
    assert not Identity.exists("smith")


@needs_pass
def test_move_to_vault_from_the_chat_menu(store):
    from textual.widgets import OptionList

    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.store import Store
    from crptochat.tui import ChatApp, ChoiceScreen

    async def main():
        server = Server(str(store.parent / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"), Store("n"), ev, tls=False))
        async with app.run_test(size=(120, 40)) as pilot:
            async def choose(ident):
                for _ in range(300):
                    if isinstance(app.screen, ChoiceScreen):
                        break
                    await pilot.pause(0.02)
                screen = app.screen
                options = screen.query_one(OptionList)
                options.highlighted = options.get_option_index(ident)
                await pilot.press("enter")
                for _ in range(300):
                    if app.screen is not screen:
                        break
                    await pilot.pause(0.02)

            for _ in range(300):
                if app.client.online:
                    break
                await pilot.pause(0.02)
            local = app.client.identity.file
            await pilot.press("escape")
            await choose("movekey")
            await choose("vault:pass")
            await choose("yes")
            for _ in range(300):
                if app.client.identity.source:
                    break
                await pilot.pause(0.02)
            assert app.client.identity.source == PASS and app.client.identity.file is None
            assert not os.path.exists(local)
            assert load_prefs()["key_sources"]["neo"] == PASS
            assert Identity.load("neo", "pw", source=PASS).ik == app.client.identity.ik
            assert app.client.online  # the session keeps running on the key in memory
            await pilot.press("ctrl+q")
        await server.stop()
    asyncio.run(main())
