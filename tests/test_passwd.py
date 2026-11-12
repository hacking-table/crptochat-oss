"""Changing the passphrase that protects the stored key (the key itself stays)."""

import asyncio
import json
import os
import sys

import pytest

from crptochat import cli, crypto, vault
from crptochat.store import BadPassphrase, Identity

sys.path.insert(0, os.path.dirname(__file__))
from test_vault import PASS, needs_pass, store  # noqa: E402,F401  (pytest fixture)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("CRPTOCHAT_PASSPHRASE", raising=False)
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


def test_file_is_rewritten_in_place_and_the_key_stays(home):
    ident = Identity.create("neo", "velha-123")
    before = open(ident.file, "rb").read()
    old_blob = json.loads(before)["key"]
    assert ident.change_passphrase("velha-123", "nova-4567") == ident.file
    after = open(ident.file, "rb").read()
    assert len(after) == len(before) and old_blob not in after.decode()     # old bytes overwritten
    assert json.loads(after)["salt"] != json.loads(before)["salt"]           # fresh salt
    assert Identity.load("neo", "nova-4567").ik == ident.ik                  # same key, same nick
    with pytest.raises(BadPassphrase):
        Identity.load("neo", "velha-123")
    assert oct(os.stat(ident.file).st_mode & 0o777) == "0o600"
    assert not os.path.exists(ident.file + ".new") and not os.path.exists(ident.file + ".tmp")


def test_wrong_current_or_same_passphrase_changes_nothing(home):
    ident = Identity.create("neo", "velha-123")
    before = open(ident.file, "rb").read()
    with pytest.raises(BadPassphrase):
        ident.change_passphrase("errada", "nova-4567")
    with pytest.raises(ValueError):
        ident.change_passphrase("velha-123", "velha-123")
    assert open(ident.file, "rb").read() == before


def test_refuses_when_the_stored_key_is_not_this_session(home):
    ident = Identity.create("neo", "velha-123")
    other = Identity("neo", crypto.ed_generate(), ident.file)               # same file, other key in memory
    with pytest.raises(ValueError):
        other.change_passphrase("velha-123", "nova-4567")
    assert Identity.load("neo", "velha-123").ik == ident.ik


def test_anonymous_session_has_nothing_to_change(home):
    with pytest.raises(ValueError):
        Identity("anon", crypto.ed_generate()).change_passphrase("a", "b")


def test_key_on_a_removable_drive(home):
    drive = home / "pendrive"
    drive.mkdir()
    ident = Identity.create("neo", "velha-123", str(drive))
    ident.change_passphrase("velha-123", "nova-4567")
    assert Identity.load("neo", "nova-4567", str(drive)).ik == ident.ik
    assert sorted(os.listdir(drive)) == ["neo.json"]


def test_an_interrupted_change_still_opens(home):
    """Crash after the complete new copy was written but while the original
    was being overwritten: the key still opens, with the new passphrase."""
    ident = Identity.create("neo", "velha-123")
    real_open = open

    def crashing_open(path, mode="r", *a, **kw):
        if path == ident.file and mode == "r+b":
            fh = real_open(path, mode, *a, **kw)
            fh.write(b"{\"v\": 1, \"ni")                                      # half written...
            fh.truncate()
            fh.close()
            raise OSError("energia caiu")
        return real_open(path, mode, *a, **kw)

    import builtins
    builtins.open = crashing_open
    try:
        with pytest.raises(OSError):
            ident.change_passphrase("velha-123", "nova-4567")
    finally:
        builtins.open = real_open
    assert os.path.exists(ident.file + ".new")
    assert Identity.load("neo", "nova-4567").ik == ident.ik


def test_custom_vault_commands(home):
    folder = home / "cofre"
    folder.mkdir()
    spec = {"read": f"cat {folder}/{{nick}}", "write": f"sh -c 'cat > {folder}/{{nick}}'"}
    ident = Identity.create("neo", "velha-123", source=spec)
    ident.change_passphrase("velha-123", "nova-4567")
    assert Identity.load("neo", "nova-4567", source=spec).ik == ident.ik
    with pytest.raises(BadPassphrase):
        Identity.load("neo", "velha-123", source=spec)
    # a read-only vault (no write command) refuses and keeps the old passphrase
    readonly = Identity.load("neo", "nova-4567", source={"read": spec["read"]})
    with pytest.raises(vault.VaultError):
        readonly.change_passphrase("nova-4567", "outra-8901")
    assert Identity.load("neo", "nova-4567", source=spec).ik == ident.ik


@needs_pass
def test_pass_vault(store):
    ident = Identity.create("neo", "velha-123", source=PASS)
    ident.change_passphrase("velha-123", "nova-4567")
    assert Identity.load("neo", "nova-4567", source=PASS).ik == ident.ik
    with pytest.raises(BadPassphrase):
        Identity.load("neo", "velha-123", source=PASS)


def test_cli_change_pass_needs_no_server(home, monkeypatch, capsys):
    ident = Identity.create("neo", "velha-123")
    typed = iter(["velha-123", "curta", "nova-4567", "diferente", "nova-4567", "nova-4567"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(typed))
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("não devia perguntar nada além das senhas"))
    cli.main(["--change-pass", "-n", "neo"])
    out = capsys.readouterr().out
    assert "senha trocada" in out and "8 caracteres" in out and "não conferem" in out
    assert Identity.load("neo", "nova-4567").ik == ident.ik


def test_cli_refuses_without_a_key_or_for_anonymous(home, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": pytest.fail("não devia pedir senha"))
    with pytest.raises(SystemExit) as err:
        cli.main(["--change-pass", "-n", "ninguem"])
    assert "não encontrada" in str(err.value)
    with pytest.raises(SystemExit) as err:
        cli.main(["--change-pass", "-a"])
    assert "anônimas" in str(err.value)


def test_passwd_in_the_interface(home):
    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.store import Store
    from crptochat.tui import ChatApp, PassScreen

    ident = Identity.create("neo", "velha-123")

    async def main():
        server = Server(str(home / "srv"), reg_limit=0)
        port = await server.start("127.0.0.1", 0)
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, ident, Store(f"127.0.0.1:{port}"), ev, tls=False))
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

            def shown():
                return " ".join(l.plain for l in app.buffers["console"].lines)

            async def answer(*values):
                await wait(lambda: isinstance(app.screen, PassScreen))
                for value in values:
                    await pilot.press(*value)
                    await pilot.press("enter")

            await wait(lambda: app.client.online)
            await line("/passwd")
            await answer("errada")
            await answer("nova-4567", "nova-4567")
            await wait(lambda: "senha atual incorreta" in shown())
            assert Identity.load("neo", "velha-123").ik == ident.ik

            await line("/passwd")
            await answer("velha-123")
            await answer("nova-4567", "nova-4567")
            await wait(lambda: "senha da chave trocada" in shown())
            assert Identity.load("neo", "nova-4567").ik == ident.ik
            assert app.client.online                                   # nothing reconnected
            await line("/quit")
        await server.stop()
    asyncio.run(main())
