"""Etapa 8: health panel for the operator and a signature-checking installer."""

import asyncio
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys

import pytest
from test_e2e import Harness, run, until

from crptochat import crypto, update
from crptochat.store import Identity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, "packaging", "install.sh")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


# ------------------------------------------------------------------ health

def test_health_panel_counts_without_names(home):
    from crptochat.admin import AdminSocket, Console, Link, socket_path

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

            alice, bob = await h.client("alice"), await h.client("bob")
            ident = Identity("guest", crypto.ed_generate())
            anon = await h.client(crypto.guest_nick(ident.ik), identity=ident, guest=True)
            # an old client: no "ver" in its login
            h.server.sessions["bob"].client_version = ""
            await alice.create("#cofre", "senha-forte-1")
            await alice.set_policy("#cofre", history=3)
            await alice.join("#lobby")
            await anon.join("#lobby")
            for i in range(10):                                       # trip the anonymous limits
                try:
                    anon.send_message("#lobby", f"flood {i}")
                except Exception:
                    break
            await until(lambda: any(k == "ratelimit" for k, _ in anon.events))
            h.server.db.execute("INSERT INTO ip_bans (ip_hash, until, reason, label, created) VALUES "
                                "('x', 0, 'teste', 'l', 0), ('y', 1, 'vencido', 'l', 0)")
            h.server.db.commit()

            data = h.server._admin_health({})["health"]
            assert data["online"] == {"registered": 2, "anonymous": 1, "peak": data["online"]["peak"],
                                      "connections": data["online"]["connections"]}
            assert data["channels"]["total"] == 2 and data["channels"]["private"] == 1
            assert data["channels"]["with_history"] == 1
            assert data["bans"]["addresses"] == 1                       # the expired one is not active
            assert data["ratelimit"]["10min"].get("warn") and data["ratelimit"]["total"]["warn"] >= 1
            from crptochat import __version__
            assert data["versions"] == {__version__: 2, "antiga (não informa)": 1}

            text = re.sub(r"\x1b\[[0-9;]*m", "", await asyncio.to_thread(console, "health"))
            assert "registrados 2" in text and "anônimos 1" in text and "com histórico" in text
            assert __version__ in text and "antiga (não informa)" in text and "endereços 1" in text
            for secret in ("alice", "bob", "#cofre", "#lobby", "127.0.0.1", anon.nick):
                assert secret not in text                               # aggregates only
            await sock.stop()
    run(main())


def test_server_keeps_only_plain_version_numbers(home, monkeypatch):
    from crptochat import __version__, client
    from crptochat.server import VERSION_RE

    for bad in ("1.0\x1b[2J", "1" * 40, "1.2.3-evil", ""):
        assert not VERSION_RE.fullmatch(bad)

    async def main():
        async with Harness(home) as h:
            await h.client("alice")
            assert h.server.sessions["alice"].client_version == __version__
            monkeypatch.setattr(client, "__version__", "1.0\x1b[2J")         # junk is never stored or shown
            await h.client("bob")
            assert h.server.sessions["bob"].client_version == ""
    run(main())


# --------------------------------------------------------------- installer

needs_sh = pytest.mark.skipif(sys.platform.startswith("win") or not shutil.which("sh"), reason="POSIX sh")


def _asset() -> str:
    os_name = {"Linux": "linux", "Darwin": "macos"}.get(platform.system(), "")
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "")
    return f"crptochat-{os_name}-{arch}"


def fake_binary(built: int) -> bytes:
    return (f"#!/bin/sh\nif [ \"$1\" = --build-info ]; then echo 'crptochat-build 9.9.9 abc1234 {built}'; "
            f"else echo 'crptochat 9.9.9 (teste)'; fi\n").encode()


def make_release(folder, private, binary=None, built=1900000000):
    binary = binary if binary is not None else fake_binary(built)
    os.makedirs(folder, exist_ok=True)
    asset = _asset()
    with open(os.path.join(folder, asset), "wb") as fh:
        fh.write(binary)
    manifest = update.make_manifest("9.9.9", "abc1234", built,
                                    {asset: hashlib.sha256(binary).hexdigest(), "crptochat-other": "0" * 64})
    with open(os.path.join(folder, "RELEASE"), "wb") as fh:
        fh.write(manifest)
    with open(os.path.join(folder, "RELEASE.sig"), "w") as fh:
        fh.write(update.sign(manifest, private) + "\n")
    return asset


def install(tmp, public, release, path=None, args=(), home=None):
    script = os.path.join(tmp, "install.sh")
    with open(INSTALLER) as fh:
        text = fh.read()
    with open(script, "w") as fh:
        fh.write(update.stamp_installer(text, public) if public else text)
    env = {"PATH": path or os.environ["PATH"], "HOME": str(home or tmp), "CRPTOCHAT_RELEASE_DIR": str(release),
           "CRPTOCHAT_BIN_DIR": os.path.join(home or tmp, "bin")}
    proc = subprocess.run(["sh", script, *args], env=env, capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout + proc.stderr, os.path.exists(os.path.join(home or tmp, "bin", "crptochat"))


def test_stamp_installer_validates_the_key():
    private, public = update.generate_key()
    with open(INSTALLER) as fh:
        text = fh.read()
    stamped = update.stamp_installer(text, public)
    assert public in stamped and update.INSTALLER_SLOT not in stamped and update.INSTALLER_FP_SLOT not in stamped
    assert update.key_fingerprint(public) in stamped
    for bad in ("", "abc", public[:-4] + "AA==", private + "x"):
        with pytest.raises(update.UpdateError):
            update.stamp_installer(text, bad)
    with pytest.raises(update.UpdateError):
        update.stamp_installer(stamped, public)                             # no slot left


@needs_sh
def test_installer_accepts_a_correctly_signed_release(tmp_path):
    private, public = update.generate_key()
    make_release(tmp_path / "rel", private)
    code, out, installed = install(tmp_path, public, tmp_path / "rel")
    assert code == 0 and installed, out
    assert "assinatura e SHA-256 conferidos" in out
    assert "SHA256 " + update.key_fingerprint(public) in out           # same as the README publishes


@needs_sh
@pytest.mark.parametrize("attack", ["binary", "manifest", "other_key", "no_sig", "garbage_sig", "unstamped",
                                    "not_listed"])
def test_installer_refuses_anything_that_does_not_match(tmp_path, attack):
    private, public = update.generate_key()
    rel = tmp_path / "rel"
    asset = make_release(rel, private)
    if attack == "binary":
        (rel / asset).write_bytes(b"#!/bin/sh\necho trojan\n")
    elif attack == "manifest":                     # swap the hash for the trojan's, keep the old signature
        trojan = b"#!/bin/sh\necho trojan\n"
        (rel / asset).write_bytes(trojan)
        lines = (rel / "RELEASE").read_text().replace(hashlib.sha256(fake_binary(1900000000)).hexdigest(),
                                                      hashlib.sha256(trojan).hexdigest())
        (rel / "RELEASE").write_text(lines)
    elif attack == "other_key":
        make_release(rel, update.generate_key()[0])
    elif attack == "no_sig":
        (rel / "RELEASE.sig").unlink()
    elif attack == "garbage_sig":
        (rel / "RELEASE.sig").write_text("not base64 !!\n")
    elif attack == "not_listed":
        manifest = update.make_manifest("9.9.9", "abc1234", 1900000000, {"crptochat-other": "0" * 64})
        (rel / "RELEASE").write_bytes(manifest)
        (rel / "RELEASE.sig").write_text(update.sign(manifest, private))
    code, out, installed = install(tmp_path, None if attack == "unstamped" else public, rel)
    assert code != 0 and not installed, out
    assert "instalação cancelada" in out
    expected = {"binary": "SHA-256", "manifest": "ASSINATURA INVÁLIDA", "other_key": "ASSINATURA INVÁLIDA",
                "no_sig": "não está assinada", "garbage_sig": "ASSINATURA INVÁLIDA",
                "unstamped": "não tem a chave", "not_listed": "não lista"}[attack]
    assert expected in out


@needs_sh
def test_installer_falls_back_to_python_and_fails_closed_without_a_verifier(tmp_path):
    pytest.importorskip("cryptography")
    private, public = update.generate_key()
    make_release(tmp_path / "rel", private)
    # an "openssl" that is too old (LibreSSL-like): the Python check takes over
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "openssl").write_text("#!/bin/sh\necho 'LibreSSL 2.8.3'\nexit 1\n")
    (fake / "openssl").chmod(0o755)
    path = f"{fake}:{os.environ['PATH']}"
    os.makedirs(tmp_path / "a")
    code, out, installed = install(tmp_path / "a", public, tmp_path / "rel", path)
    assert code == 0 and installed, out
    # and a tampered manifest is still refused through that path
    (tmp_path / "rel" / "RELEASE").write_text((tmp_path / "rel" / "RELEASE").read_text().replace("9.9.9", "9.9.8"))
    os.makedirs(tmp_path / "b")
    code, out, installed = install(tmp_path / "b", public, tmp_path / "rel", path)
    assert code != 0 and not installed and "ASSINATURA INVÁLIDA" in out
    # no openssl 3 and no python with cryptography: refuse, never install unchecked
    for name in ("python3", "python"):
        (fake / name).write_text("#!/bin/sh\nexit 1\n")
        (fake / name).chmod(0o755)
    make_release(tmp_path / "rel", private)
    os.makedirs(tmp_path / "c")
    code, out, installed = install(tmp_path / "c", public, tmp_path / "rel", path)
    assert code != 0 and not installed and "não há como conferir" in out


@needs_sh
def test_installer_refuses_a_downgrade_unless_forced(tmp_path):
    private, public = update.generate_key()
    home = tmp_path / "home"
    make_release(tmp_path / "new", private, built=1900000000)
    make_release(tmp_path / "old", private, built=1800000000)       # older, but validly signed
    for step in ("s1", "s2", "s3", "s4"):
        os.makedirs(tmp_path / step)
    code, out, _ = install(tmp_path / "s1", public, tmp_path / "new", home=home)
    assert code == 0, out
    assert (home / ".local" / "state" / "crptochat" / "installed-build").read_text().strip() == "1900000000"
    code, out, _ = install(tmp_path / "s2", public, tmp_path / "old", home=home)
    assert code != 0 and "mais antiga que o instalado" in out and "--allow-downgrade" in out
    assert b"1900000000" in (home / "bin" / "crptochat").read_bytes()               # untouched
    code, out, _ = install(tmp_path / "s3", public, tmp_path / "new", home=home)     # same build: fine
    assert code == 0, out
    code, out, _ = install(tmp_path / "s4", public, tmp_path / "old", home=home, args=["--allow-downgrade"])
    assert code == 0 and "MAIS ANTIGO" in out
    assert b"1800000000" in (home / "bin" / "crptochat").read_bytes()


@needs_sh
def test_installer_uses_the_build_of_the_binary_updated_in_place(tmp_path):
    """/update replaced the binary with a newer build than the receipt: that one is the floor."""
    private, public = update.generate_key()
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "crptochat").write_bytes(fake_binary(1950000000))
    (home / "bin" / "crptochat").chmod(0o755)
    state = home / ".local" / "state" / "crptochat"
    state.mkdir(parents=True)
    (state / "installed-build").write_text("1800000000\n")
    make_release(tmp_path / "rel", private, built=1900000000)
    os.makedirs(tmp_path / "s")
    code, out, _ = install(tmp_path / "s", public, tmp_path / "rel", home=home)
    assert code != 0 and "build 1950000000" in out


def test_build_info_flag():
    from crptochat import __version__
    out = subprocess.run([sys.executable, "-m", "crptochat.cli", "--build-info"], capture_output=True, text=True,
                         cwd=ROOT, timeout=60).stdout.split()
    assert out[0] == "crptochat-build" and out[1] == __version__ and out[3].isdigit()


RELEASE_PUBKEY = "UXnFSaezyEwMqfhfGncgjf03YiSN/FvaIja1Kv6g5VE="


def test_readme_publishes_the_release_key_fingerprint():
    with open(os.path.join(ROOT, "README.md")) as fh:
        readme = fh.read()
    found = re.findall(r"`(SHA256 [0-9a-f ]{79})`", readme)
    # the first one is what the release workflow checks against CLIENT_SIGNING_PUBKEY
    assert found and found[0] == "SHA256 " + update.key_fingerprint(RELEASE_PUBKEY)
    assert found[0] == "SHA256 aae1 82c8 5665 f874 fab6 a97e 93c5 333b aae8 ce15 7090 f247 c9e7 e2e6 f9d2 3890"


@needs_sh
def test_installer_shows_the_fingerprint_without_openssl_or_hash_tools(tmp_path):
    pytest.importorskip("cryptography")
    private, public = update.generate_key()
    make_release(tmp_path / "rel", private)
    bare = tmp_path / "bare"
    bare.mkdir()
    for tool in ("sh", "grep", "sed", "awk", "head", "cp", "mkdir", "install", "cat", "tr", "wc", "uname",
                 "mktemp", "rm", "printf", "chmod", "python3"):
        found = shutil.which(tool)
        if found:
            os.symlink(found, bare / tool)
    # sha256sum is needed for the binary check: give a python one, but no openssl/base64/shasum
    (bare / "sha256sum").write_text("#!/bin/sh\nexec python3 -c 'import hashlib,sys;"
                                    "d=open(sys.argv[1],\"rb\").read() if len(sys.argv)>1 else sys.stdin.buffer.read();"
                                    "print(hashlib.sha256(d).hexdigest(), sys.argv[1] if len(sys.argv)>1 else \"-\")' \"$@\"\n")
    (bare / "sha256sum").chmod(0o755)
    os.makedirs(tmp_path / "a")
    code, out, installed = install(tmp_path / "a", public, tmp_path / "rel", path=str(bare))
    assert code == 0 and installed, out
    assert "SHA256 " + update.key_fingerprint(public) in out


@needs_sh
def test_installer_refuses_a_fingerprint_that_is_not_the_keys(tmp_path):
    private, public = update.generate_key()
    make_release(tmp_path / "rel", private)
    with open(INSTALLER) as fh:
        stamped = update.stamp_installer(fh.read(), public)
    other = update.key_fingerprint(update.generate_key()[1])
    script = tmp_path / "install.sh"
    script.write_text(stamped.replace(update.key_fingerprint(public), other))
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "CRPTOCHAT_RELEASE_DIR": str(tmp_path / "rel"),
           "CRPTOCHAT_BIN_DIR": str(tmp_path / "bin")}
    proc = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0 and "adulterado" in proc.stderr
    assert not (tmp_path / "bin" / "crptochat").exists()


@needs_sh
def test_installer_downloads_from_the_site_over_https_only(tmp_path):
    """No GitHub login needed any more: the default is the public site, and a
    plain-http origin is refused before anything is downloaded."""
    with open(INSTALLER) as fh:
        text = fh.read()
    assert "https://crptochat.acpt.app.br/downloads/" in text and "gh release" not in text
    assert "--proto '=https' --proto-redir '=https'" in text
    _, public = update.generate_key()
    script = tmp_path / "install.sh"
    script.write_text(update.stamp_installer(text, public))
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "CRPTOCHAT_BIN_DIR": str(tmp_path / "bin"),
           "CRPTOCHAT_UPDATE_URL": "http://crptochat.acpt.app.br/downloads/"}
    proc = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0 and "https://" in proc.stderr
    assert not (tmp_path / "bin" / "crptochat").exists()
