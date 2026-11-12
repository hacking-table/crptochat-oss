"""Self-update: verification, fail-closed behaviour, repo pinning and the server hint."""

import asyncio
import hashlib
import json
import os
import sys
import types

import pytest

from crptochat import crypto, update


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CRPTOCHAT_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(crypto, "SCRYPT_N", 2 ** 10)
    return tmp_path


NEW_BINARY = "#!/bin/sh\necho 'crptochat 1.1.0'\n"
NOW = 2_000_000_000


def make_release(folder, key=None, binary=NEW_BINARY, built=NOW, tamper=False, bad_sig=False, version="1.1.0"):
    folder.mkdir(parents=True, exist_ok=True)
    name = update.asset_name()
    (folder / name).write_text(binary)
    manifest = update.make_manifest(version, "abc1234", built, {name: hashlib.sha256(binary.encode()).hexdigest()})
    (folder / "RELEASE").write_bytes(manifest)
    if key:
        signer = update.generate_key()[0] if bad_sig else key
        (folder / "RELEASE.sig").write_text(update.sign(manifest, signer))
    if tamper:
        (folder / name).write_text(binary + "# extra\n")
    return "file://" + str(folder)


OLD_BUILT = 1_900_000_000


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A compiled binary (built at OLD_BUILT) running from tmp_path/bin."""
    target = tmp_path / "bin" / "crptochat"
    target.parent.mkdir()
    target.write_text("#!/bin/sh\necho old\n")
    target.chmod(0o755)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(target))
    monkeypatch.setattr(update, "_build", types.SimpleNamespace(COMMIT="old0001", BUILT=OLD_BUILT))
    monkeypatch.setattr(update, "__version__", "1.0.0")
    return target


OLD = "#!/bin/sh\necho old\n"


def test_manifest_and_version_info(tmp_path):
    repo = make_release(tmp_path / "rel")
    info = update.latest(repo)
    assert (info["version"], info["commit"], info["built"]) == ("1.1.0", "abc1234", NOW)
    assert info["files"] == {update.asset_name(): hashlib.sha256(NEW_BINARY.encode()).hexdigest()}
    assert update.is_newer(info, {"version": "1.0.0", "commit": "0000000", "built": NOW - 1})
    assert not update.is_newer(info, {"version": "1.0.0", "commit": "0000000", "built": NOW})   # same build
    assert not update.is_newer(info, {"version": "1.1.0", "commit": "abc1234", "built": NOW - 1})  # same version
    assert not update.is_newer(info, {"version": "1.10.0", "commit": "0000000", "built": 1})     # 1.1 < 1.10

    for broken in (b"", b"crptochat-release 2\nversion 1\ncommit ab12\nbuilt 1\n" + b"0" * 64 + b"  x\n",
                   b"crptochat-release 1\nversion 1.0\ncommit ab12\nbuilt soon\n" + b"0" * 64 + b"  x\n",
                   b"crptochat-release 1\nversion 1.0\ncommit ab12\nbuilt 5\n" + b"0" * 64 + b"  ../x\n",
                   b"crptochat-release 1\nversion 1.0\ncommit ab12\nbuilt 5\n"):
        with pytest.raises(update.UpdateError, match="manifesto"):
            update.parse_manifest(broken)


def test_sources_are_strict():
    good = ["https://crptochat.acpt.app.br/downloads/", "https://example.com", "https://h.example:8443/a/b/",
            "github:hacking-table/crptochat-client", "hacking-table/crptochat-client", "a/b", "a-b/.github",
            "x/a.b_c-d", "A1/r", "a" * 39 + "/" + "r" * 100]
    bad = ["http://crptochat.acpt.app.br/downloads/", "HTTP://x/", "https://user:pw@x/", "https://x/?a=1",
           "https://x/#f", "https://x/a b", "https://", "ftp://x/", "a/.", "a/..", "a/b/c", "/a/b", "a//b", "a/",
           "/", "-a/b", "a-/b", "a--b/c", "a/b\n", "../x", "a" * 40 + "/r", "a/" + "r" * 101, "a/b c",
           "file:///tmp/x", "", None, "https://" + "a" * 300]
    assert [r for r in good if not update.valid_source(r)] == []
    assert [r for r in bad if update.valid_source(r)] == []
    assert update.valid_source("file:///srv/mirror", local=True)        # only when the user sets it


def test_where_updates_come_from(monkeypatch):
    monkeypatch.delenv("CRPTOCHAT_UPDATE_URL", raising=False)
    assert update.DEFAULT_URL == "https://crptochat.acpt.app.br/downloads/"
    assert update.source_for({}) == update.DEFAULT_URL
    # what clients up to 1.9 remembered (the private repository) no longer counts
    assert update.source_for({"update_repo": "hacking-table/crptochat-client"}) == update.DEFAULT_URL
    assert update.source_for({"update_repo": "https://mirror.example/c/"}) == "https://mirror.example/c/"
    assert update.source_for({"update_repo": "http://mirror.example/c/"}) == update.DEFAULT_URL
    monkeypatch.setenv("CRPTOCHAT_UPDATE_URL", "https://other.example/dl/")
    assert update.source_for({"update_repo": "https://mirror.example/c/"}) == "https://other.example/dl/"
    monkeypatch.setenv("CRPTOCHAT_UPDATE_URL", "http://other.example/dl/")
    with pytest.raises(update.UpdateError, match="https"):              # an http override is refused, not used
        update.latest(update.source_for({}))


def test_a_build_without_a_signing_key_does_not_update_itself(tmp_path, installed, monkeypatch):
    monkeypatch.setattr(update, "SIGNING_KEY", "")
    with pytest.raises(update.UpdateError, match="não tem chave"):
        update.apply(make_release(tmp_path / "rel"))
    assert installed.read_text() == OLD


def test_signed_build_requires_a_valid_signature(tmp_path, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)

    with pytest.raises(update.UpdateError, match="não está assinada"):
        update.apply(make_release(tmp_path / "unsigned"))
    with pytest.raises(update.UpdateError, match="ASSINATURA INVÁLIDA"):
        update.apply(make_release(tmp_path / "forged", key=private, bad_sig=True))
    with pytest.raises(update.UpdateError, match="não confere"):
        update.apply(make_release(tmp_path / "tampered", key=private, tamper=True))
    # the version and build time are signed too: editing them breaks the signature
    edited = tmp_path / "edited"
    make_release(edited, key=private, built=OLD_BUILT - 10)
    (edited / "RELEASE").write_bytes((edited / "RELEASE").read_bytes().replace(
        f"built {OLD_BUILT - 10}".encode(), f"built {NOW}".encode()))
    with pytest.raises(update.UpdateError, match="ASSINATURA INVÁLIDA"):
        update.apply("file://" + str(edited))
    assert installed.read_text() == OLD                                  # every failure left it untouched
    assert not [f for f in os.listdir(installed.parent) if f.startswith(".crptochat-update")]

    done = update.apply(make_release(tmp_path / "good", key=private))
    assert done["signed"] and installed.read_text() == NEW_BINARY


def test_no_downgrade_even_with_a_valid_signature(tmp_path, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    for built in (OLD_BUILT - 1, OLD_BUILT):                             # older, and the very same build
        with pytest.raises(update.UpdateError, match="downgrade"):
            update.apply(make_release(tmp_path / f"r{built}", key=private, built=built, version="0.9.0"))
    assert installed.read_text() == OLD
    update.apply(make_release(tmp_path / "newer", key=private, built=OLD_BUILT + 1))
    assert installed.read_text() == NEW_BINARY


def test_a_binary_that_does_not_run_is_not_installed(tmp_path, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    with pytest.raises(update.UpdateError, match="não executou"):
        update.apply(make_release(tmp_path / "broken", key=private, binary="#!/bin/sh\nexit 3\n"))
    assert installed.read_text() == OLD


def test_source_installs_do_not_replace_python(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    with pytest.raises(update.UpdateError, match="pip"):
        update.apply(make_release(tmp_path / "rel"))


def test_signing_tool_roundtrip(tmp_path, monkeypatch, capsys):
    private, public = update.generate_key()
    monkeypatch.setenv("CLIENT_SIGNING_KEY", private)
    monkeypatch.setenv("CLIENT_SIGNING_PUBKEY", public)
    binary = tmp_path / update.asset_name()
    binary.write_bytes(b"bin")
    update.main(["manifest", "1.2.0", "abc1234", "123", str(binary)])
    (tmp_path / "RELEASE").write_text(capsys.readouterr().out)
    assert update.parse_manifest((tmp_path / "RELEASE").read_bytes())["built"] == 123
    update.main(["sign", str(tmp_path / "RELEASE")])
    (tmp_path / "RELEASE.sig").write_text(capsys.readouterr().out)
    update.main(["verify", str(tmp_path / "RELEASE"), str(tmp_path / "RELEASE.sig")])
    assert "válida" in capsys.readouterr().out
    monkeypatch.setenv("CLIENT_SIGNING_PUBKEY", update.generate_key()[1])
    with pytest.raises(update.UpdateError):
        update.main(["verify", str(tmp_path / "RELEASE"), str(tmp_path / "RELEASE.sig")])


def test_only_https_and_no_downgrade_on_redirect():
    import urllib.request

    with pytest.raises(update.UpdateError):
        update._http("http://example.invalid/x", 1024)
    with pytest.raises(update.UpdateError):
        update.fetch("http://crptochat.acpt.app.br/downloads/", "RELEASE")
    with pytest.raises(update.UpdateError):
        update._http("file:///etc/passwd", 1024)
    handler = update._HttpsOnlyRedirects()
    req = urllib.request.Request("https://crptochat.acpt.app.br/downloads/RELEASE")
    with pytest.raises(update.UpdateError):                     # https -> http: refused
        handler.redirect_request(req, None, 302, "Found", {}, "http://evil.example/blob")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.example/blob") is not None


# --------------------------------------------------- the public download site

class Site:
    """A local HTTPS server playing crptochat.acpt.app.br/downloads/."""

    def __init__(self, folder, tmp_path):
        import http.server
        import ssl
        import threading

        from crptochat.server import ensure_cert

        self.headers, self.paths = [], []
        folder_ = str(folder)
        site = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=folder_, **kw)

            def do_GET(self):
                site.headers.append(dict(self.headers))
                site.paths.append(self.path)
                super().do_GET()

            def log_message(self, *args):
                pass

        (tmp_path / "site-cert").mkdir()
        cert, key = ensure_cert(str(tmp_path / "site-cert"))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.client_ctx = ssl.create_default_context()
        self.client_ctx.check_hostname = False
        self.client_ctx.verify_mode = ssl.CERT_NONE        # test certificate; the release signature is what counts
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}/downloads/"

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "www"
    (root / "downloads").mkdir(parents=True)
    s = Site(root, tmp_path)
    monkeypatch.setattr(update, "_SSL_CONTEXT", s.client_ctx)
    monkeypatch.setenv("CRPTOCHAT_UPDATE_URL", s.url)
    monkeypatch.setenv("CRPTOCHAT_GITHUB_TOKEN", "nunca-deve-sair")
    monkeypatch.setenv("GH_TOKEN", "nem-este")
    s.folder = root / "downloads"
    yield s
    s.close()


def publish(site, key, **kw):
    """Put a release on the site, as the release workflow would."""
    for f in site.folder.iterdir():
        f.unlink()
    make_release(site.folder, key=key, **kw)
    (site.folder / "SHA256SUMS").write_text("ignorado pelo cliente\n")


def test_update_from_the_site(site, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    publish(site, private)
    source = update.source_for({})
    assert source == site.url
    info = update.latest(source)
    assert info["version"] == "1.1.0" and info["signed"]
    done = update.apply(source)
    assert installed.read_text() == NEW_BINARY and done["version"] == "1.1.0"
    assert os.access(installed, os.X_OK)
    # no token, login or cookie ever goes to the site
    assert site.headers and not [h for h in site.headers if "Authorization" in h or "Cookie" in h]
    assert [h.get("User-Agent") for h in site.headers][0] == "crptochat-updater"


def test_site_with_an_invalid_signature_is_refused(site, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    publish(site, private, bad_sig=True)                        # signed by someone else
    with pytest.raises(update.UpdateError, match="ASSINATURA INVÁLIDA"):
        update.apply(site.url)
    publish(site, private)
    (site.folder / "RELEASE.sig").unlink()                      # not signed at all
    with pytest.raises(update.UpdateError, match="não está assinada"):
        update.apply(site.url)
    assert installed.read_text() == OLD
    # the binary was never downloaded: nothing is trusted before the signature
    assert site.paths and not [p for p in site.paths if p.endswith(update.asset_name())]


def test_site_with_a_different_binary_is_refused(site, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    publish(site, private, tamper=True)
    with pytest.raises(update.UpdateError, match="não confere"):
        update.apply(site.url)
    assert installed.read_text() == OLD
    assert not [f for f in os.listdir(installed.parent) if f.startswith(".crptochat-update")]


def test_site_downgrade_and_replay_are_refused(site, installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    cases = [dict(version="0.9.0", built=NOW),                  # older version, even if built later
             dict(version="1.0.0", built=NOW),                  # same version
             dict(version="1.1.0", built=OLD_BUILT),            # newer number, but an old build (replay)
             dict(version="1.1.0", built=OLD_BUILT - 100)]
    for case in cases:
        publish(site, private, **case)
        with pytest.raises(update.UpdateError, match="downgrade"):
            update.apply(site.url)
    assert installed.read_text() == OLD


def test_http_url_is_refused(installed, monkeypatch):
    private, public = update.generate_key()
    monkeypatch.setattr(update, "SIGNING_KEY", public)
    monkeypatch.setenv("CRPTOCHAT_UPDATE_URL", "http://crptochat.acpt.app.br/downloads/")
    with pytest.raises(update.UpdateError, match="https"):
        update.apply(update.source_for({}))
    with pytest.raises(update.UpdateError, match="https"):
        update.latest("http://127.0.0.1:9/downloads/")
    assert installed.read_text() == OLD


def test_downloads_have_a_size_limit_and_a_deadline(site, monkeypatch):
    (site.folder / "RELEASE").write_bytes(b"x" * (update.MAX_MANIFEST + 1))
    with pytest.raises(update.UpdateError, match="grande demais"):
        update.fetch(site.url, "RELEASE", update.MAX_MANIFEST, update.SMALL_DEADLINE)
    (site.folder / "big").write_bytes(b"x" * 300_000)
    with pytest.raises(update.UpdateError, match="demorou"):
        update.fetch(site.url, "big", 10 ** 6, -1)              # deadline already over


def test_admin_sets_repo_and_clients_only_switch_after_confirming(tmp_path, monkeypatch):
    from textual.widgets import OptionList

    from crptochat.client import ChatClient
    from crptochat.server import Server
    from crptochat.store import Identity, Store, load_prefs
    from crptochat.tui import ChatApp, ChoiceScreen

    repo = make_release(tmp_path / "rel")
    monkeypatch.setattr(update, "DEFAULT_URL", repo)
    monkeypatch.delenv("CRPTOCHAT_UPDATE_URL", raising=False)
    monkeypatch.setattr(update, "__version__", "1.0.0")

    async def main():
        server = Server(str(tmp_path / "srv"), reg_limit=0)
        assert server.admin({"op": "update_repo", "repo": "acme/crptochat-builds"})["repo"] == "acme/crptochat-builds"
        assert "error" in server.admin({"op": "update_repo", "repo": "http://evil.example/x"})
        assert "error" in server.admin({"op": "update_repo", "repo": "file:///tmp/x"})
        port = await server.start("127.0.0.1", 0)
        app = ChatApp(lambda ev: ChatClient("127.0.0.1", port, Identity.create("neo", "pw"), Store("n"), ev, tls=False))
        async with app.run_test(size=(120, 36)) as pilot:
            async def wait(cond):
                for _ in range(400):
                    if cond():
                        return
                    await pilot.pause(0.02)
                raise AssertionError("condition not reached")

            def console():
                return " ".join(line.plain for line in app.buffers["console"].lines)

            await wait(lambda: app.client.online)
            # update available from the pinned repo, announced on connect
            await wait(lambda: "atualização disponível" in console())
            # the server's suggestion is only a hint
            assert "acme/crptochat-builds" in console() and "/update origem" in console()
            assert app.update_repo() == repo

            # the operator changes it live; clients are told again
            server.admin({"op": "update_repo", "repo": "acme/other"})
            await wait(lambda: "acme/other" in console())

            # switching needs an explicit yes
            for answer, expected in (("no", repo), ("yes", "acme/other")):
                app.input.value = "/update origem acme/other"
                await pilot.press("enter")
                await wait(lambda: isinstance(app.screen, ChoiceScreen))
                options = app.screen.query_one(OptionList)
                options.highlighted = options.get_option_index(answer)
                await pilot.press("enter")
                await wait(lambda: not app.in_dialog)
                assert app.update_repo() == expected
            assert load_prefs()["update_repo"] == "acme/other"

            app.input.value = "/update off"
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert load_prefs()["update_check"] is False
            app.input.value = "/quit"
            await pilot.press("enter")
        await server.stop()

        # the setting survives a restart of the server
        again = Server(str(tmp_path / "srv"))
        assert again.client_repo == "acme/other"
        again.db.close()
    asyncio.run(main())
