"""Update checks and self-update for the compiled client.

Trust model. Neither the chat server nor the download site is trusted to make
a client install anything:

* Releases come from the public download site (by default
  https://crptochat.acpt.app.br/downloads/, fixed at build time; the env
  CRPTOCHAT_UPDATE_URL overrides it). No token or login is ever sent there.
  The chat server only *suggests* another source (set by its operator in
  crptochat-admin), and the client switches only when the user confirms.
* Every release carries a manifest, RELEASE, listing its version, commit,
  build time and the SHA-256 of every binary, signed with Ed25519
  (RELEASE.sig). The signature is checked against the public key embedded in
  the binary *before* anything in the manifest is believed; a binary with a
  key accepts only releases signed by that key, and one without a key does not
  update itself at all.
* Updates only move forward: the version must be higher and the build time
  later than the running binary's, so an old (even validly signed) release
  cannot be replayed to downgrade anyone.
* The binary is checked against the SHA-256 in the signed manifest and
  replaced atomically. Every download has a size limit and a deadline.
* Nothing is installed without the user asking (/update or --update).

RELEASE format (one item per line):
    crptochat-release 1
    version 1.0.1
    commit abc1234
    built 1762800000
    <sha256>  crptochat-linux-amd64
    ...

A source is an https:// folder (the site), "github:owner/name" (optional,
explicit fallback to the latest GitHub release, anonymous; only works for a
public repository) or file:///path (a local mirror the user sets). Plain
http:// is refused.
"""

from __future__ import annotations

import base64
import hashlib
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__, crypto

try:
    from . import _build
except ImportError:  # running from source
    _build = None

DEFAULT_URL = getattr(_build, "UPDATE_URL", "") or "https://crptochat.acpt.app.br/downloads/"
SIGNING_KEY = getattr(_build, "PUBKEY", "")       # base64 Ed25519 public key, or "" (unsigned builds)
MANIFEST = "RELEASE"
MANIFEST_HEADER = "crptochat-release 1"
MAX_ASSET = 200 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_SIGNATURE = 1024
SMALL_DEADLINE = 30            # seconds for RELEASE / RELEASE.sig, whole download
ASSET_DEADLINE = 600           # seconds for a binary, whole download

# GitHub rules: owner is letters, digits and single inner hyphens (max 39);
# repository name is letters, digits, ".", "_" and "-" (max 100), never "." or "..".
OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}"
NAME = r"(?!\.{1,2}\Z)[A-Za-z0-9._-]{1,100}"
REPO_RE = re.compile(rf"{OWNER}/{NAME}")
SITE_RE = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?")
SHA_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._-]{1,100})")


class UpdateError(Exception):
    pass


def valid_source(source, local: bool = False) -> bool:
    """An https:// folder, github:owner/name (or the older bare owner/name),
    or, only when the user sets it (``local``), file:///path. Never http://."""
    if not isinstance(source, str) or len(source) > 300 or "\n" in source:
        return False
    if source.startswith("https://"):
        return SITE_RE.fullmatch(source) is not None
    if local and source.startswith("file:///"):
        return True
    return REPO_RE.fullmatch(source.removeprefix("github:")) is not None


valid_repo = valid_source      # older name, still used by the server's admin console


# Where clients up to 1.9 looked (a private repository, so only with a token).
# A preference still pointing there is treated as "not set".
_OLD_DEFAULT = "hacking-table/crptochat-client"


def default_source() -> str:
    """CRPTOCHAT_UPDATE_URL when set, otherwise the site this binary was built for."""
    return os.environ.get("CRPTOCHAT_UPDATE_URL") or DEFAULT_URL


def source_for(prefs: dict) -> str:
    """The source to use: CRPTOCHAT_UPDATE_URL, then the one the user chose
    (/update origem, --update-repo), then the build default."""
    if os.environ.get("CRPTOCHAT_UPDATE_URL"):
        return os.environ["CRPTOCHAT_UPDATE_URL"]
    chosen = prefs.get("update_repo")
    if chosen and chosen != _OLD_DEFAULT and valid_source(chosen, local=True):
        return chosen
    return DEFAULT_URL


def current() -> dict:
    return {"version": __version__, "commit": getattr(_build, "COMMIT", ""), "built": getattr(_build, "BUILT", 0)}


def can_self_update() -> bool:
    """Only the compiled binary replaces itself; a pip install is updated with pip."""
    return bool(getattr(sys, "frozen", False))


def asset_name() -> str:
    system = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not system or not arch:
        raise UpdateError(f"plataforma sem binário publicado: {platform.system()} {platform.machine()}")
    return f"crptochat-{system}-{arch}" + (".exe" if system == "windows" else "")


# ------------------------------------------------------------------ fetching

class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect may change host (a CDN), never drop to plain http."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://") and not _ALLOW_HTTP:
            raise UpdateError("redirecionamento para fora de https recusado")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ALLOW_HTTP = False      # tests only (local plain-http servers)
_SSL_CONTEXT = None      # tests only (a local https server with its own certificate)


def _http(url: str, limit: int, deadline: float = ASSET_DEADLINE) -> bytes:
    """GET over https only, no credentials of any kind, at most ``limit`` bytes
    and ``deadline`` seconds for the whole download (not just per read)."""
    if not url.startswith("https://") and not _ALLOW_HTTP:
        raise UpdateError("só https é aceito para baixar atualizações")
    request = urllib.request.Request(url, headers={"Accept": "*/*", "User-Agent": "crptochat-updater"})
    handlers = [_HttpsOnlyRedirects()]
    if _SSL_CONTEXT is not None:
        handlers.append(urllib.request.HTTPSHandler(context=_SSL_CONTEXT))
    opener = urllib.request.build_opener(*handlers)
    stop = time.monotonic() + deadline
    chunks, size = [], 0
    with opener.open(request, timeout=min(60, max(deadline, 1))) as response:  # nosec B310
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > limit:
            raise UpdateError("arquivo grande demais")
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise UpdateError("arquivo grande demais")
            if time.monotonic() > stop:
                raise UpdateError("o download demorou demais")
            chunks.append(chunk)
    return b"".join(chunks)


def _location(source: str, name: str) -> str:
    if source.startswith("https://"):
        return urllib.parse.urljoin(source if source.endswith("/") else source + "/", name)
    repo = source.removeprefix("github:")
    return f"https://github.com/{repo}/releases/latest/download/{name}"


def fetch(source: str, name: str, limit: int = MAX_ASSET, deadline: float = ASSET_DEADLINE) -> bytes:
    """One file of the latest release from ``source``."""
    if not valid_source(source, local=True):
        raise UpdateError(f"origem de atualização inválida: {source} (use https://…)")
    if source.startswith("file:///"):
        try:
            with open(os.path.join(source[len("file://"):], name), "rb") as fh:
                data = fh.read(limit + 1)
        except OSError as exc:
            raise UpdateError(f"{name} não encontrado em {source}") from exc
        if len(data) > limit:
            raise UpdateError("arquivo grande demais")
        return data
    url = _location(source, name)
    try:
        return _http(url, limit, deadline)
    except UpdateError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError(f"{name} não encontrado em {source}") from None
        raise UpdateError(f"não consegui acessar {source}: HTTP {exc.code}") from None
    except Exception as exc:  # urllib raises a zoo of exception types
        raise UpdateError(f"não consegui acessar {source}: {exc}") from None


# ----------------------------------------------------------------- manifest

def parse_manifest(data: bytes) -> dict:
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        raise UpdateError("manifesto RELEASE inválido") from None
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 5 or lines[0] != MANIFEST_HEADER:
        raise UpdateError("manifesto RELEASE inválido")
    info: dict = {"files": {}}
    for line, key in zip(lines[1:4], ("version", "commit", "built")):
        label, _, value = line.partition(" ")
        if label != key or not value:
            raise UpdateError("manifesto RELEASE inválido")
        info[key] = value
    if not re.fullmatch(r"\d+(\.\d+){0,3}", info["version"]) or not re.fullmatch(r"[0-9a-f]{4,40}", info["commit"]) \
            or not info["built"].isdigit():
        raise UpdateError("manifesto RELEASE inválido")
    info["built"] = int(info["built"])
    for line in lines[4:]:
        match = SHA_LINE.fullmatch(line)
        if not match or match.group(2) in info["files"]:
            raise UpdateError("manifesto RELEASE inválido")
        info["files"][match.group(2)] = match.group(1)
    return info


def make_manifest(version: str, commit: str, built: int, files: dict[str, str]) -> bytes:
    lines = [MANIFEST_HEADER, f"version {version}", f"commit {commit}", f"built {built}"]
    lines += [f"{digest}  {name}" for name, digest in sorted(files.items())]
    return ("\n".join(lines) + "\n").encode("ascii")


def verify(manifest: bytes, signature: bytes | None, key: str = "") -> None:
    """Fail closed: a binary that knows a key accepts only releases signed by it."""
    key = key or SIGNING_KEY
    if not key:
        return
    if not signature:
        raise UpdateError("a release não está assinada; esta versão do cliente só aceita releases assinadas")
    try:
        public = base64.b64decode(key, validate=True)
        sig = base64.b64decode(signature.strip(), validate=True)
    except ValueError as exc:
        raise UpdateError("assinatura malformada") from exc
    if not crypto.verify(public, sig, manifest):
        raise UpdateError("ASSINATURA INVÁLIDA: a release não foi publicada por quem assina este cliente")


# ----------------------------------------------------------------- checking

def latest(source: str, key: str = "") -> dict:
    """Version info of the latest release. The signature is checked before
    anything in the manifest is parsed or believed."""
    manifest = fetch(source, MANIFEST, MAX_MANIFEST, SMALL_DEADLINE)
    try:
        signature = fetch(source, MANIFEST + ".sig", MAX_SIGNATURE, SMALL_DEADLINE)
    except UpdateError:
        signature = None
    verify(manifest, signature, key)
    info = parse_manifest(manifest)
    info["signed"] = bool(key or SIGNING_KEY)
    return info


def _version(text) -> tuple:
    try:
        return tuple(int(part) for part in str(text).split("."))
    except ValueError:
        return ()


def is_newer(info: dict, mine: dict | None = None) -> bool:
    """Forward only: a higher version *and* a later build than the running binary
    (both are inside the signed manifest), so no downgrade and no replay."""
    mine = mine or current()
    return (_version(info["version"]) > _version(mine.get("version") or "0")
            and int(info["built"]) > int(mine.get("built") or 0))


def apply(source: str, key: str = "", target: str | None = None) -> dict:
    """Download, verify and install the latest release over the running binary."""
    if not target and not can_self_update():
        raise UpdateError("esta instalação não é o binário compilado: atualize com 'pip install -U' no código-fonte")
    if not (key or SIGNING_KEY):
        raise UpdateError("este binário não tem chave de assinatura embutida e não se atualiza sozinho; "
                          "instale a versão nova pelo site, conferindo a assinatura")
    target = target or sys.executable
    name = asset_name()
    info = latest(source, key)
    mine = current()
    if not is_newer(info, mine):
        raise UpdateError(
            f"a release publicada ({info['version']}, {info['commit']}) não é mais nova que este binário "
            f"({mine['version']}, {mine['commit'] or 'sem commit'}); nada foi instalado (proteção contra downgrade)")
    expected = info["files"].get(name)
    if not expected:
        raise UpdateError(f"a release não tem binário para esta plataforma ({name})")
    binary = fetch(source, name, MAX_ASSET, ASSET_DEADLINE)
    if hashlib.sha256(binary).hexdigest() != expected:
        raise UpdateError("o binário baixado não confere com o manifesto assinado; nada foi instalado")

    folder = os.path.dirname(os.path.abspath(target))
    fd, tmp = tempfile.mkstemp(prefix=".crptochat-update-", dir=folder)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(binary)
        mode = os.stat(target).st_mode if os.path.exists(target) else 0o755
        os.chmod(tmp, mode | stat.S_IXUSR)
        if platform.system() != "Windows":
            # fixed argv, no shell; the binary was already verified (signature + SHA-256)
            check = subprocess.run([tmp, "--version"], capture_output=True, text=True, timeout=120)  # nosec B603
            if check.returncode != 0:
                raise UpdateError("o binário novo não executou; nada foi instalado")
        os.replace(tmp, target)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return {**info, "path": target}


# ---------------------------------------------------------- release tooling

def generate_key() -> tuple[str, str]:
    """(private, public) base64 Ed25519 keys for signing releases."""
    private = crypto.ed_generate()
    return base64.b64encode(crypto.ed_seed(private)).decode(), base64.b64encode(crypto.ed_pub(private)).decode()


def sign(data: bytes, private_b64: str) -> str:
    return base64.b64encode(crypto.sign(crypto.ed_from_seed(base64.b64decode(private_b64)), data)).decode()


def public_from(private_b64: str) -> str:
    return base64.b64encode(crypto.ed_pub(crypto.ed_from_seed(base64.b64decode(private_b64)))).decode()


INSTALLER_SLOT = "@CRPTOCHAT_SIGNING_PUBKEY@"
INSTALLER_FP_SLOT = "@CRPTOCHAT_SIGNING_FINGERPRINT@"


def key_fingerprint(public_b64: str) -> str:
    """SHA-256 of the raw 32-byte public key, hex in groups of 4 (what install.sh
    prints and the README publishes)."""
    raw = base64.b64decode(public_b64, validate=True)
    if len(raw) != 32:
        raise UpdateError("chave pública de assinatura inválida (Ed25519 em base64)")
    digest = hashlib.sha256(raw).hexdigest()
    return " ".join(digest[i:i + 4] for i in range(0, 64, 4))


def stamp_installer(template: str, public_b64: str) -> str:
    """install.sh with the release public key embedded (it refuses to run without one)."""
    try:
        raw = base64.b64decode(public_b64, validate=True)
    except ValueError:
        raw = b""
    if len(raw) != 32 or base64.b64encode(raw).decode() != public_b64:
        raise UpdateError("chave pública de assinatura inválida (Ed25519 em base64)")
    if template.count(INSTALLER_SLOT) != 1 or template.count(INSTALLER_FP_SLOT) != 1:
        raise UpdateError("install.sh sem o lugar da chave pública")
    # the fingerprint goes in too, so it is shown even where nothing can hash
    return template.replace(INSTALLER_SLOT, public_b64).replace(INSTALLER_FP_SLOT, key_fingerprint(public_b64))


def main(argv=None) -> None:
    """python -m crptochat.update genkey | manifest VERSION COMMIT BUILT FILE... | sign FILE"""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["genkey"]:
        private, public = generate_key()
        print("Chave privada (guarde como secret CLIENT_SIGNING_KEY; não compartilhe):")
        print(private)
        print("Chave pública (variável CLIENT_SIGNING_PUBKEY; vai embutida nos binários):")
        print(public)
    elif argv[:1] == ["manifest"] and len(argv) >= 5:
        files = {}
        for path in argv[4:]:
            with open(path, "rb") as fh:
                files[os.path.basename(path)] = hashlib.sha256(fh.read()).hexdigest()
        sys.stdout.write(make_manifest(argv[1], argv[2], int(argv[3]), files).decode())
    elif argv[:1] == ["sign"] and len(argv) == 2:
        with open(argv[1], "rb") as fh:
            print(sign(fh.read(), os.environ["CLIENT_SIGNING_KEY"]))
    elif argv[:1] == ["fingerprint"] and len(argv) <= 2:
        print("SHA256 " + key_fingerprint(argv[1] if len(argv) == 2 else os.environ["CLIENT_SIGNING_PUBKEY"]))
    elif argv[:1] == ["installer"] and len(argv) == 2:
        with open(argv[1]) as fh:
            sys.stdout.write(stamp_installer(fh.read(), os.environ["CLIENT_SIGNING_PUBKEY"]))
    elif argv[:1] == ["verify"] and len(argv) == 3:
        with open(argv[1], "rb") as fh, open(argv[2], "rb") as sig:
            verify(fh.read(), sig.read(), os.environ["CLIENT_SIGNING_PUBKEY"])
        print("assinatura válida")
    else:
        sys.exit("uso: python -m crptochat.update genkey | manifest VERSÃO COMMIT BUILT ARQUIVO... | "
                 "sign ARQUIVO (lê CLIENT_SIGNING_KEY) | verify ARQUIVO ASSINATURA (lê CLIENT_SIGNING_PUBKEY) | "
                 "installer install.sh (lê CLIENT_SIGNING_PUBKEY) | fingerprint [CHAVE_PÚBLICA]")


if __name__ == "__main__":
    try:
        main()
    except UpdateError as exc:
        sys.exit(str(exc))
