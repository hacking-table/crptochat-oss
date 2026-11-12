"""Keeping the nick key in a password vault instead of a plain file.

What goes into the vault is the same blob that would be on disk: the Ed25519
seed already encrypted with the identity passphrase. The vault therefore adds
a second layer; someone who gets into the vault still needs the passphrase.

A vault is described by a *spec* (stored in the preferences):
    {"vault": "pass"}                           one of PRESETS
    {"read": "cmd …", "write": "cmd …"}         any tool, see below

Custom commands run without a shell. ``{nick}`` is replaced by the lowercase
nickname. The read command prints the blob on stdout; the write command
receives it on stdin. Prompts from the tool (GPG pinentry, master password)
go straight to the terminal.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess


class VaultError(OSError):
    pass


def _pass_exists(nick: str) -> bool:
    # Looks at the store itself: `pass show` cannot tell "missing" from
    # "could not decrypt right now", and `pass insert` only needs the public
    # key, so a wrong answer here could overwrite a real key.
    base = os.environ.get("PASSWORD_STORE_DIR") or os.path.expanduser("~/.password-store")
    return os.path.exists(os.path.join(base, "crptochat", nick + ".gpg"))


def _hc_path() -> str:
    return os.environ.get("CRPTOCHAT_VAULT_PATH") or "secret/crptochat/{nick}"


PRESETS = {
    "pass": {
        "label": "pass (password-store, GPG)",
        "bin": "pass",
        "read": lambda: ["pass", "show", "crptochat/{nick}"],
        "write": lambda: ["pass", "insert", "--multiline", "--force", "crptochat/{nick}"],
        "delete": lambda: ["pass", "rm", "--force", "crptochat/{nick}"],
        "exists": _pass_exists,
    },
    "secret-tool": {
        "label": "Secret Service (GNOME Keyring, KWallet, KeePassXC)",
        "bin": "secret-tool",
        "read": lambda: ["secret-tool", "lookup", "service", "crptochat", "nick", "{nick}"],
        "write": lambda: ["secret-tool", "store", "--label=crptochat {nick}", "service", "crptochat", "nick", "{nick}"],
        "delete": lambda: ["secret-tool", "clear", "service", "crptochat", "nick", "{nick}"],
    },
    "vault": {
        "label": "HashiCorp Vault (KV)",
        "bin": "vault",
        "read": lambda: ["vault", "kv", "get", "-field=identity", _hc_path()],
        "write": lambda: ["vault", "kv", "put", _hc_path(), "identity=-"],
        "delete": lambda: ["vault", "kv", "delete", _hc_path()],
    },
}


def parse(text: str) -> dict:
    """"vault:pass" (or just "pass") -> spec."""
    name = text.split(":", 1)[1] if text.lower().startswith("vault:") else text
    if name not in PRESETS:
        raise VaultError(f"cofre desconhecido: {name} (opções: {', '.join(PRESETS)})")
    return {"vault": name}


def available() -> list[str]:
    return [name for name, preset in PRESETS.items() if shutil.which(preset["bin"])]


def describe(spec: dict) -> str:
    if "vault" in spec:
        return "cofre " + PRESETS[spec["vault"]]["label"]
    return "cofre via comando: " + spec["read"].split()[0]


def _argv(spec: dict, action: str, nick: str) -> list[str] | None:
    if "vault" in spec:
        preset = PRESETS.get(spec["vault"])
        if not preset:
            raise VaultError(f"cofre desconhecido: {spec['vault']}")
        if not shutil.which(preset["bin"]):
            raise VaultError(f"o comando '{preset['bin']}' não está instalado nesta máquina")
        template = preset[action]()
    else:
        command = spec.get(action)
        if not command:
            return None
        template = shlex.split(command)
    return [part.replace("{nick}", nick.lower()) for part in template]


def _run(argv: list[str], data: str | None = None) -> subprocess.CompletedProcess:
    try:
        # no shell: argv is the user's own vault command, split with shlex
        return subprocess.run(argv, input=data, stdout=subprocess.PIPE, text=True, timeout=180)  # nosec B603
    except FileNotFoundError:
        raise VaultError(f"comando não encontrado: {argv[0]}") from None
    except subprocess.TimeoutExpired:
        raise VaultError(f"{argv[0]} não respondeu") from None
    except OSError as exc:
        raise VaultError(f"não foi possível executar {argv[0]}: {exc.strerror or exc}") from None


def read(spec: dict, nick: str) -> str | None:
    """The stored blob, or None if the vault has nothing (or refused)."""
    result = _run(_argv(spec, "read", nick))
    text = result.stdout.strip()
    return text if result.returncode == 0 and text else None


def exists(spec: dict, nick: str) -> bool:
    check = PRESETS[spec["vault"]].get("exists") if "vault" in spec else None
    return check(nick.lower()) if check else read(spec, nick) is not None


def write(spec: dict, nick: str, text: str) -> None:
    argv = _argv(spec, "write", nick)
    if argv is None:
        raise VaultError("este cofre foi configurado só para leitura (falta o comando de gravação)")
    result = _run(argv, text + "\n")
    if result.returncode != 0:
        raise VaultError(f"{argv[0]} recusou a gravação (cofre bloqueado ou sem permissão?)")


def delete(spec: dict, nick: str) -> bool:
    argv = _argv(spec, "delete", nick)
    if argv is None:
        return False
    return _run(argv).returncode == 0


def passphrase_from(command: str, nick: str) -> str:
    """First line printed by a user-supplied command (e.g. `pass show …`)."""
    argv = [part.replace("{nick}", nick.lower()) for part in shlex.split(command)]
    result = _run(argv)
    line = result.stdout.split("\n", 1)[0]
    if result.returncode != 0 or not line:
        raise VaultError(f"{argv[0]} não devolveu a senha")
    return line
