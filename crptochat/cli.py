"""`crptochat` command: asks for server / nickname / passphrase, then opens the TUI."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import __build__, __version__
from .protocol import DEFAULT_PORT, valid_nick
from . import crypto, vault
from .store import BadPassphrase, Identity, Store, load_prefs, save_prefs

C, M, Y, D, R = "\033[38;5;51m", "\033[38;5;199m", "\033[38;5;226m", "\033[38;5;60m", "\033[0m"


def say(text: str = "") -> None:
    print(f"{M}▓▒░{R} {text}")


def ask(label: str, default: str | None = None) -> str:
    suffix = f" {D}[{default}]{R}" if default else ""
    value = input(f"{M}▓▒░{R} {C}{label}{R}{suffix} {M}❯{R} ").strip()
    return value or (default or "")


def ask_secret(label: str, command: str | None = None, nick: str = "") -> str:
    env = os.environ.get("CRPTOCHAT_PASSPHRASE")
    if env is not None:
        return env
    if command:
        return vault.passphrase_from(command, nick)
    return getpass.getpass(f"{M}▓▒░{R} {C}{label}{R} {M}❯{R} ")


def change_passphrase(identity: Identity, current: str, read=None) -> str:
    """Asks the new passphrase twice and re-encrypts the stored key with it."""
    read = read or getpass.getpass
    while True:
        new = read(f"{M}▓▒░{R} {C}senha nova{R} {M}❯{R} ")
        if len(new) < 8:
            say(f"{Y}use pelo menos 8 caracteres{R}")
        elif new == current:
            say(f"{Y}a senha nova é igual à atual{R}")
        elif new != read(f"{M}▓▒░{R} {C}repita a senha nova{R} {M}❯{R} "):
            say(f"{Y}as senhas não conferem{R}")
        else:
            break
    return identity.change_passphrase(current, new)


def parse_server(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return value, DEFAULT_PORT


EPILOG = """\
dentro do chat (Esc abre o menu, /help lista tudo):
  /whois nick      fingerprint (6 grupos de 5 dígitos) e número de segurança
  /verify nick     confere a chave e marca ✓; se a chave mudou, aceita a nova
  /fp              sua fingerprint, para passar por outro meio
  /passwd          troca a senha da sua chave (ou, fora do chat: crptochat -n nick --change-pass)
  /mode #canal +t 1h   mensagens do canal somem depois de 1h (operadores; -t desliga)
  /ttl nick 10m    mensagens da conversa direta somem depois de 10min (off desliga)
  /mode #canal +h 7    histórico CIFRADO por 7 dias num canal privado (-h desliga e apaga)
  /chanpass #canal     troca a senha do canal privado e gira a chave (dono)
  /send nick|#canal arquivo   envia arquivo pelo servidor, cifrado (só depois do aceite)
  /send nick arquivo --p2p    envia direto: mais rápido na LAN, mas EXPÕE O SEU IP
  /accept [id] · /reject [id] aceita (escolhendo a pasta) ou recusa um arquivo
  /search texto    (ou Ctrl+F) busca nas conversas abertas, só na memória local
  /notify on|off   notificações do sistema em menção/DM; "preview on" mostra o texto

Se a chave de um nick mudar, as mensagens diretas com ele ficam bloqueadas
até você confirmar por outro meio e aceitar com /verify.

Mensagens diretas têm sigilo por login: chaves de sessão efêmeras assinadas
pela identidade, uma chave nova por mensagem e nada aproveitável depois que a
sessão termina (README, "Sigilo das mensagens diretas").

Histórico fica desligado por padrão. Num canal privado com histórico ligado,
o servidor guarda as mensagens cifradas com a senha do canal pelo prazo
escolhido; quem souber a senha lê o que ainda estiver guardado (README,
"Histórico de canais privados").

Ao entrar, o cliente informa ao servidor só o número da versão (aparece em
contagem no painel de saúde do operador).
"""


def run_update(prefs: dict) -> None:
    from . import update
    repo = update.source_for(prefs)
    mine = update.current()
    try:
        info = update.latest(repo)
        if not update.is_newer(info, mine):
            if info["built"] < (mine["built"] or 0):
                say(f"{Y}a release publicada ({info['version']} {info['commit']}) é mais antiga que este binário "
                    f"({mine['version']} {mine['commit']}); nada foi instalado{R}")
            else:
                say(f"já está na versão mais recente ({mine['version']} {mine['commit']})")
            return
        say(f"instalando crptochat {info['version']} ({info['commit']}) de {repo}…")
        done = update.apply(repo)
    except update.UpdateError as exc:
        sys.exit(f"atualização não instalada: {exc}")
    say(f"{Y}instalado em {done['path']}{R} ({'manifesto assinado e ' if done['signed'] else ''}SHA-256 conferidos)")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="crptochat", description="Chat de terminal cifrado ponta a ponta",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
    ap.add_argument("server", nargs="?", help=f"host[:porta] do servidor (porta padrão {DEFAULT_PORT})")
    ap.add_argument("-n", "--nick", help="nickname")
    ap.add_argument("-a", "--anon", action="store_true",
                    help="entra como anônimo: sem registro, sem senha, nick descartável")
    ap.add_argument("-j", "--join", action="append", default=[], metavar="#CANAL", help="entra no canal ao conectar")
    ap.add_argument("-k", "--key-dir", metavar="DIR",
                    help="pasta onde fica a chave do nick (ex.: um pendrive montado); lembrada por nick")
    ap.add_argument("--vault", metavar="COFRE", choices=sorted(vault.PRESETS),
                    help="guarda/lê a chave do nick num cofre de senhas: " + ", ".join(sorted(vault.PRESETS)))
    ap.add_argument("--key-cmd", metavar="CMD",
                    help="comando que imprime a chave cifrada (outros cofres: bw, op, keepassxc-cli...); {nick} é substituído")
    ap.add_argument("--key-store-cmd", metavar="CMD",
                    help="comando que recebe a chave cifrada pela entrada padrão (par do --key-cmd)")
    ap.add_argument("--pass-cmd", metavar="CMD",
                    help="comando que imprime a senha da identidade, em vez de digitá-la")
    ap.add_argument("--move-key", metavar="DESTINO",
                    help="move a chave existente do nick para uma pasta (ex.: pendrive) ou para um cofre "
                         "(vault:NOME) e sai")
    ap.add_argument("--no-tls", action="store_true", help="conecta sem TLS (servidor iniciado com --no-tls)")
    ap.add_argument("--pin", help="fingerprint SHA-256 esperada do certificado do servidor")
    ap.add_argument("--reset-pin", action="store_true", help="esquece o certificado fixado deste servidor")
    ap.add_argument("--reg-token", help="token de registro, se o servidor exigir")
    ap.add_argument("--p2p-port", type=int, default=0, help="porta TCP fixa para transferências P2P (padrão: aleatória)")
    ap.add_argument("--p2p-host", help="endereço anunciado para P2P (ex.: IP da VPN)")
    ap.add_argument("--downloads", help="pasta dos arquivos recebidos (padrão: ~/Downloads/crptochat)")
    ap.add_argument("--change-pass", action="store_true",
                    help="troca a senha que protege a chave do nick (a chave e o nick continuam os mesmos) e sai")
    ap.add_argument("--update", action="store_true",
                    help="procura e instala a versão mais recente do binário (confere SHA-256 e assinatura) e sai")
    ap.add_argument("--update-repo", metavar="ORIGEM",
                    help="passa a buscar atualizações nesta origem: https://… (padrão: o site), github:dono/repo "
                         "ou file:///pasta; 'padrao' volta ao site (fica salvo)")
    ap.add_argument("--version", action="version",
                    version=__version__ + (f" ({__build__})" if __build__ else ""))
    ap.add_argument("--build-info", action="store_true",
                    help="imprime versão, commit e data do build (usado pelo install.sh contra downgrade) e sai")
    args = ap.parse_args(argv)
    if args.build_info:
        from . import update
        info = update.current()
        print(f"crptochat-build {info['version']} {info['commit'] or '-'} {int(info['built'] or 0)}")
        return

    prefs = load_prefs()
    if args.update_repo:
        from . import update
        if args.update_repo in ("padrao", "padrão", "default"):
            prefs.pop("update_repo", None)
            save_prefs(prefs)
            say(f"atualizações voltam a vir de {update.default_source()}")
        elif not update.valid_source(args.update_repo, local=True):
            sys.exit("origem inválida: use https://… (http:// é recusado), github:dono/repo ou file:///pasta")
        else:
            prefs["update_repo"] = args.update_repo
            save_prefs(prefs)
            say(f"atualizações passam a vir de {args.update_repo}")
    if args.update:
        run_update(prefs)
        return
    print(f"\n{M}▓▒░{R} {C}\033[1mCRPTOCHAT{R} {M}░▒▓{R} {D}v{__version__} · ponta a ponta · servidor cego · arquivos p2p{R}\n")
    try:
        server = args.server or ("" if args.change_pass else ask("servidor (host[:porta])", prefs.get("server")))
        if not server and not args.change_pass:
            sys.exit("servidor obrigatório")
        host, port = parse_server(server) if server else ("", 0)
        known = Identity.list()
        anon = args.anon
        if not anon:
            nick = args.nick or ask("nickname (ou anon para entrar sem registro)",
                                    prefs.get("nick") or (known[0] if known else None))
            anon = nick.lower() in ("anon", "anonimo", "anônimo")
        if anon and args.change_pass:
            sys.exit("sessões anônimas não têm chave guardada nem senha")
        if anon:
            nick = "anon"
            say("sessão anônima: chave descartável só na memória, nada é registrado nem salvo.")
            say(f"{D}sem nick registrado você não cria canais nem tem lista de amigos, "
                f"e alguns canais podem barrar anônimos.{R}")
        if not valid_nick(nick):
            sys.exit("nickname inválido: 3 a 20 caracteres (letras, números, _ e -)")

        if anon:
            identity = Identity("anon", crypto.ed_generate())
        else:
            key_dirs = prefs.setdefault("key_dirs", {})
            key_sources = prefs.setdefault("key_sources", {})
            pass_cmds = prefs.setdefault("pass_cmds", {})
            low = nick.lower()

            # Where the key lives: an explicit flag wins over what was remembered.
            explicit = bool(args.key_dir or args.vault or args.key_cmd)
            key_dir = source = None
            if args.vault:
                source = {"vault": args.vault}
            elif args.key_cmd:
                source = {"read": args.key_cmd, "write": args.key_store_cmd}
            elif args.key_dir:
                key_dir = args.key_dir
            elif low in key_sources:
                source = key_sources[low]
            else:
                key_dir = key_dirs.get(low)
            if key_dir:
                key_dir = os.path.abspath(os.path.expanduser(key_dir))
            pass_cmd = args.pass_cmd or pass_cmds.get(low)

            def remember() -> None:
                key_dirs.pop(low, None)
                key_sources.pop(low, None)
                if source:
                    key_sources[low] = source
                elif key_dir:
                    key_dirs[low] = key_dir
                if args.pass_cmd:
                    pass_cmds[low] = args.pass_cmd

            where = vault.describe(source) if source else Identity.path(nick, key_dir)

            if args.move_key:
                dest_dir = dest_source = None
                if args.move_key.lower().startswith("vault:"):
                    dest_source = vault.parse(args.move_key)
                else:
                    dest_dir = os.path.abspath(os.path.expanduser(args.move_key))
                try:
                    dest = Identity.relocate(nick, key_dir, source, dest_dir, dest_source)
                except FileNotFoundError:
                    sys.exit(f"chave de '{nick}' não encontrada em {where}")
                except FileExistsError as exc:
                    sys.exit(f"já existe uma chave de '{nick}' em {exc}")
                except (OSError, ValueError) as exc:
                    sys.exit(f"não foi possível mover a chave: {exc}")
                key_dir, source = dest_dir, dest_source
                remember()
                save_prefs(prefs)
                say(f"chave de '{nick}' movida para {D}{dest or vault.describe(dest_source)}{R}")
                say("a partir de agora o crptochat procura a chave lá"
                    + ("; o cofre precisa estar desbloqueado ao abrir." if dest_source else
                       "; conecte o dispositivo antes de abrir."))
                return

            if args.change_pass and not Identity.exists(nick, key_dir, source):
                sys.exit(f"chave de '{nick}' não encontrada em {where}")
            if not Identity.exists(nick, key_dir, source):
                if (key_dir or source) and not explicit:
                    # We know this nick's key lives elsewhere: never offer to create a new one.
                    hint = ("Desbloqueie/autentique o cofre e tente de novo." if source else
                            "Conecte/monte o dispositivo e tente de novo (ou indique outra pasta com --key-dir).")
                    sys.exit(f"a chave de '{nick}' fica em {where}, que não está acessível.\n{hint}")
                if key_dir and not os.path.isdir(key_dir):
                    sys.exit(f"pasta não encontrada: {key_dir} (o dispositivo está montado?)")
                say(f"nenhuma identidade para '{nick}': uma nova chave será criada.")
                say(f"{Y}o nickname fica preso a essa chave para sempre; se perder a chave ou a senha,")
                say(f"{Y}ninguém (nem você, nem o servidor) poderá usar esse nickname de novo.{R}")
                if not key_dir and not source and "CRPTOCHAT_PASSPHRASE" not in os.environ:
                    vaults = vault.available()
                    say("onde guardar a chave? Enter = neste computador, uma pasta (ex.: pendrive)"
                        + (f" ou um cofre: {', '.join('vault:' + v for v in vaults)}" if vaults else ""))
                    chosen = ask("destino da chave", "")
                    if chosen.lower().startswith("vault:"):
                        source = vault.parse(chosen)
                    elif chosen:
                        key_dir = os.path.abspath(os.path.expanduser(chosen))
                        if not os.path.isdir(key_dir):
                            sys.exit(f"pasta não encontrada: {key_dir} (o dispositivo está montado?)")
                while True:
                    first = ask_secret("crie uma senha para proteger a chave", pass_cmd, nick)
                    if ("CRPTOCHAT_PASSPHRASE" in os.environ or pass_cmd
                            or first == ask_secret("repita a senha")):
                        break
                    say(f"{Y}as senhas não conferem{R}")
                try:
                    identity = Identity.create(nick, first, key_dir, source)
                except FileExistsError as exc:
                    sys.exit(f"já existe uma chave de '{nick}' em {exc}")
                except OSError as exc:
                    sys.exit(f"não foi possível gravar a chave: {exc}")
                say(f"chave criada em {D}{identity.location}{R} (mantenha um backup)")
            else:
                for attempt in range(3):
                    try:
                        current = ask_secret(f"senha {'atual ' if args.change_pass else ''}da identidade '{nick}'",
                                             pass_cmd, nick)
                        identity = Identity.load(nick, current, key_dir, source)
                        break
                    except BadPassphrase:
                        say(f"{Y}senha incorreta{R}")
                        if "CRPTOCHAT_PASSPHRASE" in os.environ or pass_cmd or attempt == 2:
                            sys.exit(1)
                    except FileNotFoundError:
                        sys.exit(f"não consegui ler a chave em {where} (cofre bloqueado?)")
            remember()
            if args.change_pass:
                try:
                    location = change_passphrase(identity, current)
                except (ValueError, OSError) as exc:
                    sys.exit(f"senha não trocada: {exc}")
                say(f"{C}senha trocada{R}: {D}{location}{R}")
                say("a chave, o nick e a fingerprint continuam os mesmos; seus contatos não veem mudança nenhuma.")
                if pass_cmd or "CRPTOCHAT_PASSPHRASE" in os.environ:
                    say(f"{Y}atualize a senha no seu gerenciador (--pass-cmd) ou em CRPTOCHAT_PASSPHRASE.{R}")
                if source and source.get("vault") == "pass":
                    say(f"{Y}se o seu pass usa git, a versão antiga (com a senha antiga) continua no histórico.{R}")
                say("cópias antigas do arquivo (backups, outro pendrive) continuam abrindo com a senha antiga.")
                return
            if source:
                say(f"chave lida do {D}{vault.describe(source)}{R}; ela já está na memória.")
            elif key_dir:
                say(f"chave lida de {D}{key_dir}{R}; ela já está na memória, pode remover o dispositivo.")
    except vault.VaultError as exc:
        sys.exit(f"cofre: {exc}")
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)

    store = Store(f"{host}:{port}")
    if args.reset_pin:
        store.pin_server(None)
    save_prefs({**prefs, "server": server} if anon else {**prefs, "server": server, "nick": identity.nick})

    from .client import ChatClient
    from .tui import ChatApp

    def factory(on_event):
        return ChatClient(host, port, identity, store, on_event, tls=not args.no_tls, pin=args.pin,
                          reg_token=args.reg_token, p2p_port=args.p2p_port, p2p_host=args.p2p_host,
                          download_dir=args.downloads, guest=anon)

    fatal = ChatApp(factory, autojoin=args.join).run()
    if fatal:
        code, text = fatal
        if identity.is_new and code in ("nick_taken", "reg_token", "reg_limit", "bad_nick"):
            prefs.get("key_dirs", {}).pop(identity.nick.lower(), None)
            prefs.get("key_sources", {}).pop(identity.nick.lower(), None)
            save_prefs(prefs)
        say(f"{Y}{text}{R}")
        if identity.is_new and code in ("nick_taken", "reg_token", "reg_limit", "bad_nick"):
            identity.delete()
            say("a identidade recém-criada foi descartada; escolha outro nickname.")
        sys.exit(1)


if __name__ == "__main__":
    main()
