"""`crptochat-admin`: administration console for whoever runs the server.

Unlike `crptochat-dash` (aggregate numbers only), this console shows
nicknames, because moderation needs them: roles, bans, channel ownership.
It still has no access to message content, and it never displays addresses
(address bans are stored as keyed hashes).

It talks to the server through a Unix socket inside the data directory
(mode 0600), so only the user that runs the server can use it. Standard
library only: it also runs inside the server container.

    crptochat-admin --data DIR                 interactive console
    crptochat-admin --data DIR role neo admin  one command and exit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import socket
import sys
import time

SOCKET_NAME = "admin.sock"

C, M, Y, G, P, D, B, R = ("\033[38;5;51m", "\033[38;5;199m", "\033[38;5;226m", "\033[38;5;46m",
                          "\033[38;5;141m", "\033[38;5;60m", "\033[1m", "\033[0m")
POLICIES = {
    "noanon": "bloquear usuários anônimos",
    "moderated": "moderado: só quem tem voz fala",
    "invite": "só convidados entram",
    "textonly": "só texto (bloqueia áudio)",
    "slow": "modo lento (segundos entre mensagens)",
    "limit": "limite de pessoas",
    "ttl": "mensagens temporárias (segundos)",
    "history": "histórico cifrado: dias guardados (só privado; 0 = desligado)",
    "history_anon": "anônimos também recebem o histórico",
}


def socket_path(data_dir: str) -> str:
    return os.path.join(data_dir, SOCKET_NAME)


# ------------------------------------------------------------- server side

class AdminSocket:
    def __init__(self, server, path: str):
        self.server = server
        self.path = path
        self._listener: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        old = os.umask(0o177)
        try:
            self._listener = await asyncio.start_unix_server(self._client, self.path)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)

    async def stop(self) -> None:
        if self._listener:
            self._listener.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    reply = self.server.admin(json.loads(line))
                except ValueError:
                    reply = {"error": "pedido inválido"}
                writer.write(json.dumps(reply).encode() + b"\n")
                await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()


# ------------------------------------------------------------- client side

class AdminError(Exception):
    pass


class Link:
    def __init__(self, path: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.stream = self.sock.makefile("rwb")

    def call(self, op: str, **args) -> dict:
        self.stream.write(json.dumps({"op": op, **args}).encode() + b"\n")
        self.stream.flush()
        line = self.stream.readline()
        if not line:
            raise AdminError("o servidor encerrou a conexão")
        reply = json.loads(line)
        if "error" in reply:
            raise AdminError(reply["error"])
        return reply


def parse_duration(text: str) -> int:
    """'30m', '12h', '7d' -> minutes. 'perm' / '0' -> 0 (forever)."""
    text = text.lower()
    if text in ("perm", "permanente", "sempre", "0"):
        return 0
    unit = {"m": 1, "h": 60, "d": 1440}.get(text[-1:])
    if not unit or not text[:-1].isdigit() or int(text[:-1]) <= 0:
        raise AdminError("duração inválida: use 30m, 12h, 7d ou perm")
    return int(text[:-1]) * unit


def is_duration(text: str) -> bool:
    try:
        parse_duration(text)
        return True
    except AdminError:
        return False


def when(until) -> str:
    if until is None:
        return ""
    return "permanente" if not until else time.strftime("até %d/%m/%Y %H:%M", time.localtime(until))


def age(seconds: int) -> str:
    days, rest = divmod(int(seconds), 86400)
    return (f"{days}d " if days else "") + time.strftime("%H:%M:%S", time.gmtime(rest))


def user_line(user: dict) -> str:
    state = f"{G}●{R}" if user["online"] else f"{D}○{R}"
    colour = {"admin": M, "mod": Y}.get(user["role"], D)
    role = f"{colour}{user['role']:<9}{R}"
    extra = []
    if user.get("away"):
        extra.append("ausente")
    if user["banned"]:
        extra.append(f"{M}BANIDO {when(user.get('banned_until'))}{R}")
    if user.get("channels"):
        extra.append(D + " ".join(user["channels"]) + R)
    return f"{state} {C}{user['nick']:<21}{R}{role} {'  '.join(extra)}"


class Console:
    def __init__(self, link: Link, out=print):
        self.link = link
        self.out = out

    # --- commands (also usable non-interactively) ---------------------------

    def cmd_status(self, args):
        o = self.link.call("overview")
        self.out(f"{M}▓▒░{R} {B}{C}CRPTOCHAT{R} {M}░▒▓{R} {D}administração · {o['name']} · no ar há {age(o['uptime'])}{R}")
        self.out(f"  online {B}{o['online']}{R} (anônimos: {o['guests']}) · nicks {B}{o['nicks']}{R} · "
                 f"equipe {B}{o['staff']}{R} · banidos {B}{o['banned']}{R} (+{o['ip_bans']} endereços) · "
                 f"canais {B}{o['channels']}{R} ({o['active_channels']} ativos) · "
                 f"anônimos {'permitidos' if o['guests_allowed'] else M + 'bloqueados' + R}")

    def cmd_health(self, args):
        """health [watch]                        saúde do servidor: online, canais, bans, limites, versões"""
        if args and args[0] == "watch":
            try:
                while True:
                    self.out("\033[2J\033[H")
                    self.cmd_health([])
                    self.out(f"  {D}atualiza a cada 2 s · Ctrl+C volta{R}")
                    time.sleep(2)
            except KeyboardInterrupt:
                self.out("")
                return None
        h = self.link.call("health")["health"]
        on, ch, bans, rl = h["online"], h["channels"], h["bans"], h["ratelimit"]
        self.out(f"{M}▓▒░{R} {B}{C}SAÚDE{R} {M}░▒▓{R} {D}servidor {h['version']} · no ar há {age(h['uptime'])} · "
                 f"{'TLS' if h['tls'] else M + 'SEM TLS' + R}{R}")
        self.out(f"  {B}online{R}     registrados {B}{on['registered']}{R} · anônimos {B}{on['anonymous']}{R} · "
                 f"conexões {on['connections']} · pico {on['peak']}")
        self.out(f"  {B}canais{R}     {ch['total']} ({ch['private']} privados) · {ch['active']} com gente · "
                 f"{ch['with_history']} com histórico ({ch['history_rows']} mensagens cifradas guardadas)")
        self.out(f"  {B}bans ativos{R} nicks {B}{bans['users']}{R} · endereços {B}{bans['addresses']}{R} · "
                 f"em canais {bans['channel']}")

        def fmt(d):
            return " · ".join(f"{label} {d.get(key, 0)}" for key, label in
                              (("refused", "recusas"), ("warn", "avisos"), ("mute", "mutes"), ("kick", "expulsões")))
        self.out(f"  {B}anti-flood{R} 10 min: {fmt(rl['10min'])}")
        self.out(f"             1 h:    {fmt(rl['1h'])}")
        self.out(f"             total:  {fmt(rl['total'])} · conexões recusadas {rl['total']['conn_refused']}")
        self.out(f"  {B}arquivos{R}   {h['transfers']} transferências pelo servidor agora")
        total = sum(h["versions"].values()) or 1
        self.out(f"  {B}versões dos clientes conectados{R}")
        for version, n in sorted(h["versions"].items(), key=lambda item: -item[1]):
            bar = "█" * max(1, round(24 * n / total))
            self.out(f"    {C}{version:<22}{R}{n:>4}  {P}{bar}{R}")
        if not h["versions"]:
            self.out(f"    {D}ninguém conectado{R}")
        return h

    def cmd_users(self, args):
        """users [online|staff|banned] [texto]   lista usuários"""
        flt = args.pop(0) if args and args[0] in ("online", "staff", "banned") else None
        users = self.link.call("users", filter=flt, query=args[0] if args else "")["users"]
        if not users:
            self.out(f"  {D}ninguém encontrado{R}")
        for user in users:
            self.out("  " + user_line(user))
        return users

    def cmd_user(self, args):
        """user NICK                             detalhes de um usuário"""
        user = self.link.call("user", nick=self._need(args, "nick"))["user"]
        self.out("  " + user_line(user))
        if user.get("ban_reason"):
            self.out(f"    motivo do banimento: {user['ban_reason']}")
        if user.get("created"):
            self.out(f"    {D}registrado em {time.strftime('%d/%m/%Y', time.localtime(user['created']))}{R}")
        for chan, role in user.get("chan_roles", []):
            self.out(f"    {P}{role:<7}{R} em {chan}")
        return user

    def cmd_role(self, args):
        """role NICK admin|mod|user              define o cargo no servidor"""
        nick, role = self._need(args, "nick"), self._need(args[1:], "cargo (admin, mod ou user)")
        r = self.link.call("role", nick=nick, role=role)
        self.out(f"  {G}ok{R} {r['nick']} agora é {B}{r['role']}{R}" + ("" if r["online"] else f" {D}(vale no próximo login){R}"))

    def cmd_ban(self, args):
        """ban NICK [30m|12h|7d|perm] [--ip] [motivo]   bane do servidor"""
        nick = self._need(args, "nick")
        rest = args[1:]
        ip = "--ip" in rest
        rest = [a for a in rest if a != "--ip"]
        minutes = parse_duration(rest.pop(0)) if rest and is_duration(rest[0]) else 0
        r = self.link.call("ban", nick=nick, minutes=minutes, ip=ip, reason=" ".join(rest))
        self.out(f"  {G}ok{R} {r['nick']} banido ({when(r['until'])})"
                 + (" · endereço bloqueado" if r["ip"] else "") + (" · desconectado" if r["online"] else ""))

    def cmd_unban(self, args):
        """unban NICK                            remove o banimento"""
        r = self.link.call("unban", nick=self._need(args, "nick"))
        self.out(f"  {G}ok{R} {r['nick']} desbanido" + (f" (+{r['ip']} endereço)" if r["ip"] else ""))

    def cmd_kick(self, args):
        """kick NICK                             desconecta agora (pode voltar)"""
        r = self.link.call("kick", nick=self._need(args, "nick"))
        self.out(f"  {G}ok{R} {r['nick']} desconectado")

    def cmd_bans(self, args):
        """bans                                  lista banimentos"""
        r = self.link.call("bans")
        if not r["users"] and not r["ips"]:
            self.out(f"  {D}nenhum banimento{R}")
        for ban in r["users"]:
            self.out(f"  {C}{ban['nick']:<21}{R}{when(ban['until']):<24} {ban['reason'] or ''}")
        for ban in r["ips"]:
            self.out(f"  {D}endereço usado por{R} {C}{ban['label']:<12}{R}{when(ban['until']):<24} {ban['reason'] or ''}")
        return r["users"]

    def cmd_channels(self, args):
        """channels                              lista os canais"""
        chans = self.link.call("channels")["channels"]
        for ch in chans:
            self.out(f"  {C}{ch['name']:<24}{R}{'privado' if ch['private'] else 'aberto':<9}"
                     f"{ch['online']:>3} online  dono: {ch['owner'] or D + '(nenhum)' + R:<20} "
                     f"{D}{' '.join(ch['policy'])}{R}")
        return chans

    def cmd_chan(self, args):
        """chan #CANAL                           cargos, políticas e bans de um canal"""
        ch = self.link.call("channel", chan=self._need(args, "#canal"))["channel"]
        self.out(f"  {C}{ch['name']}{R} · {'privado' if ch['private'] else 'aberto'} · {len(ch['online'])} online")
        for name, label in POLICIES.items():
            if name not in ch["policy"]:
                continue
            value = ch["policy"][name]
            shown = ("sim" if isinstance(value, bool) else str(value)) if value else "não"
            self.out(f"    {name:<10} {G if value else D}{shown:<5}{R} {D}{label}{R}")
        for nick, role in ch["roles"]:
            self.out(f"    {P}{role:<7}{R} {nick}")
        if ch["bans"]:
            self.out(f"    {M}banidos:{R} {', '.join(ch['bans'])}")
        if ch.get("history_rows") is not None and (ch["policy"].get("history") or ch["history_rows"]):
            self.out(f"    {Y}histórico:{R} {ch['history_rows']} mensagens cifradas guardadas · "
                     f"senha trocada {ch.get('epoch', 0)} vez(es) · o servidor não consegue lê-las")
        return ch

    def cmd_chanrole(self, args):
        """chanrole #CANAL NICK owner|op|voice|member|none   cargo dentro de um canal"""
        chan, nick = self._need(args, "#canal"), self._need(args[1:], "nick")
        role = self._need(args[2:], "cargo")
        r = self.link.call("chan_role", chan=chan, nick=nick, role=None if role == "none" else role)
        self.out(f"  {G}ok{R} {r['nick']} em {chan}: {r['role'] or 'sem cargo'}")

    def cmd_policy(self, args):
        """policy #CANAL NOME on|off|N           muda uma política de canal"""
        chan, name = self._need(args, "#canal"), self._need(args[1:], "política")
        raw = self._need(args[2:], "valor")
        value = int(raw) if raw.isdigit() else raw.lower() in ("on", "sim", "true", "1")
        self.link.call("chan_policy", chan=chan, set={name: value})
        self.out(f"  {G}ok{R} {chan}: {name} = {value}")

    def cmd_chanunban(self, args):
        """chanunban #CANAL NICK                 remove um ban de canal"""
        r = self.link.call("chan_unban", chan=self._need(args, "#canal"), nick=self._need(args[1:], "nick"))
        self.out(f"  {G}ok{R} {r['nick']} pode voltar a {r['chan']}")

    def cmd_guests(self, args):
        """guests on|off                         permite ou bloqueia acesso anônimo"""
        on = self._need(args, "on|off").lower() in ("on", "sim", "1")
        self.link.call("guests", on=on)
        self.out(f"  {G}ok{R} acesso anônimo {'permitido' if on else 'bloqueado'} {D}(até reiniciar; para fixar use --no-guests){R}")

    def cmd_updaterepo(self, args):
        """updaterepo [https://…|github:dono/repo|none]   origem de atualização sugerida aos clientes"""
        if not args:
            repo = self.link.call("update_repo")["repo"]
            self.out(f"  origem de atualização: {C}{repo or '(padrão de cada cliente)'}{R}")
            return
        repo = self.link.call("update_repo", repo=args[0])["repo"]
        self.out(f"  {G}ok{R} clientes passam a ser avisados para usar {C}{repo or 'o próprio padrão'}{R} "
                 f"{D}(cada pessoa confirma a troca; releases assinadas continuam exigidas){R}")

    def cmd_ratelimit(self, args):
        """ratelimit [show|set NOME VALOR|reset NOME|all]   limites anti-flood"""
        action = args[0].lower() if args else "show"
        if action == "set":
            name, value = self._need(args[1:], "nome"), self._need(args[2:], "valor")
            r = self.link.call("ratelimit", set={name: value})
            self.out(f"  {G}ok{R} {name} = {r['limits'][name]:g} {D}(vale na hora, também para quem já está conectado){R}")
            return r
        if action == "reset":
            target = self._need(args[1:], "nome ou all")
            r = self.link.call("ratelimit", reset=target)
            self.out(f"  {G}ok{R} {'todos os limites voltaram' if target == 'all' else target + ' voltou'} ao padrão")
            return r
        if action != "show":
            raise AdminError("uso: ratelimit [show | set NOME VALOR | reset NOME | reset all]")
        r = self.link.call("ratelimit")
        st = r["stats"]
        self.out(f"  {B}limites anti-flood{R} · disparos desde o início: recusas {B}{st['refused']}{R} · avisos "
                 f"{B}{st['warn']}{R} · mutes {B}{st['mute']}{R} · expulsões {B}{st['kick']}{R} · "
                 f"conexões recusadas {B}{st['conn_refused']}{R}")
        for name, value in r["limits"].items():
            mark = f"{Y}*{R}" if value != r["defaults"][name] else " "
            self.out(f"  {mark} {C}{name:<20}{R}{value:>9g}  {D}{r['descriptions'][name]}"
                     + (f" (padrão {r['defaults'][name]:g})" if value != r["defaults"][name] else "") + R)
        self.out(f"  {D}* alterado · 0 em taxa e rajada juntos desliga o limite · ratelimit set NOME VALOR{R}")
        return r

    def cmd_notice(self, args):
        """notice TEXTO                          aviso do servidor para todos online"""
        text = " ".join(args)
        if not text:
            raise AdminError("uso: notice TEXTO")
        self.out(f"  {G}ok{R} aviso enviado a {self.link.call('notice', text=text)['sent']} sessões")

    def cmd_help(self, args):
        self.out(f"  {B}comandos{R} {D}(ou digite o número de uma opção do menu){R}")
        for name in ("health", "users", "user", "role", "ban", "unban", "kick", "bans", "channels", "chan",
                     "chanrole", "policy", "chanunban", "guests", "ratelimit", "updaterepo", "notice"):
            self.out(f"  {C}{getattr(self, 'cmd_' + name).__doc__}{R}")

    @staticmethod
    def _need(args, what: str) -> str:
        if not args:
            raise AdminError(f"faltou informar: {what}")
        return args[0]

    def run(self, argv: list[str]) -> None:
        handler = getattr(self, "cmd_" + argv[0].lower(), None)
        if handler is None:
            raise AdminError(f"comando desconhecido: {argv[0]} (veja help)")
        handler(list(argv[1:]))

    # --- interactive menus ------------------------------------------------

    def ask(self, label: str) -> str:
        return input(f"  {C}{label}{R} {M}❯{R} ").strip()

    def pick(self, items: list, label: str):
        if not items:
            return None
        answer = self.ask(f"{label} (número, Enter volta)")
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            return items[int(answer) - 1]
        return None

    def menu_user(self, nick: str) -> None:
        while True:
            self.out("")
            user = self.cmd_user([nick])
            anon = user["role"] == "anônimo"
            self.out(f"  {Y}1{R} banir  {Y}2{R} banir + endereço  {Y}3{R} desbanir  {Y}4{R} desconectar"
                     + ("" if anon else f"  {Y}5{R} cargo no servidor") + f"  {D}Enter volta{R}")
            choice = self.ask("ação")
            try:
                if choice in ("1", "2"):
                    duration = self.ask("duração (30m, 12h, 7d, Enter = permanente)") or "perm"
                    reason = self.ask("motivo (mostrado ao usuário, opcional)")
                    self.cmd_ban([nick, duration] + (["--ip"] if choice == "2" else []) + ([reason] if reason else []))
                    if anon:
                        return
                elif choice == "3":
                    self.cmd_unban([nick])
                elif choice == "4":
                    self.cmd_kick([nick])
                    if anon:
                        return
                elif choice == "5" and not anon:
                    self.cmd_role([nick, self.ask("cargo (admin, mod, user)")])
                else:
                    return
            except AdminError as exc:
                self.out(f"  {M}erro:{R} {exc}")

    def menu_users(self, args: list[str]) -> None:
        users = self.cmd_users(args)
        for index, _ in enumerate(users, 1):
            pass
        if users:
            self.out(f"  {D}" + "  ".join(f"{i}:{u['nick']}" for i, u in enumerate(users, 1)) + R)
        chosen = self.pick(users, "abrir usuário")
        if chosen:
            self.menu_user(chosen["nick"])

    def menu_channel(self, chan: str) -> None:
        while True:
            self.out("")
            self.cmd_chan([chan])
            self.out(f"  {Y}1{R} mudar política  {Y}2{R} definir cargo  {Y}3{R} remover ban  {D}Enter volta{R}")
            choice = self.ask("ação")
            try:
                if choice == "1":
                    name = self.ask("política (" + ", ".join(POLICIES) + ")")
                    self.cmd_policy([chan, name, self.ask("valor (on, off ou número)")])
                elif choice == "2":
                    nick = self.ask("nick")
                    self.cmd_chanrole([chan, nick, self.ask("cargo (owner, op, voice, member, none)")])
                elif choice == "3":
                    self.cmd_chanunban([chan, self.ask("nick")])
                else:
                    return
            except AdminError as exc:
                self.out(f"  {M}erro:{R} {exc}")

    def loop(self) -> None:
        menu = [
            ("saúde do servidor", lambda: self.cmd_health([])),
            ("usuários online", lambda: self.menu_users(["online"])),
            ("buscar usuário", lambda: self.menu_users([self.ask("parte do nick")])),
            ("equipe (admins e mods)", lambda: self.menu_users(["staff"])),
            ("banimentos", lambda: (lambda b: b and self.menu_user(b["nick"]))(
                self.pick(self.cmd_bans([]), "abrir banido"))),
            ("canais", lambda: (lambda c: c and self.menu_channel(c["name"]))(
                self.pick((lambda cs: (self.out(f"  {D}" + "  ".join(f"{i}:{c['name']}" for i, c in enumerate(cs, 1)) + R), cs)[1])(
                    self.cmd_channels([])), "abrir canal"))),
            ("aviso a todos", lambda: self.cmd_notice([self.ask("texto do aviso")])),
            ("limites anti-flood", lambda: (
                self.cmd_ratelimit([]),
                (lambda n: n and self.cmd_ratelimit(["set", n, self.ask(f"novo valor de {n}")]))(
                    self.ask("limite a mudar (Enter volta)")))),
            ("origem de atualização do cliente", lambda: (
                self.cmd_updaterepo([]),
                (lambda r: r and self.cmd_updaterepo([r]))(self.ask("nova origem https://… ou github:dono/repo (Enter mantém, none volta ao padrão)")))),
            ("ligar/desligar acesso anônimo", lambda: self.cmd_guests(
                ["off" if self.link.call("overview")["guests_allowed"] else "on"])),
        ]
        while True:
            self.out("")
            self.cmd_status([])
            for index, (label, _) in enumerate(menu, 1):
                self.out(f"  {Y}{index}{R} {label}")
            self.out(f"  {Y}0{R} sair   {D}ou um comando direto: help{R}")
            try:
                line = input(f"{M}▓▒░{R} {C}admin{R} {M}❯{R} ").strip()
            except (EOFError, KeyboardInterrupt):
                self.out("")
                return
            if line in ("0", "q", "quit", "exit", "sair"):
                return
            if not line:
                continue
            try:
                if line.isdigit() and 1 <= int(line) <= len(menu):
                    menu[int(line) - 1][1]()
                else:
                    self.run(shlex.split(line))
            except AdminError as exc:
                self.out(f"  {M}erro:{R} {exc}")
            except (EOFError, KeyboardInterrupt):
                self.out("")
            except ValueError as exc:
                self.out(f"  {M}erro:{R} {exc}")


def main(argv=None) -> None:
    commands = "\n".join("  " + getattr(Console, name).__doc__.strip()
                          for name in sorted(dir(Console)) if name.startswith("cmd_") and getattr(Console, name).__doc__)
    ap = argparse.ArgumentParser(prog="crptochat-admin", description="Console de administração do crptochat-server",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="comandos (também no console interativo, com help):\n" + commands)
    ap.add_argument("--data", default="./crptochat-data", help="diretório de dados do servidor (o mesmo do --data dele)")
    ap.add_argument("--socket", help="caminho do socket de administração (padrão: <data>/admin.sock)")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="comando único (ex.: role neo admin); sem ele abre o console")
    args = ap.parse_args(argv)
    path = args.socket or socket_path(args.data)
    try:
        link = Link(path)
    except OSError as exc:
        sys.exit(f"não foi possível conectar em {path}: {exc}\n"
                 "o servidor está rodando com esse --data? O console só funciona para o mesmo usuário do servidor.")
    console = Console(link)
    try:
        if args.command:
            console.run(args.command)
        else:
            console.loop()
    except AdminError as exc:
        sys.exit(f"erro: {exc}")


if __name__ == "__main__":
    main()
