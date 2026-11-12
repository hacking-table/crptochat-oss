"""Cyberpunk terminal interface (Textual)."""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import re
import shlex
import os
import time
import unicodedata
from collections import deque

from rich.text import Text
from textual.app import App, ComposeResult, SuspendNotSupported
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from . import __version__, crypto
from . import audio
from .audio import AudioError, Player, Recorder, sniff
from .client import ChatClient, ChatError, NeedPassphrase
from .p2p import human_size
from .protocol import MAX_TTL, format_duration, parse_duration, valid_chan, valid_nick
from . import themes, update, vault
from .notify import Notifier
from .store import BadPassphrase, Identity, load_prefs, save_prefs

# ------------------------------------------------------------------ palette

# Module-level colour names, rebound by set_palette() when the theme changes.
# Code reads them at call time, so everything drawn afterwards uses the new theme.
BG = PANEL = CYAN = MAGENTA = PINK = YELLOW = GREEN = PURPLE = ORANGE = DIM = TEXT = ""
NICK_COLORS: list[str] = []
THEME = themes.DEFAULT


def set_palette(name: str) -> dict[str, str]:
    """Switch the active theme. Returns {old colour: new colour}."""
    global THEME
    old = [globals()[slot] for slot in themes.SLOTS] + list(NICK_COLORS)
    slots, nicks = themes.palette(name)
    globals().update(slots)
    NICK_COLORS[:] = nicks
    THEME = name if name in themes.THEMES else themes.DEFAULT
    new = [slots[slot] for slot in themes.SLOTS] + nicks
    return {a: b for a, b in zip(old, new) if a}


set_palette(themes.DEFAULT)


def level_color(level: str) -> str:
    return {"ok": GREEN, "warn": YELLOW, "err": MAGENTA}.get(level, DIM)


def recolor(text: Text, mapping: dict[str, str]) -> None:
    """Repaint a line that was drawn with the previous theme."""
    def swap(style):
        if not isinstance(style, str):
            return style
        for old in re.findall(r"#[0-9a-f]{6}", style):
            style = style.replace(old, mapping.get(old, old))
        return style
    text.style = swap(text.style)
    text.spans[:] = [span._replace(style=swap(span.style)) for span in text.spans]


CONSOLE = "console"

ROLE_MARK = {"owner": "~", "op": "@", "voice": "+"}
ROLE_NAME = {"owner": "dono (~)", "op": "operador (@)", "voice": "voz (+)", None: "sem cargo"}
POLICIES = {
    "noanon": ("bloquear anônimos", "só nicks registrados entram"),
    "moderated": ("canal moderado", "só quem tem voz, operadores e dono falam"),
    "invite": ("só convidados", "entra quem foi convidado ou tem cargo"),
    "textonly": ("só texto", "bloqueia áudio e mensagens enormes"),
    "slow": ("modo lento", "segundos de espera entre mensagens de cada pessoa"),
    "limit": ("limite de pessoas", "máximo de gente no canal (0 = padrão)"),
    "ttl": ("mensagens temporárias", "as mensagens somem depois desse tempo (/mode #canal +t 1h)"),
    "history": ("histórico cifrado", "dias que o servidor guarda o cifrado (só canal privado; /mode #canal +h 7)"),
    "history_anon": ("histórico p/ anônimos", "anônimos também recebem o histórico ao entrar"),
}

GLYPHS = {
    "C": ("█▀▀", "█  ", "▀▀▀"), "R": ("█▀█", "█▀▄", "▀ ▀"), "P": ("█▀█", "█▀▀", "▀  "),
    "T": ("▀█▀", " █ ", " ▀ "), "O": ("█▀█", "█ █", "▀▀▀"), "H": ("█ █", "█▀█", "▀ ▀"),
    "A": ("█▀█", "█▀█", "▀ ▀"),
}

CUSTOM = "__custom__"

MENU = [
    ("CANAIS", [
        ("join", "Entrar em um canal", "escolha na lista ou digite o nome"),
        ("create", "Criar canal aberto", "qualquer pessoa pode entrar"),
        ("create_priv", "Criar canal privado", "protegido por senha"),
        ("leave", "Sair do canal / fechar conversa atual", ""),
    ]),
    ("CONVERSAS", [
        ("dm", "Mensagem direta", "abre uma conversa com um nick"),
        ("friends", "Amigos", "ver quem está online, adicionar, remover"),
        ("away", "Ausente / voltei", "avisa quem falar com você"),
    ]),
    ("MODERAÇÃO DO CANAL", [
        ("mod", "Moderar um membro", "voz, operador, expulsar, banir"),
        ("policy", "Políticas do canal", "anônimos, moderado, modo lento…"),
        ("invite", "Convidar alguém", "para canais só de convidados"),
        ("staff", "Moderação do servidor", "expulsar ou banir (só equipe)"),
    ]),
    ("ÁUDIO", [
        ("rec", "Gravar mensagem de voz", "para a janela atual · F2"),
        ("play", "Ouvir um áudio recebido", ""),
        ("voice", "Proteção de voz", "disfarçar ou não a sua voz nos áudios"),
    ]),
    ("ARQUIVOS", [
        ("send", "Enviar arquivo", "cifrado, pelo servidor (ou direto, P2P)"),
        ("files", "Ofertas recebidas", "aceitar ou recusar arquivos"),
    ]),
    ("SEGURANÇA", [
        ("fp", "Minha fingerprint", ""),
        ("who", "Membros do canal e fingerprints", ""),
        ("verify", "Conferir a fingerprint de alguém", "marca como conferida ✓"),
        ("movekey", "Mover minha chave", "para um pendrive ou um cofre de senhas"),
        ("passwd", "Trocar a senha da minha chave", "a chave e o nick continuam os mesmos"),
    ]),
    ("SESSÃO", [
        ("theme", "Temas", "cores da interface"),
        ("update", "Atualizar o crptochat", "procura e instala a versão mais recente"),
        ("help", "Ajuda: comandos e teclas", ""),
        ("search", "Buscar nas conversas", "só no que está na memória · Ctrl+F"),
        ("notify", "Notificações do sistema", "menções e mensagens diretas"),
        ("clear", "Limpar a janela atual", ""),
        ("quit", "Sair do crptochat", ""),
    ]),
]

HELP = [
    ("/menu  (ou Esc / F1)", "abre o menu interativo com todas as ações"),
    ("/list", "lista os canais do servidor"),
    ("/create #canal", "cria um canal aberto"),
    ("/create #canal privado", "cria um canal privado protegido por senha"),
    ("/join #canal", "entra em um canal (pede a senha se for privado)"),
    ("/leave", "sai do canal atual / fecha a conversa"),
    ("/msg nick texto", "mensagem direta cifrada"),
    ("/query nick", "abre uma conversa direta"),
    ("/rec  (ou F2)", "grava uma mensagem de voz; /rec ou Enter envia, Esc cancela"),
    ("/voice [mascarada|natural]", "disfarce de voz nos áudios (padrão: mascarada)"),
    ("/play [n]  /stop", "ouve o áudio n (ou o mais recente); /stop interrompe"),
    ("/send nick|#canal arquivo", "envia arquivo pelo servidor, cifrado de ponta a ponta"),
    ("/send nick arquivo --p2p", "envia direto (P2P): mais rápido na rede local, mas expõe seu IP"),
    ("/accept [id]  /reject [id]", "aceita ou recusa um arquivo"),
    ("/away [texto]  /back", "modo ausente: quem te escrever recebe o aviso"),
    ("/friend add|del nick  /friends", "lista de amigos (fica só neste computador)"),
    ("/theme [nome]", "troca o tema de cores"),
    ("/update [check|origem https://…|origem padrao]", "procura no site, confere a assinatura e instala"),
    ("/op /deop /voice /devoice nick", "cargos do canal: ~dono @operador +voz"),
    ("/kick nick  /ban nick  /unban nick", "expulsa ou bane do canal (operadores)"),
    ("/policy [nome valor]", "políticas: noanon moderated invite textonly slow limit ttl"),
    ("/mode #canal +t 1h | -t", "mensagens temporárias no canal (também +m +i +a +x)"),
    ("/mode #canal +h 7 | -h", "histórico cifrado por N dias (só canal privado; desligado por padrão)"),
    ("/chanpass #canal", "troca a senha do canal privado (gira a chave; dono)"),
    ("/ttl nick 10m | off", "mensagens temporárias numa conversa direta"),
    ("/invite /owner nick  /roles /bans", "convida, transfere o canal, lista cargos e bans"),
    ("/gkick /gban /gunban nick", "moderação do servidor (só equipe)"),
    ("/who", "membros do canal e suas fingerprints"),
    ("/whois nick", "fingerprint e número de segurança de um usuário"),
    ("/verify nick", "confere a chave (ou aceita uma chave que mudou) e marca ✓"),
    ("/fp", "mostra a sua fingerprint"),
    ("/passwd", "troca a senha que protege a sua chave (chave e nick continuam os mesmos)"),
    ("/search texto  (ou Ctrl+F)", "busca nas conversas abertas (só na memória local)"),
    ("/notify on|off|preview on|off", "notificações do sistema em menção e mensagem direta"),
    ("/clear", "limpa a tela atual"),
    ("/quit", "sai"),
]
COMMANDS = ["/help", "/menu", "/list", "/create", "/join", "/leave", "/msg", "/query", "/send", "/rec", "/voice", "/play", "/stop", "/accept",
            "/reject", "/away", "/back", "/friend", "/friends", "/theme", "/update", "/mode", "/chanpass", "/ttl", "/op", "/deop", "/voice", "/devoice",
            "/kick", "/ban", "/unban", "/bans", "/roles", "/policy", "/invite", "/owner", "/gkick", "/gban", "/gunban",
            "/who", "/whois", "/verify", "/unverify", "/fp", "/passwd", "/search", "/notify", "/clear", "/quit"]

_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def clean(text: str) -> str:
    """Neutralise control characters so peers cannot inject terminal escapes."""
    return "".join(" " if c in "\n\t" else c for c in text
                   if (c.isprintable() or c in "\n\t‍") and ord(c) not in _BIDI)


def fp_block(ik: bytes) -> str:
    """Fingerprint in two lines of three groups, for the narrow side panel."""
    groups = crypto.fingerprint(ik).split()
    return " ".join(groups[:3]) + "\n" + " ".join(groups[3:])


def nick_color(nick: str) -> str:
    # only picks a display colour: not a security use
    return NICK_COLORS[hashlib.sha1(nick.lower().encode(), usedforsecurity=False).digest()[0] % len(NICK_COLORS)]


def gradient(text: str) -> Text:
    """Fade from the theme's primary accent to its frame colour."""
    start, end = ([int(colour[i:i + 2], 16) for i in (1, 3, 5)] for colour in (CYAN, MAGENTA))
    out = Text()
    span = max(len(text) - 1, 1)
    for i, char in enumerate(text):
        rgb = [round(a + (b - a) * i / span) for a, b in zip(start, end)]
        out.append(char, style=f"bold #{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}")
    return out


def banner() -> list[Text]:
    rows = [" ".join(GLYPHS[c][r] for c in "CRPTOCHAT") for r in range(3)]
    lines = [Text("")] + [Text("  ") + gradient(row) for row in rows]
    lines.append(Text.assemble(("  ░▒▓ ", MAGENTA), ("ponta a ponta", CYAN), (" · ", DIM), ("servidor cego", CYAN),
                               (" · ", DIM), ("arquivos p2p", CYAN), (" ▓▒░", MAGENTA), (f"  v{__version__}", DIM)))
    lines.append(Text(""))
    return lines


class Buffer:
    def __init__(self, name: str):
        self.name = name
        self.lines: deque[Text] = deque(maxlen=3000)
        self.expiry: dict[int, float] = {}     # id(line) -> when it disappears
        self.unread = 0
        self.alert = False

    def purge(self, now: float) -> int:
        """Drop lines whose time is up; returns how many were removed."""
        if not self.expiry:
            return 0
        gone = {key for key, when in self.expiry.items() if when <= now}
        if not gone:
            return 0
        kept = [line for line in self.lines if id(line) not in gone]
        removed = len(self.lines) - len(kept)
        self.lines = deque(kept, maxlen=3000)
        live = {id(line) for line in self.lines}
        self.expiry = {key: when for key, when in self.expiry.items() if key in live}
        return removed
    @property
    def kind(self) -> str:
        return "chan" if self.name.startswith("#") else "dm" if self.name.startswith("@") else "sys"


# ------------------------------------------------------------------ widgets

class ChatInput(Input):
    BINDINGS = [
        Binding("tab", "complete", show=False),
        Binding("up", "history(-1)", show=False),
        Binding("down", "history(1)", show=False),
    ]

    def __init__(self, **kw):
        super().__init__(**kw)
        self.history: list[str] = []
        self._hpos = 0
        self._cycle: tuple[str, list[str], int] | None = None

    def remember(self, line: str) -> None:
        if line and (not self.history or self.history[-1] != line):
            self.history.append(line)
        self._hpos = len(self.history)

    def action_history(self, step: int) -> None:
        if not self.history:
            return
        self._hpos = max(0, min(len(self.history), self._hpos + step))
        self.value = self.history[self._hpos] if self._hpos < len(self.history) else ""
        self.cursor_position = len(self.value)

    def action_complete(self) -> None:
        if self._cycle and self.value == self._cycle[0] + self._cycle[1][self._cycle[2]]:
            head, options, idx = self._cycle
            idx = (idx + 1) % len(options)
        else:
            head, _, word = self.value.rpartition(" ")
            head = head + " " if head or self.value.startswith(" ") else ""
            if not word:
                return
            options = self.app.completions(word, first=not head)
            if not options:
                return
            idx = 0
        self._cycle = (head, options, idx)
        self.value = head + options[idx]
        self.cursor_position = len(self.value)


class ChatLog(RichLog):
    """RichLog wraps at write time, so re-wrap whenever the width changes."""

    can_focus = False
    _last_width = 0

    def on_resize(self, event) -> None:
        if event.size.width != self._last_width:
            self._last_width = event.size.width
            self.app.call_after_refresh(self.app.refill)


class BufferList(Static):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.rows: list[str | None] = []

    def on_click(self, event) -> None:
        row = event.y - 1  # minus the top border
        if 0 <= row < len(self.rows) and self.rows[row]:
            target = self.rows[row]
            if target in self.app.buffers:
                self.app.switch(target)
            else:  # a friend without an open conversation yet
                self.app.execute("/query " + target[1:])


class PassScreen(ModalScreen):
    """Asks for a channel passphrase without echoing it."""

    BINDINGS = [Binding("escape", "cancel", show=False)]

    def __init__(self, title: str, confirm: bool = False, placeholder: str = "senha do canal"):
        super().__init__()
        self.title_text = title
        self.confirm = confirm
        self.placeholder = placeholder

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text.assemble(("◢◤ ", MAGENTA), (self.title_text, f"bold {CYAN}")), id="dlg-title")
            yield Input(password=True, placeholder=self.placeholder, id="p1")
            if self.confirm:
                yield Input(password=True, placeholder="repita a senha", id="p2")
            yield Static(Text("Enter confirma · Esc cancela · a senha nunca é enviada ao servidor", style=DIM),
                         id="dlg-hint")

    def on_mount(self) -> None:
        self.query_one("#dialog").border_title = "ACESSO RESTRITO"
        self.query_one("#p1", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        first = self.query_one("#p1", Input).value
        hint = self.query_one("#dlg-hint", Static)
        if not first:
            return
        if self.confirm:
            second = self.query_one("#p2", Input)
            if event.input.id == "p1":
                second.focus()
                return
            if second.value != first:
                hint.update(Text("as senhas não conferem", style=MAGENTA))
                return
            if len(first) < 8:
                hint.update(Text("use pelo menos 8 caracteres: a senha é a chave do canal", style=MAGENTA))
                return
        self.dismiss(first)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ChoiceScreen(ModalScreen):
    """A list to pick from. ``groups`` is [(header | None, [(id, label, detail)])]."""

    BINDINGS = [Binding("escape", "cancel", show=False)]

    def __init__(self, title: str, groups, heading: str = "MENU", hint: str = "↑↓ navegar · Enter escolhe · Esc fecha",
                 preview=None, start: str | None = None):
        super().__init__()
        self.title_text, self.groups, self.heading, self.hint = title, groups, heading, hint
        self.preview, self.start = preview, start

    def compose(self) -> ComposeResult:
        options = []
        for header, items in self.groups:
            if header:
                options.append(Option(Text(f"─ {header} ─", style=f"bold {PURPLE}"), disabled=True))
            for ident, label, detail in items:
                options.append(Option(Text.assemble(("  " + label, f"bold {TEXT}"),
                                                    (f"  {detail}" if detail else "", DIM)), id=ident))
        with Vertical(id="dialog"):
            if self.title_text:
                yield Static(Text.assemble(("◢◤ ", MAGENTA), (self.title_text, f"bold {CYAN}")), id="dlg-title")
            yield OptionList(*options, id="options")
            yield Static(Text(self.hint, style=DIM), id="dlg-hint")

    def on_mount(self) -> None:
        self.query_one("#dialog").border_title = self.heading
        options = self.query_one("#options", OptionList)
        options.focus()
        options.action_first()
        if self.start:
            try:
                options.highlighted = options.get_option_index(self.start)
            except Exception:
                pass

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if self.preview and event.option.id:
            self.preview(event.option.id)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class FormScreen(ModalScreen):
    """One or more text fields. Dismisses with a list of values or None."""

    BINDINGS = [Binding("escape", "cancel", show=False)]

    def __init__(self, title: str, fields: list[str], validate=None, heading: str = "ENTRADA", initial: str = ""):
        super().__init__()
        self.title_text, self.fields, self.validate, self.heading, self.initial = title, fields, validate, heading, initial

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text.assemble(("◢◤ ", MAGENTA), (self.title_text, f"bold {CYAN}")), id="dlg-title")
            for index, placeholder in enumerate(self.fields):
                yield Input(placeholder=placeholder, id=f"f{index}", value=self.initial if index == 0 else "")
            yield Static(Text("Enter confirma · Esc cancela", style=DIM), id="dlg-hint")

    def on_mount(self) -> None:
        self.query_one("#dialog").border_title = self.heading
        self.query_one("#f0", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        inputs = [self.query_one(f"#f{i}", Input) for i in range(len(self.fields))]
        index = inputs.index(event.input)
        if not event.input.value.strip():
            return
        if index + 1 < len(inputs):
            inputs[index + 1].focus()
            return
        values = [box.value.strip() for box in inputs]
        error = self.validate(values) if self.validate else None
        if error:
            self.query_one("#dlg-hint", Static).update(Text(error, style=MAGENTA))
            return
        self.dismiss(values)

    def action_cancel(self) -> None:
        self.dismiss(None)


def fold(text: str) -> str:
    """Case- and accent-insensitive form used by /search."""
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


class SearchScreen(ModalScreen):
    """Type to filter every line still on screen (RAM only, nothing is asked of
    the server); Enter jumps to the line in its window."""

    BINDINGS = [Binding("escape", "cancel", show=False), Binding("down", "results", show=False)]
    LIMIT = 200

    def __init__(self, search, initial: str = ""):
        super().__init__()
        self.search, self.initial = search, initial
        self.found: list = []

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(Text.assemble(("◢◤ ", MAGENTA), ("buscar nas conversas abertas", f"bold {CYAN}")),
                         id="dlg-title")
            yield Input(placeholder="texto ou nick", id="query", value=self.initial)
            yield OptionList(id="options")
            yield Static(Text("digite para filtrar · ↓ vai aos resultados · Enter abre · Esc fecha · "
                              "só procura no que está na memória deste computador", style=DIM), id="dlg-hint")

    def on_mount(self) -> None:
        self.query_one("#dialog").border_title = "BUSCA LOCAL"
        self.query_one("#query", Input).focus()
        self.refresh_results(self.initial)

    def refresh_results(self, query: str) -> None:
        options = self.query_one("#options", OptionList)
        options.clear_options()
        found = self.search(query) if query.strip() else []
        self.found = found[: self.LIMIT]
        options.add_options([
            Option(Text.assemble((f"{buffer[:16]:<17}", f"bold {PINK}"), (line.plain.strip()[:120], TEXT)), id=str(i))
            for i, (buffer, line) in enumerate(self.found)])
        if query.strip():
            more = " (os mais recentes)" if len(found) > self.LIMIT else ""
            self.query_one("#dlg-hint", Static).update(Text(
                f"{len(found)} resultado(s){more} · ↓ resultados · Enter abre · Esc fecha", style=DIM))

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self.refresh_results(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        if self.found:
            self.dismiss(self.found[0])

    def action_results(self) -> None:
        options = self.query_one("#options", OptionList)
        if self.found and not options.has_focus:
            options.focus()
            options.action_first()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(self.found[int(event.option.id)])

    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------- app

class ChatApp(App):
    ENABLE_COMMAND_PALETTE = False
    TITLE = "crptochat"

    CSS = """
    Screen { background: $cc-bg; color: $cc-text; }
    #topbar { height: 1; background: $cc-panel; }
    #main { height: 1fr; }
    #buffers { width: 24; height: 100%; border: heavy $cc-magenta; border-title-color: $cc-yellow;
               border-title-style: bold; padding: 0 1; background: $cc-bg; }
    #center { border: heavy $cc-cyan; border-title-color: $cc-yellow; border-title-style: bold;
              border-subtitle-color: $cc-dim; background: $cc-bg; }
    #log { background: $cc-bg; padding: 0 1; overflow-x: hidden; scrollbar-size-vertical: 1;
           scrollbar-color: $cc-magenta; scrollbar-background: $cc-bg; }
    #members { width: 26; height: 100%; border: heavy $cc-purple; border-title-color: $cc-yellow;
               border-title-style: bold; padding: 0 1; background: $cc-bg; }
    #transfer { height: 1; padding: 0 2; display: none; background: $cc-panel; }
    #transfer.active { display: block; }
    #inputbar { height: 3; border: heavy $cc-magenta; border-title-color: $cc-cyan;
                border-title-style: bold; background: $cc-bg; }
    #prompt { width: auto; padding: 0 1; }
    #input { border: none; height: 1; padding: 0; background: $cc-bg; color: $cc-text; }
    #input:focus { border: none; }
    #input > .input--cursor { background: $cc-cyan; color: $cc-bg; }
    #input > .input--placeholder { color: $cc-dim; }
    #hints { height: 1; background: $cc-panel; color: $cc-dim; padding: 0 1; }
    ModalScreen { align: center middle; background: $cc-bg 70%; }
    #dialog { max-height: 90%; }
    #options { height: auto; max-height: 24; margin: 1 0 0 0; border: none; background: $cc-panel;
               padding: 0; scrollbar-size-vertical: 1; scrollbar-color: $cc-magenta; }
    #options:focus { border: none; }
    #options > .option-list--option-highlighted { background: $cc-magenta 35%; color: $cc-cyan; text-style: bold; }
    #options > .option-list--option-disabled { color: $cc-purple; }
    #dialog { width: 76; height: auto; border: heavy $cc-magenta; border-title-color: $cc-yellow;
              border-title-style: bold; background: $cc-panel; padding: 1 2; }
    #dialog Input { border: tall $cc-cyan; background: $cc-bg; margin: 1 0 0 0; }
    #dlg-hint { margin: 1 0 0 0; }
    """

    BINDINGS = [
        Binding("ctrl+n", "cycle(1)", priority=True, show=False),
        Binding("ctrl+p", "cycle(-1)", priority=True, show=False),
        Binding("pageup", "scroll(-1)", priority=True, show=False),
        Binding("pagedown", "scroll(1)", priority=True, show=False),
        Binding("ctrl+l", "clear", priority=True, show=False),
        Binding("ctrl+f", "search", priority=True, show=False),
        Binding("ctrl+q", "quit", priority=True, show=False),
        Binding("escape", "menu", show=False),
        Binding("f1", "menu", show=False),
        Binding("f2", "record", priority=True, show=False),
    ]

    def __init__(self, client_factory, autojoin: list[str] | None = None):
        set_palette(load_prefs().get("theme") or themes.DEFAULT)
        super().__init__()
        self._banner: list[Text] = []
        self.client: ChatClient = client_factory(self.engine_event)
        self.autojoin = autojoin or []
        self.buffers: dict[str, Buffer] = {CONSOLE: Buffer(CONSOLE)}
        self.current = CONSOLE
        self.state = "connecting"
        self.fatal: tuple[str, str] | None = None
        self._runner: asyncio.Task | None = None
        self._first_online = True
        self.presence: dict[str, str] = {}
        self.clip_expiry: dict[int, float] = {}
        self._presence_known = False
        self.recorder = Recorder()
        self.player = Player()
        self.clips: dict[int, bytes] = {}   # RAM only, newest 40
        self._clip_seq = 0
        self._rec_target = ""
        self._rec_timer = None
        self.voice_mask = load_prefs().get("voice", "mask") != "natural"
        prefs = load_prefs()
        self.notifier = Notifier(enabled=prefs.get("notify", True) is not False,
                                 preview=prefs.get("notify_preview") is True)
        self.term_focused = True        # terminals that report focus update this
        self.mark = None                # line highlighted by /search

    # ---------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Static(id="topbar")
        with Horizontal(id="main"):
            yield BufferList(id="buffers")
            with Vertical(id="center"):
                yield ChatLog(id="log", wrap=True, markup=False, highlight=False, max_lines=3000, min_width=20)
            yield Static(id="members")
        yield Static(id="transfer")
        with Horizontal(id="inputbar"):
            yield Static(id="prompt")
            yield ChatInput(id="input", placeholder="digite uma mensagem · Esc abre o menu")
        yield Static(id="hints")

    def on_mount(self) -> None:
        self.log_w = self.query_one("#log", RichLog)
        self.input = self.query_one("#input", ChatInput)
        self.query_one("#buffers").border_title = "◢ JANELAS"
        self.query_one("#inputbar").border_title = "◢ TX"
        self._banner = banner()
        for line in self._banner:
            self.buffers[CONSOLE].lines.append(line)
        self.render_hints()
        self.note(f"identidade: {self.client.nick} · fingerprint {self.client.fingerprint}", buffer=CONSOLE)
        self.note("pressione Esc para abrir o menu ou digite /help para ver os comandos", buffer=CONSOLE)
        self.refresh_all(refill=True)
        self.input.focus()
        self._runner = asyncio.create_task(self.client.run())
        self.set_interval(1.0, self.expire_messages)
        self.set_interval(30, lambda: self.run_cmd(self.poll_presence(), quiet=True))

    def on_resize(self) -> None:
        self.render_topbar()

    def get_css_variables(self) -> dict[str, str]:
        variables = super().get_css_variables()
        variables.update({"cc-" + slot.lower(): globals()[slot] for slot in themes.SLOTS})
        return variables

    def apply_theme(self, name: str, save: bool = True) -> None:
        """Switch colours live: CSS, panels and the text already on screen."""
        mapping = set_palette(name)
        self.refresh_css()
        banner_ids = {id(line) for line in self._banner}
        console = self.buffers[CONSOLE].lines
        if banner_ids and len(console) >= len(self._banner) and id(console[0]) in banner_ids:
            fresh = banner()
            for index, line in enumerate(fresh):
                console[index] = line
            self._banner = fresh
            banner_ids = {id(line) for line in fresh}
        for buf in self.buffers.values():
            for line in buf.lines:
                if id(line) not in banner_ids:
                    recolor(line, mapping)
        self.render_hints()
        self.refresh_all(refill=True)
        if save:
            prefs = load_prefs()
            prefs["theme"] = THEME
            save_prefs(prefs)

    async def action_quit(self) -> None:
        await self.recorder.cancel()
        self.player.stop()
        await self.client.close()
        if self._runner:
            self._runner.cancel()
        self.exit(self.fatal)

    # ------------------------------------------------------------- rendering

    def refill(self) -> None:
        self.log_w.clear()
        target = None
        for line in self.buffers[self.current].lines:
            if line is self.mark:
                target = len(self.log_w.lines)
                line = Text.assemble(("▶ ", f"bold {YELLOW}"), line)
                line.stylize(f"on {PURPLE}")
            self.log_w.write(line, scroll_end=target is None)
        if target is not None:
            self.call_after_refresh(lambda: self.log_w.scroll_to(y=max(0, target - 3), animate=False))

    def refresh_all(self, refill: bool = False) -> None:
        self.render_topbar()
        self.render_buffers()
        self.render_members()
        buf = self.buffers[self.current]
        center = self.query_one("#center")
        if buf.kind == "chan":
            ch = self.client.channels.get(buf.name)
            lock = "privado ⊗" if ch and ch.private else "aberto"
            ttl = self.client.ttl_for(buf.name)
            days = self.history_days(buf.name)
            center.border_title = (f"◢ {buf.name} · {lock}" + (f" · ⏱ mensagens somem em {format_duration(ttl)}" if ttl else "")
                                   + (f" · 📜 HISTÓRICO LIGADO ({days} d)" if days else ""))
            center.border_subtitle = ("cifrado ponta a ponta · o servidor guarda o histórico CIFRADO com a senha do canal"
                                      if days else "cifrado ponta a ponta · sem histórico no servidor")
        elif buf.kind == "dm":
            ttl = self.client.ttl_for(buf.name)
            center.border_title = f"◢ {buf.name} · conversa direta" + (
                f" · ⏱ mensagens somem em {format_duration(ttl)}" if ttl else "")
            center.border_subtitle = "cifrado ponta a ponta · sem histórico no servidor"
        else:
            center.border_title = "◢ console"
            center.border_subtitle = ""
        self.query_one("#prompt", Static).update(Text.assemble(
            (self.client.nick, f"bold {CYAN}"), (" → ", DIM), (buf.name, f"bold {PINK}"), (" ❯", f"bold {MAGENTA}")))
        if refill:
            self.refill()

    def render_hints(self) -> None:
        self.query_one("#hints", Static).update(Text.assemble(
            (" Esc", CYAN), " menu  ", ("F2", CYAN), " gravar áudio  ", ("^N ^P", CYAN), " janelas  ",
            ("PgUp PgDn", CYAN), " rolar  ", ("Tab", CYAN), " completar  ", ("/help", CYAN), " comandos  ",
            ("^Q", CYAN), " sair", style=DIM))

    def render_topbar(self) -> None:
        dot, label = {"online": (GREEN, "ONLINE"), "connecting": (YELLOW, "CONECTANDO"),
                      "offline": (MAGENTA, "OFFLINE")}[self.state]
        left = Text.assemble((" ▓▒░ ", MAGENTA), gradient("CRPTOCHAT"), (" ░▒▓ ", MAGENTA),
                             (f" {self.client.server_name or self.client.host}", DIM))
        badges = Text()
        if self.client.guest:
            badges.append("ANÔNIMO  ", style=f"bold {ORANGE}")
        if self.client.role in ("admin", "mod"):
            badges.append("★ ADMIN  " if self.client.role == "admin" else "☆ MOD  ", style=f"bold {ORANGE}")
        if self.client.away:
            badges.append("AUSENTE  ", style=f"bold {YELLOW}")
        right = Text.assemble(badges, ("● ", dot), (label, f"bold {dot}"), ("  ", ""),
                              ("TLS " if self.client.tls else "SEM TLS ", GREEN if self.client.tls else YELLOW),
                              ("· E2EE ", GREEN))
        gap = max(1, self.size.width - left.cell_len - right.cell_len)
        self.query_one("#topbar", Static).update(Text.assemble(left, " " * gap, right))

    def render_buffers(self) -> None:
        widget = self.query_one("#buffers", BufferList)
        out, rows = Text(), []

        def entry(buf: Buffer, label: str) -> None:
            active = buf.name == self.current
            style = f"bold {CYAN}" if active else (f"bold {YELLOW}" if buf.alert else TEXT if buf.unread else DIM)
            out.append("▸ " if active else "  ", style=MAGENTA)
            out.append(label[:16], style=style)
            if buf.unread:
                out.append(f" {buf.unread}", style=f"bold {MAGENTA}")
            out.append("\n")
            rows.append(buf.name)

        def header(title: str) -> None:
            out.append(f"{title}\n", style=f"bold {PURPLE}")
            rows.append(None)

        entry(self.buffers[CONSOLE], "◈ console")
        chans = [b for b in self.buffers.values() if b.kind == "chan"]
        dms = [b for b in self.buffers.values() if b.kind == "dm"]
        if chans:
            header("─ canais ─")
            for buf in chans:
                ch = self.client.channels.get(buf.name)
                entry(buf, buf.name + (" ⊗" if ch and ch.private else ""))
        if dms:
            header("─ diretas ─")
            for buf in dms:
                mark = self.verify_mark(buf.name[1:])[0]
                entry(buf, buf.name + (" " + mark if mark else ""))
        friends = [] if self.client.guest else self.client.store.friends()
        if friends:
            header("─ amigos ─")
            for nick in friends:
                state = self.presence.get(nick.lower())
                mark, colour = {"on": ("● ", GREEN), "away": ("◐ ", YELLOW)}.get(state, ("○ ", DIM))
                out.append("  " + mark, style=colour)
                out.append(nick[:16], style=TEXT if state else DIM)
                vmark, vcolour = self.verify_mark(nick)
                out.append((" " + vmark if vmark else "") + "\n", style=vcolour)
                rows.append("@" + nick)
        widget.rows = rows
        widget.update(out)

    def render_members(self) -> None:
        widget = self.query_one("#members", Static)
        buf = self.buffers[self.current]
        out = Text()
        if buf.kind == "chan":
            ch = self.client.channels.get(buf.name)
            peers = list(ch.members.values()) if ch else []
            widget.border_title = f"◢ ONLINE [{len(peers) + 1 if ch and ch.joined else 0}]"
            people = [(self.client.nick, self.client.key, None)] if ch and ch.joined else []
            people += [(p.nick, p.key, p) for p in peers]
            people.sort(key=lambda item: (-self.client.power(buf.name, item[1]), item[1]))
            for nick, key, peer in people:
                if peer is None:
                    out.append("● ", style=GREEN)
                elif not peer.trusted:
                    out.append("⚠ ", style=MAGENTA)
                elif self.client.store.is_verified(nick):
                    out.append("✓ ", style=GREEN)
                else:
                    out.append("● ", style=DIM)
                out.append(ROLE_MARK.get(ch.roles.get(key), ""), style=f"bold {YELLOW}")
                away = self.client.away if peer is None else peer.away
                if peer is None:
                    style = f"bold {CYAN}"
                elif not peer.trusted:
                    style = MAGENTA
                else:
                    style = DIM if away or peer.guest else nick_color(nick)
                out.append(nick, style=style)
                role = self.client.role if peer is None else peer.role
                if role in ("admin", "mod"):
                    out.append(" ★" if role == "admin" else " ☆", style=ORANGE)
                if away:
                    out.append(" zZ", style=DIM)
                out.append("\n")
            out.append("\n~dono @op +voz ★equipe\n✓ conferido ⚠ chave mudou\nzZ ausente", style=DIM)
        elif buf.kind == "dm":
            widget.border_title = "◢ CONTATO"
            peer = self.client.peers.get(buf.name[1:].lower())
            out.append(buf.name[1:] + "\n", style=f"bold {nick_color(buf.name[1:])}")
            if peer:
                out.append("online\n" if peer.dh else "offline\n", style=GREEN if peer.dh else DIM)
                if peer.pending_ik:
                    out.append("\n⚠ CHAVE MUDOU\n", style=f"bold {MAGENTA}")
                    out.append("mensagens bloqueadas\n", style=MAGENTA)
                    out.append("\nnova fingerprint\n", style=PURPLE)
                    out.append(fp_block(peer.pending_ik) + "\n", style=MAGENTA)
                    out.append("\nconfira e use\n/verify " + peer.nick, style=TEXT)
                else:
                    out.append("\nfingerprint\n", style=PURPLE)
                    out.append(fp_block(peer.ik) + "\n", style=TEXT)
                    verified = self.client.store.is_verified(peer.nick)
                    out.append("\n✓ conferida" if verified else "\nnão conferida\n/verify " + peer.nick,
                               style=GREEN if verified else DIM)
        else:
            widget.border_title = "◢ IDENTIDADE"
            out.append(self.client.nick + "\n", style=f"bold {CYAN}")
            out.append("\nsua fingerprint\n", style=PURPLE)
            out.append(fp_block(self.client.identity.ik) + "\n", style=TEXT)
            out.append("\ncompare por outro canal para confirmar com quem fala", style=DIM)
        widget.update(out)

    # --------------------------------------------------------------- buffers

    def buffer(self, name: str) -> Buffer:
        if name not in self.buffers:
            self.buffers[name] = Buffer(name)
            self.render_buffers()
        return self.buffers[name]

    def switch(self, name: str) -> None:
        if name not in self.buffers:
            return
        self.current = name
        buf = self.buffers[name]
        buf.unread, buf.alert = 0, False
        self.refresh_all(refill=True)
        self.input.focus()

    @property
    def in_dialog(self) -> bool:
        return isinstance(self.screen, ModalScreen)

    def action_cycle(self, step: int) -> None:
        if self.in_dialog:
            return
        names = ([CONSOLE] + [n for n in self.buffers if n.startswith("#")]
                 + [n for n in self.buffers if n.startswith("@")])
        self.switch(names[(names.index(self.current) + step) % len(names)])

    def action_scroll(self, direction: int) -> None:
        if self.in_dialog:
            return
        if direction < 0:
            self.log_w.scroll_page_up(animate=False)
        else:
            self.log_w.scroll_page_down(animate=False)

    def action_clear(self) -> None:
        if self.in_dialog:
            return
        self.buffers[self.current].lines.clear()
        self.refill()

    def add_line(self, name: str | None, line: Text, alert: bool = False, ttl: int = 0) -> None:
        buf = self.buffer(name or self.current)
        buf.lines.append(line)
        if ttl:
            buf.expiry[id(line)] = time.time() + ttl
            line.append(f"  ⏱{format_duration(ttl)}", style=DIM)
        if buf.name == self.current:
            self.log_w.write(line)
        else:
            buf.unread += 1
            buf.alert = buf.alert or alert
            self.render_buffers()

    @staticmethod
    def stamp() -> tuple[str, str]:
        return (time.strftime("%H:%M "), DIM)

    def note(self, text: str, level: str = "info", buffer: str | None = None) -> None:
        color = level_color(level)
        self.add_line(buffer, Text.assemble(self.stamp(), ("        ◈ ", color), (clean(text), color)),
                      alert=level in ("warn", "err"))

    def chat_line(self, name: str, nick: str, text: str, mine: bool, ttl: int = 0) -> None:
        text = clean(text)
        mention = not mine and self.client.nick.lower() in text.lower()
        color = CYAN if mine else nick_color(nick)
        body = Text(text, style=f"bold {YELLOW}" if mention else TEXT)
        line = Text.assemble(self.stamp(), (f"{nick[:14]:>14}", f"bold {color}"), (" ▏", MAGENTA if mine else DIM), body)
        alert = mention or (name.startswith("@") and not mine)
        self.add_line(name, line, alert=alert, ttl=ttl)
        if alert and (name != self.current or mention):
            self.bell()
        if alert:
            self.desktop_notify(name, nick, text, mention)

    def desktop_notify(self, where: str, nick: str, text: str, mention: bool) -> None:
        """Only when you would otherwise miss it: another window, or the terminal is not focused."""
        if where != self.current or not self.term_focused:
            self.notifier.message(where, nick, text, mention)

    def on_app_blur(self, event) -> None:
        self.term_focused = False

    def on_app_focus(self, event) -> None:
        self.term_focused = True

    # ---------------------------------------------------------------- events

    def engine_event(self, kind: str, data: dict) -> None:
        handler = getattr(self, "ev_" + kind, None)
        if handler:
            handler(**data)

    def ev_status(self, state: str, retry: int = 0) -> None:
        previous, self.state = self.state, state
        if state == "offline" and previous == "online":
            self.note("conexão perdida; tentando reconectar…", "warn", CONSOLE)
        elif state == "online":
            self.note(f"conectado a {self.client.server_name} como {self.client.nick}", "ok", CONSOLE)
            if self._first_online:
                self._first_online = False
                if load_prefs().get("update_check", True):
                    self.run_cmd(self.check_update(announce_only=True), quiet=True)
                for chan in self.autojoin:
                    self.run_cmd(self.do_join(chan))
        self.refresh_all()

    def ev_welcome(self, server: str, motd: str) -> None:
        if motd:
            self.note(f"MOTD: {motd}", "info", CONSOLE)

    def ev_fatal(self, code: str, text: str) -> None:
        self.fatal = (code, text)
        self.state = "offline"
        self.note(text, "err", CONSOLE)
        self.note("pressione Ctrl+Q para sair", "warn", CONSOLE)
        self.switch(CONSOLE)

    def ev_system(self, text: str, level: str = "info", buffer: str | None = None) -> None:
        self.note(text, level, buffer)

    def history_days(self, chan: str) -> int:
        ch = self.client.channels.get(chan)
        return int(ch.policy.get("history") or 0) if ch and self.client.history_on(ch) else 0

    def history_warning(self, chan: str) -> None:
        days = self.history_days(chan)
        if days:
            self.note(f"📜 HISTÓRICO LIGADO em {chan}: o servidor guarda as mensagens por até {days} dias, cifradas "
                      "com a senha do canal. Quem souber a senha (agora ou depois) lê tudo o que ainda estiver guardado.",
                      "warn", chan)

    def ev_joined(self, chan: str, private: bool) -> None:
        fresh = chan not in self.buffers
        self.buffer(chan)
        kind = "privado (chave derivada da senha)" if private else "aberto"
        past = ("histórico cifrado ligado" if self.history_days(chan)
                else "mensagens anteriores não são recuperáveis")
        self.note(f"você entrou em {chan} · canal {kind} · {past}", "ok", chan)
        self.history_warning(chan)
        if fresh:
            self.switch(chan)
        else:
            self.refresh_all()

    def ev_left(self, chan: str) -> None:
        self.buffers.pop(chan, None)
        if self.current == chan:
            self.switch(CONSOLE)
        else:
            self.render_buffers()

    def ev_members(self, chan: str) -> None:
        if chan == self.current:
            self.render_members()

    def ev_member_join(self, chan: str, nick: str, trusted: bool) -> None:
        self.add_line(chan, Text.assemble(self.stamp(), ("        → ", GREEN), (nick, nick_color(nick)),
                                          (" entrou", DIM)))

    def ev_member_leave(self, chan: str, nick: str, kicked: str | None = None) -> None:
        how = f" foi expulso por {kicked}" if kicked else " saiu"
        self.add_line(chan, Text.assemble(self.stamp(), ("        ← ", MAGENTA), (nick, nick_color(nick)),
                                          (how + " · chaves do canal renovadas", DIM)))

    def ev_chan_role(self, chan: str, nick: str, role: str | None, by: str) -> None:
        self.add_line(chan, Text.assemble(self.stamp(), ("        ◆ ", YELLOW), (nick, nick_color(nick)),
                                          (f" agora é {ROLE_NAME.get(role, role)}", TEXT), (f" · por {by}", DIM)))

    def ev_kicked_from(self, chan: str, by: str, banned: bool, reason: str = "") -> None:
        self.buffers.pop(chan, None)
        if self.current == chan:
            self.switch(CONSOLE)
        else:
            self.render_buffers()
        self.note(f"você foi {'banido' if banned else 'expulso'} de {chan} por {by}" + (f": {reason}" if reason else ""),
                  "err", CONSOLE)

    def ev_history(self, chan: str, entries: list) -> None:
        """Lines stored by the server (encrypted with the channel password),
        shown apart from the live conversation and with the signature check."""
        self.add_line(chan, Text(f"──────── histórico guardado (cifrado) · {len(entries)} mensagens ────────", style=DIM))
        now = time.time()
        for e in entries:
            nick = clean(e["nick"])
            mark = ("✓ ", GREEN) if e["verified"] else ("⚠ assinatura não confere com a chave conhecida · ", f"bold {ORANGE}")
            line = Text.assemble((time.strftime("%d/%m %H:%M ", time.localtime(e["ts"])), DIM),
                                 (f"{nick[:14]:>14}", nick_color(nick)), (" ┆ ", DIM), mark,
                                 (clean(e["text"]), TEXT if e["verified"] else DIM))
            left = int(e.get("expires") or 0) - now
            self.add_line(chan, line, ttl=int(left) if 0 < left < 400 * 86400 else 0)
        self.add_line(chan, Text("──────── fim do histórico · daqui pra baixo é ao vivo ────────", style=DIM))

    def ev_policy(self, chan: str, policy: dict, changed: dict, by: str) -> None:
        for name, value in changed.items():
            label = POLICIES.get(name, (name,))[0]
            self.note(f"política do canal · {label}: {self._policy_state(value, name)} · por {by}", "warn", chan)
        if "history" in changed:
            if changed["history"]:
                self.history_warning(chan)
            else:
                self.note("histórico desligado: o servidor apagou o que estava guardado deste canal", "ok", chan)
        if chan == self.current:
            self.refresh_all()

    def ev_notice(self, text: str) -> None:
        line = Text.assemble(self.stamp(), ("        ▓▒░ AVISO DO SERVIDOR ░▒▓ ", f"bold {ORANGE}"),
                             (clean(text), f"bold {TEXT}"))
        self.add_line(CONSOLE, line, alert=True)
        if self.current != CONSOLE:
            self.add_line(None, line.copy())
        self.bell()

    def ev_ratelimit(self, action: str, seconds: int, text: str) -> None:
        if action == "mute":
            self.note(f"⛔ {text or f'você foi silenciado por {seconds}s por flood'}", "err")
            self.bell()
        else:
            self.note(f"⚠ {text or 'você está enviando rápido demais'}", "warn")

    def ev_client_repo(self, repo: str | None) -> None:
        self._suggest_repo(repo)

    def ev_key_changed(self, nick: str, old: bytes, new: bytes) -> None:
        lines = [
            Text.assemble(self.stamp(), ("        ▓▒░ ALERTA DE SEGURANÇA ░▒▓ ", f"bold {MAGENTA}"),
                          (f"a chave de identidade de {nick} MUDOU", f"bold {MAGENTA}")),
            Text.assemble(("               ", ""), ("chave conhecida  ", DIM), (crypto.fingerprint(old), TEXT)),
            Text.assemble(("               ", ""), ("chave nova       ", DIM), (crypto.fingerprint(new), f"bold {MAGENTA}")),
            Text.assemble(("               ", ""), (
                f"Pode ser só uma reinstalação, ou o servidor tentando se passar por {nick}. Mensagens diretas "
                f"estão bloqueadas nos dois sentidos. Confirme com {nick} por outro meio e use /verify {nick}.", YELLOW)),
        ]
        targets = {CONSOLE, self.current}
        if "@" + nick in self.buffers:
            targets.add("@" + nick)
        for target in targets:
            for line in lines:
                self.add_line(target, line.copy(), alert=True)
        self.bell()
        self.refresh_all()

    def ev_invited(self, chan: str, by: str) -> None:
        self.note(f"{by} convidou você para {chan}: digite /join {chan}", "ok")
        self.bell()

    def ev_role(self, role: str) -> None:
        text = {"admin": "você agora é ADMIN deste servidor", "mod": "você agora é MODERADOR deste servidor"}.get(
            role, "você não faz mais parte da equipe do servidor")
        self.note(text, "warn", CONSOLE)
        self.refresh_all()

    def ev_message(self, buffer: str, nick: str, text: str, mine: bool, ttl: int = 0) -> None:
        self.chat_line(buffer, nick, text, mine, ttl=ttl)

    def ev_audio(self, buffer: str, nick: str, data: bytes, seconds: float, mine: bool, ttl: int = 0) -> None:
        if not sniff(data):
            return
        self._clip_seq += 1
        number = self._clip_seq
        self.clips[number] = data
        for old in list(self.clips)[:-40]:
            del self.clips[old]
        color = CYAN if mine else nick_color(nick)
        length = f"{int(seconds) // 60}:{int(seconds) % 60:02d}"
        wave = "▂▅▇▃▆▂▇▅▃▆▂▄"[: 4 + min(8, int(seconds) // 3)]
        line = Text.assemble(self.stamp(), (f"{nick[:14]:>14}", f"bold {color}"), (" ▏", MAGENTA if mine else DIM),
                             ("▶ ", f"bold {GREEN}"), (wave, PINK), (f" áudio {length}", f"bold {TEXT}"),
                             (f"  {human_size(len(data))}  ", DIM), (f"/play {number}", CYAN))
        alert = buffer.startswith("@") and not mine
        self.add_line(buffer, line, alert=alert, ttl=ttl)
        if ttl:
            self.clip_expiry[number] = time.time() + ttl
        if alert and buffer != self.current:
            self.bell()
        if alert:
            self.desktop_notify(buffer, nick, f"mensagem de voz ({length})", False)

    def ev_file_offer(self, id: str, nick: str, name: str, size: int, buffer: str | None = None,
                      ttl: int = 0, relay: bool = False) -> None:
        if relay:
            line = Text.assemble(self.stamp(), ("        ▼ ", f"bold {CYAN}"), (nick, nick_color(nick)),
                                 (" quer enviar ", TEXT), (f"'{clean(name)}'", f"bold {TEXT}"),
                                 (f" ({human_size(size)}) pelo servidor, cifrado · ", DIM),
                                 (f"/accept {id}", CYAN), (" ou ", DIM), (f"/reject {id}", CYAN))
            self.add_line(buffer, line, alert=True, ttl=ttl)
        self.bell()

    def ev_transfer(self, id: str, name: str, nick: str, done: int, total: int, outgoing: bool, state: str) -> None:
        widget = self.query_one("#transfer", Static)
        if state != "active":
            widget.remove_class("active")
            return
        frac = done / total if total else 1.0
        width = 28
        filled = round(frac * width)
        widget.update(Text.assemble(
            ("▲ " if outgoing else "▼ ", CYAN), (f"{clean(name)[:30]} ", TEXT), ("▰" * filled, MAGENTA),
            ("▱" * (width - filled), DIM), (f" {frac * 100:5.1f}%  {human_size(done)}/{human_size(total)}", CYAN),
            (f"  p2p ↔ {nick}", DIM)))
        widget.add_class("active")

    # -------------------------------------------------------------- commands

    def completions(self, word: str, first: bool) -> list[str]:
        low = word.lower()
        if word.startswith("/"):
            return [c + " " for c in COMMANDS if c.startswith(low)]
        if word.startswith("#"):
            return [n + " " for n in self.buffers if n.startswith(low)]
        nicks = {p.nick for p in self.client.peers.values()}
        ch = self.client.channels.get(self.current)
        if ch:
            nicks = {p.nick for p in ch.members.values()} | nicks
        return [n + (": " if first else " ") for n in sorted(nicks, key=str.lower) if n.lower().startswith(low)]

    def run_cmd(self, coro, quiet: bool = False) -> None:
        async def wrapper():
            try:
                await coro
            except ChatError as exc:
                if not quiet:
                    self.note(str(exc), "err")
            except AudioError as exc:
                self.note(str(exc), "err")
            except (OSError, crypto.CryptoError) as exc:
                self.note(f"erro: {exc}", "err")
        task = asyncio.create_task(wrapper())
        self._bg = getattr(self, "_bg", set())
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        line = event.value.strip()
        event.input.value = ""
        if not line:
            if self.recorder.active:
                self.run_cmd(self.finish_recording())
            return
        self.input.remember(line)
        self.execute(line)

    def execute(self, line: str) -> None:
        """Run a command line or send it as a message to the current window."""
        if line.startswith("/") and not line.startswith("//"):
            cmd, _, rest = line.partition(" ")
            handler = getattr(self, "cmd_" + cmd[1:].lower(), None)
            if handler is None:
                self.note(f"comando desconhecido: {cmd} (veja /help)", "err")
                return
            try:
                result = handler(rest.strip())
            except ChatError as exc:
                self.note(str(exc), "err")
                return
            if asyncio.iscoroutine(result):
                self.run_cmd(result)
            return
        if line.startswith("//"):
            line = line[1:]
        buf = self.buffers[self.current]
        try:
            if buf.kind == "chan":
                self.client.send_message(buf.name, line)
            elif buf.kind == "dm":
                self.run_cmd(self.client.send_dm(buf.name[1:], line))
            else:
                self.note("isto é o console: pressione Esc para abrir o menu ou entre em um canal com /join #lobby", "warn")
        except ChatError as exc:
            self.note(str(exc), "err")

    # ------------------------------------------------------------------ menu

    async def ask(self, screen):
        """Show a dialog and wait for its result (None when cancelled)."""
        fut = asyncio.get_running_loop().create_future()
        self.push_screen(screen, lambda value: fut.done() or fut.set_result(value))
        try:
            return await fut
        finally:
            if not self.in_dialog:
                self.input.focus()

    async def ask_text(self, title: str, placeholder: str, validate=None, initial: str = "") -> str | None:
        values = await self.ask(FormScreen(title, [placeholder], validate, initial=initial))
        return values[0] if values else None

    def action_menu(self) -> None:
        if self.recorder.active:        # Esc while recording cancels it
            self.run_cmd(self.cancel_recording())
            return
        if not self.in_dialog:
            self.run_cmd(self.menu_flow())

    def cmd_menu(self, _):
        self.action_menu()

    async def menu_flow(self) -> None:
        choice = await self.ask(ChoiceScreen("", MENU))
        if choice:
            await getattr(self, "menu_" + choice)()

    async def pick_nick(self, title: str) -> str | None:
        nicks = sorted((p.nick for p in self.client.peers.values() if p.trusted), key=str.lower)
        current = self.current[1:] if self.current.startswith("@") else None
        if current and current in nicks:
            nicks.remove(current)
            nicks.insert(0, current)
        if nicks:
            items = [(n, n, "✓ conferido" if self.client.store.is_verified(n) else "") for n in nicks]
            items.append((CUSTOM, "✎ digitar outro nick…", ""))
            choice = await self.ask(ChoiceScreen(title, [(None, items)], heading="USUÁRIOS"))
            if choice != CUSTOM:
                return choice
        return await self.ask_text(title, "nickname", lambda v: None if valid_nick(v[0]) else "nickname inválido")

    @staticmethod
    def _chan_name(value: str) -> str:
        value = value.lower()
        return value if value.startswith("#") else "#" + value

    def _chan_check(self, values) -> str | None:
        return None if valid_chan(self._chan_name(values[0])) else "use letras minúsculas, números, _ e - (até 32)"

    async def menu_join(self) -> None:
        chans = await self.client.list_channels()
        items = []
        for ch in chans:
            joined = ch["name"] in self.client.channels
            detail = f"{'privado ⊗' if ch['private'] else 'aberto'} · {ch['members']} online" + (" · você está aqui" if joined else "")
            items.append((ch["name"], ch["name"], detail))
        items.append((CUSTOM, "✎ digitar o nome…", "canais privados não aparecem na lista"))
        choice = await self.ask(ChoiceScreen("entrar em qual canal?", [(None, items)], heading="CANAIS"))
        if choice == CUSTOM:
            choice = await self.ask_text("nome do canal", "#canal", self._chan_check)
        if choice:
            self.execute("/join " + self._chan_name(choice))

    async def menu_create(self, private: bool = False) -> None:
        kind = "privado" if private else "aberto"
        name = await self.ask_text(f"nome do novo canal {kind}", "#canal", self._chan_check)
        if name:
            self.execute(f"/create {self._chan_name(name)}" + (" privado" if private else ""))

    async def menu_create_priv(self) -> None:
        await self.menu_create(True)

    async def menu_leave(self) -> None:
        self.execute("/leave")

    async def menu_dm(self) -> None:
        nick = await self.pick_nick("conversar com quem?")
        if nick:
            self.execute("/query " + nick)

    async def menu_send(self) -> None:
        if self.buffers[self.current].kind == "chan":
            target = self.current
        else:
            target = await self.pick_nick("enviar arquivo para quem?")
            if not target:
                return
        path = await self.ask_text(
            f"arquivo para {target}", "/caminho/do/arquivo",
            lambda v: None if os.path.isfile(os.path.expanduser(v[0])) else "arquivo não encontrado")
        if not path:
            return
        mode = "relay"
        if not target.startswith("#"):
            mode = await self.ask(ChoiceScreen(f"como enviar para {target}?", [(None, [
                ("relay", "Pelo servidor (recomendado)", "cifrado de ponta a ponta; ninguém vê seu IP"),
                ("p2p", "Direto, P2P", "mais rápido em rede local, mas EXPÕE SEU IP ao outro lado"),
            ])], heading="ENVIAR ARQUIVO"))
            if not mode:
                return
        self.execute(f"/send {target} {shlex.quote(path)}" + (" --p2p" if mode == "p2p" else ""))

    # ----------------------------------------------------------------- audio

    def _rec_tick(self) -> None:
        widget = self.query_one("#transfer", Static)
        if not self.recorder.active:
            return
        secs = int(self.recorder.elapsed)
        if secs >= 88:
            self.run_cmd(self.finish_recording())
            return
        pulse = "●" if secs % 2 == 0 else "○"
        widget.update(Text.assemble(
            (f"{pulse} REC ", f"bold {MAGENTA}"), (f"{secs // 60}:{secs % 60:02d}", f"bold {TEXT}"),
            (f"  → {self._rec_target}  ", PINK),
            ("voz mascarada · " if self.voice_mask else "VOZ NATURAL · ", GREEN if self.voice_mask else YELLOW), ("Enter", CYAN), (" ou ", DIM), ("F2", CYAN), (" envia · ", DIM),
            ("Esc", CYAN), (" cancela · máx. 1:30", DIM)))
        widget.add_class("active")

    def _rec_done(self) -> None:
        if self._rec_timer:
            self._rec_timer.stop()
            self._rec_timer = None
        self.query_one("#transfer", Static).remove_class("active")

    async def start_recording(self) -> None:
        if self.buffers[self.current].kind == "sys":
            raise ChatError("abra um canal ou uma conversa direta antes de gravar")
        if self.voice_mask and not audio.can_mask():
            raise ChatError("a proteção de voz precisa do ffmpeg instalado; instale-o ou use "
                            "/voice natural (expõe a sua voz verdadeira)")
        try:
            await self.recorder.start()
        except AudioError as exc:
            raise ChatError(str(exc)) from None
        self._rec_target = self.current
        self._rec_tick()
        self._rec_timer = self.set_interval(0.5, self._rec_tick)

    async def finish_recording(self) -> None:
        if not self.recorder.active:
            return
        self._rec_done()
        target = self._rec_target
        try:
            data, _, seconds = await self.recorder.stop()
        except AudioError as exc:
            raise ChatError(str(exc)) from None
        if seconds < 0.5:
            raise ChatError("gravação curta demais; descartada")
        try:
            data = await audio.process(data, self.voice_mask)
        except AudioError as exc:
            raise ChatError(str(exc)) from None
        await self.client.send_audio(target, data, seconds)

    async def cancel_recording(self) -> None:
        if self.recorder.active:
            self._rec_done()
            await self.recorder.cancel()
            self.note("gravação descartada", "warn")

    def action_record(self) -> None:
        if not self.in_dialog:
            self.run_cmd(self.finish_recording() if self.recorder.active else self.start_recording())

    def cmd_rec(self, rest: str):
        if rest.lower() in ("cancel", "cancelar", "x"):
            return self.cancel_recording()
        return self.finish_recording() if self.recorder.active else self.start_recording()

    def set_voice(self, mask: bool) -> None:
        self.voice_mask = mask
        prefs = load_prefs()
        prefs["voice"] = "mask" if mask else "natural"
        save_prefs(prefs)
        if mask:
            self.note("proteção de voz ATIVADA: seus áudios saem com tom robótico e sem metadados", "ok")
            if not audio.can_mask():
                self.note("o ffmpeg não está instalado: você não conseguirá enviar áudio até instalá-lo", "warn")
        else:
            self.note("proteção de voz DESATIVADA: quem ouvir pode reconhecer a sua voz", "warn")

    def cmd_voice(self, rest: str):
        choice = rest.lower()
        if choice in ("mascarada", "mask", "on", "robo", "robô"):
            self.set_voice(True)
        elif choice in ("natural", "off"):
            self.set_voice(False)
        elif choice and self.buffers[self.current].kind == "chan":
            # IRC-style: /voice nick gives someone voice in the channel
            return self._role(rest, "voice", "/voice nick")
        else:
            self.note(f"proteção de voz: {'mascarada' if self.voice_mask else 'natural'} "
                      "· uso: /voice mascarada | /voice natural · num canal, /voice nick dá voz")

    async def menu_voice(self) -> None:
        now = "mascarada" if self.voice_mask else "natural"
        choice = await self.ask(ChoiceScreen(f"proteção de voz · atual: {now}", [(None, [
            ("mask", "Mascarada (recomendado)", "tom robótico, sem a sua entonação"),
            ("natural", "Natural", "quem ouvir pode reconhecer você"),
        ])], heading="ÁUDIO"))
        if choice:
            self.set_voice(choice == "mask")

    async def cmd_play(self, rest: str):
        if not self.clips:
            raise ChatError("nenhum áudio recebido nesta sessão")
        try:
            number = int(rest) if rest else max(self.clips)
            data = self.clips[number]
        except (ValueError, KeyError):
            raise ChatError("áudio não encontrado (já saiu da memória?) · uso: /play [número]") from None
        self.note(f"▶ tocando áudio {number} (/stop interrompe)")
        try:
            await self.player.play(data)
        except AudioError as exc:
            raise ChatError(str(exc)) from None

    def cmd_stop(self, _):
        self.player.stop()

    async def menu_rec(self) -> None:
        await self.start_recording()

    async def menu_play(self) -> None:
        if not self.clips:
            raise ChatError("nenhum áudio recebido nesta sessão")
        items = [(str(n), f"áudio {n}", human_size(len(d))) for n, d in reversed(self.clips.items())]
        choice = await self.ask(ChoiceScreen("qual áudio?", [(None, items)], heading="ÁUDIO"))
        if choice:
            await self.cmd_play(choice)

    async def menu_files(self) -> None:
        relay = self.client.relay.pending()
        p2p = [t for t in self.client.files.transfers.values() if not t.outgoing and t.state == "offered"]
        if not relay and not p2p:
            self.note("nenhuma oferta de arquivo pendente", "warn")
            return
        items = [(t.id, clean(t.name)[:30], f"{human_size(t.size)} · de {t.peer.nick} · pelo servidor") for t in relay]
        items += [(t.id.hex(), clean(t.name)[:30], f"{human_size(t.size)} · de {t.peer.nick} · P2P") for t in p2p]
        tid = await self.ask(ChoiceScreen("ofertas de arquivo recebidas", [(None, items)], heading="ARQUIVOS"))
        if not tid:
            return
        is_p2p = any(t.id.hex() == tid for t in p2p)
        action = await self.ask(ChoiceScreen("o que fazer com este arquivo?", [(None, [
            ("accept", "Aceitar e baixar",
             "conexão direta: revela seu IP ao remetente" if is_p2p else "pelo servidor, cifrado; você escolhe a pasta"),
            ("reject", "Recusar", ""),
        ])], heading="ARQUIVOS"))
        if action:
            self.execute(f"/{action} {tid[:12]}")

    async def menu_fp(self) -> None:
        self.execute("/fp")

    async def menu_who(self) -> None:
        self.execute("/who")

    async def menu_verify(self) -> None:
        nick = await self.pick_nick("conferir a chave de quem?")
        if nick:
            await self.cmd_verify(nick)

    @staticmethod
    def _mounts() -> list[str]:
        try:
            user = getpass.getuser()
        except Exception:
            user = ""
        found = []
        for base in (f"/media/{user}", f"/run/media/{user}", "/media", "/mnt"):
            try:
                entries = sorted(os.listdir(base))
            except OSError:
                continue
            for name in entries:
                path = os.path.join(base, name)
                if os.path.isdir(path) and os.access(path, os.W_OK) and path not in found \
                        and path not in (f"/media/{user}",):
                    found.append(path)
        return found[:12]

    async def menu_movekey(self) -> None:
        ident = self.client.identity
        src_dir = os.path.dirname(ident.file) if ident.file else None
        if not ident.source and not (ident.file and os.path.exists(ident.file)):
            raise ChatError("arquivo da chave não está acessível agora (reconecte o dispositivo onde ele fica)")
        current_vault = ident.source.get("vault") if ident.source else None
        folders = [(m, m, "") for m in self._mounts() if os.path.abspath(m) != src_dir]
        folders.append((CUSTOM, "✎ digitar uma pasta…", ""))
        vaults = [("vault:" + name, vault.PRESETS[name]["label"], "")
                  for name in vault.available() if name != current_vault]
        groups = [("PASTA OU PENDRIVE", folders)]
        if vaults:
            groups.append(("COFRE DE SENHAS", vaults))
        dest = await self.ask(ChoiceScreen(f"chave atual: {ident.location}", groups, heading="CHAVE DO NICK"))
        if dest == CUSTOM:
            dest = await self.ask_text(
                "pasta de destino da chave", "/media/voce/PENDRIVE",
                lambda v: None if os.path.isdir(os.path.expanduser(v[0])) else "pasta não encontrada (está montada?)")
        if not dest:
            return
        dest_dir = dest_source = None
        if dest.startswith("vault:"):
            dest_source = vault.parse(dest)
            target = vault.describe(dest_source)
        else:
            dest_dir = target = os.path.abspath(os.path.expanduser(dest))
            if not ident.source and dest_dir == src_dir:
                raise ChatError("a chave já está nessa pasta")
        confirm = await self.ask(ChoiceScreen(f"mover a chave de {ident.nick} para {target}?", [(None, [
            ("yes", "Mover", "a cópia é conferida e só então a original é apagada"),
            ("no", "Cancelar", ""),
        ])], heading="CHAVE DO NICK"))
        if confirm != "yes":
            return

        def move():
            return Identity.relocate(ident.nick, src_dir, ident.source, dest_dir, dest_source)

        try:
            if dest_source or ident.source:
                # The vault tool may need to ask for a master password or GPG
                # PIN: hand the terminal back to it while it runs.
                try:
                    with self.suspend():
                        new_file = move()
                except SuspendNotSupported:
                    new_file = move()
            else:
                new_file = move()
        except FileExistsError:
            raise ChatError("já existe uma chave desse nick no destino") from None
        except (OSError, ValueError) as exc:
            raise ChatError(f"não foi possível mover a chave: {exc}") from None
        ident.file, ident.source = new_file, dest_source
        prefs = load_prefs()
        prefs.setdefault("key_dirs", {}).pop(ident.nick.lower(), None)
        prefs.setdefault("key_sources", {}).pop(ident.nick.lower(), None)
        if dest_source:
            prefs["key_sources"][ident.nick.lower()] = dest_source
        else:
            prefs["key_dirs"][ident.nick.lower()] = dest_dir
        save_prefs(prefs)
        self.note(f"chave movida para {ident.location}", "ok")
        if dest_source:
            self.note("nas próximas vezes o cofre precisa estar desbloqueado ao abrir o crptochat; "
                      "a senha da identidade continua sendo pedida", "info")
        else:
            self.note("nas próximas vezes conecte esse dispositivo antes de abrir o crptochat; "
                      "agora ele já pode ser removido (a chave está na memória)", "info")

    async def menu_help(self) -> None:
        self.execute("/help")

    async def menu_clear(self) -> None:
        self.action_clear()

    async def menu_quit(self) -> None:
        await self.action_quit()

    # ------------------------------------------------- roles and moderation

    def _chan(self) -> str:
        if self.buffers[self.current].kind != "chan":
            raise ChatError("use este comando dentro de um canal")
        return self.current

    @staticmethod
    def _nick(rest: str, usage: str) -> str:
        nick = rest.split()[0] if rest.split() else ""
        if not valid_nick(nick):
            raise ChatError("uso: " + usage)
        return nick

    async def _role(self, rest: str, role: str | None, usage: str) -> None:
        await self.client.set_role(self._chan(), self._nick(rest, usage), role)

    def cmd_op(self, rest):
        return self._role(rest, "op", "/op nick")

    def cmd_deop(self, rest):
        return self._role(rest, None, "/deop nick")

    def cmd_devoice(self, rest):
        return self._role(rest, None, "/devoice nick")

    def cmd_owner(self, rest):
        return self._role(rest, "owner", "/owner nick (transfere o canal)")

    async def cmd_kick(self, rest: str):
        await self.client.kick(self._chan(), self._nick(rest, "/kick nick"))

    async def cmd_ban(self, rest: str):
        reply = await self.client.chan_ban(self._chan(), self._nick(rest, "/ban nick"))
        self.note(f"{reply['nick']} banido de {self.current}", "ok")

    async def cmd_unban(self, rest: str):
        reply = await self.client.chan_ban(self._chan(), self._nick(rest, "/unban nick"), on=False)
        self.note(f"{reply['nick']} pode voltar a {self.current}", "ok")

    async def cmd_bans(self, _):
        bans = await self.client.chan_bans(self._chan())
        self.note(f"banidos de {self.current}: " + (", ".join(bans) if bans else "ninguém"), "ok")

    async def cmd_roles(self, _):
        roles = await self.client.chan_roles(self._chan())
        self.note(f"cargos em {self.current}:", "ok")
        for nick, role in roles:
            label = ROLE_NAME.get(role, "convidado")
            self.add_line(None, Text.assemble(("               ", ""), (f"{label:<16}", YELLOW), (nick, nick_color(nick))))

    async def cmd_invite(self, rest: str):
        reply = await self.client.invite(self._chan(), self._nick(rest, "/invite nick"))
        self.note(f"{reply['nick']} convidado para {self.current}"
                  + ("" if reply.get("online") else " (está offline; poderá entrar quando voltar)"), "ok")

    @staticmethod
    def _policy_state(value, name: str = "") -> str:
        if isinstance(value, bool):
            return "ligado" if value else "desligado"
        if name == "ttl" and value:
            return format_duration(value)
        if name == "history" and value:
            return f"{value} dias"
        return str(value) if value else "desligado"

    def _show_policy(self, chan: str) -> None:
        policy = self.client.channels[chan].policy
        self.note(f"políticas de {chan} (operadores mudam com /policy nome valor):", "ok")
        for name, (label, desc) in POLICIES.items():
            value = policy.get(name)
            self.add_line(None, Text.assemble(("               ", ""), (f"{name:<10}", CYAN),
                                              (f"{self._policy_state(value, name):<10}", GREEN if value else DIM),
                                              (f"{label}: {desc}", TEXT)))

    async def cmd_policy(self, rest: str):
        chan = self._chan()
        parts = rest.split()
        if not parts:
            self._show_policy(chan)
            return
        name = parts[0].lower()
        if name not in POLICIES or len(parts) < 2:
            raise ChatError("uso: /policy nome valor · nomes: " + ", ".join(POLICIES) + " · valor: on, off ou número")
        raw = parts[1].lower()
        if name == "ttl":
            try:
                value = parse_duration(raw)
            except ValueError:
                raise ChatError("uso: /policy ttl 1h (30s, 10m, 1h, 7d, até 30d; off desliga)") from None
            await self.client.set_channel_ttl(chan, value)
            return
        if name in ("slow", "limit"):
            if raw in ("off", "não", "nao"):
                raw = "0"
            if not raw.isdigit():
                raise ChatError(f"/policy {name} precisa de um número (0 desliga)")
            value = int(raw)
        else:
            value = raw in ("on", "sim", "1", "true", "ligar")
        await self.client.set_policy(chan, **{name: value})

    async def cmd_gkick(self, rest: str):
        reply = await self.client.server_kick(self._nick(rest, "/gkick nick"))
        self.note(f"{reply['nick']} desconectado do servidor", "ok")

    async def cmd_gban(self, rest: str):
        nick = self._nick(rest, "/gban nick [30m|12h|7d] [--ip] [motivo]")
        parts = rest.split()[1:]
        ip = "--ip" in parts
        parts = [p for p in parts if p != "--ip"]
        minutes = 0
        if parts and re.fullmatch(r"\d+[mhd]", parts[0].lower()):
            token = parts.pop(0).lower()
            minutes = int(token[:-1]) * {"m": 1, "h": 60, "d": 1440}[token[-1]]
        reply = await self.client.server_ban(nick, minutes, " ".join(parts), ip)
        self.note(f"{reply['nick']} banido do servidor" + (" (com o endereço)" if reply.get("ip") else ""), "ok")

    async def cmd_gunban(self, rest: str):
        reply = await self.client.server_unban(self._nick(rest, "/gunban nick"))
        self.note(f"{reply['nick']} desbanido do servidor", "ok")

    async def menu_mod(self) -> None:
        chan = self._chan()
        ch = self.client.channels[chan]
        mine = self.client.power(chan)
        if mine < 2:
            raise ChatError("só operadores (@) e o dono (~) do canal podem moderar")
        people = sorted(ch.members.values(), key=lambda p: p.key)
        if not people:
            raise ChatError("não há mais ninguém no canal")
        items = [(p.nick, ROLE_MARK.get(ch.roles.get(p.key), "") + p.nick,
                  "anônimo" if p.guest else ROLE_NAME.get(ch.roles.get(p.key), "")) for p in people]
        nick = await self.ask(ChoiceScreen(f"moderar quem em {chan}?", [(None, items)], heading="MODERAÇÃO"))
        if not nick:
            return
        role = ch.roles.get(nick.lower())
        guest = ch.members[nick.lower()].guest
        actions = []
        if not guest:
            actions.append(("devoice", "Tirar a voz", "") if role == "voice"
                           else ("voice", "Dar voz (+)", "pode falar em canal moderado"))
            if mine >= 3:
                actions.append(("deop", "Remover operador", "") if role == "op"
                               else ("op", "Tornar operador (@)", "pode expulsar, banir e mudar políticas"))
                actions.append(("owner", "Transferir o canal", "você passa a ser operador"))
        actions += [("kick", "Expulsar", "pode voltar a entrar"), ("ban", "Banir do canal", "não entra mais")]
        action = await self.ask(ChoiceScreen(f"{nick} em {chan}", [(None, actions)], heading="MODERAÇÃO"))
        if action:
            self.execute(f"/{action} {nick}")

    async def menu_policy(self) -> None:
        chan = self._chan()
        policy = self.client.channels[chan].policy
        can = self.client.power(chan) >= 2
        items = [(name, f"{label}: {self._policy_state(policy.get(name), name).upper() if policy.get(name) else 'desligado'}", desc)
                 for name, (label, desc) in POLICIES.items()]
        hint = "Enter altera · Esc fecha" if can else "somente leitura: só operadores mudam políticas · Esc fecha"
        name = await self.ask(ChoiceScreen(f"políticas de {chan}", [(None, items)], heading="POLÍTICAS", hint=hint))
        if not name:
            return
        if not can:
            raise ChatError("só operadores (@) e o dono (~) mudam as políticas do canal")
        if name == "ttl":
            value = await self.ask_text("as mensagens somem depois de quanto tempo?", "ex.: 30m, 1h, 7d (off desliga)",
                                        lambda v: None if self._duration_ok(v[0]) else "use 30s, 10m, 1h, 7d ou off")
            if value is not None:
                self.execute(f"/mode {self.current} {'-t' if parse_duration(value) == 0 else '+t ' + value}")
        elif name in ("slow", "limit"):
            value = await self.ask_text(POLICIES[name][1], "número (0 desliga)",
                                        lambda v: None if v[0].isdigit() else "digite um número")
            if value is not None:
                self.execute(f"/policy {name} {value}")
        else:
            self.execute(f"/policy {name} {'off' if policy.get(name) else 'on'}")

    async def menu_invite(self) -> None:
        self._chan()
        nick = await self.pick_nick("convidar quem?")
        if nick:
            self.execute("/invite " + nick)

    async def menu_staff(self) -> None:
        if self.client.role not in ("admin", "mod"):
            raise ChatError("só a equipe do servidor (admins e moderadores) usa esta opção")
        nick = await self.pick_nick("agir sobre quem?")
        if not nick:
            return
        action = await self.ask(ChoiceScreen(f"{nick} no servidor", [(None, [
            ("gkick", "Desconectar", "pode voltar a entrar"),
            ("gban 1d", "Banir por 1 dia", ""),
            ("gban 7d", "Banir por 7 dias", ""),
            ("gban", "Banir para sempre", ""),
            ("gban --ip", "Banir para sempre, com o endereço", "bloqueia também novas contas e anônimos dali"),
            ("gunban", "Remover banimento", ""),
        ])], heading="MODERAÇÃO DO SERVIDOR"))
        if action:
            verb, _, extra = action.partition(" ")
            self.execute(f"/{verb} {nick} {extra}".strip())

    # --------------------------------------------- disappearing messages

    @staticmethod
    def _duration_ok(text: str) -> bool:
        try:
            parse_duration(text)
            return True
        except ValueError:
            return False

    MODES = {"t": "ttl", "m": "moderated", "i": "invite", "a": "noanon", "x": "textonly", "h": "history"}

    async def cmd_mode(self, rest: str):
        """IRC style: /mode #canal +t 1h · -t · +m · -i · sem modos mostra os atuais."""
        parts = rest.split()
        chan = parts.pop(0).lower() if parts and parts[0].startswith("#") else self._chan()
        ch = self.client.channels.get(chan)
        if not ch:
            raise ChatError(f"você não está em {chan}")
        if not parts:
            on = [f"+{flag}" + (f" {format_duration(ch.policy['ttl'])}" if flag == "t" else "")
                  + (f" {ch.policy['history']}d" if flag == "h" else "")
                  for flag, name in self.MODES.items() if ch.policy.get(name)]
            self.note(f"modos de {chan}: " + (" ".join(on) if on else "nenhum")
                      + " · t=mensagens temporárias m=moderado i=só convidados a=sem anônimos x=só texto"
                      " h=histórico cifrado", "ok")
            return
        changes = {}
        while parts:
            token = parts.pop(0)
            if len(token) < 2 or token[0] not in "+-" or any(f not in self.MODES for f in token[1:]):
                raise ChatError("uso: /mode #canal +t 1h | -t | +h 7 | -h | +m | -m | +i | +a | +x")
            for flag in token[1:]:
                name = self.MODES[flag]
                if name == "ttl":
                    if token[0] == "+":
                        if not parts:
                            raise ChatError("uso: /mode #canal +t 1h (30s, 10m, 1h, 7d, até 30d)")
                        try:
                            changes["ttl"] = parse_duration(parts.pop(0))
                        except ValueError:
                            raise ChatError("tempo inválido: use 30s, 10m, 1h ou 7d (até 30d)") from None
                    else:
                        changes["ttl"] = 0
                elif name == "history":
                    if token[0] == "+":
                        raw = parts.pop(0).lower().rstrip("d") if parts else ""
                        if not raw.isdigit() or int(raw) < 1:
                            raise ChatError("uso: /mode #canal +h 7 (dias que o servidor guarda o histórico cifrado)")
                        changes["history"] = int(raw)
                    else:
                        changes["history"] = 0
                else:
                    changes[name] = token[0] == "+"
        if "ttl" in changes and self.client.server_caps and "ttl" not in self.client.server_caps:
            raise ChatError("este servidor ainda não suporta mensagens temporárias em canais")
        if "history" in changes:
            if "history" not in self.client.server_caps:
                raise ChatError("este servidor não suporta histórico cifrado")
            if not ch.private:
                raise ChatError("histórico só existe em canais privados (a chave vem da senha do canal)")
        await self.client.set_policy(chan, **changes)

    # ----------------------------------------------------- search and notify

    def search_lines(self, query: str) -> list:
        """Every line in RAM that contains ``query``, newest first."""
        needle = fold(query.strip())
        if not needle:
            return []
        names = [self.current] + [n for n in self.buffers if n != self.current]   # current window first
        return [(name, line) for name in names for line in reversed(self.buffers[name].lines)
                if needle in fold(line.plain)]

    def jump_to(self, buffer: str, line) -> None:
        if buffer not in self.buffers:
            return
        self.mark = line
        if self.current == buffer:
            self.refill()
        else:
            self.switch(buffer)
        self.mark = None                # highlighted until the window is redrawn

    async def search_flow(self, initial: str = "") -> None:
        found = await self.ask(SearchScreen(self.search_lines, initial))
        if found:
            self.jump_to(*found)

    def action_search(self) -> None:
        if not self.in_dialog:
            self.run_cmd(self.search_flow())

    def cmd_search(self, rest: str):
        return self.search_flow(rest)

    cmd_find = cmd_search

    async def menu_search(self) -> None:
        await self.search_flow()

    def _save_notify(self) -> None:
        prefs = load_prefs()
        prefs["notify"] = self.notifier.enabled
        prefs["notify_preview"] = self.notifier.preview
        save_prefs(prefs)

    def _notify_state(self) -> str:
        if not self.notifier.enabled:
            return "desligadas"
        how = "com o texto da mensagem" if self.notifier.preview else "sem o texto (só quem e onde)"
        where = "" if self.notifier.available else " · nenhum notificador encontrado neste sistema"
        return f"ligadas, {how}{where}"

    def cmd_notify(self, rest: str):
        words = rest.lower().split()
        on = {"on", "sim", "ligar", "1"}
        off = {"off", "não", "nao", "desligar", "0"}
        if not words:
            self.note(f"notificações {self._notify_state()} · /notify on|off · /notify preview on|off", "ok")
            return None
        if words[0] in on | off and len(words) == 1:
            self.notifier.enabled = words[0] in on
        elif words[0] == "preview" and len(words) == 2 and words[1] in on | off:
            self.notifier.preview = words[1] in on
        else:
            raise ChatError("uso: /notify on | off | preview on | preview off")
        self._save_notify()
        self.note(f"notificações {self._notify_state()}", "ok")
        if self.notifier.enabled and self.notifier.preview:
            self.note("com preview, o texto sai do chat para o sistema: pode aparecer na tela de bloqueio "
                      "e ficar no histórico de notificações", "warn")
        return None

    async def menu_notify(self) -> None:
        choice = await self.ask(ChoiceScreen(f"notificações: {self._notify_state()}", [(None, [
            ("on", "Ligar, sem o texto", "mostra só quem escreveu e onde (recomendado)"),
            ("preview", "Ligar, com o texto", "o texto aparece no sistema e pode ficar no histórico dele"),
            ("off", "Desligar", "nenhuma notificação do sistema"),
        ])], heading="NOTIFICAÇÕES"))
        if choice == "preview":
            self.cmd_notify("on")
            self.cmd_notify("preview on")
        elif choice == "on":
            self.cmd_notify("on")
            self.cmd_notify("preview off")
        elif choice == "off":
            self.cmd_notify("off")

    async def cmd_chanpass(self, rest: str):
        """Owner: new password → new key. The old history goes away unless re-encrypted."""
        chan = rest.split()[0].lower() if rest.split() else self._chan()
        ch = self.client.channels.get(chan)
        if not ch or not ch.private:
            raise ChatError("uso: /chanpass #canal (só canais privados, só o dono)")
        fut = asyncio.get_running_loop().create_future()
        self.push_screen(PassScreen(f"nova senha de {chan}", True), lambda v: fut.done() or fut.set_result(v))
        password = await fut
        self.input.focus()
        if not password:
            return
        reencrypt = False
        if self.history_days(chan):
            choice = await self.ask(ChoiceScreen(f"o que fazer com o histórico de {chan}?", [(None, [
                ("drop", "Apagar o histórico antigo", "recomendado: a senha nova não lê nada do passado"),
                ("keep", "Re-cifrar com a senha nova", "quem tiver a senha nova lê o histórico que ainda existe"),
            ])], heading="HISTÓRICO"))
            if choice is None:
                return
            reencrypt = choice == "keep"
        reply = await self.client.change_password(chan, password, reencrypt)
        kept = reply.get("kept") or 0
        self.note(f"senha de {chan} trocada: chave nova; os outros membros saíram e precisam da senha nova"
                  + (f" · {kept} mensagens do histórico re-cifradas" if reencrypt else
                     " · histórico antigo apagado" if self.history_days(chan) else ""), "ok", chan)

    async def cmd_ttl(self, rest: str):
        parts = rest.split()
        if len(parts) == 1 and self.current.startswith("@"):
            parts.insert(0, self.current[1:])
        if len(parts) == 1 and valid_nick(parts[0]):
            seconds = self.client.dm_ttl(parts[0])
            self.note(f"mensagens com {parts[0]}: " + (f"somem em {format_duration(seconds)}" if seconds else
                                                      "não somem") + f" · /ttl {parts[0]} 10m ou off", "ok")
            return
        if len(parts) != 2 or not valid_nick(parts[0]):
            raise ChatError("uso: /ttl nick 10m (30s, 10m, 1h, 7d, até 30d; off desliga)")
        try:
            seconds = parse_duration(parts[1])
        except ValueError:
            raise ChatError("tempo inválido: use 30s, 10m, 1h ou 7d (até 30d), ou off") from None
        await self.client.set_dm_ttl(parts[0], seconds)

    def ev_dm_ttl(self, nick: str, seconds: int, by: str) -> None:
        who = "você" if by == self.client.nick else by
        text = (f"{who} ativou mensagens temporárias: elas somem {format_duration(seconds)} depois de chegar"
                if seconds else f"{who} desativou as mensagens temporárias")
        self.note(text + " · vale para os dois lados", "warn", "@" + nick)
        self.refresh_all()

    def expire_messages(self) -> None:
        """Every second: forget what has expired, on screen and in memory."""
        now = time.time()
        changed = False
        for buf in self.buffers.values():
            if buf.purge(now):
                changed = changed or buf.name == self.current
        for number in [n for n, when in self.clip_expiry.items() if when <= now]:
            self.clips.pop(number, None)
            del self.clip_expiry[number]
        if changed:
            self.refill()

    # ---------------------------------------------------- away and friends

    async def cmd_away(self, rest: str):
        await self.client.set_away(rest)
        self.note("você está ausente" + (f": {rest}" if rest else "") + " · /back para voltar", "warn")
        self.refresh_all()

    async def cmd_back(self, _):
        if not self.client.away:
            raise ChatError("você não está ausente")
        await self.client.set_away(None)
        self.note("você está de volta", "ok")
        self.refresh_all()

    async def menu_away(self) -> None:
        if self.client.away:
            await self.cmd_back("")
            return
        values = await self.ask(FormScreen("ficar ausente", ["recado para quem te escrever (ou - para nenhum)"],
                                           heading="AUSENTE"))
        if values:
            await self.cmd_away("" if values[0] == "-" else values[0])

    def _friends_ok(self) -> None:
        if self.client.guest:
            raise ChatError("a lista de amigos é para quem tem nick registrado")

    async def poll_presence(self) -> None:
        if self.client.guest or not self.client.online:
            return
        friends = self.client.store.friends()
        if not friends:
            self.presence = {}
            self.render_buffers()
            return
        old, self.presence = self.presence, await self.client.presence(friends)
        if self._presence_known:
            for nick in friends:
                was, now = old.get(nick.lower()), self.presence.get(nick.lower())
                if now and not was:
                    self.note(f"seu amigo {nick} entrou", "ok", CONSOLE)
                elif was and not now:
                    self.note(f"seu amigo {nick} saiu", "info", CONSOLE)
        self._presence_known = True
        self.render_buffers()

    async def cmd_friend(self, rest: str):
        self._friends_ok()
        action, _, nick = rest.partition(" ")
        nick = nick.strip()
        if action.lower() in ("add", "adicionar", "+") and valid_nick(nick):
            peer = await self.client.resolve(nick)          # must be a real, registered nick
            if peer.guest:
                raise ChatError("usuários anônimos não podem ser adicionados: o nick deles muda a cada sessão")
            self.client.store.set_friend(peer.nick)
            self._presence_known = False                    # do not announce someone just added
            self.note(f"{peer.nick} adicionado aos amigos (a lista fica só neste computador)", "ok")
        elif action.lower() in ("del", "remover", "rm", "-") and valid_nick(nick):
            if not self.client.store.set_friend(nick, False):
                raise ChatError(f"{nick} não está na sua lista de amigos")
            self.note(f"{nick} removido dos amigos", "ok")
        else:
            raise ChatError("uso: /friend add nick · /friend del nick · /friends")
        await self.poll_presence()

    async def cmd_friends(self, _):
        self._friends_ok()
        await self.poll_presence()
        friends = self.client.store.friends()
        if not friends:
            self.note("sua lista de amigos está vazia: /friend add nick", "info")
            return
        self.note(f"amigos ({sum(1 for f in friends if f.lower() in self.presence)}/{len(friends)} online):", "ok")
        for nick in friends:
            state = self.presence.get(nick.lower())
            label, colour = {"on": ("online", GREEN), "away": ("ausente", YELLOW)}.get(state, ("offline", DIM))
            self.add_line(None, Text.assemble(("               ", ""), (f"{nick:<21}", nick_color(nick)), (label, colour)))

    async def menu_friends(self) -> None:
        self._friends_ok()
        await self.poll_presence()
        items = []
        for nick in self.client.store.friends():
            state = self.presence.get(nick.lower())
            items.append((nick, nick, {"on": "● online", "away": "◐ ausente"}.get(state, "○ offline")))
        items.append((CUSTOM, "✎ adicionar amigo…", ""))
        choice = await self.ask(ChoiceScreen("amigos", [(None, items)], heading="AMIGOS"))
        if choice == CUSTOM:
            nick = await self.pick_nick("adicionar quem?")
            if nick:
                self.execute("/friend add " + nick)
        elif choice:
            action = await self.ask(ChoiceScreen(choice, [(None, [
                ("query", "Conversar", ""), ("del", "Remover dos amigos", "")])], heading="AMIGOS"))
            if action == "query":
                self.execute("/query " + choice)
            elif action == "del":
                self.execute("/friend del " + choice)

    # ---------------------------------------------------------------- update

    @staticmethod
    def update_repo() -> str:
        return update.source_for(load_prefs())

    def _suggest_repo(self, repo: str | None) -> None:
        # The server only suggests: switching needs the user's own confirmation.
        if repo and repo != self.update_repo() and update.valid_source(repo):
            self.note(f"este servidor indica atualizações em {repo} (você usa {self.update_repo()}). "
                      f"Se confiar, use /update origem {repo}", "warn", CONSOLE)

    async def check_update(self, announce_only: bool = False) -> dict | None:
        self._suggest_repo(self.client.server_repo)
        repo = self.update_repo()
        try:
            info = await asyncio.to_thread(update.latest, repo)
        except update.UpdateError as exc:
            if not announce_only:
                raise ChatError(str(exc)) from None
            return None
        mine = update.current()
        if not update.is_newer(info, mine):
            if info["built"] < (mine["built"] or 0) and update.can_self_update():
                self.note(f"a release publicada em {repo} ({info['version']}, {info['commit']}) é mais antiga que "
                          "este binário; ela não será instalada (proteção contra downgrade)", "warn", CONSOLE)
            elif not announce_only:
                self.note(f"você está na versão mais recente ({mine['version']}"
                          + (f", {mine['commit']}" if mine["commit"] else "") + ")", "ok")
            return None
        when = time.strftime("%d/%m/%Y %H:%M", time.localtime(info["built"])) if info["built"] else "?"
        self.note(f"atualização disponível: crptochat {info['version']} ({info['commit']}, {when}) em {repo}"
                  + (" · /update para instalar" if update.can_self_update() else
                     " · esta instalação é do código-fonte: atualize com git pull e pip install"), "warn", CONSOLE)
        if announce_only:
            self.bell()
        return info

    async def cmd_update(self, rest: str):
        parts = rest.split()
        if parts[:1] in (["repo"], ["origem"]):
            if len(parts) == 2 and parts[1] in ("padrao", "padrão", "default"):
                prefs = load_prefs()
                prefs.pop("update_repo", None)
                save_prefs(prefs)
                self.note(f"atualizações voltam a vir de {update.default_source()}", "ok")
                return
            if len(parts) != 2 or not update.valid_source(parts[1], local=True):
                raise ChatError("uso: /update origem https://…  (http:// é recusado; padrao volta ao site)")
            answer = await self.ask(ChoiceScreen(
                f"buscar atualizações em {parts[1]}?", [(None, [
                    ("yes", "Sim, confio nesta origem", "o binário instalado ainda precisa ter assinatura válida"),
                    ("no", "Não", f"continuar em {self.update_repo()}")])], heading="ATUALIZAÇÃO"))
            if answer == "yes":
                prefs = load_prefs()
                prefs["update_repo"] = parts[1]
                save_prefs(prefs)
                self.note(f"atualizações passam a vir de {parts[1]}", "ok")
            return
        if parts[:1] in (["off"], ["on"]):
            prefs = load_prefs()
            prefs["update_check"] = parts[0] == "on"
            save_prefs(prefs)
            self.note("verificação automática de atualizações " + ("ligada" if parts[0] == "on" else "desligada"), "ok")
            return
        info = await self.check_update()
        if not info or parts[:1] == ["check"] or not update.can_self_update():
            return
        signed = ("manifesto assinado e SHA-256 conferidos" if info.get("signed")
                  else "SHA-256 conferido (cliente sem chave de assinatura)")
        answer = await self.ask(ChoiceScreen(
            f"instalar crptochat {info['version']} ({info['commit']}) de {self.update_repo()}?", [(None, [
                ("yes", "Instalar agora", signed),
                ("no", "Agora não", "")])], heading="ATUALIZAÇÃO"))
        if answer != "yes":
            return
        self.note("baixando e conferindo a atualização…", "info")
        try:
            done = await asyncio.to_thread(update.apply, self.update_repo())
        except update.UpdateError as exc:
            raise ChatError(f"atualização não instalada: {exc}") from None
        self.note(f"crptochat {done['version']} ({done['commit']}) instalado em {done['path']}. "
                  "Saia (Ctrl+Q) e abra de novo para usar a versão nova.", "ok")

    async def menu_update(self) -> None:
        await self.cmd_update("")

    # ---------------------------------------------------------------- themes

    def cmd_theme(self, rest: str):
        name = rest.strip().lower()
        if not name:
            self.note("temas (use /theme nome):", "ok")
            for key, (label, desc, _, _) in themes.THEMES.items():
                self.add_line(None, Text.assemble(("               ", ""), (f"{key:<12}", CYAN),
                                                  (desc, TEXT), ("  ← atual" if key == THEME else "", GREEN)))
            return
        if name not in themes.THEMES:
            raise ChatError("tema desconhecido: " + name + " · opções: " + ", ".join(themes.THEMES))
        self.apply_theme(name)
        self.note(f"tema {themes.THEMES[name][0]} aplicado", "ok")

    async def menu_theme(self) -> None:
        before = THEME
        items = [(key, label, desc) for key, (label, desc, _, _) in themes.THEMES.items()]
        choice = await self.ask(ChoiceScreen(
            "escolha um tema", [(None, items)], heading="TEMAS", start=before,
            hint="↑↓ pré-visualiza · Enter aplica · Esc cancela",
            preview=lambda name: self.apply_theme(name, save=False)))
        self.apply_theme(choice or before, save=bool(choice))
        if choice:
            self.note(f"tema {themes.THEMES[choice][0]} aplicado", "ok")

    # -------------------------------------------------------------- commands

    def cmd_help(self, _):
        self.note("comandos disponíveis:", "ok")
        for usage, desc in HELP:
            self.add_line(None, Text.assemble(("               ", ""), (f"{usage:<28}", CYAN), (desc, TEXT)))
        self.add_line(None, Text.assemble(
            ("               ", ""), ("segure Shift para selecionar/copiar texto com o mouse", DIM)))

    async def cmd_list(self, _):
        chans = await self.client.list_channels()
        self.note(f"{len(chans)} canal(is) visível(is) (canais privados só aparecem para quem está dentro):", "ok")
        for ch in chans:
            self.add_line(None, Text.assemble(
                ("               ", ""), (f"{ch['name']:<22}", CYAN),
                ("⊗ privado   " if ch["private"] else "aberto      ", PINK if ch["private"] else GREEN),
                (f"{ch['members']} online", DIM)))

    def ask_pass(self, title: str, confirm: bool, then) -> None:
        def done(value):
            if value:
                self.run_cmd(then(value))
            self.input.focus()
        self.push_screen(PassScreen(title, confirm), done)

    def cmd_create(self, rest: str):
        parts = rest.split()
        if not parts:
            raise ChatError("uso: /create #canal [privado]")
        chan = parts[0].lower() if parts[0].startswith("#") else "#" + parts[0].lower()
        if not valid_chan(chan):
            raise ChatError("nome de canal inválido: use #nome (minúsculas, números, _ e -)")
        if len(parts) > 1:
            if parts[1].lower() not in ("privado", "private", "priv", "-p"):
                raise ChatError("uso: /create #canal [privado]")
            self.ask_pass(f"defina a senha de {chan}", True, lambda pw: self.client.create(chan, pw))
            return None
        return self.client.create(chan)

    async def do_join(self, chan: str) -> None:
        try:
            await self.client.join(chan)
        except NeedPassphrase:
            self.ask_pass(f"senha de {chan}", False, lambda pw: self.client.join(chan, pw))

    def cmd_join(self, rest: str):
        if not rest:
            raise ChatError("uso: /join #canal")
        chan = rest.split()[0].lower()
        chan = chan if chan.startswith("#") else "#" + chan
        if chan in self.buffers and self.client.channels.get(chan) and self.client.channels[chan].joined:
            self.switch(chan)
            return None
        return self.do_join(chan)

    cmd_j = cmd_join

    def cmd_leave(self, rest: str):
        target = rest.split()[0] if rest else self.current
        if target.startswith("@"):
            self.buffers.pop(target, None)
            self.switch(CONSOLE)
            return None
        if target == CONSOLE:
            raise ChatError("uso: /leave dentro de um canal")
        return self.client.leave(target)

    cmd_part = cmd_close = cmd_leave

    async def cmd_msg(self, rest: str):
        nick, _, text = rest.partition(" ")
        if not valid_nick(nick) or not text.strip():
            raise ChatError("uso: /msg nick texto")
        await self.client.send_dm(nick, text.strip())

    async def cmd_query(self, rest: str):
        if not valid_nick(rest):
            raise ChatError("uso: /query nick")
        peer = await self.client.resolve(rest)
        self.buffer("@" + peer.nick)
        self.switch("@" + peer.nick)
        if not peer.dh:
            self.note(f"{peer.nick} está offline; mensagens só são entregues com os dois online", "warn")

    async def cmd_send(self, rest: str):
        try:
            parts = shlex.split(rest)
        except ValueError:
            raise ChatError("uso: /send nick|#canal /caminho/do/arquivo [--p2p]") from None
        p2p = "--p2p" in parts
        parts = [p for p in parts if p != "--p2p"]
        if len(parts) == 1 and self.buffers[self.current].kind in ("dm", "chan"):
            parts.insert(0, self.current.lstrip("@"))
        if len(parts) != 2:
            raise ChatError("uso: /send nick|#canal /caminho/do/arquivo [--p2p]")
        target, path = parts
        if p2p:
            if target.startswith("#"):
                raise ChatError("--p2p só funciona para uma pessoa; num canal o arquivo vai pelo servidor")
            if not valid_nick(target):
                raise ChatError("uso: /send nick /caminho/do/arquivo --p2p")
            answer = await self.ask(ChoiceScreen(
                f"enviar direto (P2P) para {target}?", [(None, [
                    ("no", "Não, mandar pelo servidor", "cifrado de ponta a ponta, seu IP fica escondido"),
                    ("yes", "Sim, conexão direta", f"{target} vai ver o SEU ENDEREÇO IP (e você o dele)"),
                ])], heading="⚠ P2P EXPÕE SEU IP"))
            if answer == "yes":
                await self.client.files.offer(target, path)
            elif answer == "no":
                await self.client.relay.offer(target, path)
            return
        if not target.startswith("#") and not valid_nick(target):
            raise ChatError("uso: /send nick|#canal /caminho/do/arquivo [--p2p]")
        await self.client.relay.offer(target, path)

    async def cmd_accept(self, rest: str):
        tr = self.client.relay.find(rest.strip() or None)
        if tr is None:
            await self.client.files.accept(rest or None)       # a direct (P2P) offer
            return
        default = self.client.files.download_dir
        title = f"salvar '{clean(tr.name)}' ({human_size(tr.size)}) de {tr.peer.nick} em qual pasta?"
        if tr.ttl:
            title += f" · ⏱ o arquivo será APAGADO do disco {format_duration(tr.ttl)} depois de chegar"
        folder = await self.ask_text(title, "pasta de destino", initial=default)
        if folder:
            await self.client.relay.accept(tr.id, folder)

    async def cmd_reject(self, rest: str):
        if self.client.relay.find(rest.strip() or None):
            await self.client.relay.reject(rest.strip() or None)
        else:
            await self.client.files.reject(rest or None)

    def _fp_line(self, nick: str, ik: bytes, extra: str = "", style: str | None = None) -> None:
        self.add_line(None, Text.assemble(("               ", ""), (f"{nick:<21}", nick_color(nick)),
                                          (crypto.fingerprint(ik), style or CYAN), (extra, DIM)))

    def _info_line(self, label: str, value: str, style: str | None = None) -> None:
        self.add_line(None, Text.assemble(("               ", ""), (f"{label:<21}", DIM), (value, style or TEXT)))

    def _safety_lines(self, ik: bytes) -> None:
        groups = crypto.safety_number(self.client.identity.ik, ik).split()
        self._info_line("número de segurança", " ".join(groups[:6]), f"bold {YELLOW}")
        self._info_line("", " ".join(groups[6:]), f"bold {YELLOW}")

    def verify_mark(self, nick: str) -> tuple[str, str]:
        """(mark, colour) for a nick: ⚠ changed key, ✓ verified, or nothing."""
        peer = self.client.peers.get(nick.lower())
        if (peer and peer.pending_ik) or (not peer and self.client.store.pending(nick)):
            return "⚠", MAGENTA
        if self.client.store.is_verified(nick):
            return "✓", GREEN
        return "", DIM

    def cmd_who(self, _):
        ch = self.client.channels.get(self.current)
        if not ch:
            raise ChatError("uso: /who dentro de um canal")
        self.note(f"membros de {ch.name}:", "ok")
        self._fp_line(self.client.nick, self.client.identity.ik, "  (você)")
        for peer in sorted(ch.members.values(), key=lambda p: p.key):
            mark = "  ⚠ CHAVE MUDOU" if peer.pending_ik else "  ✓" if self.client.store.is_verified(peer.nick) else ""
            self._fp_line(peer.nick, peer.ik, mark)

    async def cmd_whois(self, rest: str):
        if not valid_nick(rest.strip()):
            raise ChatError("uso: /whois nick")
        peer = await self.client.resolve(rest.strip())
        state = "online" if peer.dh else "offline"
        if peer.guest:
            self.note(f"{peer.nick} ({state}) · anônimo: chave descartável, não há o que conferir", "info")
            self._fp_line(peer.nick, peer.ik)
            return
        if peer.pending_ik:
            self.note(f"{peer.nick} ({state}) · ⚠ A CHAVE MUDOU e não foi aceita: mensagens bloqueadas · "
                      f"/verify {peer.nick}", "err")
            self._fp_line(peer.nick, peer.ik, "  chave conhecida")
            self._fp_line(peer.nick, peer.pending_ik, "  chave nova", MAGENTA)
            return
        verified = self.client.store.is_verified(peer.nick)
        self.note(f"{peer.nick} ({state}) · " + ("✓ conferido" if verified else f"não conferido · /verify {peer.nick}"),
                  "ok" if verified else "info")
        self._fp_line(peer.nick, peer.ik, "  fingerprint")
        self._safety_lines(peer.ik)
        self._info_line("clientes antigos (hex)", crypto.legacy_fingerprint(peer.ik), DIM)

    async def _ask_secret(self, title: str, confirm: bool, placeholder: str) -> str | None:
        fut = asyncio.get_running_loop().create_future()
        self.push_screen(PassScreen(title, confirm, placeholder), lambda v: fut.done() or fut.set_result(v))
        value = await fut
        self.input.focus()
        return value

    async def cmd_passwd(self, _=""):
        """New passphrase for the stored key: same key, same nick, contacts see nothing."""
        ident = self.client.identity
        if self.client.guest or (not ident.file and not ident.source):
            raise ChatError("sessão anônima: a chave só existe na memória, não há senha para trocar")
        current = await self._ask_secret("senha ATUAL da sua chave", False, "senha atual")
        if not current:
            return
        new = await self._ask_secret("senha NOVA da sua chave", True, "senha nova")
        if not new:
            return
        try:
            where = await asyncio.to_thread(ident.change_passphrase, current, new)
        except BadPassphrase:
            raise ChatError("senha atual incorreta: nada foi alterado") from None
        except FileNotFoundError:
            raise ChatError(f"a chave não está acessível em {ident.location} (dispositivo ou cofre?)") from None
        except (ValueError, OSError) as exc:
            raise ChatError(f"senha não trocada: {exc}") from None
        self.note(f"senha da chave trocada ({where}). A chave, o nick e a fingerprint continuam os mesmos.", "ok")
        self.note("cópias antigas do arquivo (backups, outro pendrive) continuam abrindo com a senha antiga; "
                  "se usa --pass-cmd ou CRPTOCHAT_PASSPHRASE, atualize lá também", "warn")

    async def menu_passwd(self) -> None:
        await self.cmd_passwd()

    def cmd_fp(self, _):
        self.note("sua fingerprint (compartilhe por outro meio para ser conferida):", "ok")
        self._fp_line(self.client.nick, self.client.identity.ik)
        self._info_line("clientes antigos (hex)", crypto.legacy_fingerprint(self.client.identity.ik), DIM)

    async def cmd_verify(self, rest: str):
        nick = rest.strip()
        if not valid_nick(nick):
            raise ChatError("uso: /verify nick")
        peer = await self.client.resolve(nick)
        if peer.guest:
            raise ChatError("usuários anônimos usam chaves descartáveis: não há o que conferir")
        if peer.pending_ik:
            new = peer.pending_ik
            answer = await self.ask(ChoiceScreen(
                f"a chave de {peer.nick} MUDOU · conhecida {crypto.fingerprint(peer.ik)} · "
                f"nova {crypto.fingerprint(new)}", [(None, [
                    ("keep", "Manter bloqueado", "não confirmei a troca por outro meio"),
                    ("accept_verified", "Conferi: aceitar a nova chave e marcar ✓",
                     f"número de segurança: {crypto.safety_number(self.client.identity.ik, new)}"),
                    ("accept", "Aceitar a nova chave sem marcar ✓", "volta a conversar, mas sem conferência"),
                ])], heading="⚠ CHAVE DE IDENTIDADE MUDOU"))
            if answer in ("accept", "accept_verified"):
                # pass the key whose fingerprint was on screen: if the server swapped it
                # again while the dialog was open, accept_key refuses
                await self.client.accept_key(peer.nick, new, verified=answer == "accept_verified")
                self.note(f"nova chave de {peer.nick} aceita" + (" e marcada ✓" if answer == "accept_verified" else
                                                                 " (não conferida)"), "ok")
            else:
                self.note(f"{peer.nick} continua bloqueado até você aceitar a nova chave", "warn")
            self.refresh_all()
            return
        answer = await self.ask(ChoiceScreen(
            f"{peer.nick} · fingerprint {crypto.fingerprint(peer.ik)}", [(None, [
                ("yes", "Confere", f"número de segurança: {crypto.safety_number(self.client.identity.ik, peer.ik)}"),
                ("no", "Não confere / não conferi", "remove a marca ✓"),
            ])], heading="CONFERIR FINGERPRINT",
            hint="compare o número de segurança com o que aparece para a outra pessoa · Esc fecha"))
        if answer:
            self.client.store.set_verified(peer.nick, answer == "yes")
            self.note(f"{peer.nick} marcado como " + ("conferido ✓" if answer == "yes" else "não conferido"), "ok")
            self.refresh_all()

    async def cmd_unverify(self, rest: str):
        nick = rest.strip()
        if not self.client.store.set_verified(nick, False):
            raise ChatError("uso: /unverify nick")
        self.note(f"{nick} marcado como não conferido", "ok")
        self.refresh_all()

    def cmd_clear(self, _):
        self.action_clear()

    def cmd_quit(self, _):
        return self.action_quit()

    cmd_q = cmd_exit = cmd_quit
