"""What `crptochat` does on the command line before the interface opens, for
the browser: open (or create) the local identity, connect over WebSocket and
run the same Textual interface inside xterm.js."""

from __future__ import annotations

import asyncio
import os

# Textual reads this when it is first imported (textual.constants). Setting it
# here, at module import, is enough: driver.py (and Textual) are imported only
# in start(), after the login, so the page does not pay for them while the form
# is still waiting for a nick and passphrase.
os.environ["TEXTUAL_DRIVER"] = "crptoweb.driver:XtermDriver"

from .wire import check_url  # noqa: E402

HOME = "/data/home"            # IndexedDB-backed (mounted and synced by main.js)


async def _inline(func, /, *args, **kwargs):
    # no threads in the browser: run it here (the screen waits while it works)
    return func(*args, **kwargs)


def open_identity(nick: str, passphrase: str):
    from crptochat.store import BadPassphrase, Identity
    if Identity.exists(nick):
        try:
            return Identity.load(nick, passphrase), False
        except BadPassphrase:
            raise ValueError("senha incorreta para esta chave") from None
    if len(passphrase) < 8:
        raise ValueError("chave nova: use uma senha de pelo menos 8 caracteres")
    return Identity.create(nick, passphrase), True


def prepare() -> None:
    """Environment for everything below (keys on the login page included)."""
    os.environ["CRPTOCHAT_HOME"] = HOME
    os.environ.setdefault("TERM", "xterm-256color")
    os.environ.setdefault("COLORTERM", "truecolor")
    os.makedirs(HOME, mode=0o700, exist_ok=True)
    asyncio.to_thread = _inline


async def start(terminal, url: str, nick: str, passphrase: str, guest: bool = False,
                sensitive: bool = False) -> str:
    """Runs the chat until it ends; returns why it ended (for the page).

    ``sensitive`` is the web page's optional 'modo sensível': keep fewer
    decrypted lines and wipe the screen when the tab is left.
    """
    prepare()
    # Read by crptochat.tui when a Buffer/ChatLog is created, so setting it here
    # (before ChatApp) is enough. The page imports tui only now, together with
    # the driver and the rest of Textual.
    os.environ["CRPTOCHAT_SENSITIVE"] = "1" if sensitive else "0"
    from . import driver  # noqa: E402  (imports Textual; not needed on the login page)
    driver.TERMINAL = terminal

    host, port, tls = check_url(url)
    from crptochat import crypto
    from crptochat.client import ChatClient
    from crptochat.store import Store
    from crptochat.tui import ChatApp
    from .net import WebSocketStream

    async def open_connection(*_args, **_kwargs):
        stream = await WebSocketStream.open(url)
        return stream, stream

    asyncio.open_connection = open_connection        # the client's only way out is this WebSocket

    identity = None
    if not guest:
        identity, _new = open_identity(nick, passphrase)
    else:
        from crptochat.store import Identity
        identity = Identity("anon", crypto.ed_generate())
    store = Store(f"{host}:{port}")

    def factory(on_event):
        # tls=False: the client opens no TLS of its own (the browser does, for wss://);
        # external_tls tells the interface the link is TLS all the same
        return ChatClient(host, port, identity, store, on_event, tls=False, external_tls=tls, guest=guest,
                          download_dir=os.path.join(HOME, "downloads"))

    app = ChatApp(factory)
    hide = None
    if sensitive:
        # JS keeps this callback after start() is gone: make a proxy, and free it
        # on the way out. The browser side waits ~15 s before calling it, so a
        # quick switch to another tab does not wipe the screen.
        from pyodide.ffi import create_proxy

        def wipe():
            app.call_later(app.clear_sensitive)

        hide = create_proxy(wipe)
        terminal.set_hide_handler(hide)
    try:
        fatal = await app.run_async()
    finally:
        if hide is not None:
            terminal.set_hide_handler(None)
            hide.destroy()
    return str(fatal or "sessão encerrada")
