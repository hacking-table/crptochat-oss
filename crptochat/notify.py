"""Desktop notifications for mentions and direct messages.

What goes to the operating system leaves the chat's protection: notification
daemons can log it, show it on the lock screen or sync it. So by default the
notification says only *who* wrote and *where*, never the text; showing the
text is a separate opt-in (``/notify preview on``).

The text is always passed as a separate argument or environment variable,
never pasted into a shell or script, so a message can't run commands.
"""

from __future__ import annotations

import html
import ntpath
import os
import shutil
import subprocess
import sys
import time
import unicodedata

TITLE_MAX = 64
BODY_MAX = 160

# Windows: a toast through the WinRT API in PowerShell. The texts come from
# environment variables and are XML-escaped there, so nothing in them is code.
_PS_TOAST = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$t = [Security.SecurityElement]::Escape($env:CRPTOCHAT_NOTIFY_TITLE)
$b = [Security.SecurityElement]::Escape($env:CRPTOCHAT_NOTIFY_BODY)
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$n = [Windows.UI.Notifications.ToastNotification]::new($x)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('crptochat').Show($n)
"""

# macOS: the texts are AppleScript run arguments, not part of the script.
_OSASCRIPT = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
              "-e", "end run"]


def sanitize(text: str, limit: int) -> str:
    """One line, no control/format characters (escapes, bidi overrides), bounded."""
    out = []
    for ch in str(text):
        cat = unicodedata.category(ch)
        if ch in "\r\n\t":
            out.append(" ")
        elif cat[0] == "C":          # Cc control, Cf format (bidi), Co, Cn, Cs
            continue
        else:
            out.append(ch)
    text = " ".join("".join(out).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def windows_powershell(exists=os.path.isfile) -> str | None:
    """The system's own powershell.exe, by absolute path: never whatever a
    PATH lookup (current folder, user-writable folders) would find first."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    path = ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if exists(path) else None


def backend(platform: str | None = None, which=shutil.which, exists=os.path.isfile) -> list[str] | None:
    """The command that shows a notification here, or None if there is none."""
    platform = platform or sys.platform
    if platform.startswith("linux") or "bsd" in platform:
        path = which("notify-send")
        return [path] if path else None
    if platform == "darwin":
        path = which("osascript")
        return [path] if path else None
    if platform.startswith("win"):
        path = windows_powershell(exists)
        return [path] if path else None
    return None


def command(title: str, body: str, platform: str | None = None, which=shutil.which,
            exists=os.path.isfile) -> tuple[list[str], dict] | None:
    """argv and extra environment for one notification (no shell involved)."""
    base = backend(platform, which, exists)
    if not base:
        return None
    title, body = sanitize(title, TITLE_MAX), sanitize(body, BODY_MAX)
    platform = platform or sys.platform
    if platform == "darwin":
        return base + _OSASCRIPT + [title, body], {}
    if platform.startswith("win"):
        return (base + ["-NoProfile", "-NonInteractive", "-Command", _PS_TOAST],
                {"CRPTOCHAT_NOTIFY_TITLE": title, "CRPTOCHAT_NOTIFY_BODY": body})
    # "--" ends the options: a title starting with "-" is still just text. The body
    # is markup for notification daemons (<b>, <a href>, <img>): escape it.
    return base + ["--app-name=crptochat", "--", title, html.escape(body, quote=False)], {}


class Notifier:
    """Rate-limited desktop notifications (one per conversation every few seconds)."""

    def __init__(self, enabled: bool = True, preview: bool = False, gap: float = 5.0, runner=None):
        self.enabled = enabled
        self.preview = preview
        self.gap = gap
        self._last: dict[str, float] = {}
        self._runner = runner or self._spawn
        self.sent = 0

    @property
    def available(self) -> bool:
        return backend() is not None

    def message(self, where: str, nick: str, text: str, mention: bool) -> bool:
        """``where`` is "#canal" or "@nick"."""
        if not self.enabled:
            return False
        now = time.monotonic()
        if now - self._last.get(where, -1e9) < self.gap:
            return False
        self._last[where] = now
        if where.startswith("@"):
            title = f"crptochat · mensagem direta de {nick}"
        else:
            title = f"crptochat · {nick} mencionou você em {where}"
        body = text if self.preview else "abra o crptochat para ler (conteúdo oculto)"
        cmd = command(title, body)
        if cmd is None:
            return False
        try:
            self._runner(*cmd)
        except OSError:
            return False
        self.sent += 1
        return True

    @staticmethod
    def _spawn(argv: list[str], extra_env: dict) -> None:
        env = dict(os.environ, **extra_env) if extra_env else None
        kwargs = {}
        if sys.platform.startswith("win"):
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kwargs["start_new_session"] = True
        # no shell; the message text is an argument (or env var), already sanitized
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,  # nosec B603
                         stderr=subprocess.DEVNULL, env=env, close_fds=True, **kwargs)
