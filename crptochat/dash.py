"""`crptochat-dash`: live terminal dashboard for whoever runs the server.

Standard library only, so it also works inside the minimal server container
(``docker exec -it <container> python -m crptochat.dash --data /data``).
It shows aggregate counts and resource usage. No nickname, channel name,
address or message is available to it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import shutil
import socket
import sys

from .stats import socket_path

CYAN, MAGENTA, YELLOW, GREEN, PURPLE, DIM, TEXT = (
    (0, 240, 255), (255, 42, 109), (252, 238, 10), (57, 255, 20), (185, 103, 255), (89, 97, 138), (213, 220, 255))
RESET = "\033[0m"
_ANSI = re.compile(r"\033\[[0-9;]*m")
SPARK = "▁▂▃▄▅▆▇█"


def fg(rgb, text, bold=False) -> str:
    return f"\033[{'1;' if bold else ''}38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{text}{RESET}"


def vlen(text: str) -> int:
    return len(_ANSI.sub("", text))


def fit(text: str, width: int) -> str:
    """Pad or cut to a visible width, keeping colour codes intact."""
    out, seen, pos = [], 0, 0
    while pos < len(text) and seen < width:
        match = _ANSI.match(text, pos)
        if match:
            out.append(match.group())
            pos = match.end()
        else:
            out.append(text[pos])
            seen += 1
            pos += 1
    return "".join(out) + RESET + " " * (width - seen)


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def human_time(seconds: int) -> str:
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    return (f"{days}d " if days else "") + f"{hours:02d}:{minutes:02d}:{secs:02d}"


def spark(values, width: int, color) -> str:
    values = list(values)[-width:]
    if not values:
        return fg(DIM, "·" * width)
    top = max(values) or 1
    line = "".join(SPARK[min(7, int(v / top * 7.999))] if v > 0 else SPARK[0] for v in values)
    return fg(DIM, "·" * (width - len(values))) + fg(color, line)


def bar(fraction: float, width: int, color) -> str:
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)
    return fg(color, "▰" * filled) + fg(DIM, "▱" * (width - filled))


def row(label: str, value, color=TEXT) -> str:
    return fg(DIM, f"{label:<24}") + fg(color, str(value), bold=True)


def box(title: str, lines: list[str], width: int, color) -> list[str]:
    inner = width - 4
    head = fg(color, "┏━ ") + fg(YELLOW, title, bold=True) + " " + fg(color, "━" * max(0, width - 5 - len(title)) + "┓")
    body = [fg(color, "┃ ") + fit(line, inner) + fg(color, " ┃") for line in lines]
    return [head] + body + [fg(color, "┗" + "━" * (width - 2) + "┛")]


def side_by_side(left: list[str], right: list[str], left_width: int) -> list[str]:
    height = max(len(left), len(right))
    left = left + [" " * left_width] * (height - len(left))
    right = right + [""] * (height - len(right))
    return [a + " " + b for a, b in zip(left, right)]


def render(snap: dict, width: int = 100, height: int | None = None) -> str:
    # Two columns when there is room; on a narrow terminal (phone, split
    # pane) the boxes are stacked so no line ever wraps.
    stacked = width < 84
    width = max(44, min(width, 140))
    if stacked:
        half = other = width
    else:
        half = (width - 1) // 2
        other = width - 1 - half

    def place(left: list[str], right: list[str]) -> list[str]:
        return left + right if stacked else side_by_side(left, right, half)
    sw = half - 4
    conn, chan, traffic, res, hist, nicks = (snap[k] for k in ("conn", "chan", "traffic", "res", "hist", "nicks"))
    rate = traffic["rate"]

    title = fg(MAGENTA, "▓▒░ ") + fg(CYAN, "CRPTOCHAT", bold=True) + fg(MAGENTA, " ░▒▓") + fg(DIM, f" relay v{snap['version']}")
    status = (fg(GREEN, "● ONLINE", bold=True) + fg(DIM, "  uptime ") + fg(TEXT, human_time(snap["uptime"]))
              + "  " + (fg(GREEN, "TLS") if snap["tls"] else fg(YELLOW, "SEM TLS")))
    if vlen(title) + 1 + vlen(status) <= width:
        out = [title + " " * (width - vlen(title) - vlen(status)) + status, ""]
    else:
        out = [fit(title, width), fit(status, width), ""]

    connections = box("CONEXÕES", [
        row("sessões autenticadas", conn["auth"], CYAN),
        row("sessões anônimas", conn.get("guests", 0)),
        row("pico de sessões", conn["peak"]),
        row("conexões aceitas", conn["accepted"]),
        row("falhas de autenticação", conn["auth_fail"], MAGENTA if conn["auth_fail"] else TEXT),
        row("expulsões / banimentos", f"{conn.get('kicks', 0)} / {conn.get('bans', 0)}"),
        fg(DIM, f"sessões · últimos {len(hist.get('auth', []))}s"),
        spark(hist.get("auth", []), sw, CYAN),
    ], half, CYAN)

    flow = box("TRÁFEGO CIFRADO", [
        row("msgs de canal /s", rate["msgs"], CYAN),
        row("envelopes diretos /s", rate["directs"], CYAN),
        row("entrada / saída", f"{human_bytes(rate['in'])}/s · {human_bytes(rate['out'])}/s"),
        row("msgs de canal (total)", traffic["chan_msgs"]),
        row("envelopes diretos", traffic["directs"]),
        row("bloqueios por taxa", traffic["rate_limited"], MAGENTA if traffic["rate_limited"] else TEXT),
        fg(DIM, f"envelopes/s · últimos {len(hist.get('msgs', []))}s"),
        spark(hist.get("msgs", []), other - 4, MAGENTA),
    ], other, MAGENTA)
    out += place(connections, flow)

    buckets = chan["buckets"]
    top = max(buckets) or 1
    bw = max(4, sw - 14)
    occupancy = [fg(DIM, f"{label:<9}") + bar(count / top, bw, PURPLE) + fg(TEXT, f" {count}", bold=True)
                 for label, count in zip(("1 pessoa", "2 a 5", "6 a 20", "21+"), buckets)]
    channels = box("CANAIS E NICKS", [
        row("canais registrados", f"{chan['registered']}  ({chan['open']} abertos · {chan['private']} privados)"),
        row("canais com gente agora", chan["active"], CYAN),
        row("maior canal agora", f"{chan['largest']} online"),
        row("nicks registrados", f"{nicks['registered']}  (+{nicks['new']} nesta execução)"),
        fg(DIM, "ocupação dos canais ativos"),
        *occupancy,
    ], half, PURPLE)

    cpu_frac = res.get("cpu", 0) / 100
    mem_total = res.get("mem_total") or 1
    used = mem_total - res.get("mem_avail", 0)
    rw = max(4, other - 4 - 31)
    resources = box("RECURSOS", [
        fg(DIM, f"{'CPU do relay':<15}") + bar(cpu_frac, rw, GREEN if cpu_frac < 0.7 else MAGENTA)
        + fg(TEXT, f" {res.get('cpu', 0):5.1f}%", bold=True),
        fg(DIM, f"{'RAM do host':<15}") + bar(used / mem_total, rw, GREEN if used / mem_total < 0.85 else MAGENTA)
        + fg(TEXT, f" {used / mem_total * 100:5.1f}%", bold=True),
        row("memória do relay", human_bytes(res.get("rss", 0)), CYAN),
        row("descritores / threads", f"{res.get('fds', 0)} / {res.get('threads', 0)}"),
        row("load do host", "  ".join(f"{x:.2f}" for x in res.get("load", [])) + f"  ({res.get('ncpu', 1)} cpu)"),
        row("atraso do event loop", f"{res.get('lag_ms', 0)} ms",
            MAGENTA if res.get("lag_ms", 0) > 100 else TEXT),
        row("registro em disco", human_bytes(res.get("db_bytes", 0))),
        fg(DIM, f"CPU % · últimos {len(hist.get('cpu', []))}s"),
        spark(hist.get("cpu", []), other - 4, GREEN),
    ], other, GREEN)
    out += place(channels, resources)

    note = " só contagens agregadas: sem nicks, nomes de canal, IPs ou conteúdo"
    out += ["", fit(fg(DIM, note), width), fit(fg(DIM, " ") + fg(CYAN, "q") + fg(DIM, " sair"), width)]
    if height and len(out) > height:
        # A frame taller than the screen scrolls and pushes the title off the
        # top: drop the spacing, then the footnote, then cut what is left.
        out = [line for line in out if line]
        if len(out) > height:
            del out[-2]
        if len(out) > height:
            out = out[:height - 1] + [fit(fg(DIM, " ↓ aumente a janela para ver o restante · ") + fg(CYAN, "q")
                                          + fg(DIM, " sair"), width)]
    return "\n".join(out)


def read_snapshots(path: str):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return sock


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="crptochat-dash", description="Painel do operador do crptochat-server (só contagens agregadas)")
    ap.add_argument("--data", default="./crptochat-data", help="diretório de dados do servidor (o mesmo do --data dele)")
    ap.add_argument("--socket", help="caminho do socket de estatísticas (padrão: <data>/stats.sock)")
    ap.add_argument("--once", action="store_true", help="imprime um quadro e sai")
    ap.add_argument("--json", action="store_true", help="imprime um snapshot JSON e sai (para scripts/monitoramento)")
    args = ap.parse_args(argv)
    path = args.socket or socket_path(args.data)
    try:
        sock = read_snapshots(path)
    except OSError as exc:
        sys.exit(f"não foi possível conectar em {path}: {exc}\n"
                 "o servidor está rodando com esse --data? O painel só funciona para o mesmo usuário do servidor.")
    stream = sock.makefile("rb")

    if args.json or args.once:
        line = stream.readline()
        print(line.decode().strip() if args.json else render(json.loads(line), shutil.get_terminal_size().columns))
        return

    import termios
    import tty
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd) if sys.stdin.isatty() else None
    sys.stdout.write("\033[?1049h\033[?25l")
    try:
        if saved:
            tty.setcbreak(fd)
        while True:
            ready, _, _ = select.select([sock] + ([sys.stdin] if saved else []), [], [], 5)
            if sys.stdin in ready and os.read(fd, 32).lower().startswith((b"q", b"\x1b", b"\x03")):
                break
            if sock in ready:
                line = stream.readline()
                if not line:
                    raise ConnectionError
                size = shutil.get_terminal_size()
                frame = render(json.loads(line), size.columns, size.lines)
                sys.stdout.write("\033[H" + frame.replace("\n", "\033[K\n") + "\033[K\033[J")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    except (ConnectionError, OSError, ValueError):
        saved_msg = "conexão com o servidor encerrada"
    else:
        saved_msg = ""
    finally:
        sys.stdout.write("\033[?25h\033[?1049l")
        sys.stdout.flush()
        if saved:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    if locals().get("saved_msg"):
        print(saved_msg)


if __name__ == "__main__":
    main()
