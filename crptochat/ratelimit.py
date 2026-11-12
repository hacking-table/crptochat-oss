"""Rate limits and anti-flood for the relay.

The server cannot read messages, so flood control only looks at who sends,
how often and how much. Limits are token buckets, per session and per IP
address, with lower limits for anonymous sessions. Breaking a limit is a
*strike*; strikes escalate: warning, temporary mute, then disconnection.

Every value is configurable at runtime from crptochat-admin
(`ratelimit show`, `ratelimit set NAME VALUE`) and persisted in the
registry database.
"""

from __future__ import annotations

import time
from collections import deque

#        name: (default, description)
SETTINGS = {
    # every frame, whatever it is (protocol-level safety net)
    "frame_rate": (40.0, "frames por segundo, por conexão"),
    "frame_burst": (400.0, "rajada de frames, por conexão"),
    # channel text messages
    "msg_rate": (3.0, "mensagens de canal por segundo (registrados)"),
    "msg_burst": (15.0, "rajada de mensagens de canal (registrados)"),
    "anon_msg_rate": (1.0, "mensagens de canal por segundo (anônimos)"),
    "anon_msg_burst": (5.0, "rajada de mensagens de canal (anônimos)"),
    # anonymous identities are free, so their messages are also capped per address
    # (registered users behind one NAT are not, they are held by reg_per_hour)
    "anon_ip_msg_rate": (3.0, "mensagens de canal por segundo somando os anônimos de um IP"),
    "anon_ip_msg_burst": (15.0, "rajada de mensagens de canal dos anônimos de um IP"),
    # bulky envelopes (voice messages): measured in KiB, so audio is not taken for flood
    "bulk_kbps": (512.0, "KiB/s de envelopes grandes (áudio), registrados"),
    "bulk_burst_kb": (3072.0, "rajada de KiB de envelopes grandes, registrados (cobre o maior áudio)"),
    "anon_bulk_kbps": (128.0, "KiB/s de envelopes grandes, anônimos"),
    "anon_bulk_burst_kb": (1024.0, "rajada de KiB de envelopes grandes, anônimos"),
    # direct envelopes: also carry channel keys (one per member when joining), so generous
    "direct_rate": (20.0, "envelopes diretos por segundo (registrados)"),
    "direct_burst": (400.0, "rajada de envelopes diretos (registrados)"),
    "anon_direct_rate": (5.0, "envelopes diretos por segundo (anônimos)"),
    "anon_direct_burst": (250.0, "rajada de envelopes diretos (anônimos)"),
    # joining and creating channels
    "join_per_min": (20.0, "entradas em canal por minuto (registrados)"),
    "join_burst": (50.0, "rajada de entradas (registrados; cobre a reconexão)"),
    "anon_join_per_min": (6.0, "entradas em canal por minuto (anônimos)"),
    "anon_join_burst": (10.0, "rajada de entradas (anônimos)"),
    # identities and connections
    "reg_per_hour": (5.0, "nicks novos registrados por IP por hora (0 = sem limite)"),
    "anon_per_ip": (5.0, "sessões anônimas simultâneas por IP"),
    "conns_per_ip": (32.0, "conexões simultâneas por IP (0 = sem limite)"),
    "max_body_kb": (64.0, "tamanho máximo de um envelope cifrado, em KiB"),
    # escalation
    "warn_after": (1.0, "infrações até o aviso"),
    "mute_after": (3.0, "infrações até o mute temporário"),
    "kick_after": (6.0, "infrações até a desconexão"),
    "strike_window": (60.0, "janela, em segundos, em que as infrações contam"),
    "mute_seconds": (60.0, "duração do mute, em segundos"),
    # files relayed through the server (end-to-end encrypted, streamed, never written to disk)
    "file_max_mb": (50.0, "tamanho máximo de um arquivo enviado pelo servidor, em MiB (0 = desliga o envio pelo servidor)"),
    "file_kbps": (2048.0, "banda de envio de arquivos por usuário registrado, em KiB/s"),
    "file_burst_kb": (8192.0, "rajada de envio de arquivos por usuário registrado, em KiB"),
    "anon_file_kbps": (256.0, "banda de envio de arquivos por anônimo, em KiB/s"),
    "anon_file_burst_kb": (1024.0, "rajada de envio de arquivos por anônimo, em KiB"),
    "file_concurrent": (4.0, "transferências simultâneas por usuário"),
    # history of private channels (off by default, turned on per channel)
    "history_max_days": (30.0, "máximo de dias que um canal privado pode guardar histórico"),
    "history_max_msgs": (100.0, "mensagens do histórico entregues ao entrar no canal"),
    "history_per_sender": (200.0, "mensagens de histórico guardadas por remetente em cada canal (as mais antigas saem)"),
    "history_keep_msgs": (1000.0, "mensagens guardadas por canal (as mais antigas saem antes do prazo)"),
    "flood_ban_minutes": (5.0, "ban de IP aplicado junto com a desconexão por flood, em minutos (0 = só desconecta)"),
    "ip_memory": (600.0, "segundos que as infrações e contadores de um IP ficam guardados depois que ele desconecta"),
    # what the server holds in memory for one connection that is not reading
    "out_queue_kb": (16384.0, "máximo em KiB esperando para ser enviado a uma conexão; acima disso ela é fechada"),
}
DEFAULTS = {name: value for name, (value, _) in SETTINGS.items()}


class Limits:
    def __init__(self, stored: dict | None = None):
        self.values = dict(DEFAULTS)
        for name, value in (stored or {}).items():
            if name in DEFAULTS and isinstance(value, (int, float)) and value >= 0:
                self.values[name] = float(value)

    def __getitem__(self, name: str) -> float:
        return self.values[name]

    def set(self, name: str, value) -> float:
        if name not in DEFAULTS:
            raise KeyError(name)
        value = float(value)
        if value < 0 or value != value or value > 1e9:
            raise ValueError(name)
        self.values[name] = value
        return value

    def reset(self, name: str | None = None) -> None:
        if name is None:
            self.values = dict(DEFAULTS)
        else:
            if name not in DEFAULTS:
                raise KeyError(name)
            self.values[name] = DEFAULTS[name]

    def changed(self) -> dict:
        return {k: v for k, v in self.values.items() if v != DEFAULTS[k]}

    def max_body(self) -> int:
        """Body size cap in base64 characters (what the protocol carries)."""
        return int(self["max_body_kb"] * 1024)


class Bucket:
    """Token bucket that reads its rate and size from Limits at every use,
    so changes made in the admin console apply to existing sessions."""

    __slots__ = ("limits", "rate", "burst", "per", "tokens", "stamp")

    def __init__(self, limits: Limits, rate: str, burst: str, per: float = 1.0):
        self.limits, self.rate, self.burst, self.per = limits, rate, burst, per
        self.tokens = limits[burst]
        self.stamp = time.monotonic()

    def take(self, cost: float = 1.0) -> bool:
        rate, burst = self.limits[self.rate] / self.per, self.limits[self.burst]
        if rate <= 0 and burst <= 0:
            return True                                  # 0/0 means "no limit"
        now = time.monotonic()
        self.tokens = min(burst, self.tokens + (now - self.stamp) * rate)
        self.stamp = now
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class Strikes:
    """Escalation for one session: warn -> mute -> kick."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.times: deque[float] = deque()
        self.muted_until = 0.0
        self.warned = False

    @property
    def muted(self) -> float:
        return max(0.0, self.muted_until - time.monotonic())

    def hit(self) -> str | None:
        """Record a violation. Returns 'warn', 'mute', 'kick' or None."""
        now = time.monotonic()
        window = self.limits["strike_window"]
        while self.times and now - self.times[0] > window:
            self.times.popleft()
        self.times.append(now)
        count = len(self.times)
        if self.limits["kick_after"] and count >= self.limits["kick_after"]:
            return "kick"
        if self.limits["mute_after"] and count >= self.limits["mute_after"] and not self.muted:
            self.muted_until = now + self.limits["mute_seconds"]
            return "mute"
        if count >= self.limits["warn_after"] and not self.warned:
            self.warned = True
            return "warn"
        return None


def remember(strikes: Strikes) -> dict:
    return {"times": list(strikes.times), "muted_until": strikes.muted_until, "warned": strikes.warned}


def recall(strikes: Strikes, memory: dict) -> None:
    """Seed a new session's escalation with what its address did before."""
    window = strikes.limits["strike_window"]
    now = time.monotonic()
    strikes.times = deque(t for t in memory["times"] if now - t <= window)
    strikes.muted_until = max(strikes.muted_until, memory["muted_until"])
    strikes.warned = strikes.warned or memory["warned"]


class SessionLimits:
    """All buckets of one session (created at login, when we know if it is anonymous)."""

    def __init__(self, limits: Limits, guest: bool):
        p = "anon_" if guest else ""
        self.msg = Bucket(limits, p + "msg_rate", p + "msg_burst")
        self.bulk = Bucket(limits, p + "bulk_kbps", p + "bulk_burst_kb")
        self.direct = Bucket(limits, p + "direct_rate", p + "direct_burst")
        self.join = Bucket(limits, p + "join_per_min", p + "join_burst", per=60.0)
        self.file = Bucket(limits, p + "file_kbps", p + "file_burst_kb")
