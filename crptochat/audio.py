"""Voice messages: record from the microphone and play back.

Recording and playback are delegated to whatever tool the machine has
(ffmpeg, PulseAudio, PipeWire or ALSA utilities). Clips only touch a tmpfs
runtime directory for the few seconds a tool needs them, then are wiped;
the conversation itself keeps them in RAM only.

Overrides for unusual setups:
  CRPTOCHAT_REC_CMD   e.g. "arecord -q -D hw:1 -f MU_LAW -r 8000 -t wav {out}"
  CRPTOCHAT_PLAY_CMD  e.g. "mpv --no-video {file}"
"""

from __future__ import annotations

import asyncio
import os
import random
import shlex
import shutil
import signal
import tempfile
import time

MAX_SECONDS = 90
MAX_BYTES = 1_500_000
FORMATS = ("ogg", "wav")

_OPUS = ["-ac", "1", "-ar", "16000", "-c:a", "libopus", "-b:a", "20k", "-application", "voip"]
_FFMPEG = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-y"]

# (binary, argv with {out}, container)
RECORDERS = [
    ("ffmpeg", _FFMPEG + ["-f", "pulse", "-i", "default", *_OPUS, "-t", str(MAX_SECONDS), "{out}"], "ogg"),
    ("ffmpeg", _FFMPEG + ["-f", "alsa", "-i", "default", *_OPUS, "-t", str(MAX_SECONDS), "{out}"], "ogg"),
    ("parecord", ["parecord", "--rate=8000", "--channels=1", "--format=ulaw", "--file-format=wav", "{out}"], "wav"),
    ("pw-record", ["pw-record", "--rate", "8000", "--channels", "1", "--format", "s16", "{out}"], "wav"),
    ("arecord", ["arecord", "-q", "-f", "MU_LAW", "-r", "8000", "-c", "1", "-t", "wav",
                 "-d", str(MAX_SECONDS), "{out}"], "wav"),
]

PLAYERS = [
    ("ffplay", ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", "{file}"], FORMATS),
    ("mpv", ["mpv", "--no-video", "--really-quiet", "{file}"], FORMATS),
    ("paplay", ["paplay", "{file}"], FORMATS),
    ("pw-play", ["pw-play", "{file}"], FORMATS),
    ("aplay", ["aplay", "-q", "{file}"], ("wav",)),
]


class AudioError(Exception):
    pass


def sniff(data: bytes) -> str | None:
    """Identify the container from magic bytes; anything else is refused."""
    if data[:4] == b"OggS":
        return "ogg"
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    return None


def _runtime_dir() -> str:
    # files are created with mkstemp (exclusive, 0600); RAM-backed dirs keep audio off the disk
    for base in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm"):  # nosec B108
        if base and os.path.isdir(base) and os.access(base, os.W_OK):
            return base
    return tempfile.gettempdir()


def _scratch(suffix: str) -> str:
    fd, path = tempfile.mkstemp(prefix="crptochat-", suffix=suffix, dir=_runtime_dir())
    os.close(fd)
    return path


def _wipe(path: str) -> None:
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\0" * size)
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


async def _spawn(argv: list[str]) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL, start_new_session=True)


def _candidates(table, env: str, key: str, fmt: str | None = None):
    custom = os.environ.get(env)
    if custom:
        argv = shlex.split(custom)
        ext = os.environ.get("CRPTOCHAT_REC_FMT") or ("ogg" if any(a.endswith(".ogg}") for a in argv) else None)
        yield argv, ext
        return
    for binary, argv, kind in table:
        if shutil.which(binary) and (fmt is None or fmt in kind):
            yield argv, kind if isinstance(kind, str) else None


def can_mask() -> bool:
    return shutil.which("ffmpeg") is not None


async def process(data: bytes, mask: bool) -> bytes:
    """Prepare a recording for sending.

    Always (when ffmpeg exists): re-encode to one uniform format and drop every
    metadata tag, so clips from different machines look alike.

    With ``mask``: also disguise the speaker. The voice is shifted by a random
    amount, then re-synthesised with a fixed robotic pitch (the phase of every
    FFT frame is zeroed), which throws away the original pitch and intonation;
    filters and loudness normalisation flatten room/microphone characteristics.
    This defeats recognition by ear and simple voice matching. It does not hide
    what is said, nor speech habits, accent or loud background sounds.
    """
    if not can_mask():
        if mask:
            raise AudioError("a proteção de voz precisa do ffmpeg instalado; "
                             "instale-o ou desative com /voice natural (expõe a sua voz)")
        return data
    filters = ["aresample=16000", "highpass=f=100", "lowpass=f=3800"]
    if mask:
        rng = random.SystemRandom()
        factor = rng.choice((rng.uniform(0.72, 0.86), rng.uniform(1.16, 1.32)))
        filters += [
            "afftdn=nf=-25",
            f"asetrate=16000*{factor:.4f}", "aresample=16000", f"atempo={1 / factor:.4f}",
            "afftfilt=real='hypot(re,im)*cos(0)':imag='hypot(re,im)*sin(0)':win_size=512:overlap=0.75",
        ]
    filters += ["dynaudnorm=f=200:g=11:m=30", "alimiter=limit=0.9"]
    src, dst = _scratch("." + (sniff(data) or "wav")), _scratch(".ogg")
    try:
        with open(src, "wb") as fh:
            fh.write(data)
        proc = await _spawn(_FFMPEG + ["-i", src, "-map_metadata", "-1", "-map_chapters", "-1", "-vn",
                                       "-af", ",".join(filters), *_OPUS,
                                       "-fflags", "+bitexact", "-flags:a", "+bitexact", dst])
        try:
            code = await asyncio.wait_for(proc.wait(), 60)
        except asyncio.TimeoutError:
            proc.kill()
            code = 1
        with open(dst, "rb") as fh:
            out = fh.read(MAX_BYTES + 1)
    except OSError:
        code, out = 1, b""
    finally:
        _wipe(src)
        _wipe(dst)
    if code != 0 or sniff(out) != "ogg" or len(out) > MAX_BYTES:
        # Fail closed: never fall back to sending the untouched recording.
        raise AudioError("falha ao processar o áudio; nada foi enviado")
    return out


class Recorder:
    def __init__(self):
        self.proc: asyncio.subprocess.Process | None = None
        self.path = ""
        self.started = 0.0

    @property
    def active(self) -> bool:
        return self.proc is not None

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started if self.proc else 0.0

    async def start(self) -> None:
        if self.proc:
            raise AudioError("já existe uma gravação em andamento")
        tried = False
        for argv, fmt in _candidates(RECORDERS, "CRPTOCHAT_REC_CMD", "{out}"):
            tried = True
            path = _scratch("." + (fmt or "wav"))
            try:
                proc = await _spawn([a.replace("{out}", path) for a in argv])
            except OSError:
                _wipe(path)
                continue
            try:  # a recorder that dies right away has no usable input device
                await asyncio.wait_for(proc.wait(), 0.6)
                _wipe(path)
                continue
            except asyncio.TimeoutError:
                self.proc, self.path, self.started = proc, path, time.monotonic()
                return
        raise AudioError(
            "não foi possível acessar o microfone" if tried else
            "nenhum gravador encontrado: instale ffmpeg, pulseaudio-utils, pipewire ou alsa-utils")

    async def _finish(self) -> None:
        proc, self.proc = self.proc, None
        if proc and proc.returncode is None:
            try:
                proc.send_signal(signal.SIGINT)  # lets the tool close the file properly
                await asyncio.wait_for(proc.wait(), 5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

    async def stop(self) -> tuple[bytes, str, float]:
        """Stop and return (data, format, seconds)."""
        if not self.proc:
            raise AudioError("nenhuma gravação em andamento")
        seconds = min(self.elapsed, MAX_SECONDS)
        await self._finish()
        try:
            with open(self.path, "rb") as fh:
                data = fh.read(MAX_BYTES + 1)
        except OSError:
            data = b""
        finally:
            _wipe(self.path)
        fmt = sniff(data)
        if not fmt or len(data) < 64:
            raise AudioError("a gravação saiu vazia (microfone mudo ou sem permissão?)")
        if len(data) > MAX_BYTES:
            raise AudioError("áudio longo demais")
        return data, fmt, seconds

    async def cancel(self) -> None:
        if self.proc:
            await self._finish()
            _wipe(self.path)


class Player:
    def __init__(self):
        self.proc: asyncio.subprocess.Process | None = None

    @property
    def active(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def stop(self) -> None:
        if self.active:
            try:
                self.proc.terminate()
            except ProcessLookupError:
                pass

    async def play(self, data: bytes) -> None:
        fmt = sniff(data)
        if not fmt:
            raise AudioError("formato de áudio não reconhecido")
        self.stop()
        path = _scratch("." + fmt)
        try:
            with open(path, "wb") as fh:
                fh.write(data)
            tried = False
            for argv, _ in _candidates(PLAYERS, "CRPTOCHAT_PLAY_CMD", "{file}", fmt):
                tried = True
                try:
                    proc = self.proc = await _spawn([a.replace("{file}", path) for a in argv])
                except OSError:
                    continue
                started = time.monotonic()
                code = await proc.wait()
                if code == 0 or code < 0 or time.monotonic() - started > 1.0:
                    return  # played, or stopped by the user
            raise AudioError(
                "não foi possível reproduzir o áudio" if tried else
                "nenhum player encontrado: instale ffmpeg (ffplay), mpv, pulseaudio-utils ou alsa-utils")
        finally:
            _wipe(path)
