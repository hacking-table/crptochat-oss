"""Colour themes for the chat interface.

A theme fills a fixed set of slots. The slot names come from the original
neon theme (CYAN is "the primary accent", MAGENTA "the frame colour", and so
on); other themes put their own colours in the same slots.
"""

from __future__ import annotations

import colorsys

SLOTS = ("BG", "PANEL", "CYAN", "MAGENTA", "PINK", "YELLOW", "GREEN", "PURPLE", "ORANGE", "DIM", "TEXT")
DEFAULT = "neon"


def _sweep(hue_from: float, hue_to: float, sat: float, light_from: float, light_to: float) -> list[str]:
    """Ten nickname colours spread over a hue range (degrees)."""
    out = []
    for i in range(10):
        f = i / 9
        hue = ((hue_from + (hue_to - hue_from) * f) % 360) / 360
        # alternate lightness a little so neighbours are easier to tell apart
        light = light_from + (light_to - light_from) * (f if i % 2 == 0 else 1 - f)
        r, g, b = colorsys.hls_to_rgb(hue, light, sat)
        out.append(f"#{round(r * 255):02x}{round(g * 255):02x}{round(b * 255):02x}")
    return out


#        name: (label, description, slot values..., nick colours)
THEMES = {
    "neon": ("Neon", "ciano e magenta sobre preto azulado (padrão)",
             ("#07070f", "#0c0c1a", "#00f0ff", "#ff2a6d", "#ff5fd2", "#fcee0a", "#39ff14", "#b967ff", "#ff9f1c",
              "#59618a", "#d5dcff"),
             ["#ff5fd3", "#fcee0b", "#39ff15", "#b968ff", "#ff9f1d", "#7df9ff", "#ff6b6b", "#9dff8a", "#ffd166",
              "#c77dff"]),
    "matrix": ("Matrix", "fósforo verde, estilo terminal antigo",
               ("#020a02", "#06140a", "#39ff14", "#00a83b", "#7dffb0", "#d4ff5a", "#00ff9c", "#2fbf71", "#a8e063",
                "#3d6b47", "#c8f7d0"), _sweep(70, 170, 0.85, 0.55, 0.72)),
    "synthwave": ("Synthwave", "rosa, roxo e pôr do sol dos anos 80",
                  ("#140a24", "#1d1033", "#ff7edb", "#7b5cff", "#ff9e64", "#ffe261", "#72f1b8", "#b893ff", "#ff8b39",
                   "#6d5a8c", "#f0e6ff"), _sweep(250, 400, 0.9, 0.68, 0.78)),
    "ambar": ("Âmbar", "monitor de fósforo âmbar",
              ("#0d0800", "#171003", "#ffb000", "#c46a00", "#ffd27a", "#fff1a8", "#e8c547", "#d98e04", "#ff7b00",
               "#7a5a1e", "#ffe2b0"), _sweep(18, 58, 0.95, 0.55, 0.75)),
    "gelo": ("Gelo", "azuis frios e ciano claro",
             ("#060b14", "#0c1422", "#7fd4ff", "#3b82f6", "#a5b4fc", "#e0f2fe", "#5eead4", "#818cf8", "#93c5fd",
              "#4b607a", "#dbeafe"), _sweep(170, 255, 0.85, 0.66, 0.8)),
    "sangue": ("Sangue", "vermelhos e laranjas sobre preto",
               ("#0c0304", "#16070a", "#ff3b3b", "#a3122b", "#ff8a8a", "#ffb86b", "#ff6f59", "#c2410c", "#f97316",
                "#6b3038", "#ffdada"), _sweep(335, 400, 0.9, 0.6, 0.76)),
    "mono": ("Mono", "preto e branco de alto contraste",
             ("#000000", "#0d0d0d", "#ffffff", "#9a9a9a", "#d4d4d4", "#fafafa", "#e5e5e5", "#bdbdbd", "#cfcfcf",
              "#6e6e6e", "#ededed"), _sweep(0, 0, 0.0, 0.58, 0.93)),
    "papel": ("Papel", "tema claro, para ambientes iluminados",
              ("#f4f1ea", "#e8e3d8", "#005f73", "#9b2226", "#ae2012", "#7a5c00", "#2d6a4f", "#5a189a", "#bb3e03",
               "#8a8577", "#1f1d1a"), _sweep(0, 320, 0.75, 0.3, 0.38)),
}


def _distinct(colours: list[str]) -> list[str]:
    """Every colour of a theme must be unique so that text already on screen
    can be recoloured unambiguously when the theme changes."""
    seen, out = set(), []
    for colour in colours:
        value = int(colour[1:], 16)
        while f"#{value:06x}" in seen:
            value = value + 1 if value & 0xFF < 0xFF else value - 1
        seen.add(f"#{value:06x}")
        out.append(f"#{value:06x}")
    return out


def palette(name: str) -> tuple[dict[str, str], list[str]]:
    """({slot: colour}, [10 nickname colours]) for a theme."""
    _, _, slots, nicks = THEMES.get(name) or THEMES[DEFAULT]
    flat = _distinct(list(slots) + list(nicks))
    return dict(zip(SLOTS, flat[:len(SLOTS)])), flat[len(SLOTS):]


def is_dark(name: str) -> bool:
    background = palette(name)[0]["BG"]
    return sum(int(background[i:i + 2], 16) for i in (1, 3, 5)) < 384
