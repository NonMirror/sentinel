"""Catppuccin Frappé 配色 (与参考主题 catppuccin-frappe.theme 完全一致).

    crust      #232634      base       #303446      text     #c6d0f5
    mantle     #292c3c      surface0   #414559      subtext1 #b5bfe2
    surface1   #51576d      surface2   #626880      subtext0 #a5adce
"""
from __future__ import annotations

from textual.theme import Theme

# ---- 原始调色板 ----
ROSEWATER = "#f2d5cf"
FLAMINGO = "#eebebe"
PINK = "#f4b8e4"
MAUVE = "#ca9ee6"
RED = "#e78284"
MAROON = "#ea999c"
PEACH = "#ef9f76"
YELLOW = "#e5c890"
GREEN = "#a6d189"
TEAL = "#81c8be"
SKY = "#99d1db"
SAPPHIRE = "#85c1dc"
BLUE = "#8caaee"
LAVENDER = "#babbf1"
WHITE = "#c6d0f5"
TEXT = "#c6d0f5"
SUBTEXT1 = "#b5bfe2"
SUBTEXT0 = "#a5adce"
OVERLAY2 = "#949cbb"
OVERLAY1 = "#838ba7"
OVERLAY0 = "#737994"
SURFACE2 = "#626880"
SURFACE1 = "#51576d"
SURFACE0 = "#414559"
BASE = "#303446"
MANTLE = "#292c3c"
CRUST = "#232634"

# ---- 语义映射 ----
BG = BASE
PANEL = MANTLE
DEEP = CRUST
BORDER = SURFACE1
BORDER_SOFT = SURFACE0
FG = TEXT
FG_MUTED = SUBTEXT0
FG_DIM = OVERLAY0
ACCENT = SAPPHIRE      # 主强调色 (界面高亮)
ACCENT2 = BLUE         # 次强调色
SUCCESS = GREEN
WARNING = YELLOW
DANGER = RED
INFO = SKY
MAGENTA = MAUVE
ORANGE = PEACH

SEVERITY = {"critical": RED, "high": PEACH, "medium": YELLOW, "low": SKY, "info": OVERLAY1}

THEME_NAME = "catppuccin-frappe"


def frappe() -> Theme:
    """Textual 主题注册对象 (让内置组件也使用 Frappé 配色)."""
    return Theme(
        name=THEME_NAME,
        primary=SAPPHIRE,
        secondary=MAUVE,
        accent=SKY,
        foreground=TEXT,
        background=BASE,
        success=GREEN,
        warning=YELLOW,
        error=RED,
        surface=SURFACE0,
        panel=MANTLE,
        dark=True,
        variables={
            "crust": CRUST,
            "mantle": MANTLE,
            "base": BASE,
            "surface0": SURFACE0,
            "surface1": SURFACE1,
            "surface2": SURFACE2,
            "overlay0": OVERLAY0,
            "overlay1": OVERLAY1,
            "overlay2": OVERLAY2,
            "subtext0": SUBTEXT0,
            "subtext1": SUBTEXT1,
            "text": TEXT,
            "rosewater": ROSEWATER,
            "flamingo": FLAMINGO,
            "pink": PINK,
            "mauve": MAUVE,
            "red": RED,
            "maroon": MAROON,
            "peach": PEACH,
            "yellow": YELLOW,
            "green": GREEN,
            "teal": TEAL,
            "sky": SKY,
            "sapphire": SAPPHIRE,
            "blue": BLUE,
            "lavender": LAVENDER,
        },
    )
