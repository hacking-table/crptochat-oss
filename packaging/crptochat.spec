# -*- mode: python ; coding: utf-8 -*-
# Build from the repository root:
#   pyinstaller --noconfirm --clean packaging/crptochat.spec

import os

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

spec_dir = os.path.dirname(os.path.abspath(SPEC))
repo_root = os.path.dirname(spec_dir)

# Data/CSS from Textual, native libs from cryptography. Do not ship
# third-party .py files as datas (the app itself is included as bytecode).
datas = collect_data_files("textual")
binaries = collect_dynamic_libs("cryptography")
hiddenimports = (
    collect_submodules("textual")
    + collect_submodules("rich")
    + collect_submodules("cryptography")
    + [
        "crptochat",
        "crptochat.cli",
        "crptochat.client",
        "crptochat.tui",
        "crptochat.audio",
        "crptochat.p2p",
        "crptochat.crypto",
        "crptochat.protocol",
        "crptochat.store",
        "crptochat.vault",
        "crptochat.themes",
        "crptochat.update",
    ]
)

# Keep the server and operator dash out of the client binary.
excludes = [
    "crptochat.server",
    "crptochat.dash",
    "crptochat.stats",
    "crptochat.admin",
]

a = Analysis(
    [os.path.join(spec_dir, "client_entry.py")],
    pathex=[repo_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="crptochat",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
