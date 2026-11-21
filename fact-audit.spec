# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the fact-audit desktop UI.

Build:  uv run pyinstaller fact-audit.spec --noconfirm
Output: dist/fact-audit.exe
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
for package in ("flet", "flet_desktop"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    ["run_ui.py"],
    pathex=[str(Path(SPECPATH) / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="fact-audit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
