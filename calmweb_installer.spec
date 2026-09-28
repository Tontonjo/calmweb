# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\scripts\\..\\scripts\\pyinstaller_entry.py'],
    pathex=['C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\scripts\\..\\src'],
    binaries=[],
    datas=[('C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\scripts\\..\\resources\\calmweb.png', '.'), ('C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\scripts\\..\\resources\\calmweb_active.png', '.'), ('C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\scripts\\..\\VERSION', '.')],
    hiddenimports=['urllib3', 'tkinter', 'tkinter.scrolledtext'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='calmweb_installer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\Users\\lilyb\\Desktop\\CalmWeb\\calmweb\\resources\\calmweb.ico'],
)
