# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:/Users/Jo/Downloads/calmweb_jo/scripts/../resources/calmweb_icon.png', '.'), ('C:/Users/Jo/Downloads/calmweb_jo/scripts/../resources/calmweb_active.png', '.'), ('C:/Users/Jo/Downloads/calmweb_jo/scripts/../resources/calmweb.ico', '.'), ('C:/Users/Jo/Downloads/calmweb_jo/scripts/../resources/calmweb_active.ico', '.'), ('C:/Users/Jo/Downloads/calmweb_jo/scripts/../VERSION', '.')]
binaries = []
hiddenimports = ['urllib3', 'truststore', 'certifi', 'calmweb.net', 'tkinter', 'tkinter.scrolledtext', 'tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox', 'darkdetect', 'calmweb.gui', 'calmweb.i18n', 'calmweb.stats']
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:/Users/Jo/Downloads/calmweb_jo/scripts/../scripts/pyinstaller_entry.py'],
    pathex=['C:/Users/Jo/Downloads/calmweb_jo/scripts/../src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'setuptools', 'pkg_resources', '_distutils_hack', 'distutils', 'wheel', 'PIL._avif', 'PIL.AvifImagePlugin', 'PIL._webp', 'PIL.WebPImagePlugin', 'PIL.ImageCms', 'PIL._imagingcms', 'PIL.ImageQt', 'win32com', 'win32comext', 'win32ui', 'pythonwin', 'pywin', 'unittest', 'doctest', 'pydoc_data', 'xmlrpc', 'test', 'lib2to3'],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [('O', None, 'OPTION'), ('O', None, 'OPTION')],
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
    icon=['C:/Users/Jo/Downloads/calmweb_jo/scripts/../resources/calmweb.ico'],
)
