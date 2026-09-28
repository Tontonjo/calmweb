@echo off
setlocal

:: Repository root (folder containing this script's parent)
set "REPO_ROOT=%~dp0.."
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

REM --- Extract version from pyproject.toml ---
for /f "tokens=2 delims== " %%V in ('findstr /R "^version" "%REPO_ROOT%\pyproject.toml"') do (
    set "APP_VERSION=%%~V"
)
echo [INFO] Version: %APP_VERSION%

:: Use PyInstaller via Python (no PATH needed)
set "PYINSTALLER=python -m PyInstaller"

set "ICON_PNG=%REPO_ROOT%\resources\calmweb_icon.png"
set "ICON_ICO=%REPO_ROOT%\resources\calmweb.ico"
set "ICON_SWITCH="
if /i "%NO_ICON%"=="1" (
  echo NO_ICON=1 set: skipping icon.
) else (
  if exist "%ICON_ICO%" (
    set "ICON_SWITCH=--icon "%ICON_ICO%""
  ) else if exist "%ICON_PNG%" (
    set "ICON_SWITCH=--icon "%ICON_PNG%""
    echo Using PNG icon. If PyInstaller errors, install Pillow:  pip install pillow
  ) else (
    echo No icon found; skipping icon. Set NO_ICON=1 to suppress this message.
  )
)

REM --- Locate the Tcl/Tk runtime data -----------------------------------
REM PyInstaller bundles Tcl/Tk as "_tcl_data" / "_tk_data" at the root of the
REM bundle. Two situations exist:
REM
REM  * Tcl/Tk 8.6 (Python <= 3.13): real folders on disk. A few Python
REM    installations confuse PyInstaller's hook, so we pass the folders
REM    explicitly -- harmless when the hook already found them.
REM  * Tcl/Tk 9 (Python 3.14+): the library lives in a zipfs archive inside
REM    the DLL and $tcl_library reads "//zipfs:/lib/tcl/tcl_library". There is
REM    nothing to copy, and only PyInstaller 6.22 or newer knows how to
REM    handle it. With an older PyInstaller the build succeeds but the app
REM    dies at startup with:
REM      FileNotFoundError: Tcl data directory "..._MEIxxxxx\_tcl_data" not found
set "TCL_DIR="
set "TK_DIR="
for /f "usebackq tokens=1,* delims=;" %%A in (`python -c "import tkinter;r=tkinter.Tk();r.withdraw();print(r.tk.exprstring('$tcl_library')+';'+r.tk.exprstring('$tk_library'));r.destroy()"`) do (
  set "TCL_DIR=%%A"
  set "TK_DIR=%%B"
)

set "TCL_SWITCH="
set "TK_SWITCH="
if exist "%TCL_DIR%\init.tcl" set "TCL_SWITCH=--add-data "%TCL_DIR%;_tcl_data""
if exist "%TK_DIR%\tk.tcl" set "TK_SWITCH=--add-data "%TK_DIR%;_tk_data""

echo [INFO] Tcl library: %TCL_DIR%
echo [INFO] Tk  library: %TK_DIR%

if defined TCL_SWITCH goto :tcl_ok

echo.
echo [INFO] Tcl/Tk data is embedded in the DLL (Tcl 9 / zipfs), not on disk.
echo [INFO] This requires PyInstaller 6.22 or newer. Current version:
python -m PyInstaller --version
echo [INFO] If the built app fails with: Tcl data directory ... _tcl_data not found
echo [INFO] then run:  python -m pip install --upgrade pyinstaller
echo.

:tcl_ok

set "ENTRY=%REPO_ROOT%\scripts\pyinstaller_entry.py"
set "DIST_DIR=%REPO_ROOT%\dist"
set "DIST_EXE=%DIST_DIR%\calmweb_installer.exe"
set "BUILD_SWITCH=--onefile"
set "RUNTIME_SWITCH="

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

:: Allow forcing onedir build: set ONEDIR=1 before running
if /i "%ONEDIR%"=="1" (
  set "BUILD_SWITCH=--onedir"
  set "RUNTIME_SWITCH="
)

:: Best effort: remove previous exe so PyInstaller can overwrite
if exist "%DIST_EXE%" (
  del /f /q "%DIST_EXE%" >nul 2>&1
)

:: Drop the previous work directory and generated spec. A build tree left
:: behind by an older PyInstaller is a common source of a frozen app that
:: builds fine but cannot start.
if exist "%REPO_ROOT%\build" rmdir /s /q "%REPO_ROOT%\build" >nul 2>&1
if exist "%REPO_ROOT%\scripts\calmweb_installer.spec" del /f /q "%REPO_ROOT%\scripts\calmweb_installer.spec" >nul 2>&1

REM --- Write VERSION file for PyInstaller bundle ---
echo %APP_VERSION%> "%REPO_ROOT%\VERSION"

REM --- Modules deliberately left out of the bundle -----------------------
REM Every name below was checked as unused by CalmWeb. Together they are
REM worth roughly 18 MB of the frozen bundle.
REM
REM  * numpy        : never imported by CalmWeb. It is dragged in because
REM                   PIL._typing references numpy.typing at module level,
REM                   and it arrives with a 6.4 MB OpenBLAS DLL.
REM  * PIL codecs   : the app only ever opens .ico and .png files.
REM                   _avif.pyd alone is 4.3 MB.
REM  * setuptools   : build-time only, never used at runtime.
REM  * pywin32 GUI  : Pythonwin\mfc140u.dll, 2.7 MB, unused since
REM                   get_exe_icon() was dropped.
REM
REM If a build ever fails to start after a dependency bump, drop these lines
REM one at a time -- a missing module shows up in the log as ImportError.
set "EXCLUDES="
for %%M in (
  numpy
  setuptools pkg_resources _distutils_hack distutils wheel
  PIL._avif PIL.AvifImagePlugin
  PIL._webp PIL.WebPImagePlugin
  PIL.ImageCms PIL._imagingcms
  PIL.ImageQt
  win32com win32comext win32ui pythonwin pywin
  unittest doctest pydoc_data xmlrpc test lib2to3
) do call set "EXCLUDES=%%EXCLUDES%% --exclude-module %%M"

%PYINSTALLER% ^
  --clean ^
  --optimize 2 ^
  %EXCLUDES% ^
  --name calmweb_installer ^
  --hidden-import urllib3 ^
  --hidden-import truststore ^
  --hidden-import certifi ^
  --hidden-import calmweb.net ^
  --hidden-import tkinter ^
  --hidden-import tkinter.scrolledtext ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.filedialog ^
  --hidden-import tkinter.messagebox ^
  --hidden-import darkdetect ^
  --hidden-import calmweb.gui ^
  --hidden-import calmweb.i18n ^
  --hidden-import calmweb.stats ^
  --collect-all customtkinter ^
  --add-data "%REPO_ROOT%\resources\calmweb_icon.png;." ^
  --add-data "%REPO_ROOT%\resources\calmweb_active.png;." ^
  --add-data "%REPO_ROOT%\resources\calmweb.ico;." ^
  --add-data "%REPO_ROOT%\resources\calmweb_active.ico;." ^
  --add-data "%REPO_ROOT%\VERSION;." ^
  %TCL_SWITCH% ^
  %TK_SWITCH% ^
  %BUILD_SWITCH% ^
  --noconsole ^
  --paths "%REPO_ROOT%\src" ^
  %RUNTIME_SWITCH% ^
  %ICON_SWITCH% ^
  --distpath "%DIST_DIR%" ^
  "%ENTRY%"

if %errorlevel% neq 0 (
  echo Build failed.
  pause
  exit /b %errorlevel%
)

echo.
echo Build complete. Output: "%DIST_EXE%"

:: --- Step 2: Build Inno Setup installer ---
echo.
echo Building installer package...

set "ISCC="
for /f "delims=" %%I in ('where iscc 2^>nul') do (
    set "ISCC=%%I"
    goto :found_iscc
)
:found_iscc
if not defined ISCC (
    if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
        set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    )
)

if not defined ISCC (
    echo.
    echo Inno Setup not found. Skipping installer package.
    echo Install from: https://jrsoftware.org/isinfo.php
    goto :done
)

"%ISCC%" /DMyAppVersion=%APP_VERSION% "%REPO_ROOT%\installer\calmweb.iss"

if %errorlevel% neq 0 (
    echo Installer build failed.
    pause
    exit /b %errorlevel%
)

echo.
echo Installer built: "%REPO_ROOT%\dist\CalmWeb_Setup.exe"

:: Clean up intermediate PyInstaller executable (bundled inside the Setup)
if exist "%DIST_EXE%" (
    del /f /q "%DIST_EXE%" >nul 2>&1
    echo Cleaned up intermediate file: calmweb_installer.exe
)

:done
pause
