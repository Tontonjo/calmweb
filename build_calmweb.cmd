@echo off
setlocal

:: Repository root (folder containing this script)
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

:: Try to locate PyInstaller; fall back to common Microsoft Store locations
set "PYINSTALLER="
for /f "delims=" %%I in ('where pyinstaller 2^>nul') do (
  set "PYINSTALLER=%%I"
  goto :found_pyinstaller
)
:found_pyinstaller
if not defined PYINSTALLER (
  set "PYINSTALLER=%USERPROFILE%\\AppData\\Local\\Packages\\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\\LocalCache\\local-packages\\Python312\\Scripts\\pyinstaller.exe"
)

if not exist "%PYINSTALLER%" (
  set "PYINSTALLER=%LOCALAPPDATA%\\Python\\pythoncore-3.14-64\\Scripts\\pyinstaller.exe"
)

if not exist "%PYINSTALLER%" (
  echo PyInstaller not found at "%PYINSTALLER%".
  echo Install it with:  py -3 -m pip install --user pyinstaller
  echo or with your Python version:  py -3.14 -m pip install --user pyinstaller
  pause
  exit /b 1
)

set "ICON_PNG=%REPO_ROOT%\\ressources\\calmweb.png"
set "ICON_ICO=%REPO_ROOT%\\ressources\\calmweb.ico"
set "ICON_SWITCH="
if /i "%NO_ICON%"=="1" (
  echo NO_ICON=1 set: skipping icon.
) else (
  if exist "%ICON_ICO%" (
    set "ICON_SWITCH=--icon ""%ICON_ICO%"""
  ) else if exist "%ICON_PNG%" (
    set "ICON_SWITCH=--icon ""%ICON_PNG%"""
    echo Using PNG icon. If PyInstaller errors, install Pillow:  py -3.14 -m pip install --user pillow
  ) else (
    echo No icon found; skipping icon. Set NO_ICON=1 to suppress this message.
  )
)
set "ENTRY=%REPO_ROOT%\\program\\calmweb_installer.py"
set "DIST_DIR=%REPO_ROOT%\\dist"
set "DIST_EXE=%DIST_DIR%\\calmweb_installer.exe"
set "BUILD_SWITCH=--onefile"
set "RUNTIME_SWITCH="

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

:: Allow forcing onedir build to avoid PyInstaller temp unpack/cleanup warnings: set ONEDIR=1 before running
if /i "%ONEDIR%"=="1" (
  set "BUILD_SWITCH=--onedir"
  set "RUNTIME_SWITCH="
)

:: Best effort: remove previous exe so PyInstaller can overwrite (avoids WinError 5 if locked)
if exist "%DIST_EXE%" (
  del /f /q "%DIST_EXE%" >nul 2>&1
)

"%PYINSTALLER%" ^
  --clean ^
  --hidden-import urllib3 ^
  --hidden-import tkinter ^
  --hidden-import tkinter.scrolledtext ^
  %BUILD_SWITCH% ^
  --noconsole ^
  --uac-admin ^
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
echo Build complete. Output: "%DIST_DIR%\\calmweb_installer.exe"
pause
