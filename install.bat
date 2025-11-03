@echo off
echo ===============================================
echo     Installation de CalmWeb
echo ===============================================
echo.

echo Verification de Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH
    echo Veuillez installer Python depuis https://python.org
    echo Cochez "Add Python to PATH" lors de l'installation
    pause
    exit /b 1
)
echo [OK] Python detecte

echo.
echo Installation des dependances Python...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERREUR] Echec installation des dependances
    pause
    exit /b 1
)
echo [OK] Dependances installees

echo.
echo Le repertoire et la configuration seront crees automatiquement au premier lancement...
echo [OK] Configuration automatique

echo.
echo ===============================================
echo Installation terminee !
echo ===============================================
echo.
echo Pour lancer CalmWeb :
echo 1. Double-cliquez sur "Lancer CalmWeb.bat"
echo 2. Ou executez : python program\calmweb.py
echo.
pause