@echo off
REM H4ACKBAR launcher (Windows)
cd /d "%~dp0.."

if not exist ".venv" (
    echo [+] creating venv
    python -m venv .venv
)

call .venv\Scripts\activate.bat

python -c "import PyQt6" 2>NUL
if errorlevel 1 (
    echo [+] installing deps
    pip install -e . >NUL
)

python -m h4ackbar %*
