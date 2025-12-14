@echo off
setlocal
cd /d %~dp0

if not exist .venv (
  echo [1/3] Creation de l'environnement virtuel...
  python -m venv .venv
)

echo [2/3] Activation de l'environnement...
call .venv\Scripts\activate

echo [3/3] Installation des dependances...
pip install -r backend\requirements.txt

echo.
echo Lancement du serveur sur http://127.0.0.1:8000
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
pause
