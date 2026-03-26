@echo off
echo Starting AI Secure Data Intelligence Platform...
echo.

REM Start Backend
echo [1/2] Starting FastAPI backend on http://localhost:8000
cd /d "%~dp0backend"

if not exist ".env" (
    echo     WARNING: .env not found. Copying from .env.example...
    copy .env.example .env
)

if not exist "venv" (
    echo     Creating Python virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat
pip install -r requirements.txt -q

start "FastAPI Backend" cmd /k "venv\Scripts\activate && uvicorn main:app --reload --port 8000"

REM Start Frontend
echo [2/2] Starting React frontend on http://localhost:3000
cd /d "%~dp0frontend"

if not exist "node_modules" (
    echo     Installing npm packages...
    npm install
)

start "React Frontend" cmd /k "npm run dev"

echo.
echo Both services starting in separate windows.
echo   Backend API: http://localhost:8000
echo   Frontend UI: http://localhost:3000
echo   API Docs:    http://localhost:8000/docs
echo.
pause
