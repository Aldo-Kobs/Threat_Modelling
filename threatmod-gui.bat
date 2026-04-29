@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "VENV_PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"

if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" -m threatmod_automation.gui %*
) else (
    set "PYTHONPATH=%SCRIPT_DIR%src"
    where py >nul 2>nul
    if %errorlevel%==0 (
        py -3 -m threatmod_automation.gui %*
    ) else (
        python -m threatmod_automation.gui %*
    )
)

endlocal

