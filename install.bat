@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON_BIN=py"
    set "PYTHON_ARGS=-3"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PYTHON_BIN=python"
        set "PYTHON_ARGS="
    ) else (
        echo Python 3.11+ was not found. Please install Python and try again.
        exit /b 1
    )
)

echo Using Python: %PYTHON_BIN% %PYTHON_ARGS%

%PYTHON_BIN% %PYTHON_ARGS% -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo Tkinter is not available in this Python installation.
    echo On Windows, install Python from python.org with the bundled Tcl/Tk option enabled.
    echo Then re-run this installer.
    exit /b 1
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating virtual environment at %VENV_DIR%
    %PYTHON_BIN% %PYTHON_ARGS% -m venv "%VENV_DIR%"
    if errorlevel 1 exit /b 1
)

"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip setuptools
if errorlevel 1 exit /b 1

"%VENV_DIR%\Scripts\pip.exe" install -e "%SCRIPT_DIR%"
if errorlevel 1 exit /b 1

echo.
echo Installation complete.
echo CLI: %VENV_DIR%\Scripts\threatmod.exe
echo GUI: %VENV_DIR%\Scripts\threatmod-gui.exe
echo.
echo Direct repo launcher: %SCRIPT_DIR%threatmod-gui.bat
echo Tkinter check passed.
endlocal
