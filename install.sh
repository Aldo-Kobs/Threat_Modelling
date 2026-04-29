#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Python 3.11+ was not found. Please install Python and try again."
    exit 1
fi

echo "Using Python: $PYTHON_BIN"

if ! "$PYTHON_BIN" -c "import tkinter" >/dev/null 2>&1; then
    echo "Tkinter was not found for $PYTHON_BIN. Trying to install system Tk support."

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y python3-tk
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3-tkinter
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3-tkinter
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm tk
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y python3-tk
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add py3-tkinter
    else
        echo "Could not detect a supported package manager for Tkinter."
        echo "Please install the Tk package for your Python distribution and re-run this installer."
        exit 1
    fi

    if ! "$PYTHON_BIN" -c "import tkinter" >/dev/null 2>&1; then
        echo "Tkinter still is not available after installation attempt."
        exit 1
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools
"$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR"

echo
echo "Installation complete."
echo "CLI: $VENV_DIR/bin/threatmod"
echo "GUI: $VENV_DIR/bin/threatmod-gui"
echo
echo "Direct repo launcher: $SCRIPT_DIR/threatmod-gui.sh"
echo "Tkinter check passed."
