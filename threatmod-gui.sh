#!/bin/sh

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHONPATH="$SCRIPT_DIR/src" python -m threatmod_automation.gui "$@"
