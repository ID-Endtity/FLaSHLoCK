#!/bin/bash
# Builds FlashLock.app as a symlink-free (portable) bundle.
#
# Why this exists: PyInstaller's onedir .app contains symlinks (inside
# Python.framework). Those work on APFS but break on FAT32/exFAT — so copying
# the app to a USB stick (FlashLock's whole use case) mangles it. This script
# resolves the symlinks into real files and strips the stale signature, so the
# resulting .app survives a copy to any filesystem.
#
# Usage: ./build.sh   (or: PYINSTALLER=/path/to/pyinstaller ./build.sh)

set -euo pipefail

NAME="FlashLock"
ENTRY="flashlock_frontend.py"
PYINSTALLER="${PYINSTALLER:-$HOME/FlashLock/.venv/bin/pyinstaller}"

echo "==> 1/4 Cleaning previous build"
rm -rf build dist "$NAME.spec"

echo "==> 2/4 Building $NAME.app"
"$PYINSTALLER" --windowed --name "$NAME" "$ENTRY"

echo "==> 3/4 Resolving symlinks (portable bundle)"
cp -RL "dist/$NAME.app" "dist/${NAME}-portable.app"
rm -rf "dist/$NAME.app"
mv "dist/${NAME}-portable.app" "dist/$NAME.app"

echo "==> 4/4 Stripping the ad-hoc signature (codesign can't re-sign the resolved framework)"
rm -rf "dist/$NAME.app/Contents/_CodeSignature"

SYMLINKS=$(find "dist/$NAME.app" -type l | wc -l | tr -d ' ')
echo "==> Done. Symlinks remaining: $SYMLINKS (expected 0)"
echo "Portable app: dist/$NAME.app"
