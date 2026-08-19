#!/bin/sh
# Build a fully self-contained Windows delivery: embedded CPython + whatami.
# For hosts with no Python installed. Produces dist/whatami-portable-win64.zip:
#
#   whatami-portable/
#     whatami.cmd        run this: whatami.cmd collect --since 72h
#     whatami.pyz        standalone zipapp (works with any system Python too)
#     README.txt
#     python/            python.org embeddable CPython (no install, no admin)
#       python.exe, DLLs, python312.zip stdlib, ...
#       wtfserver/       the package, importable via the ._pth "." entry
#
# On the server: copy the zip over (\\tsclient, email, ...), extract anywhere,
# run whatami-portable\whatami.cmd. Nothing is installed or registered.
set -eu
cd "$(dirname "$0")/.."

PY="${PY:-.venv/bin/python}"
PYVER="3.12.10"   # last 3.12 with python.org binaries; supports Server 2016
EMBED="python-${PYVER}-embed-amd64.zip"
EMBED_SHA256="4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"

mkdir -p dist
if [ ! -f "dist/${EMBED}" ]; then
    curl -fsSL -o "dist/${EMBED}" "https://www.python.org/ftp/python/${PYVER}/${EMBED}"
fi
echo "${EMBED_SHA256}  dist/${EMBED}" | shasum -a 256 -c -

STAGE="dist/whatami-portable"
rm -rf "$STAGE"
mkdir -p "$STAGE/python"
unzip -q "dist/${EMBED}" -d "$STAGE/python"

# The embeddable ._pth puts "." (the python/ dir) on sys.path, so the package
# dropped next to python.exe is importable with no path configuration.
cp -R src/wtfserver "$STAGE/python/wtfserver"
find "$STAGE/python/wtfserver" -name __pycache__ -type d -exec rm -rf {} +

"$PY" -m zipapp src -m "wtfserver.cli:main" -o "$STAGE/whatami.pyz" -c

# CRLF line endings: cmd.exe misparses bare-LF batch files in edge cases.
printf '@echo off\r\n"%%~dp0python\\python.exe" -m wtfserver.cli %%*\r\n' \
    > "$STAGE/whatami.cmd"

printf '%s\r\n' \
    "WTFServer / whatami - portable Windows build (no install required)" \
    "" \
    "Usage (from this directory, any location, no admin rights needed):" \
    "  whatami.cmd collect --since 72h --output host.wtf" \
    "  whatami.cmd analyze host.wtf" \
    "  whatami.cmd analyze host.wtf --json report.json" \
    "" \
    "python\\ is the python.org ${PYVER} embeddable runtime; nothing is" \
    "installed or registered. whatami.pyz is the same tool as a single file" \
    "for hosts that already have Python >= 3.10 (py whatami.pyz ...)." \
    "" \
    "Collection is read-only. To send a bundle back through a mail filter:" \
    "  certutil -encode host.wtf host.wtf.txt" \
    > "$STAGE/README.txt"

(cd dist && rm -f whatami-portable-win64.zip \
    && zip -qr whatami-portable-win64.zip whatami-portable \
    && shasum -a 256 whatami-portable-win64.zip | tee -a SHA256SUMS.txt)

# Mail-gateway wrapper: gateways that block zips pass .txt; decode on Windows
# with the built-in  certutil -decode <file>.b64.txt <file>.zip
openssl base64 -in dist/whatami-portable-win64.zip \
    -out dist/whatami-portable-win64.zip.b64.txt
ls -la dist/whatami-portable-win64.zip dist/whatami-portable-win64.zip.b64.txt
