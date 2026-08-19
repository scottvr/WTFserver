#!/bin/sh
# Build the email-friendly delivery bundle for whatami.
#
# Produces in dist/:
#   whatami.pyz          single-file zipapp; runs with any Python >= 3.10:
#                          py whatami.pyz collect --since 72h
#   whatami.pyz.b64.txt  base64 wrapper for mail gateways that block binary
#                        attachments; decode on Windows with the built-in:
#                          certutil -decode whatami.pyz.b64.txt whatami.pyz
#   SHA256SUMS.txt       integrity check (Windows: certutil -hashfile ... SHA256)
#
# Runtime is stdlib-only, so the zipapp needs no pip and no install on the host.
set -eu
cd "$(dirname "$0")/.."

PY="${PY:-.venv/bin/python}"
mkdir -p dist

"$PY" -m zipapp src -m "wtfserver.cli:main" -o dist/whatami.pyz -c
# certutil-compatible framing (certutil accepts plain base64 with or without
# PEM headers; openssl base64 line-wraps at 64 chars, which certutil handles).
openssl base64 -in dist/whatami.pyz -out dist/whatami.pyz.b64.txt
(cd dist && shasum -a 256 whatami.pyz > SHA256SUMS.txt)

"$PY" dist/whatami.pyz --version
ls -la dist/whatami.pyz dist/whatami.pyz.b64.txt
cat dist/SHA256SUMS.txt
