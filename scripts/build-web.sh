#!/bin/sh
# Build the React app and embed it in the Go binary.
# Vite writes the dist output to web/ui, which web/embed.go includes with go:embed.
# The binary serves that build at /web.
set -eu
cd "$(dirname "$0")/.."

if command -v bun >/dev/null 2>&1; then
  (cd web-ui && bunx vite build --base /web/ --outDir ../web/ui --emptyOutDir)
elif command -v npm >/dev/null 2>&1; then
  (cd web-ui && npx vite build --base /web/ --outDir ../web/ui --emptyOutDir)
else
  echo "bun or npm is required to build the React UI" >&2
  exit 1
fi

mkdir -p bin
go build -o bin/caddyui ./cmd/caddyui
echo "built bin/caddyui — React UI is served at /web"
