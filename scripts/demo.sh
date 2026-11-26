#!/usr/bin/env bash
# Builds the server, creates two throwaway keys, starts the server on 127.0.0.1:5080
# with a temporary database, runs the attack demo against it, then stops the server.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-5080}"
URL="http://127.0.0.1:$PORT"
TMP="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "› building…"
dotnet build -c Release -v quiet -nologo src/SecureMcp.Server >/dev/null
dotnet build -c Release -v quiet -nologo samples/SecureMcp.Demo >/dev/null
SERVER=src/SecureMcp.Server/bin/Release/net10.0/SecureMcp.Server.dll
DEMO=samples/SecureMcp.Demo/bin/Release/net10.0/SecureMcp.Demo.dll

read -r READER_KEY READER_HASH < <(dotnet "$SERVER" new-key demo-reader orders.read --quiet)
read -r WRITER_KEY WRITER_HASH < <(dotnet "$SERVER" new-key demo-writer orders.read orders.write --quiet)

echo "› starting the MCP server on $URL (keys exist only for this run)…"
(
  cd "$(dirname "$SERVER")"   # content root = build output, where appsettings.json is
  export Urls="$URL" ConnectionStrings__Orders="Data Source=$TMP/orders.db" Logging__LogLevel__Default=Warning
  export McpSecurity__ApiKeys__0__Id=demo-reader McpSecurity__ApiKeys__0__Sha256="$READER_HASH" McpSecurity__ApiKeys__0__Scopes__0=orders.read
  export McpSecurity__ApiKeys__1__Id=demo-writer McpSecurity__ApiKeys__1__Sha256="$WRITER_HASH" McpSecurity__ApiKeys__1__Scopes__0=orders.read McpSecurity__ApiKeys__1__Scopes__1=orders.write
  exec dotnet SecureMcp.Server.dll >"$TMP/server.log" 2>&1
) &
PID=$!

for _ in $(seq 1 60); do
  curl -sf "$URL/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$URL/healthz" >/dev/null || { echo "server did not start:"; cat "$TMP/server.log"; exit 1; }

dotnet "$DEMO" "$URL" "$READER_KEY" "$WRITER_KEY"
