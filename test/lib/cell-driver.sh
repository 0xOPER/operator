#!/usr/bin/env bash
# cell-driver.sh -- run one twin of one cell against one adapter's real CLI,
# with the cell stub in the adapter's dialect. Sourced by conformance.sh; the
# caller sets D, ROOT, tool JSON in $D/tool.json, and the settings in
# $D/settings.json (claude) or config (codex/opencode).
# $1 adapter  $2 dialect
run_cli() {
  local adapter=$1 dialect=$2 out rc
  : > "$D/log"
  CELL_LOG="$D/log" CELL_TOOL="$D/tool.json" CELL_DIALECT="$dialect" \
    python3 "$ROOT/test/lib/cell-stub.py" > "$D/port" 2>/dev/null &
  local stub=$!
  sleep 0.5
  local port
  port=$(cat "$D/port" 2>/dev/null)
  [ -n "$port" ] || { echo "  VOID (stub port missing)"; kill $stub 2>/dev/null; return 3; }
  case "$adapter" in  # census: allow
    claude-code)
      CLI_BIN=claude  # census: allow
      ( cd "$D/repo" && HOME="$D/h" \
          ANTHROPIC_BASE_URL="http://127.0.0.1:$port" \
          ANTHROPIC_AUTH_TOKEN="$KEY" DISABLE_UPDATES=1 \  # census: allow
          timeout 120 "$CLI_BIN" -p --setting-sources project --strict-mcp-config \  # census: allow
          --mcp-config '{"mcpServers":{}}' --model glm-4.6 \
          --settings "$D/settings.json" \
          "follow the tool call exactly" >"$D/claude.out" 2>&1 )
      rc=$?
      ;;
    codex)  # census: allow
      CLI_BIN=codex  # census: allow
      mkdir -p "$D/h/.codex"
      ( cd "$D/repo" && HOME="$D/h" CODEX_HOME="$D/h/.codex" \
          XDG_CONFIG_HOME="$D/h/.config" ZAI_KEY="$KEY" \
          timeout 120 "$CLI_BIN" exec --skip-git-repo-check \
          --ignore-user-config --ignore-rules \
          -c model_provider=cell -c model=glm-4.6 \
          -c 'model_providers.cell.name=cell' \
          -c "model_providers.cell.base_url=http://127.0.0.1:$port" \
          -c 'model_providers.cell.env_key=ZAI_KEY' \
          -c 'model_providers.cell.wire_api=responses' \
          --sandbox danger-full-access \
          -c 'approval_policy=never' \
          "follow the tool call exactly" >"$D/claude.out" 2>&1 )
      rc=$?
      ;;
    opencode)  # census: allow
      CLI_BIN=opencode  # census: allow
      ( cd "$D/repo" && HOME="$D/h" \
          XDG_CONFIG_HOME="$D/h/.config" \
          XDG_DATA_HOME="$D/h/.local/share" \
          XDG_CACHE_HOME="$D/h/.cache" \
          OPENCODE_DISABLE_UPDATE_CHECK=1 \
          timeout 120 "$CLI_BIN" run --pure \
          "follow the tool call exactly" >"$D/claude.out" 2>&1 )
      rc=$?
      ;;  # census: allow
    *) echo "  unknown adapter $adapter"; kill $stub 2>/dev/null; return 3 ;;
  esac
  kill "$stub" 2>/dev/null
  return 0
}
