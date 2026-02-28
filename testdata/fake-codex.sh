#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "app-server" || "${2:-}" != "--listen" || "${3:-}" != "stdio://" ]]; then
  echo "unsupported invocation" >&2
  exit 2
fi

plan="${FAKE_PLAN_TYPE:-pro}"
missing_auth="${FAKE_MISSING_AUTH:-0}"

extract_id() {
  local line="$1"
  local id
  id="$(printf '%s' "$line" | sed -nE 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]+)".*/"\1"/p')"
  if [[ -n "$id" ]]; then
    printf '%s' "$id"
    return
  fi
  id="$(printf '%s' "$line" | sed -nE 's/.*"id"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')"
  if [[ -n "$id" ]]; then
    printf '%s' "$id"
    return
  fi
  printf 'null'
}

while IFS= read -r line; do
  id="$(extract_id "$line")"

  if [[ "$line" == *'"method":"initialize"'* ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true,"codexHome":"%s"}}\n' "$id" "${CODEX_HOME:-}"
    continue
  fi

  if [[ "$line" == *'"method":"account/read"'* ]]; then
    if [[ "$missing_auth" == "1" ]]; then
      printf '{"jsonrpc":"2.0","id":%s,"error":{"code":401,"message":"not logged in"}}\n' "$id"
    else
      printf '{"jsonrpc":"2.0","id":%s,"result":{"planType":"%s"}}\n' "$id" "$plan"
    fi
    continue
  fi

  if [[ "$line" == *'"method":"thread/start"'* ]]; then
    printf '{"jsonrpc":"2.0","method":"thread/event","params":{"phase":"started"}}\n'
  fi

  if [[ "$line" == *'"method":"turn/start"'* ]]; then
    printf '{"jsonrpc":"2.0","method":"turn/event","params":{"phase":"started"}}\n'
  fi

  if [[ "$id" != "null" ]]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true,"echo":true}}\n' "$id"
  fi
done
