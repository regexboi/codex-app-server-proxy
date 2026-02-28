# codex-app-server-proxy (Go)

HTTP + SSE wrapper for `codex app-server --listen stdio://` with strict workspace isolation, API-key auth, and server-side ChatGPT Pro bootstrap auth.

## Features

- One Codex subprocess per wrapper session.
- HTTP endpoints:
  - `POST /v1/sessions`
  - `GET /v1/sessions/{sessionId}/events` (SSE)
  - `POST /v1/sessions/{sessionId}/rpc`
  - `DELETE /v1/sessions/{sessionId}`
  - `GET /healthz`
  - `GET /readyz`
- Built-in API key auth (`Authorization: Bearer ...`) with constant-time SHA-256 key checks.
- Role model: `user` and `admin`.
- Request policy enforcement:
  - strict allow/block method matrix
  - fixed `cwd` to configured `workspace_root`
  - sandbox defaults for `thread/*` and `turn/*`
  - admin-only danger override via `X-Codex-Danger: true`
- Skills APIs are allowed (`skills/*`).
- Dedicated service `CODEX_HOME` bootstrap auth probe (`account/read`) requiring `planType=pro`.
- Per-session isolated `CODEX_HOME` clones seeded from service home auth.

## Bootstrap login (one-time)

```bash
export CODEX_HOME=/var/lib/codex-proxy/service-home
codex login --device-auth
```

## Configure

Copy `config.example.json` to `config.json`, then set real values.

To create SHA-256 key hashes:

```bash
printf 'your-secret-key' | shasum -a 256
```

Use the hex digest in `api_keys[].hash` (optionally prefixed with `sha256:`).

## Run

```bash
go run ./cmd/proxy -config ./config.json
```

## Test

```bash
go test ./...
```

## Notes

- `readyz` returns `503` when bootstrap auth is missing/invalid or plan type is not the configured required plan.
- Session homes are created under `<data_dir>/sessions/<sessionId>/home`.
- Each session is idle-reaped by `session_idle_ttl`.

## UI Integration

- UI handoff guide: `docs/UI_HANDOFF.md`
