# UI Handoff: Integrating with `codex-app-server-proxy`

This document is for frontend/webapp integration with our wrapper service.

## 1) Upstream References (OpenAI)

Use these for core protocol behavior and concepts:

- OpenAI Codex App Server docs: [developers.openai.com/codex/app-server](https://developers.openai.com/codex/app-server)
- OpenAI Codex authentication docs: [developers.openai.com/codex/auth](https://developers.openai.com/codex/auth)
- OpenAI Codex CLI overview: [developers.openai.com/codex/cli](https://developers.openai.com/codex/cli)

Important: this proxy intentionally restricts and rewrites parts of the upstream protocol. The proxy-specific behavior below is the source of truth for our UI.

## 2) Base URL and Auth

- Base URL: `http(s)://<proxy-host>:8080`
- All `/v1/*` endpoints require:
  - `Authorization: Bearer <WRAPPER_API_KEY>`
- Roles:
  - `user`: default sandboxed usage
  - `admin`: may request danger override per request

## 3) Endpoint Contract

### `POST /v1/sessions`

Creates one upstream `codex app-server` process and returns a session id.

Response `201`:

```json
{ "sessionId": "<id>" }
```

Common errors:
- `401` unauthorized
- `429` with `{ "error": { "code": "session_create_failed", ... } }`

### `GET /v1/sessions/{sessionId}/events`

SSE stream carrying upstream JSON-RPC responses/notifications.

Headers set by proxy:
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache`

Event format:
- `id: <monotonic integer>`
- `event: message`
- `data: <one line of JSON-RPC payload>`

Keepalive:
- comment ping every ~15s (`: ping`)

Reconnect/resume:
- Provide either `Last-Event-ID` header or `lastEventId` query param.

### `POST /v1/sessions/{sessionId}/rpc`

Sends exactly one JSON-RPC message to the session.

Request body:
- JSON object (max ~8MB)

Success response:

```json
{ "accepted": true }
```

Important:
- This endpoint **does not** wait for model output.
- Read results from SSE `/events`.

### `DELETE /v1/sessions/{sessionId}`

Ends session and kills subprocess.

Response:

```json
{ "deleted": true }
```

### Health/readiness

- `GET /healthz` -> process liveness (`{"ok":true}`)
- `GET /readyz` -> bootstrap auth + plan readiness; returns `503` if not ready.

## 4) Required Client Flow

1. `POST /v1/sessions`
2. Open SSE stream for that `sessionId`
3. Send `initialize` JSON-RPC request via `/rpc`
4. Send `initialized` notification (supported by proxy)
5. Start/resume/fork thread via `/rpc`
6. Start turns via `/rpc`
7. Render SSE messages in UI

Minimal `initialize` example (required fields):

```json
{
  "jsonrpc": "2.0",
  "id": "init-1",
  "method": "initialize",
  "params": {
    "clientInfo": {
      "name": "my-webapp",
      "version": "1.0.0"
    }
  }
}
```

`initialized` notification example:

```json
{
  "jsonrpc": "2.0",
  "method": "initialized",
  "params": {}
}
```

## 5) Proxy Policy (Differences from Upstream)

### Allowed request methods

- `initialize`
- `initialized`
- `thread/*`
- `turn/*`
- `review/start`
- `model/list`
- `feedback/upload`
- `skills/*`

### Blocked request methods

- `config/*`
- `account/*`
- `mcpServer/*`
- `externalAgentConfig/*`
- `windowsSandbox/*`
- `command/exec`
- `app/list`

### Forced rewrites on inbound RPC

- `params.cwd` is always replaced with configured `workspace_root`.
- For `thread/*` and `turn/*` (default mode):
  - `sandboxMode = "workspaceWrite"`
  - `writableRoots = [workspace_root]`
  - `networkAccess = true`
  - `approvalPolicy = "never"`
- For `skills/*`:
  - any `cwds` / `writableRoots` are clamped to paths within `workspace_root`.

### Danger override (admin only)

To request danger mode on eligible methods (`thread/start|resume|fork`, `turn/start`):

- Use an **admin** API key
- Add header: `X-Codex-Danger: true`

If either condition fails, proxy returns `403 policy_denied`.

## 6) Error Shape and Handling

Proxy errors are JSON:

```json
{
  "error": {
    "code": "<machine_code>",
    "message": "<human_message>"
  }
}
```

Codes you should branch on in UI:

- `unauthorized` (`401`)
- `session_not_found` (`404`)
- `method_not_allowed` (`405`)
- `policy_denied` (`403`)
- `invalid_json` / `invalid_request` (`400`)
- `upstream_write_failed` (`502`)
- `session_create_failed` (`429`)

Also consume upstream JSON-RPC errors from SSE `data` payloads.

## 7) Browser Integration Notes (Important)

Native `EventSource` does not let you set `Authorization` headers. Use one of:

- SSE over `fetch` streaming
- an SSE helper that supports custom headers (example: `@microsoft/fetch-event-source`)

### TypeScript example (header-capable SSE)

```ts
import { fetchEventSource } from "@microsoft/fetch-event-source";

const BASE = "http://127.0.0.1:8080";
const API_KEY = "...";
const headers = { Authorization: `Bearer ${API_KEY}` };

async function createSession(): Promise<string> {
  const res = await fetch(`${BASE}/v1/sessions`, { method: "POST", headers });
  if (!res.ok) throw new Error(`create session failed: ${res.status}`);
  const body = await res.json();
  return body.sessionId;
}

async function rpc(sessionId: string, message: unknown, danger = false) {
  const res = await fetch(`${BASE}/v1/sessions/${sessionId}/rpc`, {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/json",
      ...(danger ? { "X-Codex-Danger": "true" } : {}),
    },
    body: JSON.stringify(message),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`rpc failed: ${res.status} ${JSON.stringify(err)}`);
  }
}

async function run() {
  const sessionId = await createSession();

  let lastEventId = "";
  await fetchEventSource(`${BASE}/v1/sessions/${sessionId}/events`, {
    headers,
    onmessage(ev) {
      lastEventId = ev.id || lastEventId;
      if (!ev.data) return;
      const msg = JSON.parse(ev.data);
      // Route JSON-RPC responses/notifications into your state store.
      console.log("SSE JSON-RPC", msg);
    },
    onerror(err) {
      console.error("SSE error", err, { lastEventId });
      // Library retries automatically unless you throw.
    },
  });

  await rpc(sessionId, {
    jsonrpc: "2.0",
    id: "init-1",
    method: "initialize",
    params: { clientInfo: { name: "ui", version: "1.0.0" } },
  });

  await rpc(sessionId, {
    jsonrpc: "2.0",
    method: "initialized",
    params: {},
  });
}
```

## 8) Operational Expectations for UI

- Treat `/rpc` as fire-and-ack only; render from SSE stream.
- Keep one SSE connection per active session.
- Persist `lastEventId` client-side so reconnect can recover missed events.
- Session TTL exists server-side (idle reaper). If SSE closes and subsequent `/rpc` returns `session_not_found`, create a new session.
- For privileged workflows requiring danger mode, use a dedicated admin key path in backend-only code (do not expose admin key to browsers).
