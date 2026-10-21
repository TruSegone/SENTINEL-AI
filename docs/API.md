# API contract

Interactive OpenAPI: `/docs`; all application routes are versioned below `/api/v1`. JSON errors use FastAPI's `detail` object with `code` and `message` for application errors. Event, finding and incident collections return `{items,total,limit,offset}`. Caps: events 200, findings/incidents 200, bulk ingestion 500, graph 500 nodes. Event ingestion is idempotent on `event_id`.

Key routes: `GET /overview`, `GET|POST /events`, `POST /events/bulk`, `GET /events/{id}`, `GET /findings`, `GET|PATCH /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/timeline`, `POST /incidents/{id}/investigate`, `GET /entities/graph`, `GET /rules`, `GET /models/status`, `GET /scenarios`, `POST /replays`, replay `GET` and `POST pause|resume|cancel|reset`, `GET /response-actions`, `POST /incidents/{id}/response-actions`, response action `POST approve|reject|execute`, `GET /audit-logs`, and `GET /stream/events` (SSE). Operational endpoints are `/health`, `/ready`, `/metrics`.

The demo uses `X-Analyst-Token` for all writes; approval and execution additionally require `X-Analyst-Role: admin`. This is only a local demo gate, not production RBAC. Write requests from the included UI send the configured local demo token. Sensitive execution accepts `Idempotency-Key`; successful action execution itself is idempotent. Bulk operations return per-batch accepted and duplicate counts.
