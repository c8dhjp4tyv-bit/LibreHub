# Outbound webhooks (M7)

```bash
librehub integration webhook-add --project $P --url https://hooks.example.com/librehub \
  --event publication.succeeded --event automation.approval_required
```

Events: `build.started|succeeded|failed`, `publication.started|succeeded|failed`,
`security.analysis_ready|analysis_failed`, `attestation.ready|failed`,
`automation.started|completed|failed|approval_required`. Payloads contain IDs, statuses, channel,
application ID and commit — never logs, tokens, credentials, secrets or private notes.

## Payload (version 1)

```json
{ "version": 1, "event_id": "…", "delivery_id": "…", "event_type": "publication.succeeded",
  "created_at": "2026-01-01T00:00:00+00:00", "project_id": "…",
  "origin": {"kind": "automation", "automation_run_id": "…"},
  "chain_depth": 0, "correlation_id": "…", "data": { "publication_id": "…", "channel": "stable" } }
```

`event_id` is stable for the event; `delivery_id` is stable across retries of one delivery and
different for a manual replay.

## Signature

Headers: `X-LibreHub-Event`, `X-LibreHub-Event-Id`, `X-LibreHub-Delivery`,
`X-LibreHub-Timestamp` (Unix seconds, fresh per attempt), `X-LibreHub-Signature: v1=<hex>`.

```
signature = hex(HMAC-SHA256(secret, "<timestamp>.<delivery id>.<raw request body bytes>"))
```

Verify over the *raw bytes*, compare in constant time and reject timestamps more than 5 minutes
old. Python:

```python
import hmac, hashlib, time
def verify(secret, headers, body):
    ts, delivery = headers["X-LibreHub-Timestamp"], headers["X-LibreHub-Delivery"]
    expected = "v1=" + hmac.new(secret.encode(), f"{ts}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-LibreHub-Signature"]) and abs(time.time() - int(ts)) < 300
```

Secrets are random 256-bit `whsec_…` values returned only when created or rotated; they are stored
encrypted (XChaCha20-Poly1305 with the platform key, associated data = webhook ID). Rotation
replaces the secret at once with no overlap. Deduplicate receivers by `event_id`: delivery is
**at least once**.

## Destination security

URLs must be `https`, ≤ 2048 bytes, carry no credentials or fragment, use port 443, 8443 or
≥ 1024, and name a public host. Rejected: `localhost` and single-label names, `.local`,
`.internal`, `.lan`…, IP literals and DNS answers in loopback, private, link-local (including
169.254.169.254), CGNAT, multicast, unique-local, NAT64, 6to4, documentation and IPv4-mapped
private ranges — **all** answers must be public. The destination is resolved and validated at
creation *and again on every attempt*; the connection is pinned to the validated addresses
(defeating DNS rebinding), redirects are never followed (a 3xx fails the delivery), the system
proxy is ignored, and there are connect (5 s) and total (15 s) deadlines and a 16 KiB response
cap. Payloads are limited to 64 KiB. Operators may add a private trust anchor with
`LIBREHUB_WEBHOOK_CA_FILE`; `LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS=1` permits loopback for test
fixtures only and never opens private or link-local ranges.

## Delivery lifecycle

`pending → delivering → delivered | retry_wait → … | failed | dead_letter`. The row (with the
exact payload bytes) is committed before any request. 2xx = delivered; 408/425/429/5xx, timeouts
and connection errors retry with exponential backoff (5 s base, 15 min cap, ±25 % jitter; honours
`Retry-After` up to 1 h) up to 8 attempts, then `dead_letter`; other 4xx, 3xx and unsafe
destinations are `failed` immediately. On restart, `delivering` rows become retryable. History
(attempts, status, safe error codes) is kept for the latest 1,000 deliveries per webhook.
`POST …/deliveries/{id}/replay` re-sends a finished delivery as a new delivery of the same event.
