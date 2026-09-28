# email-me: email your operator

email-me is a gateway that lets you (an AI agent) send email to your operator. You can only send to recipient **aliases** your operator registered (for example `me`). You never see real addresses and cannot email anyone else. Messages are delivered synchronously and are never stored.

- Base URL: https://email-me.example.ts.net
- Full API schema (OpenAPI): https://email-me.example.ts.net/openapi.json

## Authentication

Send your token on every request: `Authorization: Bearer $EMAIL_ME_TOKEN`. Your operator gives you the token, usually in the `EMAIL_ME_TOKEN` environment variable. Never put the token in an email, a log, a file, or a commit.

## Step 1: learn what you may do

```sh
curl -s -H "Authorization: Bearer $EMAIL_ME_TOKEN" https://email-me.example.ts.net/v1/capabilities
```

The response lists your recipient aliases (with a description of what each inbox is for), your allowed services, size and rate limits, your signing status, and how your connection reached the gateway. Only use aliases and services listed there.

## Step 2: send

```sh
curl -s -X POST https://email-me.example.ts.net/v1/messages \
  -H "Authorization: Bearer $EMAIL_ME_TOKEN" -H "Content-Type: application/json" \
  -d '{"to":["me"],"subject":"Nightly benchmark finished","body":{"markdown":"## Results\n- p50: 12ms\n- p99: 48ms"},"idempotency_key":"bench-2026-09-28"}'
```

- `body` takes exactly one of `text`, `markdown`, `html`, or `pgp_message`. Prefer `markdown`.
- Attachments (service `attachments`): `"attachments":[{"filename":"results.csv","content_type":"text/csv","content_base64":"..."}]`.
- `options.thread`: a stable key such as `"nightly-bench"` groups related reports into one inbox thread. Keep the subject stable too.
- `options.priority`: `low`, `normal` or `high` (`high` needs service `priority`).
- `options.encrypt: "pgp"`: the gateway encrypts to the recipient's key; the mail provider sees only ciphertext and a generic subject. Available when `encryption_available` is true for that alias. Use it for sensitive content.
- `options.sign`: when `signing.default` is true your message is signed with your agent key unless you set `false`. You cannot opt out when `signing.required` is true.
- Always set an `idempotency_key` unique to this message and reuse it when retrying, so a retry never sends twice.

A `200` response means the upstream mail server accepted the message.

## Errors: what to do

| Status | Meaning | Action |
|---|---|---|
| 400, 422 | Invalid request | Read `message`, fix the request. Do not resend it unchanged. |
| 401 | Token missing, invalid, expired or revoked | Stop and tell your operator. |
| 403 | Not permitted (alias, service, source IP, encryption or signing rule) | Read `message` and `details`, adjust the request, or ask your operator. |
| 413, 415 | Too large, or attachment type not allowed | Shrink or drop attachments. |
| 429 | Rate limited | Wait `Retry-After` seconds, then retry. |
| 502 | Upstream mail server failed | Retry later with the same `idempotency_key`. |
| 503 | Signing or encryption unavailable (key expired or not configured) | Tell your operator. Do not retry. |

Every error body is `{"error": "<code>", "message": "<explanation>", "details": {...}}`.

## End-to-end encryption (optional)

Only possible when `e2e_available` is true in your capabilities. It is false whenever signing is required: the gateway cannot sign content it cannot read, so e2e messages are never signed.

1. Fetch the recipient's key: `curl -s -H "Authorization: Bearer $EMAIL_ME_TOKEN" https://email-me.example.ts.net/v1/recipients/me/pgp-key > me.asc`
2. Write a MIME entity with the real subject inside it: `printf 'Content-Type: text/plain; charset=utf-8\r\nSubject: Secret results\r\n\r\nThe results...\r\n' > msg.eml`
3. Encrypt it: `gpg --batch --armor --encrypt --recipient-file me.asc --output msg.asc msg.eml`
4. Send `{"to":["me"],"body":{"pgp_message":"<contents of msg.asc>"},"options":{"encrypt":"e2e"}}`. Omit `subject` and `attachments`: the visible subject is set by the gateway and attachments belong inside your MIME entity.

## Transport security

`transport` in your capabilities says how your request reached the gateway: `tls`, `local`, `tunnel` or `insecure`. If it is `insecure`, your token and message content crossed the network unencrypted: tell your operator and avoid sending secrets until TLS is set up.
