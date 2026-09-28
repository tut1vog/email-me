# email-me

A self-hosted, send-only email gateway that lets AI agents running anywhere email **you**, without ever holding your mailbox credentials or even knowing your address.

- Agents get a **token** and a list of **recipient aliases** (`me`, `work`). Only the gateway knows the real addresses and the SMTP password.
- **Per-agent policies** control which aliases, services, sizes and rates each agent gets.
- **Nothing is stored**: message bodies, subjects and attachments live only in memory; the audit log holds metadata.
- Messages are **signed with a per-agent OpenPGP key** held by the gateway (on by default), and can be **encrypted** to your key.
- The API **explains itself**: an agent only needs a URL and a token. `GET /` returns a usage guide written for LLMs and links to `/openapi.json`. No SDK, MCP server or CLI is needed on the agent side.
- A **dashboard** (the only management interface) manages agents, tokens, policies, keys and the audit log.

The agent-facing contract is the OpenAPI document in [`internal/api/docs/openapi.yaml`](internal/api/docs/openapi.yaml), served at `/openapi.json`; the guide agents read first is [`internal/api/docs/guide.md.tmpl`](internal/api/docs/guide.md.tmpl).

## Quick start (Docker)

1. Create the config and secrets:

   ```sh
   mkdir -p config secrets
   cp config.example.yaml config/config.yaml        # then edit upstream + recipients
   printf '%s' 'your-smtp-app-password' > secrets/smtp_password
   printf '%s' 'a-long-dashboard-password' > secrets/admin_password
   openssl rand -hex 32 > secrets/signing_kek         # encrypts agent signing keys at rest
   ```

   The container runs as uid 65532. On Linux, make the secrets readable by it: `sudo chown 65532:65532 secrets/* && chmod 400 secrets/*`.

2. Start it:

   ```sh
   docker compose up -d --build
   ```

   Both ports are published on `127.0.0.1` only: the agent API on `8025`, the dashboard on `8026`.

3. Open `http://email-me.localhost:8026` (Chrome and Firefox resolve `*.localhost` to your machine), log in with the admin password, create an agent, grant it one or more aliases, and issue a token. The token page shows everything to hand to the agent:

   ```
   EMAIL_ME_URL=http://localhost:8025
   EMAIL_ME_TOKEN=em_…
   ```

   plus a snippet for the agent's instructions telling it to `GET` the base URL and follow the guide.

4. The agent does the rest:

   ```sh
   curl -s -H "Authorization: Bearer $EMAIL_ME_TOKEN" $EMAIL_ME_URL/v1/capabilities
   curl -s -X POST $EMAIL_ME_URL/v1/messages \
     -H "Authorization: Bearer $EMAIL_ME_TOKEN" -H "Content-Type: application/json" \
     -d '{"to":["me"],"subject":"Nightly run finished","body":{"markdown":"## All green"},"idempotency_key":"nightly-2026-09-28"}'
   ```

Why `email-me.localhost` instead of `localhost`: browsers send a host's cookies to every port on it, so if you visit a web server that some local process (an agent, say) runs on `localhost:3000`, it would receive your dashboard session cookie. A dedicated host name keeps the cookie to email-me. The login page reminds you when you use plain `localhost`.

## Letting agents on other hosts in

The defaults keep everything on localhost. To accept agents from other machines, expose **only the API** (never the dashboard), and protect the path:

- **An encrypted tunnel**, such as Tailscale, WireGuard or an SSH tunnel. Set `api.external_transport_encryption: true` so email-me knows the path is encrypted.
- **A TLS reverse proxy** such as Caddy in front of port 8025. Set `api.trusted_proxies` to the proxy's address and `api.public_url` to the public HTTPS URL.
- **Built-in TLS** with `api.tls.cert_file` and `api.tls.key_file`.

**Use TLS or a tunnel on every non-localhost path.** Signing is on by default, and to sign a message the gateway has to read it, so message content crosses the agent → gateway hop in plaintext unless that hop is encrypted. email-me classifies every request as `tls`, `local`, `tunnel` or `insecure`, tells the agent in `/v1/capabilities`, records it in the audit log, and shows a dashboard banner when agents send over `insecure` connections. It warns; it never blocks.

## Encryption and signing

| Mode | Agent → gateway | Gateway (memory only) | Mail provider & your mailbox | Signed with agent key |
|---|---|---|---|---|
| `encrypt: none` | Plaintext unless TLS | Plaintext | Plaintext | Yes (default) |
| `encrypt: pgp` | Plaintext unless TLS | Plaintext | Ciphertext, real subject hidden | Yes (default) |
| `encrypt: e2e` | Ciphertext | Ciphertext | Ciphertext | No, impossible |

- **Gateway-side encryption (`pgp`)**: add `pgp_public_key_file` to a recipient in `config.yaml`. The agent sets `options.encrypt: "pgp"`.
- **End-to-end (`e2e`)**: the agent fetches the recipient's key from `/v1/recipients/{alias}/pgp-key`, encrypts a MIME entity itself, and sends the ciphertext. The gateway never sees plaintext, so it cannot sign; an agent needs `require_signing: false` in its policy to use `e2e`.
- **Revocation**: every agent key comes with two revocation certificates. Publish the *retired* one after rotating or deleting an agent; signatures the key already made stay valid. Publish the *compromised* one only if the key may have leaked (for example, the database and the KEK were both exposed); it invalidates every signature the key made.
- **Signatures**: each agent's key has the user ID `<agent> via email-me <your from address>`. Download public keys from the agent page, or all of them from Settings, and import them into your mail client. A signature proves the message was submitted through your gateway with that agent's token and was not modified afterwards.

## Operations

- **Health**: the image has a Docker `HEALTHCHECK` (`email-me healthcheck`), and `GET /healthz` on the API.
- **Config changes**: edit `config/config.yaml` and restart. The config is validated at startup and every problem is listed at once.
- **State**: `state.db` in the `email-me-data` volume holds agents, token hashes, encrypted signing keys and audit metadata. Back it up together with `signing_kek`; without the KEK the signing keys cannot be decrypted.
- **Admin password as a hash**: `admin_password` may hold an argon2id PHC string instead of plaintext, e.g. `printf '%s' 'password' | argon2 "$(openssl rand -hex 16)" -id -t 3 -m 16 -p 2 -e`.

## Development

```sh
go test ./...                                  # unit + integration tests (fake SMTP server in-process)
docker compose -f compose.dev.yml up --build   # email-me + Mailpit
```

The dev stack delivers to Mailpit (`http://localhost:8027`); the dashboard password is `dev-password-change-me`. The secrets in `dev/` are throwaway values.

Layout: `cmd/email-me` (binary), `internal/api` (agent API, guide and OpenAPI spec in `internal/api/docs`), `internal/dashboard`, `internal/compose` (MIME), `internal/pgp` (PGP/MIME), `internal/keys` (agent signing keys), `internal/store` (SQLite), `internal/config`, `internal/policy`.
