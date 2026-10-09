# email-me

A self-hosted, send-only email gateway that lets AI agents running anywhere email **you**, without ever holding your mailbox credentials or even knowing your address.

- Agents get a **token** and a list of **recipient aliases** (`me`, `work`). Only the gateway knows the real addresses and the SMTP password.
- **Per-agent policies** control which aliases, services, sizes and rates each agent gets.
- **Nothing is stored**: message bodies, subjects and attachments live only in memory; the audit log holds metadata.
- Messages are **signed with a per-agent OpenPGP key** held by the gateway (on by default), and can be **encrypted** to your key.
- The API **explains itself**: an agent only needs a URL and a token. `GET /` returns a usage guide written for LLMs and links to `/openapi.json`. No SDK, MCP server or CLI is needed on the agent side.
- A **dashboard** (the only management interface) manages agents, tokens, policies, recipients, keys, settings and the audit log.

The agent-facing contract is the OpenAPI document in [`internal/api/docs/openapi.yaml`](internal/api/docs/openapi.yaml), served at `/openapi.json`; the guide agents read first is [`internal/api/docs/guide.md.tmpl`](internal/api/docs/guide.md.tmpl).

## Quick start (Docker)

1. Create the config and secrets:

   ```sh
   mkdir -p config secrets
   cp config.example.yaml config/config.yaml        # then edit upstream (and the first recipient), or leave them out
   printf '%s' 'your-smtp-app-password' > secrets/smtp_password
   printf '%s' 'a-long-dashboard-password' > secrets/admin_password
   openssl rand -hex 32 > secrets/signing_kek         # encrypts agent signing keys at rest
   ```

   `upstream` and the SMTP password can also be left out and set on the dashboard's **Settings** page after the first start. The container runs as uid 65532. On Linux, make the secrets readable by it: `sudo chown 65532:65532 secrets/* && chmod 400 secrets/*`.

2. Start it:

   ```sh
   docker compose up -d --build
   ```

   Both ports are published on `127.0.0.1` only: the agent API on `8025`, the dashboard on `8026`.

3. Open `http://email-me.localhost:8026` (Chrome and Firefox resolve `*.localhost` to your machine) and log in with the admin password. If the overview says **Configure SMTP**, set the upstream server on the **Settings** page; it applies when saved. On the **Recipients** page, check the recipient imported from `config.yaml` or add your address (optionally pasting your PGP public key). Then create an agent, grant it one or more aliases, and issue a token. The token page shows everything to hand to the agent:

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

- **An encrypted tunnel**, such as Tailscale, WireGuard or an SSH tunnel. Tick *Transport is encrypted outside email-me* (`api.external_transport_encryption`) on the Settings page so email-me knows the path is encrypted.
- **A TLS reverse proxy** such as Caddy in front of port 8025. On the Settings page, set the trusted proxies (`api.trusted_proxies`) to the proxy's address and the public URL (`api.public_url`) to the public HTTPS URL.
- **Built-in TLS** with `api.tls.cert_file` and `api.tls.key_file` in `config.yaml`.

**Use TLS or a tunnel on every non-localhost path.** Signing is on by default, and to sign a message the gateway has to read it, so message content crosses the agent → gateway hop in plaintext unless that hop is encrypted. email-me classifies every request as `tls`, `local`, `tunnel` or `insecure`, tells the agent in `/v1/capabilities`, records it in the audit log, and shows a dashboard banner when agents send over `insecure` connections. It warns; it never blocks.

## Encryption and signing

| Mode | Agent → gateway | Gateway (memory only) | Mail provider & your mailbox | Signed with agent key |
|---|---|---|---|---|
| `encrypt: none` | Plaintext unless TLS | Plaintext | Plaintext | Yes (default) |
| `encrypt: pgp` | Plaintext unless TLS | Plaintext | Ciphertext, real subject hidden | Yes (default) |
| `encrypt: e2e` | Ciphertext | Ciphertext | Ciphertext | No, impossible |

- **Gateway-side encryption (`pgp`)**: paste the recipient's ASCII-armored public key (`gpg --export --armor --export-options export-minimal you@example.com`) on its page under **Recipients**. The agent sets `options.encrypt: "pgp"`.
- **End-to-end (`e2e`)**: the agent fetches the recipient's key from `/v1/recipients/{alias}/pgp-key`, encrypts a MIME entity itself, and sends the ciphertext. The gateway never sees plaintext, so it cannot sign; an agent needs `require_signing: false` in its policy to use `e2e`.
- **Revocation**: every agent key comes with two revocation certificates. Publish the *retired* one after rotating or deleting an agent; signatures the key already made stay valid. Publish the *compromised* one only if the key may have leaked (for example, the database and the KEK were both exposed); it invalidates every signature the key made.
- **Signatures**: each agent's key has the user ID `<agent> via email-me <your from address>`. Download public keys from the agent's Signing tab, or all of them from Settings, and import them into your mail client. A signature proves the message was submitted through your gateway with that agent's token and was not modified afterwards.

## Operations

- **Health**: the image has a Docker `HEALTHCHECK` (`email-me healthcheck`), and `GET /healthz` on the API.
- **Settings**: the upstream SMTP server and its password, the From address, the agent API's public URL, guide access and trusted proxies, the default policy, the dashboard session lifetime, audit retention and signing-key validity are edited on the dashboard's **Settings** page and stored in `state.db`. Saving applies them at once, without a restart: the next send uses the new upstream server and policy, the next login the new session lifetime. The SMTP password is write-only on the page and stored encrypted with the signing KEK (unencrypted without a KEK, which the dashboard flags).
- **`config.yaml`** keeps the bootstrap keys: `data_dir`, the listen addresses, `api.tls`, the admin password file, the `signing` key files, and `log`. They are read at every start: when the file changes on disk, a banner on every dashboard page offers **Restart now**, which restarts email-me inside the container. In-flight sends finish first, the listeners are down for a moment, and you log in again. `docker kill -s HUP <container>` restarts the same way; restart the container instead when the change also needs new mounts or ports. Only the file itself is watched: after replacing a secret file it names, restart too. Every problem is listed at once; if the file no longer loads, a restart from the dashboard or `SIGHUP` is refused and the gateway keeps running.
- **Seeds**: the file's other sections (`upstream`, the managed `api`, `dashboard` and `signing` keys, `defaults`, `audit`) and `recipients:` are imported into `state.db` on the first start and ignored afterwards (a log line says so; you may delete them). `upstream.smtp.password_file` is read only then. Recipients are managed on the **Recipients** page and take effect immediately; the `recipients:` section is imported again only when the database has none.
- **Upgrading** from a version that read these settings from `config.yaml`: the first start imports your current values once, so nothing changes; from then on, edit them on the dashboard.
- **State**: `state.db` in the `email-me-data` volume holds agents, token hashes, recipients and their PGP public keys, settings and the SMTP password, encrypted signing keys and audit metadata. Back it up together with `signing_kek`; without the KEK the signing keys and the stored SMTP password cannot be decrypted (the dashboard then asks for the password again).
- **Admin password as a hash**: `admin_password` may hold an argon2id PHC string instead of plaintext, e.g. `printf '%s' 'password' | argon2 "$(openssl rand -hex 16)" -id -t 3 -m 16 -p 2 -e`.

## Development

```sh
go test ./...                                  # unit + integration tests (fake SMTP server in-process)
docker compose -f compose.dev.yml up --build   # email-me + Mailpit
```

The dev stack delivers to Mailpit (`http://localhost:8027`); the dashboard password is `dev-password-change-me`. The secrets in `dev/` are throwaway values.

Layout: `cmd/email-me` (binary), `internal/api` (agent API, guide and OpenAPI spec in `internal/api/docs`), `internal/dashboard`, `internal/compose` (MIME), `internal/pgp` (PGP/MIME), `internal/keys` (agent signing keys), `internal/recipients` (recipient registry), `internal/settings` (managed settings), `internal/store` (SQLite), `internal/config`, `internal/policy`.
