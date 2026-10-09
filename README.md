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

1. Create the config and the key-encryption key (KEK):

   ```sh
   mkdir -p config ~/.config/email-me
   cp config.example.yaml config/config.yaml        # then edit upstream (and the first recipient), or leave them out
   (umask 077; openssl rand -hex 32 > ~/.config/email-me/kek)
   echo "EMAIL_ME_KEK_FILE=$HOME/.config/email-me/kek" > .env
   ```

   The KEK is the only secret email-me needs from you: every credential it stores (the SMTP password, the agents' signing keys) is encrypted with it in `state.db`. Keep it outside the checkout; Compose mounts the file named by `EMAIL_ME_KEK_FILE` (from `.env` or your shell) as a Docker secret. The container runs as uid 65532: on Linux, make the file readable by it (`sudo chown 65532 ~/.config/email-me/kek`). **Keep a copy in your password manager**: without it, those credentials are lost. `upstream` can also be left out and set on the dashboard's **Settings** page after the first start; the SMTP password is always entered there.

2. Start it:

   ```sh
   docker compose up -d --build
   docker compose logs email-me | grep 'setup password'
   ```

   Both ports are published on `127.0.0.1` only: the agent API on `8025`, the dashboard on `8026`. The first start logs a one-time **setup password** for the dashboard.

3. Open `http://email-me.localhost:8026` (Chrome and Firefox resolve `*.localhost` to your machine), log in with the setup password and choose your own (at least 12 characters). On the **Settings** page, enter the SMTP password (and the upstream server, if the overview says **Configure SMTP**); it applies when saved. On the **Recipients** page, check the recipient imported from `config.yaml` or add your address (optionally pasting your PGP public key). Then create an agent, grant it one or more aliases, and issue a token. The token page shows everything to hand to the agent:

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

## Install the binary (macOS and Linux)

Docker is the recommended way to run email-me. To run the binary directly instead, install it (or update it to the latest release) with:

```sh
curl -fsSL https://github.com/tut1vog/email-me/releases/latest/download/install.sh | sh
```

The script downloads the release for your OS and architecture (amd64 or arm64), checks it against the release's `checksums.txt` and puts `email-me` in `~/.local/bin`, or where `email-me` already is on your `PATH`. Run the same command again to update; restart a running gateway afterwards. `email-me version` prints the installed version. Set `EMAIL_ME_VERSION=v1.2.3` to install a specific release and `EMAIL_ME_INSTALL_DIR` to choose the directory, e.g. `curl -fsSL … | EMAIL_ME_INSTALL_DIR=/usr/local/bin sh`.

Outside the container, adapt the paths in `config.example.yaml`: point `data_dir` and `kek.file` at your own directories (the KEK file holds `openssl rand -hex 32`, mode `600`), and set both `listen` addresses to `127.0.0.1` (the default `0.0.0.0` relies on Docker publishing the ports on localhost only). Then run `email-me serve --config /path/to/config.yaml` under your service manager.

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
- **Certification**: optionally paste a master private key (and its passphrase) on the Settings page. Every agent key generated afterwards is certified by it, so GnuPG users can trust the master key once. It is stored encrypted, without its passphrase.
- **Signatures**: each agent's key has the user ID `<agent> via email-me <your from address>`. Download public keys from the agent's Signing tab, or all of them from Settings, and import them into your mail client. A signature proves the message was submitted through your gateway with that agent's token and was not modified afterwards.

## Operations

- **Health**: the image has a Docker `HEALTHCHECK` (`email-me healthcheck`), and `GET /healthz` on the API.
- **Settings**: the upstream SMTP server and its password, the From address, the agent API's public URL, guide access and trusted proxies, the default policy, the dashboard session lifetime, audit retention, signing-key validity and the certification key are edited on the dashboard's **Settings** page and stored in `state.db`. Saving applies them at once, without a restart: the next send uses the new upstream server and policy, the next login the new session lifetime. The SMTP password is write-only on the page and stored encrypted (unencrypted without a KEK, which the dashboard flags).
- **Credentials**: every credential lives in `state.db`. The admin password is an argon2id hash, changed on the dashboard's **Password** page. The SMTP password, the agents' signing keys and the certification key are encrypted with a random data key, which is itself encrypted with the KEK. Without a KEK (an empty KEK file), signing is off and the SMTP password is stored unencrypted.
- **`config.yaml`** keeps the bootstrap keys: `data_dir`, the listen addresses, `api.tls`, `kek`, and `log`. They are read at every start: when the file changes on disk, a banner on every dashboard page offers **Restart now**, which restarts email-me inside the container. In-flight sends finish first, the listeners are down for a moment, and you log in again. `docker kill -s HUP <container>` restarts the same way; recreate the container instead when the change also needs new mounts or ports (`docker compose up -d`) or a new KEK (`docker compose up -d --force-recreate`: Compose does not notice a changed secret file). Only the file itself is watched. Every problem is listed at once; if the file no longer loads, or its KEK does not open the stored credentials, a restart from the dashboard or `SIGHUP` is refused and the gateway keeps running.
- **Seeds**: the file's other sections (`upstream` without its password, the managed `api`, `dashboard` and `signing` keys, `defaults`, `audit`) and `recipients:` are imported into `state.db` on the first start and ignored afterwards (a log line says so; you may delete them). Recipients are managed on the **Recipients** page and take effect immediately; the `recipients:` section is imported again only when the database has none.
- **State**: `state.db` in the `email-me-data` volume holds agents, token hashes, recipients and their PGP public keys, settings, the encrypted credentials and audit metadata. Back it up, and keep the KEK somewhere else: a copy of `state.db` alone reveals no credential, and without the KEK the encrypted ones are lost.
- **Rotating the KEK**: write the new key to a new file and point `EMAIL_ME_KEK_FILE` at it, point `EMAIL_ME_PREVIOUS_KEK_FILE` at the old one, uncomment the `previous_kek` secret in `docker-compose.yml`, and run `docker compose up -d --force-recreate`. The start re-encrypts the data key with the new KEK (one row, nothing else changes). Then remove the previous key and the secret and run `docker compose up -d --force-recreate` again; the dashboard reminds you until you do. A start whose KEK does not open the stored credentials fails and says so (`docker compose logs email-me`).
- **Recovery**: a forgotten admin password: `docker compose exec email-me /email-me reset-admin-password` prints a new setup password. A lost KEK: the gateway no longer starts, so run `docker compose stop` and `docker compose run --rm email-me reset-keyring --yes`, which discards the encrypted credentials (the SMTP password, the certification key, and the agents' signing keys, which are retired); then start with a new KEK, and agents get new keys. Everything else is kept.

## Development

```sh
go test ./...   # unit + integration tests (fake SMTP server in-process)
```

CI (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request: `gofmt`, `go mod tidy`, `go vet`, `go test -race`, `shellcheck install.sh` and a multi-platform image build.

Releases: pushing a tag such as `v1.2.3` runs `.github/workflows/release.yml`, which runs the CI checks, attaches the macOS and Linux tarballs, `checksums.txt` and `install.sh` to a GitHub release, and pushes the image to `ghcr.io/tut1vog/email-me` (`1.2.3`, `1.2`, `latest`). A tag with a suffix (`v1.2.3-rc.1`) makes a prerelease that the install script and `latest` skip.

Layout: `cmd/email-me` (binary), `internal/api` (agent API, guide and OpenAPI spec in `internal/api/docs`), `internal/dashboard`, `internal/compose` (MIME), `internal/pgp` (PGP/MIME), `internal/keys` (agent signing keys), `internal/keyring` (credential encryption), `internal/admin` (admin password), `internal/recipients` (recipient registry), `internal/settings` (managed settings), `internal/store` (SQLite), `internal/config`, `internal/policy`.
