# email-me

A self-hosted, send-only email gateway that lets AI agents running anywhere email **you**, without ever holding your mailbox credentials or even knowing your address.

- Agents get a **token** and a list of **recipient aliases** (`me`, `work`). Only the gateway knows the real addresses and the SMTP password.
- **Per-agent policies** control which aliases, services, sizes and rates each agent gets.
- **Nothing is stored**: message bodies, subjects and attachments live only in memory; the audit log holds metadata.
- Messages are **signed with a per-agent OpenPGP key** held by the gateway (on by default), and can be **encrypted** to your key.
- The API **explains itself**: an agent only needs a URL and a token. `GET /` returns a usage guide written for LLMs and links to `/openapi.json`. No SDK, MCP server or CLI is needed on the agent side.
- A **dashboard**, opened on demand with `email-me console`, manages agents, tokens, policies, recipients, keys, settings and the audit log.
- Your **configuration lives on your machine** in `~/.config/email-me`, not in the container: deleting the container or its volume never loses it.

The agent-facing contract is the OpenAPI document in [`internal/api/docs/openapi.yaml`](internal/api/docs/openapi.yaml), served at `/openapi.json`; the guide agents read first is [`internal/api/docs/guide.md.tmpl`](internal/api/docs/guide.md.tmpl).

## Quick start

email-me runs in Docker; the `email-me` binary on your machine sets up and drives the container. You need Docker and macOS or Linux.

1. Install the binary:

   ```sh
   curl -fsSL https://github.com/tut1vog/email-me/releases/latest/download/install.sh | sh
   ```

2. Start the gateway:

   ```sh
   email-me start
   ```

   The first run creates `~/.config/email-me` with a commented starter `config.yaml` and a **key-encryption key** (`kek`), then starts the container. Both ports are published on `127.0.0.1` only: the agent API on `8025`, the dashboard on `8026`.

   The KEK is the only secret email-me needs from you: every credential it stores (the SMTP password, the agents' signing keys) is encrypted with it. **Back up `~/.config/email-me`**, KEK included: without it those credentials are lost, and the directory is your whole configuration besides.

3. Open the dashboard:

   ```sh
   email-me console
   ```

   It prints a one-time login link (`http://email-me.localhost:8026/login?token=…`; Chrome and Firefox resolve `*.localhost` to your machine) and keeps the dashboard open until you press Ctrl-C, which closes it and signs you out. There is no password: whoever can run `email-me console` on this machine is the operator.

   On the **Settings** page, set the upstream SMTP server, its password and the From address. On the **Recipients** page, add your address (optionally pasting your PGP public key). Then create an agent, grant it one or more aliases, and issue a token. The token page shows everything to hand to the agent:

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

Why `email-me.localhost` instead of `localhost`: browsers send a host's cookies to every port on it, so if you visit a web server that some local process (an agent, say) runs on `localhost:3000`, it would receive your dashboard session cookie. A dedicated host name keeps the cookie to email-me.

## Commands

```sh
email-me start                 # create and start the container; the first run writes ~/.config/email-me
email-me stop                  # stop it; sends in flight finish first
email-me restart               # stop, then start: applies config.yaml edits and a new version
email-me console               # open the dashboard and print a login link; Ctrl-C closes it
email-me reset-keyring --yes   # lost KEK: discard the credentials encrypted with it
email-me version
```

`start` checks `config.yaml` first and lists every problem, so a typo never replaces a running gateway; if the gateway then fails to start, it shows the container's log. The container is recreated on every start: everything durable is in `~/.config/email-me` and the `email-me-data` volume. It restarts with Docker after a reboot, so no service unit is needed.

The image's tag follows the binary's version: rerun the install script, then `email-me restart`, to upgrade. `EMAIL_ME_IMAGE` overrides the image (e.g. a local `docker build -t email-me:dev .`), `EMAIL_ME_CONFIG_DIR` the configuration directory. Inside the image the gateway runs as `email-me run`, which also works directly on a host without Docker, under any supervisor, with `console` beside it.

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

- **`config.yaml`** in `~/.config/email-me` is the source of truth for everything you decide: the upstream SMTP server, the From address, the API's public URL, guide access and trusted proxies, the default policy, audit retention, signing-key validity, the recipients with their PGP public keys, and the agents with their policies. It holds no secret.
- **Changes on the dashboard** are written to `config.yaml` and apply at once, without a restart: the next send uses the new upstream server and policy. Only the keys you changed are rewritten; your comments and the rest of the file stay.
- **Editing `config.yaml` by hand** works too; run `email-me restart` to apply it. Until then the dashboard shows a banner and refuses changes, since saving would overwrite your edit. The listen addresses, `api.tls`, `kek` and `log` (the bootstrap keys) can only be changed this way. Paths in the file are relative to its directory, the only part of your machine the container sees.
- **Credentials** live in `state.db` in the `email-me-data` volume: token hashes, and, encrypted with a random data key that is itself encrypted with the KEK, the SMTP password, the agents' signing keys and the certification key. Without a KEK (an empty `kek` file), signing is off and the SMTP password is stored unencrypted. `state.db` also holds the audit log.
- **Losing the volume** loses only `state.db`: your configuration survives, agents keep their policies, but tokens must be reissued, the SMTP password and certification key entered again, and agents get new signing keys. An agent removed from `config.yaml` by hand keeps its tokens and keys in `state.db`, inert; adding it back revives them, and creating it anew on the dashboard deletes them.
- **Health**: the image has a Docker `HEALTHCHECK` (`email-me healthcheck`), and `GET /healthz` on the API.
- **Rotating the KEK**: rename `kek` to `previous_kek`, write a new key to `kek` (`openssl rand -hex 32`), and run `email-me restart`. The start re-encrypts the data key with the new KEK (one row, nothing else changes). Then delete `previous_kek` and restart again; the dashboard reminds you until you do.
- **Lost KEK**: the gateway no longer starts and says so. `email-me reset-keyring --yes` discards the encrypted credentials (the SMTP password, the certification key, and the agents' signing keys, which are retired); write a new `kek`, run `email-me start`, and agents get new keys. Everything else is kept.

## Development

```sh
go test ./...   # unit + integration tests (fake SMTP server in-process)
```

CI (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request: `gofmt`, `go mod tidy`, `go vet`, `go test -race`, `shellcheck install.sh` and a multi-platform image build.

Releases: pushing a tag such as `v1.2.3` runs `.github/workflows/release.yml`, which runs the CI checks, takes the release notes from the `## [1.2.3]` section of `CHANGELOG.md` (and fails without one), attaches the macOS and Linux tarballs, `checksums.txt` and `install.sh` to a GitHub release, and pushes the image to `ghcr.io/tut1vog/email-me` (`1.2.3`, `1.2`, `latest`). A tag with a suffix (`v1.2.3-rc.1`) makes a prerelease that the install script and `latest` skip, with notes generated from the commits.

Layout: `cmd/email-me` (binary), `internal/host` (the host commands that drive Docker), `internal/console` (opening the dashboard on demand), `internal/api` (agent API, guide and OpenAPI spec in `internal/api/docs`), `internal/dashboard`, `internal/compose` (MIME), `internal/pgp` (PGP/MIME), `internal/keys` (agent signing keys), `internal/keyring` (credential encryption), `internal/config` (`config.yaml`, and editing it in place), `internal/settings` (applying the dashboard's changes), `internal/recipients` (recipient input), `internal/store` (SQLite), `internal/policy`. `config.example.yaml` is the starter configuration `email-me start` writes.
