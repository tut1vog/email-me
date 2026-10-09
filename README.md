# email-me

Let your AI agents email you, without giving them your email password or even your address.

email-me is a small gateway you run on your own machine. Each agent gets a token and a few short names like `me` or `work`. The agent sends to `me`, and email-me turns that into a real email to you through your mail provider.

- **Agents never see your secrets.** Only email-me knows your real addresses and SMTP password.
- **You decide what each agent can do**: who it can email, how often, and how large its messages can be.
- **Nothing is kept.** Message content stays in memory only; the log records who sent what, when, not what it said.
- **Messages are signed**, so you can tell which agent sent them. They can also be encrypted to your PGP key.
- **No setup on the agent side.** An agent needs only a URL and a token; the API explains itself.

## Getting started

You need Docker on macOS or Linux.

**1. Install**

```sh
curl -fsSL https://github.com/tut1vog/email-me/releases/latest/download/install.sh | sh
```

**2. Start**

```sh
email-me start
```

The first run creates `~/.config/email-me`, which holds your settings and a secret key. **Back up this folder.** If you lose it, you lose your settings and the saved passwords and keys.

**3. Set it up in the dashboard**

```sh
email-me console
```

Open the login link it prints. The dashboard stays open until you press Ctrl-C. Then:

1. **Settings**: enter your mail provider's SMTP server, password and From address.
2. **Recipients**: add your email address.
3. **Agents**: create an agent, choose who it may email, and issue a token.

**4. Give the token to your agent**

The token page shows what to give the agent:

```
EMAIL_ME_URL=http://localhost:8025
EMAIL_ME_TOKEN=em_…
```

along with a short instruction to paste into the agent's prompt. That's it: the agent reads the guide at the URL and can start sending. For example:

```sh
curl -s -X POST $EMAIL_ME_URL/v1/messages \
  -H "Authorization: Bearer $EMAIL_ME_TOKEN" -H "Content-Type: application/json" \
  -d '{"to":["me"],"subject":"Nightly run finished","body":{"markdown":"## All green"}}'
```

## Commands

```sh
email-me start      # start the gateway
email-me stop       # stop it
email-me restart    # restart, e.g. after editing config.yaml or upgrading
email-me console    # open the dashboard (Ctrl-C closes it)
email-me version
```

The gateway starts again by itself after a reboot.

**Upgrade**: run `email-me update`. It installs the latest release over the binary, checking its checksum, and restarts the gateway on it if it is running.

## Agents on other machines

By default, only agents on the same machine can reach email-me. To let other machines in, expose **only the API (port 8025), never the dashboard**, and always use an encrypted connection, either:

- **a private network or tunnel**, such as Tailscale, WireGuard or SSH. Tick *Transport is encrypted outside email-me* on the Settings page.
- **an HTTPS reverse proxy**, such as Caddy. On the Settings page, set the trusted proxy and the public URL.
- **built-in TLS**: set `api.tls.cert_file` and `api.tls.key_file` in `config.yaml`.

Without encryption, message content travels in plain text. email-me still sends it, but shows a warning in the dashboard.

## Encryption

By default, messages are signed but not encrypted. To have them encrypted so that only you can read them:

1. Export your PGP public key:

   ```sh
   gpg --export --armor you@example.com
   ```

2. Paste it on your recipient's page under **Recipients** in the dashboard.

Agents can then ask for encrypted delivery; use it for anything sensitive. Your mail provider sees only ciphertext, and the real subject is hidden.

If even email-me must never see the content, an agent can encrypt the message itself (end-to-end). email-me can't sign what it can't read, so set *Require signing* to *no* in that agent's policy.

To verify signatures, download the agents' public keys from Settings and import them into your mail client.

## Configuration

Everything you set in the dashboard is saved to `~/.config/email-me/config.yaml` and applies right away. You can also edit the file by hand; run `email-me restart` afterwards.

Deleting the container never loses your configuration. Deleting its data volume (`email-me-data`) keeps your configuration too, but you'll need to issue new tokens and re-enter your SMTP password.

## Development

```sh
go test ./...
```

See [`CHANGELOG.md`](CHANGELOG.md) for release history.
