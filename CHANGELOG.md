# Changelog

All notable changes to email-me are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.4] - 2026-10-11

### Changed

- **Send test message moved to the Recipients list** — each recipient row now has a Send button in its Test message column, and the recipient's own page no longer offers one.

## [0.1.3] - 2026-10-11

### Added

- **HTML emails keep their layout and can show images** — `html` bodies keep inline `style` attributes and table-layout attributes, and an attachment with a `content_id` appears inline wherever the HTML has `<img src="cid:<content_id>">`.

### Changed

- **`html` bodies with remote images are rejected** — an `<img>` whose source is not `cid:` pointing at an inline attachment now fails with `422`; attach the image with a `content_id` instead.
- **`html` bodies are no longer styled by the gateway** — they appear exactly as the agent styled them; markdown bodies keep the gateway's styling.

## [0.1.2] - 2026-10-09

### Added

- **`email-me update` installs the latest release** — it replaces the binary after checking its checksum and restarts the gateway on the new version if it is running, so the install script is needed only once.

## [0.1.1] - 2026-10-09

### Changed

- **Send test message moved to each recipient's page** — open a recipient in the dashboard and use the button in its header, which tells you what is missing while SMTP is not configured; the Settings page keeps Test connection.

### Fixed

- **Saving or testing SMTP settings no longer looks finished when it is not** — the dashboard now names the missing host or From address until agents can send, and marks both fields as required.

## [0.1.0] - 2026-10-09

### Added

- **First release** — a send-only email gateway that lets AI agents email you through a REST API, with per-agent tokens and policy, PGP encryption and signing, and a dashboard opened by `email-me console`.
