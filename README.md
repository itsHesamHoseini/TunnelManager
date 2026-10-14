# TunnelManager
A neutral, self-hosted control panel for Backhaul and Rathole across Linux servers.
Go + PostgreSQL + React/TypeScript. Native node agents initiate outbound TLS connections. Tunnel traffic continues when the controller is unavailable.

## Quick start
M1–M3 development is in progress; release installation is not yet accepted.
From a verified release artifact: `./tunnelmanager setup`. The wizard previews changes before installing.
Default panel port: 9443. Runtime configuration: /etc/tunnelmanager. No SSH configuration changes.
See [progress](docs/PROGRESS.md), [contracts](docs/CONTRACTS.md), [acceptance](docs/REQUIREMENTS.md) and [Persian guide](README.fa.md).

## Architecture and security
Controller, PostgreSQL and HTTPS edge run in Compose. Only the HTTPS edge port is published. Native agents run under systemd, enroll using single-use short-lived tokens, require administrator approval, and prove their own locally generated identity before sending data.
Password + mandatory TOTP or single-use recovery codes. Optional Telegram approval. AEAD-encrypted secrets, master key outside the database, hashed sessions, typed actions and two-layer rate limits.
Host observations do not prove tunnel/application health; unknown and stale states are preserved.
Supported installation targets: Ubuntu 22.04/24.04 and Debian 11/12; actual OS evidence is tracked separately.

## Development
`npm ci --prefix web && npm run build --prefix web`; `go test -p 1 ./... && go vet ./...`.
Set TEST_DATABASE_URL to an isolated PostgreSQL database to execute integration tests.
`node scripts/neutrality.mjs && node scripts/secrets.mjs`.
Docker smoke: `sh scripts/compose-smoke.sh`.

## FAQ
No application users, subscriptions or inbound management. No web terminal. No automatic adoption of existing services. Existing infrastructure is never rewritten merely because it was discovered.

## Credits
[Backhaul](https://github.com/Musixal/Backhaul) and [Rathole](https://github.com/rathole-org/rathole) remain independent projects; engine downloads and license checks belong to the adapter milestone.
