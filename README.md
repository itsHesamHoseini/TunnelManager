# TunnelManager
A neutral, self-hosted control panel for Backhaul and Rathole across Linux servers.
Go + PostgreSQL + React/TypeScript. Native node agents initiate outbound TLS connections. Tunnel traffic continues when the controller is unavailable.

## Quick start
M1–M3 are implemented and deployed: protected login, reversible controller lifecycle and approved native nodes with real host metrics. Tunnel creation/adoption/control belongs to M4; see the [verified evidence and limits](docs/M1-M3-REPORT.md). This is not the complete product release.
Build from the reviewed checkout or use a verified local artifact; no tagged release is published yet:
```sh
npm ci --prefix web
npm run build --prefix web
node scripts/build.mjs
sudo env TUNNELMANAGER_BINARY=./artifacts/tunnelmanager-linux-amd64 TUNNELMANAGER_CHECKSUM_FILE=./artifacts/SHA256SUMS sh install.sh setup --with-local-node
```
Requires Node 24 and the Go version in go.mod on the build machine. The installer machine needs only the resulting static binary. The wizard previews the plan; Docker installation is a separate explicit choice. The first account must enroll TOTP and save recovery codes.
Default panel port: 9443. Runtime configuration: /etc/tunnelmanager. No SSH configuration changes.
See [progress](docs/PROGRESS.md), [contracts](docs/CONTRACTS.md), [acceptance](docs/REQUIREMENTS.md) and [Persian guide](README.fa.md).

## Architecture and security
Controller, PostgreSQL and HTTPS edge run in Compose. Only the HTTPS edge port is published. Native agents run under systemd, enroll using single-use short-lived tokens, require administrator approval, and prove their own locally generated identity before sending data.
Password + mandatory TOTP or single-use recovery codes. Optional Telegram approval. AEAD-encrypted secrets, master key outside the database, hashed sessions, typed actions and two-layer rate limits.
Host observations do not prove tunnel/application health; unknown and stale states are preserved.
Native clean installation/rerun/backup/restore/fault rollback is tested on Ubuntu 22.04/24.04 and Debian 12. Debian 11 and native ARM64 remain untested targets. Linux amd64/arm64 artifacts are cross-built.

## Development
`npm ci --prefix web && npm run build --prefix web`; `go test -p 1 ./... && go vet ./...`.
Set TEST_DATABASE_URL to an isolated PostgreSQL database to execute integration tests.
`node scripts/neutrality.mjs && node scripts/secrets.mjs`.
Docker smoke: `sh scripts/compose-smoke.sh`.

## Browser evidence
Synthetic server data, real browser/API:
![Persian server resources](docs/evidence/m3-resources-fa.png)
Deployment screenshots and private host inputs are kept outside tracked files.

## FAQ
No application users, subscriptions or inbound management. No web terminal. No automatic adoption of existing services. Existing infrastructure is never rewritten merely because it was discovered.

## Credits
[Backhaul](https://github.com/Musixal/Backhaul) and [Rathole](https://github.com/rathole-org/rathole) remain independent projects; engine downloads and license checks belong to the adapter milestone.
