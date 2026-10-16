# Acceptance register
| ID | Requirement | Evidence/status |
|---|---|---|
| M1-01 | Neutral tracked content and full history | PASS: neutrality + gitleaks directory/full history before commits; native CI |
| M1-02 | Password + TOTP/recovery, sessions revoke, audit | PASS: real PostgreSQL and HTTPS Chrome enrollment/recovery/replay/revocation; deployment owner must enroll their own TOTP |
| M1-03 | Optional expiring Telegram approval | IMPLEMENTED: fixed-provider protocol/expired challenge/cooldown fixtures; real bot delivery untested, not configured |
| M1-04 | Edge and application limits, 429 Retry-After | PASS: concurrent/backoff/application tests; native nginx profile reload and HTTP 429 smoke in disposable CI |
| M1-05 | Bilingual responsive accessible calm shell | PASS: real Chrome Persian/English, desktop/mobile, keyboard/focus, empty/error states; evidence/m1-* |
| M1-06 | Compose isolated DB/controller; only edge exposed | PASS: native Compose HTTPS/auth gate; actual deployment publishes only 9443 for this stack |
| M2-01 | Wizard/JSON automation, preflight and summary | PASS: real installer automation, CLI preview, strict JSON/YAML fields, Linux/root/disk/memory/port/TLS checks; English terminal diagnostics remain available |
| M2-02 | Verified downloads; repeat setup preserves data | PASS: SHA256 local-artifact deployment, signed apt fingerprint check, rerun retains master key/admin/DB; published-release download awaits M6 release |
| M2-03 | doctor/status/config/logs/reset/version | PASS: real CLI/native commands; native password reset rejects old password/accepts new after backoff; controller/node doctor mode verified; config/doctor never read secret contents |
| M2-04 | encrypted backup/restore/update rollback/uninstall | PASS: actual pg_dump/pg_restore, independent authenticated encryption, tamper rejection, injected failed update rollback and owned-data purge; failed native agent repair is tested separately |
| M2-05 | Ubuntu 22/24 Debian 12 native clean/fault tests | PASS: native disposable systemd/Docker matrix 38655928807, including signed Docker install, rerun, backup/restore, fault update and data removal. Debian 11 and native ARM64 untested |
| M2-06 | Installer deployment, external smoke and rollback record | PASS: real installer public cutover, valid matching TLS, outside-host HTTPS/401/Chrome; protected rollback record retained on host; no production fault injection |
| M2-07 | Reinstall after kept-data and purged-data uninstall | PASS: native Verify 38657847358; retained master key/data survive reinstall, explicit purge clears marker and fresh account installation succeeds |
| M3-01 | One-time token, node-generated key, pending approval | PASS: real PostgreSQL consumption-once, pending signed connection rejected, HTTP fingerprint mismatch/duplicate approval rejection; native node local Ed25519 identity |
| M3-02 | Outbound TLS channel, identity replay rejection and reconnect | PASS: signed channel and protocol rejection tests, native systemd/outbound TLS/identity-retaining rerun; replay/duplicate coverage extended in channel_test.go |
| M3-03 | Real CPU/RAM/disk/network/process/listener/service data | PASS: native Linux CI and approved deployment host; at least two measured samples, actual process/interface/socket/service observations; host traffic never labelled tunnel usage |
| M3-04 | Practical node pages, history, stale/offline/empty/error states | PASS: real Go/PostgreSQL/Chrome API + signed synthetic fixtures, CPU/RAM/disk/NIC history and mobile; metadata CAS conflict test preserves draft; evidence/m3-* |
| M3-05 | Same-host native systemd agent, no SSH edits | PASS: installed through --with-local-node, outbound only, systemd limits, fresh acknowledgements; seven protected services/application listener PIDs unchanged |
M4–M6 remain in the unified product and must not be claimed complete by M1–M3.

Evidence index and operator checks: [M1–M3 report](M1-M3-REPORT.md). Live ACME/Cloudflare, real Telegram and owner first-login MFA are explicitly untested. No engine creation/adoption/restart controls are claimed by this register.

## Completion register (authorized 2026-10-16)
| ID | Acceptance test | Status |
|---|---|---|
| M4-01 | Verify official pinned Backhaul/Rathole artifacts and actual engine configs on Linux; unsupported versions are read-only | pending |
| M4-02 | Persist typed jobs/results; restart controller/reconnect agent without duplicate execution; reject expired/unknown actions | pending |
| M4-03 | Discover existing instances/routes without writes, evidence-pair peers, manually import ambiguous/shared routes, explicit adoption | pending |
| M4-04 | Create both engines between two nodes; render/validate/edit TOML; keep three endpoint concepts and direction distinct | pending |
| M4-05 | Reject occupied IPv4/IPv6/Docker ports, pending reservations, incompatible config/version/cert and concurrent/drift writes | pending |
| M4-06 | Preview redacted diff and all affected routes; prepare both nodes; native local rollback on failure/disconnect/timeout; explicit confirm | pending |
| M4-07 | Start/stop/restart/reload/disable/remove/clone/bulk/version-revert affect only selected owned instances; shared route impact visible | pending |
| M5-01 | Bounded searchable redacted native logs, severity/time filters, probable explanations and operation timeline; temporary verbosity reverts | pending |
| M5-02 | Real node-sourced TCP/TLS/ping/application tests, matrix and explicitly requested bounded speed test with scope/time/result | pending |
| M5-03 | Upload/self-signed/ACME issue/renew/deploy, hostname/key/expiry checks, linked-instance reload, secrets excluded; external provider evidence separate | pending |
| M5-04 | Sustained per-service CPU/RAM thresholds, cooldown/restart ceilings, persisted stop intent, reason audit and no whole-host restart | pending |
| M5-05 | Automatic bounded persistent monitoring and independent process/transport/application health; stale/unknown/gaps honest | pending |
| M5-06 | Alert suppression/cooldown, optional Telegram alerts and explicit expiring audited mutation confirmation | pending |
| M6-01 | Browser end-to-end workflows, FA/EN/light/dark/mobile/keyboard/drafts/errors/empty/long-operation progress compared with design | pending |
| M6-02 | 7/30/90-day retention/downsampling, actual scope and no interpolated missing observations | pending |
| M6-03 | Native clean install/update/backup/restore/failure/engine workflows in CI plus controller-offline data-plane continuity | pending |
| M6-04 | Full-history neutrality/secret audit and dependency vulnerability scan; fix findings, record limitations | pending |
| M6-05 | Multi-arch static release artifacts/SHA256, GHCR and semantic tagged-release workflow; official engine license attribution | pending |
| M6-06 | Verified deployment through own installer, preserved unrelated infrastructure, public HTTPS/browser smoke and exact rollback guide | pending |
