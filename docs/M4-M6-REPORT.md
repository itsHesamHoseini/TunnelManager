# M4–M6 delivery and operational evidence

Released and deployed: **v0.6.0**, runtime source `89d9960278566c484bf0676d75a05bdb1c69bb2b`. Later commits add tests, images and reports only; production runtime code and dependency versions are unchanged.

[Release downloads](https://github.com/itsHesamHoseini/TunnelManager/releases/tag/v0.6.0) · [Persian task guide](QUICKSTART.fa.md) · [Installer/nginx/rollback](OPERATIONS.md) · [Acceptance register](REQUIREMENTS.md)

## Qualification

| Evidence | Result and actual scope |
|---|---|
| [Verify38917694921](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38917694921) | Go/PostgreSQL/vet, npm audit, native govulncheck, full directory/history scans, actual installer/backup/restore/failure smoke |
| [CleanOS38917694897](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38917694897) | Ubuntu22.04/24.04 and Debian12 disposable systemd/Docker install, repeat/update/restore/failure/uninstall |
| [Native38917694925](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38917694925) | Two real Linux/systemd peers, official engines, controller, PostgreSQL, signed TLS agents and actual browser; core365s, integrated1102s |
| [Diagnostics38923606607](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38923606607) | Unchanged runtime: actual Linux loopback TCP/TLS/HTTP/ping/echo, explicit bounded samples and durable receipts; additional test source f5abbd8,2.11s |
| [Release38921423421](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38921423421) | Exact-source gates, repeated reproducible static binaries/SHA256, multi-architecture GHCR, public assets and actual bootstrap download/execution |
| Production normal update | Own controller and native agent installer upgrades; outside-host strict HTTPS/version/source/401 and actual Chrome FA/EN/mobile login smoke;11 protected units and application listener retained |

## What works end to end

- Discover actual services/configs without writes; pair on address/transport/authentication evidence and manually import ambiguous peers. Unmatched services stay visible and can be explicitly adopted individually. Native standalone foreign-service adoption preserves its PID, then stop/start works; original-file removal stays guarded.
- Install checksum-pinned Rathole0.5.0 and Backhaul0.7.2. Browser create → validate → review diff/impact → prepare both peers → apply with local rollback → check actual HTTP → explicit confirmation passes over Rathole Noise/TLS and Backhaul TCP/WSS. User entry, transport listener/dialer and backend endpoints/direction remain independent.
- Shared listener with two distinct clients on the same node: import/adopt, sequential port changes and actual HTTP on both resulting routes pass. Supported per-client retry settings, other-route options and per-instance revision hashes are preserved. Clone generates independent credentials; version restoration, unique-instance batch actions, disable/start and owned removal are exercised through the real API/agents.
- Config/certificate plans preserve backups, CAS and file/unit drift checks. Independent real systemd timers restore actual traffic without an executor or while an agent is stopped. Manual config/unit drift blocks automatic overwriting. Explicit preserve-current releases only original failed watchdogs, keeps backups and marks affected old metadata observation-only; it is not called successful rollback.
- Actual engine logs are bounded/redacted. Temporary detailed logs restore locally for both engines. Additional real Linux tests prove TCP/TLS/HTTP, invalid-hostname/HTTP503 failure results, ping3, echo128B and an explicitly confirmed sample at most64KiB. A recreated executor returns its persisted receipt without another HTTP request and rejects changed/expired retries.
- Self-signed issuance/deployment, real TLS/WSS paths, renewal and automatic linked rotation pass. Intentional stopped consumers remain stopped; clients receive public trust without listener private identity. A real listener-certificate fault recovers actual HTTP through its independent timer after its agent stops.
- Sustained RAM recovery is tested while the controller route is unreachable: only the selected unit restarts after60s, with120s cooldown and daily ceiling; the unrelated backend and a later explicit stop remain preserved. CPU/gap logic has unit coverage. Automatic monitoring uses persistent bounded jobs, separate process/transport/TLS/application results and honest freshness/history. Both stopped agents leave actual engine HTTP working.
- Real PostgreSQL tests cover encrypted state, port reservations/concurrent changes, retention7/30/90-day weighted UTC observations, Telegram suppression/cooldown and one-time expiring mutation approval. Actual Chrome covers login/MFA, FA/EN, light/dark, mobile/keyboard, empty/error/stale/waiting and draft retention, including rejected logout preserving the draft/session.

## Release and deployment

Static Linux amd64/arm64 binaries and checksums are public. Anonymous GHCR manifest retrieval confirms both platforms at `ghcr.io/itshesamhoseini/tunnelmanager-controller:v0.6.0`. Local Windows cross-build bytes match the published Linux-built amd64 artifact:

```text
92dd60b33a2ea0376cdda38af042c960e72345aafdc04fd06e13c6026b6f6036  tunnelmanager-linux-amd64
3494d3648dbd0d7f50cdfaa2e6eb529beb3e51bd8f0eddfb8b9b016cc0672eaa  tunnelmanager-linux-arm64
```

Both deployed executables match the reviewed amd64 artifact. Independent encrypted pre-update backup, separate root-only passphrase, controller/agent snapshots and exact previous-binary rollback commands are saved in the private operator record outside Git. All11 protected unit states/PIDs and the application listener were unchanged during update; master and native node identity were retained. One approved node/admin remains, signed observations are fresh, schema4 is active and automatic inventory discovered six actual services. Zero existing tunnels were automatically adopted. Pairing requires registering the other peer; inventory alone is not invented into a verified complete path.

The owned controller/database/edge are healthy and this stack publishes only its configured HTTPS port. Outside-host actual Chrome verifies strict TLS, matching0.6.0/source89d9960, private API401, Persian RTL, English and mobile without overflow. Production owner authentication/MFA was not impersonated or captured. Production fault injection and existing-tunnel changes were not performed.

## Interface evidence

Native screenshots below come from actual disposable Linux engines/agents/browser. Their host names are deliberately labelled Synthetic; they are not production traffic. Fixture images elsewhere prove interface states only and are labelled `fixture`.

- [Actual Rathole path and layered results](evidence/m4-native-rathole-noise-path-fa.png)
- [Actual Backhaul WSS path](evidence/m4-native-backhaul-wss-path-fa.png)
- [TLS form, redacted diff and impact preview](evidence/m4-native-rathole-tls-preview.png)
- [Actual native mobile view](evidence/m4-native-mobile.png)
- [Failed diagnostic fixture](evidence/m6-diagnostic-error-fixture-fa.png), [waiting fixture](evidence/m6-operation-waiting-fixture-fa.png), [dark fixture](evidence/m6-dark-tunnels-fixture-fa.png)

Visual review retains DESIGN.md's light surface, restrained teal, Persian right sidebar, isolated technical fields, functional tables/forms and progressive disclosure. Build success alone was not acceptance evidence.

## Explicit verification and support boundaries

- Live Let's Encrypt/Cloudflare and Telegram delivery are **untested** without owner provider accounts; fixed-provider/protocol fixtures are separate evidence. Native ARM64 and Debian11 are untested; ARM64 is cross-built, not executed.
- Backhaul0.7.2 WSS encrypts but does not verify peer certificate identity. Independent panel TLS checks are stricter; acknowledgement does not change the engine. Unsupported versions, proxy/mutual-auth identities and mapping/range semantics remain visible/read-only.
- VLESS needs an appropriate application check. TCP/SSH/process success is insufficient. Traffic is measured host-interface data with real gaps, not per-tunnel billing. Bounded echo is not WAN capacity measurement.
- Existing foreign units can be adopted, inspected, edited, stopped, disabled or released from management. Deleting their original files/unit is blocked. Panel-created instances retain removal ownership after reviewed revocation/reimport. Revoked certificate consumers pause automatic deployment.
- Native command processes/receipts and reconnection are exercised, including additional persisted executor reconstruction. Forced OS controller termination in the middle of a mutation is not separately exercised. Independent watchdogs/disconnected agents are tested with actual service effects.
- Controller/agent upgrade is a verified CLI workflow; a GUI self-updater is not claimed. Owner personally enrolls MFA. Automatic backend health does not infer a missing application check.
- npm audit reports zero findings; govulncheck reports zero reachable-symbol/imported-package findings. GO-2026-5932 concerns deprecated `x/crypto/openpgp`, has no fixed version and is absent from production build imports; the dependency graph is not described as advisory-free. The workstation vulnerability endpoint returned403; successful native CI is the audit evidence.

## Failures investigated rather than hidden

Expanded native2b8ef3a found JSON integer options rendered as TOML floats (`retry_interval=2.0`), which native engines rejected. A structural regression test first reproduced the failure; release89d9960 fixes the render boundary and passes actual shared-service traffic.

The added negative TLS fixture initially used `wrong.example.com`, covered by Go's sample wildcard `*.example.com`. Public certificate inspection confirmed the fixture mistake. It now asserts `rejected.invalid` is outside the certificate before testing actual rejection. No production validation or failing assertion was disabled.
