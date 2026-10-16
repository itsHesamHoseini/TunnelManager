# M4–M6 operational evidence

Runtime candidate: `2b8ef3a`; integrated native base: `01af6d9`. This report distinguishes implemented behavior, native evidence and provider/platform limits. Publication and production update are still pending qualification of the current candidate.

## Completed workflows and evidence

- Native base [engine run 38882415283](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38882415283) ran two disposable Ubuntu/systemd nodes, PostgreSQL, the real controller, signed native agents and Chrome. Core engine tests took 362 seconds; full browser/API workflow took 869 seconds. Actual pinned Rathole 0.5.0 and Backhaul 0.7.2 carried verified HTTP traffic over Noise, TLS, TCP and WSS.
- Browser/API create → validation → preview → two-peer prepare → apply → actual path check → explicit confirmation, port editing, cloning with independent credentials, version restoration and unique-instance batch/lifecycle actions are exercised. Endpoint and reverse control direction remain distinct. A successful job is not a successful diagnostic result.
- Discovery/import/adoption preserves infrastructure until explicit adoption. Shared configuration expansion preserves other routes and supported scoped options. Candidate tests add a real shared listener with two distinct clients on the same node, sequential edits, and standalone unmatched foreign service adoption without a PID change. These expanded candidate results remain pending.
- Config and certificate changes use durable local systemd watchdogs with backups. Native certificate failure stopped an agent while its timer restored actual TLS/WSS traffic. Intentional stopped certificate consumers remain stopped; clients receive public trust without listener private identity. Candidate manual-drift tests preserve manually edited files and release only original failed watchdogs after explicit review.
- Real native detailed logging restores locally for both engines. Sustained RAM recovery runs with the controller path unavailable, restarts only the selected unit, preserves the unrelated HTTP backend and respects intentional stops. Host traffic is measured interface data, never per-tunnel billing.
- [Verify 38882415096](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38882415096) includes PostgreSQL, Go tests/vet, npm audit, native govulncheck, installer smoke and full history/directory secret scans. [Clean OS 38882415248](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/38882415248) covers Ubuntu 22.04/24.04 and Debian 12, actual backup/restore, failed-update recovery and uninstall/reinstall.
- Current Verify 38888955046 also passed: npm audit reports zero findings; govulncheck reports zero reachable-symbol/imported-package findings and one non-imported module-level advisory. This is not described as an advisory-free dependency graph. Full directory/history secret scans pass.

Current workstation tests pass with real PostgreSQL and Chrome, Go vet, Linux native-test compilation and UI build. Repeated static Linux amd64/arm64 builds have identical SHA256. CI publication independently repeats this check on Linux.

## Interface evidence

`docs/evidence/*fixture*` files show clearly synthetic browser states, including errors, stale data, pending operations and dark/mobile layout. They prove interface behavior only. Native workflow artifacts contain `m4-native-*-path-fa.png`, previews and a mobile page from the disposable real-engine environment. Test host names are deliberately synthetic; this is not production traffic.

Visual review retains the light background, restrained teal, Persian RTL/right sidebar, readable isolated technical fields, contextual tables/forms and progressive disclosure from DESIGN.md. Current status is not inferred from a running process or SSH. Operations retain timestamps, source/target, errors and next actions.

## Operator boundaries

- Existing foreign units can be adopted, inspected, edited, stopped, disabled or released from management. Removing their original files/unit is blocked. Panel-created units retain removal ownership after reviewed revocation/reimport. Affected shared routes are previewed together.
- Unconfirmed manual config/unit drift blocks automatic overwriting. Explicit preserve-current releases failed watchdogs, retains backups and marks old metadata observation-only; it is not labelled successful rollback. Rediscover/import/adopt current evidence before further changes. Revoked certificate consumers pause automatic deployment.
- Live Let's Encrypt/Cloudflare and Telegram delivery are **untested** without owner provider accounts. Protocol/fixture tests are not delivery evidence. Native ARM64 and Debian 11 are untested.
- Backhaul 0.7.2 WSS encrypts but does not verify peer certificate identity. The independent panel TLS probe is stricter; acknowledgement does not change engine behavior. Unknown versions, proxy/mutual-auth identities and unsupported mapping/range syntax stay read-only.
- A VLESS service needs an appropriate application check; TCP alone cannot prove it works. Ping/echo/limited speed tooling is bounded and does not establish a real link-capacity benchmark. ARM64 is cross-built only.
- Native receipts run in separate CLI processes; durable PostgreSQL request/job/replay behavior is tested. Forced OS controller termination in the middle of a mutation is not separately exercised. Independent watchdogs and disconnected agents are tested with actual service effects.
- Agent/controller upgrades use the verified CLI installer; a GUI self-updater is not claimed. Owner personally performs MFA enrollment. No owner authentication secrets are read or captured by test automation.

## Publication and deployment

Pending: current exact-source native checks; semantic tag, reproducible assets/SHA256, multi-architecture GHCR and actual bootstrap download; own-installer controller and same-host agent update; external strict HTTPS/auth/browser smoke and protected service baseline comparison. The independent encrypted pre-update backup and separate root-only passphrase have already been saved on the host. No existing tunnel has been adopted or restarted in production.

Use [OPERATIONS.md](OPERATIONS.md) for installation, nginx, verified upgrade and rollback. Environment-specific URLs, credentials and protected snapshot locations stay outside this public repository.
