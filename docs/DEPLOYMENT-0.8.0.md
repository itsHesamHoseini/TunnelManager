# 0.8.0 qualification and protected deployment — 2026-10-24

Runtime source: `d1230c8f15c43e61bd719a1fa595c13b7834194c`; local text equivalent `8912fd7`. Documentation-only follow-ups do not change that deployed source or retag the release.

| Evidence | Result |
|---|---|
| [Native Linux/Chrome/systemd/Backhaul](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249185) | PASS: full controller1200.08s, independent four-edit failure matrix433.23s, real TCP/WSS/HTTP, shared adoption/restore, certificates/recovery and 90-second rollback |
| [Verify/security/Compose/installer](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249241) | PASS; no secret/authentication/rate/rollback safeguard disabled |
| [Clean OS installation](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249212) | PASS: Ubuntu22/24 and Debian12; not native ARM64 |
| [Bounded native diagnostics](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249172) | PASS |
| [Release/GHCR/public bootstrap](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40073441248) | PASS; main fast-forward and tag updated atomically without force |

[Published0.8.0](https://github.com/itsHesamHoseini/TunnelManager/releases/tag/v0.8.0) artifacts match the exact-source local cross-build byte-for-byte:

```text
c31e19da1c668c26d9a794957fc1afeaa293da1f809eba7ca13cfbe88506ab1b  tunnelmanager-linux-amd64
b5e1fe982a27dc22c8c90ea17fb9d17e8eb256ffe8acd30c57801639cf83ff38  tunnelmanager-linux-arm64
```

The owner explicitly authorized finishing remaining work and production publication after the prior no-deployment correction. The existing installer updated the controller and ten reachable existing agents. An independent encrypted controller archive with a separate root-only passphrase preceded installation; startup also created a304035534-byte row-wise encrypted migration archive. Installer snapshots and actual previous-binary hashes provide rollback targets. Master key, existing admin/MFA, agent identities, protected configuration hashes, service states/PIDs and TCP listeners were retained. No existing engine instance was adopted, stopped, restarted, disabled or rewritten. No production fault injection or live VLESS test occurred.

Actual Chrome verifies strict public TLS, runtime source/version, unauthenticated API401, Persian RTL/English and mobile layout. Direct access from this workstation reset before deployment too; both before/after checks use a temporary loopback proxy through the previously verified SSH path, preserving domain/SNI and certificate verification. Owner authentication was not accessed. The temporary review proxy is removed after inspection.

Latest dated operational evidence:12 enrolled nodes;9 fresh signed observations,2 old and1 never observed. All ten updated agent services are active; a transient reconnect on one observed agent subsequently returned connected and fresh. Two SSH endpoints remain unreachable both directly and through the approved jump path, so their previous installations were untouched and updated addresses/ports were requested. The pre-existing unobserved agent still cannot deliver telemetry despite an active process and successful bounded HTTPS; no root cause or fix is invented. Current inventory has29 Backhaul services,12 observation-only tunnel records and0 managed tunnels. Inventory count alone is not management completion or VPN-health evidence.

Environment-specific receipts, encrypted-backup/key locations, fingerprints, endpoint diagnostics, actual screenshots of the public production login and per-host rollback commands are kept in the private operator handoff, outside Git. The public native artifact12551928293 has verified SHA256 `a2705a9c9a1a0cbec577d8073e8350e8f244b5fd6794726363cebc7b810c05d6`; it contains actual Chrome screenshots and the edit video, not owner credentials. See [selected native output](evidence/revision2/native-qualified-d123.txt), [navigation evidence](evidence/revision2/navigation-080.txt) and [WP acceptance/limits](REVISION-2-REPORT.fa.md).

Known limits remain explicit: cross-tunnel configuration/token rotation has no qualified group rollback and is not exposed; single-tunnel coordinated editing and existing batch lifecycle are available. Real owner configuration corpus coverage, application-specific VLESS, live external CA/DNS/Telegram provider delivery, fresh interactive-sudo bootstrap and native ARM64/Debian11 are untested. Optional SSH bootstrap, VLESS core and agent privilege redesign remain proposals, not silently implemented architecture.
