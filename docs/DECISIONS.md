# Decisions
2026-10-15: The user authorized M1–M3 and installer deployment. The repository was initially described as private; after the API showed it public, the user explicitly authorized further public milestone pushes. Visibility was not changed. The existing clean main commit is the sole history base; no previous history is imported.
D1: Native agents initiate outbound TLS WebSocket; typed actions only. No SSH edits.
D2: PostgreSQL is the durable authority for sessions, enrollment, audit and measurements. No Redis.
D3: Single static Go CLI embeds UI and deployment templates. A small line-oriented wizard has explicit steps, inline validation, masked passwords and NO_COLOR support; external terminal frameworks are unnecessary.
D4: CSS design tokens and reusable React controls preserve the restrained visual direction. No chart library until real measurements require it.
D5: Initial account must enroll TOTP before ordinary API access. Telegram approval is optional, TOTP/recovery remains available during messaging outages.
D6: Existing shared reverse proxies are preserved. Cutover disables only the previous panel site and panel unit after a working replacement and rollback snapshot exist.
D7: Production is never used for fault injection. Native deployment is normal-path evidence; clean OS/failure tests run in CI on isolated disposable machines.

D8: Enrollment token is pasted into a hidden prompt instead of shell arguments/history. Command and token are supplied separately; the security tradeoff adds one paste.
D9: UI polls visible pages every 15 seconds; agent uses persistent TLS WebSocket and 30-second host samples. No extra collector or queue.
D10: The owner's production TOTP enrollment and recovery-code storage are performed personally; automation does not impersonate that owner or capture authentication material to create deployment screenshots.
D11: Retained-data reinstall starts only the owned database before snapshotting. Explicit purge removes only its verified database subtree and obsolete marker/initial credentials. Configuration/data relocation uses verified backup/restore into a fresh installation.

D12: M4-M6 use documented role-scoped options; unsupported identity/proxy/mapping semantics remain read-only instead of lossy conversion. Shared/batch actions validate revisions and execute distinct instances once. Independent local systemd timers handle config, certificate and temporary-logging restoration. Certificate policy CAS is independent from issuance revisions; renewal keeps the PKCS12 password used by existing consumers.
D13: M6 standardizes version 0.6.0 and Go 1.27.2, embeds source commit without build timestamps, and gates publication on exact-source native checks. No extra runtime service is introduced. Checksums are verified; no upstream signature is claimed for Rathole's older fixed artifacts. Live provider behavior/native ARM64/Debian11 remain separately untested.

D14: Normalize validated integral JSON numeric options to TOML integers at render time. Native multi-client tests exposed that TOML floats such as retry_interval=2.0 are rejected by the engines. Release89d9960 includes this correction; later evidence/test-only commits do not change its runtime code.
