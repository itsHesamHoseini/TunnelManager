# Progress
2026-10-15 (Asia/Tehran).
M0 completed: clean upstream README-only repository, current main fetched; no unrelated service changes. Dedicated repository deployment key created outside checkout.
M1–M3 authorized and in progress. Previous software remains running until staged replacement passes health checks. Production host parameters remain runtime-only.

M1 checkpoint: Argon2id/MFA/recovery/session revocation/audit, enrollment authority, bilingual responsive shell and edge/application limits implemented. Real native PostgreSQL integration and Chrome HTTPS browser scenarios passed. Screenshots under docs/evidence; no enrollment secrets captured. Go test/vet and tracked/history neutrality plus full gitleaks scans passed. Compose native smoke awaits CI; live Telegram is unconfigured and not verified with a real bot. M2/M3 remain in progress.

Repository visibility was discovered to be public via GitHub API after the M1 push. No visibility change was performed. Local implementation continues; further pushes wait for the user's explicit public-push authorization or private visibility. Full tracked/history scans found no secrets before M1 publication.

User reply: continuing milestone pushes to the existing public repository is explicitly authorized. Visibility stays unchanged.

CI run 38645811734 failed before tests: the workstation npm registry mirror was inherited in lockfile URLs and timed out on GitHub. Lockfile download URLs now use the public official npm registry with unchanged package integrity hashes. No tests were removed or disabled. Native Compose still awaits the corrected CI run.

M2 implementation checkpoint: single CLI with previewed setup/repair, validated TLS modes, hidden inputs, terminal TOTP QR/recovery and optional Telegram, native Docker lifecycle, protected snapshots, independent encrypted backup, transaction-safe restore, verified local binary update and uninstall. Signed native node runtime is staged for M3. Native clean/fault installer evidence awaits CI; live CA/Cloudflare/Telegram and ARM64 are untested. No production cutover yet.

Private native staging succeeded through the real installer: controller/DB/proxy running on loopback with an existing matching certificate. Public site unchanged; no tunnel actions. CI reached native Compose: the generated fixture private key was owned by the unprivileged runner while the hardened edge had no DAC override capability. Fixture ownership is now root-only, matching actual installer behavior; secret permissions were not relaxed. M3 node identity/telemetry UI verification continues.
