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

CI run 38651905822 (source 24af4d3) passed native Ubuntu 24.04 Compose HTTPS, private API gate, installer rerun, pg_dump encrypted archive, pg_restore, injected update failure rollback and uninstall, plus Go/PostgreSQL/vet and complete history scans. M3 adds explicit connection vs freshness, public fingerprints, metadata CAS, scoped NIC byte deltas, socket counts, summarized history and server browser fixtures. A clean OS matrix is added for Ubuntu 22/24 and Debian 12; results pending. Production cutover remains pending.

Clean OS matrix failure diagnosed from native Docker journal: nested overlayfs over the outer container's overlay backing filesystem was rejected. CI gives the inner Docker/containerd data directories private tmpfs backing; production Docker configuration is unchanged. Tests remain enabled.

Native M3 CI run 38654900795 passed systemd agent installation, signed outbound TLS, two real host samples, identity retention on rerun and uninstall. Clean OS run 38655301319 passed Ubuntu 22.04/24.04 and Debian 12 after storage isolation. Latest fixes add explicit owned-data purge (preserving backups), live resource history, disk/primary-NIC charts and bounded security notifications; browser/PostgreSQL tests passed. Matrix now also runs fault rollback and verifies owned data removal per distribution.

Public replacement accepted through own installer with a matching existing certificate. External HTTPS and private API gate passed; the native same-host agent is approved with real fresh CPU/RAM/process/socket/service observations. Seven protected services and the application listener kept the same process IDs. Only the previous panel unit/site were disabled; their protected dated backup is retained outside Git. Browser desktop/mobile public login was verified without bypassing TLS. Administrator first-login TOTP enrollment remains the owner's action; no production credentials were read or captured. Follow-up fixes make doctor --mode node resolve the native agent from a controller installation, redact container labels/paths and restore failed native agent repairs.

Acceptance register and M1–M3 operational report now distinguish measured/native/browser evidence from untested provider behavior and later milestones. Additional security coverage rejects signed nonce replay/duplicate connections, verifies real nginx 429/Retry-After and profile reload in disposable CI, and exercises the password-reset CLI through real HTTPS login. Production owner enrollment, real Telegram/ACME, Debian 11/native ARM64 remain explicitly untested.

Final installer review fixed automated bootstrap stdin handling: --yes keeps protected password stdin rather than opening /dev/tty. Native CI now enters fresh setup through install.sh, first proves checksum mismatch makes no installation, then executes the verified artifact. No release-download success is claimed before M6 publishes artifacts.
