# M1–M3 evidence and operational limits

The controller and approved native host agent are deployed through the project's own installer. This checkpoint provides protected access, reversible controller maintenance and real server observation. Engine management remains M4; logs/diagnostics/tunnel certificates/alerts remain M5; public tagged artifacts and full release qualification remain M6.

## Verified behavior

- Real PostgreSQL + Chrome HTTPS: password/TOTP enrollment, recovery, session revocation, Persian/English, desktop/mobile, empty/error states. Public login was checked in Chrome with certificate validation enabled. The owner's production TOTP has not been enrolled by automation.
- Native Ubuntu 24.04 CI: HTTPS Compose stack, auth gate, actual pg_dump/pg_restore, encrypted backup, repeat setup, failed-update rollback, uninstall and native systemd node telemetry.
- Clean Ubuntu 22.04/24.04/Debian 12 CI: Docker installed via fingerprint-verified signed apt packages, native systemd agent, repeat setup, backup/restore, failed-update rollback and owned database removal. Disposable nested Docker uses private filesystem backing; no production kernel/Docker changes were used for these tests.
- Normal deployment: existing matching public certificate reused; only edge 9443 exposed by the stack; independent native agent with real CPU/RAM/process/listener/socket/service samples. Seven protected services and the application listener kept their PIDs through cutover. SSH remained usable.
- No old service/configuration was adopted into tunnel management. The old panel site and panel unit alone were disabled, with dated root-only backups and its previous database/key retained.

## Operator review

Retrieve initial login details in your own trusted terminal from `/etc/tunnelmanager/credentials.once`. Enroll TOTP at first login and save recovery codes privately. No production password, recovery code, token or QR image is in this repository.

Inspect the approved controller host under Servers. The first CPU/rate sample may be unknown; deltas need two samples. Resources show root-filesystem disk and primary-interface rate history. Processes use one-core CPU percent. Network usage covers observed primary-interface intervals in the UTC calendar month; gaps, resets and boot changes are not counted as known usage. Agent connection and process state do not prove transport/application health.

Useful commands:

```sh
sudo tunnelmanager status
sudo tunnelmanager doctor
sudo tunnelmanager doctor --mode node
sudo tunnelmanager config show
sudo tunnelmanager logs
sudo tunnelmanager backup --output /var/backups/tunnelmanager.backup
```

Backup asks for a separate passphrase. Exported backups are not removed by database purge. Node repair restores its previous binary/config/unit and running/enabled state on failure. A failed fresh node install can leave a pending identity for explicit removal or repair in the panel.

Updates require a trusted binary checksum:

```sh
sudo tunnelmanager update --binary ./tunnelmanager-linux-amd64 --checksum EXPECTED_SHA256
sudo tunnelmanager setup --yes --with-local-node
```

The first command snapshots the controller and database. The second repairs/upgrades only the installer-owned local agent, retaining its identity. Different controller origins/directories are rejected rather than silently adopted.

## Rollback record

The deployed host retains a dated root-only cutover backup outside the repository, plus installer snapshots under the owned installation's `.runtime/snapshots`. It includes the previous panel's unit/binary/config/database, dedicated reverse-proxy site and protected-service baseline. For an ordinary failed update the installer restores its own controller snapshot automatically. Manual return to the previous panel requires stopping only the new controller stack, restoring only the saved dedicated site, testing/reloading the shared reverse proxy, and starting the previous panel unit. Never stop the shared reverse proxy or tunnel/application services.

## Genuine limitations

- A real Telegram bot and real ACME/DNS account were not supplied: provider behavior is untested. Telegram protocol fixtures are not provider delivery evidence.
- The installed existing certificate is copied into protected runtime storage; renewing its source does not automatically deploy that new copy. Until M5 renewal/deployment orchestration, run the reviewed setup/repair after renewing the source certificate and check HTTPS.
- ARM64 artifacts are cross-built; native ARM64 and Debian 11 behavior are untested.
- M3 retains seven days of host summaries, and displays the latest 240 samples. Advanced retention/downsampling, connectivity matrices and per-tunnel traffic require later milestones.
- Full engine service control, logs, certificates and configuration import/adoption are not counted complete by M3. The registered node provides observations without changing existing infrastructure.
- Release bootstrap requires a published tagged release or a reviewed local artifact. M6 has not published a tagged release; never claim the remote one-line installer already has released binaries.

Browser fixture images in `evidence/` are clearly synthetic and contain no deployment inputs. Actual deployment screenshots and private rollback paths stay in ignored local runtime files.
