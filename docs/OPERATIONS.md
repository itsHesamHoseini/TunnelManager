# Operator guide
The installer owns only its controller stack and native agent. Existing tunnel/application units are discovered read-only until explicit adoption. Do not run fault tests on production.

## Start and inspect
```sh
sudo tunnelmanager status
sudo tunnelmanager doctor --output /root/tunnelmanager-doctor.json
sudo tunnelmanager logs
```
Use the URL printed by setup, normally https://panel.example.com:9443. Sign in and complete TOTP enrollment personally. The installer can save initial credentials in a root-only credentials.once file under its config directory; never copy that file into issues, screenshots or Git. Password reset revokes sessions; add --reset-mfa only for an intentional MFA recovery.

## Backup and update
```sh
sudo tunnelmanager backup --output /root/tunnelmanager.backup
```
Enter a separate backup passphrase at the hidden prompt. This archive includes the database and required protected runtime material; keep its passphrase separately and test restoration on a disposable machine.

Download the architecture binary and SHA256SUMS from the chosen official tagged release, inspect the checksum, then:
```sh
sha256sum tunnelmanager-linux-amd64
sudo tunnelmanager update --binary ./tunnelmanager-linux-amd64 --checksum EXPECTED_64_HEX_SHA256
sudo /opt/tunnelmanager-agent/tunnelmanager update --binary ./tunnelmanager-linux-amd64 --checksum EXPECTED_64_HEX_SHA256
sudo tunnelmanager doctor
```
The first command updates the controller through its own installer; the second updates an existing same-host agent through its retained installation marker. Use the actual agent install path if customized. Snapshot/health failure restores the owned previous files/state. Agent identity is retained. Upgrades do not adopt/restart existing tunnel services. Keep the source revision and protected snapshot path printed during deployment.

## Restore and rollback
```sh
sudo tunnelmanager restore --backup /root/tunnelmanager.backup --replace
```
Preview and confirm before replacing a populated controller database; provide the independent passphrase. Restore first in an isolated lab. The installer snapshots current files/database before replacement. Manual rollback uses the exact protected snapshot from that installation, not copied example paths. Never restore the database alone while discarding the master key.

Tunnel plans are separate: preflight → preview → prepare/backup both peers → arm local 90-second timer → activate → actual check → explicit keep/revert. A disconnected peer reverts locally. Partial confirmed-peer compensation retries after reconnection; newer intent/manual drift stops automatic overwriting and requires review. Inspect Operations for each peer's evidence. Intentional stopped configuration remains untested until started.

Manual config drift: read current redacted configuration, compare with the registered revision, then explicitly revoke management (preserving files/unit), rediscover, import and adopt the reviewed evidence again. Unsupported versions/options remain read-only; never overwrite them merely to clear a warning.

If recovery needs review because current files changed manually, explicitly preserving the current state disarms only that failed transaction's watchdogs and retains backups. It is not a successful rollback. Old affected revisions become observation-only until rediscovered/reimported/adopted. Revoking a certificate consumer pauses automatic deployment to prevent changing infrastructure outside current ownership.

## nginx
The normal installer includes a dedicated nginx edge with TLS, limits and agent WebSocket forwarding. An extra host nginx site is unnecessary when using the configured HTTPS port. Existing host proxies/sites are preserved.

For an owner-managed HTTPS proxy, explicitly choose proxy mode and bind the edge to loopback:
```sh
sudo tunnelmanager setup --tls proxy --bind 127.0.0.1 --port 9443 --domain panel.example.com --public-url https://panel.example.com
```
Add this location to the owner's existing TLS virtual host, then run nginx -t before reload:
```nginx
location / {
    proxy_pass http://127.0.0.1:9443;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 90s;
    client_max_body_size 64k;
}
```
The bundled edge observes the upstream proxy address in this mode; set upstream per-client abuse limits there and do not use a client-IP allowlist until the trusted proxy topology is verified. Direct edge deployment retains per-client limits. No SSH/firewall changes are part of this procedure.

## Certificates, recovery and measurements
Tunnel transport certificates are independent from website and backend/VLESS TLS. First deploy certificate/key to listener and public trust to dialer, then create TLS routes. Deploying a new linked revision includes every consumer; separate policy controls automatic renewal and deployment. Provider-token errors include prerequisites; inspect real provider behavior before enabling automation. Cloudflare DNS-01 is the implemented adapter.

Recovery targets one owned service, uses sustained observed CPU/RAM or failed-unit duration, cooldown and UTC daily ceiling. Missing samples reset duration; stop/disable intent persists. Temporary logging restores with a separate local timer even if the agent/controller stops. Finish or restore pending local changes before uninstalling.

History uses actual sample counts, seven days of detail and older weighted hourly observations up to 7/30/90 days. Gaps stay gaps. Counters are partial measured host-interface totals, not per-tunnel billing. Speed checks send at most 64 KiB to a configured echo target and are not link-capacity benchmarks. Independent process, TCP, TLS and application results carry source/target/time. Unconfigured application checks never imply VLESS health.
