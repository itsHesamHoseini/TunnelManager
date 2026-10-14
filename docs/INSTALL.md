# Installer and maintenance
Build once: npm ci --prefix web; npm run build --prefix web; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tunnelmanager-linux-amd64 ./cmd/tunnelmanager.
Use SHA256SUMS and install.sh for verified local artifacts; release bootstrap resolves an exact reviewed version and verifies its checksum before execution.
Interactive: sudo ./tunnelmanager setup. Automation: sudo ./tunnelmanager setup --yes --config setup.yaml --password-stdin.
JSON and YAML accept the same fields: mode, domain, port, dir, config_dir, language, tls, cert, key, bind, public_url, admin, profile, controller, ca. Configuration never accepts passwords or raw identity keys.
Example:
```yaml
mode: controller
domain: panel.example.com
port: 9443
dir: /opt/tunnelmanager
config_dir: /etc/tunnelmanager
language: en
tls: self-signed
profile: standard
```
Password input is hidden or protected stdin. In automation use --save-credentials to save a generated password once in a root-only runtime file. TOTP is mandatory before ordinary panel access; interactive terminal enrollment and web first-login enrollment share the same security contract.
Existing certificate: --tls existing --cert /path/cert.pem --key /path/key.pem (hostname/expiry/key match checked).
ACME: --tls acme-http requires free public port 80; --tls acme-dns requires protected TUNNELMANAGER_CLOUDFLARE_TOKEN for zone read/DNS edit. No SSH/firewall changes.
Proxy mode: --tls proxy --bind 127.0.0.1 --public-url https://panel.example.com; controller origin must equal the external HTTPS origin.
Day two: status, doctor [--output private-report.json], logs, config show, backup --output snapshot.backup, restore --backup snapshot.backup --replace, reset-admin-password, update --binary verified-binary --checksum EXPECTED_SHA256, uninstall.
Update snapshots configuration, executable and native pg_dump before health-checked replacement. Failed restoration keeps the controller stopped when recovery cannot be confirmed. Snapshots are root-only under the owned runtime directory. Exported backups have independent scrypt/AES-GCM encryption; keep the passphrase separate.
Restore preserves the target database role's current password, authenticates the archive before mutation, revokes sessions/challenges/enrollment, and uses transaction-safe native pg_restore. Run setup on a fresh destination first; then explicitly replace its empty controller state.
Node: sudo tunnelmanager setup --mode node --controller https://panel.example.com --token-stdin. For a private/self-signed CA, supply --ca /path/trusted-public-ca.pem. Node key is generated locally, mode 600. No management port opened; pending approval is explicit. --with-local-node installs/approves the controller host through the same signed protocol.
Known acceptance limitations remain in PROGRESS and REQUIREMENTS; production is never a fault-injection laboratory.
