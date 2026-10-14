#!/bin/sh
set -eu
[ "${CI:-}" = true ] || { echo "Disposable clean CI container only." >&2; exit 1; }
binary=/work/tunnelmanager
chmod 700 "$binary"
printf '%s\n' 'Synthetic-Clean-OS-Password!' | "$binary" setup --yes --install-docker --password-stdin --domain 127.0.0.1 --bind 127.0.0.1 --with-local-node
"$binary" setup --yes --config /opt/tunnelmanager/installation.json --with-local-node
"$binary" doctor
"$binary" doctor --mode node
printf '%s\n' 'Synthetic-Clean-Backup-Passphrase!' | "$binary" backup --output /work/clean.backup
printf '%s\n' 'Synthetic-Clean-Backup-Passphrase!' | "$binary" restore --backup /work/clean.backup --yes --replace
sha="$(sha256sum /work/tunnelmanager-fault | cut -d ' ' -f 1)"
if env TUNNELMANAGER_TEST_FAULT=after-start "$binary" update --binary /work/tunnelmanager-fault --checksum "$sha" --yes; then
  echo "Expected fault update to fail." >&2
  exit 1
fi
"$binary" healthcheck --url https://127.0.0.1:9443/healthz --ca /etc/tunnelmanager/tls/cert.pem --server-name 127.0.0.1
"$binary" uninstall --mode node --yes --keep-data=true
"$binary" uninstall --yes --keep-data=false
test ! -d /var/lib/tunnelmanager/postgres
echo "Clean OS signed Docker install/controller/native systemd node/rerun/backup/restore/fault rollback/owned data removal passed."
