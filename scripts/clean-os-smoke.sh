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
"$binary" uninstall --mode node --yes --keep-data=true
"$binary" uninstall --yes --keep-data=true
echo "Clean OS signed Docker install/controller/native systemd node/rerun/backup/restore/uninstall passed."
