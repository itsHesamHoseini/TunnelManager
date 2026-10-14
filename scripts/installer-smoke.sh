#!/bin/sh
set -eu
[ "${CI:-}" = true ] || { echo "Only disposable CI machines may run this destructive installer test." >&2; exit 1; }
root="$(pwd)"
dest="$root/.runtime/installed"
conf="$root/.runtime/installer-config"
mkdir -p .runtime
CGO_ENABLED=0 go build -o .runtime/installer ./cmd/tunnelmanager
cleanup() { sudo .runtime/installer uninstall --dir "$dest" --yes --keep-data=false || true; }
trap cleanup EXIT
printf '%s\n' 'Synthetic-Installer-Password!' | sudo .runtime/installer setup --yes --password-stdin --domain 127.0.0.1 --bind 127.0.0.1 --port 9443 --dir "$dest" --config-dir "$conf" --admin testadmin
before="$(sudo sha256sum "$conf/master.key" | cut -d ' ' -f 1)"
sudo .runtime/installer setup --yes --config "$dest/installation.json"
after="$(sudo sha256sum "$conf/master.key" | cut -d ' ' -f 1)"
[ "$before" = "$after" ]
sudo curl --fail --cacert "$conf/tls/cert.pem" https://127.0.0.1:9443/healthz
sudo .runtime/installer doctor --dir "$dest"
printf '%s\n' 'Synthetic-Reset-Password!' | sudo .runtime/installer reset-admin-password --dir "$dest" --yes
test "$(sudo curl --silent --cacert "$conf/tls/cert.pem" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"Username":"testadmin","Password":"Synthetic-Installer-Password!"}' https://127.0.0.1:9443/api/login)" = 401
test "$(sudo curl --silent --cacert "$conf/tls/cert.pem" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"Username":"testadmin","Password":"Synthetic-Reset-Password!"}' https://127.0.0.1:9443/api/login)" = 200
printf '%s\n' 'Synthetic-Backup-Passphrase!' | sudo .runtime/installer backup --dir "$dest" --output "$root/.runtime/test.backup"
printf '%s\n' 'Synthetic-Backup-Passphrase!' | sudo .runtime/installer restore --dir "$dest" --backup "$root/.runtime/test.backup" --yes --replace
CGO_ENABLED=0 go build -tags integrationfault -o .runtime/fault-installer ./cmd/tunnelmanager
sha="$(sha256sum .runtime/fault-installer | cut -d ' ' -f 1)"
if sudo env TUNNELMANAGER_TEST_FAULT=after-start .runtime/installer update --dir "$dest" --binary "$root/.runtime/fault-installer" --checksum "$sha" --yes; then
  echo "Expected fault update to fail." >&2
  exit 1
fi
sudo curl --fail --cacert "$conf/tls/cert.pem" https://127.0.0.1:9443/healthz
sudo .runtime/installer config show --dir "$dest"
echo "Native installer rerun, encrypted backup/restore, fault update rollback and uninstall passed."
