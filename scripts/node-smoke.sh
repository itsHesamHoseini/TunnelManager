#!/bin/sh
set -eu
[ "${CI:-}" = true ] || { echo "Disposable CI only." >&2; exit 1; }
dest="$(pwd)/.runtime/node-controller"
conf="$(pwd)/.runtime/node-config"
data="$(pwd)/.runtime/node-data"
mkdir -p .runtime
CGO_ENABLED=0 go build -o .runtime/native ./cmd/tunnelmanager
cleanup() {
  sudo .runtime/native uninstall --mode node --dir /opt/tunnelmanager-agent --yes --keep-data=true || true
  sudo .runtime/native uninstall --dir "$dest" --yes --keep-data=false || true
}
trap cleanup EXIT
printf '%s\n' 'Synthetic-Node-Controller-Password!' | sudo .runtime/native setup --yes --password-stdin --domain 127.0.0.1 --bind 127.0.0.1 --dir "$dest" --config-dir "$conf" --data-dir "$data" --with-local-node
for n in $(seq 1 20); do
  count="$(sudo docker exec tunnelmanager-db psql -U tunnelmanager -d tunnelmanager -Atc 'select count(*) from measurements')"
  if [ "$count" -ge 2 ]; then break; fi
  sleep 4
done
[ "$count" -ge 2 ]
sudo docker exec tunnelmanager-db psql -U tunnelmanager -d tunnelmanager -Atc "select json_build_object('nodes',count(*),'approved',bool_and(approved),'ram_observed',bool_and((telemetry->>'ram_total')::bigint>0),'processes_observed',bool_and(jsonb_array_length(telemetry->'processes')>0)) from nodes"
test "$(sudo docker exec tunnelmanager-db psql -U tunnelmanager -d tunnelmanager -Atc "select count(*) from nodes where approved and (telemetry->>'ram_total')::bigint>0")" = 1
sudo "$dest/tunnelmanager" doctor --mode node | tee .runtime/node-doctor.json
grep '"agent_active": true' .runtime/node-doctor.json
grep '"mode": "node"' .runtime/node-doctor.json
sudo .runtime/native setup --yes --config "$dest/installation.json" --with-local-node
test "$(sudo docker exec tunnelmanager-db psql -U tunnelmanager -d tunnelmanager -Atc 'select count(*) from nodes')" = 1
echo "Native systemd/outbound TLS identity/repeated setup/real host samples passed."
