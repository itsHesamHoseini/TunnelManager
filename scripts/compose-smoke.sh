#!/bin/sh
set -eu
mkdir -p .runtime/compose .runtime/config/tls .runtime/config/policy
mkdir -p .runtime/data/postgres
cp internal/deploy/templates/* .runtime/compose/
cp internal/deploy/templates/.dockerignore .runtime/compose/
CGO_ENABLED=0 go build -o .runtime/compose/tunnelmanager ./cmd/tunnelmanager
openssl rand 32 > .runtime/config/master.key
openssl rand -hex 24 | tr -d '\n' > .runtime/config/db-password
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout .runtime/config/tls/key.pem -out .runtime/config/tls/cert.pem -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
printf '{"domain":"localhost","port":9443,"config_dir":"/config","database":"db","language":"en"}' > .runtime/config/controller.json
sudo chown -R root:root .runtime/config
sudo chmod 600 .runtime/config/master.key .runtime/config/db-password .runtime/config/tls/key.pem
export TUNNELMANAGER_CONFIG_DIR="$(pwd)/.runtime/config"
export TUNNELMANAGER_BIND=127.0.0.1
export TUNNELMANAGER_DOMAIN=localhost
export TUNNELMANAGER_DATA_DIR="$(pwd)/.runtime/data"
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then docker compose -f .runtime/compose/compose.yaml logs --tail 40 edge controller; fi
  docker compose -f .runtime/compose/compose.yaml down -v
}
trap cleanup EXIT
docker compose -f .runtime/compose/compose.yaml up -d --build --wait --wait-timeout 120
sudo curl --fail --retry 3 --retry-all-errors --retry-delay 1 --cacert .runtime/config/tls/cert.pem https://127.0.0.1:9443/healthz
test "$(sudo curl --silent --cacert .runtime/config/tls/cert.pem -o /dev/null -w '%{http_code}' https://127.0.0.1:9443/api/me)" = 401
# Actual public bootstrap distribution through the hardened nginx edge.
sudo curl --fail --connect-timeout 10 --max-time 300 --cacert .runtime/config/tls/cert.pem https://127.0.0.1:9443/bootstrap/node-install.sh -o .runtime/edge-node-install.sh
sudo curl --fail --connect-timeout 10 --max-time 300 --cacert .runtime/config/tls/cert.pem https://127.0.0.1:9443/bootstrap/node/amd64 -o .runtime/edge-node-binary
cmp .runtime/compose/tunnelmanager .runtime/edge-node-binary
sha="$(sha256sum .runtime/edge-node-binary | cut -d ' ' -f 1)"
grep -F "expected='$sha'" .runtime/edge-node-install.sh >/dev/null
echo 'Verified edge bootstrap program bytes and script checksum match.'
# Bounded requests only on this disposable stack verify nginx's real 429 response.
for n in $(seq 1 45); do
  sudo curl --silent --cacert .runtime/config/tls/cert.pem -D ".runtime/rate-$n.headers" -o /dev/null -w '%{http_code}' https://127.0.0.1:9443/api/me > ".runtime/rate-$n.status" &
done
wait
grep -l '^429$' .runtime/rate-*.status >/dev/null
grep -i 'Retry-After: 60' .runtime/rate-*.headers >/dev/null
printf '{"profile":"strict"}' | sudo tee .runtime/config/policy/desired.json >/dev/null
for n in $(seq 1 10); do
  if sudo grep -q '"profile":"strict"' .runtime/config/policy/observed.json; then break; fi
  sleep 1
done
sudo grep '"profile":"strict"' .runtime/config/policy/observed.json
docker exec tunnelmanager-edge grep 'rate=5r/s;' /tmp/tunnelmanager-nginx.conf
