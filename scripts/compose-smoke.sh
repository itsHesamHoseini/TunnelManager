#!/bin/sh
set -eu
mkdir -p .runtime/compose .runtime/config/tls
cp internal/deploy/templates/* .runtime/compose/
CGO_ENABLED=0 go build -o .runtime/compose/tunnelmanager ./cmd/tunnelmanager
openssl rand 32 > .runtime/config/master.key
openssl rand -hex 24 | tr -d '\n' > .runtime/config/db-password
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout .runtime/config/tls/key.pem -out .runtime/config/tls/cert.pem -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
printf '{"domain":"localhost","port":9443,"config_dir":"/config","database":"db","language":"en"}' > .runtime/config/controller.json
export TUNNELMANAGER_CONFIG_DIR="$(pwd)/.runtime/config"
export TUNNELMANAGER_BIND=127.0.0.1
trap 'docker compose -f .runtime/compose/compose.yaml down -v' EXIT
docker compose -f .runtime/compose/compose.yaml up -d --build --wait --wait-timeout 120
curl --fail --cacert .runtime/config/tls/cert.pem https://localhost:9443/healthz
test "$(curl --silent --cacert .runtime/config/tls/cert.pem -o /dev/null -w '%{http_code}' https://localhost:9443/api/me)" = 401
