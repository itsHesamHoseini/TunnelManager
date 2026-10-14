#!/bin/sh
set -eu
# Download, inspect, then run this small bootstrap if preferred.
# Local artifact: TUNNELMANAGER_BINARY=./tunnelmanager TUNNELMANAGER_CHECKSUM_FILE=./SHA256SUMS sh install.sh
repo=itsHesamHoseini/TunnelManager
case "$(uname -s)" in Linux) ;; *) echo "TunnelManager setup requires Linux." >&2; exit 1;; esac
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo "Unsupported architecture." >&2; exit 1;; esac
task_temp="$(mktemp -d)"
trap 'rm -rf "$task_temp"' EXIT
if [ -n "${TUNNELMANAGER_BINARY:-}" ]; then
  [ -n "${TUNNELMANAGER_CHECKSUM_FILE:-}" ] || { echo "A trusted checksum file is required." >&2; exit 1; }
  cp "$TUNNELMANAGER_BINARY" "$task_temp/tunnelmanager-linux-$arch"
  cp "$TUNNELMANAGER_CHECKSUM_FILE" "$task_temp/SHA256SUMS"
else
  release="${TUNNELMANAGER_RELEASE:-}"
  if [ -z "$release" ]; then
    release="$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$release" ] || { echo "No release available. Use a local verified artifact." >&2; exit 1; }
  fi
  case "$release" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "Use a semantic version tag." >&2; exit 1;; esac
  base="https://github.com/$repo/releases/download/$release"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/tunnelmanager-linux-$arch" -o "$task_temp/tunnelmanager-linux-$arch"
  curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$task_temp/SHA256SUMS"
fi
expected="$(awk -v n="tunnelmanager-linux-$arch" '$2 == n || $2 == "*"n {print $1}' "$task_temp/SHA256SUMS")"
[ "${#expected}" -eq 64 ] || { echo "Checksum entry missing." >&2; exit 1; }
actual="$(sha256sum "$task_temp/tunnelmanager-linux-$arch" | cut -d ' ' -f 1)"
[ "$actual" = "$expected" ] || { echo "Checksum mismatch; nothing installed." >&2; exit 1; }
chmod 700 "$task_temp/tunnelmanager-linux-$arch"
if [ "$#" -eq 0 ]; then set -- setup; fi
unattended=0
for arg in "$@"; do
  case "$arg" in --yes) unattended=1;; esac
done
if [ "$unattended" = 1 ] || [ -t 0 ]; then
  "$task_temp/tunnelmanager-linux-$arch" "$@"
elif [ -r /dev/tty ] && ( : </dev/tty ) 2>/dev/null; then
  "$task_temp/tunnelmanager-linux-$arch" "$@" </dev/tty
else
  "$task_temp/tunnelmanager-linux-$arch" "$@"
fi
