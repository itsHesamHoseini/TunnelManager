#!/bin/sh
set -eu
umask 077
if [ "$(id -u)" -ne 0 ]; then
  exec sudo sh "$0" "$@"
fi
case "$(uname -s)" in Linux) ;; *) echo 'This node installer requires Linux.' >&2; exit 1;; esac
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported CPU architecture.' >&2; exit 1;; esac
[ "$arch" = '@ARCH@' ] || { echo 'CPU differs from this controller artifact. Use a verified matching Linux artifact.' >&2; exit 1; }
task_dir="$(mktemp -d /tmp/tm-node.XXXXXXXX)"
cleanup() { case "$task_dir" in /tmp/tm-node.*) rm -rf -- "$task_dir";; *) exit 1;; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
origin=@ORIGIN@
curl --proto '=https' --tlsv1.2 -fsSL "$origin/bootstrap/node/$arch" -o "$task_dir/tunnelmanager"
expected='@HASH@'
actual="$(sha256sum "$task_dir/tunnelmanager" | cut -d ' ' -f 1)"
[ "$actual" = "$expected" ] || { echo 'Checksum mismatch; nothing installed. Reload enrollment and retry.' >&2; exit 1; }
chmod 700 "$task_dir/tunnelmanager"
echo 'Verified panel binary. Node setup will preview its owned files; existing tunnels are not adopted.'
if [ -r /dev/tty ] && ( : </dev/tty ) 2>/dev/null; then
  "$task_dir/tunnelmanager" setup --mode node --controller "$origin" --token-stdin "$@" </dev/tty
else
  "$task_dir/tunnelmanager" setup --mode node --controller "$origin" --token-stdin "$@"
fi
