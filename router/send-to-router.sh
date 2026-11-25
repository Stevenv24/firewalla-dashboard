#!/bin/bash
# Sets up this copy's router access by hand, until the setup page does it.
# Run it on a PC in Git Bash (or on any Linux/macOS shell):
#
#     ROUTER_IP=192.168.1.1 FROM_IP=192.168.1.10 bash router/send-to-router.sh
#
#   ROUTER_IP  the router's address
#   FROM_IP    the address(es) the dashboard connects FROM (the NAS, or both
#              units of a Synology HA pair), comma separated. The router only
#              accepts this copy's key from there.
#   DRY_RUN=1  shows what would be sent, without connecting
#   VPN_SSH_FROM=a,b  only for a router reached over a site-to-site VPN
#
# It makes this copy's own key in config/ (if there is none yet), then logs in
# to the router ONCE with the SSH password shown in the Firewalla app (ssh
# asks for it; it is never saved) and runs install-on-router.sh there, which
# reuses an existing read-only filter and changes only this copy's own key
# line. The router's host key is saved to config/firewalla_known_hosts.
set -euo pipefail

: "${ROUTER_IP:?Set ROUTER_IP, e.g. ROUTER_IP=192.168.1.1}"
: "${FROM_IP:?Set FROM_IP to the NAS address(es), e.g. FROM_IP=192.168.1.10}"
VPN_SSH_FROM=${VPN_SSH_FROM:-}

valid_list() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(,[0-9]{1,3}(\.[0-9]{1,3}){3})*$ ]]; }
valid_list "$ROUTER_IP" || { echo "ROUTER_IP must be one IPv4 address."; exit 1; }
valid_list "$FROM_IP" || { echo "FROM_IP must be IPv4 addresses separated by commas."; exit 1; }
[ -z "$VPN_SSH_FROM" ] || valid_list "$VPN_SSH_FROM" || { echo "VPN_SSH_FROM must be IPv4 addresses separated by commas."; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
CONFIG="$HERE/../config"
KEY="$CONFIG/firewalla_ssh_key"
KNOWN="$CONFIG/firewalla_known_hosts"
mkdir -p "$CONFIG"
# This copy's own ID (the same file the setup page uses): its key is named
# firewalla-dashboard-shared-<ID>, so several copies can watch one router.
if ! grep -qE '^[a-z0-9]{6}$' "$CONFIG/copy_id" 2>/dev/null; then
    LC_ALL=C tr -dc 'abcdefghijkmnpqrstuvwxyz23456789' < /dev/urandom | head -c 6 > "$CONFIG/copy_id"
    echo >> "$CONFIG/copy_id"
fi
KEY_NAME="firewalla-dashboard-shared-$(head -n 1 "$CONFIG/copy_id")"

if [ ! -f "$KEY" ]; then
    if [ "${DRY_RUN:-}" = 1 ]; then
        echo "DRY RUN: would make a new key at $KEY"
    else
        ssh-keygen -q -t ed25519 -N "" -C "$KEY_NAME" -f "$KEY"
        rm -f "$KEY.pub"
        echo "Made this copy's own router key: $KEY"
    fi
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/post_main.d"
cp "$HERE/install-on-router.sh" "$HERE/dashboard-filter.py" "$WORK/"
cp "$HERE/post_main.d/dashboard-filter.sh" "$WORK/post_main.d/"
if [ -n "$VPN_SSH_FROM" ]; then
    echo "$VPN_SSH_FROM" > "$WORK/vpn-ssh-from"
    cp "$HERE/post_main.d/dashboard-vpn-ssh.sh" "$WORK/post_main.d/"
fi
# Keep LF line endings whatever the PC's git settings are (read and write
# whole files: no sed -i on the originals).
for f in "$WORK"/*.sh "$WORK"/*.py "$WORK"/post_main.d/*.sh; do
    tr -d '\r' < "$f" > "$f.lf" && mv "$f.lf" "$f"
done

if [ -f "$KEY" ]; then
    pub=$(ssh-keygen -y -f "$KEY" | awk '{print $1" "$2}')
else
    pub="ssh-ed25519 (new-key)"
fi
printf 'restrict,port-forwarding,permitopen="127.0.0.1:8934",permitopen="127.0.0.1:8941",permitlisten="127.0.0.1:1",command="/bin/false",from="%s" %s %s\n' \
    "$FROM_IP" "$pub" "$KEY_NAME" > "$WORK/key-line.txt"

if [ "${DRY_RUN:-}" = 1 ]; then
    echo "DRY RUN - nothing sent. Would send to pi@$ROUTER_IP:"
    (cd "$WORK" && find . -type f | sort)
    sed -E 's/ ssh-ed25519 [^ ]+ / ssh-ed25519 (key) /' "$WORK/key-line.txt"
    exit 0
fi

NEW_KNOWN="$WORK/known_hosts"
echo "Connecting to pi@$ROUTER_IP: type the SSH password from the Firewalla app when asked."
tar -C "$WORK" -cf - install-on-router.sh dashboard-filter.py post_main.d key-line.txt $( [ -n "$VPN_SSH_FROM" ] && echo vpn-ssh-from ) \
  | ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$NEW_KNOWN" \
        "pi@$ROUTER_IP" 'rm -rf /tmp/dash-install && mkdir -p /tmp/dash-install && tar -C /tmp/dash-install -xf - && bash /tmp/dash-install/install-on-router.sh'

if [ -s "$NEW_KNOWN" ]; then
    [ -f "$KNOWN" ] && cp "$KNOWN" "$KNOWN.before-$(date +%Y%m%d-%H%M%S)"
    head -n 1 "$NEW_KNOWN" > "$KNOWN"
    echo "Saved the router's host key to $KNOWN."
fi

echo
echo "Done. Start (or restart) this copy's project in Container Manager; the"
echo "header should show LIVE within a minute."
