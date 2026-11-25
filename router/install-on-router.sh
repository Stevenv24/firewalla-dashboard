#!/bin/bash
# Runs ON THE ROUTER (as pi). The sender (send-to-router.sh now, the setup
# page later) unpacks this folder to /tmp/dash-install first and runs it once,
# over the one login made with the SSH password from the Firewalla app.
#
# It is careful with a router that already watches itself with another copy
# of the dashboard (shareable-edition-plan.md, section 6c):
#   1. The read-only filter (/home/pi/dashboard-filter/dashboard-filter.py):
#        - already there with the same checksum: reused, nothing installed;
#        - already there but different: STOP, nothing is changed at all;
#        - not there: installed with its start-at-boot hook and started.
#      A running filter is never stopped or restarted (that would drop the
#      other copy's tunnel).
#   2. The start-at-boot hook (~/.firewalla/config/post_main.d/dashboard-filter.sh):
#      added only when missing; an existing one is left as it is.
#   3. authorized_keys: a backup copy first, then only lines ending in this
#      copy's own comment (firewalla-dashboard-shared-<its ID>, so several
#      copies can watch one router) are replaced. Every other line is left
#      alone.
#   4. Only when sent (vpn-ssh-from): SSH over a site-to-site VPN from those
#      addresses, added only when the router has no such list yet.
# Then it checks the filter listens on 127.0.0.1:8934 and :8941.
set -euo pipefail

SRC=/tmp/dash-install
DEST=/home/pi/dashboard-filter
HOOK_DIR=/home/pi/.firewalla/config/post_main.d
HOOK="$HOOK_DIR/dashboard-filter.sh"
KEYS=/home/pi/.ssh/authorized_keys
STAMP=$(date +%Y%m%d-%H%M%S)

say() { printf '\n== %s\n' "$*"; }
sum() { tr -d '\r' < "$1" | sha256sum | cut -d' ' -f1; }

# The key line must be exactly one restricted line with this copy's comment,
# so a wrong file can never let in a key with more rights.
say "Key line"
line=$(tr -d '\r' < "$SRC/key-line.txt")
# This copy's own name is the key line's comment: firewalla-dashboard-shared
# and, for each copy, its own ID (config/copy_id), e.g. -k3x9qp.
KEY_NAME=${line##* }
if ! printf '%s\n' "$KEY_NAME" | grep -qE '^firewalla-dashboard-shared(-[a-z0-9]{4,16})?$'; then
    echo "STOPPED: the key line's name isn't a dashboard copy's name. Nothing was changed."
    exit 2
fi
echo "This copy's key is named $KEY_NAME."
# The setup page can't know which address the router sees it come from (a
# NAS behind Docker shows up as the NAS's own address): it writes __CLIENT__
# in from=, and the address of this very login (SSH_CLIENT) goes in its place.
case "$line" in
    *__CLIENT__*)
        client_ip=${SSH_CLIENT%% *}
        if ! printf '%s\n' "$client_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
            echo "STOPPED: this login's own address isn't a plain IPv4 address ($client_ip). Nothing was changed."
            exit 2
        fi
        line=$(printf '%s\n' "$line" | sed "s/__CLIENT__/$client_ip/")
        echo "The dashboard connects from $client_ip: its key is accepted only from there."
        echo "FROM_ADDRESS=$client_ip"
        ;;
esac
pattern='^restrict,port-forwarding,permitopen="127\.0\.0\.1:8934",permitopen="127\.0\.0\.1:8941",permitlisten="127\.0\.0\.1:1",command="/bin/false",from="[0-9.,]+" ssh-ed25519 [A-Za-z0-9+/=]+ '"$KEY_NAME"'$'
if [ "$(printf '%s\n' "$line" | wc -l)" != 1 ] || ! printf '%s\n' "$line" | grep -qE "$pattern"; then
    echo "STOPPED: the key line is not the expected restricted line. Nothing was changed."
    exit 2
fi
echo "Key line is restricted as expected."

say "Filter"
shipped=$(sum "$SRC/dashboard-filter.py")
if [ -f "$DEST/dashboard-filter.py" ]; then
    installed=$(sum "$DEST/dashboard-filter.py")
    if [ "$installed" != "$shipped" ]; then
        echo "STOPPED: a different read-only filter is already installed."
        echo "  installed: $installed"
        echo "  this copy: $shipped"
        echo "Nothing was changed. The filter that is there keeps running."
        exit 3
    fi
    echo "The same filter is already installed (sha256 $installed): reused, not touched."
else
    sudo mkdir -p "$DEST"
    sudo install -o root -g root -m 644 "$SRC/dashboard-filter.py" "$DEST/dashboard-filter.py"
    echo "Filter installed (sha256 $shipped)."
fi

if [ -f "$HOOK" ]; then
    echo "Start-at-boot hook already there: left as it is."
else
    mkdir -p "$HOOK_DIR"
    sudo install -o root -g root -m 755 "$SRC/post_main.d/dashboard-filter.sh" "$HOOK"
    echo "Start-at-boot hook installed."
fi

if [ -s "$SRC/vpn-ssh-from" ]; then
    say "SSH over the VPN"
    if [ -f "$DEST/vpn-ssh-from" ]; then
        echo "This router already has a VPN SSH list: left as it is ($(cat "$DEST/vpn-ssh-from"))."
    else
        sudo install -o root -g root -m 644 "$SRC/vpn-ssh-from" "$DEST/vpn-ssh-from"
        sudo install -o root -g root -m 755 "$SRC/post_main.d/dashboard-vpn-ssh.sh" "$HOOK_DIR/dashboard-vpn-ssh.sh"
        bash "$HOOK_DIR/dashboard-vpn-ssh.sh"
        echo "SSH over the VPN allowed from: $(cat "$DEST/vpn-ssh-from")"
    fi
fi

say "authorized_keys"
mkdir -p /home/pi/.ssh && chmod 700 /home/pi/.ssh
touch "$KEYS" && chmod 600 "$KEYS"
BACKUP="$KEYS.before-$KEY_NAME-$STAMP"
cp "$KEYS" "$BACKUP"
echo "Backup: $BACKUP"
# Every line that is NOT this copy's, before and after: they must not change.
others() { grep -vE " $KEY_NAME"$'\r?$' "$1" || true; }
before=$(others "$KEYS" | sha256sum)
# Only this copy's own line(s) go (CRLF-safe); then its new line is added.
sed -i -E "/ $KEY_NAME\r?\$/d" "$KEYS"
printf '%s\n' "$line" >> "$KEYS"
if [ "$(others "$KEYS" | sha256sum)" != "$before" ]; then
    echo "STOPPED: other key lines would have changed. The backup is put back."
    cp "$BACKUP" "$KEYS"
    exit 4
fi
echo "Other key lines untouched: $(others "$KEYS" | grep -c . || true)."
# Show the options and comment only, never the key data.
grep -E " $KEY_NAME\$" "$KEYS" | sed -E 's/ ssh-ed25519 [^ ]+ / ssh-ed25519 (key) /'

say "Filter running"
# The hook starts the filter only if it isn't running already.
bash "$HOOK"
for _ in 1 2 3 4 5; do
    if ss -ltn | grep -qE '127\.0\.0\.1:8934 ' && ss -ltn | grep -qE '127\.0\.0\.1:8941 '; then
        echo "Filter listening on 127.0.0.1:8934 and :8941 - OK"
        rm -rf "$SRC"
        say "Done on the router"
        exit 0
    fi
    sleep 1
done
echo "FILTER NOT LISTENING - see /tmp/dashboard-filter.log:"
tail -n 20 /tmp/dashboard-filter.log 2>/dev/null || true
exit 1
