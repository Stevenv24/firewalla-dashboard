#!/bin/bash
# Lets the dashboard reach this router's SSH over a site-to-site VPN (owner,
# 21 Nov 2026: the cabin's Gold Plus, watched by a second copy of the
# dashboard on the home NAS). Firewalla's SSH switch only offers its own
# networks (ISP 1, LAN 1), so SSH coming in over the VPN is refused.
#
# This lets in TCP port 22 from the addresses listed in
# /home/pi/dashboard-filter/vpn-ssh-from (comma separated: the NAS units
# and the management PC) and from nowhere else. Nothing from the internet
# is opened, and the dashboard's key is still restricted to its tunnel
# (authorized_keys, from=). Firewalla runs every
# ~/.firewalla/config/post_main.d/*.sh after it starts (on boot and after
# upgrades); this one adds each rule only if it isn't there already.
#
# Undo: delete this file and vpn-ssh-from, then reboot the router, or
#   sudo iptables -S INPUT | grep dashboard-vpn-ssh   (to see them) and
#   sudo iptables -D INPUT <the same rule>            (for each)

FROM_FILE=/home/pi/dashboard-filter/vpn-ssh-from
[ -s "$FROM_FILE" ] || exit 0

for ip in $(tr ',\r\n' '   ' < "$FROM_FILE"); do
    # Plain IPv4 addresses only (192.168.5.236): anything else is skipped.
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
    sudo iptables -w -C INPUT -p tcp --dport 22 -s "$ip" -m comment --comment dashboard-vpn-ssh -j ACCEPT 2>/dev/null \
        || sudo iptables -w -I INPUT 1 -p tcp --dport 22 -s "$ip" -m comment --comment dashboard-vpn-ssh -j ACCEPT
done
exit 0
