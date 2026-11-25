#!/bin/bash
# Starts the dashboard read-only filter (see /home/pi/dashboard-filter/dashboard-filter.py).
# Firewalla runs every ~/.firewalla/config/post_main.d/*.sh after it starts
# (on boot and after upgrades), so this may run more than once: it only
# starts the filter if it isn't already running, and returns straight away.

FILTER=/home/pi/dashboard-filter/dashboard-filter.py
LOG=/tmp/dashboard-filter.log

if pgrep -f "python3 $FILTER" >/dev/null; then
    exit 0
fi

# Keep it running: if it ever stops, start it again after 5 seconds.
nohup bash -c "while true; do python3 $FILTER >>$LOG 2>&1; echo \"\$(date) filter exited, restarting\" >>$LOG; sleep 5; done" \
    </dev/null >/dev/null 2>&1 &
exit 0
