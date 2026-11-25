# Status page: is anything down, the ping test, WAN uptime and the dashboard's
# own health.

import json
import os
import socket
import sqlite3
import struct
import threading
import time
from collections import deque
import requests

from fastapi import Body

from core import (
    FLOW_HISTORY_DATABASE, Fields, INTERFACE_METADATA, LIVE_URL, RECENT_FLOW_MAX_RECORDS, ROUTER_IS_GOLD_PRO, router_read_note, router_reads, router_reads_lock,
    SYSTEM_LIVESTATS_STALE_SECONDS, app, claude_load, claude_lock, internet_flow_fingerprints,
    StateFileError, internet_flow_lock, internet_flow_records, mbps, msp, policy_read_json, recent_flow_lock, replace_contents,
    recent_flow_records, state,
)
from router import (
    compact_policy_rule_for_flow, internet_interface_name, normalize_policy_string_list,
    policy_rule_for_pid,
)
from flows import (
    FLOW_DB_CHECK_FILE, FLOW_DB_CHECK_HOUR_UTC, flow_db_check_lock, flow_history_publish, internet_flow_fingerprint,
    internet_interface_type, local_traffic_connection, mark_blocked_wan_hour_coverage,
    internet_flow_starts, persist_flow_history, publish_blocked_wan_hourly, publish_internet_flow_activity,
    recent_flow_device_name, record_blocked_wan_hourly, record_internet_traffic,
)


recent_flow_sequence = 0


# ------------------------------------------------------------
# STATUS PAGE: is anything down?
#
# The router's system data (read every 5 s) carries the latest record of
# each of its health checks in latestAllStateEvents: per WAN its link,
# ping (10 pings to 1.1.1.1, 8.8.8.8 and 9.9.9.9: success_rate) and DNS
# checks, the WAN and overall dual-WAN state, its ethernet ports, each
# AP's uplink and heartbeat, disk space and load. A record's value is 0
# when healthy; ts0 is when it entered that value. It keeps no history
# beyond a few earlier records (previousEventsByType,
# networkMonitorEvents), so every change is recorded here, 7 days, and
# each minute's worst packet loss and any outage, 24 hours, in
# /data/status_history.json. It reports no latency: the dashboard times a
# connection to two public servers every 30 s (over whichever WAN is in
# use). Checked 13 Nov 2026.
# ------------------------------------------------------------
STATUS_HISTORY_FILE = os.environ.get("FIREWALLA_STATUS_HISTORY_FILE", "/data/status_history.json")
STATUS_EVENT_DAYS = 7
STATUS_EVENT_TYPES = {"wan_state", "overall_wan_state", "ethernet_state", "ping", "dns", "ap_connect_state",
                      "ap_ethernet_state", "ap_ethernet_speed_change", "switch_port_speed_change", "diskspace"}
# Ordinary web sites, looked up first and then timed on the connection
# alone: 1.1.1.1 and 8.8.8.8 on 443 are DNS-over-HTTPS servers, which the
# router's DoH block list refuses (seen 13 Nov 2026).
STATUS_LATENCY_TARGETS = [("www.google.com", 443), ("www.cloudflare.com", 443)]
# The ping and latency tests run from the NAS, so they measure the NAS's own
# internet. A copy watching another router (owner, 21 Nov 2026: the cabin's,
# over the site-to-site VPN) would be measuring the wrong line: it sets
# FIREWALLA_NAS_INTERNET_TESTS to "off" and keeps only the router's own WAN
# tests. Unset or "on": as before.
NAS_INTERNET_TESTS = os.environ.get("FIREWALLA_NAS_INTERNET_TESTS", "on").strip().lower() != "off"
status_lock = threading.Lock()
status_history = {"events": [], "minutes": {}, "values": {}}
status_latency = {"ms": None, "at": None, "failed": 0, "error": None}
status_errors = {}   # last error of the recorder, shown by /api/status-page


def status_event_from(record):
    """A router record -> a status event (or None). State records
    (state_type) give a check's value since ts0; an "action" record with
    action_type ping_lossrate is the router's packet-loss alert (loss
    rate over its 10% limit to one ping server), kept in
    networkMonitorEvents and previousEventsByType."""
    if not isinstance(record, dict):
        return None
    labels = record.get("labels") or {}
    if record.get("event_type") == "action" and record.get("action_type") == "ping_lossrate":
        try:
            at = float(record.get("ts")) / 1000
        except (TypeError, ValueError):
            return None
        return {"at": at, "type": "ping_lossrate", "action": True,
                "key": f"{labels.get('wan_intf_uuid', '')}-{labels.get('target', '')}",
                "value": labels.get("lossrate"), "ok": None,
                "labels": {k: labels[k] for k in ("wan_intf_uuid", "target", "lossrate", "lossrateLimit") if k in labels}}
    if record.get("state_type") not in STATUS_EVENT_TYPES:
        return None
    try:
        at = float(record.get("ts0") or record.get("ts")) / 1000
    except (TypeError, ValueError):
        return None
    keep = ("wan_intf_name", "wan_test_ip", "success_rate", "current_speed", "ap_name", "intf", "name_server",
            "ready", "active", "wanSwitched", "changedInterface", "speed", "port", "switch_name", "wanStatus")
    return {"at": at, "type": record["state_type"], "key": str(record.get("state_key") or ""),
            "value": record.get("state_value"), "ok": labels.get("ok_value", 0),
            "labels": {k: labels[k] for k in keep if k in labels}}


def status_add_event(event):
    """Record an event unless it is already known. A state change counts
    once per (check, time) and only when its value changed; an alert
    (action) once per (alert, time)."""
    key = f"{event['type']}:{event['key']}"
    if event.get("action"):
        if any(e.get("action") and e["type"] == event["type"] and e["key"] == event["key"]
               and abs(e["at"] - event["at"]) < 1 for e in status_history["events"]):
            return False
        status_history["events"].append(event)
        return True
    known = status_history["values"].get(key)
    if known and known[0] >= event["at"] - 1:
        return False
    if known and known[1] == event["value"]:
        status_history["values"][key] = [event["at"], event["value"]]
        return False
    status_history["values"][key] = [event["at"], event["value"]]
    status_history["events"].append(event)
    return True


def record_status_history(system_data, now=None):
    """Called with every system-data read: new state changes and this
    minute's worst packet loss and outage."""
    now = now or time.time()
    latest = system_data.get("latestAllStateEvents") or {}
    with status_lock:
        if not status_history.get("loaded"):
            return  # the saved history isn't read yet (status_history_worker)
        # The router's few earlier records (its packet-loss alerts live only
        # there), then the latest state of each check, oldest first.
        older = (system_data.get("previousEventsByType") or []) + (system_data.get("networkMonitorEvents") or [])
        for event in sorted(filter(None, map(status_event_from, older + list(latest.values()))), key=lambda e: e["at"]):
            if event["at"] >= now - STATUS_EVENT_DAYS * 86400:
                status_add_event(event)
        cutoff = now - STATUS_EVENT_DAYS * 86400
        status_history["events"] = sorted((e for e in status_history["events"] if e["at"] >= cutoff), key=lambda e: e["at"])

        # This minute: worst loss per WAN, WANs down, and an outage when no
        # WAN passes its tests.
        loss, down = {}, []
        for record in latest.values():
            if (record or {}).get("state_type") == "ping":
                labels = record.get("labels") or {}
                wan = str(record.get("state_key") or "").split("-")[0]
                try:
                    loss[wan] = max(loss.get(wan, 0.0), round(1 - float(labels.get("success_rate", 1)), 2))
                except (TypeError, ValueError):
                    pass
        tests = (system_data.get("wanTestResult") or {}).get("wans") or {}
        working, in_use = 0, []
        for wan, test in tests.items():
            ok = bool(test.get("carrier") and test.get("ping") and test.get("dns"))
            working += ok
            if not ok:
                down.append(wan)
            if (test.get("wanConnState") or {}).get("inUse"):
                in_use.append(wan)
        minute = str(int(now // 60 * 60))
        bucket = status_history["minutes"].setdefault(minute, {"loss": {}, "down": [], "outage": False, "ms": None})
        for wan, value in loss.items():
            bucket["loss"][wan] = max(bucket["loss"].get(wan, 0.0), value)
        bucket["down"] = sorted(set(bucket["down"]) | set(down))
        # The WAN(s) carrying traffic: the latency measured this minute is theirs.
        bucket["in_use"] = sorted(set(bucket.get("in_use") or []) | set(in_use))
        bucket["outage"] = bucket["outage"] or (bool(tests) and working == 0)
        if status_latency["ms"] is not None and (status_latency["at"] or 0) >= now - 60:
            bucket["ms"] = max(bucket["ms"] or 0, status_latency["ms"])
        day_ago = now - 86400
        for key in [k for k in status_history["minutes"] if int(k) < day_ago]:
            del status_history["minutes"][key]


def status_latency_worker():
    """Every 30 s: time a TCP connection to two public servers (median of
    the two that answer), over the WAN in use. Off: never (NAS_INTERNET_TESTS)."""
    while not NAS_INTERNET_TESTS:
        time.sleep(3600)
    while True:
        times, error = [], None
        for host, port in STATUS_LATENCY_TARGETS:
            try:
                address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
                started = time.perf_counter()
                with socket.create_connection(address, timeout=3):
                    times.append((time.perf_counter() - started) * 1000)
            except OSError as exc:
                error = f"{host}:{port} {type(exc).__name__}: {exc}"
        with status_lock:
            if times:
                status_latency.update(ms=round(sorted(times)[len(times) // 2], 1), at=time.time(), failed=0, error=None)
            else:
                status_latency["failed"] += 1
                status_latency["error"] = error
        time.sleep(30)


# ------------------------------------------------------------
# Ping test: the dashboard's own, so packet loss doesn't rest on the
# router's test (10 pings per server, so one lost ping reads as 10%).
# One ping every 5 s, taking turns between 1.1.1.1, 8.8.8.8 and 9.9.9.9
# (12 a minute, about 1 KB), over the WAN carrying traffic: NAS ->
# switch -> router -> internet, so it also sees trouble inside the house.
# A standby WAN carries no traffic and keeps the router's test. Uses
# Linux's ping socket, which Docker allows without extra powers. Each
# minute's sent / lost / slowest per server goes into the status history
# (24 h); the last 15 minutes of single pings stay in memory for the Poor
# Connection alert. Added 14 Nov 2026.
# ------------------------------------------------------------
PING_TARGETS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
PING_EVERY = 5
PING_TIMEOUT = 2
PING_LOSS_LIMIT = 0.05    # Poor Connection: more than 5% lost ...
PING_SLOW_MS = 150        # ... or a typical ping time over 150 ms, on 2 of the 3 servers, for 10 minutes
ping_recent = deque(maxlen=15 * 60 // PING_EVERY)   # (at, server, ms or None = lost, WAN in use)
ping_status = {"ok_at": None, "error": None, "started_at": None}


def ping_once(target, seq):
    """Round-trip time in ms, or None when no reply came within 2 s."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        # Echo request; the kernel fills in the id and the checksum.
        packet = struct.pack("!BBHHH", 8, 0, 0, 0, seq) + b"firewalla-dashboard-ping"
        started = time.perf_counter()
        sock.sendto(packet, (target, 0))
        while True:
            left = started + PING_TIMEOUT - time.perf_counter()
            if left <= 0:
                return None
            sock.settimeout(left)
            try:
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                return None
            if len(data) >= 8 and data[0] == 0 and struct.unpack("!H", data[6:8])[0] == seq:
                return round((time.perf_counter() - started) * 1000, 1)
    finally:
        sock.close()


def ping_worker():
    while not NAS_INTERNET_TESTS:   # off for this copy: no pings, so no Poor Connection from them
        time.sleep(3600)
    ping_status["started_at"] = time.time()
    seq = 0
    while True:
        at = time.time()
        target = PING_TARGETS[seq % len(PING_TARGETS)]
        seq = (seq + 1) % 65536
        wans = (state.get("internet") or {}).get("wans") or {}
        in_use = next((name for name, w in wans.items() if w.get("in_use")), None)
        try:
            ms = ping_once(target, seq)
            ping_status["error"] = None
        except PermissionError as exc:
            # Not allowed in this container: nothing measured, so nothing lost.
            ping_status["error"] = f"ping isn't allowed in the container ({exc}); compose.yaml needs cap_add NET_RAW"
            time.sleep(60)
            continue
        except OSError as exc:
            ms = None   # e.g. "network unreachable": the ping got nowhere
            ping_status["error"] = f"{target}: {type(exc).__name__}: {exc}"
        if ms is not None:
            ping_status["ok_at"] = at
        with status_lock:
            ping_recent.append((at, target, ms, in_use))
            if status_history.get("loaded"):
                bucket = status_history["minutes"].setdefault(str(int(at // 60 * 60)), {"loss": {}, "down": [], "outage": False, "ms": None})
                sent, lost, slowest = (bucket.setdefault("ping", {}).get(target) or [0, 0, 0])
                bucket["ping"][target] = [sent + 1, lost + (ms is None), max(slowest, ms or 0)]
        time.sleep(max(0.5, at + PING_EVERY - time.time()))


def ping_summary(seconds=600, now=None):
    """The last 10 minutes of the dashboard's pings on the WAN in use now:
    per server sent, lost and typical (median) time; how many servers are
    over the loss and time limits; covered = seconds of pings on this WAN."""
    now = now or time.time()
    with status_lock:
        rows = [r for r in ping_recent if r[0] >= now - seconds]
    wan = rows[-1][3] if rows else None
    rows = [r for r in rows if r[3] == wan]
    servers = {}
    for target in PING_TARGETS:
        mine = [r[2] for r in rows if r[1] == target]
        times = sorted(ms for ms in mine if ms is not None)
        servers[target] = {"sent": len(mine), "lost": sum(ms is None for ms in mine),
                           "loss": (sum(ms is None for ms in mine) / len(mine)) if mine else None,
                           "ms": times[len(times) // 2] if times else None}
    return {"wan": wan, "servers": servers, "covered": (now - rows[0][0]) if rows else 0,
            "lossy": sum(1 for s in servers.values() if s["sent"] >= 10 and s["loss"] > PING_LOSS_LIMIT),
            "slow": sum(1 for s in servers.values() if s["ms"] is not None and s["ms"] > PING_SLOW_MS),
            "error": ping_status["error"], "ok_at": ping_status["ok_at"], "off": not NAS_INTERNET_TESTS}


HISTORY_READ_AGAIN_SECONDS = 300   # a history file that couldn't be read is tried again this often


def status_history_worker():
    """Loads the saved history, then saves it every minute. A file that is
    there but can't be read is left as it is and tried again every 5
    minutes; nothing is saved over it meanwhile (24 Nov 2026: any failed
    read counted as "no file yet", and the next save replaced a day of
    history with the minutes since the start)."""
    def load():
        loaded = policy_read_json(STATUS_HISTORY_FILE)
        if loaded and isinstance(loaded.get("events"), list):
            with status_lock:
                status_history.update(loaded)
    readable, tried = True, time.time()
    try:
        load()
    except StateFileError:
        readable = False
    with status_lock:
        status_history["loaded"] = True
    while True:
        time.sleep(60)
        try:
            if not readable:
                if time.time() - tried < HISTORY_READ_AGAIN_SECONDS:
                    continue
                tried = time.time()
                load()   # raises again while it can't be read
                readable = True
            with status_lock:
                text = json.dumps(status_history)
            temporary = STATUS_HISTORY_FILE + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(temporary, STATUS_HISTORY_FILE)
        except StateFileError:
            pass   # still unreadable (policy_read_json has said so in the log)
        except Exception as exc:
            print("Status history save error:", exc)


def status_port_number(intf):
    """Router port as printed on the Gold Pro: eth3..eth0 left to right
    (port 1..4), so eth0 (the main WAN) is port 4 and eth1 port 3. Another
    model (ROUTER_MODEL) has no known numbering: None, and the event names
    the port (eth0)."""
    if not ROUTER_IS_GOLD_PRO:
        return None
    try:
        return 4 - int(str(intf).replace("eth", ""))
    except ValueError:
        return None


def status_event_text(event, wan_names):
    """A recorded change in plain words: (level, text)."""
    t, key, value, labels = event["type"], event["key"], event["value"], event.get("labels") or {}
    good = value == event.get("ok", 0)
    wan = labels.get("wan_intf_name") or wan_names.get(key.split("-")[0]) or key
    if t == "wan_state":
        if good:
            return "good", f"{wan} restored" + (" and active" if labels.get("active") else " as standby")
        return "bad", f"{wan} down"
    if t == "overall_wan_state":
        # From each WAN's own state (seen 13 Nov 2026: 1 = the primary is
        # down and the standby carries traffic, 2 = the standby is down).
        status = labels.get("wanStatus") or {}
        up = [v.get("wan_intf_name") or k for k, v in status.items() if v.get("ready")]
        down = [v.get("wan_intf_name") or k for k, v in status.items() if not v.get("ready")]
        carrying = [v.get("wan_intf_name") or k for k, v in status.items() if v.get("active") and v.get("ready")]
        if status and not up:
            return "bad", "Internet down: no connection working"
        if down:
            return "warn", f"{' and '.join(down)} down · internet through {' and '.join(carrying or up)}"
        if status:
            return "good", "Internet: every connection healthy"
        return ("good", "Internet: every connection healthy") if good else ("warn", f"Internet state {value}")
    if t == "ping_lossrate":
        uuid = labels.get("wan_intf_uuid")
        name = (INTERFACE_METADATA.get(uuid) or {}).get("display_name") or next(
            (n for w, n in wan_names.items() if ((state.get("internet") or {}).get("wans") or {}).get(w, {}).get("uuid") == uuid), "A WAN")
        try:
            lost = round(float(labels.get("lossrate")) * 100, 1)
        except (TypeError, ValueError):
            lost = None
        return "warn", f"{name}: high packet loss" + (f", {lost:g}%" if lost is not None else "") + f" (pings to {labels.get('target', '?')})"
    if t == "ethernet_state":
        port, name = status_port_number(key), wan_names.get(key)
        where = f"Router port {port}" + (f" ({name})" if name else "") if port else key
        if good:
            speed = labels.get("current_speed")
            return "good", f"{where} connected" + (f" at {speed / 1000:g} Gb/s" if speed else "")
        return "bad", f"{where} disconnected"
    if t == "ping":
        if good:
            return "good", f"{wan}: packet loss cleared"
        try:
            lost = round((1 - float(labels.get("success_rate", 0))) * 100)
        except (TypeError, ValueError):
            lost = None
        return "warn", f"{wan}: high packet loss" + (f", {lost}%" if lost is not None else "") + f" (pings to {labels.get('wan_test_ip', '?')})"
    if t == "dns":
        server = labels.get("name_server") or key
        return ("good", f"{wan}: DNS server {server} answering again") if good else ("warn", f"{wan}: DNS server {server} not answering")
    if t == "ap_connect_state":
        name = labels.get("ap_name") or key
        return ("good", f"{name} checking in again") if good else ("bad", f"{name} stopped checking in")
    if t == "ap_ethernet_state":
        name = labels.get("ap_name") or key
        if good:
            speed = labels.get("current_speed")
            return "good", f"{name} cable connected" + (f" at {speed / 1000:g} Gb/s" if speed else "")
        return "warn", f"{name} cable ({labels.get('intf', 'port')}) disconnected"
    if t in ("ap_ethernet_speed_change", "switch_port_speed_change"):
        name = labels.get("ap_name") or labels.get("switch_name") or key
        return "warn", f"{name}: link speed changed" + (f" to {value / 1000:g} Gb/s" if isinstance(value, (int, float)) and value else "")
    if t == "diskspace":
        return ("good", f"Router disk {key}: space OK again") if good else ("warn", f"Router disk {key} nearly full")
    return "warn", f"{t} {key}: {value}"


def status_local_blocked(hours=24):
    since = int((time.time() - hours * 3600) // 3600 * 3600)
    try:
        with local_traffic_connection() as connection:
            flows, pairs = connection.execute(
                "SELECT COALESCE(SUM(flows), 0), COUNT(DISTINCT src_mac || dst_mac) FROM local_traffic_hourly "
                "WHERE hour >= ? AND outcome = 'blocked'", (since,)).fetchone()
        return {"attempts": flows, "pairs": pairs}
    except sqlite3.Error:
        return {"attempts": None, "pairs": None}


# ------------------------------------------------------------
# TRIES TO OFFLINE CLIENTS (owner, 19 Nov 2026): the router records a try
# to reach a client that is off as blocked ("audit") without naming a rule
# or a reason, 0 bytes: it couldn't deliver it (found with Dimmer Hot Tub,
# silent since 16 Nov, the Speakers polling it on TCP 9999). Policy leaves such
# tries out, so they never come back as violations.
#   missing  offline now, at least one such try in the last 24 hours, and
#            the newest try after the router last saw it and after any
#            traffic of its own that got through.
#   periods  from the first such try after its last good traffic to when it
#            came back (open while missing): Policy leaves out the tries
#            inside one. /data/missing_devices.json, 8 days.
# There is no list of them any more (owner, 24 Nov 2026, D-985): Clients'
# Offline card lists every offline client.
#
# OFFLINE EMAIL WARNINGS (owner, 24 Nov 2026, D-986): the waits in
# /data/missing_settings.json (Settings, Offline Email Warnings) are how long
# a client may be offline before the Client Offline alert email: the
# client's own setting, else its group's, else the default (Never: the
# owner picks who warns). The alert itself is in assistant.py.
# ------------------------------------------------------------
MISSING_FILE = os.environ.get("FIREWALLA_MISSING_FILE", "/data/missing_devices.json")
MISSING_SETTINGS_FILE = os.environ.get("FIREWALLA_MISSING_SETTINGS_FILE", "/data/missing_settings.json")
MISSING_KEEP_SECONDS = 8 * 86400
MISSING_DEFAULT_WAIT = "never"
MISSING_NO_GROUP = ("none", "No Group")
MISSING_WAITS = (600, 1800, 3600, 7200, 21600, 43200, 86400, "never")
missing_lock = threading.Lock()
missing_periods = {}   # mac -> [[from, to or None], ...], read by Policy


def missing_settings_load():
    data = policy_read_json(MISSING_SETTINGS_FILE) or {}
    data["default"] = data.get("default") if data.get("default") in MISSING_WAITS else MISSING_DEFAULT_WAIT
    for key in ("groups", "devices"):
        data[key] = {k: v for k, v in (data.get(key) or {}).items() if v in MISSING_WAITS}
    return data


def missing_group_of():
    """mac -> (group id, group name): a device is in at most one group."""
    out = {}
    for g in (state.get("groups") or {}).get("groups") or []:
        for mac in g.get("members") or []:
            out[str(mac).upper()] = (str(g.get("id")), g.get("name") or str(g.get("id")))
    return out


def missing_wait(mac, settings, group_of):
    """The wait for one device: (seconds or "never", where it comes from:
    "device" | "group" | "default", its group (id, name)). A device in no
    group is in "No Group" (id "none"), which has a setting like any group."""
    group = group_of.get(mac) or MISSING_NO_GROUP
    if mac in settings["devices"]:
        return settings["devices"][mac], "device", group
    if group[0] in settings["groups"]:
        return settings["groups"][group[0]], "group", group
    return settings["default"], "default", group


def missing_equipment():
    """The router, switches and access points: never offline warnings (they
    have Equipment Health). Client devices only (owner, 19 Nov 2026)."""
    return ({str(m).upper() for m in state.get("switches") or {}} | {str(m).upper() for m in state.get("access_points") or {}}
            | {str(m).upper() for m in (state.get("router") or {}).get("macs") or []})


def missing_clients():
    """The router's devices without the network equipment: mac -> device."""
    gear = missing_equipment()
    return {mac: d for d in state.get("devices") or [] if (mac := str(d.get("mac") or "").upper()) not in gear}


def missing_load():
    return policy_read_json(MISSING_FILE) or {}


def missing_save(data):
    temporary = MISSING_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.replace(temporary, MISSING_FILE)


def missing_scan(now=None):
    """One pass: which offline clients others are trying to reach; records
    saved; missing_periods (and state["missing"]["updated_at"]) published."""
    now = now or time.time()
    devices = missing_clients()
    if not devices:
        return   # just after a restart: the router's devices aren't read yet
    since = int((now - 7 * 86400) // 3600 * 3600)
    with local_traffic_connection() as connection:
        # Unanswered tries per target and hour: blocked, no rule or reason, nothing sent.
        tries = connection.execute(
            "SELECT dst_mac, src_mac, flows, first_ts, last_ts FROM local_traffic_hourly WHERE hour >= ? "
            "AND outcome = 'blocked' AND COALESCE(blocked_by, '') = '' AND bytes_sent + bytes_received = 0", (since,)).fetchall()
        # The newest traffic of each device's that got through (either way).
        good = {}
        for mac, last in connection.execute(
                "SELECT src_mac, MAX(last_ts) FROM local_traffic_hourly WHERE hour >= ? AND outcome = 'allowed' GROUP BY src_mac "
                "UNION ALL SELECT dst_mac, MAX(last_ts) FROM local_traffic_hourly WHERE hour >= ? AND outcome = 'allowed' "
                "AND bytes_sent + bytes_received > 0 GROUP BY dst_mac", (since, since)):
            good[mac] = max(good.get(mac, 0), last or 0)
    with missing_lock:
        saved = missing_load()
        before = json.dumps(saved, sort_keys=True)
        # A missing time starts at the first try after the device's last good
        # traffic and after its previous missing time ended (it was back).
        start = {mac: max(good.get(mac, 0), r.get("until") or 0) for mac, r in saved.items()}
        per = {}
        for dst, src, flows, first, last in tries:
            if dst not in devices:
                continue   # an address with no device: Policy's No Device pattern covers it
            p = per.setdefault(dst, {"first": None, "last": 0, "tries_24h": 0})
            if (first or 0) > start.get(dst, good.get(dst, 0)):
                p["first"] = min(p["first"] or first, first)
            p["last"] = max(p["last"], last or 0)
            if (last or 0) >= now - 86400:
                p["tries_24h"] += flows or 0
        for mac, d in devices.items():
            p, r = per.get(mac), saved.get(mac)
            seen = float(d.get("last_active") or 0)
            is_missing = bool(not d.get("online") and p and p["first"] and p["tries_24h"]
                              and p["last"] > max(seen, good.get(mac, 0)))
            if r and r.get("until") is None and not is_missing:
                r["until"] = now   # back, or nothing tries it any more
            if is_missing:
                if not r or r.get("until") is not None:
                    # New, or back and missing again: the earlier time is kept in "past".
                    past = (r or {}).get("past", []) + ([[r["from"], r["until"]]] if r else [])
                    r = saved[mac] = {"from": p["first"], "until": None, "past": past}
                r["from"] = min(r["from"], p["first"])
        for mac, r in saved.items():
            if mac not in devices and r.get("until") is None:
                r["until"] = now   # the router no longer lists it (deleted in the Firewalla app): it was listed for ever
        for mac, r in list(saved.items()):
            r["past"] = [x for x in r.get("past") or [] if now - x[1] < MISSING_KEEP_SECONDS]
            if r.get("until") is not None and now - r["until"] > MISSING_KEEP_SECONDS:
                del saved[mac]
        if json.dumps(saved, sort_keys=True) != before:   # the file is written only when something changed (it was, every minute)
            missing_save(saved)
    periods = {mac: [[a, b] for a, b in r.get("past") or []] + [[r["from"], r.get("until")]] for mac, r in saved.items()}
    replace_contents(missing_periods, periods)
    state["missing"] = {"updated_at": now}   # Policy judges blocked tries only after the first pass


def missing_worker():
    while True:
        try:
            missing_scan()
        except Exception as exc:
            print("Tries to offline clients error:", exc)
        time.sleep(60)


@app.get("/api/router-reads")
def api_router_reads():
    """How much this copy reads from its router since the start, per read:
    replies (or stream lines), MB, MB an hour and GB a day at that pace
    (owner, 23 Nov 2026: what the cabin copy pulls over the VPN). Read-only."""
    with router_reads_lock:
        by = {k: list(v) for k, v in router_reads["by"].items()}
        since = router_reads["since"]
    hours = max(1 / 60, (time.time() - since) / 3600)
    rows = sorted(({"read": k, "count": n, "mb": round(b / 1e6, 2), "mb_per_hour": round(b / 1e6 / hours, 1),
                    "gb_per_day": round(b / 1e9 / hours * 24, 2), "kb_each": round(b / 1e3 / max(1, n), 1)}
                   for k, (n, b) in by.items()), key=lambda r: -r["mb"])
    total = sum(b for _, b in by.values())
    return {"since": since, "minutes": round(hours * 60, 1), "total_mb_per_hour": round(total / 1e6 / hours, 1),
            "total_gb_per_day": round(total / 1e9 / hours * 24, 2), "reads": rows}


def missing_settings_view():
    """For Settings, Offline Email Warnings: the default, every group
    (members, its wait or None = the default) and the devices with their
    own wait."""
    settings, group_of = missing_settings_load(), missing_group_of()
    devices = missing_clients()
    groups = (state.get("groups") or {}).get("groups") or []
    out_groups = [{"id": str(g.get("id")), "name": g.get("name") or str(g.get("id")),
                   "members": sum(str(m).upper() in devices for m in g.get("members") or []),
                   "wait": settings["groups"].get(str(g.get("id")))} for g in groups]
    out_groups.append({"id": MISSING_NO_GROUP[0], "name": MISSING_NO_GROUP[1], "members": sum(m not in group_of for m in devices),
                       "wait": settings["groups"].get(MISSING_NO_GROUP[0])})
    exceptions = []
    for mac, wait in settings["devices"].items():
        group = group_of.get(mac) or MISSING_NO_GROUP
        exceptions.append({"mac": mac, "name": (devices.get(mac) or {}).get("name") or mac, "group": group[1],
                           "group_wait": settings["groups"].get(group[0]), "wait": wait})
    return {"default": settings["default"], "choices": list(MISSING_WAITS), "groups": out_groups,
            "devices": sorted(exceptions, key=lambda x: x["name"].lower()),
            "all_devices": sorted(({"mac": m, "name": d.get("name") or m} for m, d in devices.items() if m not in settings["devices"]),
                                  key=lambda x: x["name"].lower())}


@app.get("/api/missing/wait")
def api_missing_wait(mac: str = ""):
    """One device's wait and where it comes from (the device popup)."""
    mac = mac.upper()
    if mac in missing_equipment():
        return {"mac": mac, "equipment": True}
    wait, source, group = missing_wait(mac, missing_settings_load(), missing_group_of())
    return {"mac": mac, "wait": wait, "source": source, "group": group[1], "choices": list(MISSING_WAITS)}


@app.post("/api/missing/settings")
def api_missing_settings(payload: dict = Body(default={})):
    """{scope: default | group | device, id (group id or mac), wait: seconds,
    "never", or "" (group: back to the default; device: back to its group)}."""
    fields = Fields(payload)
    scope = fields.choice("scope", ("default", "group", "device"))
    raw = fields.text("wait", 20)
    wait = "never" if raw == "never" else int(raw) if raw.isdigit() else None
    if not scope or (raw and raw != "current" and wait not in MISSING_WAITS) or (scope == "default" and wait is None):
        return {"ok": False, "error": "Unknown setting"}
    if scope == "device":
        key = fields.mac("id")
        if key in missing_equipment():
            key = None   # network equipment never warns (Equipment Health has it)
        if key and raw == "current":   # Add Device: starts at the wait it has now
            wait = missing_wait(key, missing_settings_load(), missing_group_of())[0]
    else:
        key = fields.text("id", 40)
        if scope == "group" and key not in {str(g.get("id")) for g in (state.get("groups") or {}).get("groups") or []} | {MISSING_NO_GROUP[0]}:
            key = None
    if scope != "default" and not key:
        return {"ok": False, "error": "Unknown group or client"}
    with missing_lock:
        settings = missing_settings_load()
        if scope == "default":
            settings["default"] = wait
        else:
            part = settings["groups" if scope == "group" else "devices"]
            if wait is None:
                part.pop(key, None)
            else:
                part[key] = wait
        temporary = MISSING_SETTINGS_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(settings, handle)
        os.replace(temporary, MISSING_SETTINGS_FILE)
    return {"ok": True}


@app.get("/api/status-page")
def api_status_page(digest: str = None):
    """Everything the Status page shows that /api/status doesn't: per-WAN
    tests and packet loss now, latency, the last 24 hours (48 half-hour
    slots: bad = an outage, warn = a WAN down, loss over 10% (2 or more of
    the router's 10 pings: 1 lost ping is normal noise), or
    latency of 150 ms or more) and the recorded events, newest first."""
    from assistant import digest_public
    now = time.time()
    wans = (state.get("internet") or {}).get("wans") or {}
    wan_names = {name: w.get("provider") or name for name, w in wans.items()}
    with status_lock:
        minutes = {int(k): v for k, v in status_history["minutes"].items()}
        events = list(status_history["events"])
        latency = dict(status_latency)
        values = dict(status_history["values"])
    loss_now = {}
    for key, (at, value) in values.items():
        if key.startswith("ping:"):
            wan = key[5:].split("-")[0]
            loss_now[wan] = loss_now.get(wan, False) or value != 0
    slow_tests = list(state.get("slow_speed_tests") or [])   # [{at, wan}], from the Internet page's reading
    slots, start = [], int((now - 86400) // 1800 * 1800) + 1800
    for i in range(48):
        s = start + i * 1800
        inside = [m for t, m in minutes.items() if s <= t < s + 1800]
        loss_by = {}
        for m in inside:
            for w, v in m["loss"].items():
                loss_by[wan_names.get(w, w)] = max(loss_by.get(wan_names.get(w, w), 0), v)
        worst = max(loss_by.values(), default=0)
        ms = max((m["ms"] or 0 for m in inside), default=0)
        # The dashboard's own pings: share lost over the half hour, per server.
        pinged = {}
        for m in inside:
            for target, (sent, lost, _) in (m.get("ping") or {}).items():
                pinged[target] = [pinged.get(target, [0, 0])[0] + sent, pinged.get(target, [0, 0])[1] + lost]
        ping_loss = sorted((lost / sent for sent, lost in pinged.values() if sent >= 10), reverse=True)
        ping_loss = ping_loss[1] if len(ping_loss) >= 2 else None   # the 2nd worst server: one bad server isn't you
        # A slow speed test on the connection in use at the time (owner, 22 Nov
        # 2026): under 80% of that connection's usual is degradation too.
        slow = [x for x in slow_tests if s <= x["at"] < s + 1800
                and x["wan"] in (minutes.get(int(x["at"] // 60 * 60), {}).get("in_use") or [x["wan"]])]
        # Either WAN down or degraded makes the half hour not green.
        level = ("none" if not inside else "bad" if any(m["outage"] for m in inside)
                 else "warn" if any(m["down"] for m in inside) or worst > 0.1 or ms >= 150
                 or (ping_loss or 0) > PING_LOSS_LIMIT or slow else "good")
        slots.append({"start": s, "level": level, "loss": worst, "ms": ms or None, "ping_loss": ping_loss,
                      "slow_tests": [wan_names.get(x["wan"], x["wan"]) for x in slow],
                      "loss_by_wan": {w: v for w, v in loss_by.items() if v},
                      "down": sorted({wan_names.get(w, w) for m in inside for w in m["down"]})})
    day = [m for t, m in minutes.items() if t >= now - 86400]
    # Per WAN: time it failed the router's tests, worst latency while it
    # carried traffic (None: not in use, so not measured), worst loss.
    per_wan = []
    for name in sorted(wans):
        carried = [m["ms"] for m in day if name in (m.get("in_use") or []) and m["ms"]]
        per_wan.append({
            "wan": name, "name": wan_names[name],
            "outage_seconds": 60 * sum(1 for m in day if name in m["down"]),
            "max_latency_ms": max(carried) if carried else None,
            "carried_minutes": sum(1 for m in day if name in (m.get("in_use") or [])),
            "max_loss": max((m["loss"].get(name, 0) for m in day), default=0),
        })
    recent = []
    for event in reversed(events):
        level, text = status_event_text(event, wan_names)
        # The same words within a minute (one check per ping server) once.
        if recent and recent[-1]["text"] == text and recent[-1]["at"] - event["at"] < 60:
            continue
        recent.append({"at": event["at"], "level": level, "text": text, "type": event["type"]})
    ping = ping_summary(now=now)
    return {
        "now": now,
        "wans": {name: {"name": wan_names[name], "role": w.get("role"), "in_use": w.get("in_use"),
                        "ready": w.get("ready"), "tests": {"link": w.get("carrier"), "ping": w.get("ping"),
                                                           "dns": w.get("dns"), "web": w.get("http")},
                        "loss_now": loss_now.get(name, False)} for name, w in wans.items()},
        "latency": latency,
        "ping": {**ping, "wan_name": wan_names.get(ping["wan"], ping["wan"])},
        "health": {"slots": slots, "covered_minutes": len(day), "wans": per_wan,
                   # Internet outage: no WAN passing its tests.
                   "outage_seconds": 60 * sum(1 for m in day if m["outage"])},
        # The Internet page's Internet Access, 24 Hours ring (owner, 22 Nov
        # 2026): the worst half hour of the bar above, and how long the internet
        # was out (no connection) or degraded (a connection down, the one in use
        # losing pings or slow, or a slow speed test: its half hour).
        "access_24h": {"level": "bad" if any(x["level"] == "bad" for x in slots) else "warn" if any(x["level"] == "warn" for x in slots)
                       else "good" if any(x["level"] == "good" for x in slots) else "none",
                       "out_minutes": sum(1 for m in day if m["outage"]),
                       "degraded_minutes": sum(1 for m in day if not m["outage"] and (m["down"] or max(m["loss"].values(), default=0) > 0.1 or (m["ms"] or 0) >= 150))},
        "events": recent[:60],
        "local_blocked": status_local_blocked(),
        "policy": state.get("policy"),
        "uptime": {w["wan"]: w for w in wan_uptime_summary(now)["wans"]},
        "errors": dict(status_errors),
        "digest": digest_public(digest),
    }


# ------------------------------------------------------------
# WAN uptime history: every 30 s each WAN's state is read (active = in
# use, standby = ready, down = neither) and every change is recorded with
# its time, kept for 7 days in /data/wan_uptime.json (a few KB). The WAN
# Uptime card reads /api/wan-uptime.
# ------------------------------------------------------------
WAN_UPTIME_FILE = os.environ.get("FIREWALLA_WAN_UPTIME_FILE", "/data/wan_uptime.json")

# ------------------------------------------------------------
# WAN peak throughput (owner, 20 Nov 2026: the Internet page's top download
# and upload over 1, 3, 7, 14 and 30 days). The fastest rate each WAN
# carried, from the router's own interface rates (read every few seconds).
# Real user load only (owner, 22 Nov 2026): the minutes around any speed
# test are left out, since a test fills the line and the router's short
# readings during one run high (8.8 Gb/s up on a 5 Gb/s line):
#  - the router's own tests (its results), 3 minutes either side;
#  - tests people run (seen 22 Nov 2026 on PC B): a flow to a
#    speed-test server (a name with "speedtest" or "ookla" in it, or one of
#    the known ones) carrying 1 MB or more (the Speedtest app used
#    speedtest.dllstx97.metronetinc.com:8080; its background check-ins to
#    mapi.speedtest.net are ~12 KB and don't count), or any visit to a
#    speed-test site that tests as soon as it opens (fast.com, whose test
#    data then comes from Netflix's own video servers), 2 minutes either
#    side of the flow.
# Each minute's top rate is held until it is 15 minutes old (a test's
# result and its flows arrive after the test), then folded into its hour
# unless a test touched it. Kept 31 days in /data/wan_peaks.json:
# {"hours": {wan: {hour: [down, up]}}, "minutes": {wan: {minute: [down, up]}},
#  "user_tests": [[start, end], ...], "left_out": {wan: [[minute, down, up]]}}
# in Mb/s and seconds.
# ------------------------------------------------------------
WAN_PEAKS_FILE = os.environ.get("FIREWALLA_WAN_PEAKS_FILE", "/data/wan_peaks.json")
WAN_PEAKS_KEEP_HOURS = 31 * 24
WAN_PEAKS_SAVE_SECONDS = 300
WAN_PEAKS_HOLD_MINUTES = 15       # a minute is folded into its hour once this old
WAN_PEAKS_TEST_MARGIN = 180       # seconds either side of a router speed test left out
WAN_PEAKS_USER_MARGIN = 120       # seconds either side of a person's speed-test flow left out
# A speed test is split over many connections (8 to 20 a server), so one
# connection of a short test carries little: 1 MB marks it (24 Nov 2026: it
# was 10 MB a flow, more than each connection to dallas.tx.speedtest.frontier.com
# carried that morning: 62 MB in 7).
WAN_PEAKS_USER_BYTES = 1024 ** 2
WAN_PEAKS_TEST_SITES = ("fast.com", "speed.cloudflare.com", "speedof.me", "testmy.net", "openspeedtest.com", "nperf.com")
WAN_PEAKS_TEST_SERVERS = ("ookla.com", "ooklaserver.net", "measurement-lab.org", "measurementlab.net", "mensura.cdn-apple.com")
# A test server by a word in its name: speedtest.dfw1.sonic.net, and Ookla's
# own servers that don't say "speedtest" (dfw-eqx11-ookla-1.99.network, 24 Nov
# 2026: 421 MB of a test went unrecognised, left out only because the same
# test also used servers that did).
WAN_PEAKS_TEST_WORDS = ("speedtest", "ookla")
WAN_PEAK_WINDOWS = (1, 3, 7, 14, 30)   # days
# left_out: {wan: [[minute start, down, up], ...]} = the minutes a speed test
# kept out of the peaks, a day of them, so the page can say what was left
# out (owner, 24 Nov 2026: the peaks looked as if tests were still counted).
# left_out_since: when that record began (first kept on 24 Nov 2026), so the page
# never says "in the last 24 hours" about a time it wasn't keeping.
wan_peaks = {"wans": None, "minutes": None, "user_tests": None, "left_out": None, "left_out_since": None,
             "saved_at": time.time(), "unreadable": False, "old_format": False}
wan_peaks_lock = threading.Lock()


def wan_peaks_pairs(hours):
    return {str(h): [float(v[0]), float(v[1])] for h, v in (hours or {}).items()
            if str(h).isdigit() and isinstance(v, list) and len(v) == 2}


def wan_peaks_loaded():
    """The kept peaks, read from the NAS on first use. A file that is there
    but can't be read is left as it is: peaks are kept in memory only and
    nothing is written over it (said once), so a passing read error at a
    start can't lose a month of peaks."""
    if wan_peaks["wans"] is None:
        wan_peaks["wans"], wan_peaks["minutes"], wan_peaks["user_tests"], wan_peaks["left_out"] = {}, {}, [], {}
        wan_peaks["left_out_since"] = time.time()
        try:
            with open(WAN_PEAKS_FILE, "r", encoding="utf-8") as handle:
                kept = json.load(handle)
            if isinstance(kept, dict) and isinstance(kept.get("hours"), dict):
                wan_peaks["wans"] = {str(w): wan_peaks_pairs(h) for w, h in kept["hours"].items() if isinstance(h, dict)}
                wan_peaks["minutes"] = {str(w): wan_peaks_pairs(m) for w, m in (kept.get("minutes") or {}).items() if isinstance(m, dict)}
                wan_peaks["user_tests"] = [[float(x[0]), float(x[1])] for x in kept.get("user_tests") or []
                                           if isinstance(x, list) and len(x) == 2]
                wan_peaks["left_out"] = {str(w): [[float(x[0]), float(x[1]), float(x[2])] for x in rows if isinstance(x, list) and len(x) == 3]
                                         for w, rows in (kept.get("left_out") or {}).items() if isinstance(rows, list)}
                # A file from before the time was kept: from its first left-out minute, else from now.
                first = min((x[0] for rows in wan_peaks["left_out"].values() for x in rows), default=None)
                wan_peaks["left_out_since"] = float(kept.get("left_out_since") or first or time.time())
            elif isinstance(kept, dict):
                # Before 22 Nov 2026: hours only, speed tests included. The
                # hours that held a test are dropped once the tests are known.
                wan_peaks["wans"] = {str(w): wan_peaks_pairs(h) for w, h in kept.items() if isinstance(h, dict)}
                wan_peaks["old_format"] = True
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            wan_peaks["unreadable"] = True
            print("WAN peaks could not be read; the file is left as it is and peaks are kept in memory until the next start:", exc)
    return wan_peaks["wans"]


def wan_peaks_router_tests(tests):
    """[start, end] around each of the router's speed tests (both WANs)."""
    windows = []
    for t in tests or []:
        try:
            at = float(t.get("timestamp"))
        except (TypeError, ValueError, AttributeError):
            continue
        windows.append([at - WAN_PEAKS_TEST_MARGIN, at + WAN_PEAKS_TEST_MARGIN])
    return windows


def wan_peaks_speed_test_flow(flow):
    """True when an internet flow is part of a speed test someone ran."""
    if flow.get("local") or flow.get("kind") != "normal":
        return False
    name = str(flow.get("destination") or "").lower().rstrip(".")
    is_on = lambda sites: any(name == s or name.endswith("." + s) for s in sites)
    if is_on(WAN_PEAKS_TEST_SITES):
        return True
    size = int(flow.get("upload_bytes") or 0) + int(flow.get("download_bytes") or 0)
    return size >= WAN_PEAKS_USER_BYTES and (any(word in name for word in WAN_PEAKS_TEST_WORDS) or is_on(WAN_PEAKS_TEST_SERVERS))


def wan_peaks_note_user_tests(flows, now=None):
    """Note the time of each speed test people ran. A flow's time may be its
    start or its end, so its length is allowed for on both sides."""
    now = now or time.time()
    found = []
    for f in flows or []:
        if not wan_peaks_speed_test_flow(f):
            continue
        try:
            at = float(f.get("flow_ts") or f.get("received_at") or now)
            length = max(0.0, float(f.get("duration_seconds") or 0))
        except (TypeError, ValueError):
            continue
        found.append([at - length - WAN_PEAKS_USER_MARGIN, at + length + WAN_PEAKS_USER_MARGIN])
    if not found:
        return
    with wan_peaks_lock:
        wan_peaks_loaded()
        keep_after = now - 2 * 3600   # the held minutes only reach back 15 minutes
        wan_peaks["user_tests"] = [w for w in wan_peaks["user_tests"] if w[1] > keep_after] + found


def wan_peaks_near_test(start, end, windows):
    """True when a speed test's window overlaps [start, end)."""
    return any(a < end and b > start for a, b in windows)


def wan_peaks_note(interfaces, tests=None, now=None):
    """Note each WAN's rates now; written to the NAS every 5 minutes."""
    now = now or time.time()
    minute = int(now // 60)
    router_tests = wan_peaks_router_tests(tests)
    with wan_peaks_lock:
        wans = wan_peaks_loaded()
        minutes = wan_peaks["minutes"]
        if wan_peaks["old_format"] and router_tests:
            for hours in wans.values():
                for h in [h for h in hours if wan_peaks_near_test(int(h) * 3600, int(h) * 3600 + 3600, router_tests)]:
                    del hours[h]
            wan_peaks["old_format"] = False
        for i in interfaces or []:
            if i.get("network_type") != "wan" or not i.get("name"):
                continue
            try:
                down, up = float(i.get("rx_mbps") or 0), float(i.get("tx_mbps") or 0)
            except (TypeError, ValueError):
                continue
            slot = minutes.setdefault(str(i["name"]), {}).setdefault(str(minute), [0.0, 0.0])
            slot[0], slot[1] = max(slot[0], down), max(slot[1], up)
        windows = router_tests + wan_peaks["user_tests"]
        for name, held in minutes.items():
            for m in [m for m in held if int(m) <= minute - WAN_PEAKS_HOLD_MINUTES]:
                down, up = held.pop(m)
                if wan_peaks_near_test(int(m) * 60, int(m) * 60 + 60, windows):
                    wan_peaks["left_out"].setdefault(name, []).append([int(m) * 60, down, up])
                    continue
                slot = wans.setdefault(name, {}).setdefault(str(int(m) // 60), [0.0, 0.0])
                slot[0], slot[1] = max(slot[0], down), max(slot[1], up)
        # An old file is not written over until its test hours are dropped.
        if wan_peaks["unreadable"] or wan_peaks["old_format"] or now - wan_peaks["saved_at"] < WAN_PEAKS_SAVE_SECONDS:
            return
        wan_peaks["saved_at"] = now
        oldest = int(now // 3600) - WAN_PEAKS_KEEP_HOURS
        for hours in wans.values():
            for h in [h for h in hours if int(h) < oldest]:
                del hours[h]
        wan_peaks["user_tests"] = [w for w in wan_peaks["user_tests"] if w[1] > now - 2 * 3600]
        wan_peaks["left_out"] = {w: [x for x in rows if x[0] > now - 86400] for w, rows in wan_peaks["left_out"].items()}
        copy = json.dumps({"hours": wans, "minutes": minutes, "user_tests": wan_peaks["user_tests"], "left_out": wan_peaks["left_out"],
                           "left_out_since": wan_peaks["left_out_since"]})
    try:
        temporary = WAN_PEAKS_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(copy)
        os.replace(temporary, WAN_PEAKS_FILE)
    except OSError as exc:
        print("WAN peaks save error:", exc)


def wan_peaks_summary(now=None):
    """{wan: {since, windows: [{days, down, up}]}}: the top rates in the last
    1, 3, 7, 14 and 30 days, and when recording began."""
    now = now or time.time()
    this_hour = int(now // 3600)
    out = {}
    with wan_peaks_lock:
        for name, hours in wan_peaks_loaded().items():
            if not hours:
                continue
            windows = []
            for days in WAN_PEAK_WINDOWS:
                inside = [v for h, v in hours.items() if int(h) > this_hour - days * 24]
                windows.append({"days": days, "down": round(max((v[0] for v in inside), default=0.0), 2),
                                "up": round(max((v[1] for v in inside), default=0.0), 2)})
            # The minutes speed tests kept out in the last day, and the top rates in them.
            skipped = [x for x in (wan_peaks["left_out"] or {}).get(name) or [] if x[0] > now - 86400]
            out[name] = {"since": min(int(h) for h in hours) * 3600, "windows": windows,
                         "left_out": {"minutes": len(skipped), "down": round(max((x[1] for x in skipped), default=0.0), 2),
                                      "up": round(max((x[2] for x in skipped), default=0.0), 2), "last": max((x[0] for x in skipped), default=None),
                                      "since": wan_peaks["left_out_since"]}}
    return out
WAN_UPTIME_DAYS = 7
wan_uptime_lock = threading.Lock()
wan_uptime = {"started_at": None, "wans": {}}  # name -> {"name", "uuid", "changes": [[t, state], ...]}


def wan_state_now(wan):
    if wan.get("in_use"):
        return "active"
    if wan.get("ready"):
        return "standby"
    return "down"


def wan_uptime_record(wans, now):
    """Note each WAN's state; returns True when something changed."""
    changed = False
    with wan_uptime_lock:
        if not wan_uptime.get("started_at"):
            wan_uptime["started_at"] = now
            changed = True
        for name, wan in wans.items():
            record = wan_uptime["wans"].setdefault(name, {"changes": []})
            if wan.get("provider") or not record.get("name"):
                record["name"] = wan.get("provider") or name
            if wan.get("uuid"):
                record["uuid"] = wan.get("uuid")
            current = wan_state_now(wan)
            if not record["changes"] or record["changes"][-1][1] != current:
                record["changes"].append([now, current])
                changed = True
            # Keep 7 days, plus the change in force at the start of them.
            cutoff = now - WAN_UPTIME_DAYS * 86400
            while len(record["changes"]) > 1 and record["changes"][1][0] <= cutoff:
                record["changes"].pop(0)
                changed = True
    return changed


def wan_uptime_worker():
    """Loads the saved uptime record, then keeps it. As status_history_worker:
    a file that can't be read is left as it is, tried again every 5 minutes,
    and nothing is saved over it meanwhile (the uptime percentages gathered
    in memory until then give way to the saved week when it reads)."""
    global wan_uptime

    def load():
        global wan_uptime
        loaded = policy_read_json(WAN_UPTIME_FILE)
        if loaded and isinstance(loaded.get("wans"), dict):
            with wan_uptime_lock:
                wan_uptime = loaded
    readable, tried = True, time.time()
    try:
        load()
    except StateFileError:
        readable = False
    while True:
        try:
            if not readable and time.time() - tried >= HISTORY_READ_AGAIN_SECONDS:
                tried = time.time()
                try:
                    load()
                    readable = True
                except StateFileError:
                    pass
            wans = (state.get("internet") or {}).get("wans") or {}
            if wans and wan_uptime_record(wans, time.time()) and readable:
                with wan_uptime_lock:
                    text = json.dumps(wan_uptime)
                temporary = WAN_UPTIME_FILE + ".tmp"
                with open(temporary, "w", encoding="utf-8") as handle:
                    handle.write(text)
                os.replace(temporary, WAN_UPTIME_FILE)
        except Exception as exc:
            print("WAN uptime recorder error:", exc)
        time.sleep(30)


def wan_uptime_summary(now=None, days=None):
    now = now or time.time()
    days = days or WAN_UPTIME_DAYS
    since = now - days * 86400
    result = []
    with wan_uptime_lock:
        started = float(wan_uptime.get("started_at") or now)
        for key, record in wan_uptime["wans"].items():
            changes = record.get("changes") or []
            totals = {"active": 0.0, "standby": 0.0, "down": 0.0}
            outages, failovers, events = 0, 0, []
            for index, (at, value) in enumerate(changes):
                start = max(float(at), since, started)
                end = float(changes[index + 1][0]) if index + 1 < len(changes) else now
                if end > start:
                    totals[value] = totals.get(value, 0.0) + (end - start)
                if float(at) >= since and index > 0:
                    previous = changes[index - 1][1]
                    if value == "down":
                        outages += 1
                    elif previous == "active" and value == "standby":
                        failovers += 1  # traffic moved to the other WAN
                    events.append({"at": at, "from": previous, "to": value})
            covered = sum(totals.values())
            result.append({
                "wan": key,
                "name": record.get("name") or key,
                "uuid": record.get("uuid"),
                "state": changes[-1][1] if changes else None,
                "covered_seconds": covered,
                "up_percent": (100.0 * (totals["active"] + totals["standby"]) / covered) if covered else None,
                "active_percent": (100.0 * totals["active"] / covered) if covered else None,
                "down_seconds": totals["down"],
                "outages": outages,
                "failovers": failovers,
                "events": events,   # every change in the period (the Internet page's History)
            })
    return {"since": max(since, started), "days": days, "wans": result}


def next_flow_db_check_at(now=None):
    now = now or time.time()
    day = int(now // 86400) * 86400
    due = day + FLOW_DB_CHECK_HOUR_UTC * 3600
    return due if due > now else due + 86400


def run_flow_db_check():
    if not flow_db_check_lock.acquire(blocking=False):
        return None  # one already running
    try:
        started = time.time()
        try:
            connection = sqlite3.connect(f"file:{FLOW_HISTORY_DATABASE}?mode=ro", uri=True, timeout=30)
            try:
                rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check(20)")]
            finally:
                connection.close()
            ok = rows == ["ok"]
            result = "ok" if ok else "; ".join(rows)[:2000]
        except Exception as exc:
            ok, result = False, f"The check could not run: {exc}"
        record = {
            "at": started,
            "ok": ok,
            "result": result,
            "seconds": round(time.time() - started, 1),
        }
        flow_history_publish({"check": {**record, "next_at": next_flow_db_check_at()}})
        try:
            temporary = FLOW_DB_CHECK_FILE + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
            os.replace(temporary, FLOW_DB_CHECK_FILE)
        except OSError as exc:
            print("Database check result not saved:", exc)
        print(f"Flow history database check: {'ok' if ok else 'FAILED'} in {record['seconds']}s - {result[:200]}")
        return record
    finally:
        flow_db_check_lock.release()


def flow_db_check_worker():
    last = None
    try:
        with open(FLOW_DB_CHECK_FILE, "r", encoding="utf-8") as handle:
            last = json.load(handle)
    except (OSError, ValueError):
        pass
    flow_history_publish({"check": {**(last or {}), "next_at": next_flow_db_check_at()}})
    # Never checked, or the last check is over a day old (the NAS was off
    # at check time, say): check 10 minutes after starting.
    if not last or time.time() - float(last.get("at") or 0) > 26 * 3600:
        time.sleep(600)
        run_flow_db_check()
    while True:
        time.sleep(max(30, next_flow_db_check_at() - time.time()))
        run_flow_db_check()


def normalize_recent_flow(raw_record, received_at):
    global recent_flow_sequence

    if not isinstance(raw_record, dict):
        return None

    ltype = str(
        raw_record.get("ltype")
        or ""
    ).lower()

    if ltype not in ("flow", "audit"):
        return None

    device_mac = str(
        raw_record.get("device")
        or ""
    ).upper()

    device_ip = str(
        raw_record.get("deviceIP")
        or ""
    )

    source_uuid = raw_record.get("intf")

    source_network = (
        internet_interface_name(
            source_uuid
        )
        if source_uuid
        else "--"
    )

    outbound_uuid = (
        raw_record.get("oIntf")
        or raw_record.get("wanIntf")
    )

    outbound_name = (
        internet_interface_name(
            outbound_uuid
        )
        if outbound_uuid
        else None
    )

    destination = (
        raw_record.get("domain")
        or raw_record.get("host")
        or raw_record.get("ip")
        or "--"
    )

    protocol = str(
        raw_record.get("protocol")
        or "--"
    ).upper()

    port = raw_record.get("port")
    remote_port = None

    # A block at the router's own internet address (device "if:<WAN>"):
    # "port" is the sender's own port; the port it aimed at on the WAN is
    # "devicePort" (seen 13 Nov 2026: 8000, 1433, 49152). Record that one.
    if device_mac.startswith("IF:") and raw_record.get("devicePort") not in (None, ""):
        remote_port, port = port, raw_record.get("devicePort")

    service = (
        f"{protocol}/{port}"
        if port is not None
        else protocol
    )

    recent_flow_sequence += 1

    normalized = {
        "id": recent_flow_sequence,
        "kind": (
            "normal"
            if ltype == "flow"
            else "blocked"
        ),
        "received_at": received_at,
        "flow_ts": raw_record.get("ts"),
        "device": recent_flow_device_name(
            device_mac,
            device_ip,
        ),
        "device_mac": (
            device_mac
            if device_mac
            else None
        ),
        "device_ip": (
            device_ip
            if device_ip
            else None
        ),
        "source_uuid": source_uuid,
        "source_network": source_network,
        "destination": str(destination),
        "remote_ip": raw_record.get("ip"),
        "country": raw_record.get("country"),
        "protocol": protocol,
        "port": port,
        "remote_port": remote_port,
        "service": service,
        "count": int(
            raw_record.get("count")
            or 1
        ),
        "direction": raw_record.get("fd"),
        "outbound_uuid": outbound_uuid,
        "outbound": outbound_name,
        "destination_uuid": (
            raw_record.get("dIntf")
        ),
        "destination_network": (
            internet_interface_name(
                raw_record.get("dIntf")
            )
            if raw_record.get("dIntf")
            else None
        ),
        "destination_mac": (
            raw_record.get("dstMac")
        ),
        "local": (
            raw_record.get("local")
            is True
        ),
        "tags": (
            normalize_policy_string_list(
                raw_record.get("tags")
            )
        ),
        "destination_tags": (
            normalize_policy_string_list(
                raw_record.get("dTags")
            )
        ),
        "flow_tags": (
            normalize_policy_string_list(
                raw_record.get(
                    "flowTags"
                )
            )
        ),
    }

    if ltype == "flow":
        normalized.update(
            {
                "upload_bytes": int(
                    raw_record.get("upload")
                    or 0
                ),
                "download_bytes": int(
                    raw_record.get("download")
                    or 0
                ),
                "duration_seconds": (
                    raw_record.get("duration")
                ),
                "blocked_type": None,
                "blocked_target": None,
                "category": (
                    raw_record.get("category")
                ),
                "policy_pid": None,
                "allowed_pid": (
                    str(
                        raw_record.get("apid")
                    )
                    if raw_record.get("apid")
                    is not None
                    else None
                ),
                "matched_rule": None,
                "allowed_rule": (
                    compact_policy_rule_for_flow(
                        policy_rule_for_pid(
                            raw_record.get(
                                "apid"
                            )
                        )
                    )
                ),
            }
        )

    else:
        normalized.update(
            {
                "upload_bytes": None,
                "download_bytes": None,
                "duration_seconds": None,
                "blocked_type": (
                    raw_record.get("bType")
                    or raw_record.get("type")
                ),
                "blocked_target": (
                    raw_record.get("bTarget")
                ),
                "category": (
                    raw_record.get("category")
                ),
                "policy_pid": (
                    str(
                        raw_record.get("pid")
                    )
                    if raw_record.get("pid")
                    is not None
                    else None
                ),
                "allowed_pid": None,
                "matched_rule": (
                    compact_policy_rule_for_flow(
                        policy_rule_for_pid(
                            raw_record.get(
                                "pid"
                            )
                        )
                    )
                ),
                "allowed_rule": None,
            }
        )

    return normalized


def publish_recent_flows(timestamp=None):

    now = float(
        timestamp
        if timestamp is not None
        else time.time()
    )

    with recent_flow_lock:
        records = list(
            recent_flow_records
        )

    normal_count = 0
    blocked_count = 0
    download_bytes = 0
    upload_bytes = 0

    for record in records:
        count = int(
            record.get("count")
            or 1
        )

        if record.get("kind") == "normal":
            normal_count += count

            download_bytes += int(
                record.get(
                    "download_bytes"
                )
                or 0
            )

            upload_bytes += int(
                record.get(
                    "upload_bytes"
                )
                or 0
            )

        elif record.get("kind") == "blocked":
            blocked_count += count

    state["recent_flows"] = {
        "max_records": (
            RECENT_FLOW_MAX_RECORDS
        ),
        "records": list(
            reversed(records)
        ),
        "normal_count": normal_count,
        "blocked_count": blocked_count,
        "reported_download_bytes": (
            download_bytes
        ),
        "reported_upload_bytes": (
            upload_bytes
        ),
        "reported_total_bytes": (
            download_bytes
            + upload_bytes
        ),
        "updated_at": now,
    }


def process_recent_flow_records(records, received_at=None):

    now = float(
        received_at
        if received_at is not None
        else time.time()
    )

    normalized_records = []
    persistent_records = []

    for raw_record in records or []:
        normalized = normalize_recent_flow(
            raw_record,
            now,
        )

        if normalized is not None:
            # Connections started (D-956), counted once here for every store.
            normalized["starts"] = internet_flow_starts(raw_record, normalized)
            normalized_records.append(
                normalized
            )

            persistent_records.append(
                (
                    raw_record,
                    normalized,
                )
            )

    if normalized_records:
        with recent_flow_lock:
            recent_flow_records.extend(
                normalized_records
            )

        persist_flow_history(
            persistent_records,
            now,
        )
        record_internet_traffic(persistent_records)
        wan_peaks_note_user_tests(normalized_records, now)

    publish_recent_flows(now)


def process_internet_flow_records(records):
    received_at = time.time()
    added = False

    mark_blocked_wan_hour_coverage(
        received_at
    )

    with internet_flow_lock:

        for raw_record in records or []:

            if not isinstance(raw_record, dict):
                continue

            fingerprint = internet_flow_fingerprint(
                raw_record
            )

            if fingerprint in internet_flow_fingerprints:
                continue

            ltype = str(
                raw_record.get("ltype")
                or ""
            ).lower()

            normalized = None

            if ltype == "flow":
                source_uuid = raw_record.get("intf")
                wan_uuid = (
                    raw_record.get("oIntf")
                    or raw_record.get("wanIntf")
                )

                # Internet Phase 2 accepts only records with
                # an explicit known outbound WAN. A missing
                # oIntf is not treated as local traffic.
                if (
                    source_uuid
                    and wan_uuid
                    and internet_interface_type(
                        wan_uuid
                    ) == "wan"
                ):
                    normalized = {
                        "kind": "internet_flow",
                        "source_uuid": source_uuid,
                        "source_network": (
                            internet_interface_name(
                                source_uuid
                            )
                        ),
                        "wan_uuid": wan_uuid,
                        "wan": internet_interface_name(
                            wan_uuid
                        ),
                        # WAN COUNTERS BY DIRECTION
                        # Preserve Firewalla's raw flow-direction field so the
                        # 300-second Internet aggregation can partition normal
                        # flows authoritatively by initiating direction.
                        "direction": str(
                            raw_record.get("fd")
                            or ""
                        ).lower(),
                        "upload_bytes": int(
                            raw_record.get("upload")
                            or 0
                        ),
                        "download_bytes": int(
                            raw_record.get("download")
                            or 0
                        ),
                        "count": int(
                            raw_record.get("count")
                            or 1
                        ),
                        "received_at": received_at,
                        "fingerprint": fingerprint,
                    }

            elif ltype == "audit":
                wan_uuid = raw_record.get("intf")

                # Internet page blocked activity includes only
                # audit records attached directly to a known
                # WAN interface. LAN-client DNS/IP audits are
                # reserved for the future Flows page.
                if (
                    wan_uuid
                    and internet_interface_type(
                        wan_uuid
                    ) == "wan"
                ):
                    normalized = {
                        "kind": "blocked_wan",
                        "wan_uuid": wan_uuid,
                        "wan": internet_interface_name(
                            wan_uuid
                        ),
                        "remote_ip": raw_record.get("ip"),
                        "country": raw_record.get(
                            "country"
                        ),
                        "protocol": raw_record.get(
                            "protocol"
                        ),
                        "port": raw_record.get("port"),
                        "count": int(
                            raw_record.get("count")
                            or 1
                        ),
                        "received_at": received_at,
                        "fingerprint": fingerprint,
                    }

                    # Use Firewalla's event timestamp for
                    # hourly placement. Receipt time remains
                    # collector metadata only.
                    flow_timestamp = (
                        raw_record.get("ts")
                    )

                    try:
                        flow_timestamp = float(
                            flow_timestamp
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        flow_timestamp = (
                            received_at
                        )

                    record_blocked_wan_hourly(
                        wan_uuid,
                        normalized["count"],
                        flow_timestamp,
                        fingerprint,
                    )

            if normalized is None:
                continue

            internet_flow_records.append(normalized)

            internet_flow_fingerprints[
                fingerprint
            ] = received_at

            added = True

    # Publish after every event. This also expires old records
    # even when the newest event had no usable Internet records.
    publish_internet_flow_activity(received_at)
    publish_blocked_wan_hourly(received_at)

    return added


def live_stats_worker():

    payload = {
        "type": "system",
        "target": "0.0.0.0",
        "queries": {
            "throughput": {},
            "flows": {},
        },
    }

    while True:

        try:

            print("Connecting to Firewalla LiveStats...")

            with requests.post(
                LIVE_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                stream=True,
                timeout=(10, 10),
            ) as response:

                response.raise_for_status()

                print("LiveStats connected.")

                for line in response.iter_lines(decode_unicode=True):

                    router_read_note("live stream (LiveStats)", len(line or "") + 1)

                    if not line or not line.startswith("data: "):
                        continue

                    try:
                        message = json.loads(line[6:])

                    except json.JSONDecodeError:
                        continue

                    data = message.get("data", {})

                    flow_records = (
                        data.get("flows")
                        or []
                    )

                    process_recent_flow_records(
                        flow_records
                    )

                    process_internet_flow_records(
                        flow_records
                    )

                    ports = []

                    for p in data.get("ports", []):

                        ports.append(
                            {
                                "name": p.get("name"),
                                "role": p.get("role"),
                                "uplink": p.get("uplink"),
                                "speed": p.get("speed"),
                                "carrier": p.get("carrier"),
                                "duplex": p.get("duplex"),
                                "rx_mbps": mbps(p.get("rx")),
                                "tx_mbps": mbps(p.get("tx")),
                            }
                        )

                    interfaces = []

                    for i in data.get(
                        "throughput",
                        [],
                    ):

                        target = i.get("target")

                        metadata = INTERFACE_METADATA.get(
                            target,
                            {},
                        )

                        interface_name = i.get("name")

                        public_ip = None

                        if metadata.get("network_type") == "wan":
                            public_ip = state["public_ips"].get(interface_name)

                        display_name = state["interface_names"].get(
                            interface_name,
                            metadata.get(
                                "display_name",
                                interface_name,
                            ),
                        )

                        interfaces.append(
                            {
                                "name": interface_name,
                                "target": target,
                                "type": i.get("type"),
                                "display_name": display_name,
                                "network_type": metadata.get("network_type"),
                                "vlan_id": metadata.get("vlan_id"),
                                "subnet": metadata.get("subnet"),
                                "dhcp_range": metadata.get("dhcp_range"),
                                "ports": metadata.get("ports") or [],
                                "router_ip": metadata.get("router_ip"),
                                "settings": metadata.get("settings") or {},
                                "public_ip": public_ip,
                                "rx_mbps": mbps(i.get("rx")),
                                "tx_mbps": mbps(i.get("tx")),
                            }
                        )

                    state["ports"] = ports
                    state["interfaces"] = interfaces
                    wan_peaks_note(interfaces, state.get("internet_speedtest_results"))
                    state["last_update"] = time.time()
                    state["connected"] = True

        except Exception as exc:

            print(
                "LiveStats error:",
                exc,
            )

            state["connected"] = False

            time.sleep(3)


# ============================================================
# SYSTEM LIVESTATS WATCHDOG
# ============================================================
def live_stats_watchdog():
    while True:
        age = time.time() - float(state.get("last_update") or 0)
        state["live_stats_health"] = {
            "age_seconds": round(age, 1),
            "stale": age > SYSTEM_LIVESTATS_STALE_SECONDS,
        }
        time.sleep(2)
SETTINGS_STARTED_AT = time.time()


def dashboard_health(now):
    """The dashboard's own parts (Settings › Dashboard Health; the Dashboard
    Part Not Working alert watches the same list)."""
    fh = state.get("flow_history") or {}
    with claude_lock:
        seen = ((claude_load().get("worker") or {}).get("seen_at")) or 0
    ping_ok = bool(ping_status["ok_at"]) and now - ping_status["ok_at"] < 120
    return [
        {"name": "Router (SSH tunnel, live statistics)", "ok": bool(state.get("connected")) and not (state.get("live_stats_health") or {}).get("stale"),
         "detail": f"last data {_ago(now, state.get('last_update'))}" if state.get("connected") else "not connected"},
        {"name": "Local traffic (router history)", "ok": (state.get("local_history") or {}).get("mode") == "history",
         "detail": (lambda h: f"last read {_ago(now, h.get('read_at'))} · {h.get('last_flows', 0)} flows"
                    if h.get("mode") == "history" else
                    f"using the live stream only (misses about a third) · {h.get('error') or 'starting'}")(state.get("local_history") or {})},
        {"name": "Switch live metrics", "ok": (state.get("switch_fast_metrics_health") or {}).get("healthy") is not False,
         "detail": "no Firewalla switches on this router" if (state.get("switch_fast_metrics_health") or {}).get("healthy", False) is None else
                   "{streams_live} of {switches_discovered} switches live".format(**{"streams_live": "?", "switches_discovered": "?", **(state.get("switch_fast_metrics_health") or {})})},
        {"name": "Flow history database", "ok": fh.get("healthy") is not False,
         "detail": fh.get("last_error") or (f"nightly check {(fh.get('check') or {}).get('result') or 'not run yet'}")},
        {"name": "Firewalla MSP", "ok": not msp.get("error") and bool(msp.get("at")),
         "detail": msp.get("error") or f"last read {_ago(now, msp.get('at'))}"},
        {"name": "Speed tests", "ok": not speedtest_scheduler_state.get("last_error"),
         "detail": speedtest_scheduler_state.get("last_error") or "running on schedule"},
        {"name": "Claude on the NAS", "ok": now - seen < 90, "detail": f"last seen {_ago(now, seen)}"},
        {"name": "Ping test", "ok": not NAS_INTERNET_TESTS or ping_ok or now - (ping_status["started_at"] or now) < 120,
         "detail": "off for this router: the NAS's pings would measure another internet line (FIREWALLA_NAS_INTERNET_TESTS)" if not NAS_INTERNET_TESTS else
                   (f"last reply {_ago(now, ping_status['ok_at'])}" if ping_status["ok_at"] else "no reply yet")
                   + (f" · {ping_status['error']}" if ping_status["error"] and not ping_ok else "")},
        # The Equipment Health worker (incidents assessed, patterns, Radio
        # History): a pass every 15 s; 3 minutes to start after a restart.
        (lambda w: {"name": "Equipment Health checks", "ok": now - (w.get("at") or 0) < 120 or now - SETTINGS_STARTED_AT < 180,
                    "detail": (f"last pass {_ago(now, w.get('at'))}" if w.get("at") else "starting" if now - SETTINGS_STARTED_AT < 180 else "not running")
                              + (f" · {w['error']}" if w.get("error") else "")})(state.get("equipment_health_worker") or {}),
    ]


def _ago(now, t):
    if not isinstance(t, (int, float)) or not t:
        return "never"
    s = max(0, now - t)
    return f"{int(s)} s ago" if s < 120 else f"{int(s // 60)} min ago" if s < 7200 else f"{s / 3600:.1f} h ago"
speedtest_scheduler_state = {
    "enabled": True,
    "running": False,
    "last_cycle_at": None,
    "next_cycle_at": None,
    "last_error": None,
    "wans": {},
}
