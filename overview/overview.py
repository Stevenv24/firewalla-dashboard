# Firewalla Overview: one page for every copy of the dashboard.
#
# Each dashboard copy watches one router and serves what it knows at
# /api/status. This service reads every copy's status (trimmed with
# ?exclude=, about 50 KB instead of 1 MB) every POLL_SECONDS, turns each into
# a short summary, and serves the summaries at /api/overview and the page at /.
# It never talks to a router and stores nothing on disk.
#
# Sites come from SITES: "Name|status base URL|page URL[|own-tab URL]" entries
# separated by commas, e.g.
#   SITES=Home|http://fwdash-home:8080|/site/home|http://192.168.23.70:8180/next,...
# (/site/<id> is the gateway's switch link; any URL works.) The optional fourth
# field is that copy's own address: the card then also offers it in a new tab,
# so two routers can be open side by side (two tabs on the gateway share one
# router cookie, so they can't).

import os
import threading
import time

import requests
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

POLL_SECONDS = max(5, int(os.environ.get("POLL_SECONDS", "10")))
STALE_SECONDS = int(os.environ.get("STALE_SECONDS", "60"))
CPU_WARN = int(os.environ.get("CPU_WARN_PERCENT", "90"))
MEM_WARN = int(os.environ.get("MEM_WARN_PERCENT", "90"))
HERE = os.path.dirname(os.path.abspath(__file__))

# Everything /api/status has that this page doesn't use.
EXCLUDE = ",".join([
    "ports", "interfaces", "wifi_stations", "access_points", "wired_clients",
    "ambiguous_wired_clients", "switches", "switch_live_rates", "recent_flows",
    "flow_history", "policy_rules", "device_flow_rates", "vpn_interfaces",
    "vpn_peers", "questions", "knowledge", "local_history", "wifi_neighbours",
    "wifi_power", "client_homes", "planned_work", "equipment_verdicts", "groups",
    "claude_usage", "claude_at", "equipment_health", "equipment_health_worker",
    "policy", "internet_page", "list_check", "mac_rotation", "blocked_wan_hourly",
    "switch_fast_metrics_health", "internet_speedtest_scheduler",
    "slow_speed_tests", "missing",
])


def parse_sites(text):
    sites = []
    for part in (text or "").split(","):
        bits = [b.strip() for b in part.split("|")]
        if len(bits) in (3, 4) and all(bits[:3]) and bits[1].startswith("http"):
            sites.append({"name": bits[0], "api": bits[1].rstrip("/"), "page": bits[2],
                          "direct": bits[3] if len(bits) == 4 else ""})
    return sites


SITES = parse_sites(os.environ.get("SITES", ""))
results = {}          # site name -> summary dict (replaced whole, never edited)
results_lock = threading.Lock()


def num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def summarize(site, status, now):
    """The few facts the overview shows, plus a list of problems."""
    problems = []   # (level, text): level "bad" or "warn"
    connected = bool(status.get("connected"))
    server_now = num(status.get("server_now")) or now
    last_update = num(status.get("last_update"))
    age = (server_now - last_update) if last_update else None

    if not connected:
        state = "offline"
        problems.append(("bad", "router not connected"))
    elif age is None or age > STALE_SECONDS:
        state = "stale"
        problems.append(("warn", "data is stale" + (f" ({int(age)} s old)" if age else "")))
    else:
        state = "live"

    # Internet: every WAN, and whether the primary is the one in use.
    internet = status.get("internet") or {}
    wans = []
    for key, w in sorted((internet.get("wans") or {}).items()):
        if not isinstance(w, dict):
            continue
        name = w.get("provider") or (status.get("interface_names") or {}).get(key) or key
        checks = {c: w.get(c) for c in ("ping", "dns", "http")}
        active = bool(w.get("active") or w.get("in_use"))
        healthy = bool(w.get("ready")) and w.get("carrier") is not False
        if active:
            healthy = healthy and not any(v is False for v in checks.values())
        wans.append({
            "name": name, "role": w.get("role") or "", "public_ip": w.get("public_ip") or "",
            "active": active, "ready": bool(w.get("ready")), "carrier": w.get("carrier"),
            "checks": checks, "healthy": healthy,
        })
        if connected:
            if w.get("carrier") is False:
                problems.append(("bad" if w.get("role") == "primary" else "warn", f"{name}: no link"))
            elif not w.get("ready"):
                problems.append(("bad" if w.get("role") == "primary" else "warn", f"{name}: down"))
            elif active and not healthy:
                failed = ", ".join(c.upper() for c, v in checks.items() if v is False)
                problems.append(("warn", f"{name}: {failed} check failing"))
            if w.get("role") == "primary" and w.get("ready") is not None and not active and internet.get("dual_wan_enabled"):
                problems.append(("warn", f"failed over: {name} (primary) not in use"))
    if connected and internet and internet.get("connected") is False:
        problems.append(("bad", "no internet"))

    devices = status.get("devices") or []
    online = sum(1 for d in devices if isinstance(d, dict) and d.get("online"))

    m = status.get("router_metrics") or {}
    cpu, mem = num(m.get("cpu_usage_percent")), num(m.get("memory_usage_percent"))
    if connected and cpu is not None and cpu >= CPU_WARN:
        problems.append(("warn", f"router CPU {cpu:.0f}%"))
    if connected and mem is not None and mem >= MEM_WARN:
        problems.append(("warn", f"router memory {mem:.0f}%"))

    msp = status.get("msp_alarms") or {}
    outbound = status.get("outbound") or {}
    offline_alerts = status.get("offline_alerts") or {}
    alarms = {
        "msp_active": num(msp.get("active")) or 0,
        "msp_critical": num(msp.get("critical")) or 0,
        "msp_high": num(msp.get("high")) or 0,
        "outbound_attention": num(outbound.get("needs_attention")) or 0,
        "offline_devices": len(offline_alerts) if isinstance(offline_alerts, (dict, list)) else 0,
    }
    if alarms["msp_critical"]:
        problems.append(("bad", f"{alarms['msp_critical']} critical alarm(s)"))
    elif alarms["msp_high"]:
        problems.append(("warn", f"{alarms['msp_high']} high alarm(s)"))
    if alarms["outbound_attention"]:
        problems.append(("warn", f"{alarms['outbound_attention']} new connection(s) need a look"))
    if alarms["offline_devices"]:
        problems.append(("warn", f"{alarms['offline_devices']} watched device(s) offline"))

    vpns = []
    for v in status.get("vpn_sites") or []:
        if isinstance(v, dict):
            vpns.append({"name": v.get("name") or "VPN", "role": v.get("role") or "",
                         "connected": bool(v.get("connected"))})

    # Newest successful speed test per WAN.
    wan_names = {w.get("uuid"): (w.get("provider") or k) for k, w in (internet.get("wans") or {}).items() if isinstance(w, dict)}
    newest = {}
    for t in status.get("internet_speedtest_results") or []:
        if not isinstance(t, dict) or not t.get("success"):
            continue
        key = t.get("uuid") or "?"
        if num(t.get("timestamp")) and (key not in newest or t["timestamp"] > newest[key]["timestamp"]):
            newest[key] = t
    speedtests = []
    for key, t in newest.items():
        r = t.get("result") or {}
        speedtests.append({
            "wan": wan_names.get(key) or (t.get("client") or {}).get("isp") or "?",
            "down": num(r.get("download")), "up": num(r.get("upload")),
            "latency": num(r.get("latency")), "at": t.get("timestamp"),
        })
    speedtests.sort(key=lambda s: s["at"] or 0, reverse=True)

    # Top networks by internet traffic in the last few minutes.
    flow = status.get("internet_flow_activity") or {}
    per_net = {}
    for p in flow.get("paths") or []:
        if isinstance(p, dict):
            name = p.get("source_network") or "?"
            per_net[name] = per_net.get(name, 0) + (num(p.get("total_bytes")) or 0)
    top_networks = [{"name": n, "bytes": b} for n, b in sorted(per_net.items(), key=lambda x: -x[1])[:3] if b]

    level = "bad" if any(l == "bad" for l, _ in problems) else ("warn" if problems else "good")
    site_info = status.get("site") or {}
    return {
        "name": site["name"], "page": site["page"], "direct": site["direct"], "reachable": True, "state": state, "level": level,
        "problems": [{"level": l, "text": t} for l, t in problems],
        "model": site_info.get("router_model") or "", "age_seconds": age,
        "internet": {"dual_wan": bool(internet.get("dual_wan_enabled")), "mode": internet.get("mode") or "", "wans": wans},
        "devices": {"online": online, "total": len(devices)},
        "router": {"cpu": cpu, "memory": mem, "uptime_seconds": num(m.get("uptime_seconds"))},
        "alarms": alarms, "vpns": vpns, "speedtests": speedtests[:2],
        "top_networks": top_networks, "flow_window_seconds": num(flow.get("window_seconds")),
        "checked_at": now,
    }


def unreachable(site, error, now):
    return {
        "name": site["name"], "page": site["page"], "direct": site["direct"], "reachable": False, "state": "offline", "level": "bad",
        "problems": [{"level": "bad", "text": f"dashboard not answering ({error})"}],
        "checked_at": now,
    }


def poll_site(site):
    session = requests.Session()
    while True:
        now = time.time()
        try:
            reply = session.get(f"{site['api']}/api/status", params={"exclude": EXCLUDE}, timeout=8)
            reply.raise_for_status()
            summary = summarize(site, reply.json(), now)
        except requests.RequestException as exc:
            summary = unreachable(site, type(exc).__name__, now)
        except (ValueError, TypeError, AttributeError) as exc:
            summary = unreachable(site, f"bad answer: {type(exc).__name__}", now)
        with results_lock:
            results[site["name"]] = summary
        time.sleep(POLL_SECONDS)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def start_pollers():
    if not SITES:
        print("No sites: set SITES (see compose.yaml).")
    for site in SITES:
        print(f"Watching {site['name']} at {site['api']}")
        threading.Thread(target=poll_site, args=(site,), daemon=True).start()


@app.get("/api/overview")
def api_overview():
    with results_lock:
        sites = [results.get(s["name"]) or {"name": s["name"], "page": s["page"], "direct": s["direct"], "reachable": None,
                                             "state": "waiting", "level": "warn",
                                             "problems": [{"level": "warn", "text": "first check not done yet"}]}
                 for s in SITES]
    return JSONResponse({"sites": sites, "poll_seconds": POLL_SECONDS, "server_now": time.time()},
                        headers={"Cache-Control": "no-store"})


@app.get("/")
def page():
    return FileResponse(os.path.join(HERE, "static", "index.html"), headers={"Cache-Control": "no-cache"})
