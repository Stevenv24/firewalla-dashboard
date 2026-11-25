# Shared by every other file: connections to the router, network names, the
# web app itself, the shared state and its locks, and small helpers.

import ipaddress
import json
import os
import re
import threading
import time
import traceback
from datetime import datetime
from collections import deque
import requests
from fastapi import FastAPI, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles



# ============================================================
# CONNECTIONS
# ============================================================

BASE_URL = "http://127.0.0.1:18834"
FWAPC_BASE_URL = "http://127.0.0.1:18841/v1"

HOSTS_URL = f"{BASE_URL}/v1/host/all"
SYSTEM_URL = f"{BASE_URL}/v1/host/system"
# How much the dashboard reads from the router, per read (owner, 23 Nov 2026:
# the cabin copy pulled about 0.75 GB an hour over the site-to-site VPN):
# name -> [replies or stream lines, bytes], since the start. /api/router-reads.
router_reads = {"since": time.time(), "by": {}}
router_reads_lock = threading.Lock()


def router_read_note(name, nbytes):
    with router_reads_lock:
        x = router_reads["by"].setdefault(name, [0, 0])
        x[0] += 1
        x[1] += nbytes


def router_read_hook(name):
    """hooks= for requests: counts a whole reply (a stream counts its own lines)."""
    def hook(response, *args, **kwargs):
        if not kwargs.get("stream"):
            router_read_note(name, len(response.content))
        return response
    return {"response": hook}


# How often this copy reads its router's system data and device list
# (owner, 23 Nov 2026, D-911): 5 s, or FIREWALLA_ROUTER_POLL_SECONDS (5 to
# 60) for a copy watching a router far away (the cabin's: every byte crosses
# her internet connection). The live streams are unaffected.
try:
    ROUTER_POLL_SECONDS = max(5.0, min(60.0, float(os.environ.get("FIREWALLA_ROUTER_POLL_SECONDS") or 5)))
except ValueError:
    ROUTER_POLL_SECONDS = 5.0
router_system_cache = {"at": 0.0, "data": None}
router_system_lock = threading.Lock()


def router_system():
    """The router's system data (host/system: 2 MB at home), read at most once
    per ROUTER_POLL_SECONDS and shared by everything that needs it (D-911:
    three parts read it every 5 s each, 97 GB a day at home). Callers only
    read it. Raises as requests does when the read fails."""
    with router_system_lock:
        if router_system_cache["data"] is not None and time.time() - router_system_cache["at"] < ROUTER_POLL_SECONDS - 0.5:
            return router_system_cache["data"]
        response = requests.get(SYSTEM_URL, timeout=15, hooks=router_read_hook("host/system"))
        response.raise_for_status()
        data = response.json()
        router_system_cache.update(at=time.time(), data=data)
        return data

STATIONS_URL = f"{FWAPC_BASE_URL}/status/station"
APS_URL = f"{FWAPC_BASE_URL}/status/ap"
SWITCHES_URL = f"{FWAPC_BASE_URL}/status/switch"
FWAPC_CONFIG_URL = f"{FWAPC_BASE_URL}/config/active"

LIVE_URL = (
    f"{BASE_URL}/v1/encipher/simple"
    "?command=get"
    "&item=liveStats"
    "&target=0.0.0.0"
    "&streaming=true"
)


# ============================================================
# DEVICE STATUS
# ============================================================

DEFAULT_OFFLINE_IDLE_SECONDS = 1800


# ============================================================
# NETWORK NAMES (learned from the router)
#
# Every WAN, LAN, VLAN and VPN network by its Firewalla ID (UUID):
#   {uuid: {display_name, network_type, vlan_id, subnet, interface}}
# Filled from the router's network config (update_interface_metadata,
# every 5 seconds), so renaming a network in the Firewalla app shows up
# on the dashboard. The last copy is kept on the NAS so names are known
# straight after a restart, before the router has answered.
# ============================================================

INTERFACE_METADATA_FILE = os.environ.get(
    "FIREWALLA_NETWORK_NAMES_FILE",
    "/data/network_names.json",
)


def load_interface_metadata():
    try:
        with open(INTERFACE_METADATA_FILE, "r", encoding="utf-8") as handle:
            saved = json.load(handle)
        return saved if isinstance(saved, dict) else {}
    except (OSError, ValueError):
        return {}


INTERFACE_METADATA = load_interface_metadata()


def subnet_of(address):
    """'192.168.5.1/24' -> '192.168.5.0/24' (None if not an IPv4 subnet)."""
    if isinstance(address, list):
        address = address[0] if address else None
    try:
        return str(ipaddress.ip_interface(str(address)).network) if address and "/" in str(address) else None
    except ValueError:
        return None


def address_of(address):
    """'192.168.5.1/24' -> '192.168.5.1' (the router's own address there)."""
    if isinstance(address, list):
        address = address[0] if address else None
    try:
        return str(ipaddress.ip_interface(str(address)).ip) if address and "/" in str(address) else None
    except ValueError:
        return None


def dhcp_range_of(cfg):
    """A network's DHCP pool as [first, last], or None (no DHCP): the
    router's networkConfig.dhcp.<interface>.range {from, to}."""
    if not isinstance(cfg, dict):
        return None
    pool = cfg.get("range") if isinstance(cfg.get("range"), dict) else cfg
    first = pool.get("from") or pool.get("start") or pool.get("begin")
    last = pool.get("to") or pool.get("end")
    return [str(first), str(last)] if first and last else None


def replace_contents(shared, new):
    """Gives a shared dict its new contents without ever leaving it empty:
    the new entries go in first, then what is no longer there comes out.
    (Emptied first, there was a moment in which other workers and page
    requests saw nothing: no network names, no Isolation, no settings.)"""
    shared.update(new)
    for key in [k for k in shared if k not in new]:
        del shared[key]


def update_interface_metadata(system_data):
    """Rebuild INTERFACE_METADATA from networkConfig.interface: each family
    (phy, bridge, vlan, wireguard, ...) maps interface names to a config
    whose meta holds the network's uuid, name and type."""
    families = ((system_data.get("networkConfig") or {}).get("interface") or {})
    dhcp = (system_data.get("networkConfig") or {}).get("dhcp") or {}
    dhcp = dhcp if isinstance(dhcp, dict) else {}
    vlan_ids = {}
    for name, config in (families.get("vlan") or {}).items():
        if isinstance(config, dict) and config.get("vid") is not None:
            vlan_ids[name] = config.get("vid")
    # The router's own sockets a network runs over (Network Manager's port
    # icons): a physical port is itself; a VLAN its parent; a bridge its
    # members, followed down to the sockets.
    physical = set(families.get("phy") or {}) if isinstance(families.get("phy"), dict) else set()

    def ports_of(name, seen=()):
        if name in physical:
            return {name}
        for family in families.values():
            config = family.get(name) if isinstance(family, dict) else None
            if isinstance(config, dict):
                under = config.get("intf")
                under = under if isinstance(under, list) else [under] if isinstance(under, str) else []
                return {port for member in under if member not in seen for port in ports_of(member, seen + (name,))}
        return set()

    # A network's own settings (Network Manager's detail pop-up, 20 Nov
    # 2026), from where the router keeps each: the interface itself (its
    # address, Spanning Tree, a WAN's connection type and DNS), dhcp,
    # dhcp6, mdns_reflector, mroute and icmp, each keyed by interface name.
    config_all = system_data.get("networkConfig") or {}

    def section(key, name):
        value = config_all.get(key)
        return value.get(name) if isinstance(value, dict) and isinstance(value.get(name), dict) else {}

    def settings_of(family_name, name, config, network_type):
        pool = section("dhcp", name)
        try:
            mask = pool.get("subnetMask") or str(ipaddress.ip_interface(str(config.get("ipv4"))).netmask)
        except ValueError:
            mask = None
        relays = config_all.get("mroute") if isinstance(config_all.get("mroute"), dict) else {}
        ping = section("icmp", name)
        out = {
            "mask": None if network_type == "wan" else mask,
            "ipv6": bool(config.get("ipv6") or config.get("dhcp6") or section("dhcp6", name)),
            "stp": config.get("stp") if isinstance(config.get("stp"), bool) else None,
            "mdns_relay": section("mdns_reflector", name).get("enabled") is True,
            # (No network had SSDP Relay on when this was written: a network named in mroute is taken as on.)
            "ssdp_relay": any(name == str(k) or name in str(k).split("-") for k in relays),
            "block_ping": (ping.get("echoRequest") is False) if "echoRequest" in ping else None,
        }
        if network_type == "wan":
            out["connection"] = ("PPPoE" if family_name == "pppoe" else "DHCP" if config.get("dhcp") is True
                                 else "Static IP" if config.get("ipv4") or config.get("ipv4s") else None)
            out["dns"] = [str(x) for x in config.get("nameservers") or []][:4]
        else:
            out["dhcp"] = {"on": bool(dhcp_range_of(pool)), "dns": [str(x) for x in pool.get("nameservers") or []][:4],
                           "lease": pool.get("lease"), "search": [str(x) for x in pool.get("searchDomain") or []][:4]}
        return out

    learned = {}
    for family_name, family in families.items():
        if not isinstance(family, dict):
            continue
        for name, config in family.items():
            if not isinstance(config, dict):
                continue
            meta = config.get("meta") or {}
            uuid = meta.get("uuid") or config.get("uuid")
            if not uuid or not meta.get("name"):
                continue
            # A bridge carries a VLAN when one of its members is a VLAN interface.
            members = config.get("intf") or []
            vlan_id = vlan_ids.get(name)
            if vlan_id is None and isinstance(members, list):
                vlan_id = next((vlan_ids[m] for m in members if m in vlan_ids), None)
            network_type = meta.get("type")
            learned[str(uuid)] = {
                "display_name": meta.get("name"),
                "network_type": network_type,
                "vlan_id": vlan_id,
                "subnet": None if network_type == "wan" else subnet_of(config.get("ipv4") or config.get("ipv4s")),
                "router_ip": None if network_type == "wan" else address_of(config.get("ipv4") or config.get("ipv4s")),
                "interface": name,
                "dhcp_range": None if network_type == "wan" else dhcp_range_of(dhcp.get(name) or config.get("dhcp")),
                "ports": sorted(ports_of(name)),
                "settings": settings_of(family_name, name, config, network_type),
            }
    if not learned or learned == INTERFACE_METADATA:
        return
    replace_contents(INTERFACE_METADATA, learned)
    try:
        temporary = INTERFACE_METADATA_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(learned, handle, indent=2)
        os.replace(temporary, INTERFACE_METADATA_FILE)
    except OSError as exc:
        print("Network names save error:", exc)


def router_ips():
    """The router's own address on each local network (from networkConfig)."""
    return {m["router_ip"] for m in INTERFACE_METADATA.values() if m.get("router_ip")}


def router_macs():
    """The router's own MAC addresses: the hosts the router lists at one of
    its own addresses. Learned, so a replaced router needs no code change."""
    return set((state.get("router") or {}).get("macs") or [])


def wan_networks():
    """[(name, uuid)] for every WAN, in interface order (eth0, eth1, ...)."""
    wans = [(m.get("interface") or "", m.get("display_name") or uuid, uuid)
            for uuid, m in INTERFACE_METADATA.items() if m.get("network_type") == "wan"]
    return [(name, uuid) for _, name, uuid in sorted(wans)]


# ============================================================
# FASTAPI
# ============================================================

# No built-in API browser (/docs, /redoc, /openapi.json): nobody uses it and
# it would describe every endpoint to anyone on the network.
app = FastAPI(
    title="Firewalla Dashboard",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Answers and page files over 2 KB go out compressed (16 Nov 2026): the
# once-a-second /api/status is about 156 KB as text, views.js 380 KB.
app.add_middleware(GZipMiddleware, minimum_size=2048, compresslevel=5)


# Names the dashboard answers to. A page on the internet can point its own
# name at the NAS ("DNS rebinding") and then read the dashboard as if it
# were that site; the browser sends that name in Host, so only these are
# served: an IP address, a plain name with no dot (NAS, dashboard
# for the Claude worker, localhost), local endings (.local, .lan,
# .home.arpa, .localhost) and FIREWALLA_ALLOWED_HOSTS (comma list).
DASHBOARD_HOSTS = {h.strip().lower() for h in os.environ.get("FIREWALLA_ALLOWED_HOSTS", "").split(",") if h.strip()}
DASHBOARD_LOCAL_ENDINGS = (".local", ".lan", ".home.arpa", ".localhost")


# Which network this copy watches. One copy of the dashboard watches one
# router; another router (for example one over a site-to-site VPN) gets its
# own copy, a second Container Manager project on its own port. Each copy
# has a name and lists the others, which the menu's Switch Router opens.
#   FIREWALLA_SITE_NAME    "Smith Home": the menu shows "Smith Home Network",
#                          and so do the browser tab and, when there are
#                          other copies, the emails' subjects. Unset: "My".
#   FIREWALLA_SITE_OTHERS  the other copies, "Name=address" separated by
#                          commas (Cabin=http://192.168.1.10:8181/next).
SITE_NAME = os.environ.get("FIREWALLA_SITE_NAME", "").strip() or "My"


def site_others(text):
    """[{name, url}] from "Name=address, ..."; only http(s) addresses."""
    out = []
    for part in (text or "").split(","):
        name, _, url = part.partition("=")
        name, url = name.strip(), url.strip()
        if name and re.match(r"https?://[^\s\"'<>]+$", url):
            out.append({"name": name, "url": url})
    return out


SITE_OTHERS = site_others(os.environ.get("FIREWALLA_SITE_OTHERS", ""))

# The router's model, FIREWALLA_ROUTER_MODEL (to be read from the router by
# the setup page). Only a Gold Pro gets the Gold Pro's photo and port
# numbering (Port 1 = eth3 ... Port 4 = eth0, owner-confirmed 20 Nov 2026);
# any other model, or none given, shows its ports by their names.
ROUTER_MODEL = os.environ.get("FIREWALLA_ROUTER_MODEL", "").strip() or "Firewalla"
ROUTER_IS_GOLD_PRO = re.sub(r"[^a-z]", "", ROUTER_MODEL.lower()).endswith("goldpro")


def site_mail_name(words):
    """An email subject's first words: "Network Alert" while this is the only
    copy, "Cabin Network Alert" when there are others to tell it from."""
    return f"{SITE_NAME} {words}" if SITE_OTHERS else words
# The biggest change a page sends is a layout (at most 2 MB, see
# DASHBOARD_LAYOUTS_MAX_BYTES); anything bigger is refused before it is read,
# so one huge request can't use up the container's memory.
DASHBOARD_MAX_BODY = 2_500_000


def log_safe(value, limit=300):
    """Text for a log line: line breaks and other control characters
    shown as "?", so a name (a device can call itself anything) can't
    write a log line of its own."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:limit]


def public_error(where, exc):
    """An error while answering a page: the details go to the container log
    with a short reference; the page gets a plain message with that
    reference (no internals: file paths, SQL, library messages)."""
    ref = os.urandom(3).hex()
    print(f"{where} error [{ref}]: {log_safe(type(exc).__name__ + ': ' + str(exc), 1000)}")
    traceback.print_exc()
    return f"Something went wrong ({where}). The details are in the dashboard's log under {ref}."


class Fields:
    """Reads a change request's fields, so every save address checks its
    input the same way (16 Nov 2026). Each reader gives a safe value or an
    empty one (None, "", []) and never raises, whatever was sent; what an
    empty one means (an error, a default) is the address's own business."""
    MAC = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

    def __init__(self, payload):
        self.payload = payload if isinstance(payload, dict) else {}

    def text(self, key, most=500, strip=True):
        """A string of at most `most` characters; "" for anything that isn't
        text or a number (a list, an object, nothing)."""
        value = self.payload.get(key)
        if not value or not isinstance(value, (str, int, float)):
            return ""
        value = str(value)
        return (value.strip() if strip else value)[:most]

    def row(self, key):
        """A database row number (1 up to 2^62), or None."""
        try:
            value = int(self.payload.get(key))
        except (TypeError, ValueError, OverflowError):
            return None
        return value if 0 < value < 2 ** 62 else None

    def rows(self, key, most=1000):
        """Row numbers from a list of 1 to `most` of them, sorted, each once;
        None when it isn't such a list or any entry isn't a row number."""
        value = self.payload.get(key)
        if not isinstance(value, list) or not 0 < len(value) <= most:
            return None
        try:
            found = sorted({int(x) for x in value})
        except (TypeError, ValueError, OverflowError):
            return None
        return found if all(0 < x < 2 ** 62 for x in found) else None

    def strings(self, key, most=500, each=100):
        """The first `most` entries of a list as strings of at most `each`
        characters; [] when it isn't a list."""
        value = self.payload.get(key)
        return [str(x)[:each] for x in value[:most]] if isinstance(value, list) else []

    def choice(self, key, choices):
        """The value when it is one of `choices`, else None."""
        value = self.payload.get(key)
        return value if isinstance(value, str) and value in choices else None

    def mac(self, key):
        """A MAC address in capitals, or None."""
        value = self.text(key, 17).upper()
        return value if self.MAC.match(value) else None

    def flag(self, key):
        return bool(self.payload.get(key))


def security_refusal(request, code, reason):
    """A refused request is logged (who, what, why) and answered with code."""
    client = request.client.host if request.client else "?"
    print(f"REFUSED {code} {log_safe(request.method, 10)} {log_safe(request.url.path, 200)} from {log_safe(client, 60)} "
          f"(host {log_safe(request.headers.get('host'), 100)}, origin {log_safe(request.headers.get('origin'), 100)}): {reason}")
    return Response(reason, status_code=code)


def dashboard_host_ok(host):
    host = (host or "").strip().lower()
    if not host:
        return True
    name = host[1:].partition("]")[0] if host.startswith("[") else host.rpartition(":")[0] if host.count(":") == 1 else host
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    name = name.rstrip(".")
    return "." not in name or name.endswith(DASHBOARD_LOCAL_ENDINGS) or name in DASHBOARD_HOSTS


@app.middleware("http")
async def security_headers(request, call_next):
    """Basic browser protections on every reply: never guess a file's type,
    never show the dashboard inside another site's frame, and never send the
    dashboard's address to other sites. A change (POST, PUT, DELETE) sent
    by a page on another site is refused: browsers name the page's site in
    Origin (and Sec-Fetch-Site), so a web page you have open can't press
    Write Digest Now, Send Test Email or any other button for you. The
    Claude worker and scripts send no Origin and are not affected. A
    request for a name the dashboard doesn't answer to is refused
    (dashboard_host_ok). Data addresses (/api/) asked for by a page on
    another site are refused too, when the browser names that page
    (Referer): another site can't read the answer anyway, but each one
    costs the NAS work. The dashboard's own pages send no Referer."""
    if not dashboard_host_ok(request.headers.get("host")):
        return security_refusal(request, 421, "Unknown address for this dashboard.")
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        length = request.headers.get("content-length")
        if length is None and request.headers.get("transfer-encoding"):
            return security_refusal(request, 411, "A change must say its size (Content-Length).")
        if length is not None and (not length.isdigit() or int(length) > DASHBOARD_MAX_BODY):
            return security_refusal(request, 413, "Too large.")
        origin = request.headers.get("origin")
        cross = request.headers.get("sec-fetch-site") == "cross-site"
        if cross or (origin and origin.split("://", 1)[-1].lower() != (request.headers.get("host") or "").lower()):
            return security_refusal(request, 403, "Changes from another site are not accepted.")
    elif request.url.path.startswith("/api/"):
        referer = request.headers.get("referer") or ""
        if request.headers.get("sec-fetch-site") == "cross-site" or (
                referer and referer.split("://", 1)[-1].split("/", 1)[0].lower() != (request.headers.get("host") or "").lower()):
            return security_refusal(request, 403, "Data requests from another site are not accepted.")
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)


# ============================================================
# APPLICATION STATE
# ============================================================

state = {
    "site": {"name": SITE_NAME, "others": SITE_OTHERS, "router_model": ROUTER_MODEL, "gold_pro": ROUTER_IS_GOLD_PRO},
    "connected": False,
    "router": {"ips": [], "macs": []},
    "last_update": None,
    "total_hosts": 0,
    "devices": [],
    "ports": [],
    "interfaces": [],
    "public_ips": {},
    "interface_names": {},
    "wifi_stations": {},
    "access_points": {},
    "wifi_last_update": None,
    "wired_clients": {},
    "ambiguous_wired_clients": {},
    "switches": {},
    "switch_live_rates": {},
    "switch_last_update": None,
    "router_metrics": {},
    "internet": {},
    "internet_flow_activity": {
        "window_seconds": 300,
        "paths": [],
        "blocked_wans": [],
        "normal_flow_count": 0,
        "blocked_wan_attempt_count": 0,
        "records_retained": 0,
        "updated_at": None,
    },
    "blocked_wan_hourly": {
        "retention_hours": 24,
        "wans": {},
        "updated_at": None,
    },
    "recent_flows": {
        "max_records": 500,
        "records": [],
        "normal_count": 0,
        "blocked_count": 0,
        "reported_download_bytes": 0,
        "reported_upload_bytes": 0,
        "updated_at": None,
    },
    "flow_history": {
        "enabled": True,
        "healthy": False,
        "database_path": None,
        "retention_hours": 24,
        "records": 0,
        "normal_records": 0,
        "blocked_records": 0,
        "oldest_event_at": None,
        "newest_event_at": None,
        "last_write_at": None,
        "last_cleanup_at": None,
        "last_inserted": 0,
        "last_duplicates": 0,
        "last_error": None,
    },
    "policy_rules": {
        "rules": [],
        "total_rules": 0,
        "active_rules": 0,
        "disabled_rules": 0,
        "updated_at": None,
    },
    "device_flow_rates": {},
    "vpn_interfaces": {},
    "vpn_peers": {},
    "vpn_sites": [],
}

switch_port_rate_state = {}

# ============================================================
# INTERNET FLOW ACTIVITY
# ============================================================
#
# Firewalla LiveStats reports completed or aggregated flow
# records in batches. These records are suitable for path and
# event summaries, but they are not instantaneous bandwidth
# samples.
#
INTERNET_FLOW_WINDOW_SECONDS = 300
internet_flow_lock = threading.Lock()
internet_flow_records = deque()
internet_flow_fingerprints = {}

RECENT_FLOW_MAX_RECORDS = 500
recent_flow_lock = threading.Lock()
recent_flow_records = deque(
    maxlen=RECENT_FLOW_MAX_RECORDS
)

FLOW_HISTORY_DATABASE = os.environ.get(
    "FIREWALLA_FLOW_DB",
    "firewalla_dashboard.db",
)

try:
    FLOW_HISTORY_HOURS = max(
        1,
        int(
            os.environ.get(
                "FIREWALLA_FLOW_HISTORY_HOURS",
                "24",
            )
        ),
    )
except (TypeError, ValueError):
    FLOW_HISTORY_HOURS = 24

FLOW_HISTORY_CLEANUP_SECONDS = 300
flow_history_lock = threading.Lock()

BLOCKED_WAN_HISTORY_FILE = os.environ.get(
    "FIREWALLA_HISTORY_FILE",
    "internet_blocked_hourly.json",
)
BLOCKED_WAN_HISTORY_HOURS = 24
BLOCKED_WAN_HISTORY_SAVE_SECONDS = 15

blocked_wan_history_lock = threading.Lock()

# Per-host Firewalla flowsummary counters are cumulative and update in
# batches. This state preserves the last counter value and the time at
# which that value was first observed, allowing a rate to be calculated
# across the actual interval between counter changes.
device_flow_counter_state = {}

# A calculated flowsummary rate remains usable between Firewalla's
# batched counter updates, but expires if no new sample is received.
DEVICE_FLOW_RATE_STALE_SECONDS = 45

# AmneziaWG peer runtime activity freshness.
AWG_PEER_ONLINE_SECONDS = 60

# Counter-derived peer traffic at or above this level also
# confirms an active AmneziaWG peer. This filters the small
# residual counter movement observed after disconnection.
AWG_PEER_ACTIVE_RATE_MBPS = 0.01

# Poll Firewalla VPN peer state independently from the slower
# full host/system inventory refresh.
VPN_DISCOVERY_POLL_SECONDS = 5

# Preserve cumulative AWG peer counters between /host/system
# samples so per-peer throughput can be derived from counter
# deltas over the actual elapsed interval.
awg_peer_rate_state = {}

SYSTEM_LIVESTATS_STALE_SECONDS = 12
SWITCH_FAST_STALE_SECONDS = 5

# ============================================================
# HELPERS
# ============================================================


def mbps(bytes_per_second):
    return round(
        (bytes_per_second or 0) * 8 / 1_000_000,
        2,
    )


def safe_number(value):
    try:
        number = float(value)

        if number.is_integer():
            return int(number)

        return round(number, 2)

    except (TypeError, ValueError):
        return None


def normalize_link_speed(value):
    return safe_number(value)


def normalize_identifier(value):
    return str(value or "").upper().replace("-", "").replace(":", "")
msp = {"at": 0, "error": None, "box": None, "lists": {}, "alarms": [], "alarms_at": 0}
# Layer 5 (14 Nov 2026): Claude's guess for a base domain none of the lists
# knows, from the hourly check (answers "dest:<base>" in claude_state.json;
# claude_load keeps this copy). Comes before the address's network, which
# for a named site is only its host (often Amazon or Cloudflare).
dest_claude = {}


# ============================================================
# CLAUDE ASSISTANT: questions answered by Claude on the NAS
#
# A separate container (claude-worker/) asks this dashboard for the next
# question (GET /api/claude/next), sends the facts to Claude as text through
# the Anthropic API with NO tools and the owner's own API key, and posts the
# answer back (POST /api/claude/answer). Both calls need the worker key
# (/run/secrets/claude_worker_key, config/claude_worker_key). Claude
# never reaches the router, Firewalla or this dashboard by itself, and it
# can't change anything: an answer is advice shown on the item.
# Questions come from the hourly check (CLAUDE HOURLY below: every new
# item with an Ask button answered ahead, and the owner's own questions
# from QUESTIONS, in one question), at most CLAUDE_BATCH_DAILY_CAP a day,
# and from Ask Now (QUESTIONS), at most CLAUDE_DAILY_CAP a day; the digest is
# counted apart and never held back. Every answer's cost estimate and
# tokens are logged per day (/data/claude_state.json).
# Kinds: policy (a Policy page item, by its key), alarm (by its aid),
# traffic (a Device Activity: a<mac>|<start>|<end>, or a saved one:
# s<saved id>), outbound (an Outbound item, by its id),
# batch (the hourly question, by its hour) and digest (by day; see DAILY
# DIGEST below).
# ============================================================
CLAUDE_STATE_FILE = os.environ.get("FIREWALLA_CLAUDE_STATE_FILE", "/data/claude_state.json")
CLAUDE_DAILY_CAP = int(os.environ.get("FIREWALLA_CLAUDE_DAILY_CAP", "40"))
CLAUDE_KEEP_SECONDS = 30 * 86400   # answers and usage are kept 30 days
CLAUDE_BATCH_DAILY_CAP = int(os.environ.get("FIREWALLA_CLAUDE_BATCH_DAILY_CAP", "24"))
CLAUDE_KINDS = ("policy", "alarm", "traffic", "outbound", "equipment", "need")
claude_lock = threading.Lock()
# When the Claude worker last asked for work, and what it said about itself
# ({seen_at, version, key_state, memory, memory_limit}). Kept in memory, not
# in the file: it asks every 5 seconds, and saving that rewrote the whole
# file 17,000 times a day (20 Nov 2026). Empty after a restart until the
# worker's next ask, a few seconds later.
claude_worker = {}


# How every Claude answer is written (owner, 18 Nov 2026): three short lines,
# What happened / Likely why / Recommend (the button first, at most one
# check), about 60 words, each fact once, no hedging or boilerplate; the
# confidence is a tag, and "Tell me more" holds the detail.
CLAUDE_STYLE_MARK = "HOW TO WRITE THE ANSWER"
CLAUDE_STYLE = CLAUDE_STYLE_MARK + """ (the owner's rules): three short lines, about 60 words in all.
- Each fact once: never repeat a device, number or rule in a second line.
- Say "client", not "device", for a phone, PC, camera or anything else on the owner's network; keep Firewalla's own names as they are (Device Active Protect, Device Isolation, Allowed Devices).
- No hedging ("it seems", "it may be worth", "possibly"), no boilerplate ("advice only", "check before you act", "I hope this helps"), no confidence words in the text: confidence is its own field.
- Plain words; name devices as the facts name them; times in 24-hour form.
- Name the owner's buttons as the page does, in words (Allow, Block, Show Me How), never as codes (keep_blocking).
An example of the style (one Policy card):
  What happened: NAS → Tapo doorbell, 14 UDP tries at 03:50; the router let 4 through.
  Likely why: Surveillance Station trying the doorbell's video over UDP; your rule allows the cameras only TCP 554 and 2020.
  Recommend: Block. Check the doorbell still records in Surveillance Station.
"Recommend" starts with the owner's button: the page shows the button's name from "recommendation" first, so "check" holds only what comes after it."""
CLAUDE_REPLY_FIELDS = """{"what_happened": "one sentence: which devices, what, when, how many",
 "likely_cause": "the Likely why line: one or two short sentences",
 "recommendation": "%s",
 "check": "after the button: at most ONE check the owner can do, or for a change the exact change; else empty",
 "false_alarm_reason": "only when you recommend false_alarm, mark_normal or normal: a short reason the owner can paste; else empty",
 "confidence": "low, medium or high",
 "more": "for Tell me more: the detail behind the three lines (how you read the facts, what else would fit, what would settle it), at most about 150 words",
 "kb_suggest": "only when this settles something the owner should keep as a known fact (why a device does this, why a rule is right): {\"title\": \"a few words\", \"text\": \"the current position in 2 to 4 short lines\"}; else empty",
 "kb_disagrees": "only when what you see disagrees with one of known_facts: {\"id\": its id, \"why\": \"one sentence\", \"text\": \"the entry as it should read now, 2 to 4 short lines\"}; else empty"}"""


def claude_reply_format(recommendation="one of the choices"):
    """The style rules and the reply format, the end of every item prompt."""
    return ("\n\n" + CLAUDE_STYLE + "\n\nReply with ONLY one JSON object, no other text, no code fence:\n"
            + CLAUDE_REPLY_FIELDS % recommendation)


def claude_answer_fill(a):
    """An answer in the new format also gets "summary" (its What happened
    line), which the digest, the Questions page and Status still read."""
    if isinstance(a, dict) and not a.get("summary"):
        a["summary"] = a.get("what_happened") or a.get("answer") or ""
    return a


def claude_load():
    st = policy_read_json(CLAUDE_STATE_FILE) or {}
    st.setdefault("questions", [])
    st.setdefault("answers", {})
    st.setdefault("usage", {})
    st["worker"] = dict(claude_worker)
    cutoff = time.time() - CLAUDE_KEEP_SECONDS
    st["answers"] = {k: a for k, a in st["answers"].items() if (a.get("at") or 0) >= cutoff}
    # A question that failed stays (so its error shows and it isn't asked
    # again by itself) for 2 days.
    st["questions"] = [q for q in st["questions"] if q.get("status") != "error" or (q.get("asked_at") or 0) >= time.time() - 2 * 86400]
    st["usage"] = {d: u for d, u in st["usage"].items() if d >= datetime.fromtimestamp(cutoff).strftime("%Y-%m-%d")}
    global dest_claude
    dest_claude = {k[5:]: a for k, a in st["answers"].items() if k.startswith("dest:")}   # owner layer 5 (DESTINATIONS)
    claude_usage_publish(st)
    return st


def claude_usage_publish(st):
    """Today's Claude counts for the banner's Ask Now counter (owner, 19 Nov
    2026), in /api/status. Refreshed on every load and save (the worker's
    heartbeat loads it every few seconds, so midnight resets it too). Also,
    for the menu's * colour (owner, 18 Nov 2026): when Claude last answered
    about each kind of item ("alarm", "outbound", "equipment", "policy"...)."""
    when = {}
    for key, a in (st.get("answers") or {}).items():
        kind = key.partition(":")[0]
        when[kind] = max(when.get(kind, 0), a.get("at") or 0)
    state["claude_at"] = when
    day = st["usage"].get(claude_today(), {})
    state["claude_usage"] = {"asked": day.get("asked", 0), "cap": CLAUDE_DAILY_CAP,
                             "batch": day.get("batch", 0), "batch_cap": CLAUDE_BATCH_DAILY_CAP, "digest": day.get("digest", 0)}


def claude_today():
    return datetime.now().strftime("%Y-%m-%d")


def claude_public(st, kind=None):
    """What the pages show: each answer and question in progress, today's
    use against the cap, and whether the worker is running."""
    today = st["usage"].get(claude_today(), {})
    out = {}
    for q in st["questions"]:
        if kind and q["kind"] != kind:
            continue
        out[q["ref"]] = {"status": q["status"], "asked_at": q["asked_at"], "error": q.get("error")}
    for ref_key, a in st["answers"].items():
        k, _, ref = ref_key.partition(":")
        if kind and k != kind:
            continue
        entry = out.setdefault(ref, {"status": "done"})
        entry["answer"] = a
    seen = (st.get("worker") or {}).get("seen_at") or 0
    batch = next((q for q in st["questions"] if q["kind"] == "batch" and q["status"] in ("queued", "working")), None)
    hourly = {i["key"].partition(":")[2] for i in (batch or {}).get("items") or [] if not kind or i["key"].startswith(kind + ":")}
    for ref in hourly:
        out.setdefault(ref, {})["hourly"] = batch["status"]   # in this hour's question
    return {"items": out, "today": {"asked": today.get("asked", 0), "answered": today.get("answered", 0), "batch": today.get("batch", 0),
                                    "digest": today.get("digest", 0), "cost_usd": round(today.get("cost_usd", 0.0), 4)},
            "cap": CLAUDE_DAILY_CAP, "batch_cap": CLAUDE_BATCH_DAILY_CAP, "batch_at": st.get("batch_at"),
            "worker_seen": seen, "worker_up": time.time() - seen < 90,
            "queued": sum(1 for q in st["questions"] if q["status"] in ("queued", "working"))}


class StateFileError(Exception):
    """A saved state file is there but could not be read."""


def policy_read_json(path):
    """A saved state file's contents, or None when there is no such file
    yet (a first start). A file that is there but can't be read (a disk
    hiccup, bad contents) is tried three times and then raises
    StateFileError: whoever asked stops there, so an empty state is never
    saved over the file (20 Nov 2026: before, any failed read counted as
    "no file yet", and the next save replaced the file with an empty one)."""
    for attempt in range(3):
        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(handle)
            if not isinstance(value, dict):
                raise ValueError("it doesn't hold a JSON object")
            return value
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            error = exc
            if attempt < 2:
                time.sleep(0.2)
    print(f"State file {path} could not be read and was left as it is: {log_safe(error)}")
    raise StateFileError(f"{os.path.basename(path)} could not be read")
