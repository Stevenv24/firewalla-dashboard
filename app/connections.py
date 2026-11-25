# Allowed Connections and Planned Changes pages (device onboarding, Phase 1,
# 17 Nov 2026): every device with what it talks to, one row per device
# pair, with ports, who starts each, when last seen and the rule that
# allowed it. Traffic stays read only here (it changes through Policy).
#
# Phase 2 (17 Nov 2026), saved in device_details.json: your Type,
# Manufacturer and Model for each device (a value you chose is confirmed;
# without one the dashboard's guess shows, in italics), values you added
# with Other, devices you deleted from these pages (they come back when
# the router sees them again), your Needs ("A prints from her phone",
# Source and Target a device, group, proposed device or the internet) and
# proposed devices that aren't on the network yet.
#
# Allowed Connections = what the router allows today: allowed local traffic of
# the last year (local_traffic_daily) and each device's "-> Internet" row
# (its home row, holding its Type, Manufacturer and Model). Every port says
# whether you decided it on the Policy page (Allow) or not yet.
# Planned Changes = Policy decisions waiting for a rule change (Block on
# allowed traffic, Allow on blocked traffic).
# Blocked traffic is on neither page: it stays on the Policy page.
# Firewalla's own equipment (router, switches, APs) is left out.
#
# Phase 3 (17 Nov 2026): a Need's assessment. Ask Claude on a Need (with the
# hourly check, or Ask Now: one of the 40 a day, shared with Questions)
# sends Claude need_facts: both sides with your Type, Manufacturer and
# Model, a year of their local traffic both ways, their groups, networks,
# isolation and the rules in the way. Claude answers with questions for
# you (answered in place on the Need) or a proposal: one line per port.
# The dashboard then checks each line itself (need_line_check, not Claude):
# what it does today, what else opening it would open, and what setup can
# enforce it. You accept all or some lines: they become the Need's ports,
# "Accepted, waiting for setup", shown in yellow on Allowed Connections.

import json
import os
import re
import threading
import time
import uuid
from fastapi import Body

from core import (
    Fields, app, claude_load, claude_lock, claude_public, policy_read_json, state,
)
from router import (
    policy_rule_for_pid,
)
from flows import (
    flush_internet_traffic, flush_local_traffic, internet_day, internet_traffic_connection,
    local_traffic_connection, past_days_written,
)
from access import (
    access_is_gear, access_isolated, access_local_rules, access_rule_text, access_sides,
    check_local_access, howto_load, howto_plan,
)
from policy import (
    local_block_kind, local_port_label, policy_data, policy_howto_progress, policy_state_load,
)

CONNECTIONS_CACHE_SECONDS = 60
CONNECTIONS_DAYS = 365
connections_lock = threading.Lock()
connections_cache = {"at": 0, "data": None}
connections_past = {"stamp": None, "found": [], "oldest": None}   # local traffic of the days before today, as connections_build read it
DEVICE_DETAILS_FILE = os.environ.get("FIREWALLA_DEVICE_DETAILS_FILE", "/data/device_details.json")
DETAIL_FIELDS = ("type", "maker", "model")
details_lock = threading.Lock()


def details_load():
    """{devices: {MAC: {type, maker, model}}, added: {type: [], maker: [],
    model: {maker: []}}, deleted: {MAC: when}, needs: [], proposed: {}}."""
    st = policy_read_json(DEVICE_DETAILS_FILE) or {}
    st.setdefault("devices", {})
    st.setdefault("added", {})
    st["added"].setdefault("type", [])
    st["added"].setdefault("maker", [])
    st["added"].setdefault("model", {})
    st.setdefault("deleted", {})
    st.setdefault("needs", [])
    st.setdefault("proposed", {})
    return st


def details_save(st):
    temporary = DEVICE_DETAILS_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle, indent=1)
    os.replace(temporary, DEVICE_DETAILS_FILE)
    connections_cache["at"] = 0   # the pages show the change at once

# The dashboard's guess of a device's Type, from the first words of its
# name (your names lead with what the device is). First match wins.
CONNECTIONS_TYPES = [
    (r"\btab\b|\bipad\b|tablet", "Tablet"), (r"^air quality", "Air Sensor"), (r"^camera|birdbuddy", "Camera"),
    (r"^chime", "Chime"), (r"^dimmer|^light\b", "Switch (Light)"), (r"^fan\b", "Switch (Fan)"),
    (r"^plug\b", "Plug"), (r"^strip\b", "Power Strip"), (r"^echo\b", "Echo"), (r"^ftvc\b|fire ?tv cube", "FTVC"),
    (r"^phone\b|iphone|\bpixel\b", "Phone"), (r"^pc\b|laptop|desktop|macbook", "PC"), (r"^nas\b", "NAS"),
    (r"^printer\b", "Printer"), (r"^tv\b", "TV"), (r"^thermostat", "Thermostat"), (r"^vacuum", "Vacuum"),
    (r"refrigerator|fridge", "Fridge"), (r"^myq\b|garage door", "Garage Opener"), (r"^rachio", "Sprinkler"),
    (r"security panel", "Security Panel"), (r"weather ?station", "Weather Station"), (r"masterbuilt|smoker", "Smoker"),
    (r"fireboard|thermoworks", "Thermometer"), (r"\bac\b|air condition", "Air Conditioner"), (r"air fryer", "Air Fryer"),
]
# The maker named in a device's name beats the network chip's maker the
# router reports (Espressif, Murata, FN-Link make Wi-Fi chips, not devices).
CONNECTIONS_MAKERS = [
    (r"\bkasa\b|\btapo\b", "TP-Link"), (r"\beufy\b", "Eufy"), (r"^echo\b|^ftvc\b|\bamazon\b|^air quality", "Amazon"),
    (r"\bsynology\b|^nas ds", "Synology"), (r"\bmyq\b", "Chamberlain"), (r"\brachio\b", "Rachio"),
    (r"\broborock\b", "Roborock"), (r"\bshark\b", "Shark"), (r"\bmidea\b", "Midea"), (r"\bmasterbuilt\b", "Masterbuilt"),
    (r"\bfireboard\b", "FireBoard"), (r"\bthermoworks\b", "ThermoWorks"), (r"\bbirdbuddy\b", "Bird Buddy"),
    (r"\bws-2000\b", "Ambient Weather"), (r"\bcanon\b", "Canon"), (r"\bpioneer\b", "Pioneer"), (r"\binsignia\b", "Insignia"),
    (r"\blg\b", "LG"), (r"\bs2\d\b|\btab s\d", "Samsung"), (r"iphone|ipad|macbook", "Apple"), (r"\basus\b", "ASUS"),
]
CONNECTIONS_CHIP_MAKERS = ("espressif", "murata", "fn-link", "unknown")
# The router's maker names, shortened to how the maker is known.
CONNECTIONS_VENDORS = [
    (r"tp-link", "TP-Link"), (r"micro-star", "MSI"), (r"samsung", "Samsung"), (r"^apple", "Apple"),
    (r"^lg ", "LG"), (r"asustek", "ASUS"), (r"synology", "Synology"), (r"canon", "Canon"), (r"roborock", "Roborock"),
]


def connections_first(patterns, text):
    text = text.lower()
    return next((value for pattern, value in patterns if re.search(pattern, text)), "")


def connections_clean_maker(vendor):
    """'TP-Link Systems Inc.' -> 'TP-Link'; 'Resideo Inc.' -> 'Resideo';
    chip makers -> ''."""
    vendor = str(vendor or "").strip()
    if not vendor or any(chip in vendor.lower() for chip in CONNECTIONS_CHIP_MAKERS):
        return ""
    known = connections_first(CONNECTIONS_VENDORS, vendor)
    if known:
        return known
    vendor = re.sub(r"[,.]?\s*\b(inc|incorporated|co|ltd|llc|corporation|corp|lim\w*)\b\.?", "", vendor, flags=re.I)
    return vendor.strip(" ,.") or ""


def connections_guess(name, vendor, router_model):
    """The dashboard's guess of a device's Type, Manufacturer and Model."""
    maker = connections_first(CONNECTIONS_MAKERS, name) or connections_clean_maker(vendor)
    # The router's model only when its maker agrees with the name's (Echo
    # Bedroom was labelled a Samsung monitor).
    model = router_model or ""
    if model and maker and vendor and maker.split()[0].lower() not in vendor.lower():
        model = ""
    return {"type": connections_first(CONNECTIONS_TYPES, name), "maker": maker, "model": model}


def connections_details(guess, saved):
    """Your values where you chose one, else the guess; "guessed" names
    the fields still showing a guess."""
    saved = saved or {}
    shown = {f: saved[f] if f in saved else guess[f] for f in DETAIL_FIELDS}
    return {**shown, "guess": guess, "guessed": [f for f in DETAIL_FIELDS if f not in saved and guess[f]]}


def connections_device(device, side, isolated, groups, saved):
    """One device's details: Type, Manufacturer and Model are yours where
    you chose them, else the dashboard's guesses."""
    name = side["name"]
    vendor = device.get("vendor") or ""
    iso_groups = [groups[g]["name"] for g in side.get("groups") or [] if (groups.get(g) or {}).get("isolation")]
    return {
        "mac": side["mac"], "name": name, "ip": side.get("ip") or "", "network": side.get("network_name") or "--",
        "online": side.get("online"), "last_active": device.get("last_active"),
        "groups": [groups[g]["name"] for g in side.get("groups") or [] if g in groups],
        **connections_details(connections_guess(name, vendor, device.get("model")), saved),
        "router_maker": vendor, "router_model": device.get("model") or "",
        "isolated": side["mac"] in isolated or bool(iso_groups),
        "isolation_via": "this client" if side["mac"] in isolated else ", ".join(iso_groups),
    }


def connections_decisions():
    """Policy page decisions by connection ("src|dst|port_key"): (intent
    allow/block, when decided); when
    the Policy page started recording; the Planned Changes waiting for
    a rule change; and the connections you deleted there (key: when)."""
    data = policy_data()
    st = policy_state_load()
    # Every decision in the decision store, as the Decided page lists them
    # (D-915): not only those with traffic in Policy's 7 days, since this page
    # shows a year (a decision gone quiet for a week isn't undecided).
    decided = {key: (d.get("intent"), d.get("at") or 0) for key, d in st["decisions"].items() if d.get("status") == "decided"}
    planned = [r for r in data.get("review") or [] if r.get("kind") == "conflict" or r.get("tab") == "rule_changes"]
    return decided, st.get("since") or 0, planned, dict(st.get("removed") or {})


def connections_build():
    now = time.time()
    sides, groups = access_sides()
    isolated = access_isolated()
    with details_lock:
        details = details_load()
    devices = {}
    for device in state.get("devices") or []:
        mac = str(device.get("mac") or "").upper()
        # A device you deleted stays off until the router sees it again.
        if mac in details["deleted"] and (device.get("last_active") or 0) <= details["deleted"][mac]:
            continue
        if mac in sides and not access_is_gear(sides[mac]):
            devices[mac] = connections_device(device, sides[mac], isolated, groups, details["devices"].get(mac))
    decided, policy_since, planned, removed = connections_decisions()
    rule_text = {}

    def decision_for(src, dst, port_key):
        """(intent, when) of your decision for this connection (every
        decision is for one connection: owner, 20 Nov 2026)."""
        return decided.get(f"{src}|{dst}|{port_key}") or (None, 0)

    def rule_name(pid):
        if pid not in rule_text:
            rule = policy_rule_for_pid(pid)
            rule_text[pid] = access_rule_text(rule) if rule else f"Rule {pid} (since removed)"
        return rule_text[pid]

    # Allowed local traffic of the last year, one row per device pair; the
    # side that starts most of it is the row's Source. Counted as connections
    # started, not router records (D-883; records on rows from before).
    flush_local_traffic()
    since_day = now - CONNECTIONS_DAYS * 86400
    today = internet_day(now)
    sql = """
        SELECT src_mac, dst_mac, protocol, port, SUM(COALESCE(starts, flows)), MAX(last_ts), COUNT(*),
               GROUP_CONCAT(DISTINCT allowed_by)
        FROM local_traffic_daily WHERE outcome = 'allowed' AND day >= ? AND day {} ?
        GROUP BY src_mac, dst_mac, protocol, port"""
    with local_traffic_connection() as connection:
        # The days before today (up to a year) are read once a day, and again
        # only when a save added to one of them; today is read every time
        # (20 Nov 2026: the whole year was read at every build, and every
        # edit on the page asked for a build).
        stamp = (today, past_days_written["local"])
        if connections_past["stamp"] != stamp:
            connections_past.update(stamp=stamp, found=connection.execute(sql.format("<"), (since_day, today)).fetchall(),
                                    oldest=connection.execute("SELECT MIN(first_ts) FROM local_traffic_daily").fetchone()[0])
        found = {row[:4]: row for row in connections_past["found"]}
        for row in connection.execute(sql.format(">="), (since_day, today)):
            old = found.get(row[:4])
            found[row[:4]] = row if not old else (*row[:4], (old[4] or 0) + (row[4] or 0), max(old[5] or 0, row[5] or 0), old[6] + row[6],
                                                  ",".join(x for x in (old[7], row[7]) if x) or None)
        found = list(found.values())
        oldest = connections_past["oldest"] or connection.execute("SELECT MIN(first_ts) FROM local_traffic_daily").fetchone()[0]
    pairs = {}
    for src, dst, protocol, port, flows, last, days, allowed_by in found:
        if src == dst or src not in devices or dst not in devices:
            continue
        port_key, label = local_port_label(protocol, port)
        intent, decided_at = decision_for(src, dst, port_key)
        # Traffic only from before you chose Block isn't allowed
        # today: it stays on the Policy page (17 Nov 2026: two ports from
        # the 16 Nov morning tests showed as conflicts). Allowed traffic
        # after that choice is a real one ("block").
        if intent == "block" and (last or 0) <= decided_at:
            continue
        pair = pairs.setdefault(tuple(sorted((src, dst))), {"ports": {}, "starts": {src: 0, dst: 0}})
        pair["starts"][src] += flows or 0
        p = pair["ports"].setdefault(port_key, {"key": port_key, "label": label, "starters": set(), "flows": 0,
                                                "last_seen": 0, "days": 0, "rules": set(), "decisions": set(),
                                                "undecided_last": 0, "deleted_at": 0})
        p["starters"].add(src)
        p["flows"] += flows or 0
        p["last_seen"] = max(p["last_seen"], last or 0)
        p["days"] = max(p["days"], days or 0)
        p["rules"].update(rule_name(x) for x in (allowed_by or "").split(",") if x)
        p["decisions"].add(intent)
        # Undecided traffic seen only before you deleted its card on the
        # Policy page isn't waiting for you: that card comes back there, as
        # new, only with new traffic (19 Nov 2026: NAS → Doorbell UDP random
        # ports counted as Not Yet Decided with no card to decide it on).
        gone = removed.get(f"{src}|{dst}|{port_key}") or 0
        if intent is None and gone >= (last or 0):
            p["deleted_at"] = max(p["deleted_at"], gone)
        elif intent is None:
            p["undecided_last"] = max(p["undecided_last"], last or 0)
    rows = []
    for (a, b), pair in pairs.items():
        src, dst = sorted((a, b), key=lambda m: (-pair["starts"][m], devices[m]["name"].lower()))
        ports = []
        for p in pair["ports"].values():
            starts = p["starters"]
            decisions = p["decisions"] - {None}
            ports.append({
                "key": p["key"], "label": p["label"], "flows": p["flows"], "last_seen": p["last_seen"], "days": p["days"],
                "dir": "both" if len(starts) == 2 else "fwd" if src in starts else "back",
                "rules": sorted(p["rules"]),
                # decided (every direction seen is Allow), block (you
                # chose to block it but the router still allows it), deleted
                # (undecided traffic only from before you deleted its Policy
                # card), before (undecided traffic only from before the Policy
                # page started recording: nothing there to decide), or open.
                "status": "block" if "block" in decisions else "decided" if decisions == {"allow"} and None not in p["decisions"]
                          else "deleted" if p["deleted_at"] and not p["undecided_last"]
                          else "before" if p["undecided_last"] < policy_since else "open",
                "deleted_at": p["deleted_at"] or None,
            })
        ports.sort(key=lambda p: (p["key"] == "same", p["key"].split()[0], int(p["key"].split()[1]) if p["key"].split()[-1].isdigit() else 99999))
        rows.append({"src": src, "dst": dst, "ports": ports, "last_seen": max(p["last_seen"] for p in ports),
                     "flows": sum(p["flows"] for p in ports)})

    # Each device's internet home row.
    flush_internet_traffic()
    with internet_traffic_connection() as connection:
        internet = {mac: (dests, flows, last, days) for mac, dests, flows, last, days in connection.execute("""
            SELECT device_mac, COUNT(DISTINCT destination), SUM(COALESCE(starts, flows)), MAX(last_ts), COUNT(DISTINCT day)
            FROM internet_traffic_daily WHERE outcome = 'allowed' AND day >= ?
            GROUP BY device_mac""", (since_day,))}
    for mac in devices:
        dests, flows, last, days = internet.get(mac) or (0, 0, None, 0)
        rows.append({"src": mac, "dst": "internet", "destinations": dests, "flows": flows or 0,
                     "last_seen": last, "days": days, "ports": []})

    planning = [{
        "src_mac": (r.get("src") or {}).get("mac"), "dst_mac": (r.get("dst") or {}).get("mac"),
        "src_name": (r.get("src") or {}).get("name"), "dst_name": (r.get("dst") or {}).get("name"),
        "port": r.get("port"), "intent": r.get("intent") or r.get("fix_intent"), "reality": r.get("reality"),
        "tab": r.get("tab"), "since": r.get("since"), "last_seen": r.get("last_seen"), "key": r.get("key"),
        # The same Show Me How as the Policy card (Phase 4, 17 Nov 2026).
        **{k: r.get(k) for k in ("kind", "fix_intent", "item", "src_group", "dst_group")},
        "src": r.get("src"), "dst": r.get("dst"),
    } for r in planned]
    proposed = {pid: {"id": pid, "name": p["name"], "at": p.get("at"),
                      **connections_details({f: "" for f in DETAIL_FIELDS}, p.get("details"))}
                for pid, p in details["proposed"].items()}
    return {"updated_at": now, "recording_since": oldest, "policy_since": policy_since, "days": CONNECTIONS_DAYS,
            "devices": devices, "rows": rows, "planning": planning,
            "options": connections_options(list(devices.values()) + list(proposed.values()), details["added"]),
            "needs": connections_needs(details, rows, sides, groups, devices), "proposed": proposed,
            "groups": sorted(({"id": str(g["id"]), "name": g["name"]} for g in groups.values()),
                             key=lambda g: g["name"].lower())}


def connections_options(shown, added):
    """Every value the dropdowns offer, A-Z: the ones in use (yours or
    guessed) and the ones you added with Other. used = in use (a value in
    use can't be deleted from its list)."""
    def pack(values, used):
        return [{"value": v, "used": v in used} for v in sorted(values, key=str.lower)]
    out = {}
    for field in ("type", "maker"):
        used = {d[field] for d in shown if d[field]}
        out[field] = pack(used | set(added[field]), used)
    models = {}
    for d in shown:
        if d["model"]:
            models.setdefault(d["maker"], set()).add(d["model"])
    out["model"] = {maker: pack(models.get(maker, set()) | set(added["model"].get(maker, [])), models.get(maker, set()))
                    for maker in set(models) | set(added["model"])}
    return out


# ---- Needs: Claude's assessment, the dashboard's check, accepted ports ----
NEED_DIRECTIONS = ("source_starts", "target_starts", "both")
NEED_SOURCES = ("Seen", "Maker", "Standard")
NEED_CHECK_PAIRS = 40       # device pairs checked per line (a group side has many)


def connections_ready():
    """The router's groups and rules have been read since the dashboard
    started. Until then nothing seems to block anything (17 Nov 2026: right
    after a restart A's printing Need showed Done for a minute, its
    VqLAN not loaded yet), so no reach check is believed. The rules entry
    is there from the start, empty, so its read time is what tells."""
    return bool(state.get("groups")) and bool((state.get("policy_rules") or {}).get("updated_at"))


def need_port(line):
    """A proposed line's port as Allowed Connections keys it, its label, and the
    port check_local_access takes: ("tcp 631", "TCP 631", ("tcp", 631))."""
    protocol, port = line.get("protocol") or "tcp", str(line.get("port") or "any")
    if protocol == "icmp":
        return "icmp", "ICMP (ping)", None
    if port == "any":
        return f"{protocol} any", f"{protocol.upper()} all ports", None
    low, _, high = port.partition("-")
    low = int(low)
    if low >= 32768:
        return f"{protocol} high", f"{protocol.upper()} random ports", (protocol, "high")
    if high:
        return f"{protocol} {low}-{high}", f"{protocol.upper()} {low}-{high}", (protocol, low)
    return f"{protocol} {low}", f"{protocol.upper()} {low}", (protocol, low)


def need_clean(value):
    """Claude's reply to a Need (a dict), kept to the fields and sizes the
    page shows; None when it has neither questions nor lines."""
    if not isinstance(value, dict):
        return None
    text = lambda v, n: str(v or "").strip()[:n]
    lines = []
    for x in value.get("lines") or []:
        if not isinstance(x, dict):
            continue
        protocol = text(x.get("protocol"), 8).lower()
        port = re.sub(r"\s+", "", text(x.get("port"), 20).lower()) or "any"
        if protocol not in ("tcp", "udp", "icmp") or not re.fullmatch(r"any|\d{1,5}(-\d{1,5})?", port):
            continue
        if port != "any" and any(int(p) > 65535 for p in port.split("-")):
            continue
        direction = text(x.get("direction"), 20).lower()
        source = text(x.get("source"), 12).title()
        confidence = text(x.get("confidence"), 8).lower()
        lines.append({"id": str(len(lines) + 1), "protocol": protocol, "port": "any" if protocol == "icmp" else port,
                      "direction": direction if direction in NEED_DIRECTIONS else "source_starts",
                      "purpose": text(x.get("purpose"), 200), "source": source if source in NEED_SOURCES else "Standard",
                      "confidence": confidence if confidence in ("low", "medium", "high") else "medium"})
    out = {"summary": text(value.get("summary"), 400), "reply": text(value.get("reply"), 1500),
           "questions": [text(q, 300) for q in value.get("questions") or [] if text(q, 300)][:5],
           "keep_plan": [text(k, 300) for k in value.get("keep_plan") or [] if text(k, 300)][:6],
           "lines": lines[:20], "implications": [text(i, 400) for i in value.get("implications") or [] if text(i, 400)][:8],
           "confidence": text(value.get("confidence"), 8).lower(), "to_settle": text(value.get("to_settle"), 400)}
    return out if out["summary"] and (out["questions"] or out["lines"] or out["keep_plan"]) else None


def need_answer_text(a):
    """Claude's answer to a Need in words, for its Questions conversation."""
    out = [a.get("reply") or "", a.get("summary") or ""]
    out += ["Claude asks: " + q for q in a.get("questions") or []]
    out += [f"{i}. {k}" for i, k in enumerate(a.get("keep_plan") or [], 1)]
    words = {"source_starts": "Source starts", "target_starts": "Target starts", "both": "either starts"}
    out += [f"- {need_port(x)[1]}, {words[x['direction']]}: {x['purpose']} ({x['source']}, {x['confidence']} confidence)"
            for x in a.get("lines") or []]
    out += ["Note: " + i for i in a.get("implications") or []]
    return "\n".join(x for x in out if x)


def need_message(need_id, text):
    """What you wrote to Claude about a Need (Questions, or Ask Claude with
    words): kept on the Need (the last 10) so its next assessment reads it."""
    with details_lock:
        st = details_load()
        need = next((n for n in st["needs"] if n["id"] == need_id), None)
        if need:
            need["messages"] = (need.get("messages") or [])[-9:] + [{"at": time.time(), "text": str(text)[:2000]}]
            details_save(st)


def need_store_assessment(need_id, answer, meta):
    """Claude's answer to a Need, kept on the Need for good (Claude's own
    answers go after 30 days). A new proposal replaces the last one; the
    ports you accepted stay."""
    with details_lock:
        st = details_load()
        need = next((n for n in st["needs"] if n["id"] == need_id), None)
        if not need:
            return False
        need["assessment"] = {**answer, "at": meta.get("at") or time.time(), "model": meta.get("model") or "",
                              "by": meta.get("by") or "now"}
        details_save(st)
    return True


def need_kind(key):
    """A kind side ("k:<Type>|<Manufacturer>|<Model>", the last two may be
    empty) as {type, maker, model}; None for any other side."""
    if not str(key).startswith("k:"):
        return None
    parts = (key[2:].split("|") + ["", ""])[:3]
    return dict(zip(("type", "maker", "model"), (p.strip() for p in parts)))


def need_kind_name(key):
    """"All Echo / Amazon" for a kind side."""
    k = need_kind(key) or {}
    return "All " + " / ".join(v for v in (k.get("type"), k.get("maker"), k.get("model")) if v)


def need_kind_macs(key, devices):
    """The devices of a kind, as the Planned Changes page shows their Type,
    Manufacturer and Model now (yours, else the dashboard's guess): a
    device that joins later, or gets its Type set, is in it from then on."""
    k = need_kind(key)
    if not k or not k["type"]:
        return set()
    return {mac for mac, d in (devices or {}).items()
            if d.get("type") == k["type"] and (not k["maker"] or d.get("maker") == k["maker"])
            and (not k["model"] or d.get("model") == k["model"])}


def need_sides(key, sides, groups, devices=None):
    """The devices a Need's side stands for: one device, a group's members
    or every device of a kind (Firewalla's own equipment left out), every
    device ("all"), none for a proposed device or the internet. devices =
    the page's devices (MAC -> details), for kinds; the last page built
    when not given."""
    if key.startswith("d:"):
        side = sides.get(key[2:].upper())
        return [side] if side else []
    if key.startswith("g:"):
        group = next((g for gid, g in groups.items() if str(gid) == key[2:]), None)
        members = {str(m).upper() for m in (group or {}).get("members") or []}
        return [s for mac, s in sides.items() if mac in members and not access_is_gear(s)]
    if key.startswith("k:") or key == "all":
        if devices is None:
            devices = (connections_cache["data"] or {}).get("devices") or {}
        macs = set(devices) if key == "all" else need_kind_macs(key, devices)
        return sorted((s for mac, s in sides.items() if mac in macs and not access_is_gear(s)), key=lambda s: s["name"].lower())
    return []


def need_side_name(key, sides, groups, details):
    """A Need's side in words, as the page and Show Me How name it."""
    if key == "internet":
        return "Internet"
    if key == "all":
        return "All Devices"
    if key.startswith("k:"):
        return need_kind_name(key)
    if key.startswith("d:"):
        return (sides.get(key[2:].upper()) or {}).get("name") or key
    if key.startswith("g:"):
        return ((need_group(key, groups) or {}).get("name") or key) + " (group)"
    return (details["proposed"].get(key[2:]) or {}).get("name", key) + " (new)"


def need_group(key, groups):
    return next((g for gid, g in groups.items() if str(gid) == key[2:]), None) if key.startswith("g:") else None


def need_describe(key, sides, groups, data, details):
    """A Need's side as Claude gets it."""
    if key == "internet":
        return {"kind": "the internet"}
    group_names = lambda side: [groups[g]["name"] for g in side.get("groups") or [] if g in groups]
    device = lambda mac: {k: (data["devices"].get(mac) or {}).get(k) for k in
                          ("name", "type", "maker", "model", "ip", "network", "isolated", "isolation_via", "online")} | {
        "groups": group_names(sides.get(mac) or {}), "connects": (sides.get(mac) or {}).get("link") or "unknown",
        "details_confirmed_by_owner": not (data["devices"].get(mac) or {}).get("guessed")}
    if key.startswith("d:"):
        return {"kind": "device", **device(key[2:].upper())}
    if key.startswith("g:"):
        group = need_group(key, groups) or {}
        members = need_sides(key, sides, groups, data["devices"])
        return {"kind": "group", "name": group.get("name"), "vqlan": bool(group.get("vqlan")),
                "isolation": bool(group.get("isolation")), "members": [device(s["mac"]) for s in members][:30],
                "member_count": len(members)}
    if key.startswith("k:") or key == "all":
        members = need_sides(key, sides, groups, data["devices"])
        return {"kind": "every device of this Type / Manufacturer / Model, now and later (not a Firewalla group)"
                if key != "all" else "all of the owner's clients", "name": need_side_name(key, sides, groups, details),
                **(need_kind(key) or {}), "members": [device(s["mac"]) for s in members][:30], "member_count": len(members)}
    p = details["proposed"].get(key[2:]) or {}
    return {"kind": "new client, not on the network yet", "name": p.get("name"), **(p.get("details") or {})}


def need_rows(src_macs, dst_macs, table, period, since, blocked_only=False):
    """The local traffic rows between the two sides, both ways, each with
    its outcome by the one definition (policy.local_block_kind, D-913): a
    blocked row that was only a try nobody answered (the other client off,
    nothing at that address, Firewalla's own gear, an allowed port that
    wasn't reached) comes back as "unanswered", not "blocked" (24 Nov 2026:
    here they read as blocked, so Troubleshoot listed them as blocked by
    "not recorded" and Claude was asked to fix a block that wasn't one).
    -> [(src, dst, protocol, port, outcome, connections, first, last, blocked_by)]"""
    flush_local_traffic()
    a, b = sorted(src_macs), sorted(dst_macs)
    marks = lambda xs: ",".join("?" * len(xs))
    with local_traffic_connection() as connection:
        found = connection.execute(f"""
            SELECT src_mac, dst_mac, protocol, port, outcome, COALESCE(starts, flows), first_ts, last_ts, blocked_by, bytes_sent + bytes_received
            FROM {table} WHERE {period} >= ?{" AND outcome = 'blocked'" if blocked_only else ""}
              AND ((src_mac IN ({marks(a)}) AND dst_mac IN ({marks(b)})) OR (src_mac IN ({marks(b)}) AND dst_mac IN ({marks(a)})))""",
            (since, *a, *b, *b, *a)).fetchall()
    out = []
    for s, d, protocol, port, outcome, n, first, last, blocked, nbytes in found:
        if s == d:
            continue
        if outcome == "blocked" and local_block_kind(s, d, protocol, port, blocked, nbytes, first, last) != "real":
            outcome = "unanswered"
        out.append((s, d, protocol, port, outcome, n or 0, first, last, blocked))
    return out


def need_lines(rows):
    """Rows of need_rows added up per who starts it, port and outcome:
    {(src, dst, protocol, port, outcome): {n, rows, first, last, blocked_by}}."""
    lines = {}
    for s, d, protocol, port, outcome, n, first, last, blocked in rows:
        x = lines.setdefault((s, d, protocol, port, outcome), {"n": 0, "rows": 0, "first": first, "last": last, "blocked_by": set()})
        x["n"] += n
        x["rows"] += 1
        x["first"] = min([t for t in (x["first"], first) if t], default=None)
        x["last"] = max([t for t in (x["last"], last) if t], default=None)
        x["blocked_by"] |= {b for b in str(blocked or "").split(",") if b}
    return lines


def need_traffic(src_macs, dst_macs, names):
    """A year of local traffic between the two sides, both ways, allowed,
    blocked and not answered: one line per who starts it, port and outcome
    (busiest first)."""
    if not src_macs or not dst_macs:
        return []
    lines = need_lines(need_rows(src_macs, dst_macs, "local_traffic_daily", "day", time.time() - CONNECTIONS_DAYS * 86400))
    day = lambda t: time.strftime("%Y-%m-%d", time.localtime(t)) if t else None
    said = {"unanswered": "not answered (the other side was off, or nothing is at that address): not a block"}
    return [{"started_by": names.get(s, s), "to": names.get(d, d), "port": local_port_label(protocol, port)[1],
             "outcome": said.get(outcome, outcome), "flows": x["n"], "days_seen": x["rows"], "first": day(x["first"]), "last": day(x["last"]),
             **({"blocked_by": ",".join(sorted(x["blocked_by"]))} if x["blocked_by"] else {})}
            for (s, d, protocol, port, outcome), x in sorted(lines.items(), key=lambda kv: -kv[1]["n"])[:80]]


TROUBLE_DAYS = 7            # blocked tries shown by Troubleshoot and given to Claude
TROUBLE_UNUSED_DAYS = 30    # an allowed port not seen for this long is "not used lately"


def need_blocked_text(code, groups):
    """What the recorder says blocked a flow, in words: "rule:123" -> the
    rule, "ap:50" -> VqLAN or Isolation of group 50."""
    kind, _, ref = str(code or "").partition(":")
    if kind == "rule":
        rule = policy_rule_for_pid(ref)
        return access_rule_text(rule) if rule else f"Rule {ref} (since removed)"
    if kind == "ap":
        group = next((g for gid, g in groups.items() if str(gid) == ref), None)
        return f"VqLAN or Isolation of {group['name'] if group else 'group ' + ref}"
    return code or "not recorded"


def need_blocked_recent(src_macs, dst_macs, names, groups):
    """Blocked tries between the two sides in the last 7 days, both ways,
    newest first: who started, port, tries, first and last time, and what
    blocked them (Troubleshoot; the owner, 17 Nov 2026); and how many more
    tries got no answer, which aren't blocks (need_rows).
    -> (the blocked lines, tries not answered)."""
    if not src_macs or not dst_macs:
        return [], 0
    lines = need_lines(need_rows(src_macs, dst_macs, "local_traffic_hourly", "hour", time.time() - TROUBLE_DAYS * 86400, blocked_only=True))
    when = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else None
    blocked = [{"started_by": names.get(s, s), "from": s, "to": names.get(d, d), "to_mac": d, "port": local_port_label(protocol, port)[1],
                "tries": x["n"], "first": when(x["first"]), "last": when(x["last"]), "last_ts": x["last"],
                "blocked_by": sorted({need_blocked_text(b, groups) for b in x["blocked_by"]}) or ["not recorded"]}
               for (s, d, protocol, port, outcome), x in sorted(lines.items(), key=lambda kv: -(kv[1]["last"] or 0)) if outcome == "blocked"][:40]
    return blocked, sum(x["n"] for (_, _, _, _, outcome), x in lines.items() if outcome == "unanswered")


def need_key(side):
    """A row's side (a MAC, "g:<id>", "p:<id>", "k:<kind>") as a Need's side."""
    side = str(side or "")
    return side if side.startswith(("g:", "p:", "k:")) or side in ("internet", "all") else "d:" + side.upper()


def need_facts(need_id):
    """What Claude gets for one Need (None when the Need is gone)."""
    with details_lock:
        details = details_load()
    need = next((n for n in details["needs"] if n["id"] == need_id), None)
    if not need:
        return None
    data = connections_cache["data"] or connections_build()
    sides, groups = access_sides()
    names = {mac: d["name"] for mac, d in data["devices"].items()}
    src, dst = need_sides(need["src"], sides, groups, data["devices"]), need_sides(need["dst"], sides, groups, data["devices"])
    facts = {"need": need["text"], "source": need_describe(need["src"], sides, groups, data, details),
             "target": need_describe(need["dst"], sides, groups, data, details),
             "local_traffic_between_them": need_traffic({s["mac"] for s in src}, {s["mac"] for s in dst}, names),
             "traffic_recorded_since": time.strftime("%Y-%m-%d", time.localtime(data["recording_since"])) if data.get("recording_since") else None}
    # Devices of the same kind as a new device: what they already use.
    if need["src"].startswith("p:") and need["dst"] != "internet":
        kind = (details["proposed"].get(need["src"][2:]) or {}).get("details") or {}
        alike = [m for m, d in data["devices"].items() if kind.get("type") and d["type"] == kind.get("type")
                 and (not kind.get("maker") or d["maker"] == kind.get("maker"))][:5]
        if alike and dst:
            facts["same_kind_devices_traffic"] = need_traffic(set(alike), {s["mac"] for s in dst}, names)
    # Today, by the dashboard's reach check (the pair as a whole, each way).
    rules = access_local_rules()
    isolated = access_isolated()
    today = []
    for a in src[:6]:
        for b in dst[:6]:
            if a["mac"] != b["mac"]:
                for x, y in ((a, b), (b, a)):
                    r = check_local_access(x, y, groups, rules, isolated=isolated)
                    today.append({"from": x["name"], "to": y["name"], "same_network": x.get("network") == y.get("network"),
                                  "verdict": r["verdict"], "decided_by": r["deciding"].get("text"),
                                  "rules_and_settings_in_the_way": [s["text"] for s in r["steps"]][:6], "notes": r["notes"][:3]})
    facts["reach_today"] = today[:24] if connections_ready() else "not known yet: the dashboard has just started and is still reading the router"
    facts["blocked_last_7_days"], unanswered = need_blocked_recent({s["mac"] for s in src}, {s["mac"] for s in dst}, names, groups)
    if unanswered:
        facts["tries_not_answered_last_7_days"] = (f"{unanswered}: the other side was off, or nothing is at that address. "
                                                   "The router logs these as blocked with no reason; no rule blocked them.")
    for b in facts["blocked_last_7_days"]:
        for k in ("from", "to_mac", "last_ts"):
            b.pop(k, None)
    if need.get("problem"):
        facts["owner_reports_a_problem"] = True
    if need.get("kind") == "keep":
        facts["keep_as_today"] = {"must_stay": need.get("keep"), "while_this_change_is_made": need.get("for_text"),
                                  "that_change_would": need.get("cause"), "change_request": need.get("for_request"),
                                  "state_now": need_keep_state(need)[1]}
    if need.get("answers"):
        facts["owner_answers_to_your_questions"] = need["answers"]
    since = (need.get("assessment") or {}).get("at") or 0
    told = [{"when": time.strftime("%Y-%m-%d %H:%M", time.localtime(m["at"])), "text": m["text"]}
            for m in need.get("messages") or [] if m["at"] > since]
    if told:
        facts["owner_messages_since_your_last_assessment"] = told
    if need.get("assessment"):
        a = need["assessment"]
        facts["your_last_assessment"] = {k: a.get(k) for k in ("summary", "questions", "lines", "implications")}
    if need.get("ports"):
        facts["lines_owner_already_accepted"] = [{k: x.get(k) for k in ("protocol", "port", "direction", "purpose")} for x in need["ports"]]
    return facts


def need_line_check(line, need, src, dst, groups, rules, isolated, seen):
    """The dashboard's own check of one proposed line (not Claude): what it
    does today, what else opening it would open, and what setup can
    enforce it. seen = {(from MAC, to MAC, port key)} allowed in a year."""
    key, _, port = need_port(line)
    if not connections_ready():
        return {"today": "unknown", "today_text": "Not checked yet: the dashboard is still reading the router after a start",
                "opens": "--", "setup": "later", "setup_text": "Checked again in a minute"}
    if need["dst"] == "internet":
        return {"today": "allowed", "today_text": "Open today: no internet limits (your choice)", "opens": "--",
                "setup": "works", "setup_text": "Nothing to set up"}
    if not src or not dst:
        return {"today": "new", "today_text": "Not on the network yet: checked once it joins", "opens": "--",
                "setup": "later", "setup_text": "Decided when it joins: on the same network as the other side only all ports both ways can be opened"}
    pairs = [(a, b) for a in src for b in dst if a["mac"] != b["mac"]][:NEED_CHECK_PAIRS]
    ways = [p for a, b in pairs for p in ([(a, b)] if line["direction"] == "source_starts" else [(b, a)]
                                           if line["direction"] == "target_starts" else [(a, b), (b, a)])]
    results = [(x, y, check_local_access(x, y, groups, rules, port=port, isolated=isolated)) for x, y in ways]
    allowed = [(x, y) for x, y, r in results if r["verdict"] == "allowed"]
    blocked = [r for _, _, r in results if r["verdict"] != "allowed"]
    used = [1 for x, y in allowed if (x["mac"], y["mac"], key) in seen or (x["mac"], y["mac"], "same") in seen]
    same_net = all(x.get("network") == y.get("network") for x, y, _ in results)
    if not results:
        today, text = "new", "Nothing to check"
    elif not blocked:
        today = "used" if used else "unused"
        text = "Allowed today, in use" if used else "Allowed today, not used in a year"
    elif not allowed:
        today, text = "blocked", "Blocked today by " + (blocked[0]["deciding"].get("text") or "a rule")
        # Your rules say blocked, yet the router let it through this year.
        if any((x["mac"], y["mac"], key) in seen for x, y, r in results):
            today, text = "partly", text + ", yet allowed traffic on it was recorded: check on the Access Test"
    else:
        today, text = "partly", f"Allowed for {len(allowed)} of {len(results)} ways ({len(blocked)} blocked by {blocked[0]['deciding'].get('text') or 'a rule'})"
    # What else it opens, and what can enforce it.
    group_src, group_dst = need_group(need["src"], groups), need_group(need["dst"], groups)
    many = lambda key, g, n: (f"all {n} members of {g['name']}" if g else
                              f"all {n} clients of {need_kind_name(key)[4:]}" if key.startswith("k:") else "")
    whole = " and ".join(x for x in (many(need["src"], group_src, len(src)), many(need["dst"], group_dst, len(dst))) if x)
    kinds = {r["deciding"].get("kind") for r in blocked}
    if not blocked:
        setup, setup_text = "works", "Works today"
        opens = "Today every port is open both ways between them (same network)" if same_net else "Nothing more"
        if same_net and line["port"] != "any":
            setup_text += " (all ports: limiting it to this port needs a network move)"
    elif same_net:
        setup, setup_text = "network", "New group + network move: on one network only all ports both ways can be opened (Allowed Devices)"
        opens = "Opening it here (Allowed Devices) opens every port, both ways"
    elif group_src and group_dst:
        setup, setup_text = "list", f"Group → group: via a target list on a rule (group-to-group local rules aren't supported)"
        opens = whole or "Nothing more"
    elif "isolation" in kinds:
        setup, setup_text = "group", "New group needed: Isolation can't be opened for one port (a target-list allow never opens it)"
        opens = "Allowed Devices instead would open every port, both ways"
    elif "vqlan" in kinds:
        # Between networks a target-list allow opens VqLAN; an ordinary allow
        # rule doesn't (real tests 4 and 8, 16 Nov 2026).
        setup, setup_text = "rules", "Works with rules: a target-list allow for this port (it opens VqLAN between networks; a plain allow rule doesn't)"
        opens = whole or "Only this port, this way"
    else:
        setup, setup_text = "rules", "Works with rules: an allow rule for this port"
        opens = whole or "Only this port, this way"
    return {"today": today, "today_text": text, "opens": opens, "setup": setup, "setup_text": setup_text,
            "ways": len(results)}


def connections_needs(details, rows, sides, groups, devices):
    """Each Need for the page with its assessment, the dashboard's check of
    each proposed line, and its accepted ports. Phase 4 (17 Nov 2026):
    each accepted port is "set_up" once the dashboard's check says the
    router allows it every way it asked, else "waiting"; a Need whose
    accepted ports are all set up is done (Planned Changes' Done tab) and
    goes back to waiting by itself if the router stops allowing one. The
    Show Me How picks (one per protocol and who starts: owner's choice)
    and any change started from them ("n|<need id>") come with it."""
    rules = access_local_rules()
    isolated = access_isolated()
    changes = [c for c in howto_load().get("changes") or [] if str(c.get("item") or "").startswith("n|")]
    out = []
    for need in details["needs"]:
        n = dict(need)
        src, dst = need_sides(need["src"], sides, groups, devices), need_sides(need["dst"], sides, groups, devices)
        macs = {s["mac"] for s in src + dst}
        seen = {(r["src"], r["dst"], p["key"]) for r in rows if r["src"] in macs and r["dst"] in macs
                for p in r["ports"] if p["dir"] in ("fwd", "both")}
        seen |= {(r["dst"], r["src"], p["key"]) for r in rows if r["src"] in macs and r["dst"] in macs
                 for p in r["ports"] if p["dir"] in ("back", "both")}
        check = lambda x: need_line_check(x, need, src, dst, groups, rules, isolated, seen)
        a = need.get("assessment")
        if a and a.get("lines") and not a.get("declined_at"):
            n["checks"] = {x["id"]: check(x) for x in a["lines"]}
        # Labels as Allowed Connections shows them; key = port key | direction.
        tag = lambda x: {**x, "key": need_port(x)[0] + "|" + x["direction"], "label": need_port(x)[1]}
        n["ports"] = []
        for x in need.get("ports") or []:
            c = check(x)
            n["ports"].append({**tag(x), "check": c, "state": "set_up" if c["today"] in ("used", "unused", "allowed") else "waiting"})
        if a:
            accepted = {p["key"] for p in n["ports"]}
            n["assessment"] = {**a, "lines": [{**tag(x), "accepted": tag(x)["key"] in accepted} for x in a.get("lines") or []]}
        n["done"] = bool(n["ports"]) and all(p["state"] == "set_up" for p in n["ports"])
        if need.get("kind") == "keep":
            n["keep_state"], n["keep_text"] = need_keep_state(need)
            n["done"] = n["keep_state"] == "ready"
        n["src_name"], n["dst_name"] = need_side_name(need["src"], sides, groups, details), need_side_name(need["dst"], sides, groups, details)
        # A kind side: its devices now (the page lists them on hover).
        n["members"] = {k: [s["mac"] for s in side] for k, side in (("src", src), ("dst", dst)) if need[k].startswith("k:") or need[k] == "all"}
        n["howto"] = need_howto(need, [p for p in n["ports"] if p["state"] != "set_up"], src, dst)
        mine = [c for c in changes if c.get("item") == "n|" + need["id"]]
        n["change"] = {k: mine[0].get(k) for k in ("id", "status", "started", "title")} if mine else None
        out.append(n)
    # A change waits for the Keep Needs made from it (do those first).
    for n in out:
        n["waits_on"] = [{"id": k["id"], "text": k["text"], "done": k["done"]} for k in out
                         if k.get("kind") == "keep" and k.get("for_item") == "n|" + n["id"]]
    # After every check: the checks read today's ports, not planned ones.
    for n in out:
        if n["ports"]:
            connections_plan_row(rows, n)
    return out


def need_keep_state(need):
    """A Keep Need: does the change it was kept from still change its pair?
    ("ready", words) once a way to make that change that works leaves the
    pair as it is today; ("waiting", words) while every such way still
    changes it; ("unknown", words) before the router is read."""
    if not connections_ready():
        return "unknown", "Not checked yet: the dashboard is still reading the router after a start"
    req = need.get("for_request") or {}
    a, b = need["src"][2:].upper(), need["dst"][2:].upper()
    try:
        plan = howto_plan(req.get("act"), req.get("a"), req.get("b"), req.get("proto"), req.get("port"), req.get("both"))
    except Exception as exc:
        return "unknown", f"The change couldn't be worked out: {exc}"
    if not plan:
        return "unknown", "The change it was kept from can't be worked out any more"
    if all(d["done"] for d in plan["directions"]):
        # Made already: did this pair stay as it was?
        sides, groups = access_sides()
        if a in sides and b in sides:
            port = ((req["proto"], int(re.split(r"[,-]", req["port"])[0])) if req.get("proto") in ("tcp", "udp")
                    and re.match(r"\d", req.get("port") or "") else None)
            now = check_local_access(sides[a], sides[b], groups, access_local_rules(), port=port)["verdict"]
            if now != need.get("keep"):
                return "waiting", f"That change is made, and this pair is now {now}, not {need.get('keep')} as you wanted: it needs its own fix"
        return "ready", "That change is made and this pair stayed as it was"
    for d in plan["directions"]:
        for fix in d["fixes"]:
            res = fix.get("result") or {}
            hit = next((m for m in res.get("impacts") or [] if m["a"] == a and m["b"] == b), None)
            if res.get("ok") == res.get("of") and (not hit or hit["after"] == hit["before"]):
                return "ready", f"Ready: \"{fix.get('title')}\" now makes that change without changing this pair"
    return "waiting", "That change would still change this pair: do this first"


def need_howto(need, ports, src, dst):
    """Show Me How picks for a Need's ports still waiting: one per protocol
    and who starts it (TCP 631 and 443 together). None for a new device
    (not on the network yet) or the internet (no limits there). A kind
    side is picked as its devices today (Show Me How takes devices and
    groups); src, dst = the sides' devices."""
    if not ports or need["src"].startswith("p:") or need["src"] == "all" or need["dst"] in ("internet",) or need["dst"].startswith("p:"):
        return []
    ref = lambda key, devs: ",".join("d:" + s["mac"] for s in devs) if key.startswith("k:") else key
    side_a, side_b = ref(need["src"], src), ref(need["dst"], dst)
    if not side_a or not side_b:
        return []
    picks = {}
    for p in ports:
        proto = p["protocol"] if p["protocol"] in ("tcp", "udp") and p["port"] != "any" else "any"
        picks.setdefault((proto, p["direction"]), []).append(p["port"])
    out = []
    for (proto, direction), nums in picks.items():
        a, b = (side_b, side_a) if direction == "target_starts" else (side_a, side_b)
        port = ",".join(dict.fromkeys(nums)) if proto != "any" else ""
        out.append({"act": "allow", "a": a, "b": b, "proto": proto if proto != "any" else "", "port": port,
                    "both": direction == "both",
                    "label": (f"{proto.upper()} {port.replace(',', ', ')}" if proto != "any" else "every port")})
    return out


def connections_plan_row(rows, n):
    """One Need's accepted ports onto its Allowed Connections row (made when the
    pair has none yet): a port still waiting for setup in yellow (a port
    already there keeps its colour, a new one shows Planned); a set-up
    port plain, or "Expected, not seen yet" when no traffic used it yet.
    Every one names its Need (hover)."""
    if n["src"] == "all":
        return
    side = lambda k: k[2:].upper() if k.startswith("d:") else k
    src, dst = side(n["src"]), side(n["dst"])
    flip = False
    if dst == "internet":
        row = next((r for r in rows if r["src"] == src and r["dst"] == "internet"), None)
    else:
        row = next((r for r in rows if {r["src"], r["dst"]} == {src, dst}), None)
        flip = bool(row) and row["src"] == dst
    if not row:
        row = {"src": src, "dst": dst, "ports": [], "last_seen": None, "flows": 0, "planned_row": True}
        rows.append(row)
    for line in n["ports"]:
        key, label, _ = need_port(line)
        waiting = line["state"] != "set_up"
        d = {"source_starts": "fwd", "target_starts": "back", "both": "both"}[line["direction"]]
        if flip and d != "both":
            d = "back" if d == "fwd" else "fwd"
        existing = next((p for p in row["ports"] if p["key"] == key and p.get("status") not in ("planned", "expected")), None)
        if existing:
            existing["need"] = n["text"]
            if waiting:
                existing["planned"] = n["text"]
        else:
            row["ports"].append({"key": key, "label": label, "dir": d, "status": "planned" if waiting else "expected",
                                 "need": n["text"], **({"planned": n["text"]} if waiting else {}),
                                 "flows": 0, "days": 0, "last_seen": None, "rules": []})


def connections_changed(result):
    """A change: the pages' data again (built now), or the refusal."""
    if isinstance(result, str):
        return {"ok": False, "error": result}
    with connections_lock:
        connections_cache["data"], connections_cache["at"] = connections_build(), time.time()
        return {"ok": True, "data": connections_cache["data"]}


def connections_known(mac):
    return any(str(d.get("mac") or "").upper() == mac for d in state.get("devices") or [])


@app.post("/api/connections/detail")
def api_connections_detail(payload: dict = Body(default={})):
    """Set (value) or clear back to the guess (value "") one device's Type,
    Manufacturer or Model; target "d:<MAC>" or "p:<proposed id>". A new
    value (Other) joins its list."""
    f = Fields(payload)
    field, target, value = f.choice("field", DETAIL_FIELDS), f.text("target", 60), f.text("value", 80)
    if not field or not target:
        return {"ok": False, "error": "Say which client and which detail."}
    with details_lock:
        st = details_load()
        if target.startswith("d:") and connections_known(target[2:].upper()):
            record = st["devices"].setdefault(target[2:].upper(), {})
        elif target.startswith("p:") and target[2:] in st["proposed"]:
            record = st["proposed"][target[2:]].setdefault("details", {})
        else:
            return connections_changed("That client isn't known.")
        if value:
            record[field] = value
        else:
            record.pop(field, None)
        if value and field in ("type", "maker") and value not in st["added"][field]:
            st["added"][field].append(value)
        if value and field == "model":
            maker = f.text("maker", 80) or record.get("maker") or ""
            models = st["added"]["model"].setdefault(maker, [])
            if value not in models:
                models.append(value)
        details_save(st)
    return connections_changed(None)


@app.post("/api/connections/confirm")
def api_connections_confirm(payload: dict = Body(default={})):
    """Confirm the guesses shown for these devices (macs): each guessed
    Type, Manufacturer and Model becomes yours."""
    macs = [m for m in (Fields({"m": x}).mac("m") for x in Fields(payload).strings("macs", 500, 17)) if m]
    if not macs:
        return {"ok": False, "error": "No clients to confirm."}
    shown = (connections_cache["data"] or connections_build())["devices"]
    with details_lock:
        st = details_load()
        for mac in macs:
            d = shown.get(mac)
            if d:
                record = st["devices"].setdefault(mac, {})
                for field in d["guessed"]:
                    record[field] = d["guess"][field]
        details_save(st)
    return connections_changed(None)


@app.post("/api/connections/delete-device")
def api_connections_delete_device(payload: dict = Body(default={})):
    """Take a device off these pages (not off the router): every row it is
    on goes, until the router sees it again. maker_too also takes its
    Manufacturer off the list when no other device uses it. A proposed
    device ("p:<id>") goes for good, with the Needs naming it."""
    f = Fields(payload)
    target = f.text("target", 60)
    shown = (connections_cache["data"] or connections_build())
    with details_lock:
        st = details_load()
        if target.startswith("p:") and target[2:] in st["proposed"]:
            maker = ((st["proposed"].pop(target[2:]).get("details")) or {}).get("maker")
            st["needs"] = [n for n in st["needs"] if target not in (n.get("src"), n.get("dst"))]
        elif target.startswith("d:") and target[2:].upper() in shown["devices"]:
            mac = target[2:].upper()
            maker = shown["devices"][mac]["maker"]
            st["deleted"][mac] = time.time()
            st["needs"] = [n for n in st["needs"] if target not in (n.get("src"), n.get("dst"))]
        else:
            return connections_changed("That client isn't on these pages.")
        if f.flag("maker_too") and maker:
            others = [d for key, d in [("d:" + k, d) for k, d in shown["devices"].items()]
                      + [("p:" + k, p) for k, p in shown["proposed"].items()] if key != target and d["maker"] == maker]
            if not others and maker in st["added"]["maker"]:
                st["added"]["maker"].remove(maker)
                st["added"]["model"].pop(maker, None)
        details_save(st)
    return connections_changed(None)


@app.post("/api/connections/list")
def api_connections_list(payload: dict = Body(default={})):
    """Take a value off a dropdown list (Type, Manufacturer, Model of a
    maker). Refused while a device uses it."""
    f = Fields(payload)
    field, value, maker = f.choice("field", DETAIL_FIELDS), f.text("value", 80), f.text("maker", 80)
    if not field or not value:
        return {"ok": False, "error": "Say which value to remove."}
    options = (connections_cache["data"] or connections_build())["options"]
    listed = options[field] if field != "model" else options["model"].get(maker, [])
    entry = next((o for o in listed if o["value"] == value), None)
    if entry and entry["used"]:
        what = {"type": "Type", "maker": "Manufacturer", "model": "Model"}[field]
        return {"ok": False, "error": f"{value} is still used by a client. Change that client's {what} or delete the client first."}
    with details_lock:
        st = details_load()
        if field == "model":
            models = st["added"]["model"].get(maker, [])
            if value in models:
                models.remove(value)
        elif value in st["added"][field]:
            st["added"][field].remove(value)
        details_save(st)
    return connections_changed(None)


@app.post("/api/connections/need")
def api_connections_need(payload: dict = Body(default={})):
    """Add, change or remove a Need: your words for what a Source must do
    with a Target. Source and Target: "d:<MAC>", "g:<group id>",
    "p:<proposed id>", "k:<Type>|<Manufacturer>|<Model>" (every device of
    that kind, now and later; Manufacturer and Model may be blank), "all"
    (Source only, with the internet) or (Target only) "internet"."""
    f = Fields(payload)
    action = f.choice("action", ("add", "edit", "remove"))
    need_id, text, src, dst = f.text("id", 40), f.text("text", 1000), f.text("src", 200), f.text("dst", 200)
    if not action:
        return {"ok": False, "error": "Unknown change."}
    with details_lock:
        st = details_load()
        if action == "remove":
            st["needs"] = [n for n in st["needs"] if n["id"] != need_id]
        else:
            if not text:
                return {"ok": False, "error": "Write the need first."}
            ok_side = lambda s, target: ((s.startswith(("d:", "g:")) and len(s) > 2) or (s.startswith("p:") and s[2:] in st["proposed"])
                                         or (need_kind(s) or {}).get("type") and s.count("|") <= 2 or (target and s == "internet")
                                         or (not target and s == "all" and dst == "internet"))
            if not ok_side(src, False) or not ok_side(dst, True):
                return {"ok": False, "error": "Pick a Source and a Target (All Devices goes with Internet only)."}
            # Same kind both sides (Echo <-> Echo, NAS <-> NAS) is a Need; the
            # same device or group twice isn't.
            if src == dst and not src.startswith("k:"):
                return {"ok": False, "error": "Pick a Source and a different Target."}
            if action == "add":
                # problem: added from Troubleshoot (something isn't working).
                # kind "keep": from Show Me How's What Else This Changes, a
                # pair another change would change that you keep as today.
                need_id = uuid.uuid4().hex[:12]
                extra = {"problem": True} if f.flag("problem") else {}
                if f.choice("kind", ("keep",)) == "keep":
                    req = payload.get("for_request") if isinstance(payload.get("for_request"), dict) else {}
                    r = Fields(req)
                    extra = {"kind": "keep", "keep": f.choice("keep", ("allowed", "blocked")) or "blocked",
                             "for_item": f.text("for_item", 200), "for_text": f.text("for_text", 300), "cause": f.text("cause", 300),
                             "for_request": {"act": r.choice("act", ("allow", "block")) or "allow", "a": r.text("a", 3000),
                                             "b": r.text("b", 3000), "proto": r.text("proto", 10), "port": r.text("port", 40),
                                             "both": r.flag("both")}}
                    if not extra["for_request"]["a"] or not extra["for_request"]["b"]:
                        return {"ok": False, "error": "Which change is this pair kept from?"}
                st["needs"].append({"id": need_id, "text": text, "src": src, "dst": dst, "at": time.time(), **extra})
            else:
                need = next((n for n in st["needs"] if n["id"] == need_id), None)
                if not need:
                    return {"ok": False, "error": "That need is gone."}
                # Claude's proposal was for the old words or sides: it stays,
                # marked as made before the change, until you ask again.
                if need.get("assessment") and (need["text"], need["src"], need["dst"]) != (text, src, dst):
                    need["assessment"]["stale"] = True
                need.update(text=text, src=src, dst=dst, changed_at=time.time())
        details_save(st)
    result = connections_changed(None)
    result["id"] = need_id
    return result


@app.get("/api/connections/troubleshoot")
def api_connections_troubleshoot(a: str = "", b: str = ""):
    """Troubleshoot one Allowed Connections row (a, b: its Source and Target, a MAC
    or "g:<id>"): what is allowed, what was blocked in the last 7 days, what
    is in the way today each way, allowed ports not used lately, and the
    Needs already written for the pair."""
    ka, kb = need_key(a), need_key(b)
    if "internet" in (ka, kb) or ka == kb:
        return {"ok": False, "error": "Troubleshoot works on two of your clients (or a group)."}
    data = api_connections_page()
    sides, groups = access_sides()
    src, dst = need_sides(ka, sides, groups, data["devices"]), need_sides(kb, sides, groups, data["devices"])
    if not src or not dst:
        return {"ok": False, "error": "Those clients aren't on the network now."}
    names = {mac: d["name"] for mac, d in data["devices"].items()}
    plain = lambda k: k[2:] if k.startswith("d:") else k
    row = next((r for r in data["rows"] if {r["src"], r["dst"]} == {plain(ka), plain(kb)}), None)
    rules, isolated = access_local_rules(), access_isolated()
    reach = []
    for x, y in [(s, t) for s in src[:3] for t in dst[:3] if s["mac"] != t["mac"]][:4]:
        for p, q in ((x, y), (y, x)):
            r = check_local_access(p, q, groups, rules, isolated=isolated)
            reach.append({"from": p["name"], "to": q["name"], "verdict": r["verdict"], "uncertain": r["uncertain"],
                          "deciding": r["deciding"].get("text"), "notes": r["notes"][:3], "a": p["mac"], "b": q["mac"],
                          "same_network": p.get("network") == q.get("network")})
    ports = [p for p in (row or {}).get("ports") or [] if p.get("status") not in ("planned", "expected")]
    old = time.time() - TROUBLE_UNUSED_DAYS * 86400
    unused = [p["label"] for p in ports if (p.get("last_seen") or 0) < old]
    open_all = reach and all(r["verdict"] == "allowed" and r["same_network"] for r in reach)
    blocked, unanswered = need_blocked_recent({s["mac"] for s in src}, {s["mac"] for s in dst}, names, groups)
    return {"ok": True, "a": ka, "b": kb, "row_src": (row or {}).get("src"), "ports": ports, "reach": reach,
            "blocked": blocked, "unanswered": unanswered,
            "unused": unused, "open_all": bool(open_all),
            "needs": [n for n in data["needs"] if {n["src"], n["dst"]} == {ka, kb}],
            "days": TROUBLE_DAYS, "unused_days": TROUBLE_UNUSED_DAYS}


@app.post("/api/connections/proposed")
def api_connections_proposed(payload: dict = Body(default={})):
    """Add a proposed device (not on the network yet) by name, or rename one."""
    f = Fields(payload)
    name, pid = f.text("name", 80), f.text("id", 40)
    if not name:
        return {"ok": False, "error": "Give the client a name."}
    with details_lock:
        st = details_load()
        if pid:
            if pid not in st["proposed"]:
                return {"ok": False, "error": "That client is gone."}
            st["proposed"][pid]["name"] = name
        else:
            pid = uuid.uuid4().hex[:12]
            st["proposed"][pid] = {"name": name, "at": time.time(), "details": {}}
        details_save(st)
    result = connections_changed(None)
    result["id"] = pid
    return result


@app.post("/api/connections/need-answers")
def api_connections_need_answers(payload: dict = Body(default={})):
    """Your answers to Claude's questions on a Need ([{q, a}]): Claude gets
    them the next time you ask it about the Need."""
    need_id = Fields(payload).text("id", 40)
    given = [x for x in payload.get("answers") or [] if isinstance(x, dict)][:5] if isinstance(payload.get("answers"), list) else []
    with details_lock:
        st = details_load()
        need = next((n for n in st["needs"] if n["id"] == need_id), None)
        if not need:
            return connections_changed("That need is gone.")
        answers = {a["q"]: a["a"] for a in need.get("answers") or []}
        for x in given:
            q, a = Fields(x).text("q", 300), Fields(x).text("a", 1000)
            if q:
                answers[q] = a
        need["answers"] = [{"q": q, "a": a} for q, a in answers.items() if a]
        details_save(st)
    return connections_changed(None)


@app.post("/api/connections/need-accept")
def api_connections_need_accept(payload: dict = Body(default={})):
    """Accept some (lines: ids) or all (all: true) of Claude's proposed lines
    for a Need: they become its ports, waiting for setup. decline: true
    puts the proposal away (the Need stays). remove: an accepted port
    ("<port key>|<direction>") taken off again."""
    f = Fields(payload)
    need_id, remove = f.text("id", 40), f.text("remove", 60)
    picked = set(f.strings("lines", 20, 4))
    with details_lock:
        st = details_load()
        need = next((n for n in st["needs"] if n["id"] == need_id), None)
        if not need:
            return connections_changed("That need is gone.")
        ports = need.setdefault("ports", [])
        a = need.get("assessment") or {}
        same = lambda x: need_port(x)[0] + "|" + x["direction"]
        if remove:
            need["ports"] = [p for p in ports if same(p) != remove]
        elif f.flag("decline"):
            if not a:
                return connections_changed("There is no proposal to decline.")
            a["declined_at"] = time.time()
        else:
            if not a.get("lines") or a.get("declined_at"):
                return connections_changed("There is no proposal to accept.")
            lines = a["lines"] if f.flag("all") else [x for x in a["lines"] if x["id"] in picked]
            if not lines:
                return connections_changed("Tick the lines to accept first.")
            have = {same(p) for p in ports}
            for x in lines:
                if same(x) not in have:
                    ports.append({k: x[k] for k in ("protocol", "port", "direction", "purpose", "source", "confidence")}
                                 | {"accepted_at": time.time(), "line": x["id"], "assessed_at": a.get("at")})
        details_save(st)
    return connections_changed(None)


@app.get("/api/connections-page")
def api_connections_page():
    """Both pages' data (built at most once a minute), with Claude's status
    on each Need and the Needs' Questions conversations (fresh each time)."""
    from assistant import questions_db, questions_lock, questions_thread_list
    with connections_lock:
        if not connections_cache["data"] or time.time() - connections_cache["at"] > CONNECTIONS_CACHE_SECONDS:
            connections_cache["data"] = connections_build()
            connections_cache["at"] = time.time()
            # Built before the router's groups and rules were read: built
            # again within 10 seconds, not kept a minute.
            if not connections_ready():
                connections_cache["at"] -= CONNECTIONS_CACHE_SECONDS - 10
        data = connections_cache["data"]
    with claude_lock:
        claude = claude_public(claude_load(), "need")
    with questions_lock, questions_db() as c:
        threads = [{k: t[k] for k in ("id", "title", "item_ref", "status", "hourly", "waiting", "last_at")}
                   for t in questions_thread_list(c, kinds={"need"})]
    # Show Me How progress (I'm Doing This) by item: a Policy card or a Need ("n|<id>").
    return {**data, "claude": claude, "need_threads": threads, "howto_progress": policy_howto_progress()}
