# MODEL ACCURACY (part 5 of the Show Me How safety plan, owner, 24 Nov 2026).
# Show Me How is only as right as its rule checker (access.check_local_access).
# Here the checker is held against the router itself: every local connection
# the router recorded in the last 24 hours (local_traffic_hourly: allowed, or
# blocked by a real block - tries at a client that wasn't answering are left
# out, D-913) is checked again by the model, on its own protocol and port,
# without the router's own credits. Where they differ, the model is missing
# something about your network:
#   verdict   the router allowed what the model says is blocked, or the other
#             way round;
#   rule      the same answer, but the router names another rule than the one
#             the model says decides it.
# Violations on the Policy page are something else: traffic against your
# decisions. These are gaps in the model, to be fixed in the checker.
# Worked out once an hour (accuracy_worker) and kept in model_accuracy.json
# with one summary line a day for 30 days; Show Me How shows it beside
# Changes (/api/model-accuracy).

import json
import os
import threading
import time

from core import app, policy_read_json, state
from access import (
    access_isolated, access_local_rows, access_local_rules, access_paused, access_rule_text,
    access_sides, check_local_access,
)

ACCURACY_FILE = os.environ.get("FIREWALLA_ACCURACY_FILE", "/data/model_accuracy.json")
ACCURACY_EVERY = 3600     # seconds between reports
ACCURACY_DAYS = 30        # days of summary lines kept
ACCURACY_SHOWN = 200      # most disagreements kept, the most connections first
accuracy_lock = threading.Lock()


def accuracy_router_words(by, groups):
    """What the router says decided a connection, in words: "#829 <rule>",
    "VqLAN or Isolation of G06 Phones", or what it sent."""
    by = str(by or "")
    if by.startswith("rule:"):
        pid = by[5:]
        rule = next((r for r in (state.get("policy_rules") or {}).get("rules") or [] if str(r.get("pid")) == pid), None)
        return f"#{pid} {access_rule_text(rule)}" if rule else f"rule #{pid}"
    kind, _, gid = by.partition(":")
    if kind == "ap" and gid:
        return f"VqLAN or Isolation of {(groups.get(gid) or {}).get('name') or 'group ' + gid}"
    return by or "nothing named"


def accuracy_build(hours=24):
    """The report: {"at", "hours", "connections", "agree", "disagree", "pct",
    "kinds": {verdict, rule}, "rows": [...]} (see the top of this file)."""
    sides, groups = access_sides()
    rules, iso = access_local_rules(), access_isolated()
    paused = {m: why for m, sd in sides.items() if (why := access_paused(sd))}
    seen = {}
    for src, dst, outcome, protocol, port, n, _records, _size, last, allowed_by, blocked_by in access_local_rows(hours):
        if outcome not in ("allowed", "blocked"):
            continue
        a, b = sides.get(str(src).upper()), sides.get(str(dst).upper())
        proto = str(protocol or "").lower()
        port = int(port) if str(port).isdigit() else None
        if not a or not b or proto not in ("tcp", "udp") or port is None:
            continue
        k = (a["mac"], b["mac"], proto, port, outcome)
        e = seen.setdefault(k, {"n": 0, "last": 0, "by": None})
        e["n"] += n or 1
        if (last or 0) >= e["last"]:
            e["last"], e["by"] = last or 0, (allowed_by if outcome == "allowed" else blocked_by) or e["by"]
    total = agree = 0
    kinds = {"verdict": 0, "rule": 0}
    out = {}
    cache = {}
    for (am, bm, proto, port, outcome), e in seen.items():
        total += e["n"]
        ck = (am, bm, proto, port)
        if ck not in cache:
            cache[ck] = check_local_access(sides[am], sides[bm], groups, rules, lists_uncertain=False,
                                           port=(proto, port), isolated=iso, paused=paused)
        r = cache[ck]
        router_pid = str(e["by"] or "")[5:] if str(e["by"] or "").startswith("rule:") else None
        model_pid = str(r["deciding"].get("pid")) if r["deciding"].get("kind") == "rule" else None
        kind = ("verdict" if r["verdict"] != outcome else
                "rule" if router_pid and model_pid and router_pid != model_pid else None)
        if not kind:
            agree += e["n"]
            continue
        kinds[kind] += e["n"]
        row = out.setdefault((am, bm, kind, outcome, r["deciding"]["text"], str(e["by"])), {
            "a": am, "b": bm, "an": sides[am]["name"], "bn": sides[bm]["name"], "kind": kind,
            "router": outcome, "router_by": accuracy_router_words(e["by"], groups),
            "model": r["verdict"], "model_by": r["deciding"]["text"], "uncertain": bool(r.get("uncertain")),
            # A block naming nothing is often a try at a client that wasn't
            # answering that the unanswered-try check didn't catch (D-913).
            "unnamed": outcome == "blocked" and not e["by"],
            "ports": [], "connections": 0, "last": 0})
        row["connections"] += e["n"]
        row["last"] = max(row["last"], e["last"])
        label = f"{proto.upper()} {port}"
        if label not in row["ports"] and len(row["ports"]) < 12:
            row["ports"].append(label)
    rows = sorted(out.values(), key=lambda x: -x["connections"])
    return {"at": time.time(), "hours": hours, "connections": total, "agree": agree, "disagree": total - agree,
            "pct": round(100.0 * agree / total, 1) if total else None, "kinds": kinds,
            "pairs": len(rows), "rows": rows[:ACCURACY_SHOWN]}


def accuracy_load():
    return policy_read_json(ACCURACY_FILE) or {}


def accuracy_save(st):
    temporary = ACCURACY_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, ACCURACY_FILE)


def accuracy_run():
    """Builds the report and keeps one summary line a day (the latest)."""
    report = accuracy_build()
    day = time.strftime("%Y-%m-%d", time.localtime(report["at"]))
    with accuracy_lock:
        st = accuracy_load()
        days = [d for d in st.get("days") or [] if d.get("day") != day][-(ACCURACY_DAYS - 1):]
        days.append({"day": day, **{k: report[k] for k in ("connections", "agree", "disagree", "pct", "pairs", "kinds")}})
        accuracy_save({"report": report, "days": days})
    return report


def accuracy_worker():
    # First report a few minutes after a start, so the router reads are in.
    time.sleep(180)
    while True:
        accuracy_run()
        time.sleep(ACCURACY_EVERY)


@app.get("/api/model-accuracy")
def api_model_accuracy(fresh: str = None):
    """The latest report and the daily summary lines; fresh=1 works it out now."""
    if fresh in ("1", "true"):
        accuracy_run()
    with accuracy_lock:
        st = accuracy_load()
    return {"report": st.get("report"), "days": st.get("days") or [], "updated_at": time.time()}
