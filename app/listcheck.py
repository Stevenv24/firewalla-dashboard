# LIST CHECK (owner, 23 Nov 2026). A target list holds addresses, not
# clients, so it doesn't follow clients that come and go:
#   leftover  a line for an address on one of your networks that no client
#             has any more (not in use, not reserved, not a NAS's shared
#             address): the client was removed. If the address is handed
#             to another client, that client gets the old one's access.
#   missing   a client in a group whose other clients a list (used by a
#             rule) holds, while it isn't in it: usually a client that
#             joined the group after the list was made (a new camera not in
#             the cameras list). Intentional ones: Acknowledge.
#   shared    (24 Nov 2026, D-1061) a list that rules On more than one
#             group, client or network use: a change to it for one changes
#             the others too. A list has one owner; the steps give each of
#             the others a list of its own.
# Each item comes with Show Me How style steps (MSP and app, Print Steps),
# and in parts the page can lay out (24 Nov 2026, D-1062): "title" (a few
# words), "facts" ([label, text] pairs: Used By, Why It Matters, What To
# Do) beside "text" (the same in one sentence, for Print Steps and exports).
# Worked out every minute (24 Nov 2026, D-1063; it was once a night), from
# a few minutes after a start, and on Check Now (which reads your lists
# from the MSP again first): a finding goes as soon as its list or rule is
# put right. Kept in state["list_check"] (Status's Needs You and the Target
# Lists page's menu * read it) and list_check.json (when each item was
# first seen, and what you declined). Decline (D-1063; it was Acknowledge):
# the finding is not offered again while it stays the same finding.

import ipaddress
import json
import os
import re
import threading
import time
from collections import Counter

from fastapi import Body

from core import Fields, INTERFACE_METADATA, app, msp, policy_read_json, state
from router import feature_settings, internet_interface_name
from access import (
    ACCESS_HA_PAIRS, access_is_gear, access_rule_text, access_sides, access_target_list_side, howto_addresses, howto_app, howto_id,
    howto_list_owners, howto_own_list_name, howto_reserve_step, howto_reserved,
)

LIST_CHECK_FILE = os.environ.get("FIREWALLA_LIST_CHECK_FILE", "/data/list_check.json")
LIST_CHECK_EVERY = 60       # seconds between looks
TARGET_LIST_LIMIT = 100     # Firewalla MSP Professional and Business: up to 100 lists of your own, 2,000 lines each (its help page on Target Lists)
list_check_lock = threading.Lock()


def list_check_load():
    st = policy_read_json(LIST_CHECK_FILE) or {}
    st.setdefault("seen", {})
    # What you acknowledged before 24 Nov 2026 counts as declined (sig None: whatever the finding says).
    st.setdefault("declined", {k: {"at": at, "sig": None} for k, at in (st.pop("acked", None) or {}).items()})
    return st


def list_check_save(st):
    temporary = LIST_CHECK_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, LIST_CHECK_FILE)


def list_check_lans():
    """Your own networks' address ranges (no WAN): only addresses on them
    can belong to one of your clients."""
    out = []
    for meta in INTERFACE_METADATA.values():
        if meta.get("network_type") == "wan" or not meta.get("subnet"):
            continue
        try:
            out.append(ipaddress.ip_network(str(meta["subnet"]), strict=False))
        except ValueError:
            pass
    return out


def list_check_lines(tl):
    """A list's lines that name one address: [(line, address, ending)];
    ending = what follows the address (",tcp:554,2020" or "")."""
    out = []
    for t in tl.get("targets") or []:
        text = str(t).strip()
        if not text or text.startswith("#"):
            continue
        address = text.partition(",")[0].partition(":")[0].strip()
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue   # a domain or a range: not one client
        out.append((text, str(ip), text[len(address):]))
    return out


def list_check_split_steps(tid, tl, users, owners):
    """A shared list's steps: the owner of its oldest rule keeps it; every
    other owner gets a copy of it under its own name, a rule that uses the
    copy, and then its old rule paused or deleted (in that order, so nothing
    is closed in between). -> (steps, the owner that keeps the list)."""
    name = tl.get("name") or tid
    key = lambda on: (str(on.get("kind")), str(on.get("id")).upper())
    mine = {}
    for r in users:
        on = r.get("applies_on" if access_target_list_side(r) == "matching" else "matching") or {}
        mine.setdefault(key(on), []).append(r)
    number = lambda r: int(r["pid"]) if str(r.get("pid")).isdigit() else 10 ** 9
    keeper = min(owners, key=lambda o: min(number(r) for r in mine[key(o)]))
    lines = [str(t).strip() for t in tl.get("targets") or [] if str(t).strip()]
    real = lambda targets: {str(t).strip().lower() for t in targets or [] if str(t).strip() and not str(t).startswith("#")}
    what = re.sub(r"(\s+[\d,\-]+)+$", "", name)   # the list's name without its ports
    steps, taken = [], []
    for o in owners:
        if o is keeper:
            continue
        # What is done already is left out (D-1063): a list of this owner's own with these
        # lines that its rule uses (only the old rule is left), or one no rule uses yet.
        ready = spare = None
        for lid, other in msp["lists"].items():
            if lid == tid or not real(tl.get("targets")) <= real(other.get("targets")):
                continue
            theirs = howto_list_owners(lid)
            if len(theirs) == 1 and key(theirs[0]) == key(o):
                ready = other
            elif not theirs and real(other.get("targets")) == real(tl.get("targets")):
                spare = spare or other
        new = (ready or spare or {}).get("name") or howto_own_list_name({"name": o["name"]}, [{"name": what}], [], taken)
        taken.append(new)
        if not (ready or spare):
            n = len(real(lines))   # a note (a line starting with #) is copied too, but isn't counted
            steps.append({"title": f"Create the target list \"{new}\" ({n} line{'s' if n != 1 else ''}, the same as \"{name}\")",
                          "msp": {"path": ["Target Lists", "Create Target List"], "fields": [["List Name", new, new], ["Category", "Private", None],
                                  ["Targets", f"{n} line{'s' if n != 1 else ''}", "\n".join(lines)], ["Notes", "what it's for", None]], "lines": lines},
                          "app": {"note": "Target lists can only be made on the MSP website."},
                          "note": f"Then Create. It is {o['name']}'s own list.", "picture": "msp-targetlist-create.jpg", "undo": f"Delete the list \"{new}\" (after its rule)."})
        for r in mine[key(o)]:
            pid, text, action = r.get("pid"), access_rule_text(r), str(r.get("action") or "allow")
            if ready:
                pass   # its own list and a rule on it are there: only the old rule is left
            elif access_target_list_side(r) == "matching":
                way = {"outbound": "Outbound only", "inbound": "Inbound only"}.get(r.get("direction"), "Bi-directional")
                steps.append({"title": f"Create the rule \"{new}\": {action.title()} Target List {new} On {o['name']}",
                              "msp": {"path": ["Rules", "Create Rule"], "fields": [["Name", new, new], ["Action", action.title(), None], ["Matching", f"Target List › {new}", None],
                                      ["On", f"FWG Pro (Router) + {o['name']}", None], ["Direction", way, None], ["Schedule", "Always", None]]},
                              "app": howto_app("rule", name=new, action=action, matching_path=f"Set a target › Target List › {new}", matching_label="Target List",
                                               matching_value=new, target=f"Target List {new}", list=True, on_kind=o.get("kind"), on=o["name"],
                                               direction=r.get("direction") or "bidirection"),
                              "note": f"Then Create. It does what rule #{pid} does, from {o['name']}'s own list. Direction appears once Matching is set.",
                              "picture": "msp-rule-create.jpg", "undo": f"Delete the rule \"{new}\" On {o['name']}."})
            else:
                steps.append({"title": f"Create a copy of rule #{pid} that uses \"{new}\" in place of \"{name}\"",
                              "msp": {"path": ["Rules", "Create Rule"], "fields": [["Like", f"#{pid} {text}", None], ["Target List", new, new]]},
                              "app": {"note": f"Make the same rule as #{pid}, with the target list \"{new}\"."}, "note": "Then Create.",
                              "picture": "msp-rule-create.jpg", "undo": "Delete the copy."})
            steps.append({"title": f"Pause or delete rule #{pid} ({text})",
                          "msp": {"path": ["Rules", f"#{pid} {text}"], "fields": [["Button", "Pause (or Delete)", None]]},
                          "app": howto_app("pause", scope=o["name"] or "its scope", rule=text),
                          "note": f"Rule Details › Pause, once the new rule is there: \"{name}\" is then {keeper['name']}'s alone. Delete it when you see nothing is missed.",
                          "picture": "msp-rule-details.jpg", "undo": f"Resume rule #{pid}."})
    return steps, keeper


def list_check_build():
    sides, groups = access_sides()
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    lans = list_check_lans()
    # Every address in use or held: today's, reservations, offline clients' last, a NAS's shared one.
    held = set()
    for d in state.get("devices") or []:
        if d.get("ip"):
            held.add(str(d["ip"]))
        held.update(howto_reserved(str(d.get("mac") or "").upper()))
    for s in sides.values():
        held.update(s.get("ips") or [])
    held.update(shared for shared, _ in ACCESS_HA_PAIRS)
    owner = {}   # address -> client
    for s in sides.values():
        for ip in howto_addresses(s)[0] + list(s.get("ips") or []):
            owner.setdefault(ip, s)
    items = []
    for tid, tl in sorted(msp["lists"].items(), key=lambda x: str(x[1].get("name") or "").lower()):
        name = tl.get("name") or tid
        users = [r for r in rules if access_target_list_side(r) and str((r.get(access_target_list_side(r)) or {}).get("id")) == str(tid)]
        used_by = [f"#{r.get('pid')} {r.get('action')} On {(r.get('applies_on') or {}).get('name') or ''}".strip() for r in users]
        used_words = " · ".join(f"#{r.get('pid')} {str(r.get('action') or '').title()} On {(r.get('applies_on') or {}).get('name') or ''}".strip() for r in users) or "No rule"
        count = lambda n, one, many=None: f"{n} {one if n == 1 else many or one + 's'}"
        lines = list_check_lines(tl)
        # 1) Leftover lines.
        gone = [(text, ip) for text, ip, _ in lines if ip not in held and any(ipaddress.ip_address(ip) in n for n in lans)]
        if gone:
            items.append({
                "id": f"left:{tid}", "kind": "leftover", "list": name, "used_by": used_by, "sig": "|".join(sorted(t for t, _ in gone)),
                "title": f"{count(len(gone), 'line')} for an address no client has",
                "facts": [["Lines", "; ".join(t for t, _ in gone)], ["Used By", used_words],
                          ["Why It Matters", f"A client that gets {'that address' if len(gone) == 1 else 'one of those addresses'} later gets this access too." if used_by
                           else "No rule uses the list, so nothing is open: the lines are only left over."],
                          ["What To Do", f"Remove the {'line' if len(gone) == 1 else 'lines'} from the list (1 step)."]],
                "text": f"\"{name}\" has {len(gone)} line{'s' if len(gone) != 1 else ''} for an address no client has any more "
                        f"({', '.join(ip for _, ip in gone[:4])}{' …' if len(gone) > 4 else ''})"
                        + (f": {', '.join(used_by)} still {'gives' if len(used_by) == 1 else 'give'} it access, so a client that gets "
                           f"{'that address' if len(gone) == 1 else 'one of them'} later gets that access too" if used_by else ": no rule uses the list"),
                "steps": [{"title": f"Remove {len(gone)} line{'s' if len(gone) != 1 else ''} from your list \"{name}\"",
                           "msp": {"path": ["Target Lists", name], "fields": [["Remove", f"{len(gone)} line{'s' if len(gone) != 1 else ''}", "\n".join(t for t, _ in gone)]],
                                   "lines": [t for t, _ in gone]},
                           "app": {"note": "Target lists can only be edited on the MSP website."},
                           "note": "Delete each of these lines, then Save & Apply. If you removed the client in Firewalla, also delete its address reservation (if it had one), so the address is free.",
                           "picture": "msp-targetlist-edit.jpg", "undo": f"Add the lines back to \"{name}\": " + "; ".join(t for t, _ in gone)}],
            })
        # 3) A list that more than one group, client or network uses (D-1061).
        owners = howto_list_owners(tid)
        if len(owners) > 1:
            steps, keeper = list_check_split_steps(tid, tl, users, owners)
            others = [o["name"] for o in owners if o is not keeper]
            items.append({
                "id": f"shared:{tid}", "kind": "shared", "list": name, "used_by": used_by,
                "sig": "|".join(sorted(f"{o['kind']}:{o['id']}" for o in owners)),
                "title": f"shared by {len(owners)} groups or clients",
                "facts": [["Used By", used_words],
                          ["Why It Matters", f"A change to it for one changes the other{'s' if len(owners) > 2 else ''} too. A list should have one owner."],
                          ["What To Do", f"{keeper['name']} keeps this list. {', '.join(others)} get{'s' if len(others) == 1 else ''} {'a list' if len(others) == 1 else 'lists'} of "
                                         f"{'its' if len(others) == 1 else 'their'} own: " + (f"{len(steps)} steps, in order, so nothing closes in between." if len(steps) > 1 else "1 step left.")]],
                "text": f"\"{name}\" is used by rules On {len(owners)} groups or clients ({', '.join(o['name'] for o in owners)}): a change to it for one changes "
                        f"the other{'s' if len(owners) > 2 else ''} too. A list should have one owner: {keeper['name']} keeps it, and "
                        f"{', '.join(others)} get{'s' if len(others) == 1 else ''} {'a list' if len(others) == 1 else 'lists'} of {'its' if len(others) == 1 else 'their'} own",
                "steps": steps,
            })
        # 2) Clients a used list leaves out of a group it otherwise holds.
        if not users:
            continue
        covered = {}
        for text, ip, ending in lines:
            s = owner.get(ip)
            if s:
                covered.setdefault(s["mac"], []).append(ending)
        for gid, g in sorted(groups.items(), key=lambda x: str(x[1].get("name") or "")):
            members = [m for m in g.get("members") or [] if m in sides and not access_is_gear(sides[m])]
            inside = [m for m in members if m in covered]
            if len(inside) < 2 or len(inside) * 2 < len(members):
                continue
            ending = Counter(e for m in inside for e in covered[m]).most_common(1)[0][0]
            for m in members:
                if m in covered:
                    continue
                s = sides[m]
                ips, reserved = howto_addresses(s)
                if not ips:
                    continue
                add = [f"{ip}{ending}" for ip in ips]
                steps = []
                if not reserved and s.get("ip"):
                    steps.append(howto_reserve_step(s))
                steps.append({"title": f"Add {howto_id(s)} to your list \"{name}\"",
                              "msp": {"path": ["Target Lists", name], "fields": [["Targets", "add this line" if len(add) == 1 else "add these lines", "\n".join(add)]], "lines": add},
                              "app": {"note": "Target lists can only be edited on the MSP website."},
                              "note": f"Then Save & Apply. {', '.join(used_by)} then {'covers' if len(used_by) == 1 else 'cover'} it as {'it covers' if len(used_by) == 1 else 'they cover'} "
                                      f"the other {len(inside)} client{'s' if len(inside) != 1 else ''} of {g.get('name')} in the list.",
                              "picture": "msp-targetlist-edit.jpg", "undo": f"Remove the line{'s' if len(add) != 1 else ''} again: " + "; ".join(add)})
                items.append({
                    "id": f"miss:{tid}:{m}", "kind": "missing", "list": name, "used_by": used_by, "mac": m, "sig": "",
                    "title": f"{howto_id(s)} isn't in it",
                    "facts": [["Its Group", f"{g.get('name')}: the list holds {len(inside)} of its {count(len(members), 'client')}"], ["Used By", used_words],
                              ["Why It Matters", "It doesn't get what the others in its group get from this list."],
                              ["What To Do", ("Reserve its address, then add" if len(steps) > 1 else "Add") + f" its line to the list, with the same ports as the others ({count(len(steps), 'step')})."]],
                    "text": f"{howto_id(s)} is in {g.get('name')}, but not in your list \"{name}\", which holds {len(inside)} of its "
                            f"{len(members)} clients ({', '.join(used_by)}): it doesn't get what the others get from it",
                    "steps": steps,
                })
    return items


def list_check_run(force=True):
    """Work the findings out and publish them. force False (the every-minute
    look): when nothing changed, only the time of the look moves on, and
    nothing is written."""
    items = list_check_build()
    now = time.time()
    same = lambda xs: [(x["id"], x["sig"], x["text"], [st["title"] for st in x["steps"]]) for x in xs]
    current = state.get("list_check")
    if not force and current and same(current["items"]) == same(items):
        current["at"] = now
        return current
    with list_check_lock:
        st = list_check_load()
        ids = {x["id"] for x in items}
        st["seen"] = {k: v for k, v in st["seen"].items() if k in ids}
        for x in items:
            x["first_seen"] = st["seen"].setdefault(x["id"], now)
            no = st["declined"].get(x["id"])
            x["declined"] = no["at"] if no and no.get("sig") in (None, x["sig"]) else None
        # A decline stays while its list exists, also while the finding is away for a
        # time (a rule paused for a day): declined means not offered again.
        st["declined"] = {k: v for k, v in st["declined"].items() if k.split(":")[1] in msp["lists"]}
        st["at"] = now
        list_check_save(st)
    open_items = [x for x in items if not x["declined"]]
    state["list_check"] = {"at": now, "items": items, "open": len(open_items),
                           "newest_at": max((x["first_seen"] for x in open_items), default=0)}
    return state["list_check"]


def list_check_worker():
    time.sleep(240)   # the router and MSP reads come in first
    while True:
        try:
            list_check_run(force=False)
        except Exception as exc:
            print("List Check error:", exc)
        time.sleep(LIST_CHECK_EVERY)


@app.post("/api/list-check/run")
def api_list_check_run():
    """Check Now: your lists are read from the MSP again first (they are
    otherwise read every 5 minutes), so a change you just made counts."""
    from traffic import msp_lists_now
    return {"ok": True, "lists_error": msp_lists_now(), **list_check_run()}


@app.post("/api/list-check/decline")
def api_list_check_decline(payload: dict = Body(default={})):
    """Decline a finding (owner, 24 Nov 2026, D-1063): it is not offered
    again: it leaves To Do, Needs You and the menu's *, for as long as it
    stays the same finding. offer: true takes the decline back."""
    fields = Fields(payload)
    item = fields.text("id", 300, strip=False)
    with list_check_lock:
        st = list_check_load()
        if payload.get("offer"):
            st["declined"].pop(item, None)
        else:
            found = next((x for x in (state.get("list_check") or {}).get("items") or [] if x["id"] == item), None)
            if not found:
                return {"ok": False, "error": "That finding is no longer listed."}
            st["declined"][item] = {"at": time.time(), "sig": found["sig"]}
        list_check_save(st)
    return {"ok": True, **list_check_run()}


@app.get("/api/quarantine-settings")
def api_quarantine_settings():
    """New Device Quarantine as the router has it (23 Nov 2026, for Add a
    Client): the box's and each network's setting, and the Quarantine
    group (id 1): its switches, members and the rules on it."""
    groups = {str(g.get("id")): g for g in (state.get("groups") or {}).get("groups") or []}
    q = groups.get("1") or {}
    rules = [{"pid": r.get("pid"), "action": r.get("action"), "matching": (r.get("matching") or {}).get("label"), "direction": r.get("direction"),
              "disabled": r.get("disabled")}
             for r in (state.get("policy_rules") or {}).get("rules") or []
             if any((r.get(x) or {}).get("kind") == "group" and str((r.get(x) or {}).get("id")) == "1" for x in ("applies_on", "matching"))]
    return {"box": (feature_settings.get("box") or {}).get("new_device"),
            "networks": {internet_interface_name(n) or n: v.get("new_device") for n, v in (feature_settings.get("networks") or {}).items()},
            "group": {"name": q.get("name"), "vqlan": q.get("vqlan"), "isolation": q.get("isolation"), "members": q.get("members"),
                      "settings": (feature_settings.get("groups") or {}).get("1"), "rules": rules}}


# ============================================================
# TARGET LISTS PAGE (owner, 23 Nov 2026, D-940): every one of your lists and
# every line, spread out: each line's address, protocol, ports, the client
# that has the address (its group, online or not, reserved or not), the rules
# the list feeds, and List Check's findings.
# ============================================================

@app.get("/api/target-lists-page")
def api_target_lists_page():
    sides, groups = access_sides()
    rules = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True]
    owner = {}
    for s in sides.values():
        for ip in howto_addresses(s)[0] + list(s.get("ips") or []):
            owner.setdefault(ip, s)
    shared = {sh: macs for sh, macs in ACCESS_HA_PAIRS}
    findings = {}
    for item in (state.get("list_check") or {}).get("items") or []:
        findings.setdefault(item["list"], []).append({"kind": item["kind"], "text": item["text"], "declined": bool(item.get("declined"))})
    lists, lines = [], []
    lans = list_check_lans()
    for tid, tl in sorted(msp["lists"].items(), key=lambda t: str(t[1].get("name") or "").lower()):
        name = tl.get("name") or tid
        users = [r for r in rules if access_target_list_side(r) and str((r.get(access_target_list_side(r)) or {}).get("id")) == str(tid)]
        used_by = [{"pid": str(r.get("pid")), "action": r.get("action"), "direction": r.get("direction"),
                    "on": (r.get("applies_on") or {}).get("name") or (r.get("applies_on") or {}).get("label") or "",
                    "on_kind": (r.get("applies_on") or {}).get("kind")} for r in users]
        clients, unmatched, count = set(), 0, 0
        for t in tl.get("targets") or []:
            text = str(t).strip()
            if not text:
                continue
            if text.startswith("#"):
                continue
            count += 1
            address, _, rest = text.partition(",")
            host, _, port_only = address.partition(":")   # "x:80" form
            proto, _, ports = rest.partition(":")
            if port_only and not rest:
                ports = port_only
            s = owner.get(host.strip())
            # A website (domain) line, or an address that isn't on your networks, has no client by design.
            try:
                ip = ipaddress.ip_address(host.strip())
                mine = any(ip in n for n in lans)
            except ValueError:
                ip, mine = None, False
            kind = "client" if s else "shared" if host.strip() in shared else "website" if ip is None else "none" if mine else "outside"
            if s:
                clients.add(s["mac"])
            elif kind == "none":
                unmatched += 1
            gid = s["groups"][0] if s and s["groups"] else None
            lines.append({"list": name, "list_id": tid, "line": text, "address": host.strip(),
                          "protocol": (proto.strip() or ("tcp" if port_only else "")).upper() or "Any",
                          "ports": ports.strip() or "every port",
                          "client": s["name"] if s else {"shared": "shared NAS address", "website": "a website", "outside": "not on your networks"}.get(kind),
                          "mac": s["mac"] if s else None, "group": (groups.get(gid) or {}).get("name") if gid else None,
                          "online": s.get("online") if s else None,
                          "reserved": (host.strip() in howto_reserved(s["mac"])) if s else None,
                          "used": bool(users)})
        lists.append({"id": tid, "name": name, "notes": tl.get("notes") or "", "updated": tl.get("last_updated"),
                      "lines": count, "clients": len(clients), "unmatched": unmatched, "used_by": used_by,
                      "findings": findings.get(name) or []})
    return {"lists": lists, "lines": lines, "limit": TARGET_LIST_LIMIT, "read_at": msp.get("at"), "updated_at": time.time()}
