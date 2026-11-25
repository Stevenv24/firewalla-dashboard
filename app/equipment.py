# Access points and switches: their collectors and the year-long equipment
# health record.

import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from collections import Counter
import requests
from fastapi import Body

from core import (
    claude_reply_format,
    APS_URL, CLAUDE_KINDS, FWAPC_BASE_URL, FWAPC_CONFIG_URL, Fields,
    ROUTER_MODEL, STATIONS_URL, SWITCHES_URL, SWITCH_FAST_STALE_SECONDS, app, router_read_hook,
    claude_load, claude_public, log_safe, normalize_identifier, normalize_link_speed, router_macs,
    safe_number, state, switch_port_rate_state,
)


# ============================================================
# AP7C / WI-FI COLLECTOR
# ============================================================


log_repeats = {}   # collector -> [last error text, when it was last printed, times since]


def log_repeat(key, text):
    """A collector's error in the log: printed when it is new, then the same
    error once every 10 minutes with how often it came (owner, 21 Nov 2026:
    a router without the AP and switch controller would otherwise write the
    same line every 2 seconds)."""
    last = log_repeats.get(key)
    now = time.time()
    if last and last[0] == text and now - last[1] < 600:
        last[2] += 1
        return
    repeats = f" (again {last[2]} times in the last 10 minutes)" if last and last[0] == text and last[2] else ""
    print(log_safe(text, 500) + repeats)
    log_repeats[key] = [text, now, 0]


def wifi_status_worker():

    while True:

        try:
            # ------------------------------------------------
            # Retrieve current Wi-Fi station status
            # ------------------------------------------------

            station_response = requests.get(
                STATIONS_URL,
                timeout=15,
                hooks=router_read_hook("fwapc station"),
            )

            station_response.raise_for_status()

            station_data = station_response.json().get("info") or {}

            # ------------------------------------------------
            # Retrieve current AP runtime status
            # ------------------------------------------------

            ap_response = requests.get(
                APS_URL,
                timeout=15,
                hooks=router_read_hook("fwapc ap"),
            )

            ap_response.raise_for_status()

            ap_data = ap_response.json().get("info") or {}

            # ------------------------------------------------
            # Retrieve configured asset metadata
            # ------------------------------------------------

            config_response = requests.get(
                FWAPC_CONFIG_URL,
                timeout=15,
                hooks=router_read_hook("fwapc config"),
            )

            config_response.raise_for_status()

            config_data = config_response.json()

            configured_assets = config_data.get("assets") or {}
            # House-wide Wi-Fi settings (D-996): 5 GHz DFS is on unless
            # Firewalla's autoDisableDfsChannels is true (found 24 Nov 2026).
            global_wifi = config_data.get("globalSysConfig") or {}
            if "autoDisableDfsChannels" in global_wifi:
                state["wifi_settings"] = {"dfs_on": not global_wifi.get("autoDisableDfsChannels"),
                                          "auto_steer": global_wifi.get("autoSteer"), "read_at": time.time()}

            configured_assets_upper = {
                str(asset_uid).upper(): asset
                for asset_uid, asset in configured_assets.items()
            }

            # ------------------------------------------------
            # Retrieve Switch X runtime status
            #
            # AP LLDP records can identify an upstream
            # Switch X by its chassis ID.
            # ------------------------------------------------

            switch_response = requests.get(
                SWITCHES_URL,
                timeout=15,
                hooks=router_read_hook("fwapc switch"),
            )

            switch_response.raise_for_status()

            switch_data = switch_response.json().get("info") or {}

            ap_ids_by_normalized_id = {
                normalize_identifier(asset_uid): asset_uid
                for asset_uid in ap_data.keys()
            }

            switch_ids_by_normalized_id = {
                normalize_identifier(asset_uid): str(asset_uid).upper()
                for asset_uid in switch_data.keys()
            }

            switch_names = {}

            for switch_uid, switch_status in switch_data.items():

                normalized_switch_uid = str(switch_uid).upper()

                configured_switch = configured_assets_upper.get(
                    normalized_switch_uid,
                    {},
                )

                switch_sys_config = configured_switch.get("sysConfig") or {}

                switch_names[normalized_switch_uid] = (
                    switch_sys_config.get("name")
                    or switch_status.get("model")
                    or "Unnamed Switch"
                )

            # ------------------------------------------------
            # Helpers used only inside this worker
            # ------------------------------------------------

            def format_channel_width(value):

                if value is None:
                    return None

                text = str(value).strip().upper()

                if text.startswith("HT"):
                    text = text[2:]

                try:
                    width = int(text)
                    return width

                except ValueError:
                    return value

            def first_list_value(value):

                if isinstance(value, list) and value:
                    return value[0]

                return None

            def mesh_upstream_name(value):

                if value is None:
                    return None

                if isinstance(value, dict):
                    return (
                        value.get("name")
                        or value.get("apName")
                        or value.get("sys_name")
                        or value.get("assetUID")
                        or value.get("mac")
                    )

                return str(value)

            # ------------------------------------------------
            # Normalize AP topology and radio configuration
            # ------------------------------------------------

            access_points = {}

            for asset_uid, ap in ap_data.items():

                normalized_uid = str(asset_uid).upper()

                configured_ap = configured_assets_upper.get(
                    normalized_uid,
                    {},
                )

                sys_config = configured_ap.get("sysConfig") or {}

                channel_config = sys_config.get("channel") or {}

                power_config = sys_config.get("txPower") or {}

                width_config = sys_config.get("htmode") or {}

                ap_name = (
                    ap.get("name")
                    or sys_config.get("name")
                    or ap.get("model")
                    or "Unnamed AP"
                )

                backhaul_state = ap.get("backhaulState") or "Unknown"

                backhaul_type = str(backhaul_state).lower()

                active_uplink = ap.get("activeUplink")

                ethernet_interfaces = ap.get("eths") or {}

                primary_ethernet_name = None
                primary_ethernet = None

                for (
                    interface_name,
                    interface_status,
                ) in ethernet_interfaces.items():

                    if interface_status.get("primary") is True:
                        primary_ethernet_name = interface_name

                        primary_ethernet = interface_status

                        break

                if primary_ethernet is None:

                    for (
                        interface_name,
                        interface_status,
                    ) in ethernet_interfaces.items():

                        if interface_status.get("connected") is True:
                            primary_ethernet_name = interface_name

                            primary_ethernet = interface_status

                            break

                link_speed = None

                if primary_ethernet:
                    link_speed = safe_number(primary_ethernet.get("linkSpeed"))

                # --------------------------------------------
                # Resolve Ethernet uplink using LLDP
                # --------------------------------------------

                uplink_type = None
                uplink_name = None
                uplink_port = None

                lldp_entries = (ap.get("lldp") or {}).get("entries") or []

                active_local_interface = str(active_uplink or "").split(".")[0]

                # --------------------------------------------
                # Identify APs connected through this AP's
                # non-uplink Ethernet interface.
                #
                # Example:
                # Media Room eth1 -> Switch X uplink
                # Media Room eth0 -> downstream AP7 Bedroom
                # --------------------------------------------

                downstream_aps = []

                for lldp_entry in lldp_entries:

                    local_interface = lldp_entry.get("port")

                    # A downstream device must be attached to a
                    # different physical interface from the active
                    # Ethernet uplink.
                    if (
                        not active_local_interface
                        or not local_interface
                        or local_interface == active_local_interface
                    ):
                        continue

                    remote_chassis_id = normalize_identifier(
                        lldp_entry.get("chassis_id")
                    )

                    remote_ap_uid = ap_ids_by_normalized_id.get(remote_chassis_id)

                    if not remote_ap_uid:
                        continue

                    remote_ap = ap_data.get(remote_ap_uid) or {}

                    remote_ap_name = (
                        remote_ap.get("name")
                        or lldp_entry.get("sys_name")
                        or str(remote_ap_uid)
                    )

                    local_interface_status = (
                        ethernet_interfaces.get(local_interface) or {}
                    )

                    downstream_link_speed = safe_number(
                        local_interface_status.get("linkSpeed")
                    )

                    downstream_aps.append(
                        {
                            "asset_id": str(remote_ap_uid).upper(),
                            "name": remote_ap_name,
                            "local_interface": (local_interface),
                            "remote_interface": (lldp_entry.get("remote_id")),
                            "link_speed": (downstream_link_speed),
                            "link_speed_source": ("fwapc"),
                            "link_state": (local_interface_status.get("linkState")),
                            "connected": (
                                local_interface_status.get("connected") is True
                            ),
                        }
                    )

                matching_lldp_entries = [
                    entry
                    for entry in lldp_entries
                    if (
                        not active_local_interface
                        or entry.get("port") == active_local_interface
                    )
                ]

                if not matching_lldp_entries:
                    matching_lldp_entries = lldp_entries

                # A switch heard on the uplink port wins over an AP heard
                # there too: on a shared segment (a powerline network or an
                # unmanaged switch) the AP hears both, in no fixed order
                # (19 Nov 2026: AP7 Sm Garage flipped between Switch X #3
                # and Lg Garage).
                for entry in sorted(matching_lldp_entries,
                                    key=lambda e: normalize_identifier(e.get("chassis_id")) not in switch_ids_by_normalized_id):

                    chassis_id = normalize_identifier(entry.get("chassis_id"))

                    matching_switch_uid = switch_ids_by_normalized_id.get(chassis_id)

                    if matching_switch_uid:

                        uplink_type = "switch"

                        uplink_name = (
                            switch_names.get(matching_switch_uid) or "Unnamed Switch"
                        )

                        uplink_port = entry.get("remote_id")

                        break

                    remote_description = str(entry.get("sys_description") or "").lower()

                    remote_name = entry.get("sys_name")

                    if remote_name and (
                        "firewalla ap" in remote_description
                        or str(entry.get("remote_type")).lower() == "mac"
                    ):

                        uplink_type = "ap"
                        uplink_name = remote_name
                        uplink_port = None

                        break

                # --------------------------------------------
                # Normalize mesh upstream telemetry
                #
                # These arrays are empty for the current
                # Ethernet-backhauled APs. The first array
                # entry is retained if an AP later uses mesh.
                # --------------------------------------------

                upstream_ap_value = first_list_value(ap.get("upstreamAPs"))

                mesh_upstream_ap = mesh_upstream_name(upstream_ap_value)

                mesh_rssi = safe_number(first_list_value(ap.get("upstreamRSSIs")))

                mesh_rx_rate = safe_number(first_list_value(ap.get("upstreamRxRates")))

                mesh_tx_rate = safe_number(first_list_value(ap.get("upstreamTxRates")))

                if backhaul_type != "ethernet" and mesh_upstream_ap:
                    uplink_type = "ap"
                    uplink_name = mesh_upstream_ap
                    uplink_port = None

                # --------------------------------------------
                # Derive actual operating radio values
                #
                # The AP runtime "aps" structure contains
                # interfaces for normal SSIDs and mesh.
                # Prefer a non-mesh AP-mode interface for each
                # band so the card reports the client-serving
                # radio rather than a mesh backhaul interface.
                # --------------------------------------------

                runtime_radios = {}

                for radio_status in (ap.get("aps") or {}).values():

                    if not isinstance(
                        radio_status,
                        dict,
                    ):
                        continue

                    band = radio_status.get("band")

                    if band not in (
                        "2g",
                        "5g",
                        "6g",
                    ):
                        continue

                    is_client_radio = (
                        radio_status.get("mode") == "ap"
                        and radio_status.get("mesh") is not True
                    )

                    existing_radio = runtime_radios.get(band)

                    if existing_radio is None or is_client_radio:
                        runtime_radios[band] = {
                            "channel": safe_number(radio_status.get("channel")),
                            "width_mhz": safe_number(radio_status.get("width")),
                            "tx_power": safe_number(radio_status.get("txPower")),
                            "interface": (radio_status.get("intf")),
                            "mesh": (radio_status.get("mesh")),
                        }

                    if is_client_radio:
                        runtime_radios[band]["_preferred"] = True

                # --------------------------------------------
                # Per-band configured radio settings
                # --------------------------------------------

                radio_settings = {
                    "2g": {
                        "label": "2.4 GHz",
                        "channel": (
                            runtime_radios.get("2g", {}).get("channel")
                            or safe_number(channel_config.get("2g"))
                        ),
                        "width_mhz": (
                            runtime_radios.get("2g", {}).get("width_mhz")
                            or format_channel_width(width_config.get("2g"))
                        ),
                        "tx_power": (
                            runtime_radios.get("2g", {}).get("tx_power")
                            or safe_number(power_config.get("2g"))
                        ),
                    },
                    "5g": {
                        "label": "5 GHz",
                        "channel": (
                            runtime_radios.get("5g", {}).get("channel")
                            or safe_number(channel_config.get("5g"))
                        ),
                        "width_mhz": (
                            runtime_radios.get("5g", {}).get("width_mhz")
                            or format_channel_width(width_config.get("5g"))
                        ),
                        "tx_power": (
                            runtime_radios.get("5g", {}).get("tx_power")
                            or safe_number(power_config.get("5g"))
                        ),
                    },
                    "6g": {
                        "label": "6 GHz",
                        "channel": (
                            runtime_radios.get("6g", {}).get("channel")
                            or safe_number(channel_config.get("6g"))
                        ),
                        "width_mhz": (
                            runtime_radios.get("6g", {}).get("width_mhz")
                            or format_channel_width(width_config.get("6g"))
                        ),
                        "tx_power": (
                            runtime_radios.get("6g", {}).get("tx_power")
                            or safe_number(power_config.get("6g"))
                        ),
                    },
                }

                # --------------------------------------------
                # Save normalized AP record
                # --------------------------------------------

                access_points[normalized_uid] = {
                    "name": ap_name,
                    "model": ap.get("model"),
                    "healthy": ap.get("healthy"),
                    "checked_in": ap.get("checkedIn"),
                    "backhaul_type": (backhaul_type),
                    "backhaul_state": (backhaul_state),
                    "active_uplink": (active_uplink),
                    "primary_interface": (primary_ethernet_name),
                    "link_speed": link_speed,
                    "uplink_type": uplink_type,
                    "uplink_name": uplink_name,
                    "uplink_port": uplink_port,
                    "downstream_aps": (downstream_aps),
                    "mesh_upstream_ap": (mesh_upstream_ap),
                    "mesh_band": None,
                    "mesh_channel": None,
                    "mesh_rssi": mesh_rssi,
                    "mesh_rx_rate": (mesh_rx_rate),
                    "mesh_tx_rate": (mesh_tx_rate),
                    "radio_settings": (radio_settings),
                    # What the Firewalla app has set for each band (owner, 23 Nov
                    # 2026: the app showed Lg Garage on 37 while it broadcast on
                    # 165): channel, power and width as configured, unchanged
                    # (automatic shows as the router sends it).
                    # Backhaul Mode (D-996, the owner's flip test on AP7
                    # Office 24 Nov 2026): meshMode "auto" = Automatic,
                    # "legacy_controller" = Wired Only.
                    "backhaul_mode": {"auto": "automatic", "legacy_controller": "wired_only"}.get(sys_config.get("meshMode"), sys_config.get("meshMode")),
                    "radio_config": {b: {"channel": channel_config.get(b), "power": power_config.get(b), "width": width_config.get(b)}
                                     for b in ("2g", "5g", "6g")},
                    # How busy each band's channel is, % (D-989): the Wi-Fi
                    # Radios page's radio table.
                    "channel_use": ap_air_busy(ap),
                    # The radios the AP itself reports now (radio_settings falls
                    # back to the configured values, so it can't show one off).
                    "radios_live": {band: {k: r.get(k) for k in ("channel", "width_mhz", "tx_power")}
                                    for band, r in runtime_radios.items() if not r.get("mesh") and r.get("channel")},
                    # Each Ethernet port's cable (connected, speed): the
                    # second port says whether another AP can hang off it.
                    "eth_ports": {name: {"connected": e.get("connected") is True, "speed": safe_number(e.get("linkSpeed"))}
                                  for name, e in ethernet_interfaces.items() if isinstance(e, dict)},
                }

            # ------------------------------------------------
            # AP behind AP only when the cable is real (owner, 19 Nov 2026):
            # an AP named as upstream must have a live cable on a port other
            # than its own uplink (Media Room eth0 -> Bedroom). Without one (Sm
            # Garage "on" Lg Garage, whose eth0 is unplugged: each is on its
            # own powerline adapter to Switch X #3) the two share the other's
            # switch port instead, and the map draws a shared link. The name
            # Firewalla gave stays in uplink_claimed.
            # ------------------------------------------------

            by_name = {}
            for uid, rec in access_points.items():
                by_name[rec["name"]] = uid
                by_name.setdefault(str(rec["name"]).split(" ", 1)[-1], uid)   # LLDP names drop the "AP7 " prefix
            for uid, rec in access_points.items():
                if rec.get("uplink_type") != "ap" or rec.get("backhaul_type") != "ethernet":
                    continue
                parent = access_points.get(by_name.get(rec.get("uplink_name")) or "")
                if parent and not ap_has_second_cable(parent) and parent.get("uplink_type") == "switch":
                    rec.update(uplink_claimed=rec["uplink_name"], uplink_type="switch",
                               uplink_name=parent.get("uplink_name"), uplink_port=parent.get("uplink_port"))

            # ------------------------------------------------
            # Normalize connected Wi-Fi stations
            # ------------------------------------------------

            wifi_stations = {}

            for mac, station in station_data.items():

                normalized_mac = str(mac).upper()

                asset_uid = station.get("assetUID")

                if asset_uid:
                    asset_uid = str(asset_uid).upper()

                ap_info = (
                    access_points.get(
                        asset_uid,
                        {},
                    )
                    if asset_uid
                    else {}
                )

                wifi_stations[normalized_mac] = {
                    "connection_type": "wifi",
                    "ap_id": asset_uid,
                    "ap_name": ap_info.get("name"),
                    "ssid": station.get("ssid"),
                    "band": station.get("band"),
                    "channel": safe_number(station.get("channel")),
                    "rssi": safe_number(station.get("rssi")),
                    "snr": safe_number(station.get("snr")),
                    "phy_mode": station.get("phymode"),
                    # Current station rates are reported by FWAPC in
                    # bits/second. Publish Mbps consistently so frontend
                    # consumers never have to reinterpret the raw unit.
                    "current_rx_rate": round(
                        float(
                            safe_number(
                                station.get("curRxRate")
                            )
                            or 0
                        )
                        / 1_000_000,
                        3,
                    ),
                    "current_tx_rate": round(
                        float(
                            safe_number(
                                station.get("curTxRate")
                            )
                            or 0
                        )
                        / 1_000_000,
                        3,
                    ),
                    # FWAPC/AP perspective: curRxRate is received by the AP
                    # from the station (device TX); curTxRate is sent by the
                    # AP to the station (device RX). Raw values are bits/second.
                    "traffic_rx_mbps": round(float(safe_number(station.get("curTxRate")) or 0) / 1_000_000, 3),
                    "traffic_tx_mbps": round(float(safe_number(station.get("curRxRate")) or 0) / 1_000_000, 3),
                    "rx_rate": safe_number(station.get("rxRate")),
                    "tx_rate": safe_number(station.get("txRate")),
                    "rx_nss": safe_number(station.get("rxnss")),
                    "tx_nss": safe_number(station.get("txnss")),
                    "state": station.get("state"),
                    "updated_at": station.get("ts"),
                }

            # ------------------------------------------------
            # Publish the completed snapshot
            # ------------------------------------------------

            state["wifi_stations"] = wifi_stations
            try:
                wifi_roams_note(wifi_stations, time.time())
            except Exception as exc:
                print("Wi-Fi roam learning error:", exc)
            try:
                wifi_signal_note(wifi_stations, time.time())
            except Exception as exc:
                print("Wi-Fi signal learning error:", exc)
            try:
                client_homes_note(wifi_stations, time.time())
            except Exception as exc:
                print("Client homes error:", exc)

            # Equipment Health logs every label change; a unit shows red
            # only after 60 s bad (health_shown).
            equipment_health_observe(ap_data, switch_data, access_points, configured_assets_upper)
            for asset_uid, record in access_points.items():
                record["health_shown"] = equipment_health_shown(asset_uid)
                record["health_verdict"] = equipment_health_verdict(asset_uid)

            state["access_points"] = access_points

            state["wifi_last_update"] = time.time()

        except Exception as exc:

            log_repeat("wifi", f"Wi-Fi status refresh error: {exc}")
            equipment_health_no_controller()

        # AP7 station traffic is used as the primary source for Wi-Fi
        # client RX/TX. Poll frequently enough for the dashboard to feel live.
        time.sleep(2)


# ============================================================
# SWITCH X COLLECTOR
# ============================================================


switch_live_lock = threading.Lock()


def switch_live_publish(uid, entry):
    """One switch's live rates go out as a new copy of the whole list. The
    list in state is never changed in place (20 Nov 2026), so a page answer
    being written out while a stream reports isn't disturbed."""
    with switch_live_lock:
        state["switch_live_rates"] = {**state["switch_live_rates"], uid: entry}


def switch_fast_metrics_worker(switch_uid):
    """Consume FWAPC fast NDJSON metrics for one Switch X."""
    url = f"{FWAPC_BASE_URL}/switch/metrics/{switch_uid}"
    previous = {}
    uid = str(switch_uid).upper()
    reconnects = 0
    while True:
        try:
            switch_live_publish(uid, {
                **(state["switch_live_rates"].get(uid) or {}),
                "connected": False,
                "stale": True,
                "status": "connecting",
                "reconnects": reconnects,
            })
            with requests.get(
                url,
                params={"mode": "fast", "timeout_secs": 60},
                headers={"Accept": "application/x-ndjson"},
                stream=True,
                timeout=(10, 75),
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    try:
                        sample = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts_ms = safe_number(sample.get("ts"))
                    if ts_ms is None:
                        continue
                    live_ports = {}
                    for port in sample.get("port_statistics") or []:
                        port_key = str(port.get("port"))
                        if not port_key or port_key == "None":
                            continue
                        tx_bytes = safe_number(port.get("txBytes"))
                        rx_bytes = safe_number(port.get("rxBytes"))
                        prev = previous.get(port_key)
                        device_rx = 0.0
                        device_tx = 0.0
                        if prev:
                            elapsed = (float(ts_ms) - float(prev["ts_ms"])) / 1000.0
                            if elapsed > 0:
                                if tx_bytes is not None and prev["tx_bytes"] is not None and tx_bytes >= prev["tx_bytes"]:
                                    device_rx = round(((tx_bytes - prev["tx_bytes"]) * 8) / elapsed / 1_000_000, 3)
                                if rx_bytes is not None and prev["rx_bytes"] is not None and rx_bytes >= prev["rx_bytes"]:
                                    device_tx = round(((rx_bytes - prev["rx_bytes"]) * 8) / elapsed / 1_000_000, 3)
                        previous[port_key] = {"ts_ms": ts_ms, "tx_bytes": tx_bytes, "rx_bytes": rx_bytes}
                        live_ports[port_key] = {
                            "rx_mbps": device_rx,
                            "tx_mbps": device_tx,
                            "updated_at": time.time(),
                            "source_ts_ms": ts_ms,
                        }
                    switch_live_publish(uid, {
                        "ports": live_ports,
                        "updated_at": time.time(),
                        "source_ts_ms": ts_ms,
                        "connected": True,
                        "stale": False,
                        "status": "live",
                        "reconnects": reconnects,
                        "error": None,
                    })
        except Exception as exc:
            reconnects += 1
            switch_live_publish(uid, {
                **(state["switch_live_rates"].get(uid) or {}),
                "connected": False,
                "stale": True,
                "status": "reconnecting",
                "error": str(exc),
                "reconnects": reconnects,
            })
            time.sleep(2)


switch_fast_workers = {}   # switch id -> its stream's thread (kept here, so the manager started again finds them)


def switch_fast_metrics_manager():
    """Start one fast metrics stream per discovered Switch X."""
    workers = switch_fast_workers
    while True:
        switch_ids = set((state.get("switches") or {}).keys())
        for uid in switch_ids:
            if uid in workers and workers[uid].is_alive():
                continue
            thread = threading.Thread(
                target=switch_fast_metrics_worker,
                args=(uid,),
                daemon=True,
                name=f"switch-fast-{uid}",
            )
            workers[uid] = thread
            thread.start()
        time.sleep(5)


def switch_status_worker():

    while True:

        try:
            # ------------------------------------------------
            # Retrieve current Switch X runtime status.
            # ------------------------------------------------

            switch_response = requests.get(
                SWITCHES_URL,
                timeout=15,
                hooks=router_read_hook("fwapc switch"),
            )

            switch_response.raise_for_status()

            switch_data = switch_response.json().get("info") or {}

            # ------------------------------------------------
            # Retrieve configured asset names.
            # ------------------------------------------------

            config_response = requests.get(
                FWAPC_CONFIG_URL,
                timeout=15,
                hooks=router_read_hook("fwapc config"),
            )

            config_response.raise_for_status()

            config_data = config_response.json() or {}

            configured_assets = config_data.get("assets") or {}

            configured_assets_upper = {
                str(asset_uid).upper(): asset
                for asset_uid, asset in configured_assets.items()
            }

            known_asset_ids = {
                normalize_identifier(asset_uid)
                for asset_uid in configured_assets.keys()
            }

            # ------------------------------------------------
            # Build a friendly-name lookup from the main
            # Firewalla device inventory.
            # ------------------------------------------------

            device_names_by_mac = {}

            device_records = state.get("devices") or []

            if isinstance(
                device_records,
                dict,
            ):
                device_records = device_records.values()

            for device in device_records:

                if not isinstance(
                    device,
                    dict,
                ):
                    continue

                device_mac = device.get("mac")

                if not device_mac:
                    continue

                normalized_device_mac = str(device_mac).upper()

                device_name = (
                    device.get("name")
                    or device.get("hostname")
                    or device.get("vendor")
                    or normalized_device_mac
                )

                device_names_by_mac[normalized_device_mac] = device_name

            # ------------------------------------------------
            # Build switch records and collect possible
            # wired-client locations.
            # ------------------------------------------------

            sample_time = time.time()

            switches = {}
            wired_candidates = {}

            for asset_uid, switch in switch_data.items():

                normalized_uid = str(asset_uid).upper()

                configured_asset = configured_assets_upper.get(
                    normalized_uid,
                    {},
                )

                sys_config = configured_asset.get("sysConfig") or {}

                switch_sys_config = configured_asset.get("switchSysConfig") or {}

                configured_port_settings = switch_sys_config.get("portSettings") or {}

                switch_name = (
                    sys_config.get("name")
                    or switch.get("name")
                    or switch.get("model")
                    or "Unnamed Switch"
                )

                # --------------------------------------------
                # Switch-level PoE telemetry.
                #
                # budgetUtil is already expressed in watts.
                #
                # powerDraw and per-port poePower are
                # expressed in tenths of a watt.
                # --------------------------------------------

                system_status = switch.get("systemStatus") or {}

                poe_budget_raw = safe_number(system_status.get("budgetUtil"))

                poe_draw_raw = safe_number(system_status.get("powerDraw"))

                poe_budget_watts = (
                    float(poe_budget_raw) if poe_budget_raw is not None else None
                )

                poe_used_watts = (
                    round(
                        float(poe_draw_raw) / 10,
                        1,
                    )
                    if poe_draw_raw is not None
                    else 0.0
                )

                if poe_budget_watts and poe_budget_watts > 0:
                    poe_percent = round(
                        (poe_used_watts / poe_budget_watts) * 100,
                        1,
                    )
                else:
                    poe_percent = 0.0

                # --------------------------------------------
                # Normalize all 12 Switch X ports.
                #
                # Ports 1-8 are copper PoE++ ports.
                # Ports 9-12 are SFP+ ports.
                # --------------------------------------------

                ports = switch.get("ports") or []

                port_map = {}

                for port in ports:

                    port_id = port.get("port")

                    if port_id is None:
                        continue

                    port_key = str(port_id)

                    tx_bytes = safe_number(port.get("txBytes"))

                    rx_bytes = safe_number(port.get("rxBytes"))

                    rate_key = (
                        normalized_uid,
                        port_key,
                    )

                    previous_sample = switch_port_rate_state.get(rate_key)

                    # Use the source status timestamp when available.
                    # Repeated local polls can return the same FWAPC sample.
                    source_sample_time = safe_number(switch.get("ts"))

                    if source_sample_time is None:
                        source_sample_time = sample_time

                    # Preserve the last calculated rates while FWAPC is
                    # returning the same cumulative counter sample.
                    rx_mbps = (
                        previous_sample.get(
                            "rx_mbps",
                            0.0,
                        )
                        if previous_sample
                        else 0.0
                    )

                    tx_mbps = (
                        previous_sample.get(
                            "tx_mbps",
                            0.0,
                        )
                        if previous_sample
                        else 0.0
                    )

                    if previous_sample:

                        previous_time = previous_sample.get("source_time")

                        previous_rx = previous_sample.get("rx_bytes")

                        previous_tx = previous_sample.get("tx_bytes")

                        counters_changed = (
                            rx_bytes != previous_rx or tx_bytes != previous_tx
                        )

                        source_time_changed = (
                            previous_time is None or source_sample_time != previous_time
                        )

                        # Calculate a new rate only when FWAPC actually
                        # delivers a new counter sample.
                        if counters_changed and source_time_changed:

                            elapsed = source_sample_time - previous_time

                            if elapsed > 0:

                                # rx_mbps / tx_mbps are the DEVICE's download
                                # and upload, as the fast stream publishes
                                # them: what the port sends (txBytes) the
                                # device receives (24 Nov 2026: here they
                                # were the port's own, so a port's Download
                                # and Upload swapped whenever the fast
                                # stream paused and this took over).
                                if (
                                    tx_bytes is not None
                                    and previous_tx is not None
                                    and tx_bytes >= previous_tx
                                ):
                                    rx_mbps = round(
                                        ((tx_bytes - previous_tx) * 8)
                                        / elapsed
                                        / 1_000_000,
                                        2,
                                    )

                                else:
                                    rx_mbps = 0.0

                                if (
                                    rx_bytes is not None
                                    and previous_rx is not None
                                    and rx_bytes >= previous_rx
                                ):
                                    tx_mbps = round(
                                        ((rx_bytes - previous_rx) * 8)
                                        / elapsed
                                        / 1_000_000,
                                        2,
                                    )

                                else:
                                    tx_mbps = 0.0

                            switch_port_rate_state[rate_key] = {
                                "source_time": (source_sample_time),
                                "rx_bytes": rx_bytes,
                                "tx_bytes": tx_bytes,
                                "rx_mbps": rx_mbps,
                                "tx_mbps": tx_mbps,
                            }

                    else:

                        # The first sample establishes the baseline.
                        # A rate requires at least two source samples.
                        switch_port_rate_state[rate_key] = {
                            "source_time": (source_sample_time),
                            "rx_bytes": rx_bytes,
                            "tx_bytes": tx_bytes,
                            "rx_mbps": 0.0,
                            "tx_mbps": 0.0,
                        }

                    fast_switch = (state.get("switch_live_rates") or {}).get(normalized_uid) or {}
                    fast_port_rate = (fast_switch.get("ports") or {}).get(port_key) or {}
                    fast_updated = safe_number(fast_port_rate.get("updated_at"))
                    fast_age = (
                        max(0.0, time.time() - float(fast_updated))
                        if fast_updated is not None
                        else None
                    )
                    fast_fresh = (
                        fast_switch.get("connected") is True
                        and fast_age is not None
                        and fast_age <= SWITCH_FAST_STALE_SECONDS
                    )
                    rate_source = "switch_status"
                    if fast_fresh:
                        rx_mbps = float(fast_port_rate.get("rx_mbps") or 0)
                        tx_mbps = float(fast_port_rate.get("tx_mbps") or 0)
                        rate_source = "switch_fast_metrics"
                    port_config = configured_port_settings.get(port_key) or {}

                    has_vlan_override = any(
                        key in port_config
                        for key in (
                            "tagged",
                            "untagged",
                            "pvid",
                        )
                    )

                    tagged_vlans = list(port_config.get("tagged") or [])

                    untagged_vlans = list(port_config.get("untagged") or [])

                    pvid = safe_number(port_config.get("pvid"))

                    if not has_vlan_override:

                        switchport_mode = "trunk_default"

                    elif (
                        len(tagged_vlans) == 0
                        and len(untagged_vlans) == 1
                        and pvid == safe_number(untagged_vlans[0])
                    ):

                        switchport_mode = "access"

                    else:

                        switchport_mode = "trunk"

                    try:

                        port_number = int(port_id)

                    except (
                        TypeError,
                        ValueError,
                    ):

                        port_number = None

                    if port_number is not None and 1 <= port_number <= 8:

                        port_type = "copper"
                        poe_capable = True

                    elif port_number is not None and 9 <= port_number <= 12:

                        port_type = "sfp+"
                        poe_capable = False

                    else:

                        port_type = "unknown"
                        poe_capable = False

                    poe_power_raw = safe_number(port.get("poePower"))

                    poe_power_watts = (
                        round(
                            float(poe_power_raw) / 10,
                            1,
                        )
                        if poe_power_raw is not None
                        else 0.0
                    )

                    port_map[port_key] = {
                        "port": port_id,
                        "port_type": port_type,
                        "switchport_mode": (switchport_mode),
                        "pvid": pvid,
                        "tagged_vlans": (tagged_vlans),
                        "untagged_vlans": (untagged_vlans),
                        "vlan_config_inherited": (not has_vlan_override),
                        "poe_capable": (poe_capable),
                        "link_up": port.get("linkUp"),
                        "link_speed": (normalize_link_speed(port.get("linkSpeed"))),
                        "rx_mbps": rx_mbps,
                        "tx_mbps": tx_mbps,
                        "rate_source": rate_source,
                        "fast_sample_age_seconds": (round(fast_age, 2) if fast_age is not None else None),
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "poe_enabled": (port.get("poe") is True),
                        "poe_status": port.get("poeStatus"),
                        "poe_mode": port.get("poeMode"),
                        "poe_power_watts": (poe_power_watts),
                        "stp_role": ((port.get("stp") or {}).get("portRole")),
                        "stp_state": ((port.get("stp") or {}).get("portState")),
                        "direct_client_count": 0,
                        "connection_type": None,
                        "connected_names": [],
                        "connected_macs": [],
                        "downstream_infrastructure": [],
                        "friendly_name": None,
                    }
                # --------------------------------------------
                # Identify switch/AP infrastructure ports.
                #
                # Devices learned behind these ports should
                # not be reported as direct connections to
                # this switch.
                # --------------------------------------------

                infrastructure_ports = set()


                # Normalize the Gold Pro multiple MAC addresses into one physical infrastructure connection.

                gateway_macs = router_macs()

                learned_macs_by_port = {}

                for learned in switch.get("mac_addresses") or []:

                    learned_port = learned.get("portId")

                    learned_mac = str(learned.get("mac") or "").upper()

                    if learned_port is None or not learned_mac:

                        continue

                    learned_macs_by_port.setdefault(str(learned_port), set()).add(learned_mac)


                gold_pro_ports = {

                    port_key

                    for port_key, learned_macs in learned_macs_by_port.items()

                    if learned_macs.intersection(gateway_macs)

                }

                infrastructure_ports.update(gold_pro_ports)


                for gold_port_key in gold_pro_ports:

                    port_record = port_map.get(gold_port_key)

                    if not port_record:

                        continue

                    port_record["connection_type"] = "infrastructure"

                    port_record["friendly_name"] = ROUTER_MODEL

                    port_record["connected_names"] = [ROUTER_MODEL]

                    port_record["connected_macs"] = sorted(learned_macs_by_port.get(gold_port_key) or [])

                    port_record["direct_client_count"] = 0
                for neighbor in switch.get("lldps") or []:

                    chassis_id = normalize_identifier(neighbor.get("chassis_id"))

                    lldp_port = neighbor.get("port")

                    if chassis_id in known_asset_ids and lldp_port is not None:

                        port_key = str(lldp_port)

                        infrastructure_ports.add(port_key)

                        # ----------------------------------------
                        # Resolve the neighbor's configured name.
                        # ----------------------------------------

                        neighbor_asset = None

                        for (
                            configured_uid,
                            configured_value,
                        ) in configured_assets.items():

                            if normalize_identifier(configured_uid) == chassis_id:
                                neighbor_asset = configured_value
                                break

                        neighbor_sys_config = (neighbor_asset or {}).get(
                            "sysConfig"
                        ) or {}

                        # ----------------------------------------
                        # Resolve the best friendly infrastructure
                        # name.
                        #
                        # Prefer our normalized AP runtime name,
                        # then the configured asset name, and use
                        # raw LLDP names only as fallbacks.
                        # ----------------------------------------

                        neighbor_name = None

                        access_points = state.get("access_points") or {}

                        for (
                            ap_uid,
                            ap_record,
                        ) in access_points.items():

                            if normalize_identifier(ap_uid) == chassis_id:
                                neighbor_name = ap_record.get("name")
                                break

                        if not neighbor_name:

                            neighbor_name = (
                                neighbor_sys_config.get("name")
                                or neighbor.get("sys_name")
                                or neighbor.get("sys_description")
                                or neighbor.get("chassis_id")
                            )

                        port_record = port_map.get(port_key)

                        if port_record:

                            port_record["connection_type"] = "infrastructure"

                            port_record["friendly_name"] = neighbor_name

                            if (
                                neighbor_name
                                and neighbor_name not in port_record["connected_names"]
                            ):
                                port_record["connected_names"].append(neighbor_name)

                            chassis_value = neighbor.get("chassis_id")

                            if (
                                chassis_value
                                and chassis_value not in port_record["connected_macs"]
                            ):
                                port_record["connected_macs"].append(chassis_value)

                switches[normalized_uid] = {
                    "name": switch_name,
                    "model": switch.get("model"),
                    "healthy": switch.get("healthy"),
                    "ports": port_map,
                    "infrastructure_ports": (sorted(infrastructure_ports)),
                    "direct_client_count": 0,
                    "poe_used_watts": (poe_used_watts),
                    "poe_budget_watts": (poe_budget_watts),
                    "poe_percent": (poe_percent),
                    "temperature": safe_number(system_status.get("temperature")),
                    "fan_status": (system_status.get("fanStatus")),
                    "fan_speed_percent": (
                        safe_number(system_status.get("fanSpeedPercentage"))
                    ),
                }

                # --------------------------------------------
                # Collect possible direct wired-client
                # locations from the switch MAC table.
                # --------------------------------------------

                learned_macs = switch.get("mac_addresses") or []

                for learned in learned_macs:

                    mac = learned.get("mac")

                    port_id = learned.get("portId")

                    if not mac or port_id is None:
                        continue

                    port_key = str(port_id)

                    if port_key in infrastructure_ports:
                        continue

                    normalized_mac = str(mac).upper()

                    port_info = port_map.get(port_key) or {}

                    candidate = {
                        "connection_type": ("wired"),
                        "switch_id": (normalized_uid),
                        "switch_name": (switch_name),
                        "port": port_id,
                        "link_up": (port_info.get("link_up")),
                        "link_speed": (port_info.get("link_speed")),
                        "vlan_id": (learned.get("vlanId")),
                    }

                    wired_candidates.setdefault(
                        normalized_mac,
                        [],
                    ).append(candidate)

            # ------------------------------------------------
            # Enrich switch ports using normalized AP topology.
            #
            # Multiple APs may reside behind the same physical
            # switch port, such as APs reached through a
            # transparent powerline Ethernet segment.
            # ------------------------------------------------

            access_points = state.get("access_points") or {}

            for ap_record in access_points.values():

                if not isinstance(
                    ap_record,
                    dict,
                ):
                    continue

                if ap_record.get("uplink_type") != "switch":
                    continue

                ap_name = ap_record.get("name")

                uplink_switch_name = ap_record.get("uplink_name")

                uplink_port = ap_record.get("uplink_port")

                if not ap_name or not uplink_switch_name or not uplink_port:
                    continue

                # Convert Firewalla's LLDP port notation,
                # such as Gi0/5, to our normalized port key 5.
                uplink_port_text = str(uplink_port)

                if "/" in uplink_port_text:
                    port_key = uplink_port_text.rsplit("/", 1)[-1]
                else:
                    port_key = uplink_port_text

                # Locate the normalized Switch X record by
                # its friendly/configured name.
                target_switch = next(
                    (
                        switch_record
                        for switch_record in switches.values()
                        if switch_record.get("name") == uplink_switch_name
                    ),
                    None,
                )

                if not target_switch:
                    continue

                port_record = target_switch.get("ports", {}).get(port_key)

                if not port_record:
                    continue

                downstream_infrastructure = port_record.setdefault(
                    "downstream_infrastructure",
                    [],
                )

                for downstream_ap in ap_record.get("downstream_aps") or []:

                    downstream_name = downstream_ap.get("name")

                    if not downstream_name:
                        continue

                    downstream_entry = {
                        "name": downstream_name,
                        "via": ap_name,
                        "via_interface": (downstream_ap.get("local_interface")),
                        "remote_interface": (downstream_ap.get("remote_interface")),
                        "link_speed": (downstream_ap.get("link_speed")),
                        "link_speed_source": (downstream_ap.get("link_speed_source")),
                        "link_state": (downstream_ap.get("link_state")),
                        "connected": (downstream_ap.get("connected")),
                    }

                    if not any(
                        existing.get("name") == downstream_name
                        for existing in downstream_infrastructure
                    ):
                        downstream_infrastructure.append(downstream_entry)

                port_record["connection_type"] = "infrastructure"

                connected_names = port_record.setdefault(
                    "connected_names",
                    [],
                )

                if ap_name not in connected_names:
                    connected_names.append(ap_name)

                # One infrastructure device can use its
                # friendly name directly. If more than one
                # device exists behind the port, preserve the
                # full list and use a concise summary.
                if len(connected_names) == 1:

                    port_record["friendly_name"] = connected_names[0]

                else:

                    port_record["friendly_name"] = (
                        str(len(connected_names)) + " infrastructure devices"
                    )

            # ------------------------------------------------
            # Resolve direct wired-client locations.
            #
            # A client is accepted only when its learned MAC
            # resolves to exactly one unique switch/port.
            # ------------------------------------------------

            wired_clients = {}
            ambiguous_wired_clients = {}

            for mac, candidates in wired_candidates.items():

                unique_locations = {}

                for candidate in candidates:

                    location_key = (
                        candidate["switch_id"],
                        str(candidate["port"]),
                    )

                    if location_key not in unique_locations:
                        unique_locations[location_key] = candidate

                resolved_candidates = list(unique_locations.values())

                if len(resolved_candidates) == 1:

                    resolved = resolved_candidates[0]

                    wired_clients[mac] = resolved

                    switch_id = resolved.get("switch_id")

                    port_key = str(resolved.get("port"))

                    switch_record = switches.get(switch_id)

                    if switch_record:

                        switch_record["direct_client_count"] += 1

                        port_record = switch_record.get(
                            "ports",
                            {},
                        ).get(port_key)

                        if port_record:

                            port_record["direct_client_count"] += 1

                            port_record["connection_type"] = "client"

                            friendly_name = device_names_by_mac.get(mac) or mac

                            if friendly_name not in port_record["connected_names"]:
                                port_record["connected_names"].append(friendly_name)

                            if mac not in port_record["connected_macs"]:
                                port_record["connected_macs"].append(mac)

                            if port_record["direct_client_count"] == 1:
                                port_record["friendly_name"] = friendly_name

                            else:
                                port_record["friendly_name"] = (
                                    str(port_record["direct_client_count"]) + " clients"
                                )

                elif len(resolved_candidates) > 1:

                    ambiguous_wired_clients[mac] = {
                        "candidate_count": len(resolved_candidates)
                    }

            # ------------------------------------------------
            # Publish completed switch snapshot.
            # ------------------------------------------------

            for asset_uid, record in switches.items():
                record["health_shown"] = equipment_health_shown(asset_uid)
                record["health_verdict"] = equipment_health_verdict(asset_uid)

            state["switches"] = switches

            state["wired_clients"] = wired_clients

            state["ambiguous_wired_clients"] = ambiguous_wired_clients

            state["switch_last_update"] = time.time()

        except Exception as exc:

            log_repeat("switch", f"Switch status refresh error: {exc}")

        time.sleep(5)

# ============================================================
# SWITCH FAST METRICS WATCHDOG
# ============================================================
def switch_fast_metrics_watchdog():
    while True:
        now = time.time()
        healthy = 0
        stale_count = 0
        with switch_live_lock:   # each entry's age and stale mark go out in a new copy, like the streams' own reports
            live = {}
            for uid, entry in state["switch_live_rates"].items():
                updated = safe_number(entry.get("updated_at"))
                age = max(0.0, now - float(updated)) if updated is not None else None
                stale = (
                    entry.get("connected") is not True
                    or age is None
                    or age > SWITCH_FAST_STALE_SECONDS
                )
                live[uid] = {**entry, "age_seconds": round(age, 2) if age is not None else None, "stale": stale}
                if stale:
                    stale_count += 1
                else:
                    healthy += 1
            state["switch_live_rates"] = live
        switch_count = len(state.get("switches") or {})
        state["switch_fast_metrics_health"] = {
            "switches_discovered": switch_count,
            "streams_known": len(live),
            "streams_live": healthy,
            "streams_stale": stale_count,
            "stale_after_seconds": SWITCH_FAST_STALE_SECONDS,
            # A router with no Firewalla switch (owner, 21 Nov 2026: the cabin's
            # Gold Plus): once the controller has answered with none, there is
            # nothing to be healthy or not (None). Never answered: not working.
            "healthy": (healthy == switch_count) if switch_count else (None if state.get("switch_last_update") else False),
            "updated_at": now,
        }
        time.sleep(1)


# ============================================================
# EQUIPMENT HEALTH: a year of what Firewalla says about each AP and switch
#
# Agreed 15 Nov 2026. Firewalla's controller gives each AP7 and Switch X a
# one-word health label ("Healthy", "Checking", "Unhealthy"...), never a
# reason. The dashboard reads it every 2 s (switches' labels come with the
# AP poll) and keeps two logs in /data/equipment_health.db, one year each:
#   Firewalla Reported (the quiet log): every label change, with a snapshot
#     of Firewalla's own details at that moment (last check-in, cable links,
#     uplink, the switch port's power, mesh signal, firmware, uptime);
#     "Checking" (a routine check-in) is only counted per unit per day,
#     unless it lasts over 60 s; firmware changes.
#   Assessment: one entry per incident (bad and back; flaps within 2 min
#     are one incident) with a Likely Cause from a fixed set, Why, How Sure
#     and whether it was raised; and patterns across incidents (repeats,
#     timing, chains, getting worse, after a firmware update).
# A unit only shows red after its label has been bad for 60 s
# ("health_shown"); shorter blips are logged, not shown. Rules, not Claude,
# do the assessing; Ask Claude on an incident gives a second opinion.
# Firmware = the controller's "version" (plus "imageVersion" on an AP7,
# its operating system image); uptime = "sysUptime" (a switch also has
# systemStatus.uptime). Seen 15 Nov 2026: AP7 1.18.26 / image 0.2.10,
# Switch X 0.6.35.
# ============================================================
EQUIPMENT_HEALTH_DATABASE = os.environ.get("FIREWALLA_EQUIPMENT_HEALTH_DB", "/data/equipment_health.db")
EH_KEEP_SECONDS = 365 * 86400
EH_RED_AFTER = 60          # seconds a bad label must last before the unit shows red
# A blip up to 90 s with cable, power and the controller's link normal is
# routine (16 Nov 2026: AP7 Bedroom and Skywalk went Unhealthy for 49-62 s
# about once an hour, at their hourly check-in, with 1 ms latency to the
# controller, cable and PoE up and uptime counting throughout).
EH_ROUTINE_MAX = 90
# Looser since 20 Nov 2026 (owner): check-ins come in waves across the units,
# and one in a wave (another unit's incident started within 3 minutes of it)
# may run to two back to back (AP7 Sm Garage, 97 s on 18 Nov, lost nothing,
# two other access points checked in two minutes before). And a couple of
# Wi-Fi clients leaving a lightly used access point during a check-in is no
# drop (AP7 Office, 6 to 4 on 18 Nov): a drop is 3 or more clients and at
# least half of them.
EH_ROUTINE_MAX_SHARED = 120
EH_WAVE_WINDOW = 180
EH_DROP_MIN = 3
EH_DROP_SHARE = 0.5
EH_FLAP_MERGE = 120        # back to bad within 2 minutes = the same incident
EH_RELATED_WINDOW = 30     # incidents starting within 30 s of each other are related
EH_GOOD = "Healthy"
EH_CHECKING = "Checking"
EH_CAUSES = ("Routine Check-In", "Not Confirmed", "Firmware Update", "Lost Contact", "Cable or Port", "Power or Reboot", "Wireless Link", "Upstream Unit", "Can't Tell")
EH_NOT_REPORTED = "Not Reported"
EH_ASSESS_VERSION = 7      # raise when eh_assess's rules change: every incident is assessed again once
eh_lock = threading.Lock()
eh = {"units": {}, "last_observe": None, "summary": {"needs": [], "units": {}}}


def eh_db():
    connection = sqlite3.connect(EQUIPMENT_HEALTH_DATABASE, timeout=15)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=15000")
    connection.row_factory = sqlite3.Row
    return connection


def initialize_equipment_health():
    with eh_db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY, at REAL NOT NULL, unit_id TEXT NOT NULL,
                unit_name TEXT, unit_type TEXT, label_before TEXT, label_after TEXT, seconds_before REAL,
                details TEXT, incident_id INTEGER);
            CREATE INDEX IF NOT EXISTS changes_by_time ON changes (at);
            CREATE INDEX IF NOT EXISTS changes_by_incident ON changes (incident_id);
            CREATE TABLE IF NOT EXISTS checking (day TEXT NOT NULL, unit_id TEXT NOT NULL, unit_name TEXT,
                times INTEGER NOT NULL DEFAULT 0, longest REAL NOT NULL DEFAULT 0, PRIMARY KEY (day, unit_id));
            CREATE TABLE IF NOT EXISTS firmware (id INTEGER PRIMARY KEY, at REAL NOT NULL, unit_id TEXT NOT NULL,
                unit_name TEXT, before TEXT, after TEXT);
            CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, unit_id TEXT NOT NULL, unit_name TEXT,
                unit_type TEXT, started REAL NOT NULL, ended REAL, labels TEXT, flaps INTEGER NOT NULL DEFAULT 1,
                cause TEXT, why TEXT, sure TEXT, related TEXT, raised TEXT, routine INTEGER, firmware TEXT,
                seen_at REAL);
            CREATE INDEX IF NOT EXISTS incidents_by_time ON incidents (started);
            CREATE TABLE IF NOT EXISTS patterns (id INTEGER PRIMARY KEY, key TEXT UNIQUE, found REAL NOT NULL,
                kind TEXT, units TEXT, period_from REAL, period_to REAL, incidents TEXT, summary TEXT, sure TEXT,
                raised TEXT, seen_at REAL);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS unit_events (id INTEGER PRIMARY KEY, at REAL NOT NULL, unit_id TEXT NOT NULL,
                unit_name TEXT, unit_type TEXT, kind TEXT NOT NULL, band TEXT, before TEXT, after TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS unit_events_by_unit ON unit_events (unit_id, at);
            CREATE INDEX IF NOT EXISTS unit_events_by_time ON unit_events (at);
        """)
        if eh_meta(c, "unit_events_since") is None:
            eh_meta(c, "unit_events_since", time.time())   # when the history began recording


def eh_meta(c, key, value=None):
    if value is None:
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None
    c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, json.dumps(value)))


def ap_has_second_cable(ap=None, ports=None, primary=None):
    """True when an AP has a live cable on a port other than its uplink, so
    another AP can be plugged into it (19 Nov 2026). Takes a normalized AP
    record (eth_ports, primary_interface) or a health snapshot's
    cable_links and primary."""
    if ap is not None:
        ports, primary = ap.get("eth_ports") or {}, ap.get("primary_interface")
    return any(name != primary and (p.get("connected") or p.get("up")) for name, p in (ports or {}).items())


def eh_bad(label):
    return label not in (EH_GOOD, EH_CHECKING)


def eh_version_uptime(raw):
    """A unit's firmware and uptime (seconds) as the controller reports them."""
    version = str(raw.get("version") or "").strip() or None
    if version and raw.get("imageVersion"):
        version += f" · image {raw['imageVersion']}"
    uptime = safe_number(raw.get("sysUptime"))
    if uptime is None:
        uptime = safe_number((raw.get("systemStatus") or {}).get("uptime"))
    if uptime is not None and uptime > 1e9:   # a boot time, not an uptime
        uptime = time.time() - (uptime / 1000 if uptime > 1e12 else uptime)
    return version, uptime


def eh_port_number(port):
    match = re.search(r"(\d+)$", str(port or ""))
    return match.group(1) if match else None


def eh_snapshot(kind, uid, raw, norm, now):
    """Firewalla's own details about one unit at this moment."""
    unit = eh["units"].get(uid) or {}
    snap = {"firmware": unit.get("firmware"), "uptime": unit.get("uptime")}
    if kind == "ap":
        # Wi-Fi clients on it now, and about 10-40 s before (did any drop?).
        hist = unit.get("clients_hist") or []
        snap["clients"] = (eh.get("ap_clients") or {}).get(uid)
        old = [n for t, n in hist if t <= now - 10]
        snap["clients_before"] = old[0] if old else (hist[0][1] if hist else None)
        checked = safe_number(raw.get("checkedIn"))
        checked = checked / 1000 if checked and checked > 1e12 else checked
        snap["last_check_in_seconds"] = round(now - checked) if checked else None
        latency = safe_number(raw.get("latencyToController"))
        snap["latency_to_controller"] = latency
        for key, label in (("healthySince", "healthy_since"), ("lastActiveUplinkTs", "uplink_changed_at")):
            stamp = safe_number(raw.get(key))
            snap[label] = (stamp / 1000 if stamp and stamp > 1e12 else stamp) or None
        snap["primary"] = norm.get("primary_interface")
        snap["uplink_type"] = "Cable" if str(raw.get("backhaulState") or "").lower() == "ethernet" else "Mesh"
        snap["upstream"] = norm.get("uplink_name")
        snap["upstream_port"] = norm.get("uplink_port")
        snap["cable_links"] = {name: {"up": e.get("connected") is True, "speed": safe_number(e.get("linkSpeed"))}
                               for name, e in (raw.get("eths") or {}).items() if isinstance(e, dict)}
        if snap["uplink_type"] == "Mesh":
            snap["mesh_signal"] = norm.get("mesh_rssi")
        switch = next((s for s in (state.get("switches") or {}).values() if s.get("name") == norm.get("uplink_name")), None)
        port = (switch or {}).get("ports", {}).get(eh_port_number(norm.get("uplink_port")) or "")
        if port:
            snap["port_power"] = {"watts": port.get("poe_power_watts"), "status": port.get("poe_status"),
                                  "link_up": port.get("link_up"), "speed": port.get("link_speed")}
    else:
        snap.update({"temperature": norm.get("temperature"), "fan": norm.get("fan_status"),
                     "uplinks": {p: {"up": norm["ports"][p].get("link_up"), "speed": norm["ports"][p].get("link_speed")}
                                 for p in norm.get("infrastructure_ports") or [] if p in (norm.get("ports") or {})}})
    upstream = next((u for u in eh["units"].values() if u.get("name") and u.get("name") == snap.get("upstream")), None)
    if upstream:
        snap["upstream_label"] = upstream.get("label")
    return snap


def eh_change(c, uid, unit, before, after, seconds, snap, now):
    c.execute("INSERT INTO changes (at, unit_id, unit_name, unit_type, label_before, label_after, seconds_before, details, incident_id)"
              " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (now, uid, unit["name"], unit["type"], before, after, round(seconds or 0, 1), json.dumps(snap, default=str),
               unit.get("incident") or unit.get("pending_id")))


def eh_open_incident(c, uid, unit, started):
    """Start an incident, or continue the one that ended under 2 minutes ago."""
    if unit.get("pending_id") and started - (unit.get("pending_at") or 0) <= EH_FLAP_MERGE:
        unit["incident"] = unit.pop("pending_id")
        unit.pop("pending_at", None)
        c.execute("UPDATE incidents SET ended=NULL, flaps=flaps+1 WHERE id=?", (unit["incident"],))
        return
    cursor = c.execute("INSERT INTO incidents (unit_id, unit_name, unit_type, started, labels, firmware) VALUES (?, ?, ?, ?, ?, ?)",
                       (uid, unit["name"], unit["type"], started, json.dumps([unit["label"]]), unit.get("firmware")))
    unit["incident"] = cursor.lastrowid


def eh_label(c, kind, uid, name, label, raw, norm, now):
    unit = eh["units"].get(uid)
    if unit is None:
        unit = eh["units"][uid] = {"type": kind, "name": name, "label": label, "since": now, "seen": now}
        if label != EH_GOOD:
            unit["off_since"] = now
        if eh_bad(label):
            eh_open_incident(c, uid, unit, now)
            eh_change(c, uid, unit, "(first seen)", label, 0, eh_snapshot(kind, uid, raw, norm, now), now)
        if label == EH_CHECKING:
            eh_checking(c, uid, unit, now, start=True)
        return
    unit.update({"name": name, "seen": now, "type": kind})
    if label == unit["label"]:
        # A check-in that goes on for over 60 s is no longer routine.
        if label == EH_CHECKING and not unit.get("incident") and now - unit["since"] > EH_RED_AFTER:
            eh_open_incident(c, uid, unit, unit["since"])
            eh_change(c, uid, unit, EH_CHECKING, EH_CHECKING + " for over 60 s", now - unit["since"],
                      eh_snapshot(kind, uid, raw, norm, now), now)
        return
    before, seconds = unit["label"], now - unit["since"]
    if before == EH_CHECKING:
        eh_checking(c, uid, unit, now, seconds=seconds)
    if label == EH_CHECKING:
        eh_checking(c, uid, unit, now, start=True)
    in_incident = bool(unit.get("incident"))
    # off_since: when it stopped being Healthy. A bad label changing to
    # another (Unhealthy -> Disconnected) keeps it, so a red unit stays red.
    if label == EH_GOOD:
        unit.pop("off_since", None)
    elif before == EH_GOOD:
        unit["off_since"] = now
    else:
        unit.setdefault("off_since", unit["since"])
    unit["label"], unit["since"] = label, now
    if eh_bad(label) and not in_incident:
        eh_open_incident(c, uid, unit, now)
    if unit.get("incident"):
        row = c.execute("SELECT labels FROM incidents WHERE id=?", (unit["incident"],)).fetchone()
        labels = json.loads(row[0] or "[]") if row else []
        if eh_bad(label) and label not in labels:
            c.execute("UPDATE incidents SET labels=? WHERE id=?", (json.dumps(labels + [label]), unit["incident"]))
    # Healthy <-> Checking is routine: counted, not logged.
    if unit.get("incident") or eh_bad(before) or eh_bad(label):
        eh_change(c, uid, unit, before, label, seconds, eh_snapshot(kind, uid, raw, norm, now), now)
    if label == EH_GOOD and unit.get("incident"):
        c.execute("UPDATE incidents SET ended=? WHERE id=?", (now, unit["incident"]))
        unit["pending_id"], unit["pending_at"] = unit.pop("incident"), now


def eh_checking(c, uid, unit, now, start=False, seconds=None):
    day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
    c.execute("INSERT OR IGNORE INTO checking (day, unit_id, unit_name) VALUES (?, ?, ?)", (day, uid, unit["name"]))
    if start:
        c.execute("UPDATE checking SET times=times+1, unit_name=? WHERE day=? AND unit_id=?", (unit["name"], day, uid))
    elif seconds is not None:
        c.execute("UPDATE checking SET longest=MAX(longest, ?) WHERE day=? AND unit_id=?", (round(seconds, 1), day, uid))


def equipment_health_observe(ap_raw, switch_raw, ap_norm, assets):
    """Called by the AP collector every 2 s with the controller's records."""
    now = time.time()
    switch_norm = state.get("switches") or {}
    # Wi-Fi clients per AP (by its id, or by name when a station only names it).
    by_id, by_name = Counter(), Counter()
    for st in (state.get("wifi_stations") or {}).values():
        if st.get("ap_id"):
            by_id[str(st["ap_id"]).upper()] += 1
        elif st.get("ap_name"):
            by_name[st["ap_name"]] += 1
    try:
        with eh_lock, eh_db() as c:
            seen, raw_by_uid = set(), {}
            removed = eh_meta(c, EH_REMOVED_KEY) or {}
            for kind, raw_all, norm_all in (("ap", ap_raw, ap_norm), ("switch", switch_raw, switch_norm)):
                for raw_uid, raw in (raw_all or {}).items():
                    uid = str(raw_uid).upper()
                    seen.add(uid)
                    raw_by_uid[uid] = raw
                    norm = norm_all.get(uid) or {}
                    name = norm.get("name") or raw.get("name") or ((assets.get(uid) or {}).get("sysConfig") or {}).get("name") or uid
                    version, uptime = eh_version_uptime(raw)
                    if kind == "ap":
                        eh.setdefault("ap_clients", {})[uid] = by_id.get(uid, 0) + by_name.get(name, 0)
                    if uid in removed:   # seen again: it's back on the network
                        removed.pop(uid)
                        eh_meta(c, EH_REMOVED_KEY, removed)
                    unit = eh["units"].get(uid)
                    if unit is not None:
                        if version and unit.get("firmware") and version != unit["firmware"]:
                            c.execute("INSERT INTO firmware (at, unit_id, unit_name, before, after) VALUES (?, ?, ?, ?, ?)",
                                      (now, uid, name, unit["firmware"], version))
                            eh_event(c, uid, unit, "firmware", None, unit["firmware"], version, {}, now)
                            unit["firmware_changed"] = version
                            unit.setdefault("restarted_at", now)
                        # Uptime starting again from zero = a restart.
                        if uptime is not None and unit.get("uptime") is not None and uptime < unit["uptime"] - 60:
                            unit["restarted_at"] = now
                            eh_event(c, uid, unit, "restart", None, round(unit["uptime"]), round(uptime), {}, now)
                        if unit.get("restarted_at") and now - unit["restarted_at"] >= 600:
                            unit.pop("restarted_at", None)
                            unit.pop("firmware_changed", None)
                        if version:
                            unit["firmware"] = version
                        if uptime is not None:
                            unit["uptime"] = uptime
                    eh_label(c, kind, uid, name, str(raw.get("healthy") or "Unknown"), raw, norm, now)
                    if unit is None and version:
                        eh["units"][uid]["firmware"] = version
                        eh["units"][uid]["uptime"] = uptime
                    if kind == "ap":
                        hist = eh["units"][uid].setdefault("clients_hist", [])
                        hist.append((now, eh["ap_clients"][uid]))
                        del hist[:-20]   # 20 readings, 2 s apart
            # A unit the controller stops listing (while it lists the others).
            if seen:
                for uid, unit in eh["units"].items():
                    if unit["type"] != "router" and uid not in seen and now - unit.get("seen", now) > 10 and unit["label"] != EH_NOT_REPORTED:
                        eh_label(c, unit["type"], uid, unit["name"], EH_NOT_REPORTED, {}, {}, now)
            # The one verdict per unit, from our own checks (listed or not).
            eh_own_since(c)
            eh_planned_publish(c, now)   # Planned Work that ran out ends first (D-912)
            devices = {str(d.get("mac") or "").upper(): d for d in state.get("devices") or []}
            for uid, unit in list(eh["units"].items()):
                kind = unit["type"]
                if kind == "router":
                    continue
                norm = ((ap_norm if kind == "ap" else switch_norm) or {}).get(uid) or {}
                try:   # one unit's fault never freezes the others (22 Nov 2026)
                    eh_verdict(c, kind, uid, raw_by_uid.get(uid) or {}, norm, now, devices)
                except Exception as exc:
                    log_repeat("verdict-" + uid, f"Equipment verdict error ({unit.get('name')}): {exc}")
            eh_router_pass(c, now)
            eh_raw_sample(ap_raw, switch_raw, now)
            eh["last_observe"] = now
    except Exception as exc:
        print("Equipment health error:", exc)


def eh_router_pass(c, now):
    """The part of a health pass that needs nothing from the controller: the
    router's own verdict, the internet connections' history, and every
    unit's verdict published."""
    try:
        eh_router_verdict(c, now)
    except Exception as exc:
        log_repeat("verdict-router", f"Router verdict error: {exc}")
    try:
        eh_wan_spells(c, now)
    except Exception as exc:
        log_repeat("wan-spells", f"Internet connection history error: {exc}")
    eh_look_save(c)
    state["equipment_verdicts"] = equipment_verdicts()


def equipment_health_no_controller():
    """Called by the AP collector when the controller can't be read: the
    router is off or restarting, its controller is silent, or the router has
    no access points or switches. The router's own verdict is still judged
    (24 Nov 2026: nothing was, so its Outage rule never ran in the one case
    it is for, and no Outage email went out), Planned Work still runs out
    and the internet connections' history goes on. The access points and
    switches keep their last verdict: without the controller nothing new is
    known about them."""
    now = time.time()
    try:
        with eh_lock, eh_db() as c:
            eh_own_since(c)
            eh_planned_publish(c, now)
            eh_router_pass(c, now)
    except Exception as exc:
        print("Equipment health error:", exc)


def equipment_health_verdict(uid):
    """The unit's verdict (state, word, sentence, since, checks), or None."""
    unit = eh["units"].get(str(uid).upper())
    return (unit or {}).get("verdict")


def equipment_health_shown(uid):
    """good / checking / bad for every page, from the unit's one verdict."""
    unit = eh["units"].get(str(uid).upper())
    if not unit:
        return None
    # "look" (Needs a Look) shows amber like "checking" did; it counts as up.
    # "acked" (a Needs a Look you acknowledged) and "planned" (Planned Work) are grey, and up.
    return {"healthy": "good", "look": "checking", "acked": "acked", "planned": "acked", "outage": "bad"}.get((unit.get("verdict") or {}).get("state"), "good")


# ------------------------------------------------------------
# OUR OWN CHECKS AND THE ONE VERDICT (22 Nov 2026, owner)
#
# Firewalla's label alone turned units red 35 times in a year for routine
# check-ins (327 of 328 changes were routine; median 51 s, longest 97 s).
# So while the label is bad the dashboard checks the unit itself, every
# 2 s, from signs that don't come from the label:
#   the controller still measures its latency (AP7),
#   the router still hears it (its last-active time),
#   its cable: the switch port it's plugged into is still up,
#   its Wi-Fi clients are still passing traffic (the router hears them),
#   its uptime keeps counting (no restart), its port's power holds,
#   a switch's own live data keeps arriving.
# One verdict per unit, made here and nowhere else: Healthy, Checking
# (Firewalla says bad, our checks pass) or Outage (a check fails for 6 s,
# the label stays bad over 2 minutes, or two checks fail for 30 s while
# Firewalla says Healthy). Every page, the Status alerts, the emails and
# the digest read this verdict, so no page can say Healthy while another
# says Outage. The sentence says why; the checklist shows each check.
# ------------------------------------------------------------
EH_OUTAGE_AFTER = 120          # a bad label longer than any routine check-in seen (97 s)
EH_FAIL_HOLD = 6               # a check must fail this long (3 readings) to count
EH_OWN_ONLY_HOLD = 30          # two checks failing while Firewalla says Healthy
# The router's last-active times come in batches every 2-4 minutes (22 Nov
# 2026: every device's age climbed to 218 s between batches), so this is a
# slow backstop, not a quick sign.
EH_HEARD_LIMIT = {"ap": 420, "switch": 600}
EH_CLIENT_HEARD = 60           # a Wi-Fi client in the router's live flow rates within a minute is passing traffic
EH_STREAM_LIMIT = 30           # a switch's live data missing this long = stopped
EH_CLIENTS_TO_JUDGE = 2        # fewer active clients than this before: too few to judge by
EH_REMOVED_KEY = "removed_units"
EH_OWNER_CAUSES_KEY = "owner_causes"  # {incident id: {cause, at}}: the owner's own call (Mark Not Confirmed)
EH_OWN_SINCE_KEY = "own_checks_since"   # when our own checks started: incidents from then need them to count


def eh_ago(seconds):
    return fmt_duration_short(seconds) + " ago"


def eh_port_seeing(uid):
    """(switch id, switch, port) whose own client list has this unit, when
    Firewalla names no uplink port (22 Nov 2026: AP7 Skywalk, Media Room and
    Bedroom). Ports between switches see everything behind them, so a port
    that also sees another switch is left out; of the rest, the one that
    sees the fewest (Bedroom is seen on Media Room's port: it hangs off it)."""
    switches = state.get("switches") or {}
    others = {str(k).upper() for k in switches}
    best = None
    for sid, sw in switches.items():
        for p in (sw.get("ports") or {}).values():
            macs = {str(m).upper() for m in p.get("connected_macs") or []}
            if uid in macs and not (macs & (others - {str(sid).upper()})):
                if best is None or len(macs) < best[2]:
                    best = ((sid, sw), p, len(macs))
    return (best[0], best[1]) if best else (None, None)


def eh_checks(kind, uid, unit, raw, norm, now, devices):
    """Each check: key, name, ok (True, False, or None = can't tell), value."""
    checks = []
    add = lambda key, name, ok, value, hard=True: checks.append({"key": key, "name": name, "ok": ok, "value": value, "hard": hard})
    listed = bool(raw)
    label, held = unit["label"], now - unit.get("off_since", unit["since"])
    add("label", "What Firewalla Says", unit["label"] == EH_GOOD,
        "Healthy" if label == EH_GOOD else f"{label} for {fmt_duration_short(held)}", hard=False)
    if kind == "ap":
        latency = safe_number(raw.get("latencyToController")) if listed else None
        add("controller", "Controller Reaches It", None if not listed else latency is not None,
            "the controller no longer lists it" if not listed else f"{latency:g} ms" if latency is not None else "no answer")
    else:
        live = (state.get("switch_live_rates") or {}).get(uid) or {}
        age = now - live["updated_at"] if safe_number(live.get("updated_at")) else None
        # Stopped only after 30 s without any (22 Nov 2026: the stream pauses
        # a few seconds now and then; the watchdog's 5 s "stale" flickered).
        ok_ = None if not live or age is None else age <= EH_STREAM_LIMIT
        add("stream", "Its Live Data Arrives", ok_,
            "not started yet" if ok_ is None else f"{age:.0f} s old" if ok_ else f"stopped {fmt_duration_short(age)} ago")
    dev = devices.get(uid) or {}
    last = safe_number(dev.get("last_active"))
    if last:
        add("heard", "Router Hears It", now - last <= EH_HEARD_LIMIT[kind], "last heard " + eh_ago(now - last))
    else:
        add("heard", "Router Hears It", None, "not in the router's device list")
    if kind == "ap":
        uplink_type = "Cable" if str(raw.get("backhaulState") or "").lower() == "ethernet" else "Mesh" if listed else None
        switch = next(((sid, s) for sid, s in (state.get("switches") or {}).items() if s.get("name") == norm.get("uplink_name")), None)
        port = (switch[1].get("ports") or {}).get(eh_port_number(norm.get("uplink_port")) or "") if switch else None
        behind = None
        if not port and listed:
            switch, port = eh_port_seeing(uid)
            # A port that also sees another AP with a cable on its second port:
            # this AP hangs off that one (AP7 Bedroom off Media Room's eth0, 22
            # Nov 2026), so the switch port and its power are the other AP's.
            if port:
                aps = state.get("access_points") or {}
                macs = {str(m).upper() for m in port.get("connected_macs") or []}
                behind = next((a for o, a in aps.items() if o != uid and o in macs and ap_has_second_cable(a)), None)
        if behind:
            own = (raw.get("eths") or {}).get(norm.get("primary_interface")) or {}
            sp = safe_number(own.get("linkSpeed"))
            add("cable", "Its Cable", own.get("connected") is not False,
                f"{behind['name']} port {next((n for n, e in (behind.get('eth_ports') or {}).items() if n != behind.get('primary_interface') and e.get('connected')), 'eth0')} "
                + ("down" if own.get("connected") is False else
                f"up{', ' + eh_speed(sp) if sp else ''}, through {behind['name']}"))
            if raw.get("powerType"):
                add("power", "Its Power", True, f"{raw['powerType']} (not from the switch port)", hard=False)
        elif port:
            rate = ((((state.get("switch_live_rates") or {}).get(switch[0]) or {}).get("ports") or {}).get(str(port.get("port"))) or {})
            moving = (rate.get("rx_mbps") or 0) + (rate.get("tx_mbps") or 0)
            speed = port.get("link_speed")
            add("cable", "Its Cable", port.get("link_up") is not False,
                f"{switch[1]['name']} port {port.get('port')} " + ("down" if port.get("link_up") is False else
                f"up{', ' + (str(speed // 1000) + ' Gb/s' if speed and speed >= 1000 else str(speed) + ' Mb/s') if speed else ''}, "
                + (f"{moving:.1f} Mb/s moving" if moving >= 0.05 else "little data moving")))
            # Power counts only on a port that has delivered it (a powerline
            # adapter's port never does: AP7 Sm Garage, 19 Nov 2026).
            if port.get("poe_status") == "delivering":
                unit["power_ok_at"] = now
            # An AP on its own adapter (powerType "DC") isn't powered by the port.
            on_poe = "poe" in str(raw.get("powerType") or "poe").lower()
            if unit.get("power_ok_at") and port.get("poe_status") and on_poe:
                add("power", "Its Port's Power", port.get("poe_status") == "delivering",
                    f"{port.get('poe_status')}" + (f", {port['poe_power_watts']} W" if port.get("poe_power_watts") else "")
                    + (f" ({raw['powerType']})" if raw.get("powerType") else ""))
            if not any(ch["key"] == "power" for ch in checks) and raw.get("powerType"):
                # It's running, so its own power source works.
                add("power", "Its Power", True, f"{raw['powerType']} (not from the switch port)", hard=False)
        elif uplink_type == "Mesh":
            rssi = norm.get("mesh_rssi")
            add("cable", "Its Wireless Link", None if rssi is None else rssi >= -80, f"mesh, signal {rssi} dBm" if rssi is not None else "mesh", hard=False)
        else:
            add("cable", "Its Cable", None, "its switch port isn't known (Firewalla names no uplink port)" if listed else "not reported")
        # Wi-Fi clients the router still hears. "Before" = the most heard in
        # the 2 minutes before this went bad (or now, while healthy).
        stations = [m for m, s in (state.get("wifi_stations") or {}).items() if str(s.get("ap_id") or "").upper() == uid]
        unit.setdefault("client_macs", {}).update({m: now for m in stations})
        unit["client_macs"] = {m: t for m, t in unit["client_macs"].items() if now - t <= 300}
        # The router's live per-device flow rates (about every 10 s) list the
        # clients that had traffic: the router saw it, not the controller.
        rates = state.get("device_flow_rates") or {}
        heard = sum(1 for m in unit["client_macs"] if now - (safe_number((rates.get(m) or {}).get("updated_at")) or 0) <= EH_CLIENT_HEARD)
        hist = unit.setdefault("heard_hist", [])
        hist.append((now, heard))
        del hist[:-60]   # 2 minutes
        start = unit.get("off_since", now)
        before = max([n for t, n in hist if t < start] or [heard])
        if before < EH_CLIENTS_TO_JUDGE:
            add("clients", "Wi-Fi Clients Passing Traffic", None, f"{heard} active: too few to judge by")
        else:
            # Supporting only (22 Nov 2026, owner): clients come and go, stick to
            # an AP on a weak signal or leave it empty; what they do isn't the
            # AP's health. Shown, and named in the reason, never deciding.
            add("clients", "Wi-Fi Clients Passing Traffic", heard > 0, f"{heard} of {len(unit['client_macs'])} sent data in the last minute"
                + (f", {before} before" if heard < before else ""), hard=False)
    up = unit.get("uptime")
    restarted = unit.get("restarted_at")
    if restarted and now - restarted < 600:
        fw = unit.get("firmware_changed")
        # A restart is a sign only while Firewalla says it's bad: once it is
        # back and the rest passes, it is history (shown, not deciding).
        add("restart", "No Restart", False, f"restarted {eh_ago(now - restarted)}" + (f", firmware now {fw}" if fw else ""), hard=label != EH_GOOD)
    else:
        add("restart", "No Restart", None if up is None else True, f"up {fmt_duration_short(up)}" if up is not None else "uptime not reported")
    # The unit above it, and others at the same moment (not checks of this unit).
    upstream = norm.get("uplink_name")
    above = next((u for u in eh["units"].values() if u.get("name") and upstream and (u["name"] == upstream or u["name"].endswith(" " + upstream))), None)
    if above:
        st = (above.get("verdict") or {}).get("state", "healthy")
        add("upstream", "The Unit Above It", st != "outage", f"{above['name']}: {st.title()}", hard=False)
    others = [u["name"] for o, u in eh["units"].items() if o != uid and eh_bad(u["label"])]
    add("others", "Other Units Right Now", len(others) < 3, ("all fine" if not others else f"{len(others)} not healthy too: {', '.join(sorted(others)[:4])}"), hard=False)
    return checks


# ------------------------------------------------------------
# NEEDS A LOOK (22 Nov 2026, owner: to-do item 10, AP7C / AP7D full health)
#
# Beyond up or down: an access point can be working but not at its best.
# Judged from the AP's own signs only (never from what clients do, D-848):
#   its cable runs slower than the best this AP has had (a drop to 100 Mb/s),
#   its cable link went down and up 3 or more times in the last hour,
#   on mesh, its signal is weaker than -70 dBm,
#   a radio it had (2.4, 5 or 6 GHz) is off,
#   (a radio's width or transmit power changing is only recorded in its
#   Radio History, 23 Nov 2026: most are Firewalla's own nightly tuning),
#   a radio changed channel 4 or more times in 24 hours (interference, radar),
#   its firmware differs from most of the other access points.
# Amber "Needs a Look" with the reason; never red, never an incident, no email.
# What the AP has had (best speed, radios, channel changes) is kept in the
# health database's meta, so a restart doesn't forget it.
# ------------------------------------------------------------
EH_BUCKETS = {   # (name, check keys), in table order; "radio" covers radio_2g/5g/6g
    "ap": [("Reachable", ("controller", "heard", "restart")), ("Connection", ("cable", "speed", "flaps", "mesh", "backhaul")),
           ("Power", ("power",)), ("Radios", ("radio", "ssids", "airtime")),
           ("System", ("firmware", "cpu", "memory", "storage", "temperature"))],
    # Same columns as the access points where they mean the same (22 Nov 2026,
    # owner: keep the two tables aligned): Ports sits where Radios does.
    "switch": [("Reachable", ("stream", "heard", "restart")), ("Connection", ("uplink", "speed", "flaps")),
               ("Power", ("poe",)), ("Ports", ("gear_ports", "port_errors")), ("System", ("fan", "temperature", "fault", "firmware"))],
    "router": [("Reachable", ("tunnel", "cloud", "routing", "restart")), ("Connection", ("wan",)), ("Power", ("power",)),
               ("Ports", ("lan_ports",)), ("System", ("cpu", "memory", "firmware", "dfs"))],   # backhaul, dfs: D-996
}
EH_LOOK_KEY = "ap_history"
EH_LOOK_HOLD = 30              # a Needs a Look item must last this long to show
EH_CPU_BUSY = 80               # % CPU held for 5 minutes
EH_FREE_LOW = 0.10             # memory or storage free below 10%
EH_FLAP_LIMIT = 3              # cable link changes in an hour
EH_CHANNEL_LIMIT = 4           # channel changes in 24 hours, per radio
EH_MESH_WEAK = -70
EH_BANDS = {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}


def ap_air_busy(raw):
    """How busy each band's channel is, % (owner's test, 24 Nov 2026, D-989):
    Firewalla's channelUtilization is the share of air that is FREE (AP7
    Office's 6 GHz read 98 idle and fell to 5-76 during back-to-back speed
    tests on it), so busy = 100 minus it."""
    out = {}
    for band, v in (raw.get("channelUtilization") or {}).items():
        free = safe_number(v)
        if free is not None:
            out[band] = round(max(0, min(100, 100 - free)))
    return out


EH_BUCKET_WORD = {"good": "Healthy", "warn": "Degraded", "bad": "Down", "none": "Can't tell"}


def eh_days(value):
    """'up 411.5 h' -> 'Up 17 days'."""
    m = re.match(r"up ([\d.]+) h", value or "")
    if m and float(m.group(1)) >= 48:
        return f"Up {float(m.group(1)) / 24:.0f} days"
    return (value or "").capitalize()


def eh_power_type(text):
    return re.sub(r"\bPOE\b", "PoE", str(text or ""))


def eh_short(ch):
    """A check as one or two short lines for the bucket table's hover
    (22 Nov 2026, owner: formatted, abbreviated, easy to read)."""
    k, ok, v = ch["key"], ch["ok"], str(ch.get("value") or "")
    if k == "controller":
        if ok:
            return ["Communicating with the router", f"Low latency {v}"]
        return ["Not listed by the router" if "no longer lists" in v else "Router gets no answer"] if ok is False else []
    if k == "heard":
        return [v.replace("last heard", "Heard" if ok else "Last heard", 1)] if v.startswith("last heard") else []
    if k == "restart":
        if ok is False:
            return [v.replace("restarted", "Restarted", 1).replace(", firmware now", " (firmware") + (")" if "firmware" in v else "")]
        return [eh_days(v)] if ok else []
    if k == "stream":
        return ["Live data arriving" if ok else "Live data stopped"] if ok is not None else []
    if k == "cable":
        m = re.match(r"(.+? port \S+) (up|down)(.*)", v)
        if not m:
            return ["Uplink port not known"] if ok is None else []
        where, rest = m.group(1), m.group(3)
        if m.group(2) == "down":
            return [f"Uplink port down ({where})"]
        if ", through " in rest:   # behind another AP: its speed is the Link line
            return [f"Uplink port active ({where})"]
        return [f"Uplink port active ({where})", "Little data moving" if "little data" in rest else "Passing data"]
    if k == "speed":
        m = re.match(r"(\S+ \S+), it has run at (.+)", v)
        return [f"Link slowed to {m.group(1)} (was {m.group(2)})"] if ok is False and m else [f"Link {v.replace(' (its best)', '')}"]
    if k == "flaps":
        return ["No cable drops in the last hour"] if ok else [v.replace("went down or up", "Cable dropped", 1)]
    if k == "mesh":
        return [("Mesh signal " if ok else "Weak mesh signal ") + v.split(",")[0]]
    if k == "power":
        if "not from the switch port" in v:
            kind_ = eh_power_type(v.replace(' (not from the switch port)', ''))
            return ["Powered by its own DC adapter" if kind_.upper() == "DC" else f"Powered ({kind_}, not from the switch)"]
        m = re.match(r"delivering, ([\d.]+ W)(?: \((.+)\))?", v)
        if m:
            return [f"Delivering {m.group(1)}" + (f" ({eh_power_type(m.group(2))})" if m.group(2) else "")]
        return [f"Port power {v.split(',')[0]}"]
    if k == "ssids":
        if ok:
            names = [n.strip() for n in v.split(",")]
            return ["Broadcasting: " + (" and ".join(names) if len(names) <= 2 else ", ".join(names[:-1]) + " and " + names[-1])]
        return ["Not broadcasting: " + v.split(" not broadcasting")[0]]
    if k == "cpu":
        return [f"CPU: {v.split(',')[0]}" + (" for 5 min" if ok is False else "")]
    if k == "memory":
        return [f"Memory: {v}"]
    if k == "storage":
        return [f"Storage: {v}"]
    if k == "temperature":
        if v[:1].isdigit():   # a switch: its own reading
            return [f"Temperature: {v.split(',')[0]}" + ("" if ok else " (too warm)")]
        return ["Temperature: acceptable" if ok else "Temperature: too warm"]
    if k == "uplink":
        return [f"Uplink {v.replace(' up', ' active').replace(' down', ' down')}".replace("Uplink port", "Uplink port")]
    if k == "gear_ports":
        return [f"Ports to other units: {v}"] if ok else [p_.strip().capitalize() for p_ in v.split(";")]
    if k == "port_errors":
        return ["No port errors in the last hour"] if ok else [f"Port errors: {v}"]
    if k == "poe":
        return [f"PoE: {v}" + ("" if ok else " (nearly full)")]
    if k == "fan":
        return [f"Fan: {v}"]
    if k == "fault":
        return ["Fault light off"] if ok else [f"Fault light {v}"]
    if k == "firmware":
        m = re.match(r"(\S+).*most [a-z ]+ have (\S+)", v)
        return [f"Firmware {m.group(1)} (others {m.group(2)})"] if ok is False and m else [f"Firmware: {v.split(' ')[0]}"]
    # The two checks of D-996 (24 Nov 2026: they had no short line, so with
    # DFS off the router's sentence read "Needs a Look: ." and neither showed
    # in its bucket's hover).
    if k == "backhaul":
        return ["Backhaul Mode: Wired Only" if ok else "Backhaul Mode: Automatic (set Wired Only)"]
    if k == "dfs":
        return ["5 GHz DFS: on" if ok else "5 GHz DFS: off (APs saved on channels 52-144 move)"]
    return []


def eh_radio_lines(checks):
    """The radios in a line or two: which are on, then any that aren't right."""
    radios = [ch for ch in checks if ch["key"].startswith("radio_")]
    on = [EH_BANDS[ch["key"][6:]].replace(" GHz", "") for ch in radios if "off:" not in str(ch["value"])]
    lines = []
    if on:
        lines.append("Radios on: " + (" and ".join(on) if len(on) <= 2 else ", ".join(on[:-1]) + " and " + on[-1]) + " GHz")
    for ch in radios:
        band = EH_BANDS[ch["key"][6:]]
        v = str(ch["value"])
        if "off:" in v:
            lines.append(f"{band} radio off")
        elif ch["ok"] is False and ": " in v:
            for note in v.split(": ", 1)[1].split("; "):
                lines.append(f"{band} " + note)
    return lines


def eh_look_history(c):
    if eh.get("look_hist") is None:
        eh["look_hist"] = eh_meta(c, EH_LOOK_KEY) or {}
        eh["look_dirty"] = False
    return eh["look_hist"]


# ------------------------------------------------------------
# UNIT HISTORY (owner, 23 Nov 2026): every change or blip of a unit is
# recorded quietly in unit_events, never announced one by one; the unit's
# popup shows a summary and its latest events, and a unit raises at most one
# item (its Needs a Look) when the summary crosses a limit. First user: the
# access points' radios (channel, width, power, 6 GHz puncturing), each with
# what the radio had, whether the router had just pushed settings to the AP
# (lastConfigTs: Firewalla moved it) and how busy the channel was. Kept 30
# days; the popup shows 7.
# ------------------------------------------------------------
EH_EVENTS_KEEP = 30 * 86400
EH_TEMP_STEP = 5               # a switch's temperature is recorded when it moves this many °C
EH_EVENTS_SHOWN = 7 * 86400
EH_PUSH_WINDOW = 300           # the router pushed settings this soon before a change (it may have caused it, not proof)
# Why a radio keeps changing channel, by band: radar rules (DFS) don't apply to 6 GHz.
EH_CHANNEL_WHY = {"6g": "likely your own access points on the same channel", "5g": "interference or radar", "2g": "interference"}


def eh_event(c, uid, unit, kind, band, before, after, detail, now):
    c.execute("INSERT INTO unit_events (at, unit_id, unit_name, unit_type, kind, band, before, after, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (now, uid, unit.get("name"), unit.get("type"), kind, band,
               None if before is None else str(before), None if after is None else str(after), json.dumps(detail or {})))


def eh_channel_pair(c, uid, band, since):
    """The two channels a radio moved between most since then ("37 ↔ 101"),
    when one pair makes up at least half of its moves."""
    pairs = Counter()
    for before, after in c.execute("SELECT before, after FROM unit_events WHERE unit_id=? AND band=? AND kind='channel' AND at>=?", (uid, band, since)):
        if before and after:
            pairs[tuple(sorted((before, after), key=lambda x: float(x)))] += 1
    if not pairs:
        return None
    (a, b), n = pairs.most_common(1)[0]
    return f"{a} ↔ {b}" if n >= 2 and n * 2 >= sum(pairs.values()) else None


def eh_air(band, channel, width):
    """The stretch of air a radio uses, in MHz (low, high), from its channel
    and width: 20 MHz channels 5 MHz apart; wider ones in fixed blocks (6 GHz
    from 5945 MHz; 5 GHz from 5170, and from 5735 for 149 and up)."""
    try:
        n, w = float(channel), float(width or 20)
    except (TypeError, ValueError):
        return None
    if band == "2g":
        f = 2407 + 5 * n
        return (f - w / 2, f + w / 2)
    f = (5950 if band == "6g" else 5000) + 5 * n
    base = 5945 if band == "6g" else (5735 if n >= 149 else 5170)
    low = base + (f - base) // w * w
    return (low, low + w)


def eh_share_air(band, a, b):
    x, y = eh_air(band, *a), eh_air(band, *b)
    return bool(x and y and x[0] < y[1] and y[0] < x[1])


def eh_radio_history(c, now):
    """Each access point's radio history for its popup: per band a summary
    and the latest events (7 days)."""
    since = now - EH_EVENTS_SHOWN
    began = eh_meta(c, "unit_events_since") or 0
    quiet = f"no changes since recording began {datetime.fromtimestamp(began).strftime('%d %b %H:%M')}" if began > since else "no changes in 7 days"
    radios_now = eh.get("radios_now") or {}
    out = {}
    rows = c.execute("SELECT * FROM unit_events WHERE at>=? AND kind IN ('channel','width','power','puncture') ORDER BY at DESC", (since,)).fetchall()
    by_unit = {}
    for r in rows:
        by_unit.setdefault(r["unit_id"], []).append(r)
    for uid, now_radios in radios_now.items():
        events = by_unit.get(uid, [])
        bands = []
        for band, label in EH_BANDS.items():
            live = now_radios.get(band)
            if not live:
                continue
            mine = [r for r in events if r["band"] == band]
            moves = [r for r in mine if r["kind"] == "channel"]
            day = [r for r in moves if r["at"] >= now - 86400]
            lines = []
            if not mine:
                lines.append(quiet)
            else:
                lines.append(f"{len(day)} channel change{'s' if len(day) != 1 else ''} in 24 h, {len(moves)} in 7 days")
                pair = eh_channel_pair(c, uid, band, since)
                if pair:
                    lines.append(f"mostly {pair}")
                if len(moves) >= 3:
                    hours = Counter(datetime.fromtimestamp(r["at"]).hour // 2 * 2 for r in moves)
                    h, n = hours.most_common(1)[0]
                    if n >= 2 and n * 3 >= len(moves):
                        lines.append(f"busiest {h:02d}:00-{h + 2:02d}:00 ({n} of {len(moves)})")
                pushed = sum(bool(json.loads(r["detail"] or "{}").get("pushed")) for r in moves)
                if moves:
                    # Only that a push came just before, not who moved it (owner, 23 Nov
                    # 2026: his own change in the app pushed settings to every AP).
                    lines.append("all right after a settings push" if pushed == len(moves)
                                 else "none after a settings push" if not pushed
                                 else f"{pushed} of {len(moves)} right after a settings push")
            shares = sorted(radios_now[o]["name"] for o in radios_now if o != uid and radios_now[o].get(band)
                            and eh_share_air(band, (live["channel"], live["width"]), (radios_now[o][band]["channel"], radios_now[o][band]["width"])))
            bands.append({"band": band, "label": label, "channel": live["channel"], "width": live["width"], "power": live["power"],
                          "lines": lines, "shares": shares, "why": EH_CHANNEL_WHY.get(band)})
        out[uid] = {"bands": bands, "events": [{"at": r["at"], "band": r["band"], "kind": r["kind"], "before": r["before"], "after": r["after"],
                                                **eh_radio_event_detail(r)} for r in events[:10]], "total": len(events)}
    return out


EH_USE_BUSY_SINCE = 1795518753   # 24 Nov 2026 05:12 (D-989): a radio event saved from here holds the busy share; before, Firewalla's free share


def eh_radio_event_detail(r):
    """A saved radio event's details, its Channel Use as the busy share
    whenever it was saved (24 Nov 2026: events from before the turn-round
    showed the free share in the same column, 95% beside 5%)."""
    detail = json.loads(r["detail"] or "{}")
    use = safe_number(detail.get("use"))
    if use is not None and r["at"] < EH_USE_BUSY_SINCE:
        detail["use"] = round(max(0, min(100, 100 - use)))
    return detail


# ------------------------------------------------------------
# AP NEIGHBOURS (owner, 23 Nov 2026, Wi-Fi Radios page): which access points
# cover the same area, learned from clients roaming. A client seen on one AP
# and, within WIFI_ROAM_GAP, on another means the two overlap. Kept 7 days
# in the health database's meta ("wifi_roams": [[time, from AP, to AP]]),
# saved every 10 minutes; published as state["wifi_neighbours"].
# ------------------------------------------------------------
WIFI_ROAM_GAP = 120
WIFI_ROAM_KEEP = 7 * 86400
WIFI_ROAM_MAX = 50000
wifi_roam = {"last": {}, "log": None, "since": None, "saved": 0}


def wifi_roams_note(stations, now):
    if wifi_roam["log"] is None:
        with eh_lock, eh_db() as c:
            wifi_roam["log"] = eh_meta(c, "wifi_roams") or []
            wifi_roam["since"] = eh_meta(c, "wifi_roams_since")
            if wifi_roam["since"] is None:
                wifi_roam["since"] = now
                eh_meta(c, "wifi_roams_since", now)
    last, log = wifi_roam["last"], wifi_roam["log"]
    for mac, st in stations.items():
        ap = st.get("ap_id")
        if not ap:
            continue
        was = last.get(mac)
        if was and was[0] != ap and now - was[1] <= WIFI_ROAM_GAP:
            log.append([round(now), was[0], ap, str(mac).upper()])   # the client since 24 Nov 2026 (D-992)
        last[mac] = [ap, now]
    if log and (log[0][0] < now - WIFI_ROAM_KEEP or len(log) > WIFI_ROAM_MAX):
        log[:] = [x for x in log if x[0] >= now - WIFI_ROAM_KEEP][-WIFI_ROAM_MAX:]
    if now - wifi_roam["saved"] >= 600:
        with eh_lock, eh_db() as c:
            eh_meta(c, "wifi_roams", log)
        wifi_roam["saved"] = now
    # Moving and fixed clients (owner, 24 Nov 2026, D-992): a phone, tablet
    # or laptop carried about shows which APs meet along the way; a fixed
    # client (camera, plug, Echo, TV) that flips between two APs sits where
    # both reach it about equally, the stronger sign of overlap, so its roams
    # weigh double in the plan. Roams logged before 24 Nov have no client:
    # in the total only, weight 1.
    moving = wifi_moving_macs()
    names = {str(d.get("mac") or "").upper(): d.get("name") for d in state.get("devices") or []}
    pairs = {}
    for x in log:
        k = "|".join(sorted((x[1], x[2])))
        p = pairs.setdefault(k, {"roams": 0, "moving": 0, "fixed": 0, "last": 0, "clients": Counter()})
        p["roams"] += 1
        p["last"] = max(p["last"], x[0])
        if len(x) > 3:
            p["moving" if x[3] in moving else "fixed"] += 1
            if x[3] not in moving:
                p["clients"][x[3]] += 1
    for p in pairs.values():
        p["weight"] = p["roams"] + p["fixed"]
        p["flippers"] = [{"mac": m, "name": names.get(m) or m, "roams": n} for m, n in p.pop("clients").most_common(3) if n >= WIFI_FLIP_MIN]
    state["wifi_neighbours"] = {"since": wifi_roam["since"], "split_since": wifi_roam_split_since(log), "roams": len(log), "pairs": pairs}


# ------------------------------------------------------------
# A DAY OF SIGNAL PER RADIO (owner, 24 Nov 2026, D-1005): the Wi-Fi Radios
# power advice judged on the last 24 hours, not one moment (it proposed 3 dB
# less on every look: AP7 Sm Garage 18, 15, then 12). Per AP and band, each
# hour's weakest client signal and the clients seen; and when the radio's TX
# power last changed (the advice waits 24 h after). Kept 48 hours in the
# health database's meta ("wifi_signal"), saved every 10 minutes; published
# as state["wifi_power"]: "ap|band" -> {weakest, clients, hours, changed_at,
# weakest_fixed, clients_fixed}. The fixed clients' weakest is kept apart
# (24 Nov 2026): a phone carried out of range is the day's weakest signal on
# almost every radio, and it held the power up everywhere.
# ------------------------------------------------------------
WIFI_SIGNAL_KEEP = 48 * 3600
wifi_signal = {"data": None, "saved": 0, "moving": set(), "moving_at": 0}


def wifi_power_changed(key):
    """When this radio's ("ap|band") TX power last changed; None when it
    hasn't since the dashboard first saw it."""
    return (((wifi_signal["data"] or {}).get("power") or {}).get(key) or {}).get("changed_at")


def wifi_signal_note(stations, now):
    if wifi_signal["data"] is None:
        with eh_lock, eh_db() as c:
            wifi_signal["data"] = eh_meta(c, "wifi_signal") or {"hours": {}, "power": {}, "since": now}
    d = wifi_signal["data"]
    if now - wifi_signal["moving_at"] >= 60:   # who counts as moving: read once a minute
        wifi_signal["moving"], wifi_signal["moving_at"] = wifi_moving_macs(), now
    moving = wifi_signal["moving"]
    hour = str(int(now // 3600 * 3600))
    bucket = d["hours"].setdefault(hour, {})
    for mac, st in stations.items():
        ap, band, rssi = st.get("ap_id"), st.get("band"), safe_number(st.get("rssi"))
        if not ap or not band or rssi is None:
            continue
        slot = bucket.setdefault(f"{ap}|{band}", {"min": rssi, "macs": []})
        slot["min"] = min(slot["min"], rssi)
        if str(mac).upper() not in moving:
            slot["min_fixed"] = min(slot.get("min_fixed", rssi), rssi)
        if mac not in slot["macs"]:
            slot["macs"].append(mac)
    for h in [h for h in d["hours"] if int(h) < now - WIFI_SIGNAL_KEEP]:
        del d["hours"][h]
    # Power changes: each radio's live TX power against the last one seen.
    for uid, a in (state.get("access_points") or {}).items():
        for band, r in (a.get("radios_live") or {}).items():
            p = (r or {}).get("tx_power")
            if p is None:
                continue
            key, was = f"{uid}|{band}", d["power"].get(f"{uid}|{band}")
            if not was or was.get("power") != p:
                d["power"][key] = {"power": p, "changed_at": now if was else None}
    if now - wifi_signal["saved"] >= 600:
        with eh_lock, eh_db() as c:
            eh_meta(c, "wifi_signal", d)
        wifi_signal["saved"] = now
    out = {}
    for h, slots in d["hours"].items():
        if int(h) < now - 86400:
            continue
        for key, slot in slots.items():
            o = out.setdefault(key, {"weakest": slot["min"], "macs": set(), "hours": 0, "fixed": None})
            o["weakest"] = min(o["weakest"], slot["min"])
            o["macs"].update(slot["macs"])
            o["hours"] += 1
            if slot.get("min_fixed") is not None:   # hours saved before 24 Nov 2026 have none
                o["fixed"] = slot["min_fixed"] if o["fixed"] is None else min(o["fixed"], slot["min_fixed"])
    covered = min(24, (now - d["since"]) / 3600)
    state["wifi_power"] = {"covered_hours": round(covered, 1), "radios": {
        key: {"weakest": o["weakest"], "clients": len(o["macs"]), "hours": o["hours"],
              "weakest_fixed": o["fixed"], "clients_fixed": sum(1 for m in o["macs"] if str(m).upper() not in moving),
              "changed_at": (d["power"].get(key) or {}).get("changed_at")} for key, o in out.items()},
        "changed": {key: v.get("changed_at") for key, v in d["power"].items() if v.get("changed_at")}}


# ------------------------------------------------------------
# CLIENT HOMES (owner, 24 Nov 2026, D-1010): which AP should serve each
# fixed Wi-Fi client (not phones, tablets or laptops: wifi_moving_macs).
# Each minute, per client and radio ("ap|band") it is on: an hour's
# minutes, RSSI and SNR (sums), and the hour's AP switches. 7 days, in the
# health database's meta ("client_homes"), saved every 10 minutes.
#   home       the radio with the best typical RSSI among those it spent an
#              hour or more on (a tie: the one it spent longest on)
#   bouncing   4 or more switches in the last 24 hours between 2 or more APs
#              it spent 30 minutes or more on: a Client Fixes row (block the
#              other AP when home is 6 dB or more better; else it sits
#              between them)
#   moved      a lasting change, not back and forth (client_home_changed):
#              it now lives on an AP it has spent under an hour on in the 7
#              days kept, or on its home radio with a typical signal 10 dB
#              or more from before (counted from that radio's last TX power
#              change). Judged over the last 6 hours (on one AP 80% of the
#              time, 2 switches or fewer), and over the first 30 minutes
#              back after 30 minutes off (on one AP 80% of that time): never
#              on one reading, and not when the dashboard itself wasn't
#              looking (24 Nov 2026). Or the owner's Moved button. Its
#              history starts again from the move (earlier hours are
#              ignored) and it is Reassessing for 3 days: no fix, not
#              counted for power.
#   learned    a client with 3 days of data since it started or moved.
# Published as state["client_homes"]: fixes, reassessing, per radio its
# intended clients (home there, learned) with their weakest typical
# signal since that radio's last TX power change, and per AP its fixed
# clients and how many were steady (no switch in 24 h).
# The collector's minute pass and the Moved button change the same data:
# both hold client_homes_lock.
# ------------------------------------------------------------
HOME_KEEP = 7 * 86400
HOME_LEARN = 3 * 86400
HOME_EVERY = 60
HOME_MOVE_WINDOW = 6 * 3600
HOME_BACK_OFF = 30 * 60      # off this long, then back: a move is looked for
HOME_BACK_JUDGE = 30 * 60    # ...over its first minutes back
HOME_HOLE = 5 * 60           # no pass at all for this long: the dashboard wasn't looking (a restart, the controller silent)
client_homes = {"data": None, "saved": 0, "sampled": 0}
client_homes_lock = threading.Lock()


def client_homes_load():
    if client_homes["data"] is None:
        with eh_lock, eh_db() as c:
            client_homes["data"] = eh_meta(c, "client_homes") or {"since": time.time(), "clients": {}}
    return client_homes["data"]


def client_home_profile(rec, start, end=None):
    """Per radio over the hours from start (to end): minutes, mean RSSI and SNR."""
    out = {}
    for h, radios in rec["hours"].items():
        if int(h) < start or (end is not None and int(h) >= end):
            continue
        for key, (n, rs, ss) in radios.items():
            o = out.setdefault(key, [0, 0.0, 0.0])
            o[0] += n
            o[1] += rs
            o[2] += ss
    return {k: {"minutes": n, "rssi": round(rs / n, 1), "snr": round(ss / n, 1)} for k, (n, rs, ss) in out.items() if n}


def client_home_of(profile, least=60):
    able = [(k, v) for k, v in profile.items() if v["minutes"] >= least]
    if not able:
        return None
    return max(able, key=lambda kv: (kv[1]["rssi"], kv[1]["minutes"]))[0]


def client_home_moved(rec, mac, now, how):
    rec["moved_at"], rec["moved_how"] = now, how
    rec.pop("back", None)


def client_home_changed(rec, key, rssi, start, before, now):
    """Has a fixed client that now lives on this radio (key), at this typical
    signal, changed places? Its history is read up to the hour `before`.
    - An access point it hasn't lived on: under an hour on it in everything
      kept (7 days), what an earlier move set aside included. An AP it has
      lived on is back and forth, not a move (a client that is off each
      night and comes back on either of two APs was Reassessing every
      morning, so it never got a home).
    - Its home radio, its typical signal 10 dB or more from before. Before
      = since that radio's TX power last changed (a power change shifts
      every client's signal: those aren't moves); with nothing since, there
      is nothing to compare.
    False while it has lived nowhere for an hour yet."""
    lived = {}
    for k, v in client_home_profile(rec, now - HOME_KEEP, before).items():
        lived[k.split("|")[0]] = lived.get(k.split("|")[0], 0) + v["minutes"]
    if not any(minutes >= 60 for minutes in lived.values()):
        return False
    if lived.get(key.split("|")[0], 0) < 60:
        return True
    if key != client_home_of(client_home_profile(rec, start, before)):
        return False
    changed = wifi_power_changed(key)
    since = max(start, int(-(-changed // 3600) * 3600) if changed else 0)   # the whole hours after a power change
    was = client_home_profile(rec, since, before).get(key)
    return bool(was and was["minutes"] >= 60 and abs(was["rssi"] - rssi) >= 10)


def client_homes_note(stations, now):
    if now - client_homes["sampled"] < HOME_EVERY:
        return
    client_homes["sampled"] = now
    with client_homes_lock:
        d = client_homes_load()
        # The last pass was long ago: the dashboard wasn't looking (a restart,
        # the controller silent), so a client's gap says nothing about it.
        hole = now - (d.get("sampled_at") or 0) > HOME_HOLE
        d["sampled_at"] = now
        moving = wifi_moving_macs()
        gear = {str(m).upper() for m in state.get("access_points") or {}}
        hour = str(int(now // 3600 * 3600))
        for mac, st in stations.items():
            mac = str(mac).upper()
            if mac in moving or mac in gear:
                continue
            ap, band, rssi, snr = st.get("ap_id"), st.get("band"), safe_number(st.get("rssi")), safe_number(st.get("snr"))
            if not ap or not band or rssi is None:
                continue
            key = f"{ap}|{band}"
            rec = d["clients"].setdefault(mac, {"hours": {}, "switches": {}, "last_ap": None, "last_seen": None, "moved_at": None, "moved_how": None, "since": now})
            gap = now - (rec["last_seen"] or now)
            if rec["last_ap"] and rec["last_ap"] != ap and (gap < HOME_BACK_OFF or hole):
                rec["switches"][hour] = rec["switches"].get(hour, 0) + 1
            # Back after 30 minutes off: whether it moved is judged on its
            # first 30 minutes back (below), not on this one reading.
            if gap >= HOME_BACK_OFF and not hole:
                rec["back"] = {"at": now, "radios": {}}
            if rec.get("back"):
                tally = rec["back"]["radios"].setdefault(key, [0, 0.0])
                tally[0] += 1
                tally[1] += rssi
            slot = rec["hours"].setdefault(hour, {}).setdefault(key, [0, 0.0, 0.0])
            slot[0] += 1
            slot[1] += rssi
            slot[2] += snr if snr is not None else 0
            rec["last_ap"], rec["last_seen"] = ap, now
        # Back for 30 minutes: on one AP 80% of that time, and somewhere new?
        for mac, rec in d["clients"].items():
            back = rec.get("back")
            if not back or now - back["at"] < HOME_BACK_JUDGE:
                continue
            rec.pop("back")
            total = sum(n for n, _ in back["radios"].values())
            if total < 0.5 * HOME_BACK_JUDGE / HOME_EVERY:
                continue   # seen under half of that time: off again, nothing to judge
            key, (n, signal) = max(back["radios"].items(), key=lambda kv: kv[1][0])
            start = max(rec.get("moved_at") or 0, rec.get("since") or 0, now - HOME_KEEP)
            if n >= 0.8 * total and client_home_changed(rec, key, signal / n, start, int(back["at"] // 3600 * 3600), now):
                client_home_moved(rec, mac, back["at"], "auto")
        # Lasting changes seen over the last 6 hours (once an hour per client
        # is enough). The window is whole hours, as the readings are kept by
        # the hour: 6 to 7 hours back (it was cut mid-hour, which left 5
        # hours of readings against a need for 80% of 6: it could hardly fire).
        if hour != d.get("checked_hour"):
            d["checked_hour"] = hour
            cut = int((now - HOME_MOVE_WINDOW) // 3600 * 3600)
            for mac, rec in d["clients"].items():
                start = max(rec.get("moved_at") or 0, rec.get("since") or 0, now - HOME_KEEP)
                if cut - start < 24 * 3600:
                    continue   # too little history before the window to compare with
                recent = client_home_profile(rec, cut)
                total = sum(v["minutes"] for v in recent.values())
                if total < 0.8 * (now - cut) / HOME_EVERY:
                    continue
                top = max(recent.items(), key=lambda kv: kv[1]["minutes"])
                sw = sum(n for h, n in rec["switches"].items() if int(h) >= cut)
                if top[1]["minutes"] >= 0.8 * total and sw <= 2 and client_home_changed(rec, top[0], top[1]["rssi"], start, cut, now):
                    client_home_moved(rec, mac, cut, "auto")
        for mac in list(d["clients"]):
            rec = d["clients"][mac]
            for part in ("hours", "switches"):
                for h in [h for h in rec[part] if int(h) < now - HOME_KEEP]:
                    del rec[part][h]
            if not rec["hours"] and (rec["last_seen"] or 0) < now - HOME_KEEP:
                del d["clients"][mac]
        if now - client_homes["saved"] >= 600:
            with eh_lock, eh_db() as c:
                eh_meta(c, "client_homes", d)
            client_homes["saved"] = now
        client_homes_publish(d, now)


def client_homes_publish(d, now):
    names = {str(x.get("mac") or "").upper(): x.get("name") for x in state.get("devices") or []}
    ap_names = {uid: a.get("name") for uid, a in (state.get("access_points") or {}).items()}
    apn = lambda key: ap_names.get(key.split("|")[0], key.split("|")[0])
    fixes, reassessing, intended, steady = [], [], {}, {}
    day = now - 86400
    for mac, rec in d["clients"].items():
        name = names.get(mac) or mac
        moved = rec.get("moved_at")
        start = max(moved or 0, rec.get("since") or 0, now - HOME_KEEP)
        if moved and now - moved < HOME_LEARN:
            reassessing.append({"mac": mac, "name": name, "moved_at": moved, "how": rec.get("moved_how"), "days": round((now - moved) / 86400, 1)})
            continue
        prof = client_home_profile(rec, start)
        home = client_home_of(prof)
        if not home:
            continue
        learned = now - start >= HOME_LEARN
        sw = sum(n for h, n in rec["switches"].items() if int(h) >= day)
        ap_home = home.split("|")[0]
        s = steady.setdefault(ap_home, {"fixed": 0, "steady": 0})
        s["fixed"] += 1
        s["steady"] += sw == 0
        if not learned:
            continue
        # Its typical signal on its home radio counts from the whole hours
        # after that radio's TX power last changed (24 Nov 2026: readings
        # from before the change stayed in, so the advice went on proposing
        # lower power). Under an hour since: not counted for power yet.
        changed = wifi_power_changed(home)
        typical = prof[home] if not changed or changed <= start else client_home_profile(rec, int(-(-changed // 3600) * 3600)).get(home)
        if typical and typical["minutes"] >= 60:
            i = intended.setdefault(home, {"clients": [], "weakest": None})
            i["clients"].append(name)
            i["weakest"] = typical["rssi"] if i["weakest"] is None else min(i["weakest"], typical["rssi"])
        today = client_home_profile(rec, int(day // 3600 * 3600))
        others = {k: v for k, v in today.items() if k.split("|")[0] != ap_home and v["minutes"] >= 30}
        if sw >= 4 and others:
            other = max(others.items(), key=lambda kv: kv[1]["minutes"])
            margin = prof[home]["rssi"] - prof.get(other[0], other[1])["rssi"]
            evidence = " · ".join(f"{apn(k)} {v['rssi']:.0f} dBm, SNR {v['snr']:.0f}, {v['minutes'] // 60} h {v['minutes'] % 60:02d} min"
                                  for k, v in sorted(prof.items(), key=lambda kv: -kv[1]["minutes"]))
            fixes.append({"mac": mac, "name": name, "home": apn(home), "home_id": ap_home, "also": [apn(k) for k in others],
                          "switches": sw, "fix": "block" if margin >= 6 else "between", "block": apn(other[0]),
                          "margin": round(margin, 1), "evidence": f"{evidence} · {sw} switches in 24 h"})
    state["client_homes"] = {"since": d["since"], "learned_days": round(max(0, min(3, (now - d["since"]) / 86400)), 1),
                             "fixes": sorted(fixes, key=lambda x: -x["switches"]), "reassessing": sorted(reassessing, key=lambda x: -x["moved_at"]),
                             "intended": intended, "steady": steady}


@app.post("/api/client-moved")
def api_client_moved(payload: dict = Body(default={})):
    """The owner's Moved button (D-1010): {mac}: reassess it from now."""
    mac = Fields(payload).mac("mac")
    if not mac:
        return {"ok": False, "error": "Unknown client"}
    if mac in wifi_moving_macs():
        return {"ok": False, "error": "Not followed: it counts as a moving client (phone, tablet or laptop in its name or group), so it has no home AP"}
    now = time.time()
    with client_homes_lock:
        d = client_homes_load()
        # One not seen on Wi-Fi yet is kept as seen now (it was made, answered
        # as saved, and removed again by the next minute's clean-up).
        rec = d["clients"].setdefault(mac, {"hours": {}, "switches": {}, "last_ap": None, "last_seen": now, "moved_at": None, "moved_how": None, "since": now})
        client_home_moved(rec, mac, now, "owner")
        with eh_lock, eh_db() as c:
            eh_meta(c, "client_homes", d)
        client_homes_publish(d, now)
    return {"ok": True}


WIFI_FLIP_MIN = 5   # a fixed client this many times between one pair: named
WIFI_MOVING = re.compile(r"phone|tablet|ipad|\btab\b|tab s\d|laptop|macbook", re.I)


def wifi_moving_macs():
    """Clients carried about: a name, or a group name, with phone, tablet,
    iPad, Tab or laptop in it (D-992)."""
    out = set()
    for g in (state.get("groups") or {}).get("groups") or []:
        if WIFI_MOVING.search(str(g.get("name") or "")):
            out |= {str(m).upper() for m in g.get("members") or []}
    for d in state.get("devices") or []:
        if WIFI_MOVING.search(str(d.get("name") or "")):
            out.add(str(d.get("mac") or "").upper())
    return out


def wifi_roam_split_since(log):
    return next((x[0] for x in log if len(x) > 3), None)


# ------------------------------------------------------------
# ACKNOWLEDGE A NEEDS A LOOK (owner, 23 Nov 2026): the unit turns grey on
# every page ("Acknowledged"), leaves the banner, Needs You and the counts,
# and turns yellow again only when another check fails. Once the condition
# clears by itself the acknowledgement goes, so the next time is fresh.
# Kept in the health database's meta ("look_acks": {unit: {at, keys}}).
# Each failing check also says how it clears.
# ------------------------------------------------------------
EH_CLEARS = {
    "radio": f"clears by itself once each radio changes channel fewer than {EH_CHANNEL_LIMIT} times in 24 h",
    "speed": "clears when its cable runs at its best speed again",
    "flaps": "clears after an hour with fewer drops",
    "mesh": "clears when the mesh signal is -70 dBm or better",
    "ssids": "clears when every network is broadcasting again",
    "firmware": "clears when its firmware matches the others",
    "cpu": "clears when the CPU is less busy", "memory": "clears when more memory is free",
    "storage": "clears when more storage is free", "temperature": "clears when it cools down",
    "backhaul": "clears when its Backhaul Mode is Wired Only again",
    "dfs": "clears when 5 GHz DFS is on again",
}


def eh_acks(c=None):
    if eh.get("look_acks") is None:
        if c is None:
            with eh_db() as c2:
                eh["look_acks"] = eh_meta(c2, "look_acks") or {}
        else:
            eh["look_acks"] = eh_meta(c, "look_acks") or {}
    return eh["look_acks"]


# ------------------------------------------------------------
# PLANNED WORK (owner, 23 Nov 2026, to-do item 2; D-912): before working on
# the network you say so, for one unit or for the whole network, for 30
# minutes, 1 hour or 2 hours. Meanwhile the unit (every unit, for the whole
# network) is grey "Planned Work" on every page and raises nothing (no alert,
# email, Needs You or menu *); for the whole network the internet alerts
# pause too (assistant.py). Our checks still run and are recorded: the
# verdict keeps its checklist, Planned Work's start and end go in the unit's
# History (the router's for the whole network) and an incident that starts
# meanwhile gets the cause Planned Work and stays Quiet. It ends by itself
# (or with End Now); a unit still down afterwards is judged as usual.
# Kept in the health database's meta "planned_work": {"network": {at, until}
# or None, "units": {uid: {at, until}}, "past": [{scope, at, until}] 30 days}.
# ------------------------------------------------------------
EH_PLANNED_MINUTES = (30, 60, 120)
EH_PLANNED_KEEP = 30 * 86400


def eh_planned(c=None):
    if eh.get("planned") is None:
        if c is None:
            with eh_db() as c2:
                eh["planned"] = eh_meta(c2, "planned_work") or {}
        else:
            eh["planned"] = eh_meta(c, "planned_work") or {}
        for key, empty in (("network", None), ("units", {}), ("past", [])):
            eh["planned"].setdefault(key, empty)
    return eh["planned"]


def eh_planned_for(uid, now):
    """The Planned Work covering this unit now (its own or the whole network's), or None."""
    p = eh_planned()
    for scope, rec in (("unit", p["units"].get(uid)), ("network", p["network"])):
        if rec and rec["until"] > now:
            return {**rec, "scope": scope}
    return None


def eh_planned_during(uid, at):
    """Planned Work (now or in the last 30 days) that covered this unit at that time."""
    p = eh_planned()
    # No whole-network Planned Work is the usual case: p["network"] is None
    # then, and must not be unpacked (24 Nov 2026: it was, so every
    # assessment failed and the health worker stopped at each start).
    spans = p["past"] + ([{"scope": "network", **p["network"]}] if p["network"] else []) \
        + ([{"scope": uid, **p["units"][uid]}] if uid in p["units"] else [])
    return next((s for s in spans if s["scope"] in ("network", uid) and s["at"] <= at < s["until"]), None)


def eh_planned_end(c, scope, rec, end, how):
    """Planned Work over: into the 30-day list, and an end event in the History."""
    p = eh_planned(c)
    p["past"] = [s for s in p["past"] if s["until"] >= end - EH_PLANNED_KEEP] + [{"scope": scope, "at": rec["at"], "until": end}]
    uid = ROUTER_UID if scope == "network" else scope
    eh_event(c, uid, eh["units"].get(uid) or {"name": uid}, "planned", None, "on", "off",
             {"scope": "network" if scope == "network" else "unit", "ended": how}, end)


def eh_planned_publish(c, now):
    """Ends what ran out; state["planned_work"] for the pages and the alerts."""
    p = eh_planned(c)
    changed = False
    for uid, rec in list(p["units"].items()):
        if rec["until"] <= now:
            p["units"].pop(uid)
            eh_planned_end(c, uid, rec, rec["until"], "by itself")
            changed = True
    if p["network"] and p["network"]["until"] <= now:
        rec, p["network"] = p["network"], None
        eh_planned_end(c, "network", rec, rec["until"], "by itself")
        changed = True
    if changed:
        eh_meta(c, "planned_work", p)
    state["planned_work"] = {"network": p["network"], "minutes": list(EH_PLANNED_MINUTES),
                             "units": {u: {**r, "name": (eh["units"].get(u) or {}).get("name") or u} for u, r in p["units"].items()}}


def eh_planned_apply(c, uid, unit, now):
    """After a verdict is made (and any acknowledgement): grey Planned Work
    while it covers the unit; the checks underneath stay as they are."""
    rec = eh_planned_for(uid, now)
    if not rec:
        return
    v = unit["verdict"]
    under = v.get("raw") or v["state"]
    until = datetime.fromtimestamp(rec["until"]).strftime("%H:%M")
    v.update(raw=under, state="planned", word="Planned Work", planned_until=rec["until"], planned_scope=rec["scope"],
             sentence=f"Planned Work until {until}" + (" (whole network)" if rec["scope"] == "network" else "")
             + ("." if under == "healthy" else f"; meanwhile our checks say: {v['sentence']}"))
    for b in v.get("buckets") or []:
        if b["state"] in ("warn", "bad", "acked"):
            b["state"], b["word"] = "acked", "Planned Work"


def eh_ack_apply(c, uid, unit, now):
    """After a verdict is made: its failing checks, how they clear, and an
    acknowledgement that still covers them (state "acked")."""
    v = unit["verdict"]
    # The checks that make a unit Needs a Look (the router's are all of its
    # checks). Not the others (24 Nov 2026: Firewalla's own label failing
    # during a routine check-in counted as "another check", so an
    # acknowledged unit turned yellow again each time).
    looked = v["checks"] if unit.get("type") == "router" else [ch for ch in v["checks"] if ch.get("look")]
    keys = sorted({ch["key"] for ch in looked if ch["ok"] is False})
    unit["look_keys"] = keys
    hints = [EH_CLEARS.get(k.split("_")[0]) for k in keys]
    v["clears"] = "; ".join(dict.fromkeys(h for h in hints if h)) if v["state"] == "look" else ""
    acks = eh_acks(c)
    a = acks.get(uid)
    if not a:
        return
    if v["state"] != "look":
        # Cleared by itself only when none of the checks it covered still fail:
        # after a restart every unit reads Healthy for its first 30 s (the
        # Needs a Look hold) while those checks already fail again (23 Nov
        # 2026: a rebuild dropped the owner's three acknowledgements). Nor
        # when nothing was checked this time: the controller stopped listing
        # the unit for a moment, which says nothing about what it covered.
        if looked and not set(keys) & set(a.get("keys") or []):
            acks.pop(uid, None)      # the next time is fresh
            eh_meta(c, "look_acks", acks)
        return
    if set(keys) <= set(a.get("keys") or []):
        at = datetime.fromtimestamp(a["at"]).strftime("%d %b %H:%M")
        v.update(raw="look", state="acked", word="Acknowledged", acked=a["at"],
                 sentence=v["sentence"].replace("Needs a Look: ", f"Needs a Look, acknowledged {at}: ", 1))
        for b in v["buckets"]:
            if b["state"] == "warn":
                b["state"], b["word"] = "acked", "Acknowledged"


def eh_unit_history(c, now):
    """Each unit's other history for its popup (23 Nov 2026): cable drops,
    speed changes, mesh signal going weak, restarts and firmware updates in
    the last 7 days, as summary lines, and the latest 10 events."""
    since = now - EH_EVENTS_SHOWN
    out = {}
    rows = c.execute("SELECT * FROM unit_events WHERE at>=? AND kind IN ('cable','speed','mesh','restart','firmware','port','poe','errors','fan','temperature',"
                     "'link','cloud','wan','failover','cpu','memory','planned') ORDER BY at DESC", (since,)).fetchall()
    by_unit = {}
    for r in rows:
        by_unit.setdefault(r["unit_id"], []).append(r)
    when = lambda t: datetime.fromtimestamp(t).strftime("%d %b %H:%M")
    for uid, events in by_unit.items():
        lines = []
        drops = [r for r in events if r["kind"] == "cable" and r["after"] == "down"]
        if drops:
            day = sum(r["at"] >= now - 86400 for r in drops)
            line = f"cable dropped {len(drops)} time{'s' if len(drops) != 1 else ''} in 7 days ({day} in 24 h), last {when(drops[0]['at'])}"
            if len(drops) >= 3:
                hours = Counter(datetime.fromtimestamp(r["at"]).hour // 2 * 2 for r in drops)
                h, n = hours.most_common(1)[0]
                if n >= 2 and n * 3 >= len(drops):
                    line += f", mostly {h:02d}:00-{h + 2:02d}:00"
            lines.append(line)
        speeds = [r for r in events if r["kind"] == "speed"]
        if speeds:
            low = min(float(r["after"]) for r in speeds)
            lines.append(f"cable speed changed {len(speeds)} time{'s' if len(speeds) != 1 else ''}, lowest {eh_speed(low)}")
        weak = [r for r in events if r["kind"] == "mesh" and json.loads(r["detail"] or "{}").get("weak")]
        if weak:
            lines.append(f"mesh signal went weaker than {EH_MESH_WEAK} dBm {len(weak)} time{'s' if len(weak) != 1 else ''}")
        # A switch's ports: each unit's port by name, the rest counted.
        downs = [r for r in events if r["kind"] == "port" and r["after"] == "down"]
        if downs:
            info = lambda r: json.loads(r["detail"] or "{}")
            named = Counter(info(r)["port"] + (f" ({info(r)['unit']})" if info(r).get("unit") else "") for r in downs if info(r).get("unit") or info(r).get("lan"))
            for label, n in named.most_common(4):
                lines.append(f"{label} went down {n} time{'s' if n != 1 else ''}")
            rest = [r for r in downs if not info(r).get("unit") and not info(r).get("lan")]
            if rest:
                lines.append(f"{len({info(r)['port'] for r in rest})} other port{'s' if len({info(r)['port'] for r in rest}) != 1 else ''} went down {len(rest)} time{'s' if len(rest) != 1 else ''} (clients switching off or asleep)")
        errs = [r for r in events if r["kind"] == "errors"]
        if errs:
            lines.append("errors started on " + ", ".join(sorted({json.loads(r["detail"] or "{}").get("port", "?") for r in errs})))
        poes = [r for r in events if r["kind"] == "poe"]
        if poes:
            lines.append(f"PoE changed {len(poes)} time{'s' if len(poes) != 1 else ''} on {len({json.loads(r['detail'] or '{}').get('port') for r in poes})} port{'s' if len({json.loads(r['detail'] or '{}').get('port') for r in poes}) != 1 else ''}")
        temps = [r for r in events if r["kind"] == "temperature"]
        if temps:
            lines.append(f"temperature between {min(min(float(r['before']), float(r['after'])) for r in temps):.0f} and {max(max(float(r['before']), float(r['after'])) for r in temps):.0f} °C")
        for r in [r for r in events if r["kind"] == "fan"][:1]:
            lines.append(f"fan {r['before']} → {r['after']} on {when(r['at'])}")
        # The router: its internet connections, traffic moving, its links, its load.
        moves = [r for r in events if r["kind"] == "failover"]
        if moves:
            lines.append(f"traffic moved {len(moves)} time{'s' if len(moves) != 1 else ''}, last {moves[0]['before']} → {moves[0]['after']} {when(moves[0]['at'])}")
        fails = Counter(json.loads(r["detail"] or "{}").get("wan", "?") for r in events if r["kind"] == "wan" and r["after"] != "working")
        for wan, n in fails.most_common():
            lines.append(f"{wan} stopped working {n} time{'s' if n != 1 else ''}")
        for kind, what in (("link", "the dashboard lost touch with it"), ("cloud", "Firewalla's cloud lost it")):
            n = sum(r["kind"] == kind and r["after"] in ("down", "offline") for r in events)
            if n:
                lines.append(f"{what} {n} time{'s' if n != 1 else ''}")
        for kind, what in (("cpu", f"CPU busy over {EH_ROUTER_BUSY}% for 5 minutes"), ("memory", "memory low")):
            n = sum(r["kind"] == kind and r["after"] in ("busy", "high") for r in events)
            if n:
                lines.append(f"{what} {n} time{'s' if n != 1 else ''}")
        plans = [r for r in events if r["kind"] == "planned" and r["after"] == "on"]
        if plans:
            lines.append(f"Planned Work {len(plans)} time{'s' if len(plans) != 1 else ''}, last {when(plans[0]['at'])}")
        boots = [r for r in events if r["kind"] == "restart"]
        if boots:
            lines.append(f"restarted {len(boots)} time{'s' if len(boots) != 1 else ''}, last {when(boots[0]['at'])}")
        for r in [r for r in events if r["kind"] == "firmware"][:1]:
            lines.append(f"firmware {r['before']} → {r['after']} on {when(r['at'])}")
        out[uid] = {"lines": lines, "total": len(events),
                    "events": [{"at": r["at"], "kind": r["kind"], "before": r["before"], "after": r["after"], **json.loads(r["detail"] or "{}")} for r in events[:10]]}
    return out


# ------------------------------------------------------------
# INTERNET CONNECTION HISTORY (owner, 23 Nov 2026, the unit history's last
# step): per connection, spells of packet loss and of slow answers, recorded
# quietly in unit_events as "WAN:<interface>" (one event when a spell ends:
# its start, minutes and worst value), from the Status history's minutes.
# Loss: the router's own ping test, on both connections. Latency: the
# dashboard's timed connections, so only the connection carrying traffic.
# Outages, failovers and speed tests have their own records (the WAN uptime
# recorder, the speed-test history); the Internet page joins them up.
# ------------------------------------------------------------
EH_WAN_LOSS = 0.10       # a minute losing 10% of the router's pings or more (its own alert limit; 1 of 10)
EH_WAN_SLOW_MS = 100     # a minute answering in 100 ms or more (usually under 20 ms)
EH_WAN_KEY = "wan_spells"


def eh_wan_spells(c, now):
    """Every 2 s with the verdicts; acts once per finished minute. The first
    run goes back over the 24 hours of minutes the Status history keeps."""
    import status as _status
    wans = (state.get("internet") or {}).get("wans") or {}
    if not wans or not _status.status_history.get("loaded"):
        return
    hist = eh_look_history(c).setdefault(EH_WAN_KEY, {})
    done = hist.get("done") or now - 86400
    if "since" not in hist:
        hist["since"] = done
    upto = (now - 5) // 60 * 60 - 60          # the last finished minute
    if upto <= done:
        return
    with _status.status_lock:
        minutes = sorted((int(k), dict(b)) for k, b in _status.status_history["minutes"].items() if done < int(k) <= upto)
    open_ = hist.setdefault("open", {})
    for at, b in minutes:
        in_use = b.get("in_use") or []
        for key, w in wans.items():
            unit = {"name": w.get("provider") or key, "type": "wan"}
            loss = (b.get("loss") or {}).get(key) or 0
            ms = b.get("ms") if in_use == [key] else None
            for kind, value, bad in (("loss", round(loss * 100), loss >= EH_WAN_LOSS), ("latency", ms, ms is not None and ms >= EH_WAN_SLOW_MS)):
                spell = open_.get(f"{kind}|{key}")
                if bad and spell and at - spell["last"] <= 60:
                    spell.update(last=at, worst=max(spell["worst"], value))
                    continue
                if spell:
                    eh_event(c, "WAN:" + key, unit, kind, None, None, spell["worst"],
                             {"start": spell["start"], "minutes": round((spell["last"] + 60 - spell["start"]) / 60), "wan": unit["name"]}, spell["last"] + 60)
                    open_.pop(f"{kind}|{key}")
                if bad:
                    open_[f"{kind}|{key}"] = {"start": at, "last": at, "worst": value}
    hist["done"] = upto
    eh["look_dirty"] = True


def eh_wan_events(key, since):
    """One connection's recorded spells since then, newest first, and since
    when they are recorded."""
    with eh_lock, eh_db() as c:
        rows = c.execute("SELECT * FROM unit_events WHERE unit_id=? AND at>=? ORDER BY at DESC", ("WAN:" + key, since)).fetchall()
        began = (eh_look_history(c).get(EH_WAN_KEY) or {}).get("since")
    return [{"at": r["at"], "kind": r["kind"], "worst": float(r["after"]), **json.loads(r["detail"] or "{}")} for r in rows], began


def eh_speed(mbps):
    return "--" if not mbps else f"{mbps / 1000:g} Gb/s" if mbps >= 1000 else f"{mbps:g} Mb/s"


def eh_look_checks(c, uid, unit, raw, norm, now):
    """Needs a Look checks for one access point, as checklist rows."""
    out = []
    add = lambda key, name, ok, value: out.append({"key": key, "name": name, "ok": ok, "value": value, "hard": False, "look": True})
    if not raw:
        return out   # the controller doesn't list it: nothing to judge
    hist = eh_look_history(c).setdefault(uid, {})
    def mark():
        eh["look_dirty"] = True
    # Its cable's speed, against the best this AP has had (its own port).
    primary = norm.get("primary_interface")
    eth = (raw.get("eths") or {}).get(primary) or {}
    speed = safe_number(eth.get("linkSpeed"))
    if str(raw.get("backhaul_state") or raw.get("backhaulState") or "").lower() == "ethernet" or eth.get("connected"):
        if speed and speed > (hist.get("best_speed") or 0):
            hist["best_speed"] = speed
            mark()
        # Unit history (23 Nov 2026): every change of its cable's speed.
        if speed and hist.get("last_speed") and speed != hist["last_speed"]:
            eh_event(c, uid, unit, "speed", None, f"{hist['last_speed']:g}", f"{speed:g}", {"port": primary}, now)
        if speed and speed != hist.get("last_speed"):
            hist["last_speed"] = speed
            mark()
        best = hist.get("best_speed")
        if speed:
            add("speed", "Cable Speed", not (best and speed < best),
                f"{eh_speed(speed)}" + (f", it has run at {eh_speed(best)}" if best and speed < best else " (its best)"))
        # Link flapping: its cable going down and up.
        up = eth.get("connected") is True
        if "link_up" in hist and hist["link_up"] != up:
            hist.setdefault("flaps", []).append(now)
            eh_event(c, uid, unit, "cable", None, "up" if hist["link_up"] else "down", "up" if up else "down", {"port": primary, "speed": speed}, now)
            mark()
        if hist.get("link_up") != up:
            hist["link_up"] = up
            mark()
        flaps = [t for t in hist.get("flaps") or [] if now - t <= 3600]
        if len(flaps) != len(hist.get("flaps") or []):
            hist["flaps"] = flaps
            mark()
        add("flaps", "Cable Steady", len(flaps) < EH_FLAP_LIMIT,
            "no drops in the last hour" if not flaps else f"went down or up {len(flaps)} time{'s' if len(flaps) != 1 else ''} in the last hour")
    elif norm.get("mesh_rssi") is not None:
        rssi = norm["mesh_rssi"]
        weak = rssi < EH_MESH_WEAK
        if "mesh_weak" in hist and hist["mesh_weak"] != weak:
            eh_event(c, uid, unit, "mesh", None, hist.get("mesh_rssi"), rssi, {"weak": weak}, now)
        if hist.get("mesh_weak") != weak:
            hist["mesh_weak"], hist["mesh_rssi"] = weak, rssi
            mark()
        add("mesh", "Mesh Signal", rssi >= EH_MESH_WEAK, f"{rssi} dBm" + ("" if rssi >= EH_MESH_WEAK else f", weaker than {EH_MESH_WEAK} dBm"))
    # Its radios: on, settings unchanged, channel settled.
    live = norm.get("radios_live") or {}
    radios = hist.setdefault("radios", {})
    # For the history: whether the router just pushed settings to it, how
    # busy each band is, and 6 GHz puncturing (parts of a wide channel
    # switched off because of interference; 0 = none).
    pushed_at = safe_number(raw.get("lastConfigTs"))
    pushed = bool(pushed_at and 0 <= now - pushed_at <= EH_PUSH_WINDOW)
    util = ap_air_busy(raw)
    pbits = {w.get("band"): w.get("pBitmap") for w in (raw.get("wifis") or {}).values() if isinstance(w, dict) and "pBitmap" in w}
    eh.setdefault("radios_now", {})[uid] = {"name": unit.get("name"), **{b: {"channel": r.get("channel"), "width": r.get("width_mhz"), "power": r.get("tx_power")}
                                                                    for b, r in live.items()}}
    for band, label in EH_BANDS.items():
        r, was = live.get(band), radios.get(band)
        if r is None:
            if was:
                add("radio_" + band, f"{label} Radio", False, "off: it isn't broadcasting")
            continue
        if not was:
            radios[band] = {"width": r.get("width_mhz"), "power": r.get("tx_power"), "channel": r.get("channel"), "changes": []}
            mark()
            was = radios[band]
        notes = []
        detail = {"channel": r.get("channel"), "width": r.get("width_mhz"), "power": r.get("tx_power"), "use": util.get(band), "pushed": pushed}
        for key, field, unit_ in (("width", "width_mhz", " MHz"), ("power", "tx_power", "")):
            if r.get(field) is not None and was.get(key) is not None and r.get(field) != was.get(key):
                eh_event(c, uid, unit, key, band, f"{was[key]:g}", f"{r[field]:g}", detail, now)
                was[key] = r.get(field)
                mark()
            elif was.get(key) is None and r.get(field) is not None:
                was[key] = r.get(field)
                mark()
        if r.get("channel") != was.get("channel"):
            was.setdefault("changes", []).append(now)
            if was.get("channel") is not None and r.get("channel") is not None:
                eh_event(c, uid, unit, "channel", band, f"{was['channel']:g}", f"{r['channel']:g}", detail, now)
            was["channel"] = r.get("channel")
            mark()
        if band in pbits and pbits[band] != was.get("pbitmap", pbits[band]):
            eh_event(c, uid, unit, "puncture", band, was.get("pbitmap"), pbits[band], detail, now)
        if band in pbits and pbits[band] != was.get("pbitmap"):
            was["pbitmap"] = pbits[band]
            mark()
        changes = [t for t in was.get("changes") or [] if now - t <= 86400]
        if len(changes) != len(was.get("changes") or []):
            was["changes"] = changes
            mark()
        if len(changes) >= EH_CHANNEL_LIMIT:
            pair = eh_channel_pair(c, uid, band, now - 86400)
            notes.append(f"changed channel {len(changes)} times in 24 h{', mostly ' + pair if pair else ''} ({EH_CHANNEL_WHY[band]})")
        add("radio_" + band, f"{label} Radio", not notes,
            f"channel {r.get('channel'):g}, {r.get('width_mhz') or '--'} MHz, power {r.get('tx_power') if r.get('tx_power') is not None else '--'}"
            + (": " + "; ".join(notes) if notes else ""))
    # Networks broadcasting (its own radios, not mesh): every network name it
    # has had is still on. "forwarding" = the radio is passing traffic.
    ssids_now = sorted({a.get("ssid") for a in (raw.get("aps") or {}).values()
                        if isinstance(a, dict) and a.get("mode") == "ap" and not a.get("mesh") and a.get("ssid")
                        and a.get("linkState") in (None, "forwarding")})
    known = hist.setdefault("ssids", [])
    for name in ssids_now:
        if name not in known:
            known.append(name)
            mark()
    # A name gone for a day was most likely taken off on purpose: forgotten.
    gone = hist.setdefault("ssid_gone", {})
    for name in list(known):
        if name in ssids_now:
            if gone.pop(name, None) is not None:
                mark()
        else:
            gone.setdefault(name, now)
            if now - gone[name] > 86400:
                known.remove(name)
                gone.pop(name, None)
                mark()
    # Backhaul Mode (D-996): Wired Only, or it keeps a standby 6 GHz link and
    # follows a neighbouring AP's channel (Firewalla support, 24 Nov 2026).
    mode = norm.get("backhaul_mode")
    if mode in ("automatic", "wired_only"):
        add("backhaul", "Backhaul Mode", mode == "wired_only",
            "Wired Only" if mode == "wired_only" else "Automatic: it follows a neighbouring AP's 6 GHz channel (set Wired Only)")
    if known:
        missing = [n for n in known if n not in ssids_now]
        add("ssids", "Networks Broadcasting", not missing,
            ", ".join(ssids_now) if not missing else f"{', '.join(missing)} not broadcasting" + (f" (on: {', '.join(ssids_now)})" if ssids_now else ""))
    # How busy its radio channels are (D-989: Firewalla's number is the free
    # share, turned round): shown, not judged yet. The 85-100% "on every AP"
    # of 22 Nov 2026 was the free share; no norm chosen since.
    util = ap_air_busy(raw)
    if util:
        add("airtime", "Channel Use", None, " · ".join(f"{EH_BANDS.get(b, b)} {util[b]}%" for b in ("2g", "5g", "6g") if b in util))
    # The unit itself: CPU (5 minutes over 80%), memory and storage left,
    # radio temperature (Firewalla's temperature level above 0).
    cpu = safe_number(raw.get("cpu"))
    if cpu is not None:
        ch = unit.setdefault("cpu_hist", [])
        ch.append((now, cpu))
        del ch[:-150]   # 5 minutes, 2 s apart
        busy = len(ch) >= 120 and min(x for _, x in ch) > EH_CPU_BUSY
        add("cpu", "CPU", not busy, f"{cpu:.0f}%" + (f", over {EH_CPU_BUSY}% for 5 minutes" if busy else ""))
    mem = safe_number(raw.get("freeMem"))
    if mem is not None:
        add("memory", "Memory Free", mem >= EH_FREE_LOW, f"{mem * 100:.0f}% free")
    disk = safe_number(raw.get("freeOverlayfs"))
    if disk is not None:
        add("storage", "Storage Free", disk >= EH_FREE_LOW, f"{disk * 100:.0f}% free")
    wifis = [w for w in (raw.get("wifis") or {}).values() if isinstance(w, dict) and w.get("temp") is not None]
    if wifis:
        hot = [w for w in wifis if (safe_number(w.get("tempLevel")) or 0) > 0]
        add("temperature", "Radio Temperature", not hot,
            " · ".join(f"{EH_BANDS.get(w.get('band'), w.get('band'))} {w['temp']} °C" for w in sorted(wifis, key=lambda w: str(w.get("band"))))
            + (": Firewalla says too warm" if hot else ""))
    # Firmware: the same as most of the other access points.
    versions = Counter(u.get("firmware") for o, u in eh["units"].items() if u.get("type") == "ap" and u.get("firmware") and u["label"] != EH_NOT_REPORTED)
    mine = unit.get("firmware")
    if mine and len(versions) > 1:
        common, n = versions.most_common(1)[0]
        add("firmware", "Firmware Like the Others", mine == common or versions[mine] >= n,
            f"{mine}" + ("" if mine == common or versions[mine] >= n else f"; most access points have {common}"))
    elif mine:
        add("firmware", "Firmware Like the Others", True, f"{mine} (all the same)")
    return out


EH_SW_HOT = 60                 # °C: a Switch X over this needs a look
EH_POE_FULL = 0.9              # share of the PoE budget in use
EH_PORT_ERRORS = 100           # error or discard frames on one port in an hour


def eh_switch_look_checks(c, uid, unit, raw, norm, now):
    """Needs a Look checks for one Switch X (22 Nov 2026, owner: the Switch X
    table): its uplink, its ports to other units and their errors, its PoE
    budget, fan, temperature, fault light and firmware."""
    out = []
    add = lambda key, name, ok, value: out.append({"key": key, "name": name, "ok": ok, "value": value, "hard": False, "look": True})
    if not raw:
        return out
    hist = eh_look_history(c).setdefault(uid, {})
    ports = {str(p.get("port")): p for p in raw.get("ports") or [] if isinstance(p, dict)}
    # Its uplink: the port STP calls root (the way to the router).
    root = next((p for p in ports.values() if ((p.get("stp") or {}).get("portRole") or "").lower() == "root"), None)
    if root:
        name, up, speed = root.get("port"), root.get("linkUp") is True, safe_number(root.get("linkSpeed"))
        if speed and speed > (hist.get("best_speed") or 0):
            hist["best_speed"] = speed
            eh["look_dirty"] = True
        # Unit history (23 Nov 2026): its uplink's speed changes.
        if speed and hist.get("last_speed") and speed != hist["last_speed"]:
            eh_event(c, uid, unit, "speed", None, f"{hist['last_speed']:g}", f"{speed:g}", {"port": f"port {name}"}, now)
        if speed and speed != hist.get("last_speed"):
            hist["last_speed"] = speed
            eh["look_dirty"] = True
        best = hist.get("best_speed")
        add("uplink", "Uplink Port", up, f"port {name} " + ("up" if up else "down"))
        if speed:
            add("speed", "Uplink Speed", not (best and speed < best),
                f"{eh_speed(speed)}" + (f", it has run at {eh_speed(best)}" if best and speed < best else " (its best)"))
        if "link_up" in hist and hist["link_up"] != up:
            hist.setdefault("flaps", []).append(now)
            eh_event(c, uid, unit, "cable", None, "up" if hist["link_up"] else "down", "up" if up else "down", {"port": f"port {name} (uplink)", "speed": speed}, now)
        hist["link_up"] = up
        flaps = [t for t in hist.get("flaps") or [] if now - t <= 3600]
        hist["flaps"] = flaps
        add("flaps", "Uplink Steady", len(flaps) < EH_FLAP_LIMIT,
            "no drops in the last hour" if not flaps else f"went down or up {len(flaps)} time{'s' if len(flaps) != 1 else ''} in the last hour")
    # Ports to other units (its other switches and APs): up. A port is one when
    # its own client list has an AP or another switch (Firewalla's own list
    # of equipment ports leaves some out: Switch X #2's APs on ports 3 and 4,
    # 22 Nov 2026). A port between switches sees the units behind it too, so
    # it is named by the switch; the uplink isn't one of these.
    aps = state.get("access_points") or {}
    sws = state.get("switches") or {}
    known_units = {**{str(k).upper(): a.get("name") for k, a in aps.items()}, **{str(k).upper(): w.get("name") for k, w in sws.items()}}
    gear, names = [], {}
    for p, info in ((norm.get("ports") or {}).items()):
        if root is not None and str(p) == str(root.get("port")):
            continue
        macs = {str(m).upper() for m in info.get("connected_macs") or []}
        on = [known_units[m] for m in macs if m in known_units and m != uid]
        if on:
            gear.append(str(p))
            switches_on = [known_units[m] for m in macs if m in sws and m != uid]
            names[str(p)] = ", ".join(sorted(switches_on or on))
    gear.sort(key=lambda x: int(x) if x.isdigit() else 0)
    # Remember them: a port to a unit that went down no longer lists it.
    # Forgotten after a day without it (the unit moved, or was taken away).
    was = hist.setdefault("gear_ports", {})
    for p in gear:
        if not isinstance(was.get(p), dict) or was[p].get("name") != names[p] or now - was[p].get("seen", 0) > 600:
            was[p] = {"name": names[p], "seen": now}
            eh["look_dirty"] = True
    for p, rec in list(was.items()):
        if not isinstance(rec, dict) or now - rec.get("seen", 0) > 86400:
            was.pop(p, None)
            eh["look_dirty"] = True
        elif p not in gear and p in ports:
            gear.append(p)
            names[p] = rec["name"]
    down = [p for p in gear if p in ports and ports[p].get("linkUp") is False]
    # Unit history (23 Nov 2026): each port going down and up (a unit's port
    # named by the unit), and each port's PoE starting or stopping.
    rec_up, rec_poe = hist.setdefault("ports_up", {}), hist.setdefault("ports_poe", {})
    for p, info in ports.items():
        if root is not None and p == str(root.get("port")):
            continue   # the uplink is recorded above
        up_now = info.get("linkUp") is True
        if p in rec_up and rec_up[p] != up_now:
            eh_event(c, uid, unit, "port", None, "up" if rec_up[p] else "down", "up" if up_now else "down",
                     {"port": f"port {p}", "unit": names.get(p) or (was.get(p) or {}).get("name"), "speed": safe_number(info.get("linkSpeed"))}, now)
        if rec_up.get(p) != up_now:
            rec_up[p] = up_now
            eh["look_dirty"] = True
        poe_now = info.get("poeStatus")
        if poe_now is not None:
            if p in rec_poe and rec_poe[p] != poe_now:
                eh_event(c, uid, unit, "poe", None, rec_poe[p], poe_now, {"port": f"port {p}", "unit": names.get(p) or (was.get(p) or {}).get("name")}, now)
            if rec_poe.get(p) != poe_now:
                rec_poe[p] = poe_now
                eh["look_dirty"] = True
    if gear:
        add("gear_ports", "Ports to Other Units", not down,
            f"{len(gear) - len(down)} of {len(gear)} up" if not down else "; ".join(f"port {p}" + (f" ({names[p]})" if names.get(p) else "") + " down" for p in down))
    # Errors and discards per port, over the last hour.
    errs = unit.setdefault("port_errors", {})
    noisy = []
    for p, info in ports.items():
        total = sum(safe_number(info.get(k)) or 0 for k in ("rxErrorFrames", "txErrorFrames", "rxDiscardFrames", "txDiscardFrames"))
        hist_p = errs.setdefault(p, [])
        if hist_p and total < hist_p[-1][1]:
            hist_p.clear()   # counters reset (a restart)
        if not hist_p or now - hist_p[-1][0] >= 60:
            hist_p.append((now, total))
        while hist_p and now - hist_p[0][0] > 3600:
            hist_p.pop(0)
        if len(hist_p) >= 2 and hist_p[-1][1] - hist_p[0][1] >= EH_PORT_ERRORS:
            noisy.append(f"port {p} {hist_p[-1][1] - hist_p[0][1]:.0f}")
    # Unit history: a port starting to have errors (and stopping).
    was_noisy, now_noisy = set(hist.get("noisy_ports") or []), {x.split()[1] for x in noisy}
    for p in now_noisy - was_noisy:
        n = next(x.split()[2] for x in noisy if x.split()[1] == p)
        eh_event(c, uid, unit, "errors", None, "0", n, {"port": f"port {p}"}, now)
    if now_noisy != was_noisy:
        hist["noisy_ports"] = sorted(now_noisy)
        eh["look_dirty"] = True
    add("port_errors", "Port Errors", not noisy, "none in the last hour" if not noisy else ", ".join(noisy) + " in the last hour")
    # PoE budget.
    used, budget = safe_number(norm.get("poe_used_watts")), safe_number(norm.get("poe_budget_watts"))
    if budget:
        delivering = sum(1 for p in ports.values() if p.get("poeStatus") == "delivering")
        add("poe", "PoE Budget", (used or 0) < budget * EH_POE_FULL,
            f"{used or 0:.1f} W of {budget:.0f} W" + (f" to {delivering} port{'s' if delivering != 1 else ''}" if delivering else ""))
    # The unit: fan, temperature, fault light, firmware like the other switches.
    st = raw.get("systemStatus") or {}
    fan = str(st.get("fanStatus") or norm.get("fan_status") or "")
    if fan:
        if hist.get("fan") and hist["fan"] != fan:
            eh_event(c, uid, unit, "fan", None, hist["fan"], fan, {}, now)
        if hist.get("fan") != fan:
            hist["fan"] = fan
            eh["look_dirty"] = True
        speed = st.get("fanSpeedPercentage")
        add("fan", "Fan", fan.lower() == "ok", f"{fan}" + (f", {speed}%" if speed is not None else ""))
    temp = safe_number(st.get("temperature") if st.get("temperature") is not None else norm.get("temperature"))
    if temp is not None:
        # Unit history: a step of 5 °C or more from the last one recorded.
        last_t = hist.get("temp_rec")
        if last_t is not None and abs(temp - last_t) >= EH_TEMP_STEP:
            eh_event(c, uid, unit, "temperature", None, f"{last_t:.0f}", f"{temp:.0f}", {"hot": temp > EH_SW_HOT}, now)
        if last_t is None or abs(temp - last_t) >= EH_TEMP_STEP:
            hist["temp_rec"] = temp
            eh["look_dirty"] = True
        add("temperature", "Temperature", temp <= EH_SW_HOT, f"{temp:.0f} °C" + (f", over {EH_SW_HOT} °C" if temp > EH_SW_HOT else ""))
    fault = str((raw.get("ledStatus") or {}).get("faultLED") or "")
    if fault:
        add("fault", "Fault Light", fault.lower() == "dark", "off" if fault.lower() == "dark" else f"on ({fault})")
    versions = Counter(u.get("firmware") for o, u in eh["units"].items() if u.get("type") == "switch" and u.get("firmware") and u["label"] != EH_NOT_REPORTED)
    mine = unit.get("firmware")
    if mine:
        common, n = versions.most_common(1)[0] if versions else (mine, 1)
        same = mine == common or versions[mine] >= n
        add("firmware", "Firmware Like the Others", same,
            f"{mine}" + (" (all the same)" if len(versions) <= 1 else "" if same else f"; most switches have {common}"))
    return out


# ------------------------------------------------------------
# THE ROUTER'S VERDICT (22 Nov 2026, owner: the Router table)
#
# Firewalla gives the router no health word, so its verdict is our checks
# alone. The dashboard's tunnel is OUR link to it, not the router: on its own
# a broken tunnel is Needs a Look ("can't reach it, but..."). Outage only when
# the tunnel is down AND a second, independent sign agrees: Firewalla's cloud
# says it's offline, or traffic no longer flows through it (the NAS's own
# internet pings). Buckets line up with the other tables: Reachable,
# Connection (its internet connections), Power (not reported), Ports (its LAN
# ports in use), System (CPU, memory, firmware).
# ------------------------------------------------------------
ROUTER_UID = "ROUTER"
EH_ROUTER_TUNNEL = 30          # s without live stats from the router
EH_ROUTER_PINGS = 120          # s without a good ping through it
EH_ROUTER_CLOUD = 900          # s Firewalla's cloud may go without hearing it
EH_ROUTER_BUSY = 90            # % CPU for 5 minutes, or memory used


def eh_wan_failures(failures):
    """The router's failed tests as words: [{type: ping, target: 1.1.1.1}, ...]
    -> "ping to 1.1.1.1, 9.9.9.9 and 8.8.8.8"."""
    by = {}
    for f in failures or []:
        if isinstance(f, dict):
            by.setdefault(str(f.get("type") or "test"), []).append(str(f.get("target") or "")) 
        else:
            by.setdefault(str(f), [])
    join = lambda xs: xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]
    return "; ".join(f"{t} to {join([x for x in ts if x])}" if any(ts) else t for t, ts in by.items())


def eh_router_checks(c, unit, now):
    out = []
    add = lambda key, name, ok, value, hard=False: out.append({"key": key, "name": name, "ok": ok, "value": value, "hard": hard})
    hist = eh_look_history(c).setdefault(ROUTER_UID, {})
    age = now - float(state.get("last_update") or 0)
    tunnel_ok = bool(state.get("connected")) and age <= EH_ROUTER_TUNNEL
    add("tunnel", "Dashboard Reaches It", tunnel_ok, f"live stats {fmt_duration_short(age)} old" if age < 86400 else "no live stats", hard=True)
    # Unit history (23 Nov 2026): what changed since the last look, recorded
    # quietly (rec = the last state of each).
    rec = hist.setdefault("rec", {})
    def note(key, value, kind, before, after, detail=None):
        if key in rec and rec[key] != value:
            eh_event(c, ROUTER_UID, unit, kind, None, before(rec[key]) if callable(before) else before, after, detail or {}, now)
        if rec.get(key) != value:
            rec[key] = value
            eh["look_dirty"] = True
    note("tunnel", tunnel_ok, "link", lambda was: "up" if was else "down", "up" if tunnel_ok else "down")
    # 5 GHz DFS for every access point (D-996): off, the APs leave saved DFS
    # channels (52-144) for others, as they did before 24 Nov 2026.
    wifi = state.get("wifi_settings") or {}
    if "dfs_on" in wifi:
        add("dfs", "5 GHz DFS (Access Points)", wifi["dfs_on"], "On" if wifi["dfs_on"] else "Off: APs saved on channels 52-144 move to others")
    box = state.get("msp_box") or {}
    if box:
        seen = safe_number(box.get("last_seen"))
        online = box.get("online") is not False and (not seen or now - seen <= EH_ROUTER_CLOUD)
        add("cloud", "Firewalla's Cloud Sees It", online,
            ("online" if box.get("online") is not False else "offline") + (f", last heard {eh_ago(now - seen)}" if seen else ""), hard=True)
        note("cloud", online, "cloud", lambda was: "online" if was else "offline", "online" if online else "offline")
    else:
        add("cloud", "Firewalla's Cloud Sees It", None, "not read yet", hard=True)
    try:
        import status as _status   # here: status imports from this module's neighbours
        ok_at = _status.ping_status.get("ok_at")
    except Exception:
        ok_at = None
    add("routing", "Traffic Flows Through It", None if ok_at is None else now - ok_at <= EH_ROUTER_PINGS,
        "not measured yet" if ok_at is None else f"last good ping {eh_ago(now - ok_at)}", hard=True)
    m = state.get("router_metrics") or {}
    up = safe_number(m.get("uptime_seconds"))
    if up is not None:
        if unit.get("uptime") is not None and up < unit["uptime"] - 60:
            unit["restarted_at"] = now
            eh_event(c, ROUTER_UID, unit, "restart", None, round(unit["uptime"]), round(up), {}, now)
        unit["uptime"] = up
    if unit.get("restarted_at") and now - unit["restarted_at"] < 600:
        add("restart", "No Restart", False, f"restarted {eh_ago(now - unit['restarted_at'])}")
    elif up is not None:
        add("restart", "No Restart", True, f"up {fmt_duration_short(up)}")
    # Its internet connections.
    wans = (state.get("internet") or {}).get("wans") or {}
    for key, w in sorted(wans.items()):
        name = w.get("provider") or key
        role = "in use" if w.get("in_use") else (w.get("role") or "standby")
        ok = bool(w.get("carrier")) and w.get("ready") is not False
        add("wan_" + key, name, ok, (f"{role}, working" if ok else f"{role}, " + ("link down" if not w.get("carrier") else "failing the router's tests"
                                     + (f" ({eh_wan_failures(w.get('failures'))})" if w.get("failures") else ""))))
        said = "working" if ok else ("link down" if not w.get("carrier") else "failing tests")
        note("wan_" + key, said, "wan", lambda was: was, said, {"wan": name, "role": role,
             "tests": eh_wan_failures(w.get("failures")) if w.get("failures") else ""})
    # Traffic moving from one connection to the other (a failover, or back).
    in_use = next((w.get("provider") or k for k, w in sorted(wans.items()) if w.get("in_use")), None)
    if in_use:
        note("in_use", in_use, "failover", lambda was: was, in_use)
    # Its LAN ports in use (remembered a day, so one that goes down still counts).
    wan_names = set(wans)
    # The Gold Pro's own numbering: Port 1 = eth3 ... Port 4 = eth0 (owner, 20 Nov 2026).
    gold = bool((state.get("site") or {}).get("gold_pro"))
    label = lambda n: f"Port {4 - int(n[3:])} ({n})" if gold and re.fullmatch(r"eth[0-3]", n) else n
    used = hist.setdefault("ports", {})
    ports = [p for p in state.get("ports") or [] if p.get("name") and p["name"] not in wan_names]
    for p in ports:
        speed = safe_number(p.get("speed")) or 0
        if p.get("carrier"):
            rec = used.get(p["name"]) or {}
            if not rec or now - rec.get("seen", 0) > 600 or speed > rec.get("best", 0):
                used[p["name"]] = {"seen": now, "best": max(speed, rec.get("best", 0))}
                eh["look_dirty"] = True
    for name, rec in list(used.items()):
        if now - rec.get("seen", 0) > 86400:
            used.pop(name)
            eh["look_dirty"] = True
    down = [label(p["name"]) for p in ports if p["name"] in used and not p.get("carrier")]
    slow = [f"{label(p['name'])} at {eh_speed(p.get('speed'))} (was {eh_speed(used[p['name']]['best'])})" for p in ports
            if p.get("carrier") and p["name"] in used and (safe_number(p.get("speed")) or 0) < used[p["name"]].get("best", 0)]
    for p in ports:
        if p["name"] in used:
            note("lan_" + p["name"], bool(p.get("carrier")), "port", lambda was: "up" if was else "down", "up" if p.get("carrier") else "down",
                 {"port": label(p["name"]), "lan": True, "speed": safe_number(p.get("speed"))})
    in_use = [p for p in ports if p["name"] in used]
    if in_use:
        add("lan_ports", "LAN Ports in Use", not down and not slow,
            (f"{len(in_use) - len(down)} of {len(in_use)} up" + (", " + ", ".join(f"{label(p['name'])} {eh_speed(p.get('speed'))}" for p in in_use if p.get("carrier")) if not down else ""))
            if not down and not slow else "; ".join([f"{n} down" for n in down] + slow))
    # The unit: CPU (5 minutes), memory, firmware.
    cpu = safe_number(m.get("cpu_usage_percent"))
    if cpu is not None:
        ch = unit.setdefault("cpu_hist", [])
        ch.append((now, cpu))
        del ch[:-150]
        busy = len(ch) >= 120 and min(x for _, x in ch) > EH_ROUTER_BUSY
        add("cpu", "CPU", not busy, f"{cpu:.0f}%" + (f", over {EH_ROUTER_BUSY}% for 5 minutes" if busy else ""))
        note("cpu_busy", busy, "cpu", lambda was: "busy" if was else "normal", "busy" if busy else "normal", {"pct": round(cpu)})
    mem = safe_number(m.get("memory_usage_percent"))
    if mem is not None:
        add("memory", "Memory Free", mem < EH_ROUTER_BUSY, f"{100 - mem:.0f}% free")
        note("mem_high", mem >= EH_ROUTER_BUSY, "memory", lambda was: "high" if was else "normal", "high" if mem >= EH_ROUTER_BUSY else "normal", {"free": round(100 - mem)})
    if box.get("version"):
        note("firmware", str(box["version"]), "firmware", lambda was: was, str(box["version"]))
        unit["firmware"] = str(box["version"])   # By Unit's Firmware column
        add("firmware", "Firmware", True, str(box["version"]))
    return out


def eh_router_verdict(c, now):
    """The router's one verdict, every 2 s with the other units."""
    unit = eh["units"].get(ROUTER_UID)
    if unit is None:
        unit = eh["units"][ROUTER_UID] = {"type": "router", "name": (state.get("site") or {}).get("router_model") or "Router",
                                          "label": EH_GOOD, "since": now, "seen": now}
    unit["seen"] = now
    checks = eh_router_checks(c, unit, now)
    fails = unit.setdefault("fail_since", {})
    for ch in checks:
        if ch["ok"] is False:
            fails.setdefault(ch["key"], now)
        else:
            fails.pop(ch["key"], None)
    held = lambda key, t: key in fails and now - fails[key] >= t
    tunnel_down = held("tunnel", EH_FAIL_HOLD)
    second = held("cloud", EH_FAIL_HOLD) or held("routing", EH_FAIL_HOLD)
    bad = [ch for ch in checks if ch["ok"] is False and held(ch["key"], EH_LOOK_HOLD if ch["key"] not in ("tunnel", "cloud", "routing") else EH_FAIL_HOLD)]
    if tunnel_down and second and held("tunnel", EH_OWN_ONLY_HOLD):
        state_ = "outage"
        sentence = "The dashboard can't reach it and " + ("Firewalla's cloud says it's offline" if held("cloud", EH_FAIL_HOLD) else "no traffic flows through it") + "."
    elif bad:
        state_ = "look"
        said = []
        for ch in bad:
            if ch["key"] == "tunnel":
                said.append("the dashboard can't reach it (" + ", ".join(x for x in ("Firewalla's cloud still sees it" if not held("cloud", 1) else "",
                            "traffic still flows" if not held("routing", 1) else "") if x) + ")")
            else:
                said += eh_short_router(ch)
        wan_checks = [ch for ch in checks if ch["key"].startswith("wan_")]
        if wan_checks and all(ch in bad for ch in wan_checks):
            # Internet out: the router still works (owner, 22 Nov 2026: yellow,
            # not red; Status shows the internet outage itself in red).
            said = [x for x in said if not any(x.startswith(ch["name"] + ":") for ch in wan_checks)]
            said.insert(0, "No internet connection works (" + "; ".join(f"{ch['name']}: {ch['value']}" for ch in wan_checks) + ")")
        sentence = "Needs a Look: " + "; ".join(said) + "."
    else:
        state_, sentence = "healthy", "Healthy."
    before = (unit.get("verdict") or {}).get("raw") or (unit.get("verdict") or {}).get("state")
    since = unit["verdict"]["since"] if before == state_ and unit.get("verdict") else now
    word = {"healthy": "Healthy", "look": "Needs a Look", "outage": "Outage"}[state_]
    buckets = []
    for name, keys in EH_BUCKETS["router"]:
        mine = [ch for ch in checks if ch["key"] in keys or any(ch["key"].startswith(k + "_") for k in keys)]
        if not mine:
            continue
        badm = [ch for ch in mine if ch["ok"] is False and held(ch["key"], EH_FAIL_HOLD)]
        tone = ("bad" if state_ == "outage" and any(ch["key"] in ("tunnel", "cloud", "routing") for ch in badm) and name == "Reachable"
                else "bad" if name == "Connection" and mine and all(ch["ok"] is False for ch in mine)
                else "warn" if badm else "good" if any(ch["ok"] is True for ch in mine) else "none")
        buckets.append({"name": name, "state": tone, "word": EH_BUCKET_WORD[tone], "lines": [l for ch in mine for l in eh_short_router(ch)],
                        "text": "; ".join(f"{ch['name']}: {ch['value']}" for ch in (badm or mine))})
    unit["verdict"] = {"state": state_, "word": word, "sentence": sentence, "since": since, "buckets": buckets,
                       "checks": [{k: ch[k] for k in ("key", "name", "ok", "value")} for ch in checks]}
    eh_ack_apply(c, ROUTER_UID, unit, now)
    eh_planned_apply(c, ROUTER_UID, unit, now)
    # An outage is an incident, like a switch's or an AP's.
    if state_ == "outage" and not unit.get("incident"):
        eh_open_incident(c, ROUTER_UID, unit, now)
        c.execute("UPDATE incidents SET labels=? WHERE id=?", (json.dumps(["Our Checks Failed"]), unit["incident"]))
    if before != state_ and (unit.get("incident") or unit.get("pending_id")):
        eh_change(c, ROUTER_UID, unit, f"Verdict: {(before or 'healthy').title()}", f"Verdict: {word}", 0,
                  {"checks": unit["verdict"]["checks"], "sentence": sentence, "uptime": unit.get("uptime")}, now)
    if state_ != "outage" and unit.get("incident"):
        c.execute("UPDATE incidents SET ended=? WHERE id=?", (now, unit["incident"]))
        unit["pending_id"], unit["pending_at"] = unit.pop("incident"), now


def eh_short_router(ch):
    """The router's checks as short lines (the bucket hover)."""
    k, ok, v = ch["key"], ch["ok"], str(ch.get("value") or "")
    if k == "tunnel":
        return ["Dashboard connected" if ok else "Dashboard can't reach it"]
    if k == "cloud":
        return ([f"Firewalla's cloud: {v.split(',')[0]}"] if ok is not None else [])
    if k == "routing":
        return (["Traffic flowing"] if ok else ["No traffic getting through"]) if ok is not None else []
    if k.startswith("wan_"):
        return [f"{ch['name']}: {v}"]
    if k == "lan_ports":
        return [f"LAN ports: {v}"] if ok else [(f"LAN {x.strip()}" if x.strip().startswith("Port") else f"LAN port {x.strip()}") for x in v.split(";")]
    if k == "memory":
        return [f"Memory: {v}"]
    return eh_short(ch)


def eh_look_save(c):
    if eh.get("look_dirty"):
        eh_meta(c, EH_LOOK_KEY, eh["look_hist"])
        eh["look_dirty"] = False


def eh_raw_sample(ap_raw, switch_raw, now):
    """Hourly: what the controller sends for one AP and one switch, as a file
    (/data/equipment_raw_sample.json), to see which fields exist (22 Nov 2026:
    CPU, memory, temperature, SSIDs for Needs a Look). Read-only data."""
    if now - (eh.get("sample_at") or 0) < 3600 or not ap_raw:
        return
    eh["sample_at"] = now
    try:
        sample = {"at": now, "ap": next(iter(ap_raw.values())), "switch": next(iter((switch_raw or {}).values()), None)}
        path = os.path.join(os.path.dirname(EQUIPMENT_HEALTH_DATABASE), "equipment_raw_sample.json")
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(sample, handle, indent=1, default=str)
        os.replace(path + ".tmp", path)
    except Exception as exc:
        print("Equipment sample error:", exc)


def eh_own_since(c):
    """When our own checks started (kept in meta): the first verdict change
    logged, else now. Incidents from then count only when they confirmed them."""
    if not eh.get("own_since"):
        since = eh_meta(c, EH_OWN_SINCE_KEY)
        if not since:
            first = c.execute("SELECT MIN(at) FROM changes WHERE label_after LIKE 'Verdict:%'").fetchone()[0]
            since = min(first or time.time(), time.time())
            eh_meta(c, EH_OWN_SINCE_KEY, since)
        eh["own_since"] = since
    return eh["own_since"]


def eh_verdict(c, kind, uid, raw, norm, now, devices):
    """Make the unit's one verdict and keep its incident in step with it."""
    unit = eh["units"][uid]
    checks = eh_checks(kind, uid, unit, raw, norm, now, devices)
    look = eh_look_checks(c, uid, unit, raw, norm, now) if kind == "ap" else eh_switch_look_checks(c, uid, unit, raw, norm, now)
    fails = unit.setdefault("fail_since", {})
    for ch in checks:
        if ch["hard"] and ch["ok"] is False:
            fails.setdefault(ch["key"], now)
        else:
            fails.pop(ch["key"], None)
    held = [ch for ch in checks if ch["key"] in fails and now - fails[ch["key"]] >= EH_FAIL_HOLD]
    bad_for = now - unit.get("off_since", unit["since"])
    label_good = unit["label"] == EH_GOOD
    # How a failed check reads in the reason.
    said = {"controller": "the controller gets no answer from it", "stream": "its live data stopped arriving",
            "heard": "the router {v}", "cable": "its cable: {v}",
            "power": "its port's power is {v}", "clients": "its Wi-Fi clients stopped passing traffic ({v})", "restart": "it {v}"}
    what = lambda: "; ".join(said.get(ch["key"], ch["name"].lower() + ": {v}").format(v=ch["value"]).replace("router last heard", "router last heard it") for ch in held)
    upstream = next((ch for ch in checks if ch["key"] == "upstream" and ch["ok"] is False), None)
    many = next((ch for ch in checks if ch["key"] == "others" and ch["ok"] is False), None)
    clients = next((ch for ch in checks if ch["key"] == "clients" and ch["ok"] is False), None)
    # Amber or red only when our own checks confirm a problem (22 Nov 2026,
    # owner: "I don't want it going amber or red unless we can confirm that
    # there's an issue"). Firewalla's label alone, however long, stays green
    # with a note: 327 of its 328 bad labels in a year were routine.
    if label_good and len([ch for ch in held if now - fails[ch["key"]] >= EH_OWN_ONLY_HOLD]) >= 2:
        state_, sentence = "outage", f"Firewalla says Healthy, but our checks fail: {what()}."
    elif not label_good and held:
        state_ = "outage"
        sentence = f"Firewalla says {unit['label']} ({fmt_duration_short(bad_for)}) and our checks confirm it: {what()}."
    elif label_good:
        state_ = "healthy"
        sentence = "Healthy." + (f" One check is off, not enough to call it a problem: {what()}." if held else "")
    else:
        state_ = "healthy"
        start = (f"Firewalla's controller stopped listing it {fmt_duration_short(bad_for)} ago" if unit["label"] == EH_NOT_REPORTED
                 else f"Firewalla says {unit['label']} ({fmt_duration_short(bad_for)})")
        sentence = f"Healthy. {start}, but our checks pass, so nothing is confirmed."
    # Needs a Look: working, but not at its best (to-do item 10). Amber, with
    # the reason; never red, never an incident.
    # Each must hold 30 s, so one odd reading never flashes a unit amber.
    look_since = unit.setdefault("look_since", {})
    for ch in look:
        if ch["ok"] is False:
            look_since.setdefault(ch["key"], now)
        else:
            look_since.pop(ch["key"], None)
    looks = [ch for ch in look if ch["ok"] is False and now - look_since[ch["key"]] >= EH_LOOK_HOLD]
    if state_ == "healthy" and looks:
        state_ = "look"
        sentence = "Needs a Look: " + "; ".join(f"{ch['name'].lower().replace('ghz', 'GHz')}: {ch['value']}" for ch in looks) + "."             + (f" {sentence[len('Healthy. '):]}" if sentence.startswith("Healthy. ") else "")
    checks = checks + look
    if state_ == "outage" and upstream:
        sentence += f" Most likely because {upstream['value'].split(':')[0]} above it is down."
    if state_ == "outage" and clients:
        sentence += f" Its Wi-Fi clients stopped passing traffic at the same time ({clients['value']})."
    if state_ == "outage" and many:
        sentence += " Several units at once: most likely the router or its controller, not this unit."
    before = (unit.get("verdict") or {}).get("raw") or (unit.get("verdict") or {}).get("state")
    since = unit["verdict"]["since"] if before == state_ and unit.get("verdict") else now
    word = {"healthy": "Healthy", "look": "Needs a Look", "outage": "Outage"}[state_]
    # Buckets (22 Nov 2026, owner): each check belongs to one; a bucket is
    # red when one of its checks confirmed the outage, yellow when one is off
    # (degraded, still working), green otherwise, grey when none can tell.
    held_keys = {ch["key"] for ch in held}
    buckets = []
    for name, keys in EH_BUCKETS[kind]:
        mine = [ch for ch in checks if ch["key"] in keys or any(ch["key"].startswith(k + "_") for k in keys)]
        if not mine:
            continue
        # A dot turns yellow only once its check has failed as long as the
        # verdict waits (6 s; 30 s for Needs a Look items): no flash on a blip.
        bad = [ch for ch in mine if ch["ok"] is False and (
            now - (look_since.get(ch["key"]) or now) >= EH_LOOK_HOLD if ch.get("look") else now - (fails.get(ch["key"]) or now) >= EH_FAIL_HOLD
            if ch.get("hard") else now - (look_since.get(ch["key"]) or fails.get(ch["key"]) or now) >= EH_FAIL_HOLD)]
        tone = ("bad" if state_ == "outage" and any(ch["key"] in held_keys for ch in bad) else "warn" if bad
                else "good" if any(ch["ok"] is True for ch in mine) else "none")
        lines = []
        for ch in mine:
            if not ch["key"].startswith("radio_"):
                lines += eh_short(ch)
        if name == "Radios":
            lines = eh_radio_lines(mine) + lines
        off = [l for ch in bad if not ch["key"].startswith("radio_") for l in eh_short(ch)]
        if any(ch["key"].startswith("radio_") for ch in bad):
            off = [l for l in eh_radio_lines(bad) if not l.startswith("Radios on")] + off
        buckets.append({"name": name, "state": tone, "word": EH_BUCKET_WORD[tone], "lines": lines, "off": off,
                        "text": "; ".join(f"{ch['name']}: {ch['value']}" for ch in (bad or mine))})
    # A yellow bucket makes the whole unit yellow (22 Nov 2026, owner): the
    # row never says Healthy next to a degraded bucket.
    if state_ == "healthy" and any(b["state"] == "warn" for b in buckets):
        state_ = "look"
        off = [l for b in buckets if b["state"] == "warn" for l in b.get("off") or []]
        sentence = "Needs a Look: " + ("; ".join(off) if off else ", ".join(b["name"] for b in buckets if b["state"] == "warn") + " degraded") + "."
        since = unit["verdict"]["since"] if before == state_ and unit.get("verdict") else now
        word = "Needs a Look"
    unit["verdict"] = {"state": state_, "word": word, "sentence": sentence, "since": since, "buckets": buckets,
                       "checks": [{k: ch[k] for k in ("key", "name", "ok", "value")} for ch in checks]}
    eh_ack_apply(c, uid, unit, now)
    eh_planned_apply(c, uid, unit, now)
    # An outage our checks found while Firewalla says Healthy is an incident too.
    if state_ == "outage" and not unit.get("incident"):
        eh_open_incident(c, uid, unit, now)
        unit["own_incident"] = True
        row = c.execute("SELECT labels FROM incidents WHERE id=?", (unit["incident"],)).fetchone()
        labels = json.loads(row[0] or "[]") if row else []
        if "Our Checks Failed" not in labels:
            c.execute("UPDATE incidents SET labels=? WHERE id=?", (json.dumps(labels + ["Our Checks Failed"]), unit["incident"]))
    # Each verdict change is logged with its checks: the incident's record.
    if before != state_ and (unit.get("incident") or unit.get("pending_id")):
        eh_change(c, uid, unit, f"Verdict: {(before or 'healthy').title()}", f"Verdict: {word}", 0,
                  {**eh_snapshot(kind, uid, raw, norm, now), "checks": unit["verdict"]["checks"], "sentence": sentence}, now)
    if unit.get("own_incident") and label_good and state_ == "healthy" and unit.get("incident"):
        c.execute("UPDATE incidents SET ended=? WHERE id=?", (now, unit["incident"]))
        unit["pending_id"], unit["pending_at"] = unit.pop("incident"), now
        unit.pop("own_incident", None)


def equipment_verdicts():
    """Every watched unit's verdict, for the pages, alerts and digest."""
    return {uid: {"name": u["name"], "type": u["type"], "label": u["label"], **(u.get("verdict") or {"state": "healthy", "word": "Healthy", "sentence": "Healthy.", "checks": []}),
                  "listed": u["label"] != EH_NOT_REPORTED}
            for uid, u in list(eh["units"].items())}


def eh_assess(c, incident_id):
    """Likely Cause, Why, How Sure and Raised for a finished incident."""
    inc = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    rows = c.execute("SELECT * FROM changes WHERE incident_id=? ORDER BY at", (incident_id,)).fetchall()
    snaps = [json.loads(r["details"] or "{}") for r in rows]
    duration = (inc["ended"] or time.time()) - inc["started"]
    labels = json.loads(inc["labels"] or "[]")
    related = c.execute("SELECT id, unit_name, started FROM incidents WHERE id != ? AND started BETWEEN ? AND ?",
                        (incident_id, inc["started"] - EH_RELATED_WINDOW, inc["started"] + EH_RELATED_WINDOW)).fetchall()
    names = [r["unit_name"] for r in related]
    wave = c.execute("SELECT 1 FROM incidents WHERE id != ? AND unit_id != ? AND started BETWEEN ? AND ?",
                     (incident_id, inc["unit_id"], inc["started"] - EH_WAVE_WINDOW, inc["started"] + EH_WAVE_WINDOW)).fetchone()
    first = snaps[0] if snaps else {}
    upstream = first.get("upstream")
    # Upstream Unit only when the chain is real (19 Nov 2026, owner): an AP
    # named as upstream must have had a live cable on its second port (its
    # own snapshot nearest the time, else its ports now). Two APs side by
    # side on one powerline network or unmanaged switch checking in at the
    # same moment are two check-ins.
    if upstream and not any(s.get("name") == upstream for s in (state.get("switches") or {}).values()):
        # (Firewalla's LLDP names drop the "AP7 " prefix: "Lg Garage".)
        near = c.execute("SELECT details FROM changes WHERE (unit_name=? OR unit_name LIKE ?) AND at BETWEEN ? AND ? ORDER BY ABS(at - ?) LIMIT 1",
                         (upstream, "% " + upstream, inc["started"] - 300, inc["started"] + 300, inc["started"])).fetchone()
        snap_up = json.loads(near["details"] or "{}") if near else {}
        now_up = next((a for a in (state.get("access_points") or {}).values()
                       if a.get("name") == upstream or str(a.get("name") or "").endswith(" " + upstream)), None)
        real = (ap_has_second_cable(ports=snap_up.get("cable_links"), primary=snap_up.get("primary")) if snap_up.get("cable_links")
                else ap_has_second_cable(now_up) if now_up else True)
        if not real:
            upstream = None
    upstream_first = bool(upstream) and any(r["unit_name"] == upstream and r["started"] <= inc["started"] + 5 for r in related)
    links = {json.dumps(s.get("cable_links") or s.get("uplinks") or {}, sort_keys=True) for s in snaps}
    # An AP's unused port is always down: only its uplink port counts.
    cable_down = any(((s.get("cable_links") or {}).get(s.get("primary") or "") or {}).get("up") is False for s in snaps)
    uptimes = [s.get("uptime") for s in snaps if isinstance(s.get("uptime"), (int, float))]
    rebooted = len(uptimes) > 1 and min(uptimes[1:]) < uptimes[0]
    # The switch port's power counts only where it was reported: a reading
    # that goes missing is no change (19 Nov 2026, owner: AP7 Sm Garage at
    # 12:00 on 18 Nov lost it when Firewalla named another uplink; it is on
    # a powerline adapter, its port never delivers power).
    power_seen = [s["port_power"].get("status") for s in snaps if s.get("port_power")]
    power_drop = len(set(power_seen)) > 1 and any(p != "delivering" for p in power_seen)
    weak_mesh = any(isinstance(s.get("mesh_signal"), (int, float)) and s["mesh_signal"] < -75 for s in snaps)
    # Lost contact: the controller says so, or stops reporting latency to
    # the unit. The time since its last check-in is no sign: it counts up
    # to the hourly check-in (54 min on 16 Nov while latency stayed 1 ms).
    no_latency = any(s.get("latency_to_controller") is None for s in snaps) if snaps and "latency_to_controller" in first else False
    lost = no_latency or any(l in (EH_NOT_REPORTED,) or re.search(r"disconnect|offline|lost|unreach", l, re.I) for l in labels)
    # A firmware update: its version changed during it or just after it came
    # back (22 Nov 2026, owner). Quiet unless it took over 10 minutes.
    firmware = c.execute("SELECT before, after FROM firmware WHERE unit_id=? AND at BETWEEN ? AND ? ORDER BY at DESC LIMIT 1",
                         (inc["unit_id"], inc["started"] - 60, (inc["ended"] or time.time()) + 300)).fetchone()
    # What our own checks said during it (from 22 Nov 2026).
    own_outage = any(str(r["label_after"] or "") == "Verdict: Outage" for r in rows)
    if firmware:
        cause, sure, why = "Firmware Update", "Clear", f"its firmware went from {firmware['before']} to {firmware['after']}"
    elif len(links) > 1 or cable_down:
        cause, sure, why = "Cable or Port", "Clear", "a cable link went down or changed speed during it"
    elif rebooted or power_drop:
        cause, sure, why = "Power or Reboot", "Clear" if rebooted else "Likely", \
            "its uptime started again from zero" if rebooted else "the switch port's power changed during it"
    # Several units at once is the router or its controller only when this
    # one really lost contact; otherwise it is a shared check-in (19 Nov
    # 2026, owner: four AP7s at 04:58 on 18 Nov all kept their latency,
    # cable and clients through their hourly check-in).
    elif len(names) >= 3 and lost:
        cause, sure, why = "Lost Contact", "Likely", f"{len(names) + 1} units at once, so most likely the router or its controller, not the units"
    elif upstream_first:
        cause, sure, why = "Upstream Unit", "Likely", f"{upstream} went bad at the same moment; this unit's own cable stayed up"
    elif weak_mesh:
        cause, sure, why = "Wireless Link", "Likely", "it was on mesh with a weak signal"
    elif duration < (EH_ROUTINE_MAX_SHARED if wave else EH_ROUTINE_MAX) and inc["flaps"] <= 1 and not lost:
        cause, sure, why = "Routine Check-In", "Likely", "short, and its cable, power and link to the controller stayed normal"
    elif lost:
        cause, sure, why = "Lost Contact", "Likely", ("the controller stopped reporting its latency to it" if no_latency
                                                      else "the controller stopped listing it" if EH_NOT_REPORTED in labels
                                                      else "Firewalla reported it " + ", ".join(labels))
    else:
        cause, sure, why = "Can't Tell", "Guess", "Firewalla gave no detail that points to a cause"
    if names and cause not in ("Upstream Unit", "Lost Contact"):
        why += f"; at the same time: {', '.join(sorted(set(names)))}"
    # Did its Wi-Fi clients drop? A real drop (3 or more, and half or more
    # of them) means it wasn't routine, whatever else looked normal.
    before = next((s.get("clients_before") for s in snaps if s.get("clients_before") is not None), None)
    during = [s.get("clients") for s in snaps if s.get("clients") is not None]
    dropped = False
    if before is not None and during:
        low = min(during)
        dropped = before - low >= max(EH_DROP_MIN, before * EH_DROP_SHARE)
        if dropped and cause == "Routine Check-In":
            cause, sure, why = "Can't Tell", "Guess", ("its Wi-Fi clients dropped though its cable, power and link "
                                                      "to the controller stayed normal")
        why += (f"; Wi-Fi clients {before} before, {low} at the lowest during it" if low < before
                else f"; its {before} Wi-Fi clients stayed connected")
    if own_outage and cause == "Routine Check-In":
        cause, sure, why = "Can't Tell", "Guess", "our own checks found it down, though nothing Firewalla reported points to a cause"
    if own_outage:
        last = next((json.loads(r["details"] or "{}").get("sentence") for r in reversed(rows) if r["label_after"] == "Verdict: Outage"), None)
        if last:
            why += f"; our checks: {last}"
    routine = cause == "Routine Check-In" and not dropped
    # Started during Planned Work you set (D-912): recorded, raised nowhere.
    planned = eh_planned_during(inc["unit_id"], inc["started"])
    if planned:
        span = f"{datetime.fromtimestamp(planned['at']).strftime('%d %b %H:%M')}-{datetime.fromtimestamp(planned['until']).strftime('%H:%M')}"
        c.execute("UPDATE incidents SET cause=?, why=?, sure=?, related=?, raised=?, routine=? WHERE id=?",
                  ("Planned Work", f"During the Planned Work you set ({span}" + (", whole network" if planned["scope"] == "network" else "") + "); " + why,
                   "Clear", json.dumps(sorted(set(names))), "Quiet", 1, incident_id))
        return inc["unit_id"]
    # The owner's own call wins over every rule, and survives re-assessing
    # (22 Nov 2026: the 13:57 AP7 Office incident, before our checks ran).
    owner = (eh_meta(c, EH_OWNER_CAUSES_KEY) or {}).get(str(incident_id))
    if owner:
        c.execute("UPDATE incidents SET cause=?, why=?, sure=?, related=?, raised=?, routine=? WHERE id=?",
                  (owner["cause"], f"Marked {owner['cause']} by you on {datetime.fromtimestamp(owner['at']).strftime('%d %b %H:%M')}; " + why,
                   "Clear", json.dumps(sorted(set(names))), "Quiet", 1, incident_id))
        return inc["unit_id"]
    # From when our own checks run (22 Nov 2026, owner): an incident is an
    # issue only when they confirmed it. Firewalla's label alone is logged
    # (Firewalla Reported) but counts nowhere and raises nothing.
    own_since = eh_own_since(c)
    if own_since and inc["started"] >= own_since and not own_outage:
        if cause not in ("Routine Check-In", "Firmware Update"):
            cause, sure, why = "Not Confirmed", "Clear", f"Firewalla reported it {', '.join(labels) or 'bad'}, but our own checks passed throughout"
        routine, raised = True, "Quiet"
    elif cause == "Firmware Update":
        raised = "Needs Attention" if duration > 600 else "Quiet"
    else:
        raised = "Needs Attention" if not routine and (own_outage or duration > EH_RED_AFTER or dropped) else "Quiet"
    c.execute("UPDATE incidents SET cause=?, why=?, sure=?, related=?, raised=?, routine=? WHERE id=?",
              (cause, why[0].upper() + why[1:], sure, json.dumps(sorted(set(names))), raised, int(routine), incident_id))
    return inc["unit_id"]


def eh_pattern(c, key, kind, units, start, end, incidents, summary, sure, raised):
    old = c.execute("SELECT id FROM patterns WHERE key=?", (key,)).fetchone()
    if old:
        c.execute("UPDATE patterns SET units=?, period_to=?, incidents=?, summary=?, sure=? WHERE id=?",
                  (json.dumps(units), end, json.dumps(incidents), summary, sure, old[0]))
    else:
        c.execute("INSERT INTO patterns (key, found, kind, units, period_from, period_to, incidents, summary, sure, raised)"
                  " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (key, time.time(), kind, json.dumps(units), start, end, json.dumps(incidents), summary, sure, raised))


def eh_patterns(c, uid, now=None):
    """Patterns for one unit: repeats, timing, chain, getting worse, after a firmware update."""
    now = now or time.time()
    rows = c.execute("SELECT * FROM incidents WHERE unit_id=? AND ended IS NOT NULL AND cause IS NOT NULL AND started > ? ORDER BY started",
                     (uid, now - 60 * 86400)).fetchall()
    if not rows:
        return
    name = rows[-1]["unit_name"]
    week = datetime.fromtimestamp(now).strftime("%G-W%V")
    issues = [r for r in rows if not r["routine"]]
    last7 = [r for r in issues if r["started"] > now - 7 * 86400]
    prev7 = [r for r in issues if now - 14 * 86400 < r["started"] <= now - 7 * 86400]
    if len(last7) >= 3:
        causes = Counter(r["cause"] for r in last7).most_common(1)[0][0]
        eh_pattern(c, f"repeats:{uid}:{week}", "Repeats", [name], last7[0]["started"], last7[-1]["started"], [r["id"] for r in last7],
                   f"{name}: {len(last7)} issues in 7 days, mostly {causes}", "Clear", "Needs Attention")
    if len(last7) >= 3 and len(last7) >= 2 * max(1, len(prev7)):
        eh_pattern(c, f"worse:{uid}:{week}", "Getting Worse", [name], last7[0]["started"], last7[-1]["started"], [r["id"] for r in last7],
                   f"{name}: {len(last7)} issues this week against {len(prev7)} the week before", "Likely", "Needs Attention")
    chain = [r for r in rows[-6:] if r["cause"] == "Upstream Unit"]
    if len(chain) >= 3:
        upstream = Counter(r["why"].split(" went bad")[0] for r in chain).most_common(1)[0][0]
        eh_pattern(c, f"chain:{uid}:{week}", "Chain", [name, upstream], chain[0]["started"], chain[-1]["started"], [r["id"] for r in chain],
                   f"{name}: {len(chain)} issues, each just after {upstream}. Likely {upstream} or the cable between them",
                   "Likely", "Needs Attention" if any(not r["routine"] for r in chain) else "Quiet")
    recent = [r for r in rows if r["started"] > now - 14 * 86400]
    for r in recent:
        minute = lambda t: (datetime.fromtimestamp(t).hour * 60 + datetime.fromtimestamp(t).minute)
        alike = [x for x in recent if abs(minute(x["started"]) - minute(r["started"])) <= 15]
        days = {datetime.fromtimestamp(x["started"]).date() for x in alike}
        if len(days) >= 3:
            at = datetime.fromtimestamp(r["started"]).strftime("%H:%M")
            eh_pattern(c, f"timing:{uid}:{week}", "Timing", [name], alike[0]["started"], alike[-1]["started"], [x["id"] for x in alike],
                       f"{name}: blips around {at} on {len(days)} different days. A schedule (a nightly check, a client asleep) is the usual cause",
                       "Likely", "Quiet")
            break
    for fw in c.execute("SELECT * FROM firmware WHERE unit_id=? AND at > ?", (uid, now - 45 * 86400)).fetchall():
        after = [r for r in issues if fw["at"] <= r["started"] <= fw["at"] + 14 * 86400]
        before = [r for r in issues if fw["at"] - 14 * 86400 <= r["started"] < fw["at"]]
        if len(after) >= 3 and len(after) > len(before):
            eh_pattern(c, f"firmware:{uid}:{fw['after']}", "After Firmware Update", [name], fw["at"], after[-1]["started"], [r["id"] for r in after],
                       f"{name}: {len(before)} issues in the 14 days before the update to {fw['after']}, {len(after)} in the 14 days after",
                       "Likely", "Needs Attention")
    # Several units with issues after the same update.
    for fw in c.execute("SELECT after, MIN(at) AS at, COUNT(DISTINCT unit_id) AS n FROM firmware WHERE at > ? GROUP BY after HAVING n >= 2",
                        (now - 45 * 86400,)).fetchall():
        hit = c.execute("SELECT unit_name, COUNT(*) AS n FROM incidents WHERE routine=0 AND started BETWEEN ? AND ? GROUP BY unit_id HAVING n >= 2",
                        (fw["at"], fw["at"] + 14 * 86400)).fetchall()
        if len(hit) >= 2:
            eh_pattern(c, f"firmware-many:{fw['after']}", "After Firmware Update", [h["unit_name"] for h in hit], fw["at"], now, [],
                       f"{len(hit)} units started having issues after the update to {fw['after']}: the firmware is the likely cause, not each unit",
                       "Likely", "Needs Attention")


def eh_summary(c, now):
    """What /api/status carries: open Needs Attention items and each unit's
    Health History line."""
    needs = []
    for r in c.execute("SELECT * FROM incidents WHERE raised='Needs Attention' AND seen_at IS NULL AND started > ? ORDER BY started DESC",
                       (now - 7 * 86400,)):
        needs.append({"kind": "incident", "id": r["id"], "at": r["started"], "text": f"{r['unit_name']}: {r['cause']} for {fmt_duration_short((r['ended'] or now) - r['started'])}"})
    for r in c.execute("SELECT * FROM patterns WHERE raised='Needs Attention' AND seen_at IS NULL AND found > ? ORDER BY found DESC",
                       (now - 14 * 86400,)):
        needs.append({"kind": "pattern", "id": r["id"], "at": r["found"], "text": r["summary"]})
    units = {}
    for r in c.execute("SELECT unit_id, SUM(routine=0) AS issues, SUM(routine=1) AS routine, MAX(started) AS last FROM incidents"
                       " WHERE started > ? AND cause IS NOT NULL GROUP BY unit_id", (now - 30 * 86400,)):
        units[r["unit_id"]] = {"issues_30d": r["issues"] or 0, "routine_30d": r["routine"] or 0, "last": r["last"]}
    for r in c.execute("SELECT unit_id, COUNT(*) AS n FROM incidents WHERE started > ? AND cause IS NOT NULL GROUP BY unit_id", (now - EH_KEEP_SECONDS,)):
        units.setdefault(r["unit_id"], {"issues_30d": 0, "routine_30d": 0, "last": None})["year"] = r["n"]
    return {"needs": needs, "units": units, "radio_history": eh_radio_history(c, now), "unit_history": eh_unit_history(c, now)}


def fmt_duration_short(seconds):
    seconds = int(seconds or 0)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    return f"{seconds / 3600:.1f} h"


def equipment_health_worker():
    """Every 15 s: close incidents (2 minutes after the last flap), assess
    them, look for patterns, and keep a heartbeat (so incidents a restart
    left open end where the dashboard stopped)."""
    with eh_lock, eh_db() as c:
        now = time.time()
        beat = eh_meta(c, "heartbeat")
        # Not Watched was removed (22 Nov 2026, owner): its gap log goes too.
        c.execute("DROP TABLE IF EXISTS watching")
        # Incidents left open by the last run end where the watching stopped.
        for r in c.execute("SELECT id FROM incidents WHERE ended IS NULL OR cause IS NULL").fetchall():
            c.execute("UPDATE incidents SET ended=COALESCE(ended, ?) WHERE id=?", (beat or now, r["id"]))
            eh_assess(c, r["id"])
        # When the rules change (16 Nov 2026: Lost Contact only when the
        # controller can't reach the unit, routine up to 90 s; 19 Nov 2026:
        # several units at once needs a real loss of contact, a missing power
        # reading is no power change): assess every incident again, withdraw
        # patterns whose incidents are now all routine, and look for patterns
        # afresh. Done once per EH_ASSESS_VERSION.
        if (eh_meta(c, "assess_version") or 1) < EH_ASSESS_VERSION:
            for r in c.execute("SELECT id FROM incidents WHERE ended IS NOT NULL").fetchall():
                eh_assess(c, r["id"])
            for p in c.execute("SELECT id, incidents FROM patterns").fetchall():
                ids = json.loads(p["incidents"] or "[]")
                if ids and not c.execute(f"SELECT 1 FROM incidents WHERE routine=0 AND id IN ({','.join('?' * len(ids))})", ids).fetchone():
                    c.execute("DELETE FROM patterns WHERE id=?", (p["id"],))
            for (uid,) in c.execute("SELECT DISTINCT unit_id FROM incidents").fetchall():
                eh_patterns(c, uid, now)
            eh_meta(c, "assess_version", EH_ASSESS_VERSION)
        eh_meta(c, "heartbeat", now)
    last_daily = None
    while True:
        time.sleep(15)
        try:
            now = time.time()
            with eh_lock, eh_db() as c:
                eh_meta(c, "heartbeat", now)
                done = set()
                for uid, unit in eh["units"].items():
                    if unit.get("pending_id") and now - unit["pending_at"] > EH_FLAP_MERGE:
                        eh_assess(c, unit.pop("pending_id"))
                        unit.pop("pending_at", None)
                        done.add(uid)
                for uid in done:
                    eh_patterns(c, uid, now)
                day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
                if day != last_daily:
                    last_daily = day
                    for uid in list(eh["units"]):
                        eh_patterns(c, uid, now)
                    cut = now - EH_KEEP_SECONDS
                    for table, column in (("changes", "at"), ("firmware", "at"), ("incidents", "started"), ("patterns", "found")):
                        c.execute(f"DELETE FROM {table} WHERE {column} < ?", (cut,))
                    c.execute("DELETE FROM checking WHERE day < ?", (datetime.fromtimestamp(cut).strftime("%Y-%m-%d"),))
                    c.execute("DELETE FROM unit_events WHERE at < ?", (now - EH_EVENTS_KEEP,))
                eh["summary"] = eh_summary(c, now)
            state["equipment_health"] = eh["summary"]
            # Its last good pass, for Settings › Dashboard Health (24 Nov 2026:
            # it had stopped at every start for a day and nothing said so).
            state["equipment_health_worker"] = {"at": now, "error": None}
        except Exception as exc:
            print("Equipment health worker error:", exc)
            state["equipment_health_worker"] = {"at": (state.get("equipment_health_worker") or {}).get("at"), "error": str(exc)[:200]}


def eh_row(r):
    out = dict(r)
    for k in ("labels", "related", "units", "incidents", "details"):
        if k in out and isinstance(out[k], str):
            try:
                out[k] = json.loads(out[k])
            except ValueError:
                pass
    return out


EH_ROUTINE_LISTED_SECONDS = 30 * 86400


@app.get("/api/equipment-health/history")
def api_equipment_health_history(unit: str = "", days: int = 7):
    """One unit's history (Show All in its popup): every event of the last
    days (1-30), newest first."""
    days = max(1, min(30, days))
    with eh_lock, eh_db() as c:
        rows = c.execute("SELECT * FROM unit_events WHERE unit_id=? AND at>=? ORDER BY at DESC LIMIT 2000",
                         (str(unit)[:64], time.time() - days * 86400)).fetchall()
    return {"unit": unit, "days": days, "events": [{"at": r["at"], "band": r["band"], "kind": r["kind"], "before": r["before"], "after": r["after"],
                                                    **json.loads(r["detail"] or "{}")} for r in rows]}


@app.get("/api/equipment-health")
def api_equipment_health(incident: int = None):
    """The Equipment Health page: units, a year of incidents and patterns,
    gaps and firmware changes; with ?incident=<id>, that incident's
    Firewalla Reported entries too."""
    incident = incident if incident and 0 < incident < 2 ** 62 else None   # a row number, or none
    now = time.time()
    with eh_lock, eh_db() as c:
        changes = [eh_row(r) for r in c.execute("SELECT * FROM changes WHERE incident_id=? ORDER BY at", (incident,))] if incident else []
        # A year of issues, but routine check-ins only for the last 30 days
        # (the page lists the newest 300 anyway; every AP makes one or more a
        # day, so a year of them would be tens of thousands of rows in each
        # answer). The one being looked at is always sent; how many older
        # ones were left out is said.
        recent = now - EH_ROUTINE_LISTED_SECONDS
        incidents = [eh_row(r) for r in c.execute(
            "SELECT * FROM incidents WHERE started > ? AND (routine IS NOT 1 OR started > ? OR id = ?) ORDER BY started DESC",
            (now - EH_KEEP_SECONDS, recent, incident if incident else -1))]
        routine_older = c.execute("SELECT COUNT(*) FROM incidents WHERE started > ? AND started <= ? AND routine = 1",
                                  (now - EH_KEEP_SECONDS, recent)).fetchone()[0]
        patterns = [eh_row(r) for r in c.execute("SELECT * FROM patterns ORDER BY found DESC")]
        firmware = [eh_row(r) for r in c.execute("SELECT * FROM firmware ORDER BY at DESC")]
        checking = [eh_row(r) for r in c.execute("SELECT unit_id, SUM(times) AS times, MAX(longest) AS longest FROM checking WHERE day >= ? GROUP BY unit_id",
                                                 (datetime.fromtimestamp(now - 30 * 86400).strftime("%Y-%m-%d"),))]
        removed = eh_meta(c, EH_REMOVED_KEY) or {}
        owner_causes = eh_meta(c, EH_OWNER_CAUSES_KEY) or {}
    units = []
    verdicts = equipment_verdicts()
    for uid, u in sorted(eh["units"].items(), key=lambda x: (x[1]["type"], x[1]["name"])):
        mine = [i for i in incidents if i["unit_id"] == uid and i.get("cause")]
        issues = [i for i in mine if not i.get("routine")]
        units.append({"id": uid, "name": u["name"], "type": u["type"], "label": u["label"], "shown": equipment_health_shown(uid),
                      "verdict": verdicts.get(uid), "listed": u["label"] != EH_NOT_REPORTED,
                      "firmware": u.get("firmware"), "uptime": u.get("uptime"),
                      "issues_30d": sum(1 for i in issues if i["started"] > now - 30 * 86400), "issues_year": len(issues),
                      "routine_30d": sum(1 for i in mine if i.get("routine") and i["started"] > now - 30 * 86400),
                      "common_cause": Counter(i["cause"] for i in issues).most_common(1)[0][0] if issues else None,
                      "last_issue": issues[0]["started"] if issues else None})
    return {"now": now, "units": units, "removed": removed, "owner_causes": owner_causes, "incidents": incidents, "routine_older": routine_older, "patterns": patterns,
            "firmware": firmware, "checking": checking, "causes": EH_CAUSES, "incident_changes": changes,
            "claude": claude_public(claude_load(), "equipment") if "equipment" in CLAUDE_KINDS else None}


@app.post("/api/equipment-health/look-ack")
def api_equipment_health_look_ack(payload: dict = Body(default={})):
    """Acknowledge a unit's Needs a Look (undo: true takes it back)."""
    fields = Fields(payload)
    uid = (fields.text("id", 64) or "").upper()
    with eh_lock, eh_db() as c:
        unit = eh["units"].get(uid)
        if not unit:
            return {"ok": False, "error": "Unknown unit"}
        acks = eh_acks(c)
        if payload.get("undo") is True:
            acks.pop(uid, None)
        else:
            if ((unit.get("verdict") or {}).get("raw") or (unit.get("verdict") or {}).get("state")) != "look":
                return {"ok": False, "error": "It doesn't need a look now"}
            acks[uid] = {"at": time.time(), "keys": unit.get("look_keys") or []}
        eh_meta(c, "look_acks", acks)
    return {"ok": True}


@app.post("/api/planned-work")
def api_planned_work(payload: dict = Body(default={})):
    """Planned Work (D-912): {scope: a unit's id or "network", minutes: 30,
    60 or 120}, or minutes 0 to end it now. Starting it again replaces the time."""
    fields = Fields(payload)
    scope = (fields.text("scope", 64) or "").upper()
    scope = "network" if scope == "NETWORK" else scope
    minutes = payload.get("minutes")
    if minutes not in (0, *EH_PLANNED_MINUTES):
        return {"ok": False, "error": "Choose 30 minutes, 1 hour or 2 hours"}
    now = time.time()
    with eh_lock, eh_db() as c:
        p = eh_planned(c)
        if scope != "network" and scope not in eh["units"]:
            return {"ok": False, "error": "Unknown unit"}
        rec = p["network"] if scope == "network" else p["units"].get(scope)
        if minutes == 0:
            if not rec:
                return {"ok": False, "error": "No Planned Work is on"}
            if scope == "network":
                p["network"] = None
            else:
                p["units"].pop(scope)
            eh_planned_end(c, scope, rec, now, "ended by you")
        else:
            new = {"at": (rec or {}).get("at") or now, "until": now + minutes * 60}
            if scope == "network":
                p["network"] = new
            else:
                p["units"][scope] = new
            if not rec:
                uid = ROUTER_UID if scope == "network" else scope
                eh_event(c, uid, eh["units"].get(uid) or {"name": uid}, "planned", None, "off", "on",
                         {"scope": "network" if scope == "network" else "unit", "minutes": minutes, "until": new["until"]}, now)
        eh_meta(c, "planned_work", p)
        eh_planned_publish(c, now)
        eh["summary"] = eh_summary(c, now)   # its start or end in the History at once
    state["equipment_health"] = eh["summary"]
    return {"ok": True, "planned_work": state["planned_work"]}


@app.post("/api/equipment-health/seen")
def api_equipment_health_seen(payload: dict = Body(default={})):
    """Mark Seen: an incident or pattern leaves Needs Attention."""
    fields = Fields(payload)
    table, item = {"incident": "incidents", "pattern": "patterns"}.get(fields.text("kind", 20)), fields.row("id")
    if not table or item is None:
        return {"ok": False, "error": "Unknown item"}
    with eh_lock, eh_db() as c:
        c.execute(f"UPDATE {table} SET seen_at=? WHERE id=?", (time.time(), item))
        eh["summary"] = eh_summary(c, time.time())
    state["equipment_health"] = eh["summary"]
    return {"ok": True}


@app.post("/api/equipment-health/not-confirmed")
def api_equipment_health_not_confirmed(payload: dict = Body(default={})):
    """Mark Not Confirmed (22 Nov 2026, owner): an issue the owner judges was
    no real problem. It stops counting anywhere and raises nothing; Undo
    (undo=true) gives it back to the rules."""
    fields = Fields(payload)
    item = fields.row("id")
    if item is None:
        return {"ok": False, "error": "Unknown incident"}
    with eh_lock, eh_db() as c:
        row = c.execute("SELECT unit_id, ended FROM incidents WHERE id=?", (item,)).fetchone()
        if not row or not row["ended"]:
            return {"ok": False, "error": "Only an incident that has ended can be marked"}
        owner = eh_meta(c, EH_OWNER_CAUSES_KEY) or {}
        if payload.get("undo") is True:
            owner.pop(str(item), None)
        else:
            owner[str(item)] = {"cause": "Not Confirmed", "at": time.time()}
        eh_meta(c, EH_OWNER_CAUSES_KEY, owner)
        eh_assess(c, item)
        eh_patterns(c, row["unit_id"])
        eh["summary"] = eh_summary(c, time.time())
    state["equipment_health"] = eh["summary"]
    return {"ok": True}


@app.post("/api/equipment-health/removed")
def api_equipment_health_removed(payload: dict = Body(default={})):
    """Removed From Network (22 Nov 2026, owner): a unit the controller no
    longer lists leaves every page; its history stays; it comes back by
    itself if the controller lists it again."""
    uid = str(Fields(payload).text("id", 40) or "").upper()
    with eh_lock, eh_db() as c:
        unit = eh["units"].get(uid)
        if not unit:
            return {"ok": False, "error": "Unknown unit"}
        if unit["label"] != EH_NOT_REPORTED:
            return {"ok": False, "error": "Firewalla still lists this unit: remove it in the Firewalla app first"}
        now = time.time()
        for key in ("incident", "pending_id"):
            if unit.get(key):
                c.execute("UPDATE incidents SET ended=COALESCE(ended, ?) WHERE id=?", (now, unit[key]))
                eh_assess(c, unit[key])
        removed = eh_meta(c, EH_REMOVED_KEY) or {}
        removed[uid] = {"name": unit["name"], "type": unit["type"], "at": now}
        eh_meta(c, EH_REMOVED_KEY, removed)
        eh["units"].pop(uid, None)
        eh["summary"] = eh_summary(c, now)
    state["equipment_health"] = eh["summary"]
    state["equipment_verdicts"] = equipment_verdicts()
    return {"ok": True}


def claude_equipment_facts(ref):
    try:
        incident_id = int(ref)
    except ValueError:
        return None
    with eh_lock, eh_db() as c:
        r = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not r:
            return None
        inc = eh_row(r)
        changes = [eh_row(x) for x in c.execute("SELECT at, label_before, label_after, seconds_before, details FROM changes WHERE incident_id=? ORDER BY at", (incident_id,))]
        earlier = [eh_row(x) for x in c.execute("SELECT started, ended, labels, cause, routine FROM incidents WHERE unit_id=? AND id != ? AND started > ? ORDER BY started DESC LIMIT 20",
                                               (inc["unit_id"], incident_id, inc["started"] - 90 * 86400))]
        firmware = [eh_row(x) for x in c.execute("SELECT at, before, after FROM firmware WHERE unit_id=? ORDER BY at DESC LIMIT 5", (inc["unit_id"],))]
    when = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else None
    for x in changes:
        x["at"] = when(x["at"])
    for x in earlier:
        x["started"], x["ended"] = when(x["started"]), when(x["ended"])
    for x in firmware:
        x["at"] = when(x["at"])
    return {"unit": inc["unit_name"], "unit_type": "access point (AP7)" if inc["unit_type"] == "ap" else "switch (Switch X)",
            "started": when(inc["started"]), "ended": when(inc["ended"]),
            "seconds": round((inc["ended"] or time.time()) - inc["started"]), "labels_reported": inc["labels"], "flaps": inc["flaps"],
            "dashboard_assessment": {"likely_cause": inc["cause"], "why": inc["why"], "how_sure": inc["sure"]},
            "related_units_same_moment": inc["related"], "label_changes_with_firewalla_details": changes,
            "earlier_incidents_90_days": earlier, "firmware_changes": firmware}



def equipment_health_router_version(version):
    """The router's own Firewalla version (from the MSP): a change is logged
    like a unit's firmware change, since it can affect every unit."""
    version = str(version or "").strip()
    if not version:
        return
    with eh_lock, eh_db() as c:
        old = eh_meta(c, "router_version")
        if old and old != version:
            c.execute("INSERT INTO firmware (at, unit_id, unit_name, before, after) VALUES (?, 'router', ?, ?, ?)",
                      (time.time(), ROUTER_MODEL, old, version))
        if old != version:
            eh_meta(c, "router_version", version)
