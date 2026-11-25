# Internet flows: live throughput, the 24-hour flow history, the local traffic
# recorder and the long-term internet totals.

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import Counter
from contextlib import contextmanager
import requests

from core import (
    BLOCKED_WAN_HISTORY_FILE, BLOCKED_WAN_HISTORY_HOURS, BLOCKED_WAN_HISTORY_SAVE_SECONDS,
    FLOW_HISTORY_CLEANUP_SECONDS, FLOW_HISTORY_DATABASE, FLOW_HISTORY_HOURS,
    BASE_URL, INTERFACE_METADATA, INTERNET_FLOW_WINDOW_SECONDS, LIVE_URL, StateFileError, blocked_wan_history_lock, policy_read_json, router_read_hook, router_read_note,
    flow_history_lock, internet_flow_fingerprints, internet_flow_lock, internet_flow_records,
    state,
)


flow_history_last_cleanup = 0.0
blocked_wan_history = {}
blocked_wan_history_dirty = False
blocked_wan_history_saved_at = 0
blocked_wan_history_unreadable = False   # the saved file is there but couldn't be read: not saved over, tried again
blocked_wan_history_tried_at = 0
BLOCKED_WAN_HISTORY_WRITE_SECONDS = 60


# ============================================================
# LIVE THROUGHPUT COLLECTOR
# ============================================================




def blocked_wan_hour_start(timestamp=None):
    value = float(
        timestamp
        if timestamp is not None
        else time.time()
    )

    return int(value // 3600) * 3600


def blocked_wan_known_interfaces():
    return {
        interface_uuid: (
            metadata.get("display_name")
            or interface_uuid
        )
        for interface_uuid, metadata
        in INTERFACE_METADATA.items()
        if metadata.get("network_type") == "wan"
    }


def prune_blocked_wan_history(now=None):
    current_hour = blocked_wan_hour_start(now)

    # Keep exactly the current hour plus the previous 23 hours.
    oldest_hour = current_hour - (
        (BLOCKED_WAN_HISTORY_HOURS - 1) * 3600
    )

    for wan_uuid in list(blocked_wan_history):
        buckets = (
            blocked_wan_history.get(wan_uuid)
            or {}
        )

        for hour_key in list(buckets):
            try:
                hour_start = int(hour_key)
            except (TypeError, ValueError):
                buckets.pop(hour_key, None)
                continue

            if (
                hour_start < oldest_hour
                or hour_start > current_hour
            ):
                buckets.pop(hour_key, None)

        if not buckets:
            blocked_wan_history.pop(
                wan_uuid,
                None,
            )


def load_blocked_wan_history():
    global blocked_wan_history
    global blocked_wan_history_dirty
    global blocked_wan_history_unreadable, blocked_wan_history_tried_at

    # A file that is there but can't be read is left as it is: nothing is
    # saved over it, and the worker tries it again every 5 minutes (24 Nov
    # 2026: any failed read counted as an empty history, and the next save
    # replaced the day's counts and their repeat guards with nothing).
    blocked_wan_history_tried_at = time.time()
    try:
        loaded = (policy_read_json(BLOCKED_WAN_HISTORY_FILE) or {}).get("wans") or {}
        blocked_wan_history_unreadable = False
    except StateFileError:
        blocked_wan_history_unreadable = True
        return

    with blocked_wan_history_lock:
        blocked_wan_history = (
            loaded
            if isinstance(loaded, dict)
            else {}
        )

        # Normalize persisted bucket fields. Fingerprints are kept
        # in memory as a set of short keys (files saved before
        # version 2 held each whole record; those become keys too).
        for wan_uuid, buckets in (
            blocked_wan_history.items()
        ):
            if not isinstance(
                buckets,
                dict,
            ):
                blocked_wan_history[
                    wan_uuid
                ] = {}
                continue

            for hour_key, bucket in list(
                buckets.items()
            ):
                if not isinstance(
                    bucket,
                    dict,
                ):
                    buckets.pop(
                        hour_key,
                        None,
                    )
                    continue

                saved = bucket.get("fingerprints")
                bucket["fingerprints"] = {
                    blocked_fingerprint_key(value)
                    for value in (saved if isinstance(saved, list) else [])
                }

        prune_blocked_wan_history()
        blocked_wan_history_dirty = False

    publish_blocked_wan_hourly()


def blocked_fingerprint_key(fingerprint):
    """Short fixed-size key (16 hex characters of SHA-1) for one blocked
    record, used to spot a record Firewalla sends again. Keys already in
    that form are returned as they are."""
    text = str(fingerprint)
    if len(text) == 16 and all(c in "0123456789abcdef" for c in text):
        return text
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def save_blocked_wan_history():
    global blocked_wan_history_dirty, blocked_wan_history_saved_at

    with blocked_wan_history_lock:
        # Written once a minute at most (20 Nov 2026): blocked attempts
        # arrive all the time, so the whole file (about 320 KB) was sorted
        # and rewritten every 15 seconds. The page's counts still update
        # every 15 seconds; a stop now loses up to a minute of them.
        if blocked_wan_history_unreadable:
            return   # the saved file couldn't be read: it is not replaced (load_blocked_wan_history)
        if not blocked_wan_history_dirty or time.time() - blocked_wan_history_saved_at < BLOCKED_WAN_HISTORY_WRITE_SECONDS:
            return
        blocked_wan_history_saved_at = time.time()

        prune_blocked_wan_history()

        # Copied while locked: the collector keeps adding records.
        payload = {
            "version": 2,
            "retention_hours": (
                BLOCKED_WAN_HISTORY_HOURS
            ),
            "saved_at": time.time(),
            "wans": {
                wan_uuid: {
                    hour_key: {**bucket, "fingerprints": sorted(bucket.get("fingerprints") or ())}
                    for hour_key, bucket in buckets.items()
                }
                for wan_uuid, buckets in blocked_wan_history.items()
            },
        }

        blocked_wan_history_dirty = False

    temporary_path = (
        BLOCKED_WAN_HISTORY_FILE
        + ".tmp"
    )

    try:
        with open(
            temporary_path,
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                payload,
                handle,
                separators=(",", ":"),
            )

        os.replace(
            temporary_path,
            BLOCKED_WAN_HISTORY_FILE,
        )

    except Exception as exc:
        with blocked_wan_history_lock:
            blocked_wan_history_dirty = True

        print(
            "Blocked WAN history save error:",
            exc,
        )


def mark_blocked_wan_hour_coverage(timestamp=None):
    global blocked_wan_history_dirty

    now = float(
        timestamp
        if timestamp is not None
        else time.time()
    )

    hour_start = blocked_wan_hour_start(now)
    hour_key = str(hour_start)

    with blocked_wan_history_lock:
        for wan_uuid, wan_name in (
            blocked_wan_known_interfaces().items()
        ):
            wan_buckets = (
                blocked_wan_history.setdefault(
                    wan_uuid,
                    {},
                )
            )

            bucket = wan_buckets.setdefault(
                hour_key,
                {
                    "hour_start": hour_start,
                    "attempt_count": 0,
                    "first_observed_at": now,
                    "last_observed_at": now,
                },
            )

            first_observed = float(
                bucket.get(
                    "first_observed_at",
                    now,
                )
            )

            bucket["wan"] = wan_name
            bucket["hour_start"] = hour_start
            bucket["first_observed_at"] = min(
                first_observed,
                now,
            )
            bucket["last_observed_at"] = max(
                float(
                    bucket.get(
                        "last_observed_at",
                        now,
                    )
                ),
                now,
            )

        prune_blocked_wan_history(now)
        blocked_wan_history_dirty = True


def record_blocked_wan_hourly(
    wan_uuid,
    attempt_count,
    timestamp=None,
    fingerprint=None,
):
    global blocked_wan_history_dirty

    if not wan_uuid:
        return

    if (
        INTERFACE_METADATA.get(
            wan_uuid,
            {},
        ).get("network_type")
        != "wan"
    ):
        return

    now = float(
        timestamp
        if timestamp is not None
        else time.time()
    )

    hour_start = blocked_wan_hour_start(now)
    hour_key = str(hour_start)

    with blocked_wan_history_lock:
        wan_buckets = (
            blocked_wan_history.setdefault(
                wan_uuid,
                {},
            )
        )

        bucket = wan_buckets.setdefault(
            hour_key,
            {
                "hour_start": hour_start,
                "attempt_count": 0,
                "first_observed_at": now,
                "last_observed_at": now,
                "fingerprints": set(),
            },
        )

        # Buckets made by mark_blocked_wan_hour_coverage have
        # no fingerprints yet.
        fingerprints = bucket.setdefault(
            "fingerprints",
            set(),
        )

        # Persistently deduplicate each blocked WAN audit
        # record in its own WAN/hour bucket. This prevents
        # Firewalla replay after an SSE reconnect or backend
        # restart from incrementing the same event again.
        if fingerprint:
            fingerprint = blocked_fingerprint_key(
                fingerprint
            )

            if fingerprint in fingerprints:
                return False

            fingerprints.add(
                fingerprint
            )

        bucket["wan"] = (
            INTERFACE_METADATA.get(
                wan_uuid,
                {},
            ).get("display_name")
            or wan_uuid
        )

        bucket["attempt_count"] = (
            int(
                bucket.get(
                    "attempt_count",
                    0,
                )
                or 0
            )
            + int(attempt_count or 1)
        )

        bucket["first_observed_at"] = min(
            float(
                bucket.get(
                    "first_observed_at",
                    now,
                )
            ),
            now,
        )

        bucket["last_observed_at"] = max(
            float(
                bucket.get(
                    "last_observed_at",
                    now,
                )
            ),
            now,
        )

        # By the clock, not this record's own time (24 Nov 2026: a record
        # from just before the hour, arriving just after it, made the old
        # hour "now" and wiped the new hour's bucket, its count and its
        # repeat guard, on every WAN).
        prune_blocked_wan_history()
        blocked_wan_history_dirty = True

        return True


def publish_blocked_wan_hourly(now=None):
    now = float(
        now
        if now is not None
        else time.time()
    )

    current_hour = blocked_wan_hour_start(now)
    oldest_hour = current_hour - (
        (BLOCKED_WAN_HISTORY_HOURS - 1)
        * 3600
    )

    known_wans = blocked_wan_known_interfaces()
    published_wans = {}

    with blocked_wan_history_lock:
        prune_blocked_wan_history(now)

        for wan_uuid, wan_name in (
            known_wans.items()
        ):
            stored = (
                blocked_wan_history.get(
                    wan_uuid,
                    {},
                )
            )

            buckets = []
            total_attempts = 0
            completed_peak = None

            for index in range(
                BLOCKED_WAN_HISTORY_HOURS
            ):
                hour_start = (
                    oldest_hour
                    + (index * 3600)
                )

                record = stored.get(
                    str(hour_start)
                )

                if record is None:
                    bucket = {
                        "hour_start": hour_start,
                        "hour_end": (
                            hour_start + 3600
                        ),
                        "attempt_count": None,
                        "available": False,
                        "current": (
                            hour_start
                            == current_hour
                        ),
                        "coverage_seconds": 0,
                    }

                else:
                    attempt_count = int(
                        record.get(
                            "attempt_count",
                            0,
                        )
                        or 0
                    )

                    first_observed = float(
                        record.get(
                            "first_observed_at",
                            hour_start,
                        )
                    )

                    last_observed = float(
                        record.get(
                            "last_observed_at",
                            first_observed,
                        )
                    )

                    coverage_seconds = max(
                        0,
                        min(
                            3600,
                            last_observed
                            - first_observed,
                        ),
                    )

                    bucket = {
                        "hour_start": hour_start,
                        "hour_end": (
                            hour_start + 3600
                        ),
                        "attempt_count": (
                            attempt_count
                        ),
                        "available": True,
                        "current": (
                            hour_start
                            == current_hour
                        ),
                        "coverage_seconds": (
                            round(
                                coverage_seconds,
                                1,
                            )
                        ),
                    }

                    total_attempts += (
                        attempt_count
                    )

                    if hour_start != current_hour:
                        if (
                            completed_peak is None
                            or attempt_count
                            > completed_peak[
                                "attempt_count"
                            ]
                        ):
                            completed_peak = {
                                "hour_start": (
                                    hour_start
                                ),
                                "attempt_count": (
                                    attempt_count
                                ),
                            }

                buckets.append(bucket)

            current_bucket = buckets[-1]

            published_wans[wan_uuid] = {
                "wan_uuid": wan_uuid,
                "wan": wan_name,
                "total_24h": total_attempts,
                "current_hour": (
                    current_bucket.get(
                        "attempt_count"
                    )
                    if current_bucket.get(
                        "available"
                    )
                    else None
                ),
                "peak_completed_hour": (
                    completed_peak
                ),
                "buckets": buckets,
            }

    state["blocked_wan_hourly"] = {
        "retention_hours": (
            BLOCKED_WAN_HISTORY_HOURS
        ),
        "current_hour_start": (
            current_hour
        ),
        "wans": published_wans,
        "updated_at": now,
    }


def blocked_wan_history_worker():
    while True:
        try:
            now = time.time()

            # A saved file that couldn't be read: tried again every 5 minutes.
            if blocked_wan_history_unreadable and now - blocked_wan_history_tried_at >= 300:
                load_blocked_wan_history()

            # Mark the collector as present during the current
            # hour even if no blocked attempts were observed.
            mark_blocked_wan_hour_coverage(now)
            publish_blocked_wan_hourly(now)
            save_blocked_wan_history()

        except Exception as exc:
            print(
                "Blocked WAN history worker error:",
                exc,
            )

        time.sleep(
            BLOCKED_WAN_HISTORY_SAVE_SECONDS
        )


def internet_interface_type(interface_uuid):
    metadata = INTERFACE_METADATA.get(interface_uuid) or {}

    return metadata.get("network_type")


def internet_flow_fingerprint(record):
    """
    Return a deterministic representation of one raw LiveStats
    flow record. This protects rolling totals if Firewalla ever
    repeats a record after a reconnect or in a later batch.
    """
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    )


def publish_internet_flow_activity(now=None):
    now = float(now or time.time())
    cutoff = now - INTERNET_FLOW_WINDOW_SECONDS

    with internet_flow_lock:

        # Expire records in receipt-time order.
        while (
            internet_flow_records
            and internet_flow_records[0]["received_at"] < cutoff
        ):
            expired = internet_flow_records.popleft()
            fingerprint = expired.get("fingerprint")

            if fingerprint:
                internet_flow_fingerprints.pop(
                    fingerprint,
                    None,
                )

        path_totals = {}
        allowed_wan_totals = {}
        blocked_wan_totals = {}
        normal_flow_count = 0
        blocked_wan_attempt_count = 0

        for record in internet_flow_records:

            kind = record.get("kind")

            if kind == "internet_flow":
                flow_count = int(
                    record.get("count") or 1
                )
                normal_flow_count += flow_count

                # WAN COUNTERS BY DIRECTION
                wan_uuid = record.get("wan_uuid")
                wan_direction = allowed_wan_totals.setdefault(
                    wan_uuid,
                    {
                        "wan_uuid": wan_uuid,
                        "wan": record.get("wan"),
                        "allowed_outbound_count": 0,
                        "allowed_inbound_count": 0,
                        "unknown_direction_count": 0,
                        "last_seen": 0,
                    },
                )
                direction = str(
                    record.get("direction")
                    or ""
                ).lower()
                # WAN LIVESTATS DIRECTION SEMANTICS
                # In this Firewalla LiveStats stream, normal records carrying an
                # explicit outbound WAN arrive with fd=in. fd is therefore an
                # interface-perspective marker here, not the UI initiation label.
                if direction == "in":
                    wan_direction["allowed_outbound_count"] += flow_count
                elif direction == "out":
                    wan_direction["allowed_inbound_count"] += flow_count
                else:
                    wan_direction["unknown_direction_count"] += flow_count
                wan_direction["last_seen"] = max(
                    float(wan_direction.get("last_seen") or 0),
                    float(record.get("received_at") or 0),
                )

                path_key = (
                    record.get("source_uuid"),
                    record.get("wan_uuid"),
                )

                aggregate = path_totals.setdefault(
                    path_key,
                    {
                        "source_uuid": record.get(
                            "source_uuid"
                        ),
                        "source_network": record.get(
                            "source_network"
                        ),
                        "wan_uuid": record.get("wan_uuid"),
                        "wan": record.get("wan"),
                        "upload_bytes": 0,
                        "download_bytes": 0,
                        "flow_count": 0,
                        "last_seen": 0,
                    },
                )

                aggregate["upload_bytes"] += int(
                    record.get("upload_bytes") or 0
                )

                aggregate["download_bytes"] += int(
                    record.get("download_bytes") or 0
                )

                aggregate["flow_count"] += int(
                    record.get("count") or 1
                )

                aggregate["last_seen"] = max(
                    float(aggregate.get("last_seen") or 0),
                    float(record.get("received_at") or 0),
                )

            elif kind == "blocked_wan":
                attempts = int(
                    record.get("count") or 1
                )

                blocked_wan_attempt_count += attempts

                wan_uuid = record.get("wan_uuid")

                aggregate = blocked_wan_totals.setdefault(
                    wan_uuid,
                    {
                        "wan_uuid": wan_uuid,
                        "wan": record.get("wan"),
                        "attempt_count": 0,
                        "last_seen": 0,
                        "remote_sources": {},
                    },
                )

                aggregate["attempt_count"] += attempts

                aggregate["last_seen"] = max(
                    float(aggregate.get("last_seen") or 0),
                    float(record.get("received_at") or 0),
                )

                source_key = " | ".join(
                    [
                        str(
                            record.get("remote_ip")
                            or "--"
                        ),
                        str(
                            record.get("country")
                            or "--"
                        ),
                        str(
                            record.get("protocol")
                            or "--"
                        ).upper()
                        + "/"
                        + str(
                            record.get("port")
                            if record.get("port")
                            is not None
                            else "--"
                        ),
                    ]
                )

                source = aggregate[
                    "remote_sources"
                ].setdefault(
                    source_key,
                    {
                        "remote_ip": record.get(
                            "remote_ip"
                        ),
                        "country": record.get(
                            "country"
                        ),
                        "protocol": record.get(
                            "protocol"
                        ),
                        "port": record.get("port"),
                        "attempt_count": 0,
                        "last_seen": 0,
                    },
                )

                source["attempt_count"] += attempts
                source["last_seen"] = max(
                    float(source.get("last_seen") or 0),
                    float(record.get("received_at") or 0),
                )

        paths = []

        for aggregate in path_totals.values():
            aggregate["total_bytes"] = (
                int(
                    aggregate.get("upload_bytes")
                    or 0
                )
                + int(
                    aggregate.get("download_bytes")
                    or 0
                )
            )

            paths.append(aggregate)

        paths.sort(
            key=lambda item: (
                item.get("total_bytes") or 0,
                item.get("flow_count") or 0,
            ),
            reverse=True,
        )

        allowed_wans = list(
            allowed_wan_totals.values()
        )
        allowed_wans.sort(
            key=lambda item: (
                int(item.get("allowed_outbound_count") or 0)
                + int(item.get("allowed_inbound_count") or 0),
                item.get("last_seen") or 0,
            ),
            reverse=True,
        )

        blocked_wans = []

        for aggregate in blocked_wan_totals.values():
            top_sources = list(
                aggregate.pop(
                    "remote_sources",
                    {},
                ).values()
            )

            top_sources.sort(
                key=lambda item: (
                    item.get("attempt_count") or 0,
                    item.get("last_seen") or 0,
                ),
                reverse=True,
            )

            aggregate["top_sources"] = top_sources[:10]
            blocked_wans.append(aggregate)

        blocked_wans.sort(
            key=lambda item: (
                item.get("attempt_count") or 0,
                item.get("last_seen") or 0,
            ),
            reverse=True,
        )

        state["internet_flow_activity"] = {
            "window_seconds": (
                INTERNET_FLOW_WINDOW_SECONDS
            ),
            "paths": paths,
            # WAN COUNTERS BY DIRECTION
            "allowed_wans": allowed_wans,
            "blocked_wans": blocked_wans,
            "normal_flow_count": normal_flow_count,
            "blocked_wan_attempt_count": (
                blocked_wan_attempt_count
            ),
            "records_retained": len(
                internet_flow_records
            ),
            "updated_at": now,
        }



def recent_flow_device_name(device_mac, device_ip):
    """A device's current name: by MAC when the record has one (an IP can be
    shared, e.g. the NAS cluster's .254 follows the active node); by IP only
    when there is no MAC."""
    mac = str(device_mac or "").upper()
    ip = str(device_ip or "")
    devices = state.get("devices") or []
    for device in devices:
        if mac:
            if str(device.get("mac") or "").upper() != mac:
                continue
        elif not ip or str(device.get("ip") or device.get("ipv4Addr") or "") != ip:
            continue
        return device.get("name") or device.get("display_name") or device.get("bname") or ip or mac
    # A VPN peer (another site, a phone on the VPN): a flow names it by its
    # key ("AWG_PEER:<KEY>"); its name is the one you gave it in Firewalla.
    if "_PEER:" in mac:
        for peers in (state.get("vpn_peers") or {}).values():
            for peer in peers:
                if peer.get("flow_id") == mac and peer.get("name"):
                    return peer["name"]
    return ip or mac or "--"



# ============================================================
# PERSISTENT FLOW HISTORY
# ============================================================

flow_history_publish_lock = threading.Lock()


def flow_history_publish(changes):
    """New flow-history figures for state: they go out as a new copy with
    the changed ones replaced. The copy in state is never changed in place
    (20 Nov 2026), so a page answer being written out isn't disturbed."""
    with flow_history_publish_lock:
        state["flow_history"] = {**state["flow_history"], **changes}


def flow_history_connection():
    connection = sqlite3.connect(
        FLOW_HISTORY_DATABASE,
        timeout=15,
    )

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )
    connection.execute(
        "PRAGMA synchronous=NORMAL"
    )
    connection.execute(
        "PRAGMA busy_timeout=15000"
    )

    return connection


@contextmanager
def flow_history_reader():
    """A connection for reading. Reads take no lock: the database is in WAL
    mode, so readers never wait for the writer or for each other (holding
    flow_history_lock for a 4-second summary held up saving the live feed).
    Writes and deletes still take flow_history_lock."""
    connection = flow_history_connection()
    try:
        yield connection
    finally:
        connection.close()


def flow_history_event_timestamp(record):
    value = record.get("flow_ts")

    try:
        value = float(value)
    except (TypeError, ValueError):
        value = float(
            record.get("received_at")
            or time.time()
        )

    return value


def flow_history_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def flow_history_fingerprint(raw_record):
    canonical = internet_flow_fingerprint(
        raw_record
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def initialize_flow_history():
    database_parent = os.path.dirname(
        os.path.abspath(
            FLOW_HISTORY_DATABASE
        )
    )

    if database_parent:
        os.makedirs(
            database_parent,
            exist_ok=True,
        )

    try:
        with flow_history_lock:
            connection = flow_history_connection()

            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schema_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS flow_records (
                        row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint TEXT NOT NULL UNIQUE,
                        received_at REAL NOT NULL,
                        event_at REAL NOT NULL,
                        kind TEXT NOT NULL,
                        device TEXT,
                        device_mac TEXT,
                        device_ip TEXT,
                        source_uuid TEXT,
                        source_network TEXT,
                        outbound_uuid TEXT,
                        outbound TEXT,
                        destination TEXT,
                        remote_ip TEXT,
                        country TEXT,
                        protocol TEXT,
                        port INTEGER,
                        service TEXT,
                        direction TEXT,
                        policy_pid TEXT,
                        allowed_pid TEXT,
                        count INTEGER NOT NULL DEFAULT 1,
                        starts INTEGER,
                        upload_bytes INTEGER,
                        download_bytes INTEGER,
                        payload_json TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_event_at
                        ON flow_records(event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_kind_event
                        ON flow_records(kind, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_device_mac_event
                        ON flow_records(device_mac, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_device_ip_event
                        ON flow_records(device_ip, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_source_event
                        ON flow_records(source_uuid, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_outbound_event
                        ON flow_records(outbound_uuid, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_destination_event
                        ON flow_records(destination, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_policy_event
                        ON flow_records(policy_pid, event_at);

                    CREATE INDEX IF NOT EXISTS
                        idx_flow_records_allowed_event
                        ON flow_records(allowed_pid, event_at);
                    """
                )

                if "starts" not in {row[1] for row in connection.execute("PRAGMA table_info(flow_records)")}:
                    connection.execute("ALTER TABLE flow_records ADD COLUMN starts INTEGER")   # D-956: rows from before have none

                connection.execute(
                    """
                    INSERT INTO schema_metadata(key, value)
                    VALUES('schema_version', '1')
                    ON CONFLICT(key)
                    DO UPDATE SET value=excluded.value
                    """
                )

                connection.commit()

            finally:
                connection.close()

        flow_history_publish(
            {
                "enabled": True,
                "healthy": True,
                "database_path": (
                    FLOW_HISTORY_DATABASE
                ),
                "retention_hours": (
                    FLOW_HISTORY_HOURS
                ),
                "last_error": None,
            }
        )

        cleanup_flow_history(
            force=True
        )
        publish_flow_history_status(force=True)

        print(
            "Flow history database ready:",
            FLOW_HISTORY_DATABASE,
        )

    except Exception as exc:
        flow_history_publish(
            {
                "enabled": True,
                "healthy": False,
                "database_path": (
                    FLOW_HISTORY_DATABASE
                ),
                "retention_hours": (
                    FLOW_HISTORY_HOURS
                ),
                "last_error": str(exc),
            }
        )

        print(
            "Flow history initialization error:",
            exc,
        )


def persist_flow_history(
    raw_and_normalized_records,
    received_at,
):
    if not raw_and_normalized_records:
        return

    inserted = 0
    duplicates = 0

    rows = []

    for raw_record, normalized in (
        raw_and_normalized_records
    ):
        fingerprint = flow_history_fingerprint(
            raw_record
        )

        event_at = flow_history_event_timestamp(
            normalized
        )

        rows.append(
            (
                fingerprint,
                float(
                    normalized.get("received_at")
                    or received_at
                ),
                event_at,
                normalized.get("kind")
                or "unknown",
                normalized.get("device"),
                normalized.get("device_mac"),
                normalized.get("device_ip"),
                normalized.get("source_uuid"),
                normalized.get("source_network"),
                normalized.get("outbound_uuid"),
                normalized.get("outbound"),
                normalized.get("destination"),
                normalized.get("remote_ip"),
                normalized.get("country"),
                normalized.get("protocol"),
                normalized.get("port"),
                normalized.get("service"),
                normalized.get("direction"),
                normalized.get("policy_pid"),
                normalized.get("allowed_pid"),
                int(
                    normalized.get("count")
                    or 1
                ),
                normalized.get("starts"),
                normalized.get("upload_bytes"),
                normalized.get("download_bytes"),
                flow_history_json(
                    normalized
                ),
            )
        )

    try:
        with flow_history_lock:
            connection = flow_history_connection()

            try:
                before_changes = (
                    connection.total_changes
                )

                connection.executemany(
                    """
                    INSERT INTO flow_records (
                        fingerprint,
                        received_at,
                        event_at,
                        kind,
                        device,
                        device_mac,
                        device_ip,
                        source_uuid,
                        source_network,
                        outbound_uuid,
                        outbound,
                        destination,
                        remote_ip,
                        country,
                        protocol,
                        port,
                        service,
                        direction,
                        policy_pid,
                        allowed_pid,
                        count,
                        starts,
                        upload_bytes,
                        download_bytes,
                        payload_json
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(fingerprint)
                    DO NOTHING
                    """,
                    rows,
                )

                inserted = (
                    connection.total_changes
                    - before_changes
                )
                duplicates = max(
                    0,
                    len(rows) - inserted,
                )

                connection.commit()

            finally:
                connection.close()

        flow_history_publish(
            {
                "healthy": True,
                "last_write_at": time.time(),
                "last_inserted": inserted,
                "last_duplicates": duplicates,
                "last_error": None,
            }
        )

        cleanup_flow_history()
        publish_flow_history_status()

    except Exception as exc:
        flow_history_publish(
            {
                "healthy": False,
                "last_error": str(exc),
            }
        )

        print(
            "Flow history write error:",
            exc,
        )


def cleanup_flow_history(force=False):
    global flow_history_last_cleanup

    now = time.time()

    if (
        not force
        and (
            now - flow_history_last_cleanup
            < FLOW_HISTORY_CLEANUP_SECONDS
        )
    ):
        return

    cutoff = (
        now
        - FLOW_HISTORY_HOURS
        * 3600
    )

    try:
        with flow_history_lock:
            connection = flow_history_connection()

            try:
                connection.execute(
                    """
                    DELETE FROM flow_records
                    WHERE event_at < ?
                    """,
                    (cutoff,),
                )
                connection.commit()

            finally:
                connection.close()

        flow_history_last_cleanup = now

        flow_history_publish(
            {
                "healthy": True,
                "last_cleanup_at": now,
                "last_error": None,
            }
        )

    except Exception as exc:
        flow_history_publish(
            {
                "healthy": False,
                "last_error": str(exc),
            }
        )

        print(
            "Flow history cleanup error:",
            exc,
        )


# ------------------------------------------------------------
# Nightly database self-check: SQLite's full integrity check on the flow
# history, read-only (the dashboard keeps recording while it runs). The
# result is kept in /data so a restart doesn't lose it, and shown on the
# Telemetry Health card. It reports; it never repairs anything.
# ------------------------------------------------------------
FLOW_DB_CHECK_FILE = os.environ.get("FIREWALLA_DB_CHECK_FILE", "/data/flow_db_check.json")
# Worked out in UTC whatever the container's own time zone (Central since
# 14 Nov 2026): 09:00 UTC is 3 AM Central Standard Time (4 AM during
# daylight saving time).
FLOW_DB_CHECK_HOUR_UTC = 9
flow_db_check_lock = threading.Lock()


FLOW_HISTORY_STATUS_SECONDS = 30
flow_history_status_at = 0


def publish_flow_history_status(force=False):
    """Record counts for the status reply. Asked for after every write (every
    few seconds), but counted at most every 30 s: counting the whole day's
    records after each batch of flows was needless work for the live feed."""
    global flow_history_status_at
    now = time.time()
    if not force and now - flow_history_status_at < FLOW_HISTORY_STATUS_SECONDS:
        return
    flow_history_status_at = now
    try:
        with flow_history_reader() as connection:
            counts = dict(connection.execute("SELECT kind, COUNT(*) FROM flow_records GROUP BY kind").fetchall())
            oldest, newest = connection.execute("SELECT MIN(event_at), MAX(event_at) FROM flow_records").fetchone()
        flow_history_publish({
            "enabled": True, "healthy": True, "database_path": FLOW_HISTORY_DATABASE,
            "retention_hours": FLOW_HISTORY_HOURS, "records": sum(counts.values()),
            "normal_records": counts.get("normal", 0), "blocked_records": counts.get("blocked", 0),
            "oldest_event_at": oldest, "newest_event_at": newest, "last_error": None,
        })
    except Exception as exc:
        flow_history_publish({"healthy": False, "last_error": str(exc)})
        print("Flow history status error:", exc)


# ============================================================
# LOCAL TRAFFIC RECORDER
#
# Traffic between your own devices (across networks/VLANs), which the
# internet flow history never sees. A second LiveStats stream asks the
# router for local flows (flows: audit + local); each finished flow is
# added to an hourly total per (initiator, responder, protocol, port,
# allowed/blocked) with bytes each way and the number of flows.
# Totals for the last minute are held in memory and written to their
# own small database every minute; 7 days are kept. The same totals also
# go into local_traffic_daily, one row per day and connection, kept 1 year
# (17 Nov 2026: the "ever seen" record, so rare traffic such as printing
# or backups builds up beyond the hourly week; days seen = its rows).
#
# Direction: the router reports each flow once, from one device's side
# ("device"; fd "in" = that device started it, as seen on 13 Nov 2026:
# NAS -> camera port 2020 with fd "in"; "out" = the other side did).
# Rows are stored initiator -> responder, bytes as sent/received by the
# initiator; "port" is the responder's port. fd "lo" = two devices on
# the same network: reported without protocol or port (stored as "").
# When fd points the wrong way (blocked flows are reported from the
# answering side; long streams picked up mid-way), the port decides: the
# side on a fixed port is the responder (see local_traffic_row).
# "Blocked" = ltype "audit" (the router's word for a blocked flow); the
# live stream sends blocked LOCAL flows only when asked with "localAudit"
# (13 Nov 2026). The last raw records are kept for /api/local-traffic/status.
#
# ALLOWED local flows come from the router's stored history instead (the
# list the app's Local Flows tab shows), read every 3 minutes: the live
# stream sends only about two thirds of them (17 Nov 2026: 531 of the 826
# the router stored in five minutes; 20 of 80 device pairs missing, e.g.
# NAS <-> cameras, Speakers, Phone B -> Fire TV). Blocked local flows still
# come from the live stream. While the history can't be read (the router's
# dashboard filter not updated, the router busy), the live stream's allowed
# flows are recorded as before; see local_history_worker.
# ============================================================

LOCAL_TRAFFIC_DATABASE = os.environ.get("FIREWALLA_LOCAL_TRAFFIC_DB", "/data/local_traffic.db")
LOCAL_TRAFFIC_RETENTION_SECONDS = 7 * 86400
LOCAL_TRAFFIC_DAILY_SECONDS = 365 * 86400
LOCAL_TRAFFIC_FLUSH_SECONDS = 60
LOCAL_TRAFFIC_COLUMNS = """src_mac TEXT NOT NULL, dst_mac TEXT NOT NULL,
    protocol TEXT NOT NULL, port TEXT NOT NULL, outcome TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_intf TEXT, dst_intf TEXT,
    src_groups TEXT, dst_groups TEXT,
    bytes_sent INTEGER NOT NULL DEFAULT 0, bytes_received INTEGER NOT NULL DEFAULT 0,
    flows INTEGER NOT NULL DEFAULT 0,
    first_ts REAL, last_ts REAL, starts INTEGER"""

local_traffic_lock = threading.Lock()
local_traffic_pending = {}           # row key -> totals not yet written
local_traffic_seen = {}              # fingerprint -> time seen (repeat guard, 10 min)
# A connection that stays open (a camera stream, a backup, the dashboard's
# SSH tunnel) gets a fresh router record about every minute, all with the
# same two addresses and ports (seen 23 Nov 2026: each Tapo stream 57-60
# records an hour, the cabin SSH tunnel 120 an hour, counted as 2812 "tries"
# by the nightly review). "starts" counts only the records whose addresses
# and ports weren't seen in the LOCAL_CONNECTION_GAP before: the connections
# actually opened. A record without the starting side's port counts as a
# start. Rows written before 23 Nov 2026 have none (NULL).
local_connections_open = {}          # (src, src port, dst, dst port, protocol) -> last record time
local_no_port = Counter()            # "tcp 554" -> records without the starting side's port, since the start (/api/traffic-local/open)
LOCAL_CONNECTION_GAP = 300
local_traffic_stats = {
    "connected": False, "started_at": None, "last_record_at": None, "last_flush_at": None,
    "records": 0, "local": 0, "allowed": 0, "blocked": 0, "repeats": 0, "skipped": 0, "error": None,
    "left_to_history": 0,
}


def local_traffic_connection():
    connection = sqlite3.connect(LOCAL_TRAFFIC_DATABASE, timeout=15)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize_local_traffic():
    with local_traffic_connection() as connection:
        connection.execute(f"""
            CREATE TABLE IF NOT EXISTS local_traffic_hourly (
                hour INTEGER NOT NULL, {LOCAL_TRAFFIC_COLUMNS},
                PRIMARY KEY (hour, src_mac, dst_mac, protocol, port, outcome)
            )""")
        connection.execute("CREATE INDEX IF NOT EXISTS local_traffic_by_time ON local_traffic_hourly (hour)")
        # allowed_by: the rule the router says allowed the flow (its "apid");
        # blocked_by: what it says blocked it ("rule:<pid>", or "<orig>:<group>",
        # e.g. "ap:50" = VqLAN/Isolation of group 50). Both added 13 Nov 2026
        # to databases made before then.
        columns = {row[1] for row in connection.execute("PRAGMA table_info(local_traffic_hourly)")}
        for column in ("allowed_by", "blocked_by"):
            if column not in columns:
                connection.execute(f"ALTER TABLE local_traffic_hourly ADD COLUMN {column} TEXT")
        if "starts" not in columns:
            connection.execute("ALTER TABLE local_traffic_hourly ADD COLUMN starts INTEGER")
        new_daily = not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'local_traffic_daily'").fetchone()
        connection.execute(f"""
            CREATE TABLE IF NOT EXISTS local_traffic_daily (
                day INTEGER NOT NULL, {LOCAL_TRAFFIC_COLUMNS},
                allowed_by TEXT, blocked_by TEXT,
                PRIMARY KEY (day, src_mac, dst_mac, protocol, port, outcome)
            )""")
        connection.execute("CREATE INDEX IF NOT EXISTS local_traffic_daily_by_pair"
                           " ON local_traffic_daily (src_mac, dst_mac, day)")
        if new_daily:
            # Start the year with the week the hourly table still holds.
            local_traffic_upsert(connection, "local_traffic_daily", "day", [
                ((internet_day(r[0]), *r[1:6]), dict(zip(LOCAL_TRAFFIC_TOTALS, r[6:])))
                for r in connection.execute(
                    f"SELECT hour, src_mac, dst_mac, protocol, port, outcome, {', '.join(LOCAL_TRAFFIC_TOTAL_COLUMNS)}"
                    " FROM local_traffic_hourly ORDER BY hour")])
        if "starts" not in {row[1] for row in connection.execute("PRAGMA table_info(local_traffic_daily)")}:
            connection.execute("ALTER TABLE local_traffic_daily ADD COLUMN starts INTEGER")
        local_traffic_drop_misrecorded(connection)
        connection.execute("CREATE TABLE IF NOT EXISTS local_traffic_meta (name TEXT PRIMARY KEY, value REAL)")
        # When "starts" began: rows from the next hour (day) on all have it.
        connection.execute("INSERT OR IGNORE INTO local_traffic_meta VALUES ('starts_since', ?)", (time.time(),))
        # The connections that were open at the last save (flush_local_traffic).
        try:
            for conn, ts in json.loads(local_meta_get(connection, "connections_open") or "[]"):
                local_connections_open.setdefault(tuple(conn), float(ts))
        except (TypeError, ValueError):
            pass


def local_meta_get(connection, name):
    row = connection.execute("SELECT value FROM local_traffic_meta WHERE name = ?", (name,)).fetchone()
    return row[0] if row else None


def local_meta_set(connection, name, value):
    connection.execute("INSERT INTO local_traffic_meta VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value", (name, value))


# Before the direction fix of 13 Nov 2026 11:26 (local_traffic_row: the side
# on a fixed port is the responder), long streams picked up mid-way and
# blocked flows reported from the answering side were stored the wrong way
# round: camera -> NAS on a random port (really NAS -> camera TCP 554),
# refrigerator -> Rachio on random ports. Removed once (17 Nov 2026, the
# owner's go-ahead): random-port rows recorded before 11:30 that day whose
# pair has a fixed-port row the other way. The rows' tables note it done.
LOCAL_TRAFFIC_FIX_AT = 1794591000   # 13 Nov 2026 11:30 US Central


def local_traffic_drop_misrecorded(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS local_traffic_cleanups (name TEXT PRIMARY KEY, at REAL, removed INTEGER)")
    if connection.execute("SELECT 1 FROM local_traffic_cleanups WHERE name = 'misrecorded-direction'").fetchone():
        return
    removed = 0
    for table in ("local_traffic_daily", "local_traffic_hourly"):
        removed += connection.execute(f"""
            DELETE FROM {table} WHERE rowid IN (
                SELECT a.rowid FROM {table} a
                WHERE a.port <> '' AND CAST(a.port AS INTEGER) >= 32768 AND a.last_ts < ?
                  AND EXISTS (SELECT 1 FROM {table} b WHERE b.src_mac = a.dst_mac AND b.dst_mac = a.src_mac
                              AND b.protocol = a.protocol AND b.port <> '' AND CAST(b.port AS INTEGER) < 32768))""",
            (LOCAL_TRAFFIC_FIX_AT,)).rowcount
    connection.execute("INSERT INTO local_traffic_cleanups VALUES ('misrecorded-direction', ?, ?)", (time.time(), removed))
    print(f"Local traffic: removed {removed} rows stored the wrong way round before 13 Nov 2026")


# Totals kept per row, as named in memory (pending) and in the tables.
LOCAL_TRAFFIC_TOTALS = ("src_ip", "dst_ip", "src_intf", "dst_intf", "src_groups", "dst_groups",
                        "sent", "received", "flows", "first_ts", "last_ts", "allowed_by", "blocked_by", "starts")
LOCAL_TRAFFIC_TOTAL_COLUMNS = ("src_ip", "dst_ip", "src_intf", "dst_intf", "src_groups", "dst_groups",
                               "bytes_sent", "bytes_received", "flows", "first_ts", "last_ts",
                               "allowed_by", "blocked_by", "starts")


def local_traffic_upsert(connection, table, period, rows):
    """Add (key, totals) rows to a local traffic table; key = (period start,
    src_mac, dst_mac, protocol, port, outcome)."""
    if not rows:
        return
    connection.executemany(f"""
        INSERT INTO {table} ({period}, src_mac, dst_mac, protocol, port, outcome,
            {', '.join(LOCAL_TRAFFIC_TOTAL_COLUMNS)})
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT ({period}, src_mac, dst_mac, protocol, port, outcome) DO UPDATE SET
            src_ip = excluded.src_ip, dst_ip = excluded.dst_ip,
            src_intf = excluded.src_intf, dst_intf = excluded.dst_intf,
            src_groups = excluded.src_groups, dst_groups = excluded.dst_groups,
            bytes_sent = bytes_sent + excluded.bytes_sent,
            bytes_received = bytes_received + excluded.bytes_received,
            flows = flows + excluded.flows,
            first_ts = MIN(first_ts, excluded.first_ts),
            last_ts = MAX(last_ts, excluded.last_ts),
            allowed_by = COALESCE(excluded.allowed_by, allowed_by),
            blocked_by = COALESCE(excluded.blocked_by, blocked_by),
            starts = starts + excluded.starts""",
        [(*key, *(t[name] for name in LOCAL_TRAFFIC_TOTALS)) for key, t in rows])


def local_traffic_row(raw):
    """One raw local flow -> (row key, values), or None if not usable."""
    ltype = str(raw.get("ltype") or "").lower()
    if ltype not in ("flow", "audit"):
        return None
    device = {
        "mac": str(raw.get("device") or "").upper(),
        "ip": str(raw.get("deviceIP") or ""),
        "intf": raw.get("intf") or "",
        "groups": [str(t) for t in raw.get("tags") or []],
    }
    peer_tags = raw.get("dstTags") if isinstance(raw.get("dstTags"), dict) else {}
    peer = {
        "mac": str(raw.get("dstMac") or "").upper(),
        "ip": str(raw.get("ip") or ""),
        "intf": raw.get("dIntf") or "",
        "groups": [str(t) for t in peer_tags.get("tags") or []],
    }
    if not (device["mac"] or device["ip"]) or not (peer["mac"] or peer["ip"]):
        return None
    sent, received = int(raw.get("upload") or 0), int(raw.get("download") or 0)
    # "port" is the peer's port, "devicePort" the reporting device's.
    port_of = lambda value: None if value in (None, "") else str(value)
    device["port"], peer["port"] = port_of(raw.get("devicePort")), port_of(raw.get("port"))
    if str(raw.get("fd") or "in").lower() == "in":
        src, dst = device, peer
    else:
        src, dst, sent, received = peer, device, received, sent
    # The side answering on a fixed port is the responder, whatever fd says:
    # when the "responder" uses a random high port (32768 and up, where
    # operating systems pick the starter's port) and the "starter" a fixed
    # one, swap them. Fixes blocked flows (fd "in" from the answering side,
    # e.g. refrigerator -> Rachio:8883 reported as Rachio -> port 51748)
    # and long streams picked up mid-way (camera -> NAS high port).
    ephemeral = lambda p: p is not None and p.isdigit() and int(p) >= 32768
    if ephemeral(dst["port"]) and src["port"] is not None and not ephemeral(src["port"]):
        src, dst, sent, received = dst, src, received, sent
    try:
        ts = float(raw.get("ts") or time.time())
    except (TypeError, ValueError):
        ts = time.time()
    outcome = "blocked" if ltype == "audit" else "allowed"
    key = (
        int(ts // 3600 * 3600),
        src["mac"] or src["ip"], dst["mac"] or dst["ip"],
        str(raw.get("protocol") or "").lower(), dst["port"] or "",
        outcome,
    )
    return key, {
        "src": src, "dst": dst, "sent": sent, "received": received, "ts": ts,
        "flows": max(1, int(raw.get("count") or 1)),
        "connection": None if src["port"] is None else (src["mac"] or src["ip"], src["port"], dst["mac"] or dst["ip"], dst["port"],
                                                         str(raw.get("protocol") or "").lower()),
        "allowed_by": None if raw.get("apid") in (None, "") else str(raw.get("apid")),
        "blocked_by": local_blocked_by(raw) if outcome == "blocked" else None,
    }


def local_blocked_by(raw):
    """What the router says blocked a local flow: its rule, else the kind of
    block and the group it belongs to (orig "ap" + isoGID = a group's VqLAN
    or Isolation)."""
    if raw.get("pid") not in (None, ""):
        return f"rule:{raw['pid']}"
    orig = str(raw.get("orig") or raw.get("reason") or "").strip()
    group = raw.get("isoGID")
    return f"{orig}:{group}" if orig and group not in (None, "") else (orig or None)


def record_local_traffic(records, source="live"):
    now = time.time()
    with local_traffic_lock:
        for raw in records or []:
            local_traffic_stats["records"] += 1
            if not isinstance(raw, dict):
                continue
            if (source == "live" and raw.get("local") and str(raw.get("ltype") or "").lower() == "flow"
                    and local_history["mode"] != "live"):
                local_traffic_stats["left_to_history"] += 1   # the history has it (and the ones the stream misses)
                continue
            if not raw.get("local"):
                continue
            fingerprint = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            if fingerprint in local_traffic_seen:
                local_traffic_stats["repeats"] += 1
                continue
            local_traffic_seen[fingerprint] = now
            row = local_traffic_row(raw)
            if row is None:
                local_traffic_stats["skipped"] += 1
                continue
            key, v = row
            local_traffic_stats["local"] += 1
            local_traffic_stats[key[5]] += 1
            local_traffic_stats["last_record_at"] = now
            totals = local_traffic_pending.get(key)
            if totals is None:
                totals = local_traffic_pending[key] = {
                    "src_ip": v["src"]["ip"], "dst_ip": v["dst"]["ip"],
                    "src_intf": v["src"]["intf"], "dst_intf": v["dst"]["intf"],
                    "src_groups": json.dumps(v["src"]["groups"]), "dst_groups": json.dumps(v["dst"]["groups"]),
                    "sent": 0, "received": 0, "flows": 0, "first_ts": v["ts"], "last_ts": v["ts"],
                    "allowed_by": None, "blocked_by": None, "starts": 0,
                }
            totals["allowed_by"] = v["allowed_by"] or totals["allowed_by"]
            totals["blocked_by"] = v["blocked_by"] or totals["blocked_by"]
            totals["sent"] += v["sent"]
            totals["received"] += v["received"]
            totals["flows"] += v["flows"]
            conn = v["connection"]
            before = local_connections_open.get(conn) if conn else None
            if before is None or abs(v["ts"] - before) > LOCAL_CONNECTION_GAP:
                totals["starts"] += v["flows"]
            if conn:
                local_connections_open[conn] = max(before or 0, v["ts"])
            else:
                local_no_port[f"{key[3]} {key[4]}"] += v["flows"]   # counted as starts: no port to match
            totals["first_ts"] = min(totals["first_ts"], v["ts"])
            totals["last_ts"] = max(totals["last_ts"], v["ts"])
        if len(local_connections_open) > 20000:
            latest = max(local_connections_open.values())
            for conn in [c for c, ts in local_connections_open.items() if ts < latest - LOCAL_CONNECTION_GAP]:
                del local_connections_open[conn]
        if len(local_traffic_seen) > 20000:
            cutoff = now - 600
            for fp in [fp for fp, seen in local_traffic_seen.items() if seen < cutoff]:
                del local_traffic_seen[fp]


# When a save last added to a day before today (a flow that arrived late,
# the catch-up after a restart). Pages that keep the totals of the days
# before today read them again when this changes; otherwise those days are
# read once a day instead of at every build.
past_days_written = {"local": 0.0, "internet": 0.0}


def traffic_put_back(waiting, unsaved, sums):
    """After a save that failed: the totals it didn't write go back with the
    waiting ones (added to whatever was recorded since), so the next save
    writes them (20 Nov 2026: before, that minute was lost). Both tables are
    written in one step, so a failed save wrote neither."""
    for key, old in unsaved.items():
        new = waiting.get(key)
        if new is None:
            waiting[key] = old
            continue
        for name in sums:
            new[name] += old[name]
        new["first_ts"] = min(new["first_ts"], old["first_ts"])
        new["last_ts"] = max(new["last_ts"], old["last_ts"])
        for name, value in old.items():
            if new.get(name) is None:
                new[name] = value


def flush_local_traffic():
    with local_traffic_lock:
        pending = dict(local_traffic_pending)
        local_traffic_pending.clear()
        # The connections open now go with the save, so a restart knows
        # them (24 Nov 2026: the table was only in memory, so after every
        # restart each stream still open counted as a new start).
        latest = max(local_connections_open.values(), default=0)
        open_now = [[list(conn), ts] for conn, ts in local_connections_open.items() if ts >= latest - LOCAL_CONNECTION_GAP]
    try:
        with local_traffic_connection() as connection:
            rows = list(pending.items())
            local_traffic_upsert(connection, "local_traffic_hourly", "hour", rows)
            local_traffic_upsert(connection, "local_traffic_daily", "day", [((internet_day(key[0]), *key[1:]), t) for key, t in rows])
            local_meta_set(connection, "connections_open", json.dumps(open_now))
            now = time.time()
            connection.execute("DELETE FROM local_traffic_hourly WHERE hour < ?",
                               (int(now - LOCAL_TRAFFIC_RETENTION_SECONDS) // 3600 * 3600,))
            connection.execute("DELETE FROM local_traffic_daily WHERE day < ?",
                               (internet_day(now - LOCAL_TRAFFIC_DAILY_SECONDS),))
    except Exception:
        with local_traffic_lock:
            traffic_put_back(local_traffic_pending, pending, ("sent", "received", "flows", "starts"))
        raise
    if any(key[0] < internet_day(now) for key in pending):
        past_days_written["local"] = now
    local_traffic_stats["last_flush_at"] = time.time()


def local_traffic_flush_worker():
    while True:
        time.sleep(LOCAL_TRAFFIC_FLUSH_SECONDS)
        try:
            flush_local_traffic()
        except Exception as exc:
            local_traffic_stats["error"] = f"save: {exc}"
            print("Local traffic save error:", exc)


def local_traffic_worker():
    # "audit" alone brings only internet blocks (seen 13 Nov 2026: 178 blocked
    # records in 3.5 min, none local); "localAudit" asks for blocked local
    # flows too (the option Firewalla's own app uses).
    payload = {"type": "system", "target": "0.0.0.0",
               "queries": {"flows": {"audit": True, "local": True, "localAudit": True}}}
    local_traffic_stats["started_at"] = time.time()
    while True:
        try:
            with requests.post(LIVE_URL, json=payload, headers={"Content-Type": "application/json"},
                               stream=True, timeout=(10, 30)) as response:
                response.raise_for_status()
                local_traffic_stats["connected"] = True
                local_traffic_stats["error"] = None
                for line in response.iter_lines(decode_unicode=True):
                    router_read_note("live stream (local traffic)", len(line or "") + 1)
                    if not line or not line.startswith("data: "):
                        continue
                    try:
                        data = (json.loads(line[6:]) or {}).get("data") or {}
                    except ValueError:
                        continue
                    record_local_traffic(data.get("flows") or [])
        except Exception as exc:
            local_traffic_stats["error"] = f"stream: {exc}"
            print("Local traffic stream error:", exc)
        local_traffic_stats["connected"] = False
        time.sleep(5)


LOCAL_HISTORY_URL = f"{BASE_URL}/v1/encipher/complex?command=get&target=0.0.0.0"
LOCAL_HISTORY_SECONDS = 180
LOCAL_HISTORY_LAG_SECONDS = 120          # the router writes local flows in batches, about once a minute
LOCAL_HISTORY_MAX = 5000                 # rows per call (the router filter's limit)
LOCAL_HISTORY_CATCH_UP_SECONDS = 86400   # after a restart, at most the last day is read back
LOCAL_HISTORY_GIVE_UP = 3                # failed reads in a row (9 minutes) before the live stream takes over
# mode: "live" = the live stream's allowed local flows are recorded (at the
# start, and while the history stays unreadable); "history" = they come from the
# history; "starting" = after a restart with a saved place, the first read
# fills in the time the dashboard was down.
# cursor: the history is read (or needn't be) up to here. holes: [[from,
# to], ...] times a give-up left unread, read once the history answers
# again (24 Nov 2026: they were skipped). Both are kept in the database.
local_history = {"mode": "live", "cursor": None, "holes": [], "read_at": None, "last_flows": 0, "flows": 0, "error": None}


def local_history_fetch(begin, end):
    """The router's stored local flows with begin <= ts < end. A window the
    router fills to the limit is read again in halves."""
    begin, end = round(begin, 3), round(end, 3)   # as sent, so a window's edge is the next one's start
    body = {"item": "flows", "local": True, "begin": begin, "end": end, "count": LOCAL_HISTORY_MAX}
    response = requests.post(LOCAL_HISTORY_URL, json=body, headers={"Content-Type": "application/json"}, timeout=(10, 90),
                             hooks=router_read_hook("local flow history"))
    response.raise_for_status()
    reply = response.json()
    flows = (reply.get("data") or {}).get("flows") if isinstance(reply, dict) else None
    if not isinstance(flows, list):
        raise RuntimeError(f"router reply without flows (code {reply.get('code') if isinstance(reply, dict) else '?'})")
    if len(flows) >= LOCAL_HISTORY_MAX and end - begin > 2:
        middle = (begin + end) / 2
        return local_history_fetch(begin, middle) + local_history_fetch(middle, end)
    keep = []
    for flow in flows:
        try:
            ts = float(flow.get("ts"))
        except (AttributeError, TypeError, ValueError):
            continue
        if begin <= ts < end:
            keep.append({**flow, "local": True})
    return keep


def local_history_save_cursor(cursor):
    local_history["cursor"] = cursor
    with local_traffic_connection() as connection:
        local_meta_set(connection, "history_cursor", cursor)


def local_history_save_holes():
    with local_traffic_connection() as connection:
        local_meta_set(connection, "history_holes", json.dumps(local_history["holes"]))


def local_history_read(begin, end, done):
    """The stored local flows from begin to end, recorded: an hour per call
    to the router at most, each call's flows oldest first ("starts" compares
    a record with the one before it on its connection). A part's flows are
    saved before done(upto) notes how far the reading got (24 Nov 2026: the
    place was saved first and the flows up to a minute later, so a restart
    in between lost that part for good). -> the flows added."""
    added = 0
    while begin < end:
        upto = min(end, begin + 3600)
        flows = local_history_fetch(begin, upto)
        flows.sort(key=lambda flow: float(flow.get("ts") or 0))
        record_local_traffic(flows, source="history")
        flush_local_traffic()
        added += len(flows)
        begin = upto
        done(upto)
    return added


def local_history_read_holes(now):
    """The times a give-up left unread, oldest first (nothing older than
    the catch-up limit). Each shrinks as it is read, so a failed read or a
    restart goes on from where it got to."""
    added = 0
    while local_history["holes"]:
        hole = local_history["holes"][0]

        def done(upto):
            hole[0] = upto
            local_history_save_holes()
        added += local_history_read(max(hole[0], now - LOCAL_HISTORY_CATCH_UP_SECONDS), hole[1], done)
        local_history["holes"].pop(0)
        local_history_save_holes()
    return added


def local_history_step(now=None):
    """One read of the router's history; returns the flows added."""
    now = time.time() if now is None else now
    end = now - LOCAL_HISTORY_LAG_SECONDS
    if local_history["mode"] == "live":
        # The live stream has recorded everything until now, so a restart
        # would go on from here. The history takes over only once a real
        # read of it works (24 Nov 2026: it took over at once, unasked, so
        # after a give-up the stream was recorded 3 minutes in every 12
        # until the router answered again). The read is of the unread
        # times, or of one second when there are none.
        local_history_save_cursor(now)
        added = 0
        if local_history["holes"]:
            added = local_history_read_holes(now)
        else:
            local_history_fetch(end - 1, end)   # nothing to read: only to see that the history answers
        local_history["mode"] = "history"
        local_history_save_cursor(time.time())   # the stream was recorded until this moment: nothing read twice
        return added
    added = local_history_read(max(local_history["cursor"], now - LOCAL_HISTORY_CATCH_UP_SECONDS), end, local_history_save_cursor)
    local_history["mode"] = "history"
    return added + local_history_read_holes(now)


def local_history_give_up(now=None):
    """The history has stayed away: from now the live stream's allowed flows
    are recorded. The time not read yet is kept (a hole) to read when the
    history answers again."""
    now = time.time() if now is None else now
    cursor = local_history["cursor"]
    if cursor and now > cursor:
        local_history["holes"].append([max(cursor, now - LOCAL_HISTORY_CATCH_UP_SECONDS), now])
        del local_history["holes"][:-20]
    local_history["mode"] = "live"
    try:
        local_history_save_cursor(now)
        local_history_save_holes()
    except Exception as exc:
        print("Local traffic history place not saved:", exc)


def local_history_worker():
    with local_traffic_connection() as connection:
        cursor, holes = local_meta_get(connection, "history_cursor"), local_meta_get(connection, "history_holes")
    try:
        local_history["holes"] = [[float(a), float(b)] for a, b in json.loads(holes or "[]")]
    except (TypeError, ValueError):
        local_history["holes"] = []
    if cursor:
        local_history["mode"], local_history["cursor"] = "starting", float(cursor)
    failed = 0
    while True:
        try:
            added = local_history_step()
            failed = 0
            local_history.update(read_at=time.time(), last_flows=added, flows=local_history["flows"] + added, error=None)
        except Exception as exc:
            # A failed read loses nothing: the place is kept and the next
            # read goes on from there. Only when the history stays away
            # (LOCAL_HISTORY_GIVE_UP reads in a row) does the live stream
            # take over (20 Nov 2026: before, one failed read did that, and
            # the history then started again from "now", skipping the time
            # in between, or the whole catch-up after a restart).
            failed += 1
            local_history["error"] = str(exc)[:200]
            if local_history["mode"] != "live":
                if failed >= LOCAL_HISTORY_GIVE_UP:
                    print("Local traffic history unavailable, recording the live stream:", exc)
                    local_history_give_up()
                elif failed == 1:
                    print("Local traffic history read failed, trying again from the same place:", exc)
        state["local_history"] = dict(local_history)
        time.sleep(LOCAL_HISTORY_SECONDS)


# ============================================================
# INTERNET TRAFFIC: long-term totals of each device's internet traffic
#
# The base for internet monitoring (learning each device's normal and
# spotting what's new). Fed from the same router stream as the 24-hour
# flow history: every internet flow a device makes, allowed or blocked,
# is added to hourly totals (kept 30 days) and daily totals (kept 1 year),
# one row per device, destination (domain, else IP), country, protocol,
# port, direction, outcome and the rule that allowed or blocked it.
# direction "out" = the device started it; "in" = the internet side did
# (e.g. through a port forward). Left out: local traffic (its own
# recorder) and blocks of the router's own internet address (device
# "if:<WAN>": internet scans of the WAN, not a device's traffic). The
# stream can repeat a record; repeats within 30 minutes count once.
# ============================================================

INTERNET_TRAFFIC_DATABASE = os.environ.get("FIREWALLA_INTERNET_TRAFFIC_DB", "/data/internet_traffic.db")
INTERNET_TRAFFIC_HOURLY_SECONDS = 30 * 86400
INTERNET_TRAFFIC_DAILY_SECONDS = 365 * 86400
INTERNET_TRAFFIC_FLUSH_SECONDS = 60
INTERNET_TRAFFIC_KEY = "device_mac, destination, country, protocol, port, direction, outcome, rule"

internet_traffic_lock = threading.Lock()
internet_traffic_pending = {}       # (hour, *key) -> totals not yet written
internet_traffic_seen = {}          # fingerprint -> time seen (repeat guard)
internet_traffic_stats = {"records": 0, "added": 0, "repeats": 0, "skipped": 0,
                          "last_record_at": None, "last_flush_at": None, "error": None}
# Internet connections started (owner, 23 Nov 2026, D-956), as local traffic
# counts them (D-883): the router writes a fresh record about every minute
# while a connection stays open, so an allowed record whose client address and
# port, remote address and port weren't seen in the LOCAL_CONNECTION_GAP
# before opens a connection; the rest continue one. A blocked record's tries
# are all tries; a record without the client's port counts as a start.
internet_connections_open = {}      # (mac, client port, remote ip, port, protocol) -> last record time


def internet_flow_starts(raw, flow):
    """How many connections this normalized internet record opens."""
    n = max(1, int(flow.get("count") or 1))
    mac = str(flow.get("device_mac") or "").upper()
    sport = raw.get("devicePort") if isinstance(raw, dict) else None
    if flow.get("kind") == "blocked" or not mac or mac.startswith("IF:") or sport in (None, ""):
        return n
    try:
        ts = float(raw.get("ts") or flow.get("received_at") or time.time()) + float(raw.get("du") or 0)
    except (TypeError, ValueError):
        ts = time.time()
    conn = (mac, str(sport), str(flow.get("remote_ip") or ""), str(flow.get("port") or ""), str(flow.get("protocol") or "").lower())
    before = internet_connections_open.get(conn)
    internet_connections_open[conn] = max(before or 0, ts)
    if len(internet_connections_open) > 100000:
        for c in [c for c, t in internet_connections_open.items() if t < ts - LOCAL_CONNECTION_GAP]:
            del internet_connections_open[c]
    return n if before is None or abs(ts - before) > LOCAL_CONNECTION_GAP else 0


def internet_traffic_connection():
    connection = sqlite3.connect(INTERNET_TRAFFIC_DATABASE, timeout=15)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize_internet_traffic():
    with internet_traffic_connection() as connection:
        for table, period in (("internet_traffic_hourly", "hour"), ("internet_traffic_daily", "day")):
            connection.execute(f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    {period} INTEGER NOT NULL,
                    device_mac TEXT NOT NULL, destination TEXT NOT NULL, country TEXT NOT NULL,
                    protocol TEXT NOT NULL, port TEXT NOT NULL, direction TEXT NOT NULL,
                    outcome TEXT NOT NULL, rule TEXT NOT NULL,
                    device_ip TEXT, remote_ip TEXT, network TEXT, groups TEXT,
                    bytes_up INTEGER NOT NULL DEFAULT 0, bytes_down INTEGER NOT NULL DEFAULT 0,
                    flows INTEGER NOT NULL DEFAULT 0, first_ts REAL, last_ts REAL, starts INTEGER,
                    PRIMARY KEY ({period}, {INTERNET_TRAFFIC_KEY}))""")
            connection.execute(f"CREATE INDEX IF NOT EXISTS {table}_by_device ON {table} (device_mac, {period})")
            if "starts" not in {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN starts INTEGER")   # D-956: rows from before have none
        # What a restart must not forget (24 Nov 2026: both were only in
        # memory, so after every restart each connection still open counted
        # as a new start, and a record the router sent again was added to
        # these totals a second time). The connections open at the last
        # save come back from here; the records of the last 30 minutes count
        # as seen, from the 24-hour flow history (the same fingerprint).
        connection.execute("CREATE TABLE IF NOT EXISTS internet_traffic_meta (name TEXT PRIMARY KEY, value TEXT)")
        row = connection.execute("SELECT value FROM internet_traffic_meta WHERE name = 'connections_open'").fetchone()
        try:
            for conn, ts in json.loads(row[0]) if row and row[0] else []:
                internet_connections_open.setdefault(tuple(conn), float(ts))
        except (TypeError, ValueError):
            pass
    try:
        with flow_history_reader() as connection:
            for fingerprint, received_at in connection.execute(
                    "SELECT fingerprint, received_at FROM flow_records WHERE event_at >= ?", (time.time() - 2400,)):
                if received_at >= time.time() - 1800:
                    internet_traffic_seen.setdefault(fingerprint, received_at)
    except sqlite3.Error as exc:
        print("Internet traffic: the last minutes' records weren't read back:", exc)


def internet_traffic_row(raw, flow):
    """One normalized flow -> (key, values), or None if it isn't a device's
    internet traffic."""
    mac = str(flow.get("device_mac") or "").upper()
    if flow.get("local") or not mac or mac.startswith("IF:"):
        return None
    try:
        ts = float(flow.get("flow_ts") or flow.get("received_at") or time.time())
    except (TypeError, ValueError):
        ts = time.time()
    blocked = flow.get("kind") == "blocked"
    rule = flow.get("policy_pid") if blocked else flow.get("allowed_pid")
    rule = f"rule:{rule}" if rule not in (None, "") else (
        f"type:{flow['blocked_type']}" if blocked and flow.get("blocked_type") else "")
    key = (mac, str(flow.get("destination") or flow.get("remote_ip") or ""), str(flow.get("country") or ""),
           str(flow.get("protocol") or "").lower(), "" if flow.get("port") is None else str(flow["port"]),
           "out" if str(flow.get("direction") or "in").lower() == "in" else "in",
           "blocked" if blocked else "allowed", rule)
    return key, {"ts": ts, "device_ip": flow.get("device_ip"), "remote_ip": flow.get("remote_ip"),
                 "network": flow.get("source_network"), "groups": json.dumps(flow.get("tags") or []),
                 "up": int(flow.get("upload_bytes") or 0), "down": int(flow.get("download_bytes") or 0),
                 "flows": max(1, int(flow.get("count") or 1)),
                 "starts": int(flow["starts"]) if flow.get("starts") is not None else max(1, int(flow.get("count") or 1))}


def record_internet_traffic(raw_and_normalized):
    now = time.time()
    with internet_traffic_lock:
        for raw, flow in raw_and_normalized or []:
            internet_traffic_stats["records"] += 1
            row = internet_traffic_row(raw, flow)
            if row is None:
                internet_traffic_stats["skipped"] += 1
                continue
            fingerprint = flow_history_fingerprint(raw)
            if fingerprint in internet_traffic_seen:
                internet_traffic_stats["repeats"] += 1
                continue
            internet_traffic_seen[fingerprint] = now
            key, v = row
            internet_traffic_stats["added"] += 1
            internet_traffic_stats["last_record_at"] = now
            totals = internet_traffic_pending.get((int(v["ts"] // 3600 * 3600), *key))
            if totals is None:
                totals = internet_traffic_pending[(int(v["ts"] // 3600 * 3600), *key)] = {
                    "up": 0, "down": 0, "flows": 0, "starts": 0, "first_ts": v["ts"], "last_ts": v["ts"]}
            totals.update(device_ip=v["device_ip"], remote_ip=v["remote_ip"], network=v["network"], groups=v["groups"])
            totals["up"] += v["up"]
            totals["down"] += v["down"]
            totals["flows"] += v["flows"]
            totals["starts"] = totals.get("starts", 0) + v["starts"]
            totals["first_ts"] = min(totals["first_ts"], v["ts"])
            totals["last_ts"] = max(totals["last_ts"], v["ts"])
        if len(internet_traffic_seen) > 50000:
            cutoff = now - 1800
            for fp in [fp for fp, seen in internet_traffic_seen.items() if seen < cutoff]:
                del internet_traffic_seen[fp]


def internet_day(hour):
    """Start of the local calendar day an hour falls in."""
    day = time.localtime(hour)
    return int(time.mktime((day.tm_year, day.tm_mon, day.tm_mday, 0, 0, 0, 0, 0, -1)))


def flush_internet_traffic():
    with internet_traffic_lock:
        pending = dict(internet_traffic_pending)
        internet_traffic_pending.clear()
    # The connections open now go with the save (see initialize_internet_traffic).
    # The table is filled by the stream's thread: a copy that fails is tried at the next save.
    try:
        latest = max(internet_connections_open.values(), default=0)
        open_now = [[list(conn), ts] for conn, ts in list(internet_connections_open.items()) if ts >= latest - LOCAL_CONNECTION_GAP]
    except RuntimeError:
        open_now = None
    try:
        with internet_traffic_connection() as connection:
            if open_now is not None:
                connection.execute("INSERT INTO internet_traffic_meta VALUES ('connections_open', ?) "
                                   "ON CONFLICT (name) DO UPDATE SET value = excluded.value", (json.dumps(open_now),))
            for table, period, of in (("internet_traffic_hourly", "hour", lambda h: h),
                                      ("internet_traffic_daily", "day", internet_day)):
                if pending:
                    connection.executemany(f"""
                        INSERT INTO {table} ({period}, {INTERNET_TRAFFIC_KEY}, device_ip, remote_ip, network, groups,
                            bytes_up, bytes_down, flows, first_ts, last_ts, starts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT ({period}, {INTERNET_TRAFFIC_KEY}) DO UPDATE SET
                            device_ip = excluded.device_ip, remote_ip = excluded.remote_ip,
                            network = excluded.network, groups = excluded.groups,
                            bytes_up = bytes_up + excluded.bytes_up, bytes_down = bytes_down + excluded.bytes_down,
                            flows = flows + excluded.flows, starts = COALESCE(starts, 0) + excluded.starts,
                            first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)""",
                        [(of(key[0]), *key[1:], t["device_ip"], t["remote_ip"], t["network"], t["groups"],
                          t["up"], t["down"], t["flows"], t["first_ts"], t["last_ts"], t.get("starts", t["flows"])) for key, t in pending.items()])
            now = time.time()
            connection.execute("DELETE FROM internet_traffic_hourly WHERE hour < ?",
                               (int(now - INTERNET_TRAFFIC_HOURLY_SECONDS) // 3600 * 3600,))
            connection.execute("DELETE FROM internet_traffic_daily WHERE day < ?",
                               (internet_day(now - INTERNET_TRAFFIC_DAILY_SECONDS),))
    except Exception:
        with internet_traffic_lock:
            traffic_put_back(internet_traffic_pending, pending, ("up", "down", "flows", "starts"))
        raise
    if any(key[0] < internet_day(now) for key in pending):
        past_days_written["internet"] = now
    internet_traffic_stats["last_flush_at"] = time.time()


def internet_traffic_flush_worker():
    while True:
        time.sleep(INTERNET_TRAFFIC_FLUSH_SECONDS)
        try:
            flush_internet_traffic()
            internet_traffic_stats["error"] = None
        except Exception as exc:
            internet_traffic_stats["error"] = f"save: {exc}"
            print("Internet traffic save error:", exc)


# ============================================================
# API
# ============================================================


# Totals worked out for every flow-history ranking, timeline bucket and
# summary (names match FLOW_METRICS, in order).
FLOW_METRICS_SQL = """
    COUNT(*) AS records,
    COALESCE(SUM(COALESCE(starts, count)), 0) AS flow_count,
    SUM(CASE WHEN kind = 'normal' THEN 1 ELSE 0 END) AS normal_records,
    COALESCE(SUM(CASE WHEN kind = 'normal' THEN COALESCE(starts, count) ELSE 0 END), 0) AS normal_count,
    SUM(CASE WHEN kind = 'blocked' THEN 1 ELSE 0 END) AS blocked_records,
    COALESCE(SUM(CASE WHEN kind = 'blocked' THEN COALESCE(starts, count) ELSE 0 END), 0) AS blocked_count,
    COALESCE(SUM(upload_bytes), 0) AS upload_bytes,
    COALESCE(SUM(download_bytes), 0) AS download_bytes
"""
FLOW_METRICS = ("records", "count", "normal_records", "normal_count",
                "blocked_records", "blocked_count", "upload_bytes", "download_bytes")


def flow_metrics(values):
    return {name: int(value or 0) for name, value in zip(FLOW_METRICS, values)}


# Several cards and open tabs ask the same flow-history questions every
# minute, and a 24-hour summary reads ~320,000 records (about 4 s). So each
# answer is worked out at most once a minute and shared; a request that
# comes while it is being worked out waits for it instead of starting the
# same work again.
FLOW_SUMMARY_CACHE_SECONDS = 60
SHARED_RESULTS_MOST = 200
shared_results = {}        # key -> (worked out at, result)
shared_result_locks = {}   # key -> held while that answer is worked out
shared_results_lock = threading.Lock()


def shared_result(key, compute):
    with shared_results_lock:
        lock = shared_result_locks.setdefault(key, threading.Lock())
    with lock:
        cached = shared_results.get(key)
        if cached and time.time() - cached[0] < FLOW_SUMMARY_CACHE_SECONDS:
            return cached[1]
        result = compute()
        now = time.time()
        with shared_results_lock:
            # Old answers go (filtered ones are asked for once, then not).
            for old in [k for k, (at, _) in shared_results.items() if now - at > FLOW_SUMMARY_CACHE_SECONDS]:
                shared_results.pop(old, None)
            for old in [k for k, l in shared_result_locks.items() if k not in shared_results and k != key and not l.locked()]:
                shared_result_locks.pop(old, None)
            if result.get("healthy"):
                # At most SHARED_RESULTS_MOST answers are kept (a filter can
                # be any text, so the keys have no natural limit): the oldest go.
                while len(shared_results) >= SHARED_RESULTS_MOST:
                    shared_results.pop(min(shared_results, key=lambda k: shared_results[k][0]), None)
                shared_results[key] = (now, result)
        return result
