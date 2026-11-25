#!/usr/bin/env python3
"""
Firewalla dashboard read-only filter (runs on the Firewalla Gold Pro).

The dashboard on the NAS reaches the router through an SSH tunnel. The
router's local APIs (FireApi on 127.0.0.1:8834, fwapc on 127.0.0.1:8841)
need no login and can also CHANGE the router (rules, policies, devices).
This filter sits in front of them and passes through only the exact
requests the dashboard uses; everything else gets 403 Forbidden.

The dashboard's SSH key is restricted (in ~/.ssh/authorized_keys) so it
can only open tunnels to this filter's ports - never to 8834/8841
directly, and never a shell. So even if the NAS is compromised, the
router's configuration can't be changed through the dashboard's key.

    127.0.0.1:8934  ->  FireApi 127.0.0.1:8834
    127.0.0.1:8941  ->  fwapc   127.0.0.1:8841

Allowed (everything is a read, except one harmless action marked *):
    FireApi  GET  /v1/host/all
             GET  /v1/host/system
             POST /v1/encipher/simple  command=get  item=liveStats (live stream)
             POST /v1/encipher/simple  command=cmd  item=runInternetSpeedtest *
             POST /v1/encipher/complex command=get  (stored local flows only:
                  body exactly item=flows, local=true, begin, end, count)
    fwapc    GET  /v1/status/station, /v1/status/ap, /v1/status/switch
             GET  /v1/config/active
             GET  /v1/switch/metrics/<id>   (live stream)

Also refused: a path that doesn't start with exactly one "/" (the check
and the router must see the same path), a bad Content-Length, and an
encipher/simple body with any field the dashboard doesn't send (liveStats:
type, target, queries; runInternetSpeedtest: wanUUID, vendor).

encipher/complex hands its whole body to the router as the request, so it is
allowed for one read only: the stored local flows the app's Local Flows tab
shows (get "flows" with local=true), for one device (target = a MAC) or the
whole network (target=0.0.0.0), with numeric begin/end and at most 5000 rows
(17 Nov 2026: the live stream misses about a third of local flows).

Python 3 standard library only. Started at boot by
~/.firewalla/config/post_main.d/dashboard-filter.sh.
"""
import http.client
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ID = r"[A-Za-z0-9:_-]{1,64}"  # no "." or "/" (no path tricks)
MAX_BODY = 64 * 1024
# The only query parameters the dashboard sends to encipher/simple.
SIMPLE_KEYS = {"command", "item", "target", "streaming"}


def simple_query(command, item):
    """encipher/simple with exactly this command and item. FireApi reads the
    command and item only from the query string (not the body). Its query
    parser also understands forms like command[1]=set, so only the plain
    parameters the dashboard uses are accepted, each exactly once."""
    def check(query):
        if set(query) - SIMPLE_KEYS or any(len(v) != 1 for v in query.values()):
            return False
        return query.get("command") == [command] and query.get("item") == [item]
    return check


MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"


def complex_get_query(query):
    """encipher/complex: command=get and a target (a MAC or 0.0.0.0), each
    exactly once and nothing else."""
    if set(query) != {"command", "target"} or any(len(v) != 1 for v in query.values()):
        return False
    return query["command"] == ["get"] and bool(re.fullmatch(MAC + r"|0\.0\.0\.0", query["target"][0]))


def local_flows_body(value):
    """The one encipher/complex body allowed: get stored local flows."""
    number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v < 1e10
    return (set(value) == {"item", "local", "begin", "end", "count"} and value["item"] == "flows"
            and value["local"] is True and number(value["begin"]) and number(value["end"])
            and isinstance(value["count"], int) and not isinstance(value["count"], bool)
            and 1 <= value["count"] <= 5000)


ANY_QUERY = None  # query string not checked (reads only)
# The only JSON body fields each encipher/simple request may carry (a set),
# or the check the whole body must pass (a function; the body is required).
LIVE_BODY = {"type", "target", "queries"}
SPEEDTEST_BODY = {"wanUUID", "vendor"}

# port -> (upstream port, [(method, path regex, query check[, body fields])])
RULES = {
    8934: (8834, [
        ("GET", r"/v1/host/all", ANY_QUERY),
        ("GET", r"/v1/host/system", ANY_QUERY),
        ("POST", r"/v1/encipher/simple", simple_query("get", "liveStats"), LIVE_BODY),
        ("POST", r"/v1/encipher/simple", simple_query("cmd", "runInternetSpeedtest"), SPEEDTEST_BODY),
        ("POST", r"/v1/encipher/complex", complex_get_query, local_flows_body),
    ]),
    8941: (8841, [
        ("GET", r"/v1/status/station", ANY_QUERY),
        ("GET", r"/v1/status/ap", ANY_QUERY),
        ("GET", r"/v1/status/switch", ANY_QUERY),
        ("GET", r"/v1/config/active", ANY_QUERY),
        ("GET", rf"/v1/switch/metrics/{ID}", ANY_QUERY),
    ]),
}

# Request headers passed on to the router (nothing else is forwarded).
FORWARD_HEADERS = ("Content-Type", "Accept", "Accept-Encoding", "User-Agent")
# Response headers not copied back (the body is re-sent as received).
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "content-length", "proxy-connection"}


def log(*parts):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *parts, file=sys.stderr, flush=True)


def allowed(port, method, raw_path):
    """The matching rule's body fields (None = body not checked), or False.
    The path must start with exactly one "/": urlsplit reads "//x/v1/host/all"
    as host x + path /v1/host/all, but the router would get the raw path."""
    if not raw_path.startswith("/") or raw_path.startswith("//"):
        return False
    split = urlsplit(raw_path)
    query = parse_qs(split.query, keep_blank_values=True)
    for rule_method, pattern, check, *body in RULES[port][1]:
        if method == rule_method and re.fullmatch(pattern, split.path) and (check is None or check(query)):
            return body[0] if body else None
    return False


def body_ok(body, fields):
    """Fields a set: an empty body, or a JSON object with only these fields.
    Fields a function: a JSON object that passes it (an empty body fails)."""
    if not body:
        return not callable(fields)
    try:
        value = json.loads(body)
    except ValueError:
        return False
    if not isinstance(value, dict):
        return False
    return fields(value) if callable(fields) else set(value) <= fields


def make_handler(port):
    upstream = RULES[port][0]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "DashboardFilter"
        sys_version = ""

        def log_message(self, *args):  # quiet: only refusals and errors are logged
            pass

        def refuse(self, code, reason):
            log(f"REFUSED {code} {self.command} {self.path} ({reason})")
            body = (reason + "\n").encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def relay(self):
            fields = allowed(port, self.command, self.path)
            if fields is False:
                return self.refuse(403, "Forbidden by dashboard read-only filter")
            if self.headers.get("Transfer-Encoding"):
                return self.refuse(411, "Content-Length required")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self.refuse(400, "Bad Content-Length")
            if length < 0:
                return self.refuse(400, "Bad Content-Length")
            if length > MAX_BODY:
                return self.refuse(413, "Request body too large")
            body = self.rfile.read(length) if length else None
            if fields is not None and not body_ok(body, fields):
                return self.refuse(403, "Forbidden by dashboard read-only filter (body)")
            headers = {h: self.headers[h] for h in FORWARD_HEADERS if self.headers.get(h)}
            conn = http.client.HTTPConnection("127.0.0.1", upstream, timeout=300)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
                self.send_response(resp.status, resp.reason)
                for name, value in resp.getheaders():
                    if name.lower() not in HOP_HEADERS:
                        self.send_header(name, value)
                # The body is passed on as it arrives (live streams stay live)
                # and the connection closes when it ends.
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass  # the dashboard went away (e.g. a stream it stopped)
            except Exception as exc:  # router API down or slow
                log(f"UPSTREAM ERROR {self.command} {self.path}: {exc}")
                try:
                    self.refuse(502, "Router API unavailable")
                except Exception:
                    pass
            finally:
                conn.close()

        def do_GET(self):
            self.relay()

        def do_POST(self):
            self.relay()

        def refuse_other(self):
            self.refuse(403, "Forbidden by dashboard read-only filter")

        do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = refuse_other

    return Handler


def main():
    # Optional: "--offset N" runs on 8934+N / 8941+N (used only for testing).
    offset = int(sys.argv[sys.argv.index("--offset") + 1]) if "--offset" in sys.argv else 0
    servers = []
    for port in RULES:
        server = ThreadingHTTPServer(("127.0.0.1", port + offset), make_handler(port))
        server.daemon_threads = True
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        log(f"listening on 127.0.0.1:{port + offset} -> 127.0.0.1:{RULES[port][0]}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
