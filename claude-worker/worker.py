"""Claude worker for the Firewalla dashboard.

Asks the dashboard for the next question every few seconds, sends it to
Claude through the Anthropic API with this copy's own API key (from the
Claude Console, never a Pro/Max sign-in) and posts the answer back.

Claude gets NO tools: the request carries only the dashboard's
instructions (system prompt) and the facts as text, so Claude can't run
commands, read or write files, browse, or reach the router or the
dashboard. It only writes text, and nothing it writes changes anything by
itself. The dashboard decides what is asked, builds the facts, caps
questions per day and logs the cost.

Mounted from the project folder (compose.yaml): a change here needs only a
container restart. Secrets in /run/secrets (the project's config/ folder):
  claude_api_key     the Anthropic API key (optional: without it nothing
                     is asked and the dashboard shows Ask Claude as off)
  claude_worker_key  shared with the dashboard, so only this worker may
                     fetch questions and post answers
"""

import json
import os
import time
import urllib.error
import urllib.request

import anthropic

DASHBOARD = os.environ.get("DASHBOARD_URL", "http://dashboard:8080").rstrip("/")
POLL_SECONDS = 5
VERSION = "worker-api-1"

# The dashboard names models by family (FIREWALLA_CLAUDE_MODEL, default
# "sonnet"); each family means its current model. A full model ID is used
# as it is.
MODELS = {"sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-5-5", "opus": "claude-opus-5-5"}
# Dollars per million tokens (input, output), for the cost the Settings
# page shows. Anthropic's bill is the real figure; this is an estimate.
PRICES = {"claude-sonnet-5-5": (2.00, 10.00), "claude-haiku-5-5": (0.10, 0.50), "claude-opus-5-5": (4.00, 20.00)}
# Models whose refusals can be answered by another model inside the same
# call ("fallbacks": "default" picks it by the kind of refusal).
FALLBACK_MODELS = {"claude-sonnet-5-5", "claude-opus-5-5"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000


SECRETS_DIR = os.environ.get("WORKER_SECRETS_DIR", "/run/secrets")


def secret(name):
    try:
        with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


API_KEY = secret("claude_api_key")
WORKER_KEY = secret("claude_worker_key")
# What the Settings page shows about the API key: "missing", "ok",
# "refused" (wrong or deleted key), "no-credit", "limit" (the Console's
# spend limit or a rate limit), "error" (anything else; see the answer).
key_state = "ok" if API_KEY else "missing"


def memory():
    """This container's memory use and limit, "used/limit" in bytes (its
    cgroup), shown on the dashboard's Settings page."""
    def read(path):
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return ""
    used = read("/sys/fs/cgroup/memory.current") or read("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    limit = read("/sys/fs/cgroup/memory.max") or read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    return f"{used if used.isdigit() else ''}/{limit if limit.isdigit() else ''}"


def call(path, body=None):
    """GET (no body) or POST (JSON body) to the dashboard; its JSON reply."""
    headers = {"x-worker-key": WORKER_KEY, "x-worker-version": VERSION,
               "x-worker-key-state": key_state, "x-worker-memory": memory()}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"
    request = urllib.request.Request(DASHBOARD + path, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def model_id(name):
    name = str(name or "sonnet").strip()
    return MODELS.get(name.lower(), name)


def cost(model, usage):
    prices = PRICES.get(model)
    if not prices or usage is None:
        return 0.0
    tokens_in = (usage.input_tokens or 0) + (getattr(usage, "cache_read_input_tokens", 0) or 0) + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
    return round((tokens_in * prices[0] + (usage.output_tokens or 0) * prices[1]) / 1_000_000, 6)


def ask(client, job):
    """One question, one request, no tools. Returns the answer the dashboard
    expects: ok, result, error, usage {cost_usd, duration_ms, input_tokens,
    output_tokens}, model."""
    global key_state
    model = model_id(job.get("model"))
    started = time.time()
    request = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": job.get("system") or "",
        "messages": [{"role": "user", "content": job.get("prompt") or ""}],
        "timeout": float(job.get("max_seconds") or 180),
    }
    try:
        if model in FALLBACK_MODELS:
            response = client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **request)
        else:
            response = client.messages.create(**request)
    except anthropic.PaymentRequiredError as exc:
        key_state = "no-credit"
        return failed(f"No credit left on the Anthropic account: add credit in the Claude Console ({exc.message})", model, started)
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
        key_state = "refused"
        return failed(f"Anthropic refused the API key: check config/claude_api_key ({exc.message})", model, started)
    except anthropic.RateLimitError as exc:
        key_state = "limit"
        return failed(f"Anthropic's limit reached (the Console's spend limit or too many questions at once): {exc.message}", model, started)
    except anthropic.APIStatusError as exc:
        key_state = "error"
        return failed(f"Anthropic error {exc.status_code}: {exc.message}", model, started)
    except anthropic.APIConnectionError as exc:
        return failed(f"Anthropic couldn't be reached: {exc}", model, started)

    key_state = "ok"
    usage = response.usage
    served_by = response.model or model
    answer_usage = {"cost_usd": cost(served_by, usage), "duration_ms": int((time.time() - started) * 1000),
                    "input_tokens": (usage.input_tokens or 0) + (getattr(usage, "cache_read_input_tokens", 0) or 0)
                    + (getattr(usage, "cache_creation_input_tokens", 0) or 0),
                    "output_tokens": usage.output_tokens or 0}
    if response.stop_reason == "refusal":
        details = response.stop_details
        why = getattr(details, "explanation", None) or getattr(details, "category", None) or "no reason given"
        return {"ok": False, "result": "", "error": f"Claude declined to answer ({why})"[:300], "usage": answer_usage, "model": served_by}
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    if not text:
        return {"ok": False, "result": "", "error": f"Claude gave no answer (stopped: {response.stop_reason})", "usage": answer_usage, "model": served_by}
    return {"ok": True, "result": text, "error": "", "usage": answer_usage, "model": served_by}


def failed(error, model, started):
    return {"ok": False, "result": "", "error": error[:300], "model": model,
            "usage": {"cost_usd": 0, "duration_ms": int((time.time() - started) * 1000), "input_tokens": 0, "output_tokens": 0}}


def check_key(client):
    """A free check of a new API key with Anthropic (it looks up a model;
    no question is asked, nothing is billed). Returns the key state."""
    try:
        client.models.retrieve(MODELS["sonnet"])
        return "ok"
    except anthropic.PaymentRequiredError:
        return "no-credit"
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError):
        return "refused"
    except anthropic.RateLimitError:
        return "limit"
    except anthropic.APIStatusError:
        return "error"
    except anthropic.APIConnectionError:
        return "ok"   # Anthropic not reachable just now: the first question will tell


def load_keys(client):
    """Reads the two keys again: added or changed keys are picked up without
    a restart (the dashboard makes the worker key on its first start, and
    the API key may be added or replaced at any time, for example by the
    setup page). A new API key is checked with Anthropic straight away.
    Returns the client to use: a new one when the API key changed, None
    without a key."""
    global API_KEY, WORKER_KEY, key_state
    WORKER_KEY = secret("claude_worker_key")
    api_key = secret("claude_api_key")
    if api_key == API_KEY and (client or not api_key):
        return client
    API_KEY = api_key
    if not api_key:
        key_state = "missing"
        print("No API key in config/claude_api_key: Ask Claude is off until one is added.", flush=True)
        return None
    client = anthropic.Anthropic(api_key=api_key, max_retries=2)
    key_state = check_key(client)
    print(f"API key in config/claude_api_key checked with Anthropic: {key_state}.", flush=True)
    return client


def loop():
    print(f"Claude worker started, asking {DASHBOARD} every {POLL_SECONDS} s", flush=True)
    client = load_keys(None)
    while True:
        # Questions are taken only with a key Anthropic accepts: every one
        # taken without would fail (the day's digest among them), so they
        # wait on the dashboard. Meanwhile the worker only reports itself
        # once a minute, so Settings and setup show the key's state.
        usable = client is not None and key_state != "refused"
        try:
            if WORKER_KEY and not usable:
                call("/api/claude/next?heartbeat=1")
            job = call("/api/claude/next") if WORKER_KEY and usable else None
            if job and job.get("id"):
                print(f"question {job['id']}: asking Claude ({model_id(job.get('model'))})", flush=True)
                answer = ask(client, job)
                print(f"question {job['id']}: {'answered' if answer['ok'] else 'failed: ' + answer['error']} "
                      f"in {round(answer['usage']['duration_ms'] / 1000)} s", flush=True)
                for attempt in (1, 2, 3):
                    try:
                        call("/api/claude/answer", {"id": job["id"], **answer})
                        break
                    except (urllib.error.URLError, OSError, ValueError) as exc:
                        if attempt == 3:
                            raise
                        print(f"question {job['id']}: the dashboard didn't take the answer ({exc}); trying again", flush=True)
                        time.sleep(POLL_SECONDS)
                # A refused key, no credit or a reached limit fails every
                # question the same way: the rest wait 10 minutes (a new
                # key is picked up after that).
                if key_state in ("refused", "no-credit", "limit"):
                    print(f"Claude can't be used right now ({key_state}): waiting 10 minutes.", flush=True)
                    time.sleep(600)
                    client = load_keys(client)
                continue   # there may be more waiting
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print("dashboard not reachable:", exc, flush=True)
        if WORKER_KEY and usable:
            time.sleep(POLL_SECONDS)
        else:
            time.sleep(60)
            client = load_keys(client)


if __name__ == "__main__":
    loop()
