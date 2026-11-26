# Firewalla Overview

One page for all your Firewalla routers. Each dashboard copy (one per router)
already serves its state at `/api/status`; this small service reads every
copy every 10 seconds and shows them side by side: live/stale/offline, each
WAN and its checks, devices online, router CPU and memory, alarms,
site-to-site VPNs, the latest speed test and the busiest networks. A banner
at the top lists everything that needs a look across all sites. Each card
links to that router's full dashboard.

It never talks to a router and stores nothing. It is a fork addition, kept in
its own folder so upstream updates to `app/` never conflict with it.

## Run

1. Start the dashboard copies first (their Docker networks must exist).
2. `cp .env.example .env` and set `SITES`.
3. `docker compose up -d --build`, then open `http://<host>:8179`.

To add a router: start its dashboard copy, then add it to `SITES` and to
the `networks:` in `compose.yaml`, and run `docker compose up -d`.

`GET /api/overview` returns the same summaries as JSON.
