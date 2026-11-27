# Firewalla Gateway and Overview

One address for all your Firewalla routers. Each dashboard copy (one per
router) keeps running as it is; this folder adds two small containers:

- **Gateway** (nginx, the address you bookmark: `http://<host>:8179`). It
  sends every request to the copy picked by a cookie, so the full dashboard
  works unchanged, and adds a **Firewalla selector** under the dashboard's
  title (in the ☰ menu on a phone, bottom right when the menu is collapsed).
  `/site/<id>` switches; `/all/` is the Overview.
- **Overview** (`/all/`): every router on one page, read from each copy's
  `/api/status` every 10 seconds: live/stale/offline, WANs and their checks,
  devices online, router CPU and memory, alarms, site-to-site VPNs, latest
  speed test, busiest networks, and a banner listing everything that needs a
  look.

Neither talks to a router or stores anything. Nothing in `app/` is changed,
so upstream updates merge cleanly.

## Run

1. Start the dashboard copies first (their Docker networks must exist).
2. `cp .env.example .env` and set `SITES`.
3. `docker compose up -d --build`, then open `http://<host>:8179`.
4. In each copy's `config/settings.env`, point `FIREWALLA_SITE_OTHERS` and
   `FIREWALLA_DASHBOARD_URL` at `http://<host>:8179/site/<id>` so the
   dashboard's own links and email links stay on the one address.

## Add a router

Start its dashboard copy (own folder, port and `CONTAINER_PREFIX`), then:
`gateway/nginx.conf` (a line in the `map` and the `/site/(...)` pattern),
`gateway/sites.json`, `SITES` in `.env`, and its network in `compose.yaml`
(under `networks:` and both services). Then `docker compose up -d`.

## Notes

- Both routers share one browser address, so per-browser table sorting and
  filters are shared; saved card layouts stay per router (kept on the server).
- The router choice is one cookie for the whole address, so two gateway tabs
  can't show different routers: switching one switches the other on its next
  refresh. For side by side, use each copy's own port: the Overview's
  "Own tab ↗" links (the optional fourth `SITES` field) open them.
- `GET /all/api/overview` returns the Overview's summaries as JSON.
