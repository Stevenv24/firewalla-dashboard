# Firewalla Dashboard

A home-network dashboard for a Firewalla router. It runs on your own NAS (in Docker) and shows what your network is doing: outages, devices, traffic, rules, alarms and more. It only **reads** your router: it can't change any setting there.

This guide installs it on a **Synology NAS** with Container Manager. It takes about 30 minutes, most of it waiting.

> Free, as it is, with no warranty and no promise of support. You use it at your own risk. Not made by, approved by or linked to Firewalla Inc.; "Firewalla" is their trademark. Your keys and passwords stay on your own NAS and are never sent to the author.

---

## What You Need

* A **Firewalla Gold or Purple** (Gold Pro, Gold Plus, Gold SE, Gold, Purple, Purple SE) running in **Router mode**.
* The **Firewalla app** on your phone, signed in as the box's owner.
* A **Synology NAS** with DSM 7.2 or later that can run **Container Manager** (most Plus models; check Package Center), on a network your Firewalla manages, with about **2 GB of free memory**.
* A computer on the same network, with a web browser.
* Optional:
  * **Firewalla MSP**, for your target lists in the rule pop-ups.
  * A **Gmail** account, for the daily digest and alerts by email.
  * An **Anthropic Console** account with a little credit, for Ask Claude (about $5 to $20 a month).

---

## Before You Start: Give the NAS a Fixed Address

The dashboard's key on your router only works from the NAS's own address, so that address must never change.

1. Open the **Firewalla app** and tap your box.
2. Tap **Devices** and find your NAS in the list.
3. Tap it, then tap its **IP address**, choose **Reserved** and keep the address it has now. (Keeping its current address means nothing changes; a different address would only take effect after the NAS's next restart.)
4. Note that address (for example `192.168.1.40`): you open the dashboard with it.

---

## Step 1: Install Container Manager

1. On the NAS, open **Package Center**.
2. Search for **Container Manager** and click **Install**.
3. When it asks for a shared folder for Docker, accept **docker** (it is created for you).

If Container Manager is already installed, you already have the **docker** shared folder: go on to step 2.

---

## Step 2: Put the Dashboard's Files on the NAS

1. Open **File Station** and go to the **docker** shared folder.
2. Create a folder named **firewalla-dashboard** in it.
3. Copy the dashboard's files into that folder, so that `compose.yaml` sits directly inside **firewalla-dashboard** (not in a folder below it).
   * If you copy them from another copy of the dashboard, **leave out** the folders `config`, `data` and `logs`, the file `.env` and the folder `.git`: those belong to the other copy.
4. Inside **firewalla-dashboard**, create three empty folders: **config**, **data** and **logs**.

The folder should now look like this:

```
docker/firewalla-dashboard/
    app/  claude-worker/  router/  config/  data/  logs/
    compose.yaml  Dockerfile  requirements.txt  start-dashboard.sh
    settings.env.example  .env.example  README.md
```

**Two copies on one NAS?** Copy `.env.example` to `.env` in the second copy's folder and give it its own `CONTAINER_PREFIX` and `PORT` (for example `PORT=8181`).

---

## Step 3: Create the Project in Container Manager

1. Open **Container Manager** and click **Project** on the left.
2. Click **Create**.
3. **Project name:** `firewalla-dashboard`.
4. **Path:** click **Set Path** and choose **docker › firewalla-dashboard**.
5. **Source:** it says it found the compose file; choose **Use the existing compose file** (the wording may differ slightly by DSM version).
6. Click **Next**. Leave **Web portal** off and click **Next** again.
7. Tick **Start the project once it is created** and click **Done**.

The first start builds the dashboard and downloads what it needs: allow **5 to 10 minutes**. When the project shows **Running** with two containers (`firewalla-dashboard` and `firewalla-dashboard-claude`), go on.

---

## Step 4: Find the Setup Code

The setup page asks for a code, so nobody else on your network can change your keys. A new code is made each time the dashboard starts.

1. In **Container Manager**, click **Container** on the left.
2. Click **firewalla-dashboard**, then **Log** (in the container's details).
3. Find the line `SETUP CODE for this start: XXXX-XXXX-XXXX` and note the code.

Or: in **File Station**, open **docker › firewalla-dashboard › config › setup_code.txt**.

---

## Step 5: Open the Setup Page and Follow It

1. On your computer, open a browser and go to **http://NAS-ADDRESS:8180/setup** (for example `http://192.168.1.40:8180/setup`).
2. Type the setup code.
3. Follow the steps on the page. Each one is checked before you go on:
   1. **Your Network:** a name, your time zone, your router's address and model.
   2. **Router Access:** turn SSH on in the Firewalla app and paste its password once. The dashboard makes its own key, which can only read your router through a read-only filter, and then forgets the password.
   3. **Checks Before Use:** router mode and New Device Quarantine.
   4. **Firewalla MSP** (optional).
   5. **Email Alerts** (optional).
   6. **Ask Claude** (optional): use an API key from the Claude Console, never a Claude Pro or Max sign-in.
   7. **Done:** the dashboard restarts with your settings.
4. Bookmark **http://NAS-ADDRESS:8180/next**: that is your dashboard.

**Keep SSH turned on** in the Firewalla app. If it is turned off, the dashboard stops until it is on again.

---

## Changing Settings Later

* Open **http://NAS-ADDRESS:8180/setup** again. The code is in the log or in `config/setup_code.txt` (a new one after each restart).
* Advanced settings that the page doesn't show are in `config/settings.env` (see `settings.env.example`). After changing that file, restart the project in Container Manager.

---

## Updating to a New Version

1. In **Container Manager › Project**, select **firewalla-dashboard** and click **Stop**.
2. In **File Station**, replace the dashboard's files with the new ones. **Keep** the folders `config`, `data` and `logs` and the file `.env`.
3. Back in **Project**, select it and choose **Build** (under **Action**), then **Start**.

Your settings, keys and history stay.

---

## Removing It

1. **Container Manager › Project:** stop **firewalla-dashboard**, then delete it. Under **Image**, delete its two images.
2. **File Station:** delete **docker › firewalla-dashboard**.
3. **On the router**, take the dashboard's key away. Its name is `firewalla-dashboard-shared-` followed by this copy's ID, which is in `config/copy_id` (note it before step 2). From a computer, open a terminal (Windows: PowerShell) and type:

   ```
   ssh pi@ROUTER-ADDRESS
   ```

   Paste the SSH password from the Firewalla app (**Settings › Advanced › Configurations › SSH Console**), then type, with your copy's ID in place of `ID`:

   ```
   sed -i '/ firewalla-dashboard-shared-ID$/d' ~/.ssh/authorized_keys
   ```

4. Only if **no other copy** of the dashboard watches this router, also remove the read-only filter, then restart the router:

   ```
   sudo rm -rf /home/pi/dashboard-filter /home/pi/.firewalla/config/post_main.d/dashboard-filter.sh
   ```

---

## If Something Goes Wrong

| What You See | What To Do |
|---|---|
| The page doesn't open at all | Check the project shows **Running** in Container Manager. If the NAS's firewall is on (**Control Panel › Security › Firewall**), allow port **8180** from your local network. |
| "Unknown address for this dashboard" | You opened it by a name with a dot in it. Use the NAS's IP address, or add that name in step 1 under **More**. |
| "That isn't this start's setup code" | The code changes at every start: take the newest one from the log or `config/setup_code.txt`. |
| "The router refused the password" | Copy it again from the app. It changes whenever the router restarts. |
| "The router doesn't answer on SSH from this NAS" | Turn SSH on in the app for the network the NAS is on. |
| "A different read-only filter is already installed" | Another version of the dashboard already watches this router. Nothing was changed; ask whoever set that one up. |
| The header doesn't show **LIVE** | Wait a minute. If it stays off, check SSH is still on in the app and the NAS kept its reserved address. |

---

## Credits

The dashboard downloads three free lists itself, on your NAS, every 30 days: **DuckDuckGo Tracker Radar** (which company a site belongs to; CC BY-NC-SA 4.0), the **Disconnect** tracking protection list, and **iptoasn.com** (which network owns an address). It checks your internet connection against Google and Cloudflare. It is built with Python, FastAPI, Uvicorn and Requests, and Ask Claude uses Anthropic's Python library.
