// Firewalla gateway selector: a dropdown that switches the dashboard to
// another router (the gateway routes by the "fwsite" cookie). Added to the
// dashboard's page by the gateway; the dashboard itself is not changed.
(function () {
    "use strict";
    if (document.getElementById("fw-site-select") || location.pathname.startsWith("/all")) return;
    const cookie = (document.cookie.match(/(?:^|;\s*)fwsite=([a-z0-9_-]+)/) || [])[1];

    function build(sites) {
        if (!Array.isArray(sites) || !sites.length) return;
        const current = cookie && sites.some(s => s.id === cookie) ? cookie : sites[0].id;
        const wrap = document.createElement("label");
        wrap.className = "fw-site";
        wrap.title = "Switch Firewalla";
        const select = document.createElement("select");
        select.id = "fw-site-select";
        select.setAttribute("aria-label", "Firewalla");
        for (const s of sites) select.add(new Option(s.name, "site:" + s.id, false, s.id === current));
        select.add(new Option("All Firewallas (overview)", "all"));
        select.addEventListener("change", () => {
            const v = select.value;
            location.href = v === "all" ? "/all/" : "/site/" + encodeURIComponent(v.slice(5));
        });
        wrap.appendChild(select);

        const style = document.createElement("style");
        style.textContent = `
.fw-site { display: block; margin: 0 0 12px; grid-column: 1 / -1; }
.fw-site select {
    width: 100%; font: 600 14px var(--font, system-ui, sans-serif); color: var(--text, #e6ebf2);
    background: var(--raised, #1b2130); border: 1px solid var(--line-strong, #2f3748);
    border-radius: var(--radius-sm, 8px); padding: 7px 10px; cursor: pointer;
}
.fw-site select:focus-visible { outline: 2px solid var(--accent, #3b82f6); outline-offset: 1px; }
.fw-site.fw-float, body.nav-collapsed .fw-site { position: fixed; bottom: 14px; right: 14px; z-index: 1900; margin: 0; width: auto; }
.fw-site.fw-float select, body.nav-collapsed .fw-site select { width: auto; box-shadow: 0 4px 14px rgba(0,0,0,.3); }`;
        document.head.appendChild(style);

        // Under the brand title in the sidebar (on a phone: in the menu, and
        // with the menu collapsed: floating at the bottom right); without a
        // sidebar, floating at the bottom right.
        const brand = document.querySelector(".brand");
        if (brand && brand.offsetParent !== null) {
            brand.insertAdjacentElement("afterend", wrap);
        } else {
            wrap.classList.add("fw-float");
            document.body.appendChild(wrap);
        }
    }

    fetch("/_fw/sites.json", { cache: "no-cache" })
        .then(r => r.ok ? r.json() : [])
        .then(build)
        .catch(() => {});
})();
