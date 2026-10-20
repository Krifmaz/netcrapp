// Tabs, live fragment refresh and the two read-only actions. No build step.
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const header = $("header.top");
  if (!header) return;
  const pollMs = Math.max(2, Number(header.dataset.poll || 10)) * 1000;
  const live = $("#live");
  let paused = false;

  async function load(pane) {
    try {
      const res = await fetch(pane.dataset.src, { credentials: "same-origin" });
      if (res.status === 401) { location.href = "/login"; return; }
      if (!res.ok) throw new Error(res.status);
      // keep <details> open state across refreshes
      const open = [...pane.querySelectorAll("details[open] > summary")].map(s => s.textContent);
      pane.innerHTML = await res.text();
      pane.querySelectorAll("details > summary").forEach(s => { if (open.includes(s.textContent)) s.parentElement.open = true; });
      live.classList.remove("stale");
    } catch (e) {
      live.classList.add("stale");
      live.textContent = "connection lost";
    }
  }

  function visible() { return [...document.querySelectorAll(".pane")].find(p => !p.hidden); }

  document.querySelectorAll(".tab").forEach(btn => btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".pane").forEach(p => { p.hidden = p.id !== "tab-" + btn.dataset.tab; });
    const p = visible();
    if (p && p.dataset.src) load(p);
  }));

  $("#pause").addEventListener("click", e => {
    paused = !paused;
    e.target.textContent = paused ? "Resume" : "Pause";
    live.classList.toggle("paused", paused);
    live.textContent = paused ? "paused" : "live";
  });

  async function action(url, label, btn) {
    const msg = $("#msg");
    btn.disabled = true;
    msg.hidden = false;
    msg.textContent = label + "…";
    try {
      const res = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "x-ds4246": "1" } });
      if (res.status === 401) { location.href = "/login"; return; }
      msg.innerHTML = await res.text();
      const p = visible();
      if (p && p.dataset.src) load(p);
    } catch (e) {
      msg.textContent = label + " failed: " + e;
    } finally {
      btn.disabled = false;
    }
  }
  $("#rescan").addEventListener("click", e => action("/action/rescan", "Reading all pages", e.target));
  $("#dump").addEventListener("click", e => action("/action/dump", "Saving dump", e.target));

  // Buttons rendered by the server: <button data-post="/url" data-target="id">
  document.addEventListener("click", async e => {
    const btn = e.target.closest("button[data-post]");
    if (!btn) return;
    const out = document.getElementById(btn.dataset.target);
    btn.disabled = true;
    if (out) out.textContent = "Working… (a firmware read can take a minute)";
    try {
      const res = await fetch(btn.dataset.post, { method: "POST", credentials: "same-origin", headers: { "x-ds4246": "1" } });
      if (res.status === 401) { location.href = "/login"; return; }
      if (out) out.innerHTML = await res.text();
    } catch (err) {
      if (out) out.textContent = "Failed: " + err;
    } finally {
      btn.disabled = false;
    }
  });

  load($("#tab-dash"));
  setInterval(() => {
    if (paused || document.hidden) return;
    const p = visible();
    if (p && p.dataset.auto) { live.textContent = "live"; load(p); }
  }, pollMs);
})();
