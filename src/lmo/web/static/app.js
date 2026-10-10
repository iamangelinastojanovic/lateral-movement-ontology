const app = document.getElementById("app");
const healthEl = document.getElementById("health");

async function api(path, opts) {
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const problem = body.problem || res.statusText;
    const fix = body.fix ? `\n${body.fix}` : "";
    throw new Error(problem + fix);
  }
  return body;
}

async function apiPost(path, payload) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function bandClass(band) {
  return `band ${esc(band)}`;
}

function entityHref(key) {
  return `#/entity/${encodeURIComponent(key)}`;
}

async function loadHealth() {
  try {
    const h = await api("/api/health");
    healthEl.className = "health " + (h.ok ? "ok" : "bad");
    healthEl.textContent = h.ok
      ? `${h.n_alerts} alerts · ${h.n_events} events · graph ${h.graph_detail}`
      : `not ready: ${h.graph_detail} · ${h.n_alerts} alerts`;
  } catch (err) {
    healthEl.className = "health bad";
    healthEl.textContent = err.message;
  }
}

function showError(err) {
  app.innerHTML = `<div class="error">${esc(err.message)}</div>`;
}

async function renderQueue() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const band = params.get("band") || "";
  const view = params.get("view") || "open";
  const offset = Number(params.get("offset") || 0);
  const qs = new URLSearchParams({ limit: "50", offset: String(offset), view });
  if (band) qs.set("band", band);
  const rows = await api("/api/alerts?" + qs.toString());
  const options = ["", "high", "medium", "low"]
    .map((b) => `<option value="${b}" ${b === band ? "selected" : ""}>${b || "all bands"}</option>`)
    .join("");
  const views = ["open", "all", "confirmed", "dismissed"]
    .map((v) => `<option value="${v}" ${v === view ? "selected" : ""}>${v}</option>`)
    .join("");
  const body = rows.length
    ? rows
        .map(
          (r) => `<tr>
            <td class="${bandClass(r.band)}">${esc(r.band)}</td>
            <td>${Number(r.score).toFixed(3)}</td>
            <td class="muted">${esc(r.decision ? r.decision.action : "—")}</td>
            <td><a href="${entityHref(r.user_uid)}">${esc(r.user_uid)}</a></td>
            <td><a href="${entityHref(r.src_host)}">${esc(r.src_host)}</a></td>
            <td class="mono">${esc(r.bucket_start_sec)}</td>
            <td>${esc(r.n_distinct_dst)}</td>
            <td><a href="#/alert/${encodeURIComponent(r.alert_uid)}">open</a>
                <div class="mono muted">${esc(r.alert_uid)}</div></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="8" class="empty">no alerts match</td></tr>`;
  const prevOff = Math.max(0, offset - 50);
  const nextOff = offset + 50;
  app.innerHTML = `
    <h1>Alert queue</h1>
    <p class="muted">Grain is (account, source host, hour). False positives leave the open view; scores do not change.</p>
    <div class="toolbar">
      <label>band <select id="band">${options}</select></label>
      <label>view <select id="view">${views}</select></label>
      <button id="prev" ${offset === 0 ? "disabled" : ""}>previous 50</button>
      <button id="next" ${rows.length < 50 ? "disabled" : ""}>next 50</button>
      <span class="muted">offset ${offset}</span>
    </div>
    <table>
      <thead><tr><th>band</th><th>score</th><th>judgement</th><th>account</th><th>from</th><th>hour start</th><th>dsts</th><th>alert</th></tr></thead>
      <tbody>${body}</tbody>
    </table>`;
  function hashFor(nextBand, nextView, nextOff) {
    const p = new URLSearchParams();
    if (nextBand) p.set("band", nextBand);
    if (nextView && nextView !== "open") p.set("view", nextView);
    if (nextOff) p.set("offset", String(nextOff));
    const q = p.toString();
    return q ? "#/?" + q : "#/";
  }
  document.getElementById("band").onchange = (e) => {
    location.hash = hashFor(e.target.value, view, 0);
  };
  document.getElementById("view").onchange = (e) => {
    location.hash = hashFor(band, e.target.value, 0);
  };
  document.getElementById("prev").onclick = () => {
    location.hash = hashFor(band, view, prevOff);
  };
  document.getElementById("next").onclick = () => {
    location.hash = hashFor(band, view, nextOff);
  };
}

function contribRows(signals) {
  const entries = Object.entries(signals || {}).filter(([, v]) => v);
  entries.sort((a, b) => b[1] - a[1]);
  if (!entries.length) return `<p class="empty">no non-zero contributions — this should not happen</p>`;
  return `<table><thead><tr><th>signal</th><th>contribution</th></tr></thead><tbody>` +
    entries.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${Number(v).toFixed(3)}</td></tr>`).join("") +
    `</tbody></table>`;
}

function eventTable(events) {
  if (!events.length) {
    return `<p class="empty">none resolvable — the lineage link is broken</p>`;
  }
  return `<table><thead><tr>
      <th>time</th><th>account</th><th>src</th><th>dst</th><th>type</th><th>result</th><th>lineage</th>
    </tr></thead><tbody>` +
    events
      .map(
        (e) => `<tr>
          <td class="mono">${esc(e.time_sec)}</td>
          <td><a href="${entityHref(e.src_user_uid)}">${esc(e.src_user_uid)}</a></td>
          <td><a href="${entityHref(e.src_endpoint)}">${esc(e.src_endpoint)}</a></td>
          <td><a href="${entityHref(e.dst_endpoint)}">${esc(e.dst_endpoint)}</a></td>
          <td>${esc(e.logon_type)} ${esc(e.activity_name)}</td>
          <td>${esc(e.status)}</td>
          <td class="mono">${esc(e.src_dataset)} / ${esc(e.src_file)} line ${esc(e.src_line_no)}
            <div class="muted">${esc(e.event_uid)}</div>
            <button type="button" class="raw-btn" data-uid="${esc(e.event_uid)}">show raw</button>
            <pre class="raw-out muted" id="raw-${esc(e.event_uid)}"></pre></td>
        </tr>`
      )
      .join("") +
    `</tbody></table>`;
}

async function renderAlert(uid) {
  const payload = await api("/api/alerts/" + encodeURIComponent(uid));
  const a = payload.alert;
  const start = a.bucket_start_sec - 3600;
  const end = a.bucket_end_sec + 3600;
  const dests = [
    ...new Set(
      (payload.events || [])
        .map((e) => e.dst_endpoint)
        .filter((h) => h && h !== a.src_host)
    ),
  ];
  const hop = payload.events.find(
    (e) => e.src_endpoint && e.dst_endpoint && e.src_endpoint !== e.dst_endpoint
  );

  let timelineHtml = `<p class="empty">not loaded</p>`;
  let neighHtml = `<p class="empty">not loaded</p>`;
  let corpHtml = `<p class="empty">no src≠dst event to corroborate</p>`;
  let pathsHtml = dests.length
    ? `<p class="muted">pick a destination from the contributing events.</p>
       <div class="toolbar"><select id="dst">${dests
         .map((d) => `<option value="${esc(d)}">${esc(d)}</option>`)
         .join("")}</select>
         <button id="go-path">find time-ordered routes</button></div>
       <div id="path-out"></div>`
    : `<p class="empty">no other hosts in the contributing events</p>`;

  try {
    const tl = await api(
      `/api/timeline?user=${encodeURIComponent(a.user_uid)}&host=${encodeURIComponent(a.src_host)}&start=${start}&end=${end}&limit=80`
    );
    timelineHtml = tl.length
      ? `<table><thead><tr><th>time</th><th>account</th><th>src</th><th>dst</th><th>result</th></tr></thead><tbody>` +
        tl
          .map(
            (e) => `<tr>
              <td class="mono">${esc(e.time_sec)}</td>
              <td>${esc(e.src_user_uid)}</td>
              <td>${esc(e.src_endpoint)}</td>
              <td>${esc(e.dst_endpoint)}</td>
              <td>${esc(e.status)}</td>
            </tr>`
          )
          .join("") +
        `</tbody></table>`
      : `<p class="empty">no events in ±1 hour around this bucket</p>`;
  } catch (err) {
    timelineHtml = `<div class="error">${esc(err.message)}</div>`;
  }

  try {
    const nb = await api(
      `/api/neighbours?host=${encodeURIComponent(a.src_host)}&start=${start}&end=${end}&limit=40`
    );
    neighHtml = nb.length
      ? `<table><thead><tr><th>dir</th><th>host</th><th>events</th><th>accounts</th></tr></thead><tbody>` +
        nb
          .map(
            (n) => `<tr>
              <td>${esc(n.direction)}</td>
              <td><a href="${entityHref(n.other)}">${esc(n.other)}</a></td>
              <td>${esc(n.events)}</td>
              <td>${esc(n.accounts)}</td>
            </tr>`
          )
          .join("") +
        `</tbody></table>`
      : `<p class="empty">no neighbours in this window</p>`;
  } catch (err) {
    neighHtml = `<div class="error">${esc(err.message)}</div>`;
  }

  if (hop) {
    try {
      const c = await api(
        `/api/corroborate?time=${hop.time_sec}&src=${encodeURIComponent(hop.src_endpoint)}&dst=${encodeURIComponent(hop.dst_endpoint)}`
      );
      corpHtml = `<div class="kv"><dt>pair</dt><dd>${esc(c.src_host)} → ${esc(c.dst_host)} at ${esc(c.time_sec)}</dd>
        <dt>flows</dt><dd>${esc(c.flows)} (${esc(c.flow_bytes)} bytes)</dd>
        <dt>dns</dt><dd>${esc(c.dns_lookups)}</dd>
        <dt>corroborated</dt><dd>${c.corroborated ? "yes" : "no"}</dd></div>`;
    } catch (err) {
      corpHtml = `<div class="error">${esc(err.message)}</div>`;
    }
  }

  app.innerHTML = `
    <p><a href="#/">← queue</a></p>
    <h1>Alert ${esc(a.alert_uid)}</h1>
    <div class="panel kv">
      <dt>who</dt><dd><a href="${entityHref(a.user_uid)}">${esc(a.user_uid)}</a> from
          <a href="${entityHref(a.src_host)}">${esc(a.src_host)}</a></dd>
      <dt>when</dt><dd class="mono">${esc(a.bucket_start_sec)}–${esc(a.bucket_end_sec)}</dd>
      <dt>score</dt><dd><span class="${bandClass(a.band)}">${esc(a.band)}</span> ${Number(a.score).toFixed(3)}</dd>
      <dt>size</dt><dd>${esc(a.n_events)} events, ${esc(a.n_distinct_dst)} destinations, ${esc(a.n_fail)} failures</dd>
      <dt>judgement</dt><dd>${esc(payload.decision ? payload.decision.action : "none yet")}</dd>
    </div>
    <p class="toolbar"><button type="button" id="pack">download case JSON</button></p>
    <h2>Record a judgement</h2>
    <form id="decide" class="panel toolbar">
      <select name="action">
        <option value="true_positive">true_positive</option>
        <option value="false_positive">false_positive</option>
        <option value="inconclusive">inconclusive</option>
      </select>
      <input name="analyst" value="local" size="12">
      <input name="note" placeholder="why" size="40">
      <button type="submit">write back</button>
    </form>
    <div id="history">${
      (payload.history || [])
        .map(
          (d) => `<div class="muted">${esc(d.created_at)} · ${esc(d.analyst)} · ${esc(d.action)}
            ${d.note ? " — " + esc(d.note) : ""}</div>`
        )
        .join("") || `<p class="empty">no writebacks yet</p>`
    }</div>
    <h2>Why</h2>
    ${contribRows(payload.signals)}
    <h2>Show me — contributing events</h2>
    ${eventTable(payload.events || [])}
    <h2>Timeline around the bucket (±1 hour)</h2>
    ${timelineHtml}
    <h2>Neighbours of ${esc(a.src_host)}</h2>
    ${neighHtml}
    <h2>Corroboration</h2>
    ${corpHtml}
    <h2>Time-ordered paths from ${esc(a.src_host)}</h2>
    ${pathsHtml}`;

  document.getElementById("pack").onclick = async () => {
    try {
      const body = await api("/api/alerts/" + encodeURIComponent(a.alert_uid) + "/pack");
      const blob = new Blob([JSON.stringify(body, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "case-" + a.alert_uid.slice(0, 12) + ".json";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showError(err);
    }
  };

  const go = document.getElementById("go-path");
  if (go) {
    go.onclick = async () => {
      const dst = document.getElementById("dst").value;
      const out = document.getElementById("path-out");
      out.textContent = "searching…";
      try {
        const paths = await api(
          `/api/paths?src=${encodeURIComponent(a.src_host)}&dst=${encodeURIComponent(dst)}&start=${start}&end=${end}&user=${encodeURIComponent(a.user_uid)}&max_hops=3`
        );
        if (!paths.length) {
          out.innerHTML = `<p class="empty">no time-ordered route in this window</p>`;
          return;
        }
        out.innerHTML = paths
          .map((p) => {
            const hops = (p.path || []).join(" → ");
            return `<div class="panel path mono">${esc(hops)}<div class="muted">${esc(JSON.stringify(p.times))}</div></div>`;
          })
          .join("");
      } catch (err) {
        out.innerHTML = `<div class="error">${esc(err.message)}</div>`;
      }
    };
  }
  const form = document.getElementById("decide");
  if (form) {
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      try {
        await apiPost("/api/alerts/" + encodeURIComponent(a.alert_uid) + "/decisions", {
          action: fd.get("action"),
          analyst: fd.get("analyst") || "local",
          note: fd.get("note") || "",
        });
        await renderAlert(uid);
      } catch (err) {
        showError(err);
      }
    };
  }
  document.querySelectorAll(".raw-btn").forEach((btn) => {
    btn.onclick = async () => {
      const eu = btn.getAttribute("data-uid");
      const box = document.getElementById("raw-" + eu);
      try {
        const got = await api("/api/events/" + encodeURIComponent(eu) + "/raw");
        box.textContent = got.raw;
      } catch (err) {
        box.textContent = err.message;
      }
    };
  });
}

async function renderEntity(key) {
  const p = await api("/api/entities/" + encodeURIComponent(key));
  const attrs = Object.entries(p.attributes || {})
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
    .join("");
  const rels = (p.relationships || [])
    .map((r) => {
      const target = r.host || r.account;
      const label = r.host ? "host" : "account";
      return `<tr><td>${esc(label)}</td><td>${
        target ? `<a href="${entityHref(target)}">${esc(target)}</a>` : ""
      }</td><td>${esc(r.events)}</td><td>${esc(r.failures)}</td><td>${esc(r.first_seen)}</td></tr>`;
    })
    .join("");
  app.innerHTML = `
    <p><a href="#/">← queue</a></p>
    <h1>${esc(p.kind)} ${esc(p.key)}</h1>
    <div class="panel kv">${attrs}</div>
    <h2>Strongest relationships</h2>
    ${
      rels
        ? `<table><thead><tr><th></th><th>entity</th><th>events</th><th>failures</th><th>first seen</th></tr></thead><tbody>${rels}</tbody></table>`
        : `<p class="empty">none</p>`
    }
    <h2>Latest judgements on this entity's alerts</h2>
    ${
      (p.decisions || []).length
        ? `<table><thead><tr><th>action</th><th>alert</th><th>analyst</th></tr></thead><tbody>` +
          p.decisions
            .map(
              (d) => `<tr><td>${esc(d.action)}</td><td><a href="#/alert/${encodeURIComponent(d.alert_uid)}">${esc(d.alert_uid)}</a></td><td>${esc(d.analyst)}</td></tr>`
            )
            .join("") +
          `</tbody></table>`
        : `<p class="empty">none</p>`
    }`;
}

async function renderIncidents() {
  const rows = await api("/api/incidents?limit=50&gap_hours=4");
  const body = rows.length
    ? rows
        .map(
          (r) => `<tr>
            <td class="${bandClass(r.band)}">${esc(r.band)}</td>
            <td>${Number(r.score_max).toFixed(3)}</td>
            <td>${esc(r.n_alerts)}</td>
            <td>${esc(r.n_hosts)}</td>
            <td><a href="${entityHref(r.user_uid)}">${esc(r.user_uid)}</a></td>
            <td class="mono">${esc(r.start_sec)}–${esc(r.end_sec)}</td>
            <td><a href="#/incident/${encodeURIComponent(r.incident_uid)}">open</a>
                <div class="mono muted">${esc(r.incident_uid)}</div></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="7" class="empty">no incidents</td></tr>`;
  app.innerHTML = `
    <h1>Incidents</h1>
    <p class="muted">Same account, hourly alerts merged if the next bucket starts within 4 hours. Scores are unchanged.</p>
    <table>
      <thead><tr><th>band</th><th>max score</th><th>alerts</th><th>hosts</th><th>account</th><th>window</th><th></th></tr></thead>
      <tbody>${body}</tbody>
    </table>`;
}

async function renderIncident(uid) {
  const r = await api("/api/incidents/" + encodeURIComponent(uid) + "?gap_hours=4");
  const members = (r.alert_uids || [])
    .map(
      (id) => `<li><a href="#/alert/${encodeURIComponent(id)}">${esc(id)}</a></li>`
    )
    .join("");
  const hosts = (r.src_hosts || [])
    .map((h) => `<a href="${entityHref(h)}">${esc(h)}</a>`)
    .join(", ");
  app.innerHTML = `
    <p><a href="#/incidents">← incidents</a></p>
    <h1>Incident ${esc(r.incident_uid)}</h1>
    <div class="panel kv">
      <dt>who</dt><dd><a href="${entityHref(r.user_uid)}">${esc(r.user_uid)}</a></dd>
      <dt>when</dt><dd class="mono">${esc(r.start_sec)}–${esc(r.end_sec)}</dd>
      <dt>score</dt><dd><span class="${bandClass(r.band)}">${esc(r.band)}</span> ${Number(r.score_max).toFixed(3)}</dd>
      <dt>size</dt><dd>${esc(r.n_alerts)} alerts, ${esc(r.n_hosts)} source hosts</dd>
      <dt>hosts</dt><dd>${hosts || "—"}</dd>
    </div>
    <h2>Member alerts</h2>
    <ol>${members || "<p class='empty'>none</p>"}</ol>`;
}

async function renderAudit() {
  const rows = await api("/api/audit?limit=50");
  app.innerHTML = `
    <p><a href="#/">← queue</a></p>
    <h1>Audit</h1>
    ${
      rows.length
        ? `<table><thead><tr><th>when</th><th>action</th><th>analyst</th><th>alert</th><th>note</th></tr></thead><tbody>` +
          rows
            .map(
              (d) => `<tr>
                <td>${esc(d.created_at)}</td>
                <td>${esc(d.action)}</td>
                <td>${esc(d.analyst)}</td>
                <td><a href="#/alert/${encodeURIComponent(d.alert_uid)}">${esc(d.alert_uid)}</a></td>
                <td>${esc(d.note)}</td>
              </tr>`
            )
            .join("") +
          `</tbody></table>`
        : `<p class="empty">no decisions recorded</p>`
    }`;
}

async function route() {
  await loadHealth();
  const raw = location.hash.replace(/^#/, "") || "/";
  const path = raw.split("?")[0] || "/";
  try {
    if (path === "/" || path === "") {
      await renderQueue();
      return;
    }
    if (path === "/incidents") {
      await renderIncidents();
      return;
    }
    const incident = path.match(/^\/incident\/(.+)$/);
    if (incident) {
      await renderIncident(decodeURIComponent(incident[1]));
      return;
    }
    if (path === "/audit") {
      await renderAudit();
      return;
    }
    const alert = path.match(/^\/alert\/(.+)$/);
    if (alert) {
      await renderAlert(decodeURIComponent(alert[1]));
      return;
    }
    const ent = path.match(/^\/entity\/(.+)$/);
    if (ent) {
      await renderEntity(decodeURIComponent(ent[1]));
      return;
    }
    app.innerHTML = `<div class="error">unknown view</div>`;
  } catch (err) {
    showError(err);
  }
}

window.addEventListener("hashchange", route);
route();
