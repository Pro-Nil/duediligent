// Shared UI: top bar, decision styles, event streams, and the report renderer with its source drawer.
const DECISIONS = {
  "APPROVE": {c: "var(--ok)", cs: "var(--ok-soft)", label: "Approve", say: "No rule found a blocking issue.",
    help: "Safe to use for the stated purpose. Nothing needs doing first."},
  "APPROVE WITH CONDITIONS": {c: "var(--warn)", cs: "var(--warn-soft)", label: "Approve with conditions", say: "Usable once the conditions below are met.",
    help: "Usable, but only after each listed condition is met, for example a current audit report."},
  "REJECT": {c: "var(--bad)", cs: "var(--bad-soft)", label: "Reject", say: "A rule found a blocking issue.",
    help: "Do not use. A rule found a blocking issue, such as a recent breach with no public fix."},
  "REFER TO HUMAN": {c: "var(--ref)", cs: "var(--ref-soft)", label: "Refer to a person", say: "The agent will not guess here. A person should decide.",
    help: "The agent stopped rather than guess: the name was ambiguous, sources disagreed, or data was missing."},
  "ERROR": {c: "var(--bad)", cs: "var(--bad-soft)", label: "Error", say: "", help: "The review could not run."},
};
// What would resolve each kind of open issue, so the reader knows what to do next.
const CLEARS = {
  R1: "Tell the agent which company you mean",
  R2: "Have a person confirm the company still operates",
  R3: "Re-run the review, or have a person check it by hand",
  R4: "Ask the vendor how they fixed it, and have a person read the answer",
  R5: "Get the vendor's audit report: they upload it through the vendor link",
  R6: "Confirm which legal entity signs the contract",
  R8: "Ask the vendor, and have a person judge the answer",
};
const COLORS = Object.fromEntries(Object.entries(DECISIONS).map(([k, v]) => [k, v.c]));
const RULES = {R1: "Identity", R2: "Viability", R3: "Coverage", R4: "Incident", R5: "Certification", R6: "Stability", R7: "Outcome", R8: "Business check"};
const CERTS = {SOC2_TYPE2: "SOC 2 Type II", SOC2: "SOC 2", ISO27001: "ISO 27001", ISO27701: "ISO 27701", PCI_DSS: "PCI DSS", HIPAA: "HIPAA", FEDRAMP: "FedRAMP", SOC3: "SOC 3", SOC2_TYPE1: "SOC 2 Type I", ISO27001_CERT: "ISO 27001 certificate"};
const CONTROLS = {bug_bounty: "Bug bounty", disclosure_policy: "Disclosure policy", encryption: "Encryption", dpa: "Data processing agreement", subprocessors: "Subprocessor list", pen_test: "Penetration testing"};
const KINDS = {crustdata: "Crustdata record", web_page: "Web page", search: "Web search", passive: "Passive check", breach_db: "Breach catalogue", document: "Vendor document"};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
}
const $ = id => document.getElementById(id);
const deco = o => DECISIONS[o] || DECISIONS.ERROR;
const badge = o => `<span class="badge" style="--c:${deco(o).c};--cs:${deco(o).cs}">${esc(deco(o).label)}</span>`;
const ruleName = r => RULES[(r || "").split(" ")[0]] || r;
const fmtDate = iso => { try { return new Date(iso).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"}); } catch (e) { return iso; } };

function topbar(active, opts = {}) {
  if (opts.vendor) {
    // Vendors see only this page: no navigation into the reviewer's workspace.
    document.body.insertAdjacentHTML("afterbegin", `<div class="topbar"><div class="in"><span class="brand"><span class="mark">dd</span>duediligent</span>
      <span class="tag">Secure document request</span></div></div>`);
    return;
  }
  const links = [["/", "Overview", "overview"], ["/new", "New review", "review"], ["/reviews", "Reviews", "reviews"],
                 ["/batch", "Supplier register", "batch"], ["/monitoring", "Monitoring", "monitoring"]];
  document.body.insertAdjacentHTML("afterbegin", `<div class="topbar"><div class="in">
    <a class="brand" href="/"><span class="mark">dd</span>duediligent</a>
    <nav class="nav">${links.map(([h, t, k]) => `<a href="${h}" class="${k === active ? "on" : ""}">${t}${k === "reviews" ? `<span class="navbadge hide" id="unread" title="Reviews with a vendor response you have not opened"></span>` : ""}</a>`).join("")}</nav>
    <span class="tag">Vendor security reviews · every claim cited</span></div></div>`);
  pollUnread();
  setInterval(pollUnread, 20000);
}

/* ---------- Updates from vendors ---------- */
async function pollUnread() {
  try {
    const r = await fetch("/api/cases?limit=500").then(x => x.json());
    const b = $("unread");
    if (b) { b.textContent = r.unread; b.classList.toggle("hide", !r.unread); }
    document.title = document.title.replace(/^\(\d+\) /, "");
    if (r.unread) document.title = `(${r.unread}) ${document.title}`;
    return r;
  } catch (e) { return null; }
}

function alertsSupported() { return "Notification" in window; }
function alertsOn() { return alertsSupported() && Notification.permission === "granted"; }
async function enableAlerts(btn) {
  if (!alertsSupported()) return;
  const p = await Notification.requestPermission();
  if (btn) btn.textContent = p === "granted" ? "Desktop alerts on" : "Alerts blocked in browser settings";
}
function desktopAlert(title, body, url) {
  if (!alertsOn()) return;
  const n = new Notification(title, {body, tag: url});
  n.onclick = () => { window.focus(); if (url) location.href = url; n.close(); };
}

const UPLOAD_SAY = h => {
  const kind = CERTS[h.report_type] || "document";
  if (!h.from || h.from === h.outcome) return `uploaded ${h.file} (${kind}). The decision is still: ${deco(h.outcome).label}.`;
  return `uploaded ${h.file} (${kind}). The decision changed from ${deco(h.from).label} to ${deco(h.outcome).label}.`;
};

/* Watch one open case. When the vendor uploads something, show a banner and a desktop alert. */
function watchCase(caseId, version, vendor, onReload) {
  let known = version;
  const tick = async () => {
    try {
      const v = await fetch(`/api/case/${caseId}/version`).then(r => r.json());
      if (v.version > known) {
        known = v.version;
        const h = v.last_event || {};
        showUpdateBanner(`${vendor} ${UPLOAD_SAY(h)}`, h.outcome, onReload);
        desktopAlert(`${vendor} responded`, UPLOAD_SAY(h), `/report/${caseId}`);
        pollUnread();
      }
    } catch (e) {}
  };
  return setInterval(tick, 6000);
}

function showUpdateBanner(text, outcome, onReload) {
  let el = $("update-banner");
  if (!el) {
    document.body.insertAdjacentHTML("beforeend", `<div class="update-banner" id="update-banner" role="status"></div>`);
    el = $("update-banner");
  }
  el.style.setProperty("--c", deco(outcome).c);
  el.innerHTML = `<div><div class="eyebrow">Vendor response</div><div>${esc(text)}</div></div>
    <button class="btn sm" id="ub-load">Show the update</button><button class="btn ghost sm" id="ub-x" aria-label="Dismiss">✕</button>`;
  el.classList.add("show");
  $("ub-x").onclick = () => el.classList.remove("show");
  $("ub-load").onclick = () => { el.classList.remove("show"); onReload(); };
}

function markSeen(caseId) { return fetch(`/api/case/${caseId}/seen`, {method: "POST"}).then(() => pollUnread()).catch(() => {}); }

function activityHTML(history) {
  if (!history || !history.length) return "";
  return `<section class="card pad"><h3>Activity</h3><ol class="timeline">${history.map(h => {
    const when = h.at ? fmtDate(h.at) : "";
    if (h.kind === "vendor_upload") return `<li><span class="tdot" style="--c:${deco(h.outcome).c}"></span><div><b>Vendor uploaded ${esc(h.file)}</b>
      <div class="small mut">${esc(CERTS[h.report_type] || "Document")} · ${h.accepted ? "accepted" : "did not meet the requirement"}</div>
      <div class="small">${h.from && h.from !== h.outcome ? `${esc(deco(h.from).label)} → ` : ""}${badge(h.outcome)}</div><div class="small mut">${esc(when)}</div></div></li>`;
    return `<li><span class="tdot" style="--c:${deco(h.outcome).c}"></span><div><b>${esc(h.event || "Review completed")}</b><div class="small">${badge(h.outcome)}</div><div class="small mut">${esc(when)}</div></div></li>`;
  }).join("")}</ol></section>`;
}

async function postStream(url, body, onEvent) {
  const res = await fetch(url, {method: "POST", body});
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch (e) {}
    onEvent({type: "error", message: msg});
    return;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const {value, done} = await reader.read();
    if (done) break;
    buf += decoder.decode(value, {stream: true});
    let cut;
    while ((cut = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, cut);
      buf = buf.slice(cut + 2);
      const line = chunk.split("\n").find(l => l.startsWith("data: "));
      if (line) onEvent(JSON.parse(line.slice(6)));
    }
  }
}

/* ---------- Live stage checklist ---------- */
const STAGES = [
  ["intake", "Read the request", /Reading the request|Reading .*\.pdf/],
  ["identity", "Identify the company", /Identifying/],
  ["record", "Company record", /Pulling the company record/],
  ["posture", "Public security posture", /Checking the public/],
  ["search", "Breaches and certifications", /Searching for breaches|Reading \d+ vendor pages/],
  ["analysis", "Read pages, check quotes", /Analysing/],
  ["decision", "Apply the rulebook", /Applying the rulebook/],
  ["audit", "Citation audit", /Citation audit/],
];

function makeStages(el, stages = STAGES) {
  el.innerHTML = stages.map(([k, t]) => `<div class="step" data-k="${k}"><span class="ic"></span><div><div class="t">${t}</div><div class="d"></div></div></div>`).join("");
  let current = null;
  const node = k => el.querySelector(`[data-k="${k}"]`);
  return {
    step(msg) {
      const hit = stages.find(([, , re]) => re.test(msg));
      if (!hit) return false;
      const idx = stages.indexOf(hit);
      stages.slice(0, idx).forEach(([k]) => { const n = node(k); if (!n.classList.contains("warn")) { n.classList.remove("active"); n.classList.add("done"); } });
      current = hit[0];
      const n = node(current);
      n.classList.add("active");
      if (!/^(Reading the request|Identifying|Applying|Pulling|Checking)/.test(msg)) n.querySelector(".d").textContent = msg;
      return true;
    },
    detail(msg, warn) {
      if (!current) return;
      const n = node(current);
      n.querySelector(".d").textContent = msg;
      if (warn) n.classList.add("warn");
    },
    finish() { el.querySelectorAll(".step").forEach(n => { n.classList.remove("active"); if (!n.classList.contains("warn")) n.classList.add("done"); }); },
  };
}

/* ---------- Report ---------- */
function citeIndex(rep) {
  const idx = {};
  const add = (id, label, quote) => { if (!id) return; (idx[id] = idx[id] || []).push({label, quote}); };
  const STATUS = {current_claim: "claimed as current", in_progress: "in progress", mention_only: "mentioned only"};
  for (const f of rep.findings || []) {
    const a = f.attrs || {};
    if (f.kind === "certification" && a.framework === "OTHER") continue;
    const label = f.kind === "certification" ? `${CERTS[a.framework] || a.framework}, ${STATUS[a.status] || a.status}`
      : f.kind === "control" ? CONTROLS[f.claim] || f.claim
      : f.kind === "leader" ? `${f.value}: ${f.claim}`
      : f.kind === "incident" ? `Incident: ${f.claim}`
      : f.kind === "closure" ? `Closure: ${f.claim}` : f.claim;
    add(f.evidence_id, label, f.quote);
  }
  for (const i of rep.incidents || []) for (const q of i.quotes || []) add(q.evidence, i.summary, q.quote);
  for (const c of rep.certifications || []) for (const q of c.quotes || []) add(q.evidence, CERTS[c.framework] || c.framework, q.quote);
  for (const d of rep.documents || []) for (const [k, q] of Object.entries(d.verified || {})) add((d.evidence || [])[0], `${k}, page ${q.page}`, q.quote);
  return idx;
}

function cites(ids) { return (ids || []).map(id => `<button class="cite" data-ev="${esc(id)}">${esc(id)}</button>`).join(""); }

function businessCheck(rep) {
  const s = rep.stability || {}, id = rep.identity || {}, cov = rep.coverage || {};
  if (id.status !== "resolved" || !(s.evidence || []).length) return {ok: null, verdict: "Could not confirm", text: "There is no company record to check against.", facts: []};
  const reach = cov.site_reachable;
  const ok = !(rep.closures || []).length && String(s.status).toLowerCase() === "active" && typeof s.headcount === "number" && s.headcount >= 5 && reach;
  const facts = [
    ["Founded", s.founded ?? "Unknown", s.evidence],
    ["Status on record", s.status ?? "Unknown", s.evidence],
    ["Staff on record", typeof s.headcount === "number" ? s.headcount.toLocaleString() : "Unknown", s.evidence],
    ["Open roles", s.openings ?? "Unknown", s.evidence],
    ["Website", `${id.domain} · ${reach ? "reachable" : "unreachable"}`, cov.site_evidence],
  ];
  if (s.acquired) facts.push(["Acquisition", s.acquired, s.evidence]);
  return {ok, verdict: ok ? "Looks real and trading" : "Could not confirm", text: (rep.closures || []).length ? "The company record and press reports disagree." : ok ? "Active record, real staff and a live website." : "Some evidence is missing or weak.", facts};
}

function reasonItems(list, style, showClears = true) {
  return list.map(r => {
    const code = (r.rule || "").split(" ")[0];
    const clears = showClears && style !== "var(--mut)" && CLEARS[code];
    return `<div class="item"><span class="${style === "box" ? "box" : "dot"}" style="--c:${style}"></span><div>
    <div>${esc(r.text)} ${cites(r.evidence)}</div>
    <div class="meta"><span class="rule">${esc(ruleName(r.rule))}</span>${clears ? ` · <span class="clears">To resolve: ${esc(clears)}</span>` : ""}</div></div></div>`;
  }).join("");
}

/* Every issue in a decision, grouped in the order a reader should act on them. */
function issuesHTML(d, withCites = true) {
  const strip = list => withCites ? list : list.map(r => ({...r, evidence: []}));
  const groups = [
    ["Needs a person", strip(d.referrals || []), "var(--ref)"],
    ["Blocking issues", strip((d.reasons || []).filter(r => !r.rule.startsWith("R7"))), "var(--bad)"],
    ["Conditions to meet", strip(d.conditions || []), "box"],
    ["Notes", strip(d.notes || []), "var(--mut)"],
  ].filter(([, l]) => l.length);
  if (!groups.length) return `<p class="empty">No issues raised.</p>`;
  return groups.map(([t, l, s]) => `<h4>${t} <span class="count">${l.length}</span></h4>${reasonItems(l, s)}`).join("");
}

/* One plain sentence that says what the decision means for this vendor. */
function summarySentence(s) {
  const d = s.report.decision, name = s.vendor || "This vendor";
  const n = d.conditions.length;
  if (d.outcome === "APPROVE") return `${name} can be used for this purpose. No rule raised a blocking issue${d.notes.length ? `, and there ${d.notes.length === 1 ? "is 1 note" : `are ${d.notes.length} notes`} worth reading` : ""}.`;
  if (d.outcome === "APPROVE WITH CONDITIONS") {
    const cert = d.conditions.some(c => c.rule.startsWith("R5"));
    const docs = (s.report.documents || []).length;
    const tail = !cert ? "" : docs ? "The vendor's audit report was checked but does not yet meet the certification requirement." : "An audit report from the vendor clears the certification condition.";
    return `${name} can be used once ${n === 1 ? "1 condition is" : `${n} conditions are`} met. ${tail}`;
  }
  if (d.outcome === "REJECT") return `Do not use ${name}. ${(d.reasons.find(r => !r.rule.startsWith("R7")) || {}).text || ""}`;
  if (d.outcome === "REFER TO HUMAN") return `The agent stopped rather than guess. ${(d.referrals[0] || {}).text || ""}`;
  return "";
}

function legendHTML() {
  return `<div class="legend">${["APPROVE", "APPROVE WITH CONDITIONS", "REFER TO HUMAN", "REJECT"].map(o =>
    `<div class="lg">${badge(o)}<span>${esc(deco(o).help)}</span></div>`).join("")}</div>`;
}

function renderReport(root, s, opts = {}) {
  const rep = s.report;
  const d = rep.decision;
  const dc = deco(d.outcome);
  const id = rep.identity || {};
  const idx = citeIndex(rep);
  const name = s.vendor || "Unidentified vendor";
  const bc = businessCheck(rep);
  const certCount = (rep.certifications || []).filter(c => c.status === "current_claim").length;
  const leaders = (rep.findings || []).filter(f => f.kind === "leader");
  const controls = {};
  for (const f of (rep.findings || []).filter(f => f.kind === "control")) (controls[f.claim] = controls[f.claim] || []).push(f.evidence_id);
  const posture = (rep.findings || []).filter(f => f.kind === "posture");
  const facts = (rep.findings || []).filter(f => f.kind === "stability");


  const tabs = [
    ["summary", "Summary", ""],
    ["incidents", "Incidents", (rep.incidents || []).length],
    ["certs", "Certifications", (rep.certifications || []).length + (rep.documents || []).length],
    ["company", "Company", ""],
    ["evidence", "Evidence", (rep.evidence || []).length],
  ];

  const incidents = (rep.incidents || []).length ? rep.incidents.map(i => `<div class="item"><span class="dot" style="--c:${i.remediated ? "var(--warn)" : "var(--bad)"}"></span><div>
      <div><b>${esc(i.date || "Date unknown")}</b> · ${esc(i.summary)} ${cites(i.evidence)}</div>
      <div class="meta">${i.remediated ? "Remediation reported" : "No remediation found"}${i.role ? ` · ${esc({breached_vendor: "vendor's own systems", customer_accounts: "customer accounts", supplier: "via a supplier"}[i.role] || i.role)}` : ""}</div>
      ${(i.quotes || []).filter(q => q.quote).slice(0, 2).map(q => `<blockquote>“${esc(q.quote)}” ${cites([q.evidence])}</blockquote>`).join("")}
    </div></div>`).join("")
    : `<p class="empty">No public breach found in the sources searched ${cites(rep.coverage.search_evidence)}. That does not prove there were none.</p>`;

  const docs = (rep.documents || []).map(x => x.readable ? `<div class="tile" style="margin-bottom:10px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>${esc(CERTS[x.report_type] || x.report_type)}</b>
        <span class="pill" style="--c:${x.current ? "var(--ok)" : "var(--warn)"};--cs:${x.current ? "var(--ok-soft)" : "var(--warn-soft)"}">${x.current ? "Current" : "Out of date"}</span>
        <span class="pill">Opinion: ${esc(x.opinion)}</span><span class="push mut small">${esc(x.filename)} ${cites(x.evidence)}</span></div>
      <dl class="kv" style="margin:10px 0 0">
        <dt>Organisation</dt><dd>${esc(x.organisation)}</dd><dt>Auditor</dt><dd>${esc(x.auditor || "Unknown")}</dd>
        <dt>Audit period</dt><dd>${esc(x.period_start || "?")} to ${esc(x.period_end || x.valid_until || "?")}</dd>
        ${x.age_months != null ? `<dt>Age</dt><dd>${x.age_months} months</dd>` : ""}
      </dl>
      ${Object.entries(x.verified || {}).map(([k, q]) => `<blockquote><span class="rule">${esc(k)} · page ${q.page}</span><br>“${esc(q.quote.slice(0, 260))}”</blockquote>`).join("")}
    </div>` : `<div class="tile">${esc(x.filename)}: ${esc(x.problem)}</div>`).join("");

  const certs = (rep.certifications || []).length ? `<div class="grid2">${rep.certifications.map(c => `<div class="tile"><b>${esc(CERTS[c.framework] || c.framework)}</b> ${cites(c.evidence)}
      <div class="k">${esc({current_claim: "Claimed as current", in_progress: "In progress", mention_only: "Mentioned only"}[c.status] || c.status)}</div></div>`).join("")}</div>
      <p class="mut small">These are the vendor's public claims. Only an uploaded audit report is checked against the auditor's own words.</p>`
    : `<p class="empty">No certification statement found publicly ${cites(rep.coverage.search_evidence)}.</p>`;

  const ev = (rep.evidence || []).map(e => {
    const link = /^https?:/.test(e.source) ? `<a href="${esc(e.source)}" target="_blank" rel="noopener">${esc(e.source)}</a>` : esc(e.source);
    return `<div class="ev" id="ev-${esc(e.id)}"><span class="id">${esc(e.id)}</span><div><div>${esc(e.title)}</div><div class="src">${esc(KINDS[e.kind] || e.kind)} · ${link} · ${esc(fmtDate(e.retrieved_at))}</div></div></div>`;
  }).join("");

  const next = nextCard(s, opts);

  root.innerHTML = `
  <section class="card hero fade" style="--c:${dc.c};--cs:${dc.cs}">
    <div class="top">
      <div class="avatar">${esc(name.trim()[0] || "?")}</div>
      <div><h2>${esc(name)}</h2><div class="sub">${id.domain ? `<a href="https://${esc(id.domain)}" target="_blank" rel="noopener">${esc(id.domain)}</a> · ` : ""}Data sensitivity: ${esc(rep.sensitivity)} · ${esc(fmtDate(rep.reviewed_at))}</div></div>
      ${badge(d.outcome)}
    </div>
    <p class="verdict-line">${esc(summarySentence(s))}</p>
    ${rep.parent ? `<p class="small mut" style="margin:6px 0 0">Re-run after you confirmed the company. <a href="/report/${esc(rep.parent)}">See the original question</a></p>` : ""}
    <div class="quote"><span class="eyebrow">Your request</span><br>“${esc(rep.request)}”</div>
    <div class="stats">
      <div class="stat" title="Every claim and every reason was re-checked against the saved source. This is how many passed."><b>${rep.audit.verified}/${rep.audit.total}</b><span>Citations verified</span></div>
      <div class="stat" title="Pages, searches and records saved as evidence. See the Evidence tab."><b>${(rep.evidence || []).length}</b><span>Sources saved</span></div>
      <div class="stat" title="Breaches or security incidents found in public reports. See the Incidents tab."><b>${(rep.incidents || []).length}</b><span>Incidents found</span></div>
      <div class="stat" title="Certifications the vendor publicly claims to hold, such as SOC 2 or ISO 27001."><b>${certCount}</b><span>Certifications claimed</span></div>
      <div class="stat" title="Things that must happen before the vendor is used. See the Summary tab."><b>${d.conditions.length}</b><span>Conditions</span></div>
    </div>
  </section>
  <div class="report">
    <section class="card fade">
      <div class="tabs">${tabs.map(([k, t, n], i) => `<button data-tab="${k}" class="${i ? "" : "on"}">${t}${n !== "" ? `<span class="n">${n}</span>` : ""}</button>`).join("")}</div>
      <div class="panel" data-panel="summary">
        <h4>Decision</h4><p style="margin:0 0 6px">${badge(d.outcome)} <span class="mut small" style="margin-left:6px">${esc(dc.help)}</span></p>
        ${issuesHTML(d)}
        <p class="hint">Tip: click any <span class="cite" style="cursor:default">E</span> number to see the saved source and the exact quote behind a claim.</p>
        ${rep.vendor_email ? `<details><summary>Draft information request to the vendor</summary><pre>${esc(rep.vendor_email)}</pre></details>` : ""}
      </div>
      <div class="panel hide" data-panel="incidents"><h4>Incidents</h4>${incidents}</div>
      <div class="panel hide" data-panel="certs">${docs ? `<h4>Audit reports from the vendor</h4>${docs}` : ""}<h4>Public claims</h4>${certs}
        ${Object.keys(controls).length ? `<h4>Published controls</h4><div class="grid2">${Object.entries(controls).map(([k, ids]) => `<div class="tile">${esc(CONTROLS[k] || k)} ${cites([...new Set(ids)])}</div>`).join("")}</div>` : ""}
        ${posture.length ? `<h4>Passive checks</h4><div class="grid2">${posture.map(f => `<div class="tile">${esc(f.claim)} ${cites([f.evidence_id])}</div>`).join("")}</div>` : ""}
      </div>
      <div class="panel hide" data-panel="company">
        <h4>Who runs it</h4>${leaders.length ? leaders.map(f => `<div class="item"><span class="dot" style="--c:var(--accent)"></span><div><b>${esc(f.value)}</b> · ${esc(f.claim)} ${cites([f.evidence_id, f.attrs?.confirmed_by].filter(Boolean))}<div class="meta">Named on the company record and confirmed by a web search</div></div></div>`).join("") : `<p class="empty">No leader could be confirmed by an independent source.</p>`}
        <h4>Company facts</h4>${facts.length ? `<dl class="kv">${facts.map(f => { const [k, ...v] = f.claim.split(": "); return `<dt>${esc(k)}</dt><dd>${esc(v.join(": "))} ${cites([f.evidence_id])}</dd>`; }).join("")}</dl>` : `<p class="empty">No company record.</p>`}
      </div>
      <div class="panel hide" data-panel="evidence"><h4>Every source this review used</h4>${ev || `<p class="empty">None.</p>`}
        ${(rep.coverage.failed_urls || []).length ? `<details><summary>${rep.coverage.failed_urls.length} pages could not be read</summary><div class="small mut">${rep.coverage.failed_urls.map(esc).join("<br>")}</div></details>` : ""}
      </div>
    </section>
    <aside class="side">
      ${next}
      ${activityHTML(rep.history)}
      <section class="card pad fade">
        <h3>Is it a real, trading business?</h3>
        <p style="margin:2px 0 10px"><span class="pill" style="--c:${bc.ok ? "var(--ok)" : "var(--warn)"};--cs:${bc.ok ? "var(--ok-soft)" : "var(--warn-soft)"}">${esc(bc.verdict)}</span> <span class="mut small">${esc(bc.text)}</span></p>
        ${bc.facts.length ? `<dl class="kv">${bc.facts.map(([k, v, e]) => `<dt>${esc(k)}</dt><dd>${esc(v)} ${cites(e)}</dd>`).join("")}</dl>` : ""}
      </section>
      ${s.case_id ? `<div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn ghost sm" href="/report/${esc(s.case_id)}" target="_blank" title="A permanent link to this review">Permanent link</a><a class="btn ghost sm" href="/report/${esc(s.case_id)}/print" target="_blank">Printable version</a></div>` : ""}
    </aside>
  </div>`;

  root.querySelectorAll(".tabs button").forEach(b => b.onclick = () => showTab(root, b.dataset.tab));
  root.querySelectorAll("form.other").forEach(f => f.onsubmit = e => {
    e.preventDefault();
    const d = f.domain.value.trim();
    if (d) location.href = `/new?clarify=${encodeURIComponent(f.dataset.case)}&domain=${encodeURIComponent(d)}`;
  });
  root.onclick = e => {
    const c = e.target.closest(".cite");
    if (c) openSource(c.dataset.ev, rep, idx);
    const copy = e.target.closest("[data-copy]");
    if (copy) { navigator.clipboard?.writeText(copy.dataset.copy); copy.textContent = "Copied"; setTimeout(() => copy.textContent = "Copy", 1400); }
  };
}

function showTab(root, k) {
  root.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === k));
  root.querySelectorAll("[data-panel]").forEach(p => p.classList.toggle("hide", p.dataset.panel !== k));
}

function nextCard(s, opts) {
  const out = s.outcome;
  if (opts.vendorView) return "";
  if (out === "APPROVE WITH CONDITIONS" && s.case_id) {
    const url = `${location.origin}/vendor/${s.case_id}`;
    const conds = s.report?.decision?.conditions || [];
    const byDoc = conds.filter(c => c.rule.startsWith("R5")).length;
    const byPerson = conds.length - byDoc;
    const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
    const uploads = (s.report?.history || []).filter(h => h.kind === "vendor_upload");
    const last = uploads[uploads.length - 1];
    const certCond = conds.find(c => c.rule.startsWith("R5"));
    const head = last
      ? `<div class="eyebrow">Next step · the vendor responded</div>
         <h3 style="margin-top:4px">${last.accepted ? "Their document was accepted" : "Their document was not enough"}</h3>
         <p class="small" style="margin:0 0 8px;color:var(--fg-2)">They uploaded <b>${esc(last.file)}</b> (${esc(CERTS[last.report_type] || "document")}). ${last.accepted ? "" : esc(certCond ? certCond.text : "")} ${byDoc ? "Send the same link to ask for a replacement:" : "Anything else still open needs a person."}</p>`
      : `<div class="eyebrow">Next step · waiting on the vendor</div>
         <h3 style="margin-top:4px">Ask the vendor for evidence</h3>
         <p class="small" style="margin:0 0 8px;color:var(--fg-2)">This review can't finish from public information alone. Send the vendor this link:</p>`;
    return `<section class="card next">${head}
      <div class="row" style="margin-top:0"><input readonly value="${esc(url)}" aria-label="Vendor link"><button class="btn ghost sm" data-copy="${esc(url)}">Copy</button></div>
      <ol class="small" style="margin:12px 0 0;padding-left:18px;color:var(--fg-2)">
        <li>The vendor sees what's missing.</li>
        <li>They upload a SOC 2 report, SOC 3 report or ISO 27001 certificate.</li>
        <li>The agent checks it, cites each fact to its page, and decides again. The new decision shows on the vendor page.</li>
      </ol>
      <p class="small mut" style="margin:10px 0 0">${byDoc ? `A valid audit report clears the certification condition.` : `No condition here needs an audit report.`}${byPerson ? ` The other ${byPerson === 1 ? "condition needs" : byPerson + " conditions need"} a person to read the vendor's answer.` : ""}</p>
      ${local ? `<p class="small mut" style="margin:8px 0 0">Running locally, this link only works on this computer. To try it, open it and act as the vendor.</p>` : ""}
      <div class="row"><a class="btn sm" href="${esc(url)}" target="_blank">Open as the vendor</a></div></section>`;
  }
  const w = s.watch;
  if (w && ["created", "existing"].includes(w.status)) {
    return `<section class="card next fade"><div class="eyebrow">Monitoring</div><h3 style="margin-top:4px">Watching ${esc(s.domain)}</h3>
      <p class="mut small" style="margin:0">Crustdata watch #${esc(w.watch_id)} checks weekly for news and headcount changes, and alerts ${esc(w.email)}.</p></section>`;
  }
  if (w) return `<section class="card next fade"><div class="eyebrow">Monitoring</div><p class="mut small" style="margin:4px 0 0">Not set up: ${esc(w.reason)}</p></section>`;
  if (out === "REFER TO HUMAN") {
    const hist = s.report?.history || [];
    const done = hist.find(h => h.kind === "clarified");
    if (done) return `<section class="card next"><div class="eyebrow">Answered</div><h3 style="margin-top:4px">You confirmed ${esc(done.choice)}</h3>
      <p class="small mut" style="margin:0 0 10px">The agent re-ran the review on that company.</p>
      ${done.child ? `<a class="btn sm" href="/report/${esc(done.child)}">Open the new review</a>` : ""}</section>`;
    const id = s.report?.identity || {};
    const isIdentity = (s.report?.decision?.referrals || []).some(r => r.rule.startsWith("R1"));
    if (isIdentity && s.case_id && !/not a review of one vendor/.test(id.detail || "")) {
      const opts = id.options || [];
      const go = (name, domain) => `/new?clarify=${encodeURIComponent(s.case_id)}&name=${encodeURIComponent(name || "")}&domain=${encodeURIComponent(domain || "")}`;
      return `<section class="card next" id="clarify"><div class="eyebrow">Next step · your answer</div>
        <h3 style="margin-top:4px">Help the agent decide</h3>
        <p class="small" style="margin:0 0 10px;color:var(--fg-2)">It wasn't sure which company you mean, so it didn't guess. Pick one, and it reviews that company in full.</p>
        ${opts.map(o => `<a class="choice" href="${go(o.name, o.domain)}"><b>${esc(o.name)}</b><span>${esc(o.domain)}${o.employees ? ` · ${/\d/.test(o.employees) ? esc(o.employees) + " staff" : /myself/i.test(o.employees) ? "one person" : esc(o.employees)}` : ""}</span></a>`).join("")}
        <form class="other" data-case="${esc(s.case_id)}">
          <label class="small mut" for="other-domain">${opts.length ? "None of these? " : ""}Enter the vendor's website</label>
          <div class="row" style="margin-top:4px"><input id="other-domain" name="domain" placeholder="vendor.com" required><button class="btn sm" type="submit">Review it</button></div>
        </form></section>`;
    }
    return `<section class="card next"><div class="eyebrow">Next step</div><h3 style="margin-top:4px">A person decides</h3><p class="mut small" style="margin:0">The agent stopped rather than guess. The reason is on the left.</p></section>`;
  }
  return "";
}

function openSource(id, rep, idx) {
  const e = (rep.evidence || []).find(x => x.id === id);
  if (!e) return;
  let drawer = $("drawer");
  if (!drawer) {
    document.body.insertAdjacentHTML("beforeend", `<div class="scrim" id="scrim"></div><aside class="drawer" id="drawer" aria-label="Source"><header><span class="eyebrow" id="dr-k"></span><button class="btn ghost sm close" id="dr-x">Close</button></header><div class="body" id="dr-b"></div></aside>`);
    drawer = $("drawer");
    const close = () => { drawer.classList.remove("open"); $("scrim").classList.remove("open"); };
    $("dr-x").onclick = close; $("scrim").onclick = close;
    document.addEventListener("keydown", ev => { if (ev.key === "Escape") close(); });
  }
  const link = /^https?:/.test(e.source) ? `<a href="${esc(e.source)}" target="_blank" rel="noopener">Open the live page ↗</a>` : `<span class="mono small">${esc(e.source)}</span>`;
  const claims = idx[id] || [];
  $("dr-k").textContent = `${e.id} · ${KINDS[e.kind] || e.kind}`;
  $("dr-b").innerHTML = `<h3 style="margin:0 0 4px">${esc(e.title)}</h3><p class="small mut" style="margin:0 0 6px">Saved ${esc(fmtDate(e.retrieved_at))}</p>
    <p style="margin:0 0 14px">${link}</p>
    <div class="eyebrow" style="margin-bottom:6px">Claims that cite this source (${claims.length})</div>
    ${claims.length ? claims.map(c => `<div class="tile" style="margin-bottom:8px"><div>${esc(c.label)}</div>${c.quote ? `<blockquote>“${esc(c.quote)}”</blockquote><div class="small mut" style="margin-top:4px">Quote matched word for word in the saved copy.</div>` : `<div class="small mut">Read from a field of the saved record.</div>`}</div>`).join("") : `<p class="empty">Used as background: searched or read, with no claim quoted from it.</p>`}
    <p class="small mut" style="margin-top:14px">Snapshot hash <span class="mono">${esc((e.sha256 || "").slice(0, 16))}…</span></p>`;
  drawer.classList.add("open"); $("scrim").classList.add("open");
}
