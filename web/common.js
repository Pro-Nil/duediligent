// Shared UI: top bar, decision styles, event streams, and the report renderer with its source drawer.
const DECISIONS = {
  "APPROVE": {c: "var(--ok)", cs: "var(--ok-soft)", label: "Approve", say: "No rule found a blocking issue."},
  "APPROVE WITH CONDITIONS": {c: "var(--warn)", cs: "var(--warn-soft)", label: "Approve with conditions", say: "Usable once the conditions below are met."},
  "REJECT": {c: "var(--bad)", cs: "var(--bad-soft)", label: "Reject", say: "A rule found a blocking issue."},
  "REFER TO HUMAN": {c: "var(--ref)", cs: "var(--ref-soft)", label: "Refer to a person", say: "The agent will not guess here. A person should decide."},
  "ERROR": {c: "var(--bad)", cs: "var(--bad-soft)", label: "Error", say: ""},
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

function topbar(active) {
  const links = [["/", "Review", "review"], ["/batch", "Supplier register", "batch"]];
  document.body.insertAdjacentHTML("afterbegin", `<div class="topbar"><div class="in">
    <a class="brand" href="/"><span class="mark">dd</span>duediligent</a>
    <nav class="nav">${links.map(([h, t, k]) => `<a href="${h}" class="${k === active ? "on" : ""}">${t}</a>`).join("")}</nav>
    <span class="tag">Vendor security reviews · every claim cited</span></div></div>`);
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

function reasonItems(list, style) {
  return list.map(r => `<div class="item"><span class="${style === "box" ? "box" : "dot"}" style="--c:${style}"></span><div>
    <div>${esc(r.text)} ${cites(r.evidence)}</div><div class="rule">${esc(ruleName(r.rule))}</div></div></div>`).join("");
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

  const why = d.referrals.length ? reasonItems(d.referrals, "var(--ref)") : "";
  const rejects = reasonItems(d.reasons.filter(r => !r.rule.startsWith("R7")), "var(--bad)");
  const conds = reasonItems(d.conditions, "box");
  const notes = reasonItems(d.notes, "var(--mut)");

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
    <div class="quote">“${esc(rep.request)}”</div>
    <div class="stats">
      <div class="stat"><b>${rep.audit.verified}/${rep.audit.total}</b><span>Citations verified</span></div>
      <div class="stat"><b>${(rep.evidence || []).length}</b><span>Sources saved</span></div>
      <div class="stat"><b>${(rep.incidents || []).length}</b><span>Incidents found</span></div>
      <div class="stat"><b>${certCount}</b><span>Certifications claimed</span></div>
      <div class="stat"><b>${d.conditions.length}</b><span>Conditions</span></div>
    </div>
  </section>
  <div class="report">
    <section class="card fade">
      <div class="tabs">${tabs.map(([k, t, n], i) => `<button data-tab="${k}" class="${i ? "" : "on"}">${t}${n !== "" ? `<span class="n">${n}</span>` : ""}</button>`).join("")}</div>
      <div class="panel" data-panel="summary">
        <h4>Decision</h4><p style="margin:0 0 6px">${badge(d.outcome)} <span class="mut small" style="margin-left:6px">${esc(dc.say)}</span></p>
        ${why ? `<h4>Needs a person</h4>${why}` : ""}
        ${rejects ? `<h4>Blocking issues</h4>${rejects}` : ""}
        ${conds ? `<h4>Conditions to meet</h4>${conds}` : ""}
        ${notes ? `<h4>Notes</h4>${notes}` : ""}
        ${!why && !rejects && !conds && !notes ? `<p class="empty">No issues raised.</p>` : ""}
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
      <section class="card pad fade">
        <h3>Is it a real, trading business?</h3>
        <p style="margin:2px 0 10px"><span class="pill" style="--c:${bc.ok ? "var(--ok)" : "var(--warn)"};--cs:${bc.ok ? "var(--ok-soft)" : "var(--warn-soft)"}">${esc(bc.verdict)}</span> <span class="mut small">${esc(bc.text)}</span></p>
        ${bc.facts.length ? `<dl class="kv">${bc.facts.map(([k, v, e]) => `<dt>${esc(k)}</dt><dd>${esc(v)} ${cites(e)}</dd>`).join("")}</dl>` : ""}
      </section>
      ${s.case_id ? `<a class="btn ghost" href="/report/${esc(s.case_id)}" target="_blank">Open printable report</a>` : ""}
    </aside>
  </div>`;

  root.querySelectorAll(".tabs button").forEach(b => b.onclick = () => showTab(root, b.dataset.tab));
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
    return `<section class="card next fade"><div class="eyebrow">Next step</div><h3 style="margin-top:4px">Request documents from the vendor</h3>
      <p class="mut small" style="margin:0">Send this link. When the vendor uploads an audit report, it is checked and the decision is made again.</p>
      <div class="row"><input readonly value="${esc(url)}"><button class="btn ghost sm" data-copy="${esc(url)}">Copy</button></div>
      <div class="row"><a class="btn sm" href="${esc(url)}" target="_blank">Open vendor page</a></div></section>`;
  }
  const w = s.watch;
  if (w && ["created", "existing"].includes(w.status)) {
    return `<section class="card next fade"><div class="eyebrow">Monitoring</div><h3 style="margin-top:4px">Watching ${esc(s.domain)}</h3>
      <p class="mut small" style="margin:0">Crustdata watch #${esc(w.watch_id)} checks weekly for news and headcount changes, and alerts ${esc(w.email)}.</p></section>`;
  }
  if (w) return `<section class="card next fade"><div class="eyebrow">Monitoring</div><p class="mut small" style="margin:4px 0 0">Not set up: ${esc(w.reason)}</p></section>`;
  if (out === "REFER TO HUMAN") return `<section class="card next fade"><div class="eyebrow">Next step</div><h3 style="margin-top:4px">A person decides</h3><p class="mut small" style="margin:0">The agent stopped rather than guess. The reason is on the left.</p></section>`;
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
