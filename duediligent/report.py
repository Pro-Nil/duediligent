"""Render the finished assessment. Every line is built from verified findings."""
from __future__ import annotations

import html
import re

CERT_NAMES = {"SOC2_TYPE2": "SOC 2 Type II", "SOC2": "SOC 2", "ISO27001": "ISO 27001", "ISO27701": "ISO 27701",
              "PCI_DSS": "PCI DSS", "HIPAA": "HIPAA", "FEDRAMP": "FedRAMP", "OTHER": "Other"}
STATUS = {"current_claim": "Claimed as current", "in_progress": "In progress", "mention_only": "Mentioned only"}


CONTROL_NAMES = {"bug_bounty": "Bug bounty programme", "disclosure_policy": "Vulnerability disclosure policy", "encryption": "Encryption statement",
                 "dpa": "Data processing agreement", "subprocessors": "Published subprocessor list", "pen_test": "Penetration testing"}


def cite(ids: list[str] | None) -> str:
    return " ".join(f"[{e}]" for e in ids or [])


def _title(r: dict) -> str:
    i = r["identity"]
    return i.get("name") or r["intake"].get("vendor_name") or r["intake"].get("domain") or "Unidentified vendor"


def business_check(r: dict) -> list[str]:
    """The handbook's question: is this a real, trading business, and since when?"""
    stab, ident = r.get("stability") or {}, r.get("identity") or {}
    if ident.get("status") != "resolved" or not stab.get("evidence"):
        return ["**Could not confirm.** There is no company record to check this against."]
    ev = cite(stab["evidence"])
    site = cite((r.get("coverage") or {}).get("site_evidence"))
    headcount, founded, status = stab.get("headcount"), stab.get("founded"), stab.get("status")
    reachable = (r.get("coverage") or {}).get("site_reachable")
    if r.get("closures"):
        verdict = "**Could not confirm.** The company record and press reports disagree."
    elif str(status).lower() == "active" and isinstance(headcount, (int, float)) and headcount >= 5 and reachable:
        verdict = "**Looks real and trading**, based on the evidence below."
    else:
        verdict = "**Could not confirm.** The evidence below is incomplete."
    staff = f"{int(headcount):,}" if isinstance(headcount, (int, float)) else "unknown"
    lines = [verdict]
    if founded:
        lines.append(f"- Founded {founded}, per the company record. {ev}")
    lines.append(f"- Record status: {status or 'unknown'}. Staff on record: {staff}. {ev}")
    if stab.get("openings") is not None:
        lines.append(f"- Open roles on record: {stab['openings']}. {ev}")
    lines.append(f"- Website {ident.get('domain')}: {'reachable' if reachable else 'could not be reached'}. {site}")
    return lines


def vendor_email(r: dict) -> str | None:
    """A draft for the buyer to send. The agent never sends it."""
    conditions = r["decision"]["conditions"]
    needs_docs = [c for c in conditions if c["rule"].startswith(("R4", "R5", "R6"))]
    if not needs_docs:
        return None
    name = _title(r)
    asks = []
    if any(c["rule"].startswith("R5") for c in needs_docs):
        asks.append("Your current SOC 2 Type II report or ISO 27001 certificate, under NDA if needed")
    if any(c["rule"].startswith("R4") for c in needs_docs):
        asks.append("Your post-incident report and the remediation completed for the incident(s) listed below")
    if any(c["rule"].startswith("R6") for c in needs_docs):
        asks.append("The legal entity that would sign our contract, and your data-return terms on exit")
    lines = [f"Subject: Security review information request: {name}", "", f"Hello {name} security team,", "",
             "We are completing a vendor security review and need the following to proceed:", ""]
    lines += [f"- {a}" for a in asks]
    incidents = [i for i in r.get("incidents", []) if i.get("date")][:3]
    if any(c["rule"].startswith("R4") for c in needs_docs) and incidents:
        lines += ["", "Incidents we found in public sources:"] + [f"- {i['date']}: {i['summary']}" for i in incidents]
    lines += ["", "Thank you."]
    return "\n".join(lines)


def to_markdown(r: dict) -> str:
    d = r["decision"]
    out = [f"# Vendor security assessment: {_title(r)}", "",
           f"**Decision: {d['outcome']}**", "",
           f"- Request: {r['request']}",
           f"- Reviewed: {r['reviewed_at']}",
           f"- Data sensitivity assumed: {r['sensitivity']}",
           f"- Citations verified: {r['audit']['verified']} of {r['audit']['total']}", ""]

    def section(title: str, rows: list[dict]) -> None:
        if rows:
            out.extend([f"## {title}", ""])
            out.extend(f"- {x['text']} {cite(x['evidence'])} *({x['rule']})*" for x in rows)
            out.append("")

    out.extend(["## Is it a real, trading business?", ""])
    out.extend(business_check(r))
    out.append("")

    if r.get("watch"):
        w = r["watch"]
        out.extend(["## Monitoring", ""])
        if w.get("status") in ("created", "existing"):
            out.append(f"- Crustdata watch #{w['watch_id']} is active for {r['identity'].get('domain')}: {w.get('tracks')}. Alerts go to {w.get('email')}.")
        else:
            out.append(f"- Not set up: {w.get('reason')}")
        out.append("")

    docs = [x for x in r.get("documents") or [] if x.get("readable")]
    if docs:
        out.extend(["## Documents from the vendor", ""])
        for x in docs:
            out.append(f"- **{x['filename']}**: {x['report_type']} for {x['organisation']}, auditor {x.get('auditor')}, "
                       f"period {x.get('period_start')} to {x.get('period_end') or x.get('valid_until')}, opinion {x['opinion']} {cite(x['evidence'])}")
            for key, q in x.get("verified", {}).items():
                out.append(f"  - {key}, page {q['page']}: \"{q['quote'][:220]}\" [{x['evidence'][0]}]")
        out.append("")

    section("Why", d["reasons"])
    section("Needs a person", d["referrals"])
    section("Conditions", d["conditions"])
    section("Notes", d["notes"])

    if not r["coverage"].get("search_evidence"):
        # With no searches behind it, silence would read as a clean record, so stop here.
        out.extend(["## Not checked", "", "No breach or certification search ran, so this report says nothing about either.", ""])
        if r["evidence"]:
            out.extend(["## Evidence", ""])
            out.extend(f"- **{e['id']}** ({e['kind']}) {e['title']} | {e['source']} | {e['retrieved_at']}" for e in r["evidence"])
        out.extend(["", "*Based on public information only. It does not replace a contractual security review.*"])
        return "\n".join(out)

    out.extend(["## Incidents", ""])
    if r["incidents"]:
        for i in r["incidents"]:
            fix = "remediation reported" if i.get("remediated") else "no remediation found"
            out.append(f"- **{i.get('date') or 'Date unknown'}**: {i['summary']} ({fix}) {cite(i['evidence'])}")
            out.extend(f"  - \"{q['quote']}\" [{q['evidence']}]" for q in i.get("quotes", []) if q.get("quote"))
    else:
        searched = cite(r["coverage"].get("search_evidence"))
        out.append(f"No public breach found in the sources searched. That does not prove there were none. {searched}")
    out.append("")

    out.extend(["## Certifications", ""])
    named = [c for c in r["certifications"] if c["framework"] != "OTHER"]
    if named:
        for c in named:
            out.append(f"- **{CERT_NAMES.get(c['framework'], c['framework'])}**: {STATUS.get(c['status'], c['status'])} {cite(c['evidence'])}")
            out.extend(f"  - \"{q['quote']}\" [{q['evidence']}]" for q in c.get("quotes", [])[:1])
    else:
        out.append(f"No certification statement found publicly. {cite(r['coverage'].get('search_evidence'))}")
    out.append("")

    for kind, title in (("leader", "Who runs it"), ("control", "Published controls"), ("posture", "Passive checks"), ("stability", "Company facts")):
        rows = [f for f in r["findings"] if f["kind"] == kind and f["verified"]]
        if kind == "control":
            grouped: dict[str, list[str]] = {}
            for f in rows:
                ids = grouped.setdefault(CONTROL_NAMES.get(f["claim"], f["claim"]), [])
                if f["evidence_id"] not in ids:
                    ids.append(f["evidence_id"])
            lines = [f"{name} {cite(ids)}" for name, ids in grouped.items()]
        elif kind == "leader":
            lines = [f"{f['value']}, {f['claim']} [{f['evidence_id']}], confirmed by web search [{f['attrs'].get('confirmed_by')}]" for f in rows]
        else:
            lines = [f"{f['claim']} [{f['evidence_id']}]" for f in rows]
        if lines:
            out.extend([f"## {title}", ""])
            out.extend(f"- {line}" for line in lines)
            out.append("")

    if r.get("vendor_email"):
        out.extend(["## Draft request to the vendor (not sent)", "", "```", r["vendor_email"], "```", ""])

    if r["coverage"].get("failed_urls"):
        out.extend(["## Pages that could not be read", ""])
        out.extend(f"- {u}" for u in r["coverage"]["failed_urls"])
        out.append("")

    out.extend(["## Evidence", ""])
    out.extend(f"- **{e['id']}** ({e['kind']}) {e['title']} | {e['source']} | {e['retrieved_at']}" for e in r["evidence"])
    out.extend(["", "*Based on public information only. It does not replace a contractual security review.*"])
    return "\n".join(out)


def _inline(text: str, ev_links: bool = True) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*\(([^*]+)\)\*", r'<span class="rule">(\1)</span>', text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*", r"<em>\1</em>", text)
    if ev_links:
        text = re.sub(r"\[(E\d+)\]", r'<a class="cite" href="#\1">\1</a>', text)
    # Sources open in a new tab, so anyone can check a claim against the live page.
    text = re.sub(r"(?<![\"'=])(https?://[^\s|<]+)", r'<a href="\1" target="_blank" rel="noopener">\1</a>', text)
    return text


def markdown_body(md: str) -> str:
    out, in_list, in_code = [], False, False
    for line in md.split("\n"):
        if line.startswith("```"):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        item = re.match(r"^(\s*)- (.*)$", line)
        if item:
            if not in_list:
                out.append("<ul>")
                in_list = True
            cls = ' class="quote"' if item.group(1) else ""
            body = _inline(item.group(2))
            ev = re.match(r"<strong>(E\d+)</strong>", body)
            anchor = f' id="{ev.group(1)}"' if ev else ""
            out.append(f"<li{cls}{anchor}>{body}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


REPORT_CSS = """
:root{--bg:#fff;--fg:#17181c;--mut:#62656e;--line:#e3e4e8;--accent:#2b4fd8;--ok:#116b3a;--warn:#8a5a00;--bad:#a81f1f;--ref:#5a3aa8}
@media (prefers-color-scheme:dark){:root{--bg:#121317;--fg:#ececef;--mut:#9a9da6;--line:#2b2d34;--accent:#8ea5ff;--ok:#5fd08f;--warn:#e5b45a;--bad:#ff8a8a;--ref:#bda6ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,system-ui,'Segoe UI',sans-serif}
.report{max-width:800px;margin:0 auto;padding:32px 16px}
h1{font-size:24px;margin:0 0 12px}h2{font-size:15px;margin:28px 0 8px;padding-top:14px;border-top:1px solid var(--line)}
ul{padding-left:18px;margin:6px 0}li{margin:4px 0;overflow-wrap:anywhere}li.quote{color:var(--mut);list-style:none;font-size:13.5px}
.rule{color:var(--mut);font-size:12.5px}.cite{font:12px ui-monospace,monospace;color:var(--accent);text-decoration:none}
pre{white-space:pre-wrap;background:color-mix(in srgb,var(--line) 35%,transparent);padding:12px;border-radius:6px;font-size:13px}
li:target{background:color-mix(in srgb,var(--accent) 16%,transparent)}
"""


def to_html(r: dict) -> str:
    return (f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(_title(r))} assessment</title><style>{REPORT_CSS}</style>"
            f"<div class=report>{markdown_body(to_markdown(r))}</div></html>")
