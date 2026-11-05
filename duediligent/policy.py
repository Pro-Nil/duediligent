"""The rulebook. Decisions come from these rules, never from the model."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date

APPROVE = "APPROVE"
CONDITIONS = "APPROVE WITH CONDITIONS"
REJECT = "REJECT"
REFER = "REFER TO HUMAN"

STRONG_CERTS = {"SOC2_TYPE2", "SOC2", "ISO27001"}


@dataclass
class Reason:
    rule: str
    text: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Decision:
    outcome: str
    reasons: list[Reason] = field(default_factory=list)
    conditions: list[Reason] = field(default_factory=list)
    referrals: list[Reason] = field(default_factory=list)
    notes: list[Reason] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def months_since(yyyy_mm: str | None, today: date) -> int | None:
    if not yyyy_mm:
        return None
    try:
        parts = yyyy_mm.split("-")
        year, month = int(parts[0]), int(parts[1]) if len(parts) > 1 else 6
    except (ValueError, IndexError):
        return None
    return (today.year - year) * 12 + today.month - month


def evaluate(ctx: dict, today: date | None = None) -> Decision:
    """ctx: identity, sensitivity, incidents, certifications, stability, coverage."""
    today = today or date.today()
    d = Decision(outcome=APPROVE)
    identity = ctx.get("identity") or {}
    cov = ctx.get("coverage") or {}
    stab = ctx.get("stability") or {}
    search_ev = cov.get("search_evidence") or []
    sensitivity = ctx.get("sensitivity") or "medium"

    # R1: never review a company we cannot pin down.
    if identity.get("status") != "resolved":
        d.referrals.append(Reason("R1 identity", identity.get("detail") or "Could not establish which company this is.", identity.get("evidence") or []))
        d.outcome = REFER
        return d
    if identity.get("assumed"):
        d.conditions.append(Reason("R1 identity", f"Confirm you meant {identity.get('name')} ({identity.get('domain')}). The request said \"{identity.get('input')}\".", identity.get("evidence") or []))

    # R2: a closed company is a rejection; a dead site alone is an exception for a person.
    if stab.get("closed"):
        d.reasons.append(Reason("R2 viability", stab.get("closed_detail") or "The company appears to have stopped operating.", stab.get("evidence") or []))
        d.outcome = REJECT
        return d
    if cov.get("site_reachable") is False:
        d.referrals.append(Reason("R2 viability", f"The vendor's website {identity.get('domain')} could not be reached, so its current status is unclear.", cov.get("site_evidence") or []))
        d.outcome = REFER
        return d

    # R3: without enough evidence the only honest answer is to ask a person.
    if not cov.get("searches_ok"):
        d.referrals.append(Reason("R3 coverage", "Breach and certification searches failed, so the review would rest on missing data.", search_ev))
        d.outcome = REFER
        return d
    if cov.get("extraction_failed"):
        d.referrals.append(Reason("R3 coverage", "Evidence was collected but could not be analysed reliably.", search_ev))
        d.outcome = REFER
        return d

    # R4: incidents, using the vendor's own response as the deciding factor.
    rejected = False
    incidents = ctx.get("incidents") or []
    for inc in incidents:
        age = months_since(inc.get("date"), today)
        ev = inc.get("evidence") or []
        when = inc.get("date") or "an unknown date"
        label = f"{inc.get('summary')} ({when})"
        if age is None:
            d.conditions.append(Reason("R4 incident", f"Confirm the date and remediation of this incident: {label}.", ev))
        elif age <= 24 and not inc.get("remediated") and inc.get("role") == "breached_vendor":
            d.reasons.append(Reason("R4 incident", f"Breach within 24 months with no public remediation found: {label}.", ev))
            rejected = True
        elif age <= 36:
            d.conditions.append(Reason("R4 incident", f"Review the remediation evidence for this recent incident: {label}.", ev))
        elif age <= 60 and sensitivity == "high":
            d.conditions.append(Reason("R4 incident", f"This workload is sensitive, so ask how this older incident was resolved: {label}.", ev))
        else:
            d.notes.append(Reason("R4 incident", f"Older incident on record: {label}.", ev))

    # R5: certifications. A claim is not proof, so sensitive data needs the report itself.
    certs = ctx.get("certifications") or []
    current = [c for c in certs if c.get("status") == "current_claim" and c.get("framework") in STRONG_CERTS]
    if current:
        names = ", ".join(sorted({c["framework"] for c in current}))
        ev = sorted({e for c in current for e in c.get("evidence", [])})
        d.notes.append(Reason("R5 certification", f"The vendor publicly claims: {names}. This review saw the claim, not the audit report.", ev))
        if sensitivity == "high":
            d.conditions.append(Reason("R5 certification", f"Obtain and review the current {names} report before sending sensitive data.", ev))
    else:
        partial = [c for c in certs if c.get("status") == "in_progress"]
        ev = sorted({e for c in partial for e in c.get("evidence", [])}) or search_ev
        if sensitivity != "low":
            d.conditions.append(Reason("R5 certification", "No current SOC 2 or ISO 27001 claim was found publicly. Obtain a report or complete a security questionnaire before sharing data.", ev))
        else:
            d.notes.append(Reason("R5 certification", "No current SOC 2 or ISO 27001 claim was found publicly.", ev))

    # R6: company stability.
    if stab.get("acquired"):
        ev = stab.get("evidence") or []
        d.conditions.append(Reason("R6 stability", f"Confirm which legal entity will sign the contract: the record shows acquisition status \"{stab.get('acquired')}\".", ev))
    shrink = stab.get("headcount_yoy")
    if isinstance(shrink, (int, float)) and shrink <= -25:
        d.conditions.append(Reason("R6 stability", f"Headcount fell {abs(shrink):.0f}% in a year. Agree exit and data-return terms.", stab.get("evidence") or []))

    # R8: anything that looks off about the business itself.
    for flag in stab.get("flags") or []:
        d.conditions.append(Reason("R8 red flag", flag["text"], flag.get("evidence") or []))

    if rejected:
        d.outcome = REJECT
    elif d.conditions:
        d.outcome = CONDITIONS
        d.reasons.append(Reason("R7 outcome", f"{len(d.conditions)} condition(s) must be met before use.", []))
    else:
        d.outcome = APPROVE
        d.reasons.append(Reason("R7 outcome", "No rule raised a blocking issue or condition for this level of data sensitivity.", search_ev))
    return d
