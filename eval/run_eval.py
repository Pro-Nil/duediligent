"""Run the test set and score it against the targets set in the application.

Usage: python eval/run_eval.py [--only messy] [--workers 3]
Labels come from public records and the vendors' own trust pages, fixed before the run.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from duediligent import policy  # noqa: E402
from duediligent.agent import review  # noqa: E402
from duediligent.config import load_env  # noqa: E402
from duediligent.crust import Crust  # noqa: E402
from duediligent.llm import LLM  # noqa: E402


def score(case: dict, r: dict) -> tuple[bool, str]:
    outcome = r["decision"]["outcome"]
    audit_ok = r["audit"]["verified"] == r["audit"]["total"]
    identity = r["identity"]
    if not audit_ok:
        return False, f"citation audit failed: {r['audit']['problems'][:2]}"
    if case["group"] == "breach":
        if identity.get("status") != "resolved":
            return False, f"not identified: {identity.get('detail')}"
        years = {int(str(i["date"])[:4]) for i in r["incidents"] if i.get("date") and str(i["date"])[:4].isdigit()}
        return bool(years & set(case["breach_years"])), f"flagged years {sorted(years)}, expected any of {case['breach_years']}; {outcome}"
    if case["group"] == "cert":
        if identity.get("status") != "resolved":
            return False, f"not identified: {identity.get('detail')}"
        claimed = {c["framework"] for c in r["certifications"] if c["status"] == "current_claim"}
        if "SOC2_TYPE2" in claimed:
            claimed.add("SOC2")
        missing = set(case["certs"]) - claimed
        return not missing, f"claimed {sorted(claimed)}; missing {sorted(missing)}; {outcome}"
    kind = case["kind"]
    if kind == "typo":
        ok = identity.get("name") == case["name"] and identity.get("assumed") is True and outcome != policy.APPROVE
        return ok, f"read as {identity.get('name')}, assumed={identity.get('assumed')}; {outcome}"
    if kind == "refer":
        return outcome == policy.REFER, outcome
    return outcome in (policy.REFER, policy.REJECT), outcome


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only")
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    load_env()
    cases = json.loads((ROOT / "eval" / "cases.json").read_text(encoding="utf-8"))
    if args.only:
        cases = [c for c in cases if c["group"] == args.only or c["id"] == args.only]
    crust, llm = Crust(), LLM()
    out_dir = ROOT / "eval" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    def run(case: dict) -> dict:
        started = time.time()
        try:
            r = review(case["request"], crust=crust, llm=llm)
            ok, detail = score(case, r)
            (out_dir / f"{case['id']}.json").write_text(json.dumps(r, indent=1, default=str), encoding="utf-8")
            row = {"id": case["id"], "group": case["group"], "pass": ok, "outcome": r["decision"]["outcome"], "detail": detail,
                   "citations": f"{r['audit']['verified']}/{r['audit']['total']}", "rejected_quotes": r["rejected_findings"],
                   "seconds": round(time.time() - started)}
        except Exception as exc:  # noqa: BLE001 - one crash must not lose the other results
            row = {"id": case["id"], "group": case["group"], "pass": False, "outcome": "CRASH",
                   "detail": f"{type(exc).__name__}: {exc}", "citations": "0/0", "rejected_quotes": 0, "seconds": round(time.time() - started)}
        print(f"{'PASS' if row['pass'] else 'FAIL'} {row['id']:<20} {row['outcome']:<25} {row['citations']:<9} {row['seconds']:>4}s  {row['detail']}", flush=True)
        return row

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(run, cases))
    passed = sum(r["pass"] for r in rows)
    print(f"\n{passed} of {len(rows)} passed")
    for group in ("breach", "cert", "messy"):
        sub = [r for r in rows if r["group"] == group]
        if sub:
            print(f"  {group}: {sum(r['pass'] for r in sub)} of {len(sub)}")
    (out_dir / "summary.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
