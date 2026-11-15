"""Compute the Insights page numbers from Neo4j and CISA's Known Exploited Vulnerabilities list.

Run from backend/:  python -m analytics.build
Writes frontend/data/analytics.json (the page reads this static file, so it costs no API calls).

Fix-first score, 0 to 100, for every CVE:
    danger  = CVSS base score / 10                     how bad it is
    ease    = exploitability score / 3.9               how easy it is to attack (3.9 is the maximum)
    reach   = ATT&CK techniques reachable / 10, max 1  how far an attacker can go through the graph
    score   = 100 x danger x ease x (0.5 + 0.5 x reach)
Reach can raise the score by up to 2x but never zero it, because many CVEs have no CAPEC link yet.

Validation: CISA KEV lists bugs attackers really used. If the score is useful, KEV bugs should be
near the top of its ranking, more than when ranking by CVSS alone or at random.
"""
import json
import time
import urllib.request
from pathlib import Path

from eval import tls  # noqa: F401
from graph.connection import run

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "frontend" / "data" / "analytics.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CUTOFFS = [50, 100, 250, 500, 1000]


def kev():
    with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
        data = json.load(resp)
    return data["catalogVersion"], {v["cveID"]: v for v in data["vulnerabilities"]}


def overview():
    labels = {r["label"]: r["n"] for r in run(
        "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n")}
    links = run("MATCH ()-[r]->() RETURN count(r) AS n")[0]["n"]
    funnel = run("""
        MATCH (c:CVE)
        RETURN count(c) AS all,
               sum(CASE WHEN EXISTS { (c)-[:CVE_CWE]->() } THEN 1 ELSE 0 END) AS cwe,
               sum(CASE WHEN EXISTS { (c)-[:CVE_CWE]->()-[:CWE_CAPEC]->() } THEN 1 ELSE 0 END) AS capec,
               sum(CASE WHEN EXISTS { (c)-[:CVE_CWE]->()-[:CWE_CAPEC]->()-[:CAPEC_ATTACK]->() }
                        THEN 1 ELSE 0 END) AS attack
    """)[0]
    return labels, links, funnel


def charts():
    severity = run("""MATCH (c:CVE) RETURN coalesce(c.severity, 'NONE') AS severity, count(*) AS n""")
    monthly = run("""MATCH (c:CVE) WHERE c.published IS NOT NULL
                     RETURN substring(toString(c.published), 0, 7) AS month, count(*) AS n ORDER BY month""")
    top_cwes = run("""MATCH (w:CWE)<-[:CVE_CWE]-(c:CVE)
                      RETURN w.id AS id, w.name AS name, count(c) AS n, round(avg(c.base_score), 1) AS avg_score
                      ORDER BY n DESC LIMIT 10""")
    tactics = run("""MATCH (c:CVE)-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
                     UNWIND t.category AS tactic
                     RETURN tactic, count(DISTINCT c) AS n ORDER BY n DESC LIMIT 10""")
    return severity, [m for m in monthly if m["month"].startswith("2024")], top_cwes, tactics


def fix_first(kev_ids):
    rows = run("""MATCH (c:CVE) WHERE c.base_score IS NOT NULL AND c.exploitability_score IS NOT NULL
                  OPTIONAL MATCH (c)-[:CVE_CWE]->(:CWE)-[:CWE_CAPEC]->(:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK)
                  RETURN c.id AS id, left(coalesce(c.name, c.description), 110) AS name,
                         c.severity AS severity, c.base_score AS base,
                         c.exploitability_score AS expl, count(DISTINCT t) AS reach""")
    for r in rows:
        reach = min(r["reach"], 10) / 10
        r["score"] = round(100 * (r["base"] / 10) * min(r["expl"] / 3.9, 1) * (0.5 + 0.5 * reach), 1)
        r["kev"] = r["id"] in kev_ids

    def hits(ranked):
        return {k: sum(r["kev"] for r in ranked[:k]) for k in CUTOFFS}

    total = len(rows)
    in_kev = sum(r["kev"] for r in rows)
    # Ties are broken by ID so each ranking is reproducible
    by_score = sorted(rows, key=lambda r: (-r["score"], r["id"]))
    by_cvss = sorted(rows, key=lambda r: (-r["base"], r["id"]))
    validation = {
        "scored_cves": total,
        "kev_in_data": in_kev,
        "fix_first": hits(by_score),
        "cvss_only": hits(by_cvss),
        "random": {k: round(in_kev * k / total, 1) for k in CUTOFFS},
    }
    for rank, r in enumerate(by_score, 1):
        r["rank"] = rank
    exploited = [r for r in by_score if r["kev"]][:8]
    return by_score[:15], exploited, validation


def main():
    version, kev_map = kev()
    labels, links, funnel = overview()
    severity, monthly, top_cwes, tactics = charts()
    top, exploited, validation = fix_first(set(kev_map))
    for r in top + exploited:
        entry = kev_map.get(r["id"])
        r["ransomware"] = bool(entry and entry.get("knownRansomwareCampaignUse") == "Known")
        r["vendor"] = f'{entry["vendorProject"]} {entry["product"]}' if entry else None
    validation["ransomware_in_data"] = sum(
        1 for cve, v in kev_map.items() if cve.startswith("CVE-2024-") and v.get("knownRansomwareCampaignUse") == "Known")
    report = {
        "built_at": time.strftime("%Y-%m-%d %H:%M"),
        "kev_version": version,
        "nodes": labels,
        "links": links,
        "funnel": funnel,
        "severity": severity,
        "monthly": monthly,
        "top_cwes": top_cwes,
        "tactics": tactics,
        "fix_first": top,
        "exploited": exploited,
        "validation": validation,
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("nodes", "links", "funnel", "validation")}, indent=2))


if __name__ == "__main__":
    main()
