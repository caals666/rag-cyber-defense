"""Build the 4 project datasets (CVE, CWE, CAPEC, ATT&CK) as Neo4j-ready CSVs.

Columns follow the node schema in the PNNL-36792 paper (Section 2.0):
  CVE:    id, name, description, base_score, exploitability_score, impact_score, severity, related_cwe_ids
  CWE:    id, name, category, description, child_of_ids
  CAPEC:  id, name, category, description, likelihood, severity, mitigations, child_of_ids
  ATTACK: id, name, type, category, description
Extra columns (related_*_ids, can_precede_ids, mitigations, ...) carry the paper's relationships:
  CVE_CWE, CWE_CHILD, CWE_CAPEC, CAPEC_CHILD, CAN_PRECEDE, CAPEC_ATTACK

Sources:
  CVE    https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip
  CWE    https://cwe.mitre.org/data/csv/1000.csv.zip
  CAPEC  https://capec.mitre.org/data/csv/1000.csv.zip
  ATT&CK https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

Usage:
  python build_datasets.py <raw_dir>
  raw_dir must contain: nvdcve-2.0-2024.json, cwe/1000.csv, capec/1000.csv, enterprise-attack.json

List columns hold ';'-separated IDs.
"""
import csv
import json
import re
import sys
from pathlib import Path

RAW = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
OUT = Path(__file__).parent


def clean(text):
    # Neo4j LOAD CSV breaks on backslashes and embedded double quotes
    return " ".join(str(text or "").replace("\\", "/").replace('"', "'").split())


def write(name, header, rows):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"{name}: {len(rows)} rows")


def mitre_fields(value, key):
    # CWE/CAPEC pack lists as '::KEY:val:KEY:val::KEY:val::'
    out = []
    for chunk in value.split("::"):
        m = re.search(key + r":(.*?)(?::[A-Z ]+:|$)", chunk)
        if m:
            out.append(m.group(1))
    return out


def build_cve():
    data = json.load(open(RAW / "nvdcve-2.0-2024.json", encoding="utf-8"))
    rows = []
    for v in data["vulnerabilities"]:
        c = v["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
        score = sev = expl = imp = ""
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            items = c.get("metrics", {}).get(key) or []
            if items:
                m = next((x for x in items if x.get("type") == "Primary"), items[0])
                d = m["cvssData"]
                score = d.get("baseScore", "")
                sev = d.get("baseSeverity") or m.get("baseSeverity", "")
                expl, imp = m.get("exploitabilityScore", ""), m.get("impactScore", "")
                break
        cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w["description"]
                       if d["value"].startswith("CWE-")})
        rows.append([c["id"], clean(c.get("cisaVulnerabilityName", "")), clean(desc), score,
                     expl, imp, sev, c["published"][:10], ";".join(cwes)])
    write("cve_dataset.csv",
          ["id", "name", "description", "base_score", "exploitability_score", "impact_score",
           "severity", "published", "related_cwe_ids"], rows)


def build_cwe():
    rows = []
    for r in csv.DictReader(open(RAW / "cwe" / "1000.csv", encoding="utf-8")):
        parents = re.findall(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000", r["Related Weaknesses"])
        consequences = [f"{s}: {i}" for s, i in zip(mitre_fields(r["Common Consequences"], "SCOPE"),
                                                   mitre_fields(r["Common Consequences"], "IMPACT"))]
        capecs = [f"CAPEC-{x}" for x in r["Related Attack Patterns"].split("::") if x.strip().isdigit()]
        rows.append([f"CWE-{r['CWE-ID']}", clean(r["Name"]), r["Weakness Abstraction"],
                     clean(r["Description"]), r["Likelihood of Exploit"],
                     clean(" | ".join(consequences)),
                     clean(" | ".join(mitre_fields(r["Potential Mitigations"], "DESCRIPTION"))),
                     ";".join(f"CWE-{p}" for p in dict.fromkeys(parents)), ";".join(capecs)])
    write("cwe_dataset.csv",
          ["id", "name", "category", "description", "likelihood", "consequences", "mitigations",
           "child_of_ids", "related_capec_ids"], rows)


def build_capec():
    rows = []
    for r in csv.DictReader(open(RAW / "capec" / "1000.csv", encoding="utf-8")):
        if r["Status"] == "Deprecated":
            continue
        rel = r["Related Attack Patterns"]
        parents = re.findall(r"NATURE:ChildOf:CAPEC ID:(\d+)", rel)
        precedes = re.findall(r"NATURE:CanPrecede:CAPEC ID:(\d+)", rel)
        cwes = [f"CWE-{x}" for x in r["Related Weaknesses"].split("::") if x.strip().isdigit()]
        attack = [f"T{x}" for x in re.findall(r"TAXONOMY NAME:ATTACK:ENTRY ID:([\d.]+)", r["Taxonomy Mappings"])]
        mitigations = [m for m in r["Mitigations"].split("::") if m.strip()]
        rows.append([f"CAPEC-{r[chr(39) + 'ID']}", clean(r["Name"]), r["Abstraction"],
                     clean(r["Description"]), r["Likelihood Of Attack"], r["Typical Severity"],
                     clean(" | ".join(mitigations)),
                     ";".join(f"CAPEC-{p}" for p in parents), ";".join(f"CAPEC-{p}" for p in precedes),
                     ";".join(cwes), ";".join(attack)])
    write("capec_dataset.csv",
          ["id", "name", "category", "description", "likelihood", "severity", "mitigations",
           "child_of_ids", "can_precede_ids", "related_cwe_ids", "related_attack_ids"], rows)


def build_attack():
    objs = json.load(open(RAW / "enterprise-attack.json", encoding="utf-8"))["objects"]
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    by_ref = {o["id"]: o for o in objs if live(o)}
    mitigations = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "mitigates" and live(o):
            src = by_ref.get(o["source_ref"])
            if src and src["type"] == "course-of-action":
                mitigations.setdefault(o["target_ref"], []).append(src["name"])
    rows = []
    for o in by_ref.values():
        if o["type"] != "attack-pattern":
            continue
        ref = next((e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        kind = "sub-technique" if o.get("x_mitre_is_subtechnique") else "technique"
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
        rows.append([ref["external_id"], clean(o["name"]), kind, ";".join(tactics),
                     clean(o.get("description", "")), ";".join(o.get("x_mitre_platforms", [])),
                     clean(" | ".join(sorted(set(mitigations.get(o["id"], []))))), ref.get("url", "")])
    rows.sort(key=lambda r: r[0])
    write("attack_dataset.csv",
          ["id", "name", "type", "category", "description", "platforms", "mitigations", "url"], rows)


if __name__ == "__main__":
    build_cve()
    build_cwe()
    build_capec()
    build_attack()
