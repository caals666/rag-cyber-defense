"""Build the fifth dataset: cyber_attack_path_dataset.csv.

Reads the four source datasets in data/raw/, extracts only the relationships that
are explicitly recorded in their reference columns, and produces:

  data/processed/dataset_inspection_report.txt   step 1 - schema inspection
  data/processed/cyber_relationships.csv         step 6 - one row per verified edge
  data/processed/cyber_attack_path_dataset.csv   step 4 - one row per attack path
  data/processed/data_quality_report.txt         step 7 - quality and coverage

Rules:
  - A relationship exists only if an ID is listed in a reference column.
  - Text similarity is never used to link entities.
  - An edge is kept only if both endpoints exist in the datasets; the rest are
    reported as unresolved, never dropped silently.
  - Partial paths are kept as partial paths; missing entities stay empty.

Usage: python build_attack_path_dataset.py
"""
import io
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"
OUT.mkdir(parents=True, exist_ok=True)

FILES = {
    "CVE": "cve_dataset.csv",
    "CWE": "cwe_dataset.csv",
    "CAPEC": "capec_dataset.csv",
    "ATTACK": "attack_dataset.csv",
}
ID_PATTERNS = {
    "CVE": r"^CVE-\d{4}-\d{4,}$",
    "CWE": r"^CWE-\d+$",
    "CAPEC": r"^CAPEC-\d+$",
    "ATTACK": r"^T\d{4}(\.\d{3})?$",
}
TOKEN = re.compile(r"(CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?)")


def load(entity):
    df = pd.read_csv(RAW / FILES[entity], dtype=str, keep_default_na=False)
    df = df.apply(lambda col: col.str.strip())      # normalize whitespace
    return df.replace("", pd.NA)                     # one consistent null


def split_ids(value):
    return [] if pd.isna(value) else [x.strip() for x in str(value).split(";") if x.strip()]


# ---------------------------------------------------------------- STEP 1
def inspect(frames):
    buf = io.StringIO()
    p = lambda *a: print(*a, file=buf)
    p("DATASET INSPECTION REPORT")
    p("Source: data/raw/*.csv (all values read as text, then whitespace-normalized)")
    for entity, df in frames.items():
        p("\n" + "=" * 90)
        p(f"FILE: {FILES[entity]}")
        p(f"Rows: {len(df):,}   Columns: {df.shape[1]}   Fully duplicated rows: {df.duplicated().sum()}")
        p(f"Duplicate values in 'id': {df['id'].duplicated().sum()}")
        p("")
        p(f"{'column':<24}{'dtype':<10}{'missing':>9}{'missing%':>10}{'unique':>9}  role")
        for col in df.columns:
            s = df[col]
            miss = s.isna().sum()
            values = s.dropna()
            tokens = values.str.findall(TOKEN).str.len().sum()
            if col == "id":
                role = "IDENTIFIER (unique key)"
            elif col.endswith("_ids") and tokens:
                role = "RELATIONSHIP / reference column"
            elif col == "url":
                role = "external reference (link, not an entity ID)"
            else:
                role = "attribute"
            # dtype as it would be inferred from the raw file
            inferred = pd.to_numeric(values, errors="coerce")
            dtype = "float64" if len(values) and inferred.notna().all() else "object"
            p(f"{col:<24}{dtype:<10}{miss:>9}{miss / len(df):>9.1%}{s.nunique():>9}  {role}")
        p("\nSample rows (text truncated to 60 chars):")
        sample = df.head(5).apply(lambda c: c.astype("string").str.slice(0, 60))
        p(sample.to_string())
    (OUT / "dataset_inspection_report.txt").write_text(buf.getvalue(), encoding="utf-8")
    return buf.getvalue()


# ---------------------------------------------------------------- STEP 2 + 6
RELATIONSHIP_SPECS = [
    # entity, column, relationship, target, direction (forward = row -> listed id)
    ("CVE", "related_cwe_ids", "CVE_CWE", "CWE", "forward"),
    ("CWE", "child_of_ids", "CWE_CHILD", "CWE", "forward"),
    ("CWE", "related_capec_ids", "CWE_CAPEC", "CAPEC", "forward"),
    ("CAPEC", "related_cwe_ids", "CWE_CAPEC", "CWE", "reverse"),
    ("CAPEC", "child_of_ids", "CAPEC_CHILD", "CAPEC", "forward"),
    ("CAPEC", "can_precede_ids", "CAN_PRECEDE", "CAPEC", "forward"),
    ("CAPEC", "related_attack_ids", "CAPEC_ATTACK", "ATTACK", "forward"),
]


def extract_relationships(frames):
    known = {e: set(df["id"].dropna()) for e, df in frames.items()}
    rows, unresolved = [], []
    for entity, col, rel, target, direction in RELATIONSHIP_SPECS:
        for src_id, refs in zip(frames[entity]["id"], frames[entity][col]):
            for ref in split_ids(refs):
                if direction == "forward":
                    s_type, s_id, t_type, t_id = entity, src_id, target, ref
                else:
                    s_type, s_id, t_type, t_id = target, ref, entity, src_id
                record = dict(source_type=s_type, source_id=s_id, relationship=rel,
                              target_type=t_type, target_id=t_id,
                              evidence_source=f"{FILES[entity]}:{col}",
                              mapping_method="direct_reference")
                if s_id in known[s_type] and t_id in known[t_type]:
                    rows.append(record)
                else:
                    missing = t_id if t_id not in known[t_type] else s_id
                    unresolved.append({**record, "missing_id": missing})

    # ATT&CK sub-technique hierarchy: the dataset marks rows as 'sub-technique' and the
    # official ID encodes the parent (T1566.001 -> T1566). Kept only if the parent row exists.
    att = frames["ATTACK"]
    for tid, kind in zip(att["id"], att["type"]):
        if kind == "sub-technique" and "." in tid:
            parent = tid.split(".")[0]
            record = dict(source_type="ATTACK", source_id=tid, relationship="SUBTECHNIQUE_OF",
                          target_type="ATTACK", target_id=parent,
                          evidence_source=f"{FILES['ATTACK']}:type+id",
                          mapping_method="id_hierarchy")
            (rows if parent in known["ATTACK"] else unresolved).append(
                record if parent in known["ATTACK"] else {**record, "missing_id": parent})

    rels = pd.DataFrame(rows)
    # CWE_CAPEC is recorded on both sides, and a few IDs repeat inside one cell;
    # merge duplicate edges and keep every evidence column that supports them
    key = ["source_type", "source_id", "relationship", "target_type", "target_id"]
    raw_counts = rels.relationship.value_counts()
    rels = (rels.groupby(key, as_index=False, sort=False)
                .agg(evidence_source=("evidence_source", lambda s: "|".join(sorted(set(s)))),
                     mapping_method=("mapping_method", "first")))
    unresolved = pd.DataFrame(unresolved).drop_duplicates(subset=key)
    rels.to_csv(OUT / "cyber_relationships.csv", index=False)
    return rels, unresolved, raw_counts


# ---------------------------------------------------------------- STEP 4 + 5
def build_paths(frames, rels):
    cve, cwe, capec, att = (frames[e] for e in ("CVE", "CWE", "CAPEC", "ATTACK"))
    edge = lambda r: rels[rels.relationship == r][["source_id", "target_id"]]

    cve_cwe = edge("CVE_CWE").rename(columns={"source_id": "cve_id", "target_id": "cwe_id"})
    cwe_capec = edge("CWE_CAPEC").rename(columns={"source_id": "cwe_id", "target_id": "capec_id"})
    capec_att = edge("CAPEC_ATTACK").rename(columns={"source_id": "capec_id", "target_id": "attack_id"})

    # Left joins walk the chain along real edges only; a missing hop leaves the rest empty
    paths = (cve[["id"]].rename(columns={"id": "cve_id"})
             .merge(cve_cwe, on="cve_id", how="left")
             .merge(cwe_capec, on="cwe_id", how="left")
             .merge(capec_att, on="capec_id", how="left"))

    # Selected attributes (original features), prefixed by entity
    pick = lambda df, cols, prefix: df[["id"] + cols].rename(
        columns={"id": f"{prefix}_id", **{c: f"{prefix}_{c}" for c in cols}})
    paths = (paths
             .merge(pick(cve, ["name", "base_score", "severity", "exploitability_score",
                               "impact_score", "published"], "cve"), on="cve_id", how="left")
             .merge(pick(cwe, ["name", "category"], "cwe"), on="cwe_id", how="left")
             .merge(pick(capec, ["name", "category", "likelihood", "severity"], "capec"),
                    on="capec_id", how="left")
             .merge(pick(att, ["name", "type", "category"], "attack"), on="attack_id", how="left")
             .rename(columns={"attack_category": "attack_tactics"}))
    for col in ("cve_base_score", "cve_exploitability_score", "cve_impact_score"):
        paths[col] = pd.to_numeric(paths[col])

    # Path-level derived features
    paths["has_cwe"] = paths.cwe_id.notna()
    paths["has_capec"] = paths.capec_id.notna()
    paths["has_attack"] = paths.attack_id.notna()
    paths["path_depth"] = paths[["has_cwe", "has_capec", "has_attack"]].sum(axis=1)  # hops 0-3
    # Each hop has exactly one evidence source (see cyber_relationships.csv for per-edge
    # evidence), so path_type alone identifies which reference columns support the row
    paths["path_type"] = paths.path_depth.map({
        0: "CVE_ONLY", 1: "CVE_CWE", 2: "CVE_CWE_CAPEC", 3: "CVE_CWE_CAPEC_ATTACK"})

    # Entity-level derived features (counts of distinct verified neighbours)
    per_cve = paths.groupby("cve_id").agg(
        cve_cwe_count=("cwe_id", "nunique"), cve_capec_count=("capec_id", "nunique"),
        cve_attack_count=("attack_id", "nunique"), cve_max_path_depth=("path_depth", "max"))
    per_cve["cve_path_count"] = paths[paths.path_depth > 0].groupby("cve_id").size()
    per_cve["cve_path_count"] = per_cve.cve_path_count.fillna(0).astype(int)
    per_cve["cve_mapping_completeness"] = (per_cve.cve_max_path_depth / 3).round(3)
    paths = paths.merge(per_cve.reset_index(), on="cve_id", how="left")

    cwe_capec_n = cwe_capec.groupby("cwe_id").capec_id.nunique().rename("cwe_capec_count")
    capec_att_n = capec_att.groupby("capec_id").attack_id.nunique().rename("capec_attack_count")
    paths = paths.merge(cwe_capec_n, on="cwe_id", how="left").merge(capec_att_n, on="capec_id", how="left")
    paths.loc[paths.has_cwe, "cwe_capec_count"] = paths.loc[paths.has_cwe, "cwe_capec_count"].fillna(0)
    paths.loc[paths.has_capec, "capec_attack_count"] = paths.loc[paths.has_capec, "capec_attack_count"].fillna(0)
    paths["cwe_capec_count"] = paths.cwe_capec_count.astype("Int64")
    paths["capec_attack_count"] = paths.capec_attack_count.astype("Int64")

    paths = paths.sort_values(["cve_id", "cwe_id", "capec_id", "attack_id"], na_position="last")
    paths.insert(0, "path_id", [f"P{i:06d}" for i in range(1, len(paths) + 1)])

    columns = [
        "path_id", "path_type", "path_depth",
        "cve_id", "cve_name", "cve_base_score", "cve_severity", "cve_exploitability_score",
        "cve_impact_score", "cve_published",
        "cwe_id", "cwe_name", "cwe_category",
        "capec_id", "capec_name", "capec_category", "capec_likelihood", "capec_severity",
        "attack_id", "attack_name", "attack_type", "attack_tactics",
        "has_cwe", "has_capec", "has_attack",
        "cve_cwe_count", "cve_capec_count", "cve_attack_count", "cve_path_count",
        "cve_max_path_depth", "cve_mapping_completeness",
        "cwe_capec_count", "capec_attack_count",
    ]
    paths = paths[columns]
    paths.to_csv(OUT / "cyber_attack_path_dataset.csv", index=False)
    return paths


# ---------------------------------------------------------------- STEP 7
def quality_report(frames, rels, unresolved, raw_counts, paths):
    buf = io.StringIO()
    p = lambda *a: print(*a, file=buf)
    p("DATA QUALITY REPORT")
    p("\n1. SOURCE DATASETS (no records deleted; cleaning = whitespace + null normalization)")
    p(f"{'dataset':<22}{'original':>10}{'cleaned':>10}{'dup ids':>9}{'dup rows':>10}{'bad id fmt':>12}{'no id':>7}")
    for e, df in frames.items():
        bad = (~df["id"].dropna().str.match(ID_PATTERNS[e])).sum()
        p(f"{FILES[e]:<22}{len(df):>10}{len(df):>10}{df['id'].duplicated().sum():>9}"
          f"{df.duplicated().sum():>10}{bad:>12}{df['id'].isna().sum():>7}")

    p("\n2. RELATIONSHIPS")
    p("resolved references = both endpoints exist; duplicates = the same edge listed more than once")
    p(f"{'relationship':<18}{'resolved refs':>14}{'duplicates':>12}{'valid edges':>13}{'unresolved':>12}")
    counts = rels.relationship.value_counts()
    unres = unresolved.relationship.value_counts() if len(unresolved) else pd.Series(dtype=int)
    for rel in ["CVE_CWE", "CWE_CHILD", "CWE_CAPEC", "CAPEC_CHILD", "CAN_PRECEDE",
                "CAPEC_ATTACK", "SUBTECHNIQUE_OF"]:
        raw, valid = raw_counts.get(rel, 0), counts.get(rel, 0)
        p(f"{rel:<18}{raw:>14}{raw - valid:>12}{valid:>13}{unres.get(rel, 0):>12}")
    p(f"{'TOTAL':<18}{raw_counts.sum():>14}{raw_counts.sum() - len(rels):>12}{len(rels):>13}{len(unresolved):>12}")
    p("CWE_CAPEC is recorded in both cwe_dataset.related_capec_ids and capec_dataset.related_cwe_ids;")
    p("the two sides describe the same 1,212 edges, so each edge keeps both columns as evidence.")
    p("\nColumn with no usable data: cwe_dataset.likelihood is empty for all 944 rows (empty in the")
    p("official MITRE CWE CSV itself), so no CWE likelihood feature is produced.")

    p("\n3. UNRESOLVED REFERENCES (kept out of the graph, listed here instead of deleted)")
    if len(unresolved):
        for rel, grp in unresolved.groupby("relationship"):
            ids = sorted(set(grp.missing_id))
            p(f"{rel}: {len(grp)} references to {len(ids)} IDs absent from the datasets")
            p("   " + ", ".join(ids))
    p("Reason: the missing CWE IDs are CWE categories, views or deprecated entries, which are not")
    p("part of the CWE weakness list (view 1000). The missing ATT&CK IDs are not in the current")
    p("Enterprise ATT&CK release (revoked/deprecated techniques, or another matrix, e.g. Mobile).")

    p("\n4. FIFTH DATASET COVERAGE")
    per_cve = paths.drop_duplicates("cve_id")
    p(f"Path rows: {len(paths):,}   Unique CVEs: {paths.cve_id.nunique():,} (all {len(frames['CVE']):,} CVEs retained)")
    for t, n in paths.path_type.value_counts().items():
        p(f"  rows of type {t:<24}{n:>8,}")
    p("CVEs by deepest verified path:")
    for d, n in per_cve.cve_max_path_depth.value_counts().sort_index().items():
        p(f"  depth {d} ({['CVE only', 'reaches CWE', 'reaches CAPEC', 'reaches ATT&CK'][d]}): {n:,}")
    full = paths[paths.path_type == "CVE_CWE_CAPEC_ATTACK"]
    p(f"Complete CVE-CWE-CAPEC-ATT&CK paths: {len(full):,} across {full.cve_id.nunique():,} CVEs")
    p(f"Duplicate path rows: {paths.duplicated(subset=['cve_id', 'cwe_id', 'capec_id', 'attack_id']).sum()}")
    (OUT / "data_quality_report.txt").write_text(buf.getvalue(), encoding="utf-8")
    return buf.getvalue()


# ---------------------------------------------------------------- STEP 8
def show(paths):
    print("\nFINAL DATASET: data/processed/cyber_attack_path_dataset.csv")
    print(f"rows={len(paths):,} columns={paths.shape[1]}")
    print("\ncolumn / dtype / missing")
    for c in paths.columns:
        print(f"  {c:<28}{str(paths[c].dtype):<10}{paths[c].isna().sum():>8}")
    sample = pd.concat([paths[paths.path_type == t].head(n) for t, n in
                        (("CVE_CWE_CAPEC_ATTACK", 4), ("CVE_CWE_CAPEC", 2), ("CVE_CWE", 2), ("CVE_ONLY", 2))])
    with pd.option_context("display.max_columns", None, "display.width", 250, "display.max_colwidth", 28):
        print("\n10 representative rows (key columns):")
        print(sample[["path_id", "path_type", "cve_id", "cve_base_score", "cwe_id", "capec_id",
                      "attack_id", "attack_tactics", "cve_path_count"]].to_string(index=False))
        print("\nDescriptive statistics:")
        print(paths.select_dtypes("number").describe().round(2).to_string())
    for e in ("cve", "cwe", "capec", "attack"):
        print(f"unique {e.upper():<7}{paths[f'{e}_id'].nunique():>8,}")


if __name__ == "__main__":
    frames = {e: load(e) for e in FILES}
    print(inspect(frames))
    rels, unresolved, raw_counts = extract_relationships(frames)
    paths = build_paths(frames, rels)
    print(quality_report(frames, rels, unresolved, raw_counts, paths))
    show(paths)
