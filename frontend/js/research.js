// The Research page: GraphRAG vs the same AI without the graph, from data/eval-results.json
// (built by backend/eval/run_eval.py).
import { escapeHtml } from "./api.js";
import { startBackdrop } from "./backdrop.js";
import { renderNav, reveal, splitWords } from "./layout.js";

const SYSTEMS = [
  { key: "graphrag", label: "GraphRAG (ours)", color: "#4f46e5" },
  { key: "plain_llm", label: "Same LLM, no graph", color: "#f59e0b" },
];
const TYPES = {
  severity: "Severity + CVSS score of a CVE",
  cve_to_cwe: "Weakness (CWE) behind a CVE",
  cwe_to_capec: "Attack patterns (CAPEC) for a CWE",
  capec_to_attack: "ATT&CK techniques for a CAPEC",
  cve_count: "Number of CVEs linked to a CWE",
};
const pct = (x) => `${Math.round(x * 100)}%`;
const truthText = (row) => (row.type === "severity" ? `${row.truth.severity}, ${row.truth.base_score}`
  : Array.isArray(row.truth) ? row.truth.join(", ") : String(row.truth));

function render(report) {
  const rag = report.summary.graphrag, plain = report.summary.plain_llm;
  const examples = report.rows.filter((r) => r.graphrag.accuracy > r.plain_llm.accuracy).slice(0, 6);
  const tile = (label, value, count, suffix, small) =>
    `<div class="tile" data-reveal><span>${label}</span><b${count != null ? ` data-count="${count}" data-suffix="${suffix}"` : ""}>${value}</b><small>${small}</small></div>`;

  document.getElementById("content").innerHTML = `
    <section class="tiles">
      ${tile("Accuracy", pct(rag.accuracy), Math.round(rag.accuracy * 100), "%", `vs ${pct(plain.accuracy)} without the graph`)}
      ${tile("Hallucinated IDs", pct(rag.hallucination_rate), Math.round(rag.hallucination_rate * 100), "%", `vs ${pct(plain.hallucination_rate)} without the graph`)}
      ${tile("Median answer time", `${rag.median_latency_s}s`, null, "", `vs ${plain.median_latency_s}s without the graph`)}
      ${tile("Questions", report.questions, report.questions, "", `${Object.keys(TYPES).length} types · answers from Neo4j`)}
    </section>

    <section class="card" data-reveal>
      <div class="chart-head"><h2>Accuracy by question type</h2>
        <div class="legend">${SYSTEMS.map((s) => `<span><i style="background:${s.color}"></i>${s.label}</span>`).join("")}</div></div>
      <div class="bars">${Object.entries(TYPES).map(([type, label]) => `<div class="bar-group"><p>${label}</p>${SYSTEMS.map((s) => {
        const value = report.summary[s.key].by_type[type] ?? 0;
        return `<div class="bar-row" title="${label} · ${s.label}: ${pct(value)}"><span class="bar-track">
          <span class="bar" style="width:${Math.max(value * 100, 1)}%;background:${s.color}"></span></span><b>${pct(value)}</b></div>`;
      }).join("")}</div>`).join("")}</div>
    </section>

    <section class="card" data-reveal>
      <h2>How we tested it</h2>
      <ol class="steps">
        <li><b>Questions with known answers.</b> We picked random CVEs, CWEs and CAPECs from Neo4j and wrote questions whose correct answer is stored in the graph, so nothing is judged by hand.</li>
        <li><b>Two systems, one model.</b> ${escapeHtml(report.model)} answers each question twice: with the facts our graph retrieves, and alone. Any difference comes from the graph.</li>
        <li><b>Automatic scoring.</b> ID questions use F1 (correct IDs found vs IDs named). Score questions need the right severity and number; count questions need the exact count.</li>
        <li><b>Hallucination rate.</b> The share of IDs an answer named that are not real links for that entity in the official MITRE and NVD data.</li>
      </ol>
    </section>

    ${examples.length ? `<section class="card" data-reveal><h2>Where the graph made the difference</h2>
      <div class="table-scroll"><table class="compare"><thead><tr><th>Question</th><th>Correct answer</th><th>Without graph</th><th>GraphRAG</th></tr></thead>
      <tbody>${examples.map((r) => `<tr><td>${escapeHtml(r.question)}</td><td class="mono">${escapeHtml(truthText(r))}</td>
        <td>${escapeHtml(r.plain_llm.text)}</td><td>${escapeHtml(r.graphrag.text)}</td></tr>`).join("")}</tbody></table></div></section>` : ""}

    <section class="card" data-reveal>
      <h2>Limits, honestly</h2>
      <ul class="steps">
        <li>${report.questions} questions is a pilot; the plan is 150 across more question types.</li>
        <li>Every question names an ID, the case our retrieval handles best. Questions with no ID (semantic search) are not scored yet.</li>
        <li>Answer times include waits for the free Groq rate limit; a paid tier would be much faster.</li>
        <li>Data covers CVEs published in 2024 only.</li>
      </ul>
      <p class="note">Run on ${escapeHtml(report.run_at)} · ${escapeHtml(report.model)} · reasoning effort ${escapeHtml(report.reasoning_effort)}</p>
    </section>`;
  reveal();
}

renderNav();
splitWords();
startBackdrop(document.getElementById("dots"), { scroll: true });
fetch("data/eval-results.json").then((r) => (r.ok ? r.json() : Promise.reject())).then(render).catch(() => {
  document.getElementById("content").innerHTML = '<p class="card error">No results yet. Run <code>python -m eval.run_eval</code> in backend/.</p>';
});
