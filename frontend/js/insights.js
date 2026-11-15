// The Insights page: charts made from data/analytics.json (built by backend/analytics/build.py).
import { escapeHtml, fmt } from "./api.js";
import { startBackdrop } from "./backdrop.js";
import { renderNav, reveal, splitWords } from "./layout.js";

const INK = "#4f46e5";
// Severity is ordered, so it uses one hue from light to dark
const SEVERITY = [["LOW", "#c7d2fe"], ["MEDIUM", "#818cf8"], ["HIGH", "#4f46e5"], ["CRITICAL", "#312e81"]];
const RANKERS = [
  { key: "fix_first", label: "Our Fix-first score", color: "#4f46e5" },
  { key: "cvss_only", label: "CVSS score alone", color: "#f59e0b" },
  { key: "random", label: "Random order", color: "#9ca3af" },
];

// A numbered card: what it shows, the chart, and why it matters
const panel = (step, title, what, body, why, wide = false) => `
  <section class="card panel${wide ? " wide" : ""}" data-reveal>
    <div class="panel-head"><span class="step">${step}</span><div><h2>${title}</h2><p class="what">${what}</p></div></div>
    ${body}${why ? `<p class="why"><b>Why it matters:</b> ${why}</p>` : ""}
  </section>`;

// Horizontal bars, one row per item
function hbars(rows) {
  const top = Math.max(...rows.map((r) => r.value));
  return `<div class="hbars">${rows.map((r) => `
    <div class="hbar" title="${escapeHtml(r.tip || `${r.label}: ${fmt(r.value)}`)}">
      <span class="hbar-label">${escapeHtml(r.label)}</span>
      <span class="hbar-track"><span class="hbar-fill" style="width:${Math.max((r.value / top) * 100, 0.8)}%;background:${r.color || INK}"></span></span>
      <b>${fmt(r.value)}</b></div>`).join("")}</div>`;
}

// Line chart of new CVEs per month; hovering reads one month
function trend(months) {
  const W = 640, H = 220, P = { l: 44, r: 12, t: 14, b: 28 };
  const max = Math.ceil(Math.max(...months.map((m) => m.n)) / 1000) * 1000;
  const x = (i) => P.l + (i * (W - P.l - P.r)) / (months.length - 1);
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  const line = months.map((m, i) => `${i ? "L" : "M"}${x(i)},${y(m.n)}`).join(" ");
  const label = (m) => new Date(`${m.month}-01T00:00:00`).toLocaleString("en-US", { month: "short" });
  return `<div class="trend" data-months='${JSON.stringify(months.map((m) => [label(m), m.n, x(months.indexOf(m)), y(m.n)]))}'>
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="New CVEs per month in 2024">
      ${[0, 0.5, 1].map((f) => `<line x1="${P.l}" x2="${W - P.r}" y1="${y(max * f)}" y2="${y(max * f)}" class="grid"/>
        <text x="${P.l - 8}" y="${y(max * f) + 4}" text-anchor="end" class="axis">${fmt(max * f)}</text>`).join("")}
      <path d="${line} L${x(months.length - 1)},${H - P.b} L${x(0)},${H - P.b} Z" class="area"/>
      <path d="${line}" class="line" pathLength="1"/>
      ${months.map((m, i) => `<text x="${x(i)}" y="${H - 8}" text-anchor="middle" class="axis">${label(m)}</text>`).join("")}
      <line class="cross" y1="${P.t}" y2="${H - P.b}" visibility="hidden"/><circle class="dot" r="5" visibility="hidden"/>
    </svg><p class="tip">Hover the chart to read a month.</p></div>`;
}

function hookTrend(el) {
  const points = JSON.parse(el.dataset.months), svg = el.querySelector("svg");
  const cross = el.querySelector(".cross"), dot = el.querySelector(".dot"), tip = el.querySelector(".tip");
  svg.addEventListener("mousemove", (e) => {
    const box = svg.getBoundingClientRect();
    const px = ((e.clientX - box.left) / box.width) * 640;
    const [label, n, x, y] = points.reduce((a, b) => (Math.abs(b[2] - px) < Math.abs(a[2] - px) ? b : a));
    cross.setAttribute("x1", x); cross.setAttribute("x2", x); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", x); dot.setAttribute("cy", y); dot.setAttribute("visibility", "visible");
    tip.innerHTML = `<b>${label} 2024:</b> ${fmt(n)} new CVEs`;
  });
}

// How many really exploited bugs each ranking puts in its top 100 / 500 / 1,000
function validation(v) {
  const cuts = ["100", "500", "1000"];
  const top = Math.max(...cuts.flatMap((c) => RANKERS.map((r) => v[r.key][c])));
  return `<div class="legend">${RANKERS.map((r) => `<span><i style="background:${r.color}"></i>${r.label}</span>`).join("")}</div>
    <div class="vgroups">${cuts.map((c) => `<div class="vgroup"><p>Top ${fmt(c)} bugs to fix</p>${RANKERS.map((r) => `
      <div class="hbar" title="${r.label}: ${v[r.key][c]} of the top ${c} are known exploited">
        <span class="hbar-track"><span class="hbar-fill" style="width:${Math.max((v[r.key][c] / top) * 100, 0.8)}%;background:${r.color}"></span></span>
        <b>${v[r.key][c]}</b></div>`).join("")}</div>`).join("")}</div>
    <p class="headline">In the top 500, our score finds <b>${v.fix_first["500"]}</b> really exploited bugs:
      <b>${(v.fix_first["500"] / v.random["500"]).toFixed(1)}×</b> random and <b>${(v.fix_first["500"] / v.cvss_only["500"]).toFixed(1)}×</b> CVSS alone.</p>`;
}

function render(d) {
  const f = d.funnel;
  const sev = Object.fromEntries(d.severity.map((s) => [s.severity, s.n]));
  const tiles = [["Vulnerabilities (CVE)", d.nodes.CVE], ["Weaknesses (CWE)", d.nodes.CWE], ["Attack patterns (CAPEC)", d.nodes.CAPEC],
                 ["Attacker techniques", d.nodes.ATTACK], ["Links between them", d.links], ["Really exploited (KEV)", d.validation.kev_in_data]];
  const pct = (n) => Math.round((n / f.all) * 100);

  document.getElementById("content").innerHTML = `
    <section class="tiles">${tiles.map(([label, n]) => `<div class="tile" data-reveal><span>${label}</span><b data-count="${n}">${fmt(n)}</b></div>`).join("")}</section>
    <div class="panels">
      ${panel(1, "From bug to attacker action", "How many CVEs we can follow through each step of the chain.", hbars([
        { label: "All CVEs", value: f.all }, { label: "→ linked to a weakness (CWE)", value: f.cwe, tip: `${pct(f.cwe)}%` },
        { label: "→ to an attack pattern (CAPEC)", value: f.capec, tip: `${pct(f.capec)}%` }, { label: "→ to an ATT&CK technique", value: f.attack, tip: `${pct(f.attack)}%` },
      ]), `${pct(f.attack)}% of 2024 bugs (${fmt(f.attack)}) connect all the way to a real attacker technique, so we can explain what an attacker does next, not just that a bug exists.`, true)}
      ${panel(2, "New vulnerabilities every month", "CVEs published per month in 2024.", trend(d.monthly), "Thousands arrive each month; no team can read them all by hand.")}
      ${panel(3, "How severe they are", "CVSS severity of every 2024 CVE.",
        hbars(SEVERITY.map(([s, color]) => ({ label: s[0] + s.slice(1).toLowerCase(), value: sev[s] || 0, color }))),
        `${fmt((sev.HIGH || 0) + (sev.CRITICAL || 0))} are High or Critical, so "fix everything severe" is still too many. We need a better order.`)}
      ${panel(4, "The most common mistakes", "Weaknesses behind the most CVEs, with their average CVSS score.",
        hbars(d.top_cwes.map((w) => ({ label: w.id, value: w.n, tip: `${w.id} ${w.name}: ${fmt(w.n)} CVEs, average score ${w.avg_score}` }))),
        "Fixing one weakness type, like cross-site scripting, in your code closes thousands of possible bugs at once.")}
      ${panel(5, "What attackers can reach", "CVEs whose attack paths lead to each ATT&CK tactic (the attacker's goal).",
        hbars(d.tactics.map((t) => ({ label: t.tactic.replace(/-/g, " "), value: t.n }))),
        "Shows defenders which goals, like stealing logins or hiding, most 2024 bugs open the door to.")}
      ${panel(6, "Fix-first: which bugs to patch first", "Our score ranks all 38,002 scored CVEs. Then we checked it against CISA's list of bugs attackers really used.",
        `<div class="formula"><span><b>How bad</b>CVSS base score ÷ 10</span><i>×</i><span><b>How easy</b>exploitability ÷ 3.9</span><i>×</i>
         <span><b>How far</b>0.5 + 0.5 × reachable techniques ÷ 10</span><i>=</i><span class="result"><b>Fix-first</b>0 to 100</span></div>${validation(d.validation)}`,
        "It is tested on real attacks, not just a formula: ranking by our score puts more really exploited bugs at the top than CVSS alone.", true)}
      ${panel(7, "Real attacks in our graph", `${d.validation.kev_in_data} of our 2024 CVEs are on CISA's exploited list, ${d.validation.ransomware_in_data} of them used by ransomware. Here are the highest ranked, with their position in our Fix-first order.`,
        `<div class="table-scroll"><table class="compare"><thead><tr><th>Rank</th><th>CVE</th><th>Product</th><th>Fix-first</th><th>Ransomware</th></tr></thead><tbody>
         ${d.exploited.map((r) => `<tr><td class="mono">#${fmt(r.rank)}</td>
           <td><a href="https://nvd.nist.gov/vuln/detail/${r.id}" target="_blank" rel="noreferrer" class="mono">${r.id}</a></td>
           <td>${escapeHtml(r.vendor)}</td><td><span class="meter"><i style="width:${r.score}%"></i></span>${r.score}</td>
           <td>${r.ransomware ? '<span class="tag danger">Used by ransomware</span>' : '<span class="tag">No known use</span>'}</td></tr>`).join("")}
         </tbody></table></div>`, "", true)}
    </div>
    <p class="note">Built ${escapeHtml(d.built_at)} from Neo4j and CISA KEV catalog ${escapeHtml(d.kev_version)}.</p>`;
  document.querySelectorAll(".trend").forEach(hookTrend);
  reveal();
}

renderNav();
splitWords();
startBackdrop(document.getElementById("dots"), { scroll: true });
fetch("data/analytics.json").then((r) => (r.ok ? r.json() : Promise.reject())).then(render).catch(() => {
  document.getElementById("content").innerHTML = '<p class="card error">No analytics yet. Run <code>python -m analytics.build</code> in backend/.</p>';
});
