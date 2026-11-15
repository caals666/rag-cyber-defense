// The attack path explorer: draws one record's real paths, CVE -> CWE -> CAPEC -> ATT&CK, as an SVG map.
// Hovering a box lights up every path through it; clicking opens the official record.
import { escapeHtml, sourceUrl } from "./api.js";

const LAYERS = ["CVE", "CWE", "CAPEC", "ATT&CK"];
const COLORS = ["#f59e0b", "#ec4899", "#8b5cf6", "#14b8a6"];
const MAX_PER_LAYER = 6; // more than this per column is unreadable; the rest is counted as "+N more"
const W = 720, ROW = 54, BOX_W = 132, BOX_H = 34;

const layerOf = (id) => (id.startsWith("CVE-") ? 0 : id.startsWith("CWE-") ? 1 : id.startsWith("CAPEC-") ? 2 : 3);

// One record -> chains of IDs, e.g. ["CVE-2024-24919", "CWE-200", "CAPEC-13", "T1574.006"]
function chainsFrom(fact) {
  const root = fact.cve || fact.cwe || fact.capec || fact.technique;
  if (!root?.id) return null;
  const names = new Map([[root.id, root.name || ""]]);
  for (const key of ["cwes", "capecs", "techniques"]) {
    for (const item of fact[key] || []) if (item?.id) names.set(item.id, item.name || "");
  }
  const idOf = (x) => (typeof x === "string" ? x : x?.id);
  const real = (x) => x && !x.startsWith("...");
  let chains = [];
  if (fact.paths?.length) chains = fact.paths.filter(real).map((p) => [root.id, ...p.split(" -> ").filter(Boolean)]);
  else if (fact.capec) chains = [
    ...(fact.cwes || []).map(idOf).filter(real).map((w) => [w, root.id]),
    ...(fact.techniques || []).map(idOf).filter(real).map((t) => [root.id, t]),
  ];
  else if (fact.technique) chains = (fact.capecs || []).map(idOf).filter(real).map((c) => [c, root.id]);
  if (!chains.length) chains = [[root.id]];
  return { root, names, chains };
}

// Where each box goes: one column per layer, keeping the IDs that appear in the most paths
function layout(chains) {
  const freq = new Map();
  for (const c of chains) for (const n of c) freq.set(n, (freq.get(n) || 0) + 1);
  const columns = LAYERS.map(() => []);
  for (const n of freq.keys()) columns[layerOf(n)].push(n);
  const hidden = columns.map((c) => Math.max(0, c.length - MAX_PER_LAYER));
  const kept = columns.map((c) => c.sort((a, b) => freq.get(b) - freq.get(a) || a.localeCompare(b)).slice(0, MAX_PER_LAYER));
  const used = [0, 1, 2, 3].filter((i) => kept[i].length);
  const height = Math.max(...kept.map((c, i) => c.length + (hidden[i] ? 1 : 0))) * ROW + 24;
  const pos = new Map();
  used.forEach((layer, col) => {
    const x = used.length === 1 ? W / 2 : 80 + (col * (W - 160)) / (used.length - 1);
    const top = (height - kept[layer].length * ROW) / 2 + ROW / 2;
    kept[layer].forEach((n, j) => pos.set(n, { x, y: top + j * ROW, layer }));
  });
  const visible = chains.filter((c) => c.every((n) => pos.has(n)));
  const edges = new Map();
  for (const c of visible) for (let i = 0; i + 1 < c.length; i++) edges.set(`${c[i]}|${c[i + 1]}`, [c[i], c[i + 1]]);
  const more = used.filter((l) => hidden[l]).map((l) => {
    const last = pos.get(kept[l][kept[l].length - 1]);
    return `<text x="${last.x}" y="${last.y + ROW * 0.85}" text-anchor="middle" class="more">+${hidden[l]} more</text>`;
  });
  return { pos, edges: [...edges.values()], chains: visible, height, used, more };
}

const curve = (a, b) => {
  const x1 = a.x + BOX_W / 2, x2 = b.x - BOX_W / 2, mid = (x1 + x2) / 2;
  return `M${x1},${a.y} C${mid},${a.y} ${mid},${b.y} ${x2},${b.y}`;
};

// CVSS rings for a CVE: base score, exploitability and impact
function rings(cve) {
  const C = 2 * Math.PI * 26;
  const items = [["Base score", cve.base_score, 10], ["Exploitability", cve.exploitability_score, 3.9], ["Impact", cve.impact_score, 6]]
    .filter(([, v]) => typeof v === "number");
  if (!items.length) return "";
  return `<div class="rings">${items.map(([label, value, max], i) => `
    <div class="ring"><svg viewBox="0 0 64 64" width="64" height="64" aria-hidden="true">
      <circle cx="32" cy="32" r="26" class="ring-track"/>
      <circle cx="32" cy="32" r="26" class="ring-fill" style="stroke-dasharray:${C};stroke-dashoffset:${C * (1 - Math.min(1, value / max))};stroke:${COLORS[i]}"/>
      <text x="32" y="36" text-anchor="middle">${value}</text></svg>
      <span>${label}<small> / ${max}</small></span></div>`).join("")}
    ${cve.severity ? `<b class="sev sev-${cve.severity.toLowerCase()}">${escapeHtml(cve.severity)}</b>` : ""}</div>`;
}

// Returns the explorer as a DOM element (or null when the record has no paths to draw)
export function attackGraph(fact) {
  const data = chainsFrom(fact);
  if (!data) return null;
  const g = layout(data.chains);
  const total = fact.counts?.paths ?? fact.cve?.path_count;
  const hint = `${total ? `${total} real path${total === 1 ? "" : "s"} in the graph. ` : ""}Hover a box to trace its paths, click to open the official record.`;

  const edges = g.edges.map(([a, b], i) => {
    const d = curve(g.pos.get(a), g.pos.get(b)), color = COLORS[layerOf(b)];
    return `<g class="edge" data-a="${a}" data-b="${b}"><path d="${d}" class="edge-base"/>
      <path d="${d}" class="edge-flow" style="stroke:${color}"/>
      <circle r="3.2" fill="${color}"><animateMotion dur="2.2s" begin="${(i % 7) * 0.3}s" repeatCount="indefinite" path="${d}"/></circle></g>`;
  }).join("");
  const nodes = [...g.pos].map(([n, p]) => `
    <a href="${sourceUrl(n)}" target="_blank" rel="noreferrer" class="node" data-id="${n}">
      <title>${escapeHtml(n + (data.names.get(n) ? " · " + data.names.get(n) : ""))}</title>
      <rect x="${p.x - BOX_W / 2}" y="${p.y - BOX_H / 2}" width="${BOX_W}" height="${BOX_H}" rx="17"
            class="${n === data.root.id ? "box root" : "box"}" style="stroke:${COLORS[p.layer]}"/>
      <circle cx="${p.x - BOX_W / 2 + 16}" cy="${p.y}" r="4.5" fill="${COLORS[p.layer]}"/>
      <text x="${p.x + 7}" y="${p.y + 4.5}" text-anchor="middle">${n}</text></a>`).join("");

  const el = document.createElement("div");
  el.className = "explorer";
  el.innerHTML = `
    <div class="explorer-head"><h2>Attack path explorer</h2>
      <div class="legend">${g.used.map((i) => `<span><i style="background:${COLORS[i]}"></i>${LAYERS[i]}</span>`).join("")}</div></div>
    ${fact.cve ? rings(fact.cve) : ""}
    <div class="graph-scroll"><svg viewBox="0 0 ${W} ${g.height}" class="graph" role="img"
      aria-label="Attack paths from ${data.root.id}">${edges}${nodes}${g.more.join("")}</svg></div>
    <p class="explorer-hint">${hint}</p>`;

  // Hover: dim everything that is not on a path through the hovered box
  const hintEl = el.querySelector(".explorer-hint");
  el.querySelectorAll(".node").forEach((node) => {
    node.addEventListener("mouseenter", () => {
      const id = node.dataset.id, lit = new Set();
      for (const c of g.chains) if (c.includes(id)) c.forEach((n) => lit.add(n));
      el.querySelectorAll(".node").forEach((n) => n.classList.toggle("dim", !lit.has(n.dataset.id)));
      el.querySelectorAll(".edge").forEach((e) => e.classList.toggle("dim", !(lit.has(e.dataset.a) && lit.has(e.dataset.b))));
      hintEl.innerHTML = `<b>${id}</b> ${escapeHtml(data.names.get(id) || "")}`;
    });
    node.addEventListener("mouseleave", () => {
      el.querySelectorAll(".dim").forEach((n) => n.classList.remove("dim"));
      hintEl.textContent = hint;
    });
  });
  return el;
}
