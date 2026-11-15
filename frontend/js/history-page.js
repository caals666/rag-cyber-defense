// The History page: every saved answer, grouped by day, with search and delete.
import { escapeHtml } from "./api.js";
import { startBackdrop } from "./backdrop.js";
import { clearHistory, loadHistory, removeEntry } from "./history.js";
import { renderNav, reveal, splitWords } from "./layout.js";

const REFUSAL = "I don't have information";
let items = loadHistory();
let confirming = false;

function day(iso) {
  const d = new Date(iso), today = new Date(), yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString("en-US", { day: "numeric", month: "long", year: "numeric" });
}

// Was the answer checked against the graph? -> [css class, label]
function status(h) {
  if (!h.answer || h.answer.startsWith(REFUSAL)) return ["", "No data found"];
  const g = h.grounding;
  if (!g || g.score == null) return ["", "No IDs to check"];
  return g.unsupported.length ? ["warn", `${g.unsupported.length} not in graph`] : ["ok", "Verified"];
}

function renderList() {
  const q = document.getElementById("search").value.trim().toLowerCase();
  const shown = items.filter((h) => !q || `${h.question} ${h.answer} ${(h.ids || []).join(" ")}`.toLowerCase().includes(q));
  const groups = new Map();
  for (const h of shown) groups.set(day(h.at), [...(groups.get(day(h.at)) || []), h]);

  document.getElementById("list").innerHTML = shown.length === 0 ? `<p class="note">Nothing matches “${escapeHtml(q)}”.</p>` :
    [...groups].map(([label, list]) => `<div class="day"><h2>${label}</h2><ul>${list.map((h) => {
      const [kind, text] = status(h);
      const answer = h.answer || "";
      return `<li class="entry"><a href="index.html?h=${h.id}" class="entry-main">
          <span class="entry-q">${escapeHtml(h.question)}</span>
          <span class="entry-a">${escapeHtml(answer.slice(0, 170))}${answer.length > 170 ? "…" : ""}</span>
          <span class="entry-meta"><span class="pill ${kind}">${text}</span>
            ${(h.ids || []).slice(0, 3).map((id) => `<span class="pill id">${id}</span>`).join("")}
            <span class="time">${new Date(h.at).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}</span></span></a>
        <button type="button" class="remove" data-id="${h.id}" aria-label="Delete">×</button></li>`;
    }).join("")}</ul></div>`).join("");
}

function render() {
  const content = document.getElementById("content");
  if (!items.length) {
    content.innerHTML = '<div class="card empty-state" data-reveal><p>No saved answers yet.</p><a href="index.html" class="cta">Ask your first question</a></div>';
    return reveal();
  }
  const checked = items.filter((h) => h.grounding?.score != null);
  const verified = checked.length ? Math.round((checked.filter((h) => !h.grounding.unsupported.length).length / checked.length) * 100) : 0;
  const ids = new Set(items.flatMap((h) => h.ids || [])).size;
  content.innerHTML = `
    <section class="tiles">
      <div class="tile" data-reveal><span>Questions asked</span><b data-count="${items.length}">${items.length}</b></div>
      <div class="tile" data-reveal><span>Answers fully verified</span><b data-count="${verified}" data-suffix="%">${verified}%</b></div>
      <div class="tile" data-reveal><span>Security IDs explored</span><b data-count="${ids}">${ids}</b></div>
    </section>
    <section class="card" data-reveal>
      <div class="history-tools">
        <input id="search" class="search" placeholder="Search questions, answers or IDs" aria-label="Search history">
        <button type="button" id="clear" class="ghost">Clear all</button>
      </div>
      <div id="list"></div>
    </section>`;
  renderList();
  reveal();

  document.getElementById("search").addEventListener("input", renderList);
  document.getElementById("list").addEventListener("click", (e) => {
    if (!e.target.matches(".remove")) return;
    items = removeEntry(Number(e.target.dataset.id));
    render();
  });
  // Two clicks to delete everything, so it can't happen by accident
  const clear = document.getElementById("clear");
  clear.addEventListener("click", () => {
    if (!confirming) { confirming = true; clear.textContent = "Click again to delete all"; clear.classList.add("danger"); return; }
    items = clearHistory();
    render();
  });
  clear.addEventListener("blur", () => { confirming = false; clear.textContent = "Clear all"; clear.classList.remove("danger"); });
}

renderNav();
splitWords();
startBackdrop(document.getElementById("dots"));
render();
