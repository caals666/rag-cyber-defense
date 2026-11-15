// The Ask page: send a question, show the answer while the AI writes it, keep the chat and history.
import { askStream, escapeHtml, markdown, sourceUrl } from "./api.js";
import { startBackdrop } from "./backdrop.js";
import { attackGraph } from "./graph.js";
import { loadHistory, saveEntry } from "./history.js";
import { renderNav, splitWords } from "./layout.js";

const EXAMPLES = [
  "Which ATT&CK techniques are reachable from CVE-2024-24919?",
  "How do attackers steal login sessions?",
  "What attack patterns are linked to CWE 287?",
];
const REFUSAL = "I don't have information";
// How the records were found, shown as a small badge on every answer
const MODES = { id_lookup: "ID lookup", hybrid_vector: "Semantic search", keyword_search: "Keyword fallback" };

const $ = (id) => document.getElementById(id);
let thread = [];      // finished answers in this chat (the last 6 go back to the AI for follow-ups)
let loading = false;

// ---------------------------------------------------------------- showing one answer
// Every record the answer used, as {id, name}, without duplicates
function collectSources(result) {
  const found = new Map();
  for (const fact of result.facts || []) {
    const main = fact.entry || fact.cve || fact.cwe || fact.capec || fact.technique || fact;
    const linked = [...(fact.cwes || []), ...(fact.capecs || []), ...(fact.techniques || [])];
    for (const item of [main, ...linked]) if (item?.id && !found.has(item.id)) found.set(item.id, item.name || "");
  }
  return [...found].map(([id, name]) => ({ id, name }));
}

// Creates the empty answer block; the returned functions fill each part as events arrive
function createReply(question) {
  const el = document.createElement("section");
  el.className = "reply";
  el.innerHTML = `<p class="bubble">${escapeHtml(question)}</p>
    <span class="badge" hidden></span><details class="cypher" hidden><summary>Cypher</summary><pre></pre></details>
    <div class="answer"><div class="skeleton"><span></span><span></span></div></div>
    <p class="grounding" hidden></p><div class="graphs"></div>
    <div class="details" hidden><h2>Technical explanation</h2><div class="details-text"></div></div>
    <p class="note missing" hidden></p><div class="sources" hidden></div>`;
  $("thread").appendChild(el);
  el.scrollIntoView({ behavior: "smooth", block: "start" });
  const part = (selector) => el.querySelector(selector);

  return {
    facts(result) {
      const badge = part(".badge");
      badge.textContent = MODES[result.mode] || result.mode;
      badge.className = `badge ${result.mode}`;
      badge.hidden = false;
      if (result.cypher?.length) {
        part(".cypher pre").textContent = result.cypher.join("\n");
        part(".cypher").hidden = false;
      }
      if (result.not_found?.length) {
        part(".missing").textContent = `Not in the dataset: ${result.not_found.join(", ")}`;
        part(".missing").hidden = false;
      }
    },
    answer(text, typing) {
      part(".answer").innerHTML = markdown(text + (typing ? " ▍" : ""));
    },
    details(text, typing) {
      part(".details").hidden = false;
      part(".details-text").innerHTML = markdown(text + (typing ? " ▍" : ""));
    },
    // After the answer: grounding check, attack path maps and sources (not for refusals)
    finish(result) {
      if (!result.answer) part(".answer").innerHTML = '<p class="muted">No answer this time.</p>';
      if (!result.answer || result.answer.startsWith(REFUSAL)) return;
      const g = result.grounding;
      if (g?.score != null) {
        const box = part(".grounding");
        box.hidden = false;
        box.className = g.unsupported.length ? "grounding warn" : "grounding ok";
        box.textContent = g.unsupported.length
          ? `Not found in the graph: ${g.unsupported.join(", ")}`
          : `Verified: all ${g.supported.length} IDs and scores in this answer are in the graph.`;
      }
      if (result.mode !== "keyword_search") {
        for (const fact of (result.facts || []).slice(0, 2)) {
          const map = attackGraph(fact);
          if (map) part(".graphs").appendChild(map);
        }
      }
      const sources = collectSources(result);
      if (sources.length) {
        const box = part(".sources");
        box.hidden = false;
        box.innerHTML = `<h2>Sources <span class="count">${sources.length}</span></h2><ul>${sources.slice(0, 12).map((s) =>
          `<li><a href="${sourceUrl(s.id)}" target="_blank" rel="noreferrer">${s.id}</a><span>${escapeHtml(s.name)}</span></li>`).join("")}</ul>
          ${sources.length > 12 ? `<p class="note">and ${sources.length - 12} more</p>` : ""}`;
      }
    },
  };
}

// Shows a saved answer again, straight from this browser's storage
function showSaved(entry) {
  const reply = createReply(entry.question);
  reply.facts(entry);
  reply.answer(entry.answer, false);
  if (entry.details) reply.details(entry.details, false);
  reply.finish(entry);
}

// ---------------------------------------------------------------- asking
async function ask(text) {
  text = text.trim();
  if (!text || loading) return;
  startChat();
  loading = true;
  $("q").value = "";
  updateButton();
  $("error").hidden = true;

  const entry = { id: Date.now(), at: new Date().toISOString(), question: text, answer: "", details: "" };
  const reply = createReply(text);
  try {
    const history = thread.slice(-6).map((t) => ({ question: t.question, answer: t.answer }));
    await askStream(text, history, (event) => {
      if (event.type === "facts") { Object.assign(entry, event); delete entry.type; reply.facts(entry); }
      if (event.type === "answer") { entry.answer += event.delta; reply.answer(entry.answer, true); }
      if (event.type === "details") { entry.details += event.delta; reply.answer(entry.answer, false); reply.details(entry.details, true); }
      if (event.type === "done") entry.grounding = event.grounding;
      if (event.type === "error") throw new Error(event.detail);
    });
    reply.answer(entry.answer, false);
    if (entry.details) reply.details(entry.details, false);
    reply.finish(entry);
    if (entry.answer) {
      thread.push(entry);
      renderRecent(saveEntry(entry));
    }
  } catch (err) {
    reply.finish(entry);
    $("error").textContent = err.message || "Something went wrong. Please try again.";
    $("error").hidden = false;
  } finally {
    loading = false;
    updateButton();
  }
}

// The first question switches from the big centred hero to the chat layout (box docked at the bottom)
function startChat() {
  if ($("main").classList.contains("chat")) return;
  $("main").className = "chat";
  $("hero").hidden = true;
  $("examples").hidden = true;
  $("ask").classList.add("docked");
  $("dots").classList.add("hidden"); // fade the sphere so answers are easy to read
}

function updateButton() {
  $("send").disabled = loading || !$("q").value.trim();
  $("send").innerHTML = loading ? '<span class="spin"></span>'
    : '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 19V5M5.5 11.5 12 5l6.5 6.5" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

// ---------------------------------------------------------------- recent questions sidebar
function renderRecent(saved) {
  $("recent-list").innerHTML = saved.slice(0, 25).map((h) =>
    `<li><button type="button" data-id="${h.id}" title="${escapeHtml(h.question)}">${escapeHtml(h.question)}</button></li>`).join("");
  $("recent-tab").textContent = `Recent (${saved.length})`;
  $("recent-tab").hidden = $("recent").hidden = saved.length === 0;
}

$("recent-list").addEventListener("click", (e) => {
  const id = e.target.dataset.id;
  const entry = id && loadHistory().find((h) => String(h.id) === id);
  if (!entry) return;
  $("thread").innerHTML = "";
  thread = [entry];
  startChat();
  showSaved(entry);
  $("recent").classList.remove("open");
});
$("recent-tab").addEventListener("click", () => $("recent").classList.add("open"));
$("recent-close").addEventListener("click", () => $("recent").classList.remove("open"));
$("recent").addEventListener("mouseleave", () => $("recent").classList.remove("open"));
$("new-q").addEventListener("click", () => { location.href = "index.html"; });

// ---------------------------------------------------------------- typing hint in the empty box
// Types the example questions letter by letter, then erases and moves to the next one
let example = 0, length = 0, direction = 1;
function hintStep() {
  const active = !$("q").value && document.activeElement !== $("q");
  const full = EXAMPLES[example];
  if (active) {
    length += direction;
    $("hint").innerHTML = `${escapeHtml(full.slice(0, length))}<i></i>`;
  }
  $("hint").hidden = !active;
  let wait = direction > 0 ? 40 : 15;
  if (length >= full.length) { direction = -1; wait = 1800; }
  if (length <= 0) { direction = 1; example = (example + 1) % EXAMPLES.length; wait = 350; }
  setTimeout(hintStep, wait);
}

// ---------------------------------------------------------------- start
renderNav();
splitWords();
startBackdrop($("dots"));
updateButton();
hintStep();
renderRecent(loadHistory());
$("examples").innerHTML = EXAMPLES.map((ex) => `<button class="chip" type="button">${escapeHtml(ex)}</button>`).join("");
$("examples").addEventListener("click", (e) => { if (e.target.matches(".chip")) ask(e.target.textContent); });
$("q").addEventListener("input", updateButton);
$("ask").addEventListener("submit", (e) => { e.preventDefault(); ask($("q").value); });

// index.html?h=<id> (links from the History page) opens that saved answer
const openId = new URLSearchParams(location.search).get("h");
const saved = openId && loadHistory().find((h) => String(h.id) === openId);
if (saved) { thread = [saved]; startChat(); showSaved(saved); }
