// Talking to the backend, and small text helpers every page uses.

// Sends a question and calls onEvent for every event the backend streams back.
// The backend sends one JSON object per line: facts, answer pieces, details pieces, done.
export async function askStream(question, history, onEvent) {
  const res = await fetch(`${window.API_URL}/ask/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, history }),
  });
  if (!res.ok) {
    const body = await res.text();
    let message = body;
    try { message = JSON.parse(body).detail; } catch {}
    throw new Error(message || `Server error ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop(); // the last piece may be half a line; keep it for the next read
    for (const line of lines) {
      if (line.trim()) onEvent(JSON.parse(line));
    }
  }
}

// The official web page for any ID, so users can check every source themselves
export function sourceUrl(id) {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("CWE-")) return `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html`;
  if (id.startsWith("CAPEC-")) return `https://capec.mitre.org/data/definitions/${id.slice(6)}.html`;
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

// Makes any text safe to put inside HTML: "<script>" shows as text instead of running
export function escapeHtml(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// 12345 -> "12,345"
export const fmt = (n) => Number(n).toLocaleString("en-US");

// A tiny, safe Markdown renderer for the AI's answers: headings, bullet lists, numbered lists,
// **bold** and `code`. The text is escaped first, so the AI can never inject HTML.
export function markdown(text) {
  const inline = (s) => s.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = [];
  let list = null; // "ul" or "ol" while inside a list
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };

  for (const raw of escapeHtml(text).split("\n")) {
    const line = raw.trim();
    let m;
    if (!line) { closeList(); continue; }
    if ((m = line.match(/^#{1,4}\s+(.*)/))) { closeList(); out.push(`<h2>${inline(m[1])}</h2>`); continue; }
    if ((m = line.match(/^[-*•]\s+(.*)/))) {
      if (list !== "ul") { closeList(); out.push("<ul>"); list = "ul"; }
      out.push(`<li>${inline(m[1])}</li>`);
      continue;
    }
    if ((m = line.match(/^\d+[.)]\s+(.*)/))) {
      if (list !== "ol") { closeList(); out.push("<ol>"); list = "ol"; }
      out.push(`<li>${inline(m[1])}</li>`);
      continue;
    }
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  return out.join("");
}
