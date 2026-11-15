// Saved answers, kept in this browser (localStorage). Each entry is the full result the page showed:
// question, answer, technical explanation, grounding check and the graph facts behind them.
const KEY = "rag-history-v1";
const LIMIT = 60; // localStorage holds about 5 MB; the oldest entries go first

export function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}

function write(items) {
  // If the browser is full, drop the oldest entries until it fits
  for (let list = items; list.length; list = list.slice(0, -1)) {
    try {
      localStorage.setItem(KEY, JSON.stringify(list));
      return list;
    } catch {}
  }
  return [];
}

export function saveEntry(entry) {
  const rest = loadHistory().filter((h) => h.id !== entry.id);
  return write([entry, ...rest].slice(0, LIMIT));
}

export function removeEntry(id) {
  return write(loadHistory().filter((h) => h.id !== id));
}

export function clearHistory() {
  try { localStorage.removeItem(KEY); } catch {}
  return [];
}
