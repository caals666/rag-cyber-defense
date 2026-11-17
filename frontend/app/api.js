// Talking to the backend lives here, so pages only deal with what to show.

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://rag-cyber-defense-sigma.vercel.app";

// Sends a question and calls onEvent for every event the backend streams back.
// The backend sends one JSON object per line: facts, answer pieces, details pieces, done.
export async function askStream(question, history, onEvent) {
  const res = await fetch(`${API_URL}/ask/stream`, {
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
