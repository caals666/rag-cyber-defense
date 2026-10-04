"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://rag-cyber-defense.vercel.app";

const EXAMPLES = [
  "Which ATT&CK techniques are reachable from CVE-2024-24919?",
  "What attack patterns are linked to CWE-287?",
  "How do attackers abuse the print spooler?",
];

// Official page for any ID, so users can verify every source themselves
function sourceUrl(id) {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("CWE-")) return `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html`;
  if (id.startsWith("CAPEC-")) return `https://capec.mitre.org/data/definitions/${id.slice(6)}.html`;
  if (id.startsWith("T")) return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  return null;
}

// Flatten the retrieved facts into a short list of {id, name} sources
function collectSources(result) {
  const seen = new Map();
  const add = (item) => {
    if (item?.id && !seen.has(item.id)) seen.set(item.id, item.name || "");
  };
  for (const fact of result.facts) {
    if (result.mode === "keyword_search") { add(fact); continue; }
    add(fact.cve || fact.cwe || fact.capec || fact.technique);
    for (const key of ["cwes", "capecs", "techniques"]) {
      for (const item of fact[key] || []) typeof item === "object" && add(item);
    }
  }
  return [...seen].map(([id, name]) => ({ id, name }));
}

export default function Home() {
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function ask(q) {
    const text = (q ?? question).trim();
    if (!text) return;
    setQuestion(text);
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API_URL}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text }),
      });
      if (!res.ok) {
        let detail = "The backend returned an error.";
        try {
          const payload = await res.json();
          detail = payload.detail || payload.message || JSON.stringify(payload);
        } catch {
          try {
            detail = await res.text();
          } catch {
            detail = "Unknown API error.";
          }
        }
        throw new Error(detail);
      }
      setResult(await res.json());
    } catch (err) {
      const message = err instanceof Error ? err.message : "Something went wrong while getting your answer. Please try again in a moment.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  const sources = result ? collectSources(result) : [];
  const SHOWN = 12;

  return (
    <main>
      <h1>Cyber Defense RAG</h1>
      <p className="sub">Answers grounded in a CVE → CWE → CAPEC → ATT&amp;CK knowledge graph</p>

      <form onSubmit={(e) => { e.preventDefault(); ask(); }}>
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask about a vulnerability, weakness or attack technique…"
        />
        <button disabled={loading}>{loading ? "Thinking…" : "Ask"}</button>
      </form>

      {!result && !loading && (
        <div className="examples">
          {EXAMPLES.map((ex) => (
            <button key={ex} className="chip" onClick={() => ask(ex)}>{ex}</button>
          ))}
        </div>
      )}

      {loading && <div className="skeleton"><span /><span /><span /></div>}

      {error && <p className="error">{error}</p>}

      {result && (
        <section>
          {result.facts.length === 0 ? (
            <div className="answer empty">
              No matching records were found in the knowledge graph. Try a specific ID such as
              CVE-2024-24919 or CWE-287, or different keywords.
            </div>
          ) : result.answer ? (
            <div className="answer">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{result.answer}</ReactMarkdown>
            </div>
          ) : (
            <div className="answer empty">
              The AI summary is unavailable right now, but the records below were found in the graph.
            </div>
          )}

          {result.not_found?.length > 0 && (
            <p className="note">Not in the dataset: {result.not_found.join(", ")}</p>
          )}

          {sources.length > 0 && (
            <div className="sources">
              <h2>Sources <span className="count">{sources.length}</span></h2>
              <ul>
                {sources.slice(0, SHOWN).map((s) => (
                  <li key={s.id}>
                    <a href={sourceUrl(s.id)} target="_blank" rel="noreferrer">{s.id}</a>
                    {s.name && <span>{s.name}</span>}
                  </li>
                ))}
              </ul>
              {sources.length > SHOWN && (
                <details>
                  <summary>Show {sources.length - SHOWN} more</summary>
                  <ul>
                    {sources.slice(SHOWN).map((s) => (
                      <li key={s.id}>
                        <a href={sourceUrl(s.id)} target="_blank" rel="noreferrer">{s.id}</a>
                        {s.name && <span>{s.name}</span>}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          )}

          {/* Developer-only details, collapsed so users never see raw JSON by default */}
          {process.env.NODE_ENV !== "production" && (
            <details className="dev">
              <summary>Developer details</summary>
              <p>mode: {result.mode} · llm: {result.llm}</p>
              <pre>{JSON.stringify(result.facts, null, 2)}</pre>
            </details>
          )}
        </section>
      )}
    </main>
  );
}
