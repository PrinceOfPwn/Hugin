import { useState } from "react";

declare global {
  interface Window {
    pagefind?: PagefindApi;
    loadHuginPagefind: () => Promise<PagefindApi>;
  }
}

type PagefindApi = { search: (query: string) => Promise<{ results: Array<{ data: () => Promise<any> }> }> };

export default function GlobalSearch() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<any[]>([]);
  const [status, setStatus] = useState("");

  async function search(value: string) {
    setQuery(value);
    if (value.trim().length < 2) { setResults([]); setStatus(""); return; }
    setStatus("Searching…");
    const pagefind = window.pagefind ?? await window.loadHuginPagefind();
    window.pagefind = pagefind;
    const response = await pagefind.search(value);
    const data = await Promise.all(response.results.slice(0, 6).map((result) => result.data()));
    setResults(data);
    setStatus(`${response.results.length.toLocaleString()} matches`);
  }

  return <div className="panel" role="search">
    <div className="toolbar">
      <input aria-label="Search HUGIN" placeholder="Search techniques, concepts, detections…" value={query} onChange={(event) => search(event.target.value)} />
      <a className="button" href={`/Hugin/explore/?q=${encodeURIComponent(query)}`}>Advanced search</a>
    </div>
    {(status || results.length > 0) && <div aria-live="polite">
      <p style={{padding: "0 18px", color: "var(--muted)"}}>{status}</p>
      {results.map((result) => <a className="result" href={result.url} key={result.url}>
        <span><h3>{result.meta.title}</h3><p dangerouslySetInnerHTML={{__html: result.excerpt}} /></span>
      </a>)}
    </div>}
  </div>;
}
