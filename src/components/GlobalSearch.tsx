import { useState } from "react";

declare global {
  interface Window {
    pagefind?: PagefindApi;
    loadHuginPagefind: () => Promise<PagefindApi>;
  }
}

type PagefindApi = {
  search: (query: string) => Promise<{
    results: Array<{ data: () => Promise<{ url: string; excerpt: string; meta: { title: string } }> }>;
  }>;
};

function plainExcerpt(value: string) {
  return value.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
}

export default function GlobalSearch() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Array<{ url: string; excerpt: string; meta: { title: string } }>>([]);
  const [status, setStatus] = useState("");

  async function search(value: string) {
    setQuery(value);
    if (value.trim().length < 2) {
      setResults([]);
      setStatus("");
      return;
    }

    setStatus("Searching the knowledge graph…");
    const pagefind = window.pagefind ?? await window.loadHuginPagefind();
    window.pagefind = pagefind;
    const response = await pagefind.search(value);
    const data = await Promise.all(response.results.slice(0, 5).map((result) => result.data()));
    setResults(data);
    setStatus(`${response.results.length.toLocaleString()} matching records`);
  }

  return (
    <div className="search-box" role="search">
      <div className="search-row">
        <input
          aria-label="Search HUGIN"
          placeholder="Search techniques, concepts, detections, or paths…"
          value={query}
          onChange={(event) => search(event.target.value)}
        />
        <a className="button" href={`/Hugin/explore/?q=${encodeURIComponent(query)}`}>Explore results</a>
      </div>
      {(status || results.length > 0) && (
        <div className="search-results" aria-live="polite">
          <p className="search-status">{status}</p>
          {results.map((result) => (
            <a className="search-result" href={result.url} key={result.url}>
              <strong>{result.meta.title}</strong>
              <p>{plainExcerpt(result.excerpt)}</p>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
