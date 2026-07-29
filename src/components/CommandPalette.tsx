import { useEffect, useMemo, useRef, useState } from "react";
import type { Entity } from "../lib/types";

interface Props {
  entities: Entity[];
  onSelect: (entity: Entity) => void;
}

type Match = {
  entity: Entity;
  score: number;   // lower is better (0 = exact prefix, 1 = substring, 2 = tag, 3 = id)
  matchStart: number;
  matchEnd: number;
  matchedField: "title" | "tag" | "id";
};

const MAX_RESULTS = 20;

// Kind pill palette — mirrors GALAXY_COLORS from GraphThreeV3.
const KIND_COLORS: Record<string, string> = {
  techniques:    "#ff2244",
  internals:     "#00f0ff",
  defenses:      "#39ff14",
  chains:        "#ffb700",
  evidence:      "#00e5ff",
  sources:       "#e040fb",
  gaps:          "#ff5555",
  architecture:  "#9d4edd",
  tradecraft_qa: "#00e5bf",
};

function matchEntity(entity: Entity, q: string): Match | null {
  const title = (entity.title || "").toLowerCase();
  const id = entity.id.toLowerCase();
  const tags = entity.tags || [];

  const titleIdx = title.indexOf(q);
  if (titleIdx === 0) return { entity, score: 0, matchStart: titleIdx, matchEnd: titleIdx + q.length, matchedField: "title" };
  if (titleIdx > 0)   return { entity, score: 1, matchStart: titleIdx, matchEnd: titleIdx + q.length, matchedField: "title" };

  for (const t of tags) {
    const ti = t.toLowerCase().indexOf(q);
    if (ti >= 0) return { entity, score: 2, matchStart: 0, matchEnd: 0, matchedField: "tag" };
  }

  const idIdx = id.indexOf(q);
  if (idIdx >= 0) return { entity, score: 3, matchStart: idIdx, matchEnd: idIdx + q.length, matchedField: "id" };

  return null;
}

function isTypingContext(el: Element | null): boolean {
  if (!el) return false;
  const tag = el.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if ((el as HTMLElement).isContentEditable) return true;
  return false;
}

export default function CommandPalette({ entities, onSelect }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Global open shortcut.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (open) return; // in-modal keys handled below
      const meta = e.metaKey || e.ctrlKey;
      if (meta && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setOpen(true);
        return;
      }
      if (e.key === "/" && !isTypingContext(document.activeElement)) {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (open) {
      // Focus the input after paint so it doesn't race the modal mount.
      const id = requestAnimationFrame(() => inputRef.current?.focus());
      return () => cancelAnimationFrame(id);
    }
    setQuery("");
    setCursor(0);
  }, [open]);

  const results = useMemo<Match[]>(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const out: Match[] = [];
    for (const e of entities) {
      const m = matchEntity(e, q);
      if (m) out.push(m);
      if (out.length > MAX_RESULTS * 4) break; // safety
    }
    out.sort((a, b) => a.score - b.score || (a.entity.title || "").localeCompare(b.entity.title || ""));
    return out.slice(0, MAX_RESULTS);
  }, [entities, query]);

  useEffect(() => { setCursor(0); }, [query]);

  const handleSelect = (m: Match) => {
    onSelect(m.entity);
    setOpen(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") { setOpen(false); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); setCursor((c) => Math.min(c + 1, Math.max(0, results.length - 1))); return; }
    if (e.key === "ArrowUp")   { e.preventDefault(); setCursor((c) => Math.max(c - 1, 0)); return; }
    if (e.key === "Enter" && results[cursor]) { e.preventDefault(); handleSelect(results[cursor]); }
  };

  if (!open) return null;

  return (
    <div
      onKeyDown={handleKeyDown}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        background: "rgba(0,0,0,0.6)",
        backdropFilter: "blur(4px)",
        WebkitBackdropFilter: "blur(4px)",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
    >
      <div
        style={{
          position: "relative",
          margin: "15vh auto 0",
          maxWidth: 640,
          width: "calc(100% - 32px)",
          background: "rgba(15,15,25,0.95)",
          border: "1px solid rgba(255,255,255,0.12)",
          borderRadius: 12,
          boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,240,255,0.15)",
          overflow: "hidden",
        }}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search techniques, defenses, sources..."
          spellCheck={false}
          autoComplete="off"
          style={{
            width: "100%",
            padding: "18px 20px",
            background: "transparent",
            border: "none",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
            color: "#e8f0ff",
            fontFamily: "monospace",
            fontSize: 18,
            outline: "none",
            boxSizing: "border-box",
          }}
        />

        <div style={{ maxHeight: "50vh", overflowY: "auto" }}>
          {query.trim() && results.length === 0 && (
            <div style={{ padding: "18px 20px", color: "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: 12 }}>
              No matches.
            </div>
          )}
          {results.map((m, i) => {
            const active = i === cursor;
            const gc = KIND_COLORS[m.entity.galaxyId] || "#00f0ff";
            const title = m.entity.title || m.entity.id;
            let titleContent: React.ReactNode = title;
            if (m.matchedField === "title" && m.matchEnd > m.matchStart) {
              const before = title.slice(0, m.matchStart);
              const hit    = title.slice(m.matchStart, m.matchEnd);
              const after  = title.slice(m.matchEnd);
              titleContent = (
                <>
                  {before}
                  <span style={{ color: "#00f0ff", fontWeight: 700 }}>{hit}</span>
                  {after}
                </>
              );
            }
            return (
              <button
                key={m.entity.id}
                type="button"
                onMouseEnter={() => setCursor(i)}
                onClick={() => handleSelect(m)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  width: "100%",
                  padding: "10px 20px",
                  background: active ? "rgba(0,240,255,0.08)" : "transparent",
                  border: "none",
                  borderLeft: `2px solid ${active ? gc : "transparent"}`,
                  cursor: "pointer",
                  textAlign: "left",
                  color: "#e8f0ff",
                  fontFamily: "system-ui, sans-serif",
                  fontSize: 13,
                }}
              >
                <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {titleContent}
                </span>
                <span style={{
                  fontSize: 9, textTransform: "uppercase", letterSpacing: "0.12em",
                  color: gc, border: `1px solid ${gc}55`, padding: "2px 6px", borderRadius: 3,
                  fontFamily: "monospace",
                }}>
                  {m.entity.galaxyId}
                </span>
                {(m.entity.mitre || []).slice(0, 2).map((tid) => (
                  <span key={tid} style={{
                    fontSize: 9, fontFamily: "monospace", color: "rgba(255,255,255,0.5)",
                    background: "rgba(255,255,255,0.06)", padding: "2px 5px", borderRadius: 3,
                  }}>{tid}</span>
                ))}
              </button>
            );
          })}
        </div>

        <div style={{
          padding: "8px 20px",
          borderTop: "1px solid rgba(255,255,255,0.06)",
          fontFamily: "monospace",
          fontSize: 10,
          color: "rgba(255,255,255,0.45)",
          display: "flex",
          gap: 16,
        }}>
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}
