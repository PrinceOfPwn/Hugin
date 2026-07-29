import { useMemo, useState, useCallback, type CSSProperties } from "react";
import type { MitreIndex } from "../lib/mitre-index";
import MitreTechniqueRow from "./MitreTechniqueRow";

interface Props {
  index: MitreIndex;
  routePrefix?: string; // e.g. "/Hugin"
}

export default function MitreMatrix({ index, routePrefix = "/Hugin" }: Props) {
  const [query, setQuery] = useState("");
  const [onlyCovered, setOnlyCovered] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const normalizedQuery = query.trim().toUpperCase();
  const highlightId = /^T\d{4}(?:\.\d+)?$/.test(normalizedQuery)
    ? normalizedQuery
    : "";

  // Group techniques by tactic for row-strip layout.
  const rows = useMemo(() => {
    const tactics = index.tactics
      .slice()
      .sort((a, b) => a.order - b.order)
      .filter((t) => (onlyCovered ? t.cardCount > 0 : true));

    return tactics.map((tactic) => {
      const group = index.byTactic[tactic.id];
      const techniqueIds = group ? group.techniqueIds : [];
      const techniques = techniqueIds
        .map((id) => index.techniques[id])
        .filter(Boolean)
        .sort((a, b) => b.cardCount - a.cardCount);
      return { tactic, techniques };
    });
  }, [index, onlyCovered]);

  const entityById = useMemo(() => {
    const map = new Map<string, { id: string; title: string; mass: number | null; galaxyId: string; route: string }>();
    for (const group of Object.values(index.byTactic)) {
      for (const e of group.entities) map.set(e.id, e);
    }
    return map;
  }, [index]);

  const entitiesForTechniqueInTactic = useCallback(
    (techniqueId: string, tacticId: string) => {
      const tech = index.techniques[techniqueId];
      const group = index.byTactic[tacticId];
      if (!tech || !group) return [];
      const groupSet = new Set(group.entities.map((e) => e.id));
      return tech.entityIds
        .filter((id) => groupSet.has(id))
        .map((id) => entityById.get(id))
        .filter((v): v is NonNullable<typeof v> => Boolean(v));
    },
    [index, entityById],
  );

  const toggle = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const jumpTo = () => {
    if (!highlightId) return;
    const el = document.querySelector(`[data-mitre-id="${CSS.escape(highlightId)}"]`);
    if (el && "scrollIntoView" in el) {
      const tacticId = el.closest<HTMLElement>("[data-tactic-id]")?.dataset.tacticId;
      if (tacticId) {
        const key = `${tacticId}::${highlightId}`;
        setExpanded((prev) => new Set(prev).add(key));
      }
      // Immediate positioning avoids a long, unstable smooth-scroll across the
      // matrix on narrow screens and leaves the revealed official link usable.
      (el as HTMLElement).scrollIntoView({ behavior: "auto", block: "center" });
    }
  };

  const meta = index.meta;
  const coverageLabel =
    `${meta.coveredTechniques} exact techniques represented · ` +
    `${meta.totalWithMitre} of ${meta.totalEntities} entities tagged · ` +
    `ATT&CK v${meta.attackVersion}`;

  if (index.tactics.length === 0) {
    return (
      <p style={{ opacity: 0.7, fontStyle: "italic" }}>
        No MITRE index available yet. Run <code>npm run data:mitre</code>.
      </p>
    );
  }

  return (
    <div>
      <div style={toolbar}>
        <input
          type="search"
          placeholder="Jump to T1055, T1071, T1562.001…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") jumpTo();
          }}
          style={search}
          aria-label="Search MITRE ID"
        />
        <label style={toggleLabel}>
          <input
            type="checkbox"
            checked={onlyCovered}
            onChange={(e) => setOnlyCovered(e.target.checked)}
          />{" "}
          Only tactics with cards
        </label>
      </div>

      <div style={coverageBar}>
        <div
          style={{
            ...coverageFill,
            width: `${Math.min(100, meta.coveragePercent)}%`,
          }}
        />
        <span style={coverageText}>
          {coverageLabel} ({meta.coveragePercent}% of the active Enterprise corpus)
        </span>
      </div>

      <div style={matrixGrid}>
        {rows.map(({ tactic, techniques }) => (
          <div key={tactic.id} style={tacticRow} data-tactic-id={tactic.id}>
            <div style={tacticHeader}>
              <div style={tacticIdRow}>
                <span style={tacticId}>{tactic.id}</span>
                <span style={tacticName}>{tactic.name}</span>
              </div>
              <p style={tacticDesc}>{tactic.shortDesc}</p>
              <div style={tacticCounts}>
                <span>{tactic.techniqueCount} techniques</span>
                <span>·</span>
                <span>{tactic.cardCount} cards</span>
              </div>
            </div>
            <div style={strip}>
              {techniques.length === 0 && (
                <p style={{ opacity: 0.55, fontStyle: "italic", fontSize: 12 }}>
                  No techniques indexed for this tactic.
                </p>
              )}
              {techniques.map((tech) => {
                const key = `${tactic.id}::${tech.id}`;
                const filtered = entitiesForTechniqueInTactic(tech.id, tactic.id);
                return (
                  <MitreTechniqueRow
                    key={key}
                    technique={{ ...tech, cardCount: filtered.length }}
                    entities={filtered}
                    routePrefix={routePrefix}
                    expanded={expanded.has(key)}
                    onToggle={() => toggle(key)}
                    highlight={highlightId === tech.id}
                  />
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const toolbar: CSSProperties = {
  display: "flex",
  gap: 12,
  flexWrap: "wrap",
  alignItems: "center",
  marginBottom: 12,
};
const search: CSSProperties = {
  flex: "1 1 240px",
  minWidth: 200,
  padding: "8px 10px",
  background: "rgba(0,8,20,0.7)",
  border: "1px solid rgba(157,124,244,0.28)",
  color: "#e8f0ff",
  fontFamily: "monospace",
  fontSize: 13,
};
const toggleLabel: CSSProperties = {
  fontFamily: "monospace",
  fontSize: 12,
  color: "#c8d4e8",
  display: "flex",
  alignItems: "center",
  gap: 4,
  cursor: "pointer",
};
const coverageBar: CSSProperties = {
  position: "relative",
  height: 22,
  border: "1px solid rgba(157,124,244,0.24)",
  background: "rgba(0,8,20,0.55)",
  marginBottom: 20,
  overflow: "hidden",
};
const coverageFill: CSSProperties = {
  position: "absolute",
  inset: "0 auto 0 0",
  background: "linear-gradient(90deg, rgba(157,124,244,0.28), rgba(157,124,244,0.08))",
};
const coverageText: CSSProperties = {
  position: "relative",
  display: "block",
  padding: "3px 10px",
  fontFamily: "monospace",
  fontSize: 11,
  color: "#e8f0ff",
  lineHeight: "16px",
};
const matrixGrid: CSSProperties = {
  display: "grid",
  gap: 14,
};
const tacticRow: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "220px 1fr",
  gap: 14,
  padding: "12px 14px",
  border: "1px solid rgba(157,124,244,0.16)",
  background: "rgba(0,8,20,0.42)",
  borderRadius: 3,
};
const tacticHeader: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 4,
};
const tacticIdRow: CSSProperties = {
  display: "flex",
  gap: 6,
  alignItems: "baseline",
  flexWrap: "wrap",
};
const tacticId: CSSProperties = {
  fontFamily: "monospace",
  fontSize: 11,
  color: "var(--nav-accent)",
  padding: "1px 6px",
  border: "1px solid rgba(157,124,244,0.32)",
  background: "rgba(157,124,244,0.12)",
};
const tacticName: CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  color: "#e8f0ff",
};
const tacticDesc: CSSProperties = {
  margin: 0,
  fontSize: 11,
  opacity: 0.7,
  lineHeight: 1.4,
};
const tacticCounts: CSSProperties = {
  display: "flex",
  gap: 6,
  marginTop: "auto",
  fontFamily: "monospace",
  fontSize: 10,
  color: "#7ea8c8",
};
const strip: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 8,
  alignItems: "flex-start",
};
