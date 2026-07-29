import type { CSSProperties } from "react";
import type { Entity, Relation } from "../lib/types";

interface Props {
  entity: Entity | null;
  entitiesById: Map<string, Entity>;
  relations: Relation[]; // may be [] if not provided
  galaxyName?: string;
  routePrefix: string;
  onSelectEntity: (id: string) => void;
}

const MITRE_RE = /^T\d{4}(?:\.\d+)?$/;

export default function EntityPreviewPane({
  entity, entitiesById, relations, galaxyName, routePrefix, onSelectEntity,
}: Props) {
  if (!entity) {
    return (
      <aside style={{ ...paneStyle, alignItems: "center", justifyContent: "center", color: "#94a3b8", textAlign: "center", padding: 24 }}>
        <p style={{ fontFamily: "monospace", fontSize: 12, opacity: 0.75, maxWidth: 240, lineHeight: 1.5 }}>
          Select an entity from the list to preview its summary, MITRE tags, and related nodes.
        </p>
      </aside>
    );
  }

  const mitreTags = (entity.tags || []).filter((t) => MITRE_RE.test(t));
  const plainTags = (entity.tags || []).filter((t) => !MITRE_RE.test(t));

  // Related entities from curated relations (fallback: nothing).
  const relatedIds = new Set<string>();
  for (const r of relations) {
    if (r.source === entity.id) relatedIds.add(r.target);
    else if (r.target === entity.id) relatedIds.add(r.source);
    if (relatedIds.size >= 24) break;
  }
  const related: Entity[] = [];
  for (const id of relatedIds) {
    const e = entitiesById.get(id);
    if (e) related.push(e);
    if (related.length >= 8) break;
  }

  const href = `${routePrefix}${entity.route}`;

  return (
    <aside style={paneStyle}>
      <div style={{ padding: "16px 16px 12px", borderBottom: "1px solid rgba(157,124,244,0.15)" }}>
        <div style={{ fontFamily: "monospace", fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--nav-accent)", opacity: 0.7 }}>
          {entity.kind.replace(/_/g, " ")}
        </div>
        <h2 style={{ margin: "6px 0 8px", fontSize: 18, lineHeight: 1.3, color: "#e8f0ff" }}>{entity.title}</h2>
        <div style={metaRow}>
          <span style={badge}>{galaxyName || entity.galaxyId}</span>
          {entity.tier && <span style={badge}>Tier {entity.tier}</span>}
          {entity.mass != null && <span style={badge}>mass {entity.mass.toFixed(1)}</span>}
          <span style={badgeMuted}>◈ {entity.degree ?? 0}</span>
          {entity.category && <span style={badgeMuted}>{entity.category}</span>}
        </div>
      </div>

      <div style={{ padding: 16, overflowY: "auto", flex: 1, display: "flex", flexDirection: "column", gap: 14 }}>
        {entity.summary && (
          <p style={{ margin: 0, fontSize: 13, lineHeight: 1.55, color: "#dae4f0" }}>{entity.summary}</p>
        )}

        {mitreTags.length > 0 && (
          <Group title="MITRE ATT&CK">
            <div style={chipRow}>
              {mitreTags.map((t) => <span key={t} style={mitreChip}>{t}</span>)}
            </div>
          </Group>
        )}

        {related.length > 0 && (
          <Group title={`Related · ${related.length}`}>
            <div style={chipRow}>
              {related.map((r) => (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => onSelectEntity(r.id)}
                  style={relatedChip}
                  title={r.title}
                >
                  {r.title.length > 32 ? `${r.title.slice(0, 32)}…` : r.title}
                </button>
              ))}
            </div>
          </Group>
        )}

        {plainTags.length > 0 && (
          <Group title={`Tags · ${plainTags.length}`}>
            <div style={chipRow}>
              {plainTags.slice(0, 32).map((t) => <span key={t} style={tagChip}>{t}</span>)}
              {plainTags.length > 32 && <span style={badgeMuted}>+{plainTags.length - 32}</span>}
            </div>
          </Group>
        )}
      </div>

      <div style={{ padding: 12, borderTop: "1px solid rgba(157,124,244,0.15)" }}>
        <a href={href} style={openBtn}>Open full record →</a>
      </div>
    </aside>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <div style={{ fontFamily: "monospace", fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--nav-accent)", opacity: 0.75, marginBottom: 6 }}>
        {title}
      </div>
      {children}
    </section>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────
const paneStyle: CSSProperties = {
  width: "100%",
  height: "100%",
  display: "flex",
  flexDirection: "column",
  background: "linear-gradient(180deg, rgba(0,8,20,0.92), rgba(0,4,12,0.85))",
  borderLeft: "1px solid rgba(157,124,244,0.15)",
  color: "#dae4f0",
  fontFamily: "'Fira Code', ui-monospace, monospace",
};

const metaRow: CSSProperties = {
  display: "flex", flexWrap: "wrap", gap: 4,
  fontFamily: "monospace", fontSize: 10,
};
const chipRow: CSSProperties = {
  display: "flex", flexWrap: "wrap", gap: 4,
};
const badge: CSSProperties = {
  padding: "1px 6px",
  background: "rgba(157,124,244,0.12)", color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.28)",
};
const badgeMuted: CSSProperties = {
  padding: "1px 6px",
  background: "rgba(255,255,255,0.06)", color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.12)",
};
const mitreChip: CSSProperties = {
  padding: "2px 6px",
  background: "rgba(157,124,244,0.14)",
  color: "#d8cdfa",
  border: "1px solid rgba(157,124,244,0.35)",
  fontSize: 10,
  fontFamily: "monospace",
};
const tagChip: CSSProperties = {
  padding: "2px 6px",
  background: "rgba(255,255,255,0.05)",
  color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.12)",
  fontSize: 10,
  fontFamily: "monospace",
};
const relatedChip: CSSProperties = {
  padding: "3px 8px",
  background: "rgba(157,124,244,0.1)",
  color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.28)",
  fontSize: 10,
  fontFamily: "monospace",
  cursor: "pointer",
  textAlign: "left",
};
const openBtn: CSSProperties = {
  display: "inline-block",
  padding: "6px 12px",
  background: "rgba(157,124,244,0.15)",
  color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.45)",
  textDecoration: "none",
  fontFamily: "monospace",
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.08em",
};
