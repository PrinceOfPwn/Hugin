import { useMemo } from "react";
import type { EvidenceRecord } from "../lib/types";
import { parseAndCleanSummary } from "../lib/summaryParser";

export type InspectorNode = {
  id: string;
  label: string;
  kind: string;
  galaxyId: string;
  category: string;
  route: string;
  summary: string;
  scope: string;
  degree: number;
  rawEvidence?: EvidenceRecord;
};

export type InspectorEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
};

interface RelatedItem {
  edgeType: string;
  direction: "outgoing" | "incoming";
  otherId: string;
  otherLabel: string;
  otherKind: string;
  otherGalaxy: string;
}

interface Props {
  node: InspectorNode | null;
  related: RelatedItem[];
  galaxyColors: Record<string, string>;
  totals: { entities: number; edges: number; galaxies: number };
  onNavigate: (id: string) => void;
  onEnterNeighborhood: () => void;
}

const KIND_LABEL: Record<string, string> = {
  technique: "TECHNIQUE",
  chain: "ATTACK CHAIN",
  detection: "DETECTION",
  concept: "CONCEPT",
  lgtm_note: "RESEARCH NOTE",
  playbook: "PLAYBOOK",
  source: "SOURCE FILE",
  "source-extract": "CODE EXTRACT",
  documentation: "DOCUMENTATION",
  reference: "REFERENCE",
  pattern: "PATTERN",
};

const EDGE_LABEL: Record<string, string> = {
  enables: "enables",
  counters: "counters",
  detects: "detects",
  chains_to: "chains to",
  requires: "requires",
  implements: "implements",
  derived_from: "derived from",
  alternative_to: "alternative to",
  related: "related to",
  concept_link: "linked concept",
  reference: "references",
  enhances: "enhances",
};

const EDGE_COLORS: Record<string, string> = {
  enables: "var(--nav-accent)", counters: "#ff334c", detects: "#38ff6b",
  chains_to: "#ffb800", requires: "#e13ffb", implements: "#ffffff",
  derived_from: "#00e5bf", alternative_to: "#9d4edd", related: "#8896b0",
  concept_link: "#00b3e6", reference: "#6b7280", enhances: "#ffdc4c",
};

function badge(text: string, color?: string, bright = false) {
  return (
    <span style={{
      display: "inline-block",
      padding: "3px 8px",
      borderRadius: 3,
      background: color ? `${color}22` : "rgba(255,255,255,0.06)",
      border: color ? `1px solid ${color}66` : "1px solid rgba(255,255,255,0.14)",
      color: color ?? "#cbd5e1",
      fontSize: 10,
      fontWeight: bright ? 700 : 500,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      fontFamily: "monospace",
      marginRight: 6,
      marginBottom: 4,
    }}>{text}</span>
  );
}

export default function RichInspector({ node, related, galaxyColors, totals, onNavigate, onEnterNeighborhood }: Props) {
  const structured = useMemo(() => node ? parseAndCleanSummary(node.summary, node.label) : null, [node]);

  if (!node) {
    return (
      <aside className="inspector" aria-live="polite">
        <span className="eyebrow-bright" style={{ letterSpacing: "0.15em", fontSize: 11, color: "#00e5ff" }}>
          UNIVERSE INSPECTOR
        </span>
        <h2 style={{ marginTop: 8 }}>{totals.entities.toLocaleString()} nodes</h2>
        <p style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.5 }}>
          A living knowledge cosmos. Each star is a piece of offensive tradecraft.
          Click to inspect. Follow the light streams to discover chains, counters, and dependencies.
        </p>
        <div style={{ marginTop: 20 }}>
          <p style={{ fontSize: 11, opacity: 0.7, textTransform: "uppercase", letterSpacing: "0.1em" }}>Signal legend</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
            {Object.entries(EDGE_COLORS).map(([k, c]) => (
              <span key={k} style={{
                display: "inline-flex", alignItems: "center", gap: 4,
                fontSize: 10, fontFamily: "monospace", opacity: 0.85,
              }}>
                <span style={{ width: 18, height: 2, background: c, boxShadow: `0 0 6px ${c}` }} />
                {EDGE_LABEL[k]}
              </span>
            ))}
          </div>
        </div>
        <dl style={{ marginTop: 24, fontFamily: "monospace", fontSize: 11 }}>
          <dt style={{ opacity: 0.55 }}>Edges</dt><dd>{totals.edges.toLocaleString()}</dd>
          <dt style={{ opacity: 0.55 }}>Galaxies</dt><dd>{totals.galaxies}</dd>
        </dl>
      </aside>
    );
  }

  const galaxyColor = galaxyColors[node.galaxyId] || "var(--nav-accent)";
  const kindLabel = KIND_LABEL[node.kind] || node.kind.toUpperCase();

  const outgoing = related.filter(r => r.direction === "outgoing");
  const incoming = related.filter(r => r.direction === "incoming");

  const relatedGroupedByType = useMemo(() => {
    const groups = new Map<string, RelatedItem[]>();
    for (const r of related) {
      const key = `${r.direction}:${r.edgeType}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(r);
    }
    return Array.from(groups.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [related]);

  return (
    <aside className="inspector" aria-live="polite" style={{ fontFamily: "system-ui, sans-serif" }}>
      {/* Header — kind + galaxy */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10, alignItems: "center" }}>
        {badge(kindLabel, galaxyColor, true)}
        {badge(node.galaxyId, galaxyColor)}
        {structured?.tier && badge(`TIER ${structured.tier}`, "#ffb800", true)}
      </div>

      <h2 style={{ fontSize: 20, lineHeight: 1.2, margin: "6px 0 4px", color: "#fff" }}>{node.label}</h2>
      <p style={{ fontSize: 11, opacity: 0.5, fontFamily: "monospace", margin: 0 }}>{node.id}</p>

      {/* Kind-specific badges */}
      {structured?.mitre && structured.mitre.length > 0 && (
        <div style={{ marginTop: 14 }}>
          {structured.mitre.map((m: string) => badge(`MITRE ${m}`, "#ff2244"))}
        </div>
      )}

      {structured?.tags && structured.tags.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {structured.tags.slice(0, 10).map((t: string) => badge(t))}
        </div>
      )}

      {/* Summary */}
      <p style={{ marginTop: 14, fontSize: 13, lineHeight: 1.55, color: "#dae4f0" }}>
        {structured?.cleanSummary ?? node.summary}
      </p>

      <a href={`/Hugin${node.route}`} className="inspector-action-primary" style={{
        display: "inline-block", marginTop: 4, marginBottom: 12,
        color: galaxyColor, textDecoration: "none", fontSize: 12,
        fontFamily: "monospace", letterSpacing: "0.05em",
        borderBottom: `1px solid ${galaxyColor}80`, paddingBottom: 2,
      }}>Open full record →</a>

      {/* Kind-specific sections */}
      {structured?.files && structured.files.length > 0 && (
        <section style={{ marginTop: 14, padding: "10px 12px", background: "rgba(157, 124, 244, 0.06)", borderLeft: `2px solid var(--nav-accent)` }}>
          <p style={{ margin: 0, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", opacity: 0.7 }}>Implementation</p>
          {structured.files.map((f: string) => (
            <div key={f} style={{ fontFamily: "monospace", fontSize: 12, marginTop: 4, color: "#7dd8ff" }}>{f}</div>
          ))}
        </section>
      )}

      {structured?.linesOfInterest && structured.linesOfInterest.length > 0 && (
        <section style={{ marginTop: 8, padding: "10px 12px", background: "rgba(255, 184, 0, 0.04)", borderLeft: `2px solid #ffb800` }}>
          <p style={{ margin: 0, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", opacity: 0.7 }}>Key code locations</p>
          {structured.linesOfInterest.map((loi: string) => (
            <div key={loi} style={{ fontFamily: "monospace", fontSize: 11, marginTop: 4, color: "#ffcf5c" }}>{loi}</div>
          ))}
        </section>
      )}

      {node.rawEvidence && (
        <section style={{ marginTop: 8, padding: "10px 12px", background: "rgba(0,229,191,0.04)", borderLeft: `2px solid #00e5bf` }}>
          <p style={{ margin: 0, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", opacity: 0.7 }}>Evidence</p>
          <p style={{ fontSize: 12, color: "#a3f5e3", marginTop: 6, lineHeight: 1.4 }}>{node.rawEvidence.summary}</p>
          <div style={{ marginTop: 6 }}>
            {badge(`Q ${node.rawEvidence.qualityScore}`, "#00e5bf")}
            {badge(node.rawEvidence.topic, "#00e5bf")}
          </div>
        </section>
      )}

      {/* Meta */}
      <dl style={{ marginTop: 16, fontFamily: "monospace", fontSize: 11 }}>
        <dt style={{ opacity: 0.55 }}>Category</dt><dd>{node.category}</dd>
        <dt style={{ opacity: 0.55 }}>Scope</dt><dd>{node.scope}</dd>
        <dt style={{ opacity: 0.55 }}>Connections</dt><dd>{node.degree.toLocaleString()} · {outgoing.length} outgoing · {incoming.length} incoming</dd>
      </dl>

      <button className="button" type="button" onClick={onEnterNeighborhood}
        style={{ width: "100%", marginTop: 6, padding: "8px 10px",
                 background: `${galaxyColor}18`, border: `1px solid ${galaxyColor}66`,
                 color: galaxyColor, fontFamily: "monospace", fontSize: 12,
                 letterSpacing: "0.1em", textTransform: "uppercase", cursor: "pointer" }}>
        Explore neighborhood →
      </button>

      {/* Related, grouped by edge type */}
      {relatedGroupedByType.length > 0 && (
        <section style={{ marginTop: 18 }}>
          <p style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", opacity: 0.7, marginBottom: 8 }}>
            Signal traffic
          </p>
          {relatedGroupedByType.map(([key, items]) => {
            const [dir, type] = key.split(":");
            const color = EDGE_COLORS[type] || "#8896b0";
            const arrow = dir === "outgoing" ? "→" : "←";
            return (
              <div key={key} style={{ marginBottom: 12 }}>
                <p style={{ fontSize: 10, fontFamily: "monospace", opacity: 0.75, marginBottom: 4 }}>
                  <span style={{ color }}>{arrow}</span>{" "}
                  <span style={{ color }}>{EDGE_LABEL[type] || type}</span>{" "}
                  <span style={{ opacity: 0.55 }}>({items.length})</span>
                </p>
                {items.slice(0, 6).map(r => {
                  const gCol = galaxyColors[r.otherGalaxy] || "#8896b0";
                  return (
                    <button key={r.otherId} onClick={() => onNavigate(r.otherId)}
                      style={{
                        display: "block", width: "100%", textAlign: "left",
                        padding: "5px 8px", marginBottom: 2,
                        background: "transparent", border: "1px solid transparent",
                        color: "#dae4f0", fontSize: 12, cursor: "pointer",
                        borderRadius: 2, fontFamily: "inherit",
                        borderLeft: `2px solid ${gCol}55`,
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = `${gCol}12`)}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                      <span style={{ color: gCol, fontSize: 10, fontFamily: "monospace", opacity: 0.8 }}>
                        {KIND_LABEL[r.otherKind]?.slice(0, 4) || "NODE"}
                      </span>
                      <span style={{ marginLeft: 8 }}>{r.otherLabel}</span>
                    </button>
                  );
                })}
                {items.length > 6 && (
                  <p style={{ fontSize: 10, opacity: 0.5, fontFamily: "monospace", marginLeft: 8 }}>
                    + {items.length - 6} more
                  </p>
                )}
              </div>
            );
          })}
        </section>
      )}
    </aside>
  );
}
