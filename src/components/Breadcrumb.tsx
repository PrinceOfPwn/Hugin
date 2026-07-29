import { Fragment } from "react";

interface Props {
  galaxyLabel?: string | null;
  nodeLabel?: string | null;
  onReset: () => void;
  onGalaxyClick: () => void;
}

const CHIP_STYLE: React.CSSProperties = {
  position: "absolute",
  top: 16,
  left: 16,
  zIndex: 25,
  maxWidth: 400,
  padding: "8px 14px",
  borderRadius: 999,
  background: "rgba(20,20,30,0.55)",
  border: "1px solid rgba(255,255,255,0.08)",
  backdropFilter: "blur(10px)",
  WebkitBackdropFilter: "blur(10px)",
  fontFamily: "monospace",
  fontSize: 11,
  color: "rgba(255,255,255,0.85)",
  letterSpacing: "0.06em",
  display: "flex",
  alignItems: "center",
  gap: 8,
  userSelect: "none",
  boxShadow: "0 4px 24px rgba(0,0,0,0.35)",
};

const SEP: React.CSSProperties = {
  color: "rgba(255,255,255,0.4)",
  fontSize: 12,
};

const CLICKABLE: React.CSSProperties = {
  cursor: "pointer",
  color: "rgba(255,255,255,0.7)",
  transition: "color 120ms ease",
  background: "transparent",
  border: "none",
  padding: 0,
  fontFamily: "inherit",
  fontSize: "inherit",
  letterSpacing: "inherit",
};

const ACTIVE: React.CSSProperties = {
  color: "#00f0ff",
  fontWeight: 600,
};

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

export default function Breadcrumb({ galaxyLabel, nodeLabel, onReset, onGalaxyClick }: Props) {
  // Build the layer list. "Universe" is always present.
  type Layer = { key: string; label: string; onClick?: () => void };
  const layers: Layer[] = [{ key: "u", label: "Universe", onClick: onReset }];
  if (galaxyLabel) layers.push({ key: "g", label: galaxyLabel, onClick: onGalaxyClick });
  if (nodeLabel) layers.push({ key: "n", label: truncate(nodeLabel, 40) });

  return (
    <div style={CHIP_STYLE} role="navigation" aria-label="Breadcrumb">
      {layers.map((layer, i) => {
        const isLast = i === layers.length - 1;
        const isClickable = !isLast && !!layer.onClick;
        return (
          <Fragment key={layer.key}>
            {i > 0 && <span style={SEP}>›</span>}
            {isClickable ? (
              <button
                type="button"
                onClick={layer.onClick}
                style={CLICKABLE}
                onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#e8f0ff"; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "rgba(255,255,255,0.7)"; }}
              >
                {layer.label}
              </button>
            ) : (
              <span style={isLast ? ACTIVE : { color: "rgba(255,255,255,0.7)" }}>
                {layer.label}
              </span>
            )}
          </Fragment>
        );
      })}
    </div>
  );
}
