import { useMemo } from "react";
import * as THREE from "three";

export type EdgeDatum = {
  source: string;
  target: string;
  type: string;
};

interface Props {
  edges: EdgeDatum[];
  positions: Map<string, THREE.Vector3>;
  focusColor?: string;   // when set, ALL edges use this color (e.g. selection highlight)
  opacity?: number;
}

// Per-type semantic color. Kept in ONE place so the legend and the render agree.
export const EDGE_COLOR: Record<string, string> = {
  enables:         "#00f0ff",
  counters:        "#ff2244",
  detects:         "#39ff14",
  chains_to:       "#ffb700",
  requires:        "#e040fb",
  implements:      "#ffffff",
  derived_from:    "#00e5bf",
  alternative_to:  "#9d4edd",
  related:         "#7788aa",
  concept_link:    "#00b0ff",
  reference:       "#556677",
  enhances:        "#ffd700",
  similar_to:      "#334455",   // used only when explicitly enabled
};

// ═════════════════════════════════════════════════════════════════════════════
//  EdgeSet — plain LineSegments with per-vertex colors. No shader branching,
//  no additive-blending storm. Additive is off; opacity blend is what makes
//  edges legible on the dark background. Missing endpoints are skipped.
// ═════════════════════════════════════════════════════════════════════════════

export default function EdgeSet({ edges, positions, focusColor, opacity = 0.6 }: Props) {
  const [geometry, material] = useMemo(() => {
    const valid: EdgeDatum[] = [];
    for (const e of edges) if (positions.has(e.source) && positions.has(e.target)) valid.push(e);

    const n = valid.length;
    const pos = new Float32Array(n * 6);
    const col = new Float32Array(n * 6);
    const c = new THREE.Color();

    for (let i = 0; i < n; i++) {
      const e = valid[i];
      const s = positions.get(e.source)!;
      const t = positions.get(e.target)!;
      const b6 = i * 6;
      pos[b6]     = s.x; pos[b6+1] = s.y; pos[b6+2] = s.z;
      pos[b6+3]   = t.x; pos[b6+4] = t.y; pos[b6+5] = t.z;

      c.set(focusColor || EDGE_COLOR[e.type] || "#556677");
      col[b6]   = c.r; col[b6+1] = c.g; col[b6+2] = c.b;
      col[b6+3] = c.r; col[b6+4] = c.g; col[b6+5] = c.b;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    geo.setAttribute("color",    new THREE.BufferAttribute(col, 3));

    const mat = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity,
      depthWrite: false,
    });

    return [geo, mat];
  }, [edges, positions, focusColor, opacity]);

  if (edges.length === 0) return null;
  return <lineSegments geometry={geometry} material={material} frustumCulled={false} />;
}
