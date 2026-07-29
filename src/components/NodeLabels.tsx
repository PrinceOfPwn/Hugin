import { useMemo, useRef, useState } from "react";
import { useFrame } from "@react-three/fiber";
import { Text } from "@react-three/drei";
import * as THREE from "three";
import type { NodeDatum } from "./NodeCloud";

// ═════════════════════════════════════════════════════════════════════════════
//  NodeLabels — sparse SDF text labels for the universe. Always shows
//  attractors + selected + hovered; fills the rest of the budget with the
//  nearest nodes to the camera. Selection is throttled to every 300ms so we
//  don't rebuild the label set every frame.
//
//  Positions are read from the (static) NodeDatum.position — server-computed
//  layout. Attractors don't orbit so this is accurate for them; satellite
//  labels sit at the initial orbit anchor which is close enough for legibility
//  without needing to pipe live positions across components.
// ═════════════════════════════════════════════════════════════════════════════

export interface LabelResolver {
  (id: string): string | undefined;
}

interface Props {
  nodes: NodeDatum[];
  getLabel: LabelResolver;
  selectedId?: string | null;
  hoveredId?: string | null;
  maxLabels?: number;
}

function truncate(s: string, max = 32): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

export default function NodeLabels({
  nodes,
  getLabel,
  selectedId,
  hoveredId,
  maxLabels = 30,
}: Props) {
  const [pickIds, setPickIds] = useState<Set<string>>(() => new Set());
  const lastPickRef = useRef<number>(-1);
  const camPos = useRef(new THREE.Vector3());

  // Attractors are stable across frames — precompute once.
  const attractors = useMemo(
    () => nodes.filter((n) => n.isAttractor).map((n) => n.id),
    [nodes]
  );

  useFrame(({ camera, clock }) => {
    const t = clock.getElapsedTime();
    if (t - lastPickRef.current < 0.3) return;
    lastPickRef.current = t;
    camPos.current.copy(camera.position);

    const picks = new Set<string>();
    for (const id of attractors) {
      if (picks.size >= maxLabels) break;
      picks.add(id);
    }
    if (selectedId) picks.add(selectedId);
    if (hoveredId) picks.add(hoveredId);

    const remaining = maxLabels - picks.size;
    if (remaining > 0) {
      const scored: Array<{ id: string; d: number }> = [];
      for (const n of nodes) {
        if (picks.has(n.id)) continue;
        const d = camPos.current.distanceToSquared(n.position);
        scored.push({ id: n.id, d });
      }
      scored.sort((a, b) => a.d - b.d);
      for (let i = 0; i < Math.min(remaining, scored.length); i++) {
        picks.add(scored[i].id);
      }
    }

    // Only trigger re-render if the pick set actually changed.
    let same = picks.size === pickIds.size;
    if (same) {
      for (const id of picks) {
        if (!pickIds.has(id)) { same = false; break; }
      }
    }
    if (!same) setPickIds(picks);
  });

  const items = useMemo(() => {
    if (pickIds.size === 0) return [] as NodeDatum[];
    return nodes.filter((n) => pickIds.has(n.id));
  }, [nodes, pickIds]);

  if (items.length === 0) return null;

  return (
    <group renderOrder={100}>
      {items.map((n) => {
        const yOffset = (n.size ?? 3) * 1.5;
        const raw = getLabel(n.id) ?? n.id;
        const txt = truncate(raw, 32);
        // Fixed world-space font size — three.js perspective already gives us
        // natural inverse-distance shrink; keep base big enough to survive
        // bloom at far range.
        const fontSize = Math.max(12, (n.size ?? 3) * 4);
        return (
          <Text
            key={n.id}
            position={[n.position.x, n.position.y + yOffset, n.position.z]}
            fontSize={fontSize}
            color="#ffffff"
            outlineWidth={0.15}
            outlineColor="#000000"
            anchorX="center"
            anchorY="bottom"
            frustumCulled
            renderOrder={100}
            depthOffset={-1}
          >
            {txt}
          </Text>
        );
      })}
    </group>
  );
}
