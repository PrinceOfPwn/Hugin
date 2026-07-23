import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import type { DatasetManifest } from "../lib/types";

const GALAXIES = [
  "techniques",
  "internals",
  "defenses",
  "chains",
  "evidence",
  "sources",
  "gaps",
  "architecture"
];

export default function RavenFlight({ manifest }: { manifest: DatasetManifest }) {
  const host = useRef<HTMLDivElement>(null);
  const [galaxy, setGalaxy] = useState(() =>
    typeof window === "undefined" ? "all" : new URLSearchParams(window.location.search).get("galaxy") || "all"
  );

  useEffect(() => {
    if (!host.current) return;
    let frame = 0;
    let stopped = false;
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x08070c);
    scene.fog = new THREE.FogExp2(0x08070c, 0.0008);
    const camera = new THREE.PerspectiveCamera(
      68,
      host.current.clientWidth / host.current.clientHeight,
      1,
      5000
    );
    camera.position.set(0, 0, 850);
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(host.current.clientWidth, host.current.clientHeight);
    host.current.appendChild(renderer.domElement);

    fetch(`/Hugin${manifest.assets.graph}`)
      .then((response) => response.json())
      .then(({ nodes }) => {
        const visible = nodes.filter((node: any) =>
          !node.isGalaxy
          && node.scope === "core"
          && (galaxy === "all" || node.galaxyId === galaxy)
        );
        const positions = new Float32Array(visible.length * 3);
        const colors = new Float32Array(visible.length * 3);
        visible.forEach((node: any, index: number) => {
          positions[index * 3] = node.x;
          positions[index * 3 + 1] = node.y;
          positions[index * 3 + 2] = (Number.parseInt(node.id.slice(-4).replace(/\W/g, ""), 16) || index) % 500 - 250;
          const color = new THREE.Color(node.color);
          colors.set([color.r, color.g, color.b], index * 3);
        });

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
        const stars = new THREE.Points(
          geometry,
          new THREE.PointsMaterial({
            size: 3,
            transparent: true,
            opacity: 0.78,
            vertexColors: true,
            depthWrite: false
          })
        );
        scene.add(stars);

        const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
        const animate = () => {
          if (stopped) return;
          if (!reduced) {
            stars.rotation.z += 0.0002;
            camera.position.z = 800 + Math.sin(performance.now() / 6000) * 55;
          }
          renderer.render(scene, camera);
          if (!reduced) frame = requestAnimationFrame(animate);
        };
        animate();
      });

    const resize = () => {
      if (!host.current) return;
      camera.aspect = host.current.clientWidth / host.current.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(host.current.clientWidth, host.current.clientHeight);
    };
    addEventListener("resize", resize);

    return () => {
      stopped = true;
      cancelAnimationFrame(frame);
      removeEventListener("resize", resize);
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, [manifest, galaxy]);

  return (
    <section style={{ height: "calc(100vh - 68px)", minHeight: 620, position: "relative", overflow: "hidden" }}>
      <div className="graph-controls">
        <a className="button" href="/Hugin/graph/">← Universe</a>
        <select aria-label="Flight galaxy" value={galaxy} onChange={(event) => setGalaxy(event.target.value)}>
          <option value="all">All galaxies</option>
          {GALAXIES.map((value) => <option value={value} key={value}>{value}</option>)}
        </select>
      </div>
      <div
        ref={host}
        style={{ width: "100%", height: "100%" }}
        role="img"
        aria-label="Optional Raven Flight through the selected HUGIN galaxy"
      />
      <div style={{ position: "absolute", left: 24, bottom: 24, maxWidth: 460 }}>
        <p className="eyebrow">Optional experience</p>
        <h1 style={{ fontSize: "clamp(2.2rem,5vw,3.7rem)", marginBottom: 12 }}>Raven Flight</h1>
        <p className="lede">
          A quiet, lazy-loaded passage through the selected galaxy. Catalog and graph remain
          the primary accessible interfaces.
        </p>
      </div>
    </section>
  );
}
