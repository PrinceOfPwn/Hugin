import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import type { DatasetManifest } from "../lib/types";

export default function RavenFlight({ manifest }: { manifest: DatasetManifest }) {
  const host = useRef<HTMLDivElement>(null);
  const [galaxy, setGalaxy] = useState(() => new URLSearchParams(location.search).get("galaxy") || "all");

  useEffect(() => {
    if (!host.current) return;
    let frame = 0;
    let stopped = false;
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x050408, 0.00075);
    const camera = new THREE.PerspectiveCamera(68, host.current.clientWidth / host.current.clientHeight, 1, 5000);
    camera.position.set(0, 0, 850);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(host.current.clientWidth, host.current.clientHeight);
    host.current.appendChild(renderer.domElement);

    fetch(`/Hugin${manifest.assets.graph}`).then((response) => response.json()).then(({ nodes }) => {
      const visible = nodes.filter((node: any) => !node.isGalaxy && (galaxy === "all" || node.galaxyId === galaxy));
      const positions = new Float32Array(visible.length * 3);
      const colors = new Float32Array(visible.length * 3);
      visible.forEach((node: any, index: number) => {
        positions[index * 3] = node.x;
        positions[index * 3 + 1] = node.y;
        positions[index * 3 + 2] = (Number.parseInt(node.id.slice(-4).replace(/\W/g, ""), 16) || index) % 500 - 250;
        const color = new THREE.Color(node.color); colors.set([color.r, color.g, color.b], index * 3);
      });
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
      geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
      const stars = new THREE.Points(geometry, new THREE.PointsMaterial({ size: 4, transparent: true, opacity: .86, vertexColors: true, blending: THREE.AdditiveBlending, depthWrite: false }));
      scene.add(stars);
      const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
      const animate = () => {
        if (stopped) return;
        if (!reduced) { stars.rotation.z += .00035; camera.position.z = 780 + Math.sin(performance.now() / 5000) * 80; }
        renderer.render(scene, camera);
        frame = requestAnimationFrame(animate);
      };
      animate();
    });

    const resize = () => { if (!host.current) return; camera.aspect = host.current.clientWidth / host.current.clientHeight; camera.updateProjectionMatrix(); renderer.setSize(host.current.clientWidth, host.current.clientHeight); };
    addEventListener("resize", resize);
    return () => { stopped = true; cancelAnimationFrame(frame); removeEventListener("resize", resize); renderer.dispose(); renderer.domElement.remove(); };
  }, [manifest, galaxy]);

  return <section style={{height: "calc(100vh - 75px)", position: "relative", overflow: "hidden"}}>
    <div className="graph-controls"><a className="button" href="/Hugin/graph/">← Universe</a><select aria-label="Flight galaxy" value={galaxy} onChange={(event) => setGalaxy(event.target.value)}><option value="all">All galaxies</option>{["techniques", "internals", "defenses", "chains", "atlas", "sources", "gaps", "architecture"].map((value) => <option key={value}>{value}</option>)}</select></div>
    <div ref={host} style={{width: "100%", height: "100%"}} role="img" aria-label="Optional Raven Flight through the selected HUGIN galaxy" />
    <div style={{position: "absolute", left: 24, bottom: 24, maxWidth: 430}}><p className="eyebrow">Optional experience</p><h1 style={{fontSize: "clamp(2rem,5vw,4rem)"}}>Raven Flight</h1><p className="lede">A lightweight, lazy-loaded Three.js passage through the selected galaxy. The catalog and permanent pages remain the primary accessible interface.</p></div>
  </section>;
}
