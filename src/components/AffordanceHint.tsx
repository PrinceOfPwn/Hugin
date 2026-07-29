import { useEffect, useState } from "react";

// Module-level flag — one render per SPA session, even if the component
// remounts (React StrictMode dev double-invoke, page-level navigation, etc.).
let SHOWN = false;

export default function AffordanceHint() {
  const [mounted, setMounted] = useState(!SHOWN);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!mounted) return;
    SHOWN = true;
    // Fade in.
    const inId = requestAnimationFrame(() => setVisible(true));

    // Fade out at 8s, unmount ~600ms later.
    const outT = window.setTimeout(() => setVisible(false), 8000);
    const unmountT = window.setTimeout(() => setMounted(false), 8600);

    // Any user interaction dismisses it early.
    const dismiss = () => { setVisible(false); window.setTimeout(() => setMounted(false), 600); };
    const listeners: Array<[string, EventListener]> = [
      ["pointerdown", dismiss],
      ["keydown", dismiss],
      ["wheel", dismiss],
    ];
    listeners.forEach(([ev, fn]) => window.addEventListener(ev, fn, { passive: true } as AddEventListenerOptions));

    return () => {
      cancelAnimationFrame(inId);
      window.clearTimeout(outT);
      window.clearTimeout(unmountT);
      listeners.forEach(([ev, fn]) => window.removeEventListener(ev, fn));
    };
  }, [mounted]);

  if (!mounted) return null;

  return (
    <div
      style={{
        position: "absolute",
        bottom: 24,
        left: "50%",
        transform: "translateX(-50%)",
        padding: "8px 20px",
        borderRadius: 999,
        background: "rgba(15,15,25,0.6)",
        border: "1px solid rgba(255,255,255,0.08)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        fontFamily: "monospace",
        fontSize: 12,
        letterSpacing: "0.05em",
        color: "rgba(255,255,255,0.75)",
        opacity: visible ? 1 : 0,
        transition: "opacity 600ms ease",
        pointerEvents: "none",
        zIndex: 20,
        whiteSpace: "nowrap",
      }}
    >
      Try: scroll to zoom · drag to rotate · ⌘K to search
    </div>
  );
}
