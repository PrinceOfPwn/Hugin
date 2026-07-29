import { useEffect, useState } from "react";

const STORAGE_KEY = "hugin.tourSeen";

type Step = {
  title: string;
  body: string;
};

const STEPS: Step[] = [
  { title: "Zoom",    body: "Scroll or pinch to zoom into the universe." },
  { title: "Rotate",  body: "Click and drag to orbit around the galaxies." },
  { title: "Inspect", body: "Click any node to see its details. Double-click to fly there." },
  { title: "Search",  body: "Press Ctrl+K (or /) to search anything by name or tag." },
];

export default function WelcomeTour() {
  const [mounted, setMounted] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(STORAGE_KEY) !== "1";
  });
  const [step, setStep] = useState(0);
  const [visible, setVisible] = useState(false); // controls fade
  const [cardKey, setCardKey] = useState(0);     // remounts card on step change to re-trigger the fade

  useEffect(() => {
    if (!mounted) return;
    // Trigger fade-in on next frame.
    const id = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(id);
  }, [mounted]);

  useEffect(() => {
    if (!mounted) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") finish();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mounted]);

  const finish = () => {
    try { window.localStorage.setItem(STORAGE_KEY, "1"); } catch {}
    setVisible(false);
    // Wait for fade-out before unmount.
    setTimeout(() => setMounted(false), 300);
  };

  const next = () => {
    if (step >= STEPS.length - 1) { finish(); return; }
    setStep((s) => s + 1);
    setCardKey((k) => k + 1);
  };

  if (!mounted) return null;

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 90,
        background: "rgba(0,0,0,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        opacity: visible ? 1 : 0,
        transition: "opacity 300ms ease",
        pointerEvents: visible ? "auto" : "none",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) { /* ignore backdrop click; use Skip */ } }}
    >
      <div
        key={cardKey}
        style={{
          maxWidth: 380,
          padding: "24px 28px",
          background: "rgba(20,20,30,0.85)",
          border: "1px solid rgba(0,240,255,0.25)",
          borderRadius: 14,
          backdropFilter: "blur(14px)",
          WebkitBackdropFilter: "blur(14px)",
          boxShadow: "0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,240,255,0.1)",
          color: "#e8f0ff",
          fontFamily: "system-ui, sans-serif",
          animation: "hugin-tour-in 300ms ease",
        }}
      >
        <div style={{
          fontFamily: "monospace",
          fontSize: 10,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          color: "#00f0ff",
          marginBottom: 8,
          opacity: 0.75,
        }}>
          Step {step + 1} / {STEPS.length}
        </div>
        <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 10, letterSpacing: "-0.01em" }}>
          {current.title}
        </div>
        <div style={{ fontSize: 14, lineHeight: 1.55, opacity: 0.82, marginBottom: 22 }}>
          {current.body}
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <button
            type="button"
            onClick={finish}
            style={{
              background: "transparent",
              border: "none",
              color: "rgba(255,255,255,0.5)",
              fontFamily: "monospace",
              fontSize: 11,
              cursor: "pointer",
              padding: 0,
              letterSpacing: "0.08em",
            }}
          >
            Skip tour
          </button>
          <button
            type="button"
            onClick={next}
            style={{
              padding: "8px 18px",
              background: "#00f0ff",
              color: "#001018",
              border: "none",
              borderRadius: 999,
              fontFamily: "monospace",
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              cursor: "pointer",
            }}
          >
            {isLast ? "Done" : "Next"}
          </button>
        </div>

        <style>{`
          @keyframes hugin-tour-in {
            from { opacity: 0; transform: translateY(8px); }
            to   { opacity: 1; transform: translateY(0); }
          }
        `}</style>
      </div>
    </div>
  );
}
