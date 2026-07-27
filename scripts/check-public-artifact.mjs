import fs from "node:fs";
import path from "node:path";

const root = path.resolve("dist");
const errors = [];
const readable = new Set([".html", ".json", ".js", ".css", ".xml", ".txt", ".svg"]);
const forbidden = [
  { label: "removed copy", pattern: /Nothing disappears because it lacks an original relation/i },
  // Keep this uppercase-only so ordinary CSS values such as `sans-serif`
  // do not trigger the provider-name privacy gate.
  { label: "named training provider", pattern: /\bSANS(?:\s+\x49\x6e\x73\x74\x69\x74\x75\x74\x65)?\b/ },
  { label: "course identifier", pattern: /\bSEC\d{3}(?:\.\d+)?\b/i },
  { label: "named research course", pattern: /\bCRTO\b|\bCertified\s+\x52\x65\x64\s+\x54\x65\x61\x6d\s+\x4f\x70\x65\x72\x61\x74\x6f\x72\b/i },
  { label: "named development course", pattern: /\x4d\x61\x6c\x44\x65\x76/i },
  { label: "named training provider", pattern: /\x4f\x66\x66\x53\x65\x63|\bOffensive\s+\x53\x65\x63\x75\x72\x69\x74\x79\b/i },
  { label: "local username", pattern: /\b(?:\x65\x6d\x69\x70\x65\x72\x61\x6c\x74\x61|\x74\x61\x6d\x61\x72\x69\x73\x6b)\b/i },
  { label: "absolute owner path", pattern: /\/(?:Users|home)\/(?:\x65\x6d\x69\x70\x65\x72\x61\x6c\x74\x61|\x74\x61\x6d\x61\x72\x69\x73\x6b|\x73\x6f\x75\x72\x63\x65\x2d\x6f\x77\x6e\x65\x72)(?:\/|\\)/i },
  { label: "absolute Windows user path", pattern: /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)/i }
];

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

if (!fs.existsSync(root)) {
  throw new Error("Missing dist/. Run the site build first.");
}

for (const file of walk(root)) {
  if (!readable.has(path.extname(file))) continue;
  const text = fs.readFileSync(file, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(text)) {
      errors.push(`${path.relative(root, file)} contains forbidden ${rule.label}`);
    }
  }
}

if (fs.existsSync(path.join(root, "atlas"))) {
  errors.push("Raw Atlas reference routes must not be generated");
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log("Public artifact is anonymous and contains no raw evidence routes.");
