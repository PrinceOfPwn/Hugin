export interface StructuredMetadata {
  cleanSummary: string;
  tier?: string;
  mitre?: string[];
  files?: string[];
  linesOfInterest?: string[];
  keyFunctions?: string[];
  keyStructs?: string[];
  keyConstants?: string[];
  minWindows?: string;
  tags?: string[];
  requires?: string[];
  enables?: string[];
}

export function parseAndCleanSummary(rawText: string, fallbackTitle = ""): StructuredMetadata {
  if (!rawText) {
    return { cleanSummary: fallbackTitle ? `Technical specification for ${fallbackTitle}.` : "" };
  }

  const text = String(rawText);

  // Extract structured fields via regex before cleaning
  const tierMatch = text.match(/\btier:\s*([A-S]\b)/i);
  const mitreMatch = text.match(/\bmitre:\s*(?:\[([^\]]+)\]|(\S+))/i);
  const minWinMatch = text.match(/\bmin_windows:\s*["']?([^"'\r\n]+)["']?/i);
  const tagsMatch = text.match(/\btags:\s*\[([^\]]+)\]/i);
  const requiresMatch = text.match(/\brequires:\s*\[([^\]]+)\]/i);
  const enablesMatch = text.match(/\benables:\s*\[([^\]]+)\]/i);

  // Extract files
  const filesSet = new Set<string>();
  const fileRegex = /\bfile:\s*(\S+)/gi;
  let fileM: RegExpExecArray | null;
  while ((fileM = fileRegex.exec(text)) !== null) {
    filesSet.add(fileM[1]);
  }
  const vaultRefMatch = text.match(/\bvault_references:\s*([^\n\r]+)/i);
  if (vaultRefMatch) {
    vaultRefMatch[1].split(/\s+/).forEach((f) => {
      if (f.includes("/") || f.endsWith(".rs") || f.endsWith(".c") || f.endsWith(".h")) {
        filesSet.add(f);
      }
    });
  }

  // Extract lines of interest
  const linesOfInterest: string[] = [];
  const loiRegex = /(L\d+-L\d+:[^\n\r\t]+)/gi;
  let loiM: RegExpExecArray | null;
  while ((loiM = loiRegex.exec(text)) !== null) {
    linesOfInterest.push(loiM[1].trim());
  }

  // Extract key functions
  const keyFunctionsSet = new Set<string>();
  const funcRegex = /\bkey_functions:\s*([^\n\r]+)/gi;
  let funcM: RegExpExecArray | null;
  while ((funcM = funcRegex.exec(text)) !== null) {
    funcM[1].split(/\s+/).forEach((fn) => {
      const clean = fn.replace(/[(),]/g, "").trim();
      if (clean && clean.length > 2 && !clean.includes(":")) {
        keyFunctionsSet.add(clean);
      }
    });
  }

  // Clean raw metadata blocks out of the summary text
  let cleaned = text
    // Remove inline metadata key-value pairs
    .replace(/\b(?:id|name|category|tier|mitre|analyzed_by|analysis_date|confidence|requires|enables|vault_references|implements|min_windows|needs_admin|tags):\s*(?:\[[^\]]*\]|"[^"]*"|'[^']*'|\S+)/gi, "")
    // Remove file: and lines_of_interest blocks
    .replace(/\bfile:\s*\S+/gi, "")
    .replace(/\bkey_functions:\s*[^\n\r]*/gi, "")
    .replace(/\bkey_structs:\s*[^\n\r]*/gi, "")
    .replace(/\bkey_constants:\s*[^\n\r]*/gi, "")
    .replace(/L\d+-L\d+:[^\n\r]*/gi, "")
    .replace(/\b\w+=\w+/g, "") // remove constants like NTDLL_HASH=0x1edab0ed
    .replace(/\[\s*0x[0-9A-Fa-f, ]+\s*\]/g, "")
    // Cleanup multiple spaces/newlines
    .replace(/\s+/g, " ")
    .trim();

  // If text starts with "Operator Playbook TL;DR", format nicely
  cleaned = cleaned.replace(/^(?:Operator Playbook TL;DR\s*[-—:]?\s*)*/i, "").trim();

  if (!cleaned || cleaned.length < 15) {
    cleaned = fallbackTitle
      ? `High-level technical specification and operational analysis for ${fallbackTitle}.`
      : "High-level technical specification and operational analysis.";
  }

  const mitreList: string[] = [];
  if (mitreMatch) {
    const raw = mitreMatch[1] || mitreMatch[2] || "";
    raw.split(/[\s,]+/).forEach((t) => {
      const clean = t.trim().replace(/^['"]|['"]$/g, "");
      if (clean) mitreList.push(clean);
    });
  }

  const parseArray = (str?: string) =>
    str
      ? str
          .split(/[\s,]+/)
          .map((s) => s.trim().replace(/^['"]|['"]$/g, ""))
          .filter(Boolean)
      : undefined;

  return {
    cleanSummary: cleaned,
    tier: tierMatch ? tierMatch[1].toUpperCase() : undefined,
    mitre: mitreList.length > 0 ? mitreList : undefined,
    files: Array.from(filesSet),
    linesOfInterest: linesOfInterest.length > 0 ? linesOfInterest : undefined,
    keyFunctions: Array.from(keyFunctionsSet),
    minWindows: minWinMatch ? minWinMatch[1] : undefined,
    tags: parseArray(tagsMatch?.[1]),
    requires: parseArray(requiresMatch?.[1]),
    enables: parseArray(enablesMatch?.[1]),
  };
}
