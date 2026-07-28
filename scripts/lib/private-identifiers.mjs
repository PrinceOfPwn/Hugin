/**
 * Runtime-only private identifier helpers.
 *
 * The tokens are deliberately encoded so a source checkout and published
 * bundles do not expose owner handles at a glance. They are decoded only in
 * the Node.js sanitization pipeline, never emitted as public data.
 */
const decodeToken = (token) => Buffer.from(token, "base64").toString("utf8");

const privateTokens = [
  decodeToken("ZW1pcGVyYWx0YQ=="),
  decodeToken("dGFtYXJpc2s="),
  decodeToken("b2Zmc2VjZXhhbQ==")
];

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const privateIdentifierSource = `\\b(?:${privateTokens.map(escapeRegex).join("|")})\\b`;
const privateRoutePattern = new RegExp(
  `https?:\\/\\/[^\\s)\\]}>"']*(?:${privateTokens.map(escapeRegex).join("|")})[^\\s)\\]}>"']*`,
  "gi"
);

// These expressions intentionally have no global flag: callers also use
// them repeatedly as validation gates, where global RegExp state is unsafe.
export const privateIdentifierPattern = new RegExp(privateIdentifierSource, "i");
export const emailAddressPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;

export function redactPrivateIdentifiers(value, replacement = "source-owner") {
  return String(value || "").replace(new RegExp(privateIdentifierSource, "gi"), replacement);
}

export function redactEmailAddresses(value, replacement = "[private-email]") {
  return String(value || "").replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement);
}

export function redactPrivateRoutes(value, replacement = "[private-source]") {
  return String(value || "").replace(privateRoutePattern, replacement);
}
