import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

function ipv4Octets(address) {
  const parts = address.split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : null;
}

export function isPublicIp(address) {
  const raw = String(address ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  const version = isIP(raw);
  if (version === 4) {
    const octets = ipv4Octets(raw);
    if (!octets) return false;
    const [a, b] = octets;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (version === 6) {
    if (raw === "::" || raw === "::1") return false;
    if (raw.startsWith("fc") || raw.startsWith("fd") || raw.startsWith("fe8") || raw.startsWith("fe9") || raw.startsWith("fea") || raw.startsWith("feb") || raw.startsWith("ff")) return false;
    const mapped = raw.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPublicIp(mapped[1]);
    return true;
  }
  return false;
}

export async function assertPublicHttpUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`Invalid source URL: ${value}`); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("External source URL must use http(s)");
  if (url.username || url.password) throw new Error("External source URL must not contain credentials");

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost")) throw new Error("External source host must be public");
  if (isIP(hostname)) {
    if (!isPublicIp(hostname)) throw new Error(`External source resolves to non-public address ${hostname}`);
    return url;
  }

  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length) throw new Error(`External source host did not resolve: ${hostname}`);
  const nonPublic = addresses.find(({ address }) => !isPublicIp(address));
  if (nonPublic) throw new Error(`External source host resolves to non-public address ${nonPublic.address}`);
  return url;
}

/** Fetch exactly the validated destination. Redirects are rejected so an
 * otherwise-public URL cannot pivot the Actions runner into a private network. */
export async function fetchPublicNoRedirect(value, options = {}) {
  const url = await assertPublicHttpUrl(value);
  const response = await fetch(url, { ...options, redirect: "manual" });
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location") || "<missing>";
    await response.body?.cancel("redirects are not allowed").catch(() => {});
    throw new Error(`External source redirects are not allowed (${response.status} -> ${location})`);
  }
  return response;
}
