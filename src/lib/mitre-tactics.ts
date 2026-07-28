// Keep in sync with the peer file mitre-tactics.{ts,mjs}
// MITRE ATT&CK v14 tactic dictionary + technique→tactic lookup.
// Kept intentionally lightweight — we don't need the full corpus, just enough
// to power the Explorer's tactic-filter facet and the /mitre matrix page.
// Unknown techniques fall through to "unknown".

export interface MitreTactic {
  id: string;        // e.g. "TA0002"
  slug: string;      // e.g. "execution"
  name: string;      // e.g. "Execution"
}

export const MITRE_TACTICS: MitreTactic[] = [
  { id: "TA0043", slug: "reconnaissance", name: "Reconnaissance" },
  { id: "TA0042", slug: "resource-development", name: "Resource Development" },
  { id: "TA0001", slug: "initial-access", name: "Initial Access" },
  { id: "TA0002", slug: "execution", name: "Execution" },
  { id: "TA0003", slug: "persistence", name: "Persistence" },
  { id: "TA0004", slug: "privilege-escalation", name: "Privilege Escalation" },
  { id: "TA0005", slug: "defense-evasion", name: "Defense Evasion" },
  { id: "TA0006", slug: "credential-access", name: "Credential Access" },
  { id: "TA0007", slug: "discovery", name: "Discovery" },
  { id: "TA0008", slug: "lateral-movement", name: "Lateral Movement" },
  { id: "TA0009", slug: "collection", name: "Collection" },
  { id: "TA0011", slug: "command-and-control", name: "Command and Control" },
  { id: "TA0010", slug: "exfiltration", name: "Exfiltration" },
  { id: "TA0040", slug: "impact", name: "Impact" },
];

// Extended tactic shape for the /mitre matrix page.
export type Tactic = {
  id: string;
  name: string;
  slug: string;
  shortDesc: string;
  order: number;
};

// 14 Enterprise tactics in kill-chain order (paired with MITRE_TACTICS above).
export const TACTICS: Tactic[] = [
  { id: "TA0043", name: "Reconnaissance",         slug: "reconnaissance",         shortDesc: "Gather information to plan future operations.",             order: 1 },
  { id: "TA0042", name: "Resource Development",   slug: "resource-development",   shortDesc: "Establish resources to support operations.",                order: 2 },
  { id: "TA0001", name: "Initial Access",         slug: "initial-access",         shortDesc: "Get into the target network.",                              order: 3 },
  { id: "TA0002", name: "Execution",              slug: "execution",              shortDesc: "Run malicious code on a local or remote system.",           order: 4 },
  { id: "TA0003", name: "Persistence",            slug: "persistence",            shortDesc: "Maintain foothold across restarts and credential changes.", order: 5 },
  { id: "TA0004", name: "Privilege Escalation",   slug: "privilege-escalation",   shortDesc: "Gain higher-level permissions.",                            order: 6 },
  { id: "TA0005", name: "Defense Evasion",        slug: "defense-evasion",        shortDesc: "Avoid detection by defenses.",                              order: 7 },
  { id: "TA0006", name: "Credential Access",      slug: "credential-access",      shortDesc: "Steal account names, passwords, and tokens.",               order: 8 },
  { id: "TA0007", name: "Discovery",              slug: "discovery",              shortDesc: "Learn about the environment.",                              order: 9 },
  { id: "TA0008", name: "Lateral Movement",       slug: "lateral-movement",       shortDesc: "Move through the environment.",                             order: 10 },
  { id: "TA0009", name: "Collection",             slug: "collection",             shortDesc: "Gather data of interest to the objective.",                 order: 11 },
  { id: "TA0011", name: "Command and Control",    slug: "command-and-control",    shortDesc: "Communicate with compromised systems.",                     order: 12 },
  { id: "TA0010", name: "Exfiltration",           slug: "exfiltration",           shortDesc: "Steal data.",                                               order: 13 },
  { id: "TA0040", name: "Impact",                 slug: "impact",                 shortDesc: "Disrupt availability or integrity.",                        order: 14 },
];

// Parent-technique → list of tactic ids. Sub-techniques inherit from their parent
// (we strip `.NN` before lookup). Sources: ATT&CK Enterprise v14.
export const TECHNIQUE_TO_TACTICS: Record<string, string[]> = {
  // Execution
  T1053: ["TA0002", "TA0003", "TA0004"], // Scheduled Task/Job
  T1059: ["TA0002"],                     // Command and Scripting Interpreter
  T1129: ["TA0002"],                     // Shared Modules
  T1106: ["TA0002"],                     // Native API
  T1204: ["TA0002"],                     // User Execution
  T1569: ["TA0002"],                     // System Services
  T1047: ["TA0002"],                     // WMI
  T1559: ["TA0002"],                     // IPC

  // Persistence / PrivEsc / Defense Evasion overlaps
  T1547: ["TA0003", "TA0004"],           // Boot/Logon Autostart
  T1543: ["TA0003", "TA0004"],           // Create/Modify System Process
  T1546: ["TA0003", "TA0004"],           // Event Triggered Execution
  T1574: ["TA0003", "TA0004", "TA0005"], // Hijack Execution Flow
  T1554: ["TA0003"],                     // Compromise Client Software Binary
  T1136: ["TA0003"],                     // Create Account
  T1098: ["TA0003"],                     // Account Manipulation
  T1197: ["TA0003", "TA0005"],           // BITS Jobs
  T1078: ["TA0001", "TA0003", "TA0004", "TA0005"], // Valid Accounts
  T1505: ["TA0003"],                     // Server Software Component

  // Defense Evasion
  T1055: ["TA0004", "TA0005"],           // Process Injection
  T1027: ["TA0005"],                     // Obfuscated Files or Information
  T1036: ["TA0005"],                     // Masquerading
  T1070: ["TA0005"],                     // Indicator Removal
  T1140: ["TA0005"],                     // Deobfuscate/Decode
  T1112: ["TA0005"],                     // Modify Registry
  T1218: ["TA0005"],                     // System Binary Proxy Execution
  T1620: ["TA0005"],                     // Reflective Code Loading
  T1622: ["TA0005"],                     // Debugger Evasion
  T1497: ["TA0005", "TA0007"],           // Virtualization/Sandbox Evasion
  T1562: ["TA0005"],                     // Impair Defenses
  T1548: ["TA0004", "TA0005"],           // Abuse Elevation Control
  T1014: ["TA0005"],                     // Rootkit
  T1480: ["TA0005"],                     // Execution Guardrails
  T1006: ["TA0005"],                     // Direct Volume Access
  T1211: ["TA0005"],                     // Exploitation for Defense Evasion
  T1134: ["TA0004", "TA0005"],           // Access Token Manipulation
  T1220: ["TA0005"],                     // XSL Script Processing
  T1222: ["TA0005"],                     // File and Directory Permissions Modification
  T1564: ["TA0005"],                     // Hide Artifacts
  T1553: ["TA0005"],                     // Subvert Trust Controls
  T1601: ["TA0005"],                     // Modify System Image
  T1207: ["TA0005"],                     // Rogue Domain Controller
  T1216: ["TA0005"],                     // System Script Proxy Execution
  T1221: ["TA0005"],                     // Template Injection
  T1550: ["TA0005", "TA0008"],           // Use Alternate Authentication Material
  T1556: ["TA0003", "TA0005", "TA0006"], // Modify Authentication Process
  T1484: ["TA0004", "TA0005"],           // Domain Policy Modification
  T1068: ["TA0004"],                     // Exploitation for Privilege Escalation
  T1037: ["TA0003", "TA0004"],           // Boot or Logon Initialization Scripts
  T1176: ["TA0003"],                     // Browser Extensions
  T1137: ["TA0003"],                     // Office Application Startup
  T1525: ["TA0003"],                     // Implant Internal Image
  T1611: ["TA0004"],                     // Escape to Host

  // Credential Access
  T1003: ["TA0006"],                     // OS Credential Dumping
  T1555: ["TA0006"],                     // Credentials from Password Stores
  T1552: ["TA0006"],                     // Unsecured Credentials
  T1110: ["TA0006"],                     // Brute Force
  T1056: ["TA0006", "TA0009"],           // Input Capture

  // Discovery
  T1082: ["TA0007"],                     // System Information Discovery
  T1057: ["TA0007"],                     // Process Discovery
  T1518: ["TA0007"],                     // Software Discovery
  T1083: ["TA0007"],                     // File and Directory Discovery
  T1087: ["TA0007"],                     // Account Discovery
  T1016: ["TA0007"],                     // System Network Configuration Discovery
  T1033: ["TA0007"],                     // System Owner/User Discovery
  T1069: ["TA0007"],                     // Permission Groups Discovery
  T1010: ["TA0007"],                     // Application Window Discovery
  T1049: ["TA0007"],                     // System Network Connections Discovery
  T1018: ["TA0007"],                     // Remote System Discovery
  T1046: ["TA0007"],                     // Network Service Discovery
  T1135: ["TA0007"],                     // Network Share Discovery
  T1007: ["TA0007"],                     // System Service Discovery
  T1614: ["TA0007"],                     // System Location Discovery
  T1201: ["TA0007"],                     // Password Policy Discovery
  T1615: ["TA0007"],                     // Group Policy Discovery
  T1124: ["TA0007"],                     // System Time Discovery
  T1040: ["TA0006", "TA0007"],           // Network Sniffing

  // Lateral Movement
  T1021: ["TA0008"],                     // Remote Services
  T1210: ["TA0008"],                     // Exploitation of Remote Services
  T1570: ["TA0008"],                     // Lateral Tool Transfer

  // Collection
  T1113: ["TA0009"],                     // Screen Capture
  T1115: ["TA0009"],                     // Clipboard Data
  T1005: ["TA0009"],                     // Data from Local System
  T1560: ["TA0009"],                     // Archive Collected Data
  T1123: ["TA0009"],                     // Audio Capture
  T1125: ["TA0009"],                     // Video Capture
  T1119: ["TA0009"],                     // Automated Collection

  // C2
  T1071: ["TA0011"],                     // Application Layer Protocol
  T1090: ["TA0011"],                     // Proxy
  T1573: ["TA0011"],                     // Encrypted Channel
  T1105: ["TA0011"],                     // Ingress Tool Transfer
  T1132: ["TA0011"],                     // Data Encoding
  T1001: ["TA0011"],                     // Data Obfuscation
  T1102: ["TA0011"],                     // Web Service
  T1568: ["TA0011"],                     // Dynamic Resolution
  T1571: ["TA0011"],                     // Non-Standard Port
  T1095: ["TA0011"],                     // Non-Application Layer Protocol

  // Exfiltration
  T1041: ["TA0010"],                     // Exfil over C2 Channel
  T1048: ["TA0010"],                     // Exfil over Alt Protocol
  T1567: ["TA0010"],                     // Exfil over Web Service

  // Impact
  T1486: ["TA0040"],                     // Data Encrypted for Impact
  T1490: ["TA0040"],                     // Inhibit System Recovery
  T1489: ["TA0040"],                     // Service Stop
  T1529: ["TA0040"],                     // System Shutdown/Reboot

  // Initial Access
  T1566: ["TA0001"],                     // Phishing
  T1190: ["TA0001"],                     // Exploit Public-Facing Application
  T1195: ["TA0001"],                     // Supply Chain Compromise
  T1189: ["TA0001"],                     // Drive-by Compromise

  // Reconnaissance / Resource Development
  T1595: ["TA0043"],                     // Active Scanning
  T1592: ["TA0043"],                     // Victim Host Information
  T1583: ["TA0042"],                     // Acquire Infrastructure
  T1587: ["TA0042"],                     // Develop Capabilities
  T1588: ["TA0042"],                     // Obtain Capabilities

  // --- Additional coverage (C2, Exfil, Impact, Credential Access, Lateral) ---
  T1219: ["TA0011"],                     // Remote Access Software
  T1572: ["TA0011"],                     // Protocol Tunneling
  T1665: ["TA0011"],                     // Hide Infrastructure
  T1008: ["TA0011"],                     // Fallback Channels
  T1092: ["TA0011"],                     // Communication Through Removable Media
  T1104: ["TA0011"],                     // Multi-Stage Channels
  T1029: ["TA0010"],                     // Scheduled Transfer
  T1030: ["TA0010"],                     // Data Transfer Size Limits
  T1020: ["TA0010"],                     // Automated Exfiltration
  T1485: ["TA0040"],                     // Data Destruction
  T1491: ["TA0040"],                     // Defacement
  T1499: ["TA0040"],                     // Endpoint Denial of Service
  T1498: ["TA0040"],                     // Network Denial of Service
  T1531: ["TA0040"],                     // Account Access Removal
  T1561: ["TA0040"],                     // Disk Wipe
  T1565: ["TA0040"],                     // Data Manipulation
  T1558: ["TA0006"],                     // Steal or Forge Kerberos Tickets
  T1187: ["TA0006"],                     // Forced Authentication
  T1621: ["TA0006"],                     // MFA Request Generation
  T1649: ["TA0006"],                     // Steal or Forge Auth Certificates
  T1534: ["TA0008"],                     // Internal Spearphishing
  T1563: ["TA0008"],                     // Remote Service Session Hijacking
  T1091: ["TA0001", "TA0008"],           // Replication Through Removable Media
  T1133: ["TA0001", "TA0003"],           // External Remote Services
  T1200: ["TA0001"],                     // Hardware Additions
  T1203: ["TA0002"],                     // Exploitation for Client Execution
  T1610: ["TA0002"],                     // Deploy Container
  T1072: ["TA0002", "TA0008"],           // Software Deployment Tools
  T1651: ["TA0002"],                     // Cloud Administration Command
  T1039: ["TA0009"],                     // Data from Network Shared Drive
  T1114: ["TA0009"],                     // Email Collection
  T1213: ["TA0009"],                     // Data from Information Repositories
  T1600: ["TA0005"],                     // Weaken Encryption
  T1647: ["TA0005"],                     // Plist File Modification
};

/** Resolve tactics for a MITRE technique id, transparently handling sub-techniques. */
export function getTacticsFor(mitreId: string): string[] {
  if (!mitreId) return [];
  const base = String(mitreId).split(".")[0].toUpperCase();
  return TECHNIQUE_TO_TACTICS[base] ?? [];
}

const MITRE_ID_RE = /^T\d{4}/;

/** Extract the parent technique id from a raw tag ("T1055.012" → "T1055"). */
export function parentTechnique(tag: string): string | null {
  if (!MITRE_ID_RE.test(tag)) return null;
  const m = tag.match(/^T\d{4}/);
  return m ? m[0] : null;
}

/** Get tactic ids for a technique tag (accepts sub-techniques). */
export function tacticsForTechnique(tag: string): string[] {
  const parent = parentTechnique(tag);
  if (!parent) return [];
  return TECHNIQUE_TO_TACTICS[parent] || [];
}

/** Collect all tactic ids implied by an entity's tag list. */
export function tacticsForTags(tags: string[]): Set<string> {
  const out = new Set<string>();
  for (const tag of tags) {
    for (const t of tacticsForTechnique(tag)) out.add(t);
  }
  return out;
}
