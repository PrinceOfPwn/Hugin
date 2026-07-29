// Keep in sync with the peer file mitre-tactics.{ts,mjs}
// Plain-JS mirror of ../../src/lib/mitre-tactics.ts consumed by build-time scripts.
// Only the fields the build-mitre-index.mjs script needs are exported.

export const TACTICS = [
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

export const TECHNIQUE_TO_TACTICS = {
  // Execution
  T1053: ["TA0002", "TA0003", "TA0004"],
  T1059: ["TA0002"],
  T1129: ["TA0002"],
  T1106: ["TA0002"],
  T1204: ["TA0002"],
  T1569: ["TA0002"],
  T1047: ["TA0002"],
  T1559: ["TA0002"],
  T1203: ["TA0002"],
  T1610: ["TA0002"],
  T1072: ["TA0002", "TA0008"],
  T1651: ["TA0002"],

  // Persistence / PrivEsc
  T1547: ["TA0003", "TA0004"],
  T1543: ["TA0003", "TA0004"],
  T1546: ["TA0003", "TA0004"],
  T1574: ["TA0003", "TA0004", "TA0005"],
  T1554: ["TA0003"],
  T1136: ["TA0003"],
  T1098: ["TA0003"],
  T1197: ["TA0003", "TA0005"],
  T1078: ["TA0001", "TA0003", "TA0004", "TA0005"],
  T1505: ["TA0003"],
  T1037: ["TA0003", "TA0004"],
  T1176: ["TA0003"],
  T1137: ["TA0003"],
  T1525: ["TA0003"],
  T1556: ["TA0003", "TA0005", "TA0006"],
  T1611: ["TA0004"],
  T1068: ["TA0004"],
  T1484: ["TA0004", "TA0005"],

  // Defense Evasion
  T1055: ["TA0004", "TA0005"],
  T1027: ["TA0005"],
  T1036: ["TA0005"],
  T1070: ["TA0005"],
  T1140: ["TA0005"],
  T1112: ["TA0005"],
  T1218: ["TA0005"],
  T1620: ["TA0005"],
  T1622: ["TA0005"],
  T1497: ["TA0005", "TA0007"],
  T1562: ["TA0005"],
  T1548: ["TA0004", "TA0005"],
  T1014: ["TA0005"],
  T1480: ["TA0005"],
  T1006: ["TA0005"],
  T1211: ["TA0005"],
  T1134: ["TA0004", "TA0005"],
  T1220: ["TA0005"],
  T1222: ["TA0005"],
  T1564: ["TA0005"],
  T1553: ["TA0005"],
  T1601: ["TA0005"],
  T1207: ["TA0005"],
  T1216: ["TA0005"],
  T1221: ["TA0005"],
  T1550: ["TA0005", "TA0008"],
  T1600: ["TA0005"],
  T1647: ["TA0005"],

  // Credential Access
  T1003: ["TA0006"],
  T1555: ["TA0006"],
  T1552: ["TA0006"],
  T1110: ["TA0006"],
  T1056: ["TA0006", "TA0009"],
  T1558: ["TA0006"],
  T1187: ["TA0006"],
  T1621: ["TA0006"],
  T1649: ["TA0006"],
  T1040: ["TA0006", "TA0007"],

  // Discovery
  T1082: ["TA0007"],
  T1057: ["TA0007"],
  T1518: ["TA0007"],
  T1083: ["TA0007"],
  T1087: ["TA0007"],
  T1016: ["TA0007"],
  T1033: ["TA0007"],
  T1069: ["TA0007"],
  T1010: ["TA0007"],
  T1049: ["TA0007"],
  T1018: ["TA0007"],
  T1046: ["TA0007"],
  T1135: ["TA0007"],
  T1007: ["TA0007"],
  T1614: ["TA0007"],
  T1201: ["TA0007"],
  T1615: ["TA0007"],
  T1124: ["TA0007"],

  // Lateral Movement
  T1021: ["TA0008"],
  T1210: ["TA0008"],
  T1570: ["TA0008"],
  T1534: ["TA0008"],
  T1563: ["TA0008"],
  T1091: ["TA0001", "TA0008"],

  // Collection
  T1113: ["TA0009"],
  T1115: ["TA0009"],
  T1005: ["TA0009"],
  T1560: ["TA0009"],
  T1123: ["TA0009"],
  T1125: ["TA0009"],
  T1119: ["TA0009"],
  T1039: ["TA0009"],
  T1114: ["TA0009"],
  T1213: ["TA0009"],

  // C2
  T1071: ["TA0011"],
  T1090: ["TA0011"],
  T1573: ["TA0011"],
  T1105: ["TA0011"],
  T1132: ["TA0011"],
  T1001: ["TA0011"],
  T1102: ["TA0011"],
  T1568: ["TA0011"],
  T1571: ["TA0011"],
  T1095: ["TA0011"],
  T1219: ["TA0011"],
  T1572: ["TA0011"],
  T1665: ["TA0011"],
  T1008: ["TA0011"],
  T1092: ["TA0011"],
  T1104: ["TA0011"],

  // Exfiltration
  T1041: ["TA0010"],
  T1048: ["TA0010"],
  T1567: ["TA0010"],
  T1029: ["TA0010"],
  T1030: ["TA0010"],
  T1020: ["TA0010"],

  // Impact
  T1486: ["TA0040"],
  T1490: ["TA0040"],
  T1489: ["TA0040"],
  T1529: ["TA0040"],
  T1485: ["TA0040"],
  T1491: ["TA0040"],
  T1499: ["TA0040"],
  T1498: ["TA0040"],
  T1531: ["TA0040"],
  T1561: ["TA0040"],
  T1565: ["TA0040"],

  // Initial Access
  T1566: ["TA0001"],
  T1190: ["TA0001"],
  T1195: ["TA0001"],
  T1189: ["TA0001"],
  T1133: ["TA0001", "TA0003"],
  T1200: ["TA0001"],

  // Reconnaissance / Resource Development
  T1595: ["TA0043"],
  T1592: ["TA0043"],
  T1583: ["TA0042"],
  T1587: ["TA0042"],
  T1588: ["TA0042"],
};

const CATEGORY_TO_TACTICS = {
  execution: ["TA0002"],
  persistence: ["TA0003"],
  privesc: ["TA0004"],
  "privilege-escalation": ["TA0004"],
  evasion: ["TA0005"],
  "defense-evasion": ["TA0005"],
  credentials: ["TA0006"],
  "credential-access": ["TA0006"],
  recon: ["TA0043"],
  reconnaissance: ["TA0043"],
  discovery: ["TA0007"],
  c2: ["TA0011"],
  "command-and-control": ["TA0011"],
  lateral: ["TA0008"],
  "lateral-movement": ["TA0008"],
  collection: ["TA0009"],
  exfiltration: ["TA0010"],
  impact: ["TA0040"],
};

/** Resolve tactics for a MITRE technique id, transparently handling sub-techniques. */
export function getTacticsFor(mitreId, category = "") {
  if (!mitreId) return [];
  const base = String(mitreId).split(".")[0].toUpperCase();
  const direct = TECHNIQUE_TO_TACTICS[base];
  if (direct && direct.length > 0) return direct;
  const catKey = String(category).toLowerCase().trim();
  return CATEGORY_TO_TACTICS[catKey] ?? [];
}
