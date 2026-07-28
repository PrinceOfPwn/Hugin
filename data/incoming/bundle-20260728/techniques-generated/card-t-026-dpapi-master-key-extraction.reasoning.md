Let me analyze the inputs carefully.

**Cluster spec**: T-026, "DPAPI Master Key Extraction for Credential Decryption", category `discovery`, tier `A`. Member note: `lgtm:dpapi-master-key-extraction`. would_relate_to: T-023.

**Source files provided**: `amaterasu.rs` and `browser.rs`. I need to verify whether these implement the technique.

Looking at `amaterasu.rs`: `harvest_dpapi()` — this enumerates:
1. Browser Local State files (checking for `encrypted_key` presence)
2. RDP credential files in `%LOCALAPPDATA%\Microsoft\Credentials`
3. Roaming credential files
4. DPAPI master key directory listing at `%APPDATA%\Microsoft\Protect\<SID>` — **metadata only** (path + size), no decryption

So amaterasu.rs does discovery/inventory of DPAPI artifacts but does NOT decrypt master keys. It locates the master key directory — that's part of the technique (locating `%APPDATA%\Microsoft\Protect\<SID>`).

Looking at `browser.rs`: This actually does DPAPI decryption:
- `get_chrome_aes_key()` reads `Local State`, extracts `os_crypt.encrypted_key`, base64 decodes, strips 5-byte "DPAPI" prefix, calls `dpapi_decrypt()`
- `dpapi_decrypt()` calls `CryptUnprotectData` — this decrypts the browser's AES key using the *current user's* DPAPI context (which internally uses the master key in `%APPDATA%\Microsoft\Protect\<SID>`)
- `chrome_decrypt_pw()` handles v10 AES-256-GCM decryption with the key, fallback to DPAPI

So `browser.rs` implements CryptUnprotectData-based decryption — which is the "use the master key via CryptUnprotectData" path (Windows internally uses the master key). It does NOT do offline master key extraction/decryption (e.g., with user password hash or domain backup key).

The cluster spec's consolidated description: "locate user's master key in %APPDATA%\Microsoft\Protect\<SID>, decrypt using LogonUser/CryptUnprotectData or offline tools, use master key to decrypt user credential caches (Chrome login database, Credential Manager vault)."

So the technique card covers: master key location, decryption paths (live via CryptUnprotectData as the user, or offline via password hash/domain backup key), and then using the master key for Chrome/Credential Manager decryption.

Do the source files implement "the primary mechanism the card describes"? The card's primary mechanism is DPAPI master key extraction for credential decryption. The sources:
- `amaterasu.rs` — locates the master key directory (part of the mechanism, step 1), enumerates credential artifacts. Does not decrypt.
- `browser.rs` — uses CryptUnprotectData to decrypt Chrome's encrypted_key (this is the live-decryption path where Windows handles master key usage internally) and AES-256-GCM for v10 passwords.

Per rule 8: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes."

The card's primary mechanism: locate master keys → decrypt master key (via CryptUnprotectData in user context, or offline) → use it to decrypt Chrome/Credential Manager secrets.

`browser.rs::dpapi_decrypt` + `get_chrome_aes_key` implement the live CryptUnprotectData path — Windows internally uses the master key from `%APPDATA%\Microsoft\Protect\<SID>` to satisfy CryptUnprotectData. This is the "decrypt using ... CryptUnprotectData" leg of the consolidated description. And then uses it to decrypt Chrome login database. That's a substantial match to the technique as described. `amaterasu.rs::harvest_dpapi` implements the location/enumeration step.

I think it's fair to reference both files, but be precise about what they implement: amaterasu.rs does artifact discovery (master key dir listing, Local State, credential files); browser.rs does the live CryptUnprotectData decryption path for Chromium. Neither does offline master key decryption (password-hash-based or domain backup key). I'll state this precisely.

Crate: `client_rust`. source_file: which one? The frontmatter has a single `source_file` field. The template says "relative path from repo root, or 'none'". Multiple files match. I could put the primary one. The existing cards in the file manifest use paths like `client_rust/src/...`. Actually looking at the manifest, paths are like "src/amaterasu.rs" within client_rust. Hmm, the manifest structure groups by crate then path like "src/amaterasu.rs". But the input files are given as `src/client_rust/src/amaterasu.rs`. The template says "relative path from repo root". Given inputs were `src/client_rust/src/amaterasu.rs` and `src/client_rust/src/browser.rs`. I'll use `src/client_rust/src/browser.rs` as primary source_file since it implements the decryption primitive, and mention amaterasu.rs in Key Implementation Details and Source Reference. Actually, source_file is a single string. I'll pick `src/client_rust/src/browser.rs` — the CryptUnprotectData path is the core implemented primitive.

Hmm, wait. Let me reconsider: is the primary mechanism "offline master key extraction" specifically? The card name: "DPAPI Master Key Extraction for Credential Decryption". The LGTM note says: "does not document the DPAPI master key access step (locating %APPDATA%\Microsoft\Protect\<SID>, decrypting the master key with the user's logon password or DPAPI domain backup key) as a distinct sub-technique... it is the rate-limiting step for offline credential decryption."

So the note emphasizes offline decryption. But the consolidated description includes "decrypt using LogonUser/CryptUnprotectData or offline tools". So the live CryptUnprotectData path is in scope. browser.rs implements CryptUnprotectData usage. I'll attribute with precision: implements the live user-context decryption leg; offline master key decryption is not implemented.

Given rule 8's strictness, I could also argue "no current implementation" of offline master key extraction. But the technique as scoped by the cluster spec (not just the note) includes CryptUnprotectData-based decryption, which browser.rs clearly implements. False attribution is worse — but here attribution would be accurate if I describe precisely what exists. I'll reference both files with precise scoping.

**Category**: proposed `discovery`. Hmm. The technique is credential harvesting. Category enum includes `discovery` but not `credential-access`. The cluster spec proposed `discovery`. MITRE best fit: T1555.004 (Windows Credential Manager)? Or T1555.003 (Credentials from Web Browsers)? Or T1003 (OS Credential Dumping)? DPAPI master key extraction specifically... ATT&CK: T1555 "Credentials from Password Stores", sub-techniques: .003 Credentials from Web Browsers, .004 Windows Credential Manager. There's also T1003.004 (LSA Secrets). For DPAPI masterkey specifically, Mimikatz dpapi::masterkey is often mapped to T1552 or T1555. Hmm.

The single best fit: the technique is about decrypting the master key to access credential stores. ATT&CK T1555.004 (Windows Credential Manager) covers Credential Manager; T1555.003 covers web browsers. The note says it's the rate-limiting step for both. MITRE primary: I'd pick T1555.004 with secondary T1555.003. Actually, hmm — is there a more specific one for DPAPI? ATT&CK doesn't have a DPAPI-specific sub-technique. Many sources map DPAPI master key theft to T1003 (OS Credential Dumping) — actually no. Let me think. Mimikatz `dpapi::masterkey` — attack.mitre references... T1552.001 is "Credentials In Files". Master key files are files containing keys, not credentials per se. The most commonly cited mapping for "DPAPI master key extraction" in public reporting is T1555.004 when used for Credential Manager, and T1555.003 for browsers. Some map masterkey extraction to T1003. I'll go: primary T1555.004, secondary [T1555.003]. Both are real IDs I'm confident about.

Category: `discovery` is proposed. The enum: syscalls|process-injection|edr-evasion|persistence|sleep-obfuscation|anti-analysis|crypto|networking|client|privesc|exploit-primitive|discovery. Credential harvesting isn't in the enum; closest options: `discovery` (as proposed) or `crypto` (it is a cryptographic primitive) or `client` (capability of the client). The cluster spec says discovery with reasoning "Singleton, focused credential-harvesting primitive". I'll keep `discovery` as assigned — it's the closest in the enum (credential discovery/access). The spec says I may adjust if atlas material clearly supports a different choice — it doesn't clearly. Keep `discovery`.

Tier: A as proposed.

**Atlas material**: Units 20 and 21 are the relevant ones:
- Unit 20 (CRTO): DPAPI is a Windows component for encrypting/decrypting data "blobs", uses cryptographic keys; used by Windows Credential Manager to store saved secrets such as RDP credentials, and by third-party apps like Google Chrome to store website credentials.
- Unit 21 (CRTO): Extracting credentials from Google Chrome's local database using SharpChromium; AppData directory; Login Data.

The atlas material is thin — it doesn't detail the master key format, %APPDATA%\Microsoft\Protect\<SID>, domain backup key, etc. But the cluster spec's consolidated description (derived from LGTM notes) includes: locate master key in %APPDATA%\Microsoft\Protect\<SID>, decrypt using LogonUser/CryptUnprotectData or offline tools, master key encrypted with user's logon password or system DPAPI key. The LGTM note adds: decrypting the master key with the user's logon password or DPAPI domain backup key.

Rule 4: claims must trace to atlas material, related cards, Rust source, or "well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)". DPAPI internals are well-established and documented (MSDN covers CryptProtectData/CryptUnprotectData, DATA_BLOB; the master key structure is documented in public research like Passcape DPAPI docs and Microsoft's [MS-DPSP]? Actually there is no MS doc for master key format; it's documented in Passcape's "DPAPI Master Key" docs and Benjamin Delpy's research). I can describe well-established facts: CryptProtectData/CryptUnprotectData API contract, DATA_BLOB structure, master key storage location (that's in the cluster spec), key derivation from user's password (well established: SHA1 of UTF-16LE password for the master key decryption, PBKDF2 iterations), the "Preferred" file, the GUID-named master key files, the BK-SYSTEM / domain backup key (RSA private key in LSASS / domain controller's DPAPI backup key), CREDHIST file. I should be careful to stay accurate and not fabricate specifics I'm unsure about (e.g., exact iteration counts — it's 4000 iterations of PBKDF2 with HMAC-SHA512 for the pre-Vista? Actually: master key encrypted with key derived via PBKDF2-HMAC-SHA512, 4000 iterations, salt from the master key file, using SHA1(password) as password input for pre-Win10? This is documented in Passcape research. I'm fairly confident: DPAPI master key decryption uses PBKDF2 with HMAC-SHA512, 4000 iterations for the password-based path historically; newer versions (Win10 v1607+?) use 8000 iterations for the newer format / and AES? Passcape documents: master key file contains salt, rounds (4000), HMAC, then encrypted master key (3DES historically, AES-256 in later versions). I need to be careful. I'll describe at a level I'm confident: password → SHA1 → PBKDF2-HMAC-SHA512 (iteration count stored in the blob) → 3DES/AES decryption of the 64-byte master key. And note entropy for the system DPAPI path. I can also describe CryptUnprotectData contract: DATA_BLOB in/out, optional entropy, CRYPTPROTECT_UI_FORBIDDEN flag, LocalFree on output. That I'm confident about and it appears in browser.rs.

Chrome specifics from browser.rs: Local State JSON `os_crypt.encrypted_key`, base64, "DPAPI" 5-byte prefix, CryptUnprotectData → 32-byte AES-256-GCM key; v10 prefix, 12-byte IV at offset 3..15, 16-byte GCM tag at end. That's from the source and it's accurate.

Also Chrome 127+ app-bound encryption — should I mention? The material doesn't discuss it. Rule: material is authority for descriptive claims; I can include well-established facts but should avoid going beyond what's supportable. App-bound encryption is well-established post-July-2024 Chrome behavior, but it adds detection-relevant context. Hmm — rule 3 says no variant ideas/suggestions; mentioning a version difference is allowed under OS Internals Context ("Version differences if the material discusses them"). The material does NOT discuss it. I could mention briefly as Windows/Chrome version context — but risk of fabricating. I know it well: Chrome 127 (July 2024) introduced App-Bound Encryption on Windows, which encrypts the key with a SYSTEM-level service requiring path validation, defeating simple CryptUnprotectData-as-user. This is well-established public knowledge. But is it "well-established Windows internals documentation"? It's Chrome internals, not Windows. The rule lists allowed sources: atlas, related cards, Rust source, well-established Windows internals docs. Strictly, app-bound encryption falls outside. However OS Internals Context says "Version differences if the material discusses them" — material doesn't. I'll omit or give it one careful sentence? I'd rather stay within rules and omit it, since the card must trace claims. Actually — a brief mention could be justified as detection-relevant context... No. Rule 4 is explicit about allowed sources. Omit.

Detection: The material does NOT discuss detection for DPAPI. Rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections." The atlas doesn't cover detection. So I must write that line. I should not invent ETW providers/Sysmon IDs. I could note residual artifacts... no — do not invent. Write the single line. Maybe the whole section is just that line. That's allowed: "If a section has no content because the material is sparse, write a single-line explanation." Actually the template for Detection Considerations has subsections; but the rule says write that sentence if material doesn't cover it. I'll write the sentence, and that's it. Hmm, could I still structure it? The instruction says write: `Training material does not discuss detection for this technique.` I'll do exactly that.

**Mechanism** section — numbered steps. Based on cluster spec + source + well-established DPAPI internals:

1. Locate master key store: `%APPDATA%\Microsoft\Protect\<SID>\` — enumerate SID subdirectories, each containing GUID-named master key files plus a `Preferred` file naming the current master key GUID. (amaterasu.rs does this enumeration.)
2. Identify target master key: read `Preferred` (16 bytes? Preferred file contains GUID + timestamps) or parse the GUID from the DPAPI blob header of the target ciphertext (each DPAPI blob embeds the GUID of the master key used). That GUID → filename.
3. Decryption path selection:
   a. Live user-context path: call CryptUnprotectData directly while executing as the target user — Windows locates the master key, derives the decryption key from the user's logon session credentials, and returns plaintext. This is what browser.rs does for Chrome's encrypted_key. If operating as another user with the target's credentials, LogonUser + impersonation (or CreateProcessWithLogonW) gives a logon session under which CryptUnprotectData works.
   b. Offline path: parse the master key file; derive decryption key from the user's password (SHA1 of UTF-16LE password → PBKDF2-HMAC-SHA512 with salt and iteration count from the blob → 3DES/AES key), or use the domain DPAPI backup key (RSA private key retrievable by a Domain Admin via MS-BKRP / lsadump::backupkey equivalent) to decrypt the RSA-wrapped master key copy stored alongside.
4. With the 64-byte master key plaintext (or live CryptUnprotectData), decrypt application blobs:
   - Chrome/Edge: Local State → os_crypt.encrypted_key → strip "DPAPI" prefix → DPAPI decrypt → 32-byte AES key; then Login Data/Cookies v10 blobs: AES-256-GCM, 12-byte nonce at offset 3, tag last 16 bytes.
   - Credential Manager: files under `%APPDATA%\Microsoft\Credentials\` / `%LOCALAPPDATA%\Microsoft\Credentials\` are DPAPI blobs; decrypted master key unwraps them (vault structure parsed by tools like Mimikatz dpapi::cred).
5. Exfiltrate results.

LogonUser is in the cluster spec ("decrypt using LogonUser/CryptUnprotectData"). Good.

**OS Internals Context**: 
- DPAPI architecture: per-user master keys, 64-byte random, encrypted with key derived from user's credential (NT password), re-encrypted on password change via CREDHIST (credential history file in same Protect dir) allowing old master keys to be decrypted with previous passwords.
- Master key file format: salt, iteration count (PBKDF2-HMAC-SHA512), HMAC, encrypted master key (historically 3DES-CBC; AES on later builds). Two copies in each file? Actually each master key file contains one master key encrypted under user password; domain users also get a domain-backup-encrypted copy inside the same blob (the "domain backup key" RSA-2048 wrap). The Preferred file: 24 bytes? It contains GUID (16 bytes) + two FILETIMEs. I believe Preferred file structure: GUID + FILETIME created + FILETIME expires. I'll state GUID + timestamps without exact size if unsure. Actually I recall Preferred file is 24 bytes: 16-byte GUID + 2×4? Hmm. To be safe: "contains the GUID of the current master key along with creation/expiration timestamps". That's accurate.
- Blob format: DPAPI blob header contains provider GUID (df9d8cd0-1501-11d1-8c7a-00c04fc297eb), master key GUID, flags, description length, crypto provider info (CALG_3DES / CALG_AES_256, CALG_SHA1/HMAC-SHA512?), salt, HMAC. I'm reasonably confident about provider GUID `df9d8cd0-1501-11d1-8c7a-00c04fc297eb` — that's the well-known DPAPI provider GUID. Yes, that's documented in Passcape and Mimikatz. I'll include it; it's well-established.
- System DPAPI: DPAPI_SYSTEM secret in LSA (HKLM\SECURITY\Policy\Secrets\DPAPI_SYSTEM) used for machine-store blobs (CRYPTPROTECT_LOCAL_MACHINE flag). Cluster spec mentions "system DPAPI key". Good.
- CryptUnprotectData contract: DATA_BLOB {cbData, pbData}, ppszDataDescr optional out, optional entropy blob, reserved, prompt struct, flags (CRYPTPROTECT_UI_FORBIDDEN = 0x1), output must be freed with LocalFree. Matches browser.rs usage (passes None for entropy/prompt, 0 flags, LocalFree on output).
- Session dependency: user master keys live under HKU\<SID>... hmm, actually the master keys are files; the decryption requires the user's password-derived key. When a user is logged on, LSA caches? The key detail: CryptUnprotectData works in the user's logon session because winlogon/lsass keeps the password hash available for DPAPI? Actually DPAPI derives the key from the user's credentials — for a logged-on user, the system can re-derive because it caches the SHA1 of the password in memory (that's why password change triggers master key re-encryption and why NTLM hash pass-the-hash enables master key decryption offline). Mimikatz sekurlsa::dpapi extracts the "DPAPI masterkey" cached in LSASS (the SHA1(password) used as the pre-key? It extracts cached master keys from LSASS memory of logged-on sessions). I know Mimikatz `sekurlsa::dpapi` grabs master keys from LSASS. That's well established. Keep it brief and hedged where needed.
- Chrome key hierarchy: Local State os_crypt.encrypted_key — DPAPI blob; decrypted gives AES-256-GCM key for v10/v11 blobs. Cookies moved from SQLite "Cookies" to "Network\Cookies" (browser.rs handles both). v10 prefix; v11 same format Edge? Not needed.

I must be careful with claims I'm unsure about: exact iteration counts (4000 vs 8000+). Passcape: Windows used PBKDF2 with 4000 iterations for the user-password-based master key encryption historically; starting some version 8000? I recall Hashcat mode 15300/15900 "DPAPI masterkey file v1/v2" — v2 (Win10 1607+) uses SHA512 with 8000 iterations? Hashcat -m 15300 DPAPI masterkey file v1: 4000 iterations of PBKDF2-HMAC-SHA1? Hmm. Actually v1: PBKDF2-HMAC-SHA512, 4000 iters? Let me recall hashcat modes: 15300 = DPAPI masterkey file v1 (context: 3DES, HMAC-SHA1?). 15900 = v2: AES, HMAC-SHA512, 8000 iterations? I think v2 uses 8000+ iterations PBKDF2-HMAC-SHA512 and AES-256. To be safe, I'll say "the iteration count is stored in the blob (historically 4000; raised in later Windows builds alongside a move from 3DES to AES)" — hmm even "raised" might be shaky. Hashcat 15900 is "DPAPI masterkey file v2" and yes, v2 = Windows 10 v1607+, PBKDF2-HMAC-SHA512 with 8000 iterations? I'm fairly confident v2 exists for Win10 1607+ and uses AES. I'll phrase: "later Windows 10 builds introduced a v2 blob format using AES instead of 3DES; the PBKDF2 iteration count is stored in the file and increased accordingly." Keep vague enough to be true: iteration count stored in blob — definitely true.

Let me be disciplined: state what's in the material (cluster spec + note + units 20/21), what's in the Rust source (precise), and well-established DPAPI facts at a level of specificity I'm confident in. Avoid: exact iteration numbers as hard claims (hedge with "commonly 4000 for the legacy format" — I am fairly confident legacy = 4000 PBKDF2-HMAC-SHA512 → 3DES. Passcape documents: Master Key file: version, salt, rounds=4000, HMAC(algHash=CALG_SHA1? no...). Honestly, hedged phrasing is best: "a fixed iteration count (4000 in the legacy format)". That's documented widely. I'll include with "legacy format" qualifier.

**Key Implementation Details**: 
- `src/client_rust/src/browser.rs`: `get_chrome_aes_key()` (Local State parse, base64, strip DPAPI prefix), `dpapi_decrypt()` (CryptUnprotectData via windows crate, CRYPT_INTEGER_BLOB, LocalFree), `chrome_decrypt_pw()` (v10 AES-256-GCM path with IV at [3..15], tag last 16 bytes, feature-gated `aes-gcm` crate else DPAPI fallback), `read_login_data`/`read_cookies` (rusqlite over temp copies — copy_to_temp avoids locked DB). Firefox: logins.json metadata only (NSS not implemented).
- `src/client_rust/src/amaterasu.rs`: `harvest_dpapi()` — enumeration only: browser Local State presence + has_encrypted_key, credential file listings (local + roaming Microsoft\Credentials), master key directory walk under `%APPDATA%\Microsoft\Protect` returning path+size metadata. No decryption performed — operator pulls files for offline work.
- Deviation from full technique: no master key file parsing, no password-hash derivation, no domain backup key usage, no CREDHIST handling. The live CryptUnprotectData leg is implemented; offline leg is not.

**Why It Matters**: rate-limiting step for offline credential decryption; T-023 mentions credential harvesting broadly (wifi/lsass/wmi) and browser harvest exists in code but the vault lacked a card for the DPAPI substrate; separates the cryptographic primitive from the browser-specific extraction.

**Related Techniques**: only T-023 (from would_relate_to). One entry.

**References**:
- Atlas material: atlas-post-exploit-part9.md (units 20, 21)
- MITRE: T1555.004 https://attack.mitre.org/techniques/T1555/004/ ; also T1555.003 URL in secondary? The template: MITRE ATT&CK: T####.### with URL. I'll list primary T1555.004 and secondary T1555.003 with URLs.
- LGTM notes: lgtm:dpapi-master-key-extraction
- Public references: SharpChromium is named in atlas unit 21 — include. The note mentions "offline tools" — Mimikatz dpapi module is the canonical one but not named in the material... The cluster spec says "offline tools" generically; unit 21 names SharpChromium. I can name SharpChromium (in material). Should I name Mimikatz? It's not in the material. Rule: "Public references: optional — original tool authors, blog posts, papers named in the atlas material; do not invent references." Mimikatz is not named in the atlas material. To be strict, only SharpChromium. Hmm — but Mechanism mentions "tools like Mimikatz dpapi::cred"? That would be naming something not in the material... Rule 4 allows well-established documentation; naming a widely-known tool isn't fabricating a reference per se, but to be safe I'll avoid Mimikatz in References and keep mechanism generic ("offline tooling parses..."). Actually, mentioning domain backup key retrieval "via the MS-BKRP BackupKey protocol" — is that safe? MS-BKRP is a real Microsoft protocol spec ([MS-BKRP] BackupKey Remote Protocol). That's well-established Microsoft documentation. I can cite the protocol name. Keep it.

**Tags** (5-10 kebab-case): [dpapi, master-key, credential-decryption, cryptunprotectdata, chrome-local-state, credential-manager, aes-256-gcm, offline-decryption, protect-directory]. That's 9. Good.

**Frontmatter**:
```yaml
---
id: T-026
name: DPAPI Master Key Extraction for Credential Decryption
category: discovery
tier: A
crate: client_rust
source_file: src/client_rust/src/browser.rs
mitre: T1555.004
mitre_secondary: [T1555.003]
tags: [dpapi, master-key, credential-decryption, cryptunprotectdata, chrome-local-state, credential-manager, aes-256-gcm, offline-decryption, protect-directory]
origin: atlas-synthesis
member_notes: [lgtm:dpapi-master-key-extraction]
---
```

Name is 7 words — within 4-8.

**Title**: `# DPAPI Master Key Extraction — Decrypting the Root Key Behind Chrome and Credential Manager Secrets`

**Summary** (3-5 sentences, first standalone): DPAPI master key extraction locates and decrypts the per-user 64-byte master keys stored in `%APPDATA%\Microsoft\Protect\<SID>` so that any DPAPI-protected blob — Chrome's Local State AES key, Credential Manager vault entries, RDP saved credentials — can be decrypted on or off the host. Windows DPAPI (CryptProtectData/CryptUnprotectData) wraps every user secret in a master key encrypted with the user's logon password (or, for domain accounts, additionally wrapped with the domain DPAPI backup key). An operator either calls CryptUnprotectData inside the target user's logon session, or extracts the master key file and decrypts it offline with the user's password hash or the domain backup key. Detection surface... the material doesn't discuss detection; summary asks for primary detection surface. I can say reads of the Protect directory and use of CryptUnprotectData are the observable operations? Is that inventing detection? The template's Summary says include "the primary detection surface" — but Detection Considerations must come from material. For the summary I can state the detection surface generically as "file access to the Protect directory and LSASS-held key material" — hmm. The material doesn't discuss detection at all. I'll phrase carefully: "its primary exposure is access to the Protect directory and the user's logon session rather than any network artifact" — that's a structural observation, not a detection claim. Keep it minimal.

**Word count**: minimum 800 body words, target 1200-1800. I'll aim ~1300-1500.

Let me now verify source claims precisely from the provided code:

browser.rs:
- `get_chrome_aes_key(local_state_path)`: reads Local State, parses JSON `os_crypt.encrypted_key`, base64 STANDARD decode, checks len > 5, strips first 5 bytes ("DPAPI" prefix per comment), calls dpapi_decrypt.
- `dpapi_decrypt(ciphertext)`: windows-only, uses `windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB}`, builds data_in, calls with None (descr), None (entropy), None (reserved), None (prompt), 0 flags, &mut data_out; on success copies cbData bytes and LocalFree(HLOCAL(pbData.cast())). Returns Option<Vec<u8>>.
- `chrome_decrypt_pw(encrypted_value, aes_key)`: v10 → AES-256-GCM: iv = [3..15] (12 bytes), ciphertext_and_tag = [15..], tag = last 16 bytes; decrypt via aes-gcm crate when `feature = "aes-gcm"`, else `win_aes_gcm_decrypt` which bails (falls back to DPAPI). Fallback: dpapi_decrypt whole blob (legacy pre-v10 Chrome passwords were raw DPAPI).
- Login Data: SQLite `logins` table, `origin_url, username_value, password_value WHERE blacklisted_by_user=0`; copies DB to temp first (`copy_to_temp`) to avoid lock.
- Cookies: `Network/Cookies` fallback to `Cookies`, LIMIT 1000.
- History LIMIT 500.
- Chromium paths: chrome and edge only in `chromium_paths`; amaterasu lists brave/opera for Local State metadata.
- Firefox: logins.json metadata only, "(encrypted — NSS required)".

amaterasu.rs harvest_dpapi():
- browsers list: chrome, edge, brave, opera Local State; records size + has_encrypted_key (content contains "encrypted_key").
- `%LOCALAPPDATA%\Microsoft\Credentials` listing; `%APPDATA%\Microsoft\Credentials` (roaming) listing.
- Master key dir: builds path from `appdata_or_empty()` + Microsoft\Protect — note: this code block is inside `if let Ok(local) = std::env::var("LOCALAPPDATA")` block. It iterates SID subdirectories and files within, returning path+size. Metadata only — explicitly commented "metadata only".
- Dispatched via harvest_type "dpapi" or "all" through MSG_AMATERASU_HARVEST (0x21).

So the implementation is: browser.rs = live decryption leg; amaterasu.rs = artifact discovery. Good.

Now Mechanism steps (numbered, concrete):

1. Resolve the target user's SID and open `%APPDATA%\Microsoft\Protect\<SID>\`. Enumerate GUID-named master key files and the `Preferred` file, which records the GUID of the currently active master key plus its creation/expiration timestamps. (Implementation: amaterasu.rs `harvest_dpapi` walks this tree.)
2. Identify the master key for a given ciphertext: every DPAPI blob carries a header containing the DPAPI provider GUID (df9d8cd0-1501-11d1-8c7a-00c04fc297eb) and the GUID of the master key that encrypted it; that GUID is the filename to decrypt. (Well-established blob format.)
3. Choose decryption path:
   - Live: execute as the target user (or LogonUser with the user's credentials then impersonate) and call CryptUnprotectData on the blob; Windows derives the master key from the logon session and returns plaintext in a DATA_BLOB freed with LocalFree. (browser.rs dpapi_decrypt)
   - Offline: copy the master key file; parse salt, iteration count, HMAC, and encrypted key material; derive SHA1(UTF-16LE(password)) then PBKDF2-HMAC-SHA512 with the stored salt/rounds; decrypt the embedded 64-byte master key (3DES in the legacy format, AES in the v2 format used by later Windows 10 builds). Validate against the stored HMAC. CREDHIST in the same directory chains previous passwords so older master keys remain recoverable.
   - Domain: for domain accounts, the same file carries a second copy of the master key wrapped under the domain's DPAPI backup RSA key; a Domain Admin can retrieve the backup key from a domain controller (MS-BKRP BackupKey protocol) and decrypt any domain user's master keys without the password.
4. Chrome/Edge: read `%LOCALAPPDATA%\<browser>\User Data\Local State`, JSON `os_crypt.encrypted_key` → base64 → strip 5-byte "DPAPI" prefix → DPAPI decrypt → 32-byte AES-256-GCM key.
5. Decrypt v10 records: for each `password_value` (Login Data → logins) or `encrypted_value` (Network\Cookies): bytes 0-2 "v10", bytes 3-14 12-byte nonce, last 16 bytes GCM tag, middle ciphertext; AES-256-GCM decrypt with the key. Legacy entries without v10 are raw DPAPI blobs → step 3.
6. Credential Manager: enumerate `%APPDATA%\Microsoft\Credentials\` and `%LOCALAPPDATA%\Microsoft\Credentials\` (amaterasu.rs harvests these listings); each file is a DPAPI blob whose plaintext is a vault credential structure — decrypt with the master key from step 3.
7. Ship plaintext/keys upstream (HUGIN: MSG_AMATERASU_HARVEST 0x21 with JSON; browser data via browser session module).

OS Internals Context content:
- Master key lifecycle: 64-byte random, generated per user, renewed on a schedule (Preferred file timestamps; ~90 days? I recall master keys expire every 90 days? Hmm — Preferred contains creation and expiry; default lifetime is often cited as 90 days? Actually I don't think master keys rotate by default on a timer... The Preferred file stores GUID + two FILETIMEs; renewal happens on password change primarily. I'll avoid the 90-day claim. Say: rotated when the password changes, CREDHIST preserves old hashes.)
- Password change handling: winlogon re-encrypts current master key with new password-derived key and appends old credential hash to CREDHIST; CREDHIST entries are themselves encrypted with the newer credential, forming a chain back through every historical password. This is well-established (Passcape docs). Confident.
- System scope: CRYPTPROTECT_LOCAL_MACHINE → machine store under `%WINDIR%\System32\Microsoft\Protect\S-1-5-18`? The machine master keys live in `C:\Windows\System32\Microsoft\Protect\S-1-5-18` and are encrypted with the DPAPI_SYSTEM LSA secret. I'm fairly confident about that path. Cluster spec says "system DPAPI key". Include, phrased carefully.
- CryptUnprotectData contract detail: entropy parameter — Chrome's encrypted_key uses no entropy (browser.rs passes None); flags 0; CRYPTPROTECT_UI_FORBIDDEN matters when running as SYSTEM/service to suppress UI. Keep to what's supportable: browser.rs passes None/None/0 — the API signature has pOptionalEntropy for application-supplied entropy (some apps set it; Chrome does not for Local State key). Is that claim safe? browser.rs passes None and it works — evidence from source. Fine.
- Kernel/user boundary: DPAPI is user-mode (crypt32.dll / dpapi.dll → RPC to... actually CryptProtectData is implemented in crypt32/dpapisrv? On modern Windows CryptProtectData is in crypt32.dll and calls into the DPAPI service? It's user-mode entirely; no syscall. The master key decryption happens in-process via crypto providers (CNG bcrypt for AES, RSA for backup). I'll state: entirely user-mode, implemented in crypt32.dll with CNG primitives; no kernel transition — which matters for hooking (EDR can hook crypt32!CryptUnprotectData in-process; indirect syscalls don't help/hinder here). Hmm — "EDR hooks crypt32" is a detection claim not in material. Keep internals neutral: "entirely user-mode; no NT syscall is involved, so syscall-level evasion is irrelevant to this primitive." That's structural, fine.
- Why LSASS matters: for logged-on users, the password-derived key material is available to the session (cached), which is why live CryptUnprotectData needs no password; tools dump cached master keys from LSASS. Is LSASS caching well-established? Yes — Mimikatz sekurlsa::dpapi. But naming Mimikatz... I can describe without naming: "the derivation secret (SHA1 of the password) is held by the authentication packages for the lifetime of the logon session, which is why a live call never prompts for a password and why offline attackers target LSASS memory or the SAM/NTDS for the hash." Reasonably well-established. Keep short.

Detection Considerations: material doesn't discuss → the exact sentence. 

Length check: I need ≥800 words body. Let me draft generously; target ~1300+.

Also the h1 format: `# <Technique Name> — <One-Line Purpose>`.

Section order fixed. Related Techniques: one entry T-023.

Source Reference: list both files with roles.

One more check on frontmatter `source_file`: single path. I'll use `src/client_rust/src/browser.rs`.

MITRE secondary: T1555.003. Also could add T1552.001? Restraint — two is fine. Actually is T1555.004 "Windows Credential Manager" the right *primary* for master key extraction? The technique's purpose is credential decryption across stores. T1555 is "Credentials from Password Stores". Master keys themselves are key material, not credentials... Alternative: T1003.008? No, that's /etc. Hmm, some map "DPAPI masterkey" to T1552.001 (Credentials In Files)? The master key file is a file containing cryptographic keys — T1552 is "Unsecured Credentials", .001 "Credentials In Files" — not a great fit either since keys are encrypted. The LGTM note frames it as prerequisite for browser + Credential Manager stores. Given the consolidated description ("Prerequisite for accessing browser and OS credential stores"), T1555.004 primary with .003 secondary is defensible and I'm confident both IDs exist. Go.

Now write the card. Watch banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". No first person, no rhetorical questions, no exclamation marks. No ratings/percentages. No suggestions.

Careful: "robust" banned — avoid. "solid" banned. Also avoid "notable" → don't say "notably".

Let me draft.

---

Summary draft:

"DPAPI master key extraction locates and decrypts the per-user master keys in `%APPDATA%\Microsoft\Protect\<SID>` so that any DPAPI-protected secret on the host can be decrypted, either in the user's live session or fully offline. Windows routes every user-scope CryptProtectData call through one of these 64-byte master keys, each stored as a GUID-named file encrypted with a key derived from the user's logon password and, for domain accounts, additionally wrapped under the domain DPAPI backup key. CRTO identifies DPAPI as the substrate behind both Windows Credential Manager (RDP saved credentials) and Google Chrome's stored website passwords, which makes the master key the single artifact standing between an operator and every cached secret on the machine. Because the blob format embeds the master key GUID, a single decrypted master key unlocks every blob the user has ever produced under it. The technique's exposure is confined to file reads under the Protect directory and execution inside the target user's logon session; the training material does not document detection content for it."

Good — 5 sentences.

Mechanism: 7 numbered steps as outlined.

OS Internals Context: paragraphs on master key file structure, derivation chain, CREDHIST, system scope, CryptUnprotectData contract, Chrome key hierarchy, user-mode-only.

Key Implementation Details: browser.rs functions + amaterasu.rs harvest_dpapi; note what's absent (offline path).

Why It Matters: 2-4 sentences. T-023 covers credential harvest broadly (wifi, LSASS dump, WMI) but no DPAPI substrate; this is the rate-limiting step for offline decryption per the LGTM note; distinct primitive reused by every store.

Detection: the single sentence.

Related: T-023 — this card documents the DPAPI sub-step that T-023's credential-harvest coverage assumes but never describes.

References: atlas-post-exploit-part9.md (units 20-21); MITRE T1555.004 + T1555.003 URLs; LGTM note; SharpChromium (named in unit 21); MS-BKRP protocol doc? That's a public reference not named in the material... "do not invent references" — MS-BKRP is real Microsoft documentation, not invented. The rule says optional public references "named in the atlas material". Strictly, only SharpChromium qualifies. I'll list SharpChromium. I mentioned MS-BKRP in mechanism — that's fine as a factual protocol name (Microsoft doc), but I won't put it in References to stay strict. Hmm, or I can include it since it is real documentation and rule 4 permits well-established docs as claim sources. References rule says "named in the atlas material; do not invent references". MS-BKRP is not in the atlas material. Keep References strict: SharpChromium only.

Source Reference: both files with line-level roles.

Now, word count. Let me write it fully and estimate.

Also mechanism step 2 claim: DPAPI blob header contains provider GUID and master key GUID — well-established (Passcape "DPAPI blob structure": DWORD version, GUID provider (df9d8cd0-1501-11d1-8c7a-00c04fc297eb), version, GUID masterkey, ...). Confident.

PBKDF2 details: master key decryption: SHA1(UTF16 password) → PBKDF2(HMAC-SHA512, salt, rounds) → key for 3DES-CBC (legacy) to decrypt; HMAC-SHA1? The file stores HMAC for validation using HMAC-SHA512? I'll keep: "derive SHA1 of the UTF-16LE password, run PBKDF2-HMAC-SHA512 with the salt and round count stored in the file, and use the result to decrypt the 64-byte master key (3DES-CBC in the legacy format; AES in the v2 format introduced in later Windows 10 builds); a stored HMAC validates correct decryption." The v2/1607+ claim: hashcat 15900 "DPAPI masterkey file v2 (Windows 10 1607+)" — I'm confident enough with "later Windows 10 builds" phrasing.

Domain backup: RSA-2048? I believe the domain backup key is RSA-2048. To be safe say "an RSA private key held by domain controllers". Avoid bit size.

System store path: `C:\Windows\System32\Microsoft\Protect\S-1-5-18` — confident. DPAPI_SYSTEM secret in LSA secrets — confident.

Master key renewal: The Preferred file holds GUID + creation/expiration FILETIMEs; default master key lifetime — commonly cited as 90 days? Passcape says master key lifetime ~90 days? Hmm, actually I recall the Preferred file contains the GUID and two timestamps and keys rotate roughly every 90 days? I've seen "the system reissues master keys every 90 days" in some writeups... Not fully sure. Omit the number; say "new keys are minted on password change and on the schedule recorded in Preferred" — risky. Simpler: "the Preferred file names the currently active master key; older GUID-named files remain on disk and remain decryptable via CREDHIST." Safe.

Chrome cookie path: `Network\Cookies` (modern) with fallback `Cookies` — from source.

Word target: let me write ~1400-1600 words body.

Write it now, carefully avoiding banned terms. Also avoid starting sections with narration.

One more consideration: crate = client_rust. Tier A. Category discovery.

Also note in Key Implementation Details the feature-gate: `aes-gcm` feature; without it, `win_aes_gcm_decrypt` bails and v10 passwords fall back to DPAPI attempt (which fails for v10 blobs, returning empty). Also copy_to_temp to dodge SQLite locks. Also the MSG protocol 0x21 and dispatch via "dpapi"/"all" harvest types.

Length of Mechanism: 7 steps with sub-bullets — fine.

Write final output: one markdown file, YAML frontmatter first, nothing else.