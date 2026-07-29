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

# DPAPI Master Key Extraction — Decrypting the Root Key Behind Chrome and Credential Manager Secrets

## Summary

DPAPI master key extraction locates and decrypts the per-user master keys stored in `%APPDATA%\Microsoft\Protect\<SID>` so that any DPAPI-protected secret on the host can be recovered, either inside the user's live logon session or fully offline. Windows routes every user-scope `CryptProtectData` call through one of these 64-byte master keys, each persisted as a GUID-named file encrypted with a key derived from the user's logon password and, for domain accounts, additionally wrapped under the domain DPAPI backup key. CRTO identifies DPAPI as the cryptographic substrate behind both Windows Credential Manager (saved RDP credentials) and Google Chrome's stored website passwords, which makes the master key the single artifact between an operator and every cached secret on the machine. Because each DPAPI blob header embeds the GUID of the master key that produced it, one decrypted master key unlocks every blob the user has ever created under it. The technique's exposure is confined to file reads under the Protect directory and code execution in the target user's session; the training material does not document detection content for it.

## Mechanism

1. Resolve the target user's master key store at `%APPDATA%\Microsoft\Protect\<SID>\`. Enumerate the GUID-named master key files and the `Preferred` file, which records the GUID of the currently active master key along with its creation and expiration timestamps. The HUGIN client performs this enumeration in `harvest_dpapi()` (`amaterasu.rs`), returning path and size metadata for every file under each SID subdirectory.
2. Identify which master key a given ciphertext needs. Every DPAPI blob carries a header containing the DPAPI provider GUID (`df9d8cd0-1501-11d1-8c7a-00c04fc297eb`) and the GUID of the master key that encrypted it; that GUID is the filename to open in the Protect directory.
3. Select the decryption path:
   - **Live user-context path.** Execute as the target user — or call `LogonUser` with the user's credentials and impersonate the resulting token — then call `CryptUnprotectData` on the blob. Windows locates the referenced master key, derives the decryption key from material held for the logon session, and returns the plaintext. This is the path implemented in `browser.rs` via `dpapi_decrypt()`.
   - **Offline password path.** Copy the GUID-named master key file and parse its structure: version fields, salt, PBKDF2 iteration count, validation HMAC, and the encrypted key material. Compute `SHA1(UTF-16LE(password))`, run PBKDF2-HMAC-SHA512 with the stored salt and round count, and use the derived key to decrypt the embedded 64-byte master key — 3DES-CBC in the legacy format, AES in the v2 format used by later Windows 10 builds. A stored HMAC confirms correct decryption. The `CREDHIST` file in the same directory chains previously used passwords, so master keys encrypted under older credentials remain recoverable.
   - **Domain backup key path.** For domain accounts, each master key file carries a second copy of the key wrapped under the domain's DPAPI backup key, an RSA private key held by domain controllers and retrievable by a Domain Admin through the MS-BKRP BackupKey remote protocol. Possession of the backup key decrypts any domain user's master keys without knowing any password.
4. Chromium browser decryption: read `%LOCALAPPDATA%\<Browser>\User Data\Local State`, parse the JSON field `os_crypt.encrypted_key`, base64-decode it, strip the 5-byte literal `DPAPI` prefix, and DPAPI-decrypt the remainder. The plaintext is the 32-byte AES-256-GCM key the browser uses for all versioned entries.
5. Decrypt versioned browser records: for each `password_value` row in the `Login Data` SQLite database (`logins` table) or `encrypted_value` in `Network\Cookies`, check the `v10` prefix. Bytes 3–14 are the 12-byte GCM nonce, the final 16 bytes are the GCM tag, and the bytes between are ciphertext; decrypt with AES-256-GCM using the key from step 4. Legacy rows without a `v10` prefix are raw DPAPI blobs and go through step 3 directly.
6. Credential Manager decryption: enumerate `%APPDATA%\Microsoft\Credentials\` and `%LOCALAPPDATA%\Microsoft\Credentials\` — both listing paths are harvested by `harvest_dpapi()` — and treat each file as a DPAPI blob. Decrypting with the master key from step 3 yields the vault credential structure containing the stored RDP or generic secret.
7. Return results to the operator channel. In the HUGIN client, DPAPI artifact inventory is shipped as JSON in `MSG_AMATERASU_HARVEST` (0x21), and decrypted browser rows are returned through the browser data module.

## OS Internals Context

DPAPI is entirely a user-mode facility. `CryptProtectData` and `CryptUnprotectData` are exported from `crypt32.dll`, take `CRYPT_INTEGER_BLOB` (`cbData`/`pbData`) input and output structures, accept an optional application-supplied entropy blob and a prompt structure, and require the caller to release the output with `LocalFree`. No NT syscall is involved, so syscall-level evasion is irrelevant to this primitive; everything happens in the calling process against files and CNG crypto providers. The HUGIN implementation calls it with no entropy, no prompt, and flags `0` — matching Chrome's own usage for the `Local State` key, which is why a bare `CryptUnprotectData` call in the user's session suffices.

The master key file format is the load-bearing structure. Each GUID-named file holds a salt, the PBKDF2 round count, an HMAC for validating a candidate password, and the master key itself encrypted under the derived key. The derivation chain — `SHA1(UTF-16LE password)` feeding PBKDF2-HMAC-SHA512 — is the reason an NTLM hash or plaintext password is equivalent to session access for offline work. When a user changes their password, the system re-encrypts the current master key under the new credential and appends the previous credential material to `CREDHIST` in the same directory; each CREDHIST entry is itself encrypted under the next-newest credential, forming a chain that lets an operator with one historical password walk back through every prior master key.

Machine-scope blobs are a separate hierarchy. When a caller sets `CRYPTPROTECT_LOCAL_MACHINE`, DPAPI uses the system store under `C:\Windows\System32\Microsoft\Protect\S-1-5-18`, whose keys are protected by the `DPAPI_SYSTEM` LSA secret rather than any user password. User-scope and machine-scope master keys never mix, which is why per-user browser and vault secrets require the user's key hierarchy specifically.

For a logged-on user, the password-derived material needed to unwrap master keys is held for the lifetime of the logon session by the authentication packages. This is what makes the live path silent — `CryptUnprotectData` never prompts — and it is also why memory acquisition of LSASS on a host with active sessions yields the same keys the offline path would derive from a password hash.

Chrome's two-layer scheme sits on top of this. The browser generates its own AES-256-GCM key and protects only that key with DPAPI (the `encrypted_key` blob in `Local State`); individual passwords and cookies are then AES-GCM encrypted under it. Stealing the database files alone yields nothing; stealing the database plus the user's session, password, or hash yields everything, which is the asymmetry this technique exploits.

## Key Implementation Details

Two files in `client_rust` touch this technique, implementing different legs of it.

`src/client_rust/src/browser.rs` implements the live decryption leg end-to-end for Chrome and Edge:

- `get_chrome_aes_key()` reads `Local State`, extracts `os_crypt.encrypted_key`, base64-decodes with the standard engine, validates length, strips the 5-byte `DPAPI` prefix, and hands the remainder to `dpapi_decrypt()`.
- `dpapi_decrypt()` is a thin Windows-only wrapper over `CryptUnprotectData` using `windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB`, passing `None` for description, entropy, reserved, and prompt, flags `0`, and freeing the output with `LocalFree`.
- `chrome_decrypt_pw()` implements the `v10` split exactly as the format specifies — nonce at `[3..15]`, tag as the trailing 16 bytes — and dispatches to `aes_256_gcm_decrypt()`, which uses the `aes-gcm` crate when the `aes-gcm` feature is enabled. Without the feature, `win_aes_gcm_decrypt()` bails and the function falls back to a raw DPAPI attempt, which only succeeds for legacy pre-`v10` entries.
- `read_login_data()`, `read_cookies()`, and `read_history()` open SQLite via `rusqlite` against a temp copy produced by `copy_to_temp()`, avoiding lock contention with the running browser. Cookies resolve `Network\Cookies` first with a fallback to the legacy `Cookies` location. Firefox is metadata-only: `logins.json` entries are reported as `(encrypted — NSS required)` because NSS decryption is not implemented.

`src/client_rust/src/amaterasu.rs` implements the artifact-discovery leg through `harvest_dpapi()`, dispatched on the `dpapi` or `all` harvest types. It inventories `Local State` files for Chrome, Edge, Brave, and Opera (recording size and whether `encrypted_key` is present), lists the local and roaming `Microsoft\Credentials` directories, and walks `%APPDATA%\Microsoft\Protect` collecting master key file paths and sizes — explicitly metadata only.

What is not implemented: master key file parsing, the PBKDF2 derivation chain, `CREDHIST` handling, domain backup key usage, and Credential Manager blob decryption. The source covers discovery plus the live `CryptUnprotectData` path; the offline leg documented in the Mechanism section would be implemented against the same Protect-directory artifacts the client already enumerates.

## Why It Matters

T-023 covers credential harvesting as a capability set — WiFi keys, LSASS dumps, WMI execution — and the client ships working browser decryption code, but no card documents the DPAPI substrate both depend on. The LGTM note identifies the master key access step as the rate-limiting step for offline credential decryption: every browser and vault secret on a host reduces to one file per user plus one of three secrets (session, password hash, domain backup key). That convergence makes the master key a distinct primitive with its own locations, formats, and access paths rather than a footnote inside browser extraction.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-023 Client Capabilities Suite** — T-023's credential-harvesting coverage (WiFi, LSASS dump, browser data, WMI) assumes access to DPAPI-protected stores without documenting the master key step; this card documents that sub-technique and the client modules (`browser.rs`, `amaterasu.rs`) that implement parts of it.

## References

- Atlas material: atlas-post-exploit-part9.md (units 20–21: CRTO coverage of DPAPI as the encryption layer for Credential Manager and Chrome, and Chrome `Login Data` extraction from the AppData directory)
- MITRE ATT&CK: T1555.004 — Windows Credential Manager (https://attack.mitre.org/techniques/T1555/004/); T1555.003 — Credentials from Web Browsers (https://attack.mitre.org/techniques/T1555/003/)
- LGTM notes: lgtm:dpapi-master-key-extraction
- Public references: SharpChromium (named in atlas unit 21 as the reference tool for Chrome `Login Data` extraction)

## Source Reference

- `src/client_rust/src/browser.rs` — live decryption leg: `get_chrome_aes_key()`, `dpapi_decrypt()` (`CryptUnprotectData`), `chrome_decrypt_pw()` (v10 AES-256-GCM), `read_login_data()`/`read_cookies()`/`read_history()`.
- `src/client_rust/src/amaterasu.rs` — artifact discovery leg: `harvest_dpapi()` enumerates browser `Local State` files, local and roaming `Microsoft\Credentials` directories, and the `%APPDATA%\Microsoft\Protect\<SID>` master key store (metadata only).
- No offline master key decryption (password-derivation or domain backup key paths) exists in the source. See the Mechanism section and MITRE references for the offline workflow.