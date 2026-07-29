---
id: T-137
name: Registry Hive Operational Map
category: discovery
tier: A
crate: none
source_file: none
mitre: T1012
mitre_secondary: [T1003.002, T1003.005, T1087.001, T1069, T1518]
tags: [registry-hive, sid-discovery, sam-dump, dcc-hash, services-enum, software-discovery, system-token, sebackup-privilege, offline-credentials, secretsdump, regsave]
member_notes: ['lgtm:coverage-registry-hive-operational-map']
origin: atlas-synthesis
---

# Registry Hive Operational Map — Six Hives and the Operational Surface Each One Discovers

## Summary

The Windows registry is the operational substrate consumed by nearly every discovery, credential-access, persistence, and reconnaissance routine on a host. This card enumerates the six hives that recur in tradecraft, names the specific values and subkeys that each operational phase pivots through, and maps each hive to its privilege boundary. The hives of record are: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` (the `ProfileImagePath` REG_EXPAND_SZ value yielding the SID↔username↔home-directory mapping — readable without elevation), `HKEY_USERS` (with `.DEFAULT` mounted from `%SystemRoot%\System32\config\default` for the SYSTEM account at boot, distinct from per-session `<SID>` and `<SID>_Classes` mounts loaded by `NtLoadKeyEx` at user logon), `HKLM\SAM\SAM\Domains\Account\Users\<RID>` (the local account `V` and `F` values holding RC4-wrapped NTLM hashes — readable only by `NT AUTHORITY\SYSTEM` because the hive Security Descriptor grants read/write to SYSTEM alone), `HKLM\SECURITY\Cache\NL$<n>` (the Domain Cached Credential — MSCASHv2 — entries, also SYSTEM-only and decryptable only with the boot key extracted from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`), `HKLM\SYSTEM\CurrentControlSet\Services` (per-service `ImagePath`, `Start`, `Type`, `ObjectName`, `FailureActions` for service and driver inventory), `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (DisplayName/DisplayVersion/UninstallString for installed software, with the `Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` mirror for 32-bit installs), and `HKCU\Software` (per-user application config, including `...\CurrentVersion\Run` for user-context persistence and `...\Explorer\Shell Folders` for default loot paths). The standard secrets-extraction pipeline is `reg save HKLM\SAM` + `reg save HKLM\SYSTEM` + `reg save HKLM\SECURITY` from a SYSTEM-context process, followed by `secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL`. The vault's T-017 card documents the cross-session credential pipeline that yields the SYSTEM token this card's SAM/SECURITY reads depend on, and T-023 documents the host-recon flow that consumes this card's Services and Uninstall enumerations — the present card documents the registry substrate underneath both.

## Mechanism

Each hive is operated by a distinct API sequence, privilege envelope, and post-processing pipeline. The seven operational surfaces below cover the cluster's anchors plus their adjacent pivots.

### Variant 1: ProfileList → SID↔Username Map

1. Open `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` via `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey)`. No elevation required — the SD grants `KEY_READ` to `BUILTIN\Users`.
2. Enumerate subkeys via `RegEnumKeyExW(hKey, dwIndex, lpName, &cchName, NULL, NULL, NULL, NULL)` until `ERROR_NO_MORE_ITEMS`. Each subkey name is a string SID of the form `S-1-5-21-<domain>-<rid>`, including `S-1-5-21-...-500` for the built-in Administrator and `...-501` for Guest.
3. For each subkey, open with `RegOpenKeyExW(hParent, lpSidString, 0, KEY_QUERY_VALUE, &hUserKey)` and read `ProfileImagePath` via `RegQueryValueExW(hUserKey, L"ProfileImagePath", NULL, &dwType, lpData, &cbData)`. Type is `REG_EXPAND_SZ` (= `2`). Expand environment variables with `ExpandEnvironmentStringsW` — `C:\Users\jsmith` yields the username component.
4. Read the optional `Sid` value (`REG_BINARY`, the SID in its self-relative binary form) and `State` (`REG_DWORD`, `0x0` = active, `0x100` = temp profile, `0x200` = mandatory profile).
5. Cross-reference against `HKU\<SID>` mounts to distinguish profiles that have an active session from those with only on-disk state. The `.DEFAULT` hive at `HKU\.DEFAULT` corresponds to the SYSTEM account, not to a SID-named mount.

### Variant 2: HKU Session and Hive Mount Map

1. Open `HKEY_USERS` and enumerate via `RegEnumKeyExW`. Visible subkeys: `.DEFAULT` (loaded from `%SystemRoot%\System32\config\default` by `Winlogon` at boot), `S-1-5-18` / `S-1-5-19` / `S-1-5-20` (machine / LocalService / NetworkService accounts whose hives are mounted by the SCM at service-host spawn), and `<user-SID>` entries for each user with a loaded hive — live session, lingering post-logoff load, or `NtLoadKeyEx` runtime mount.
2. Each `<SID>` has a parallel `<SID>_Classes` subkey — the user's merged `HKCR` backed by `HKCU\Software\Classes` plus `HKLM\SOFTWARE\Classes`.
3. To enumerate active sessions specifically, read `HKU\<SID>\Volatile Environment` — this subkey is created only at session start (by `userenv`) and destroyed at logoff. Its absence indicates a stale hive mount.
4. To map hive-mount back to file path, query `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` — each value name is a registry path (e.g., `\Registry\User\S-1-5-21-...`) and its data is the on-disk file path (e.g., `\Device\HarddiskVolume3\Users\jsmith\NTUSER.DAT`).
5. A loaded hive can be unloaded with `RegUnLoadKeyW(HKEY_USERS, L"<SID>")` if no handles remain open in the calling process — the SCM uses this on logoff.

### Variant 3: HKLM\SAM → Local NTLM Hashes

1. Open `HKLM\SAM` via `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey)`. Returns `ERROR_ACCESS_DENIED` (`5`) for any non-SYSTEM token, including Administrators. The hive SD is granted to `NT AUTHORITY\SYSTEM` exclusively — `SeBackupPrivilege` does NOT bypass this open path; it is only checked later when `RegSaveKeyEx` writes the destination file.
2. Acquire a SYSTEM token. Three common paths: (a) spawn a process as `LocalSystem` via `CreateProcessWithLogonW` against an existing LocalSystem service or `PsExec64.exe -s`; (b) duplicate the SYSTEM token from `lsass.exe` (`PID` discoverable via `NtQuerySystemInformation(SystemProcessInformation)`) using `NtOpenProcess` + `NtQueryInformationProcess(ProcessAccessToken)` + `NtDuplicateToken`; (c) take ownership of the `SAM` hive key with `SeTakeOwnershipPrivilege` and rewrite the SD via `NtSetSecurityObject` to grant Administrators `KEY_READ` — generates loud `CmRegisterCallback` events but no `lsass.exe` process interaction.
3. From SYSTEM, execute `reg.exe save HKLM\SAM C:\\Windows\\Temp\\sam.hive /y`. Internally: `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey)`, then `RegSaveKeyExW(hKey, L"C:\\Windows\\Temp\\sam.hive", NULL, REG_LATEST_FORMAT)` — the latter resolves to `NtSaveKeyEx(KeyHandle, FileHandle, REG_LATEST_FORMAT = 0x0008)`. The Configuration Manager (`nt!Cmp`) reads from the in-memory KCB tree and cell cache, NOT from the on-disk file — so `lsass.exe`'s file-lock on `%SystemRoot%\System32\config\SAM` is irrelevant.
4. Also save `HKLM\SYSTEM` to `C:\Windows\Temp\system.hive` — needed to derive the boot key (syskey).
5. Reconstruct the boot key from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` — four values: `JD`, `Skew1`, `GBG`, `Data`. Each is `REG_SZ` holding 8 hex characters (UTF-16LE-encoded; decode to 8 ASCII bytes, hex-decode to 4 raw bytes). Concatenate `JD`+`Skew1`+`GBG`+`Data` to obtain 16 bytes, then apply the fixed permutation `[8, 5, 4, 2, 11, 9, 13, 3, 7, 1, 12, 14, 6, 0, 10, 15]` to produce the final 16-byte boot key. secretsdump.py implements this in its `getBootKey`.
6. Walk the user records at `HKLM\SAM\SAM\Domains\Account\Users\<RID>` where `<RID>` is 8-hex-digit zero-padded (e.g., `000001F4` for the built-in Administrator, RID `0x1F4`). Each subkey has two values: `V` (`REG_BINARY`, ~0xCC bytes, the user record including the LM and NTLM hash) and `F` (`REG_BINARY`, the `_SAM_USER_F` metadata struct).
7. The `V` value's layout is `[header][field-table][field-data]`. The first 0xC bytes are header; bytes `0xC` onward are `(length: WORD, offset: WORD)` tuples pointing into the same buffer for username, fullname, comment, home dir, script path, profile path, workstation, logon hours, LM hash, NTLM hash. secretsdump parses this table dynamically — offsets are not fixed because the field lengths depend on username length and SAM schema version.
8. Username lookup alternative: read `HKLM\SAM\SAM\Domains\Account\Users\Names\<username>` — its value (`V`, REG_BINARY) is a binary structure containing the RID.
9. Decrypt the LM/NTLM hashes: RC4 (the AES variant exists on newer builds when `HKLM\SAM\SAM\Domains\Account\F` of `F` of the user record contains the hash type flag, but legacy RC4 remains dominant). RC4 key = `boot_key` of step 5, prefixed with `aN`/`L` byte and the user's RID little-endian — the precise construction is `MD5(boot_key + RID_le + hash_class_id)` for AES variants; for legacy RC4 the key is built as documented by `impacket`'s `CryptoCommon` class.
10. Pipe to `secretsdump.py -sam sam.hive -system system.hive LOCAL` → `username:RID:LM_hash:NTLM_hash:::` lines. Mimikatz equivalent: `lsadump::sam /sam:sam.hive /system:system.hive` offline, or `lsadump::sam` in-memory from a SYSTEM-context process.

### Variant 4: HKLM\SECURITY\Cache\NL$ → Cached Domain Credentials (DCC1/DCC2)

1. Open `HKLM\SECURITY\Cache` from a SYSTEM-context process. The hive lives on disk at `%SystemRoot%\System32\config\SECURITY`. The hive SD mirrors SAM — Administrators have no read access by default.
2. Read the values `NL$01` through `NL$10`. Default `CachedLogonsCount` is `10`, configurable in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (value `CachedLogonsCount` REG_SZ). A value of `0` disables caching — defensive hardening worth probing before expending the credential-access budget.
3. Each `NL$<n>` value is `REG_BINARY`, typically `0x60` (96) bytes for DCC1 entries or `0x74` (116) bytes for DCC2 entries. Layout:
   - Byte 0: `UserDomainLength` (or iteration hint)
   - Byte 1: `UserNameLength`
   - Bytes 2..3: flags — `0x01` = DCC1, `0x07` = DCC2 (PBKDF2-HMAC-SHA1 with 10240 iterations)
   - Bytes 4..19: encrypted DCC hash
   - Bytes 20..35: lowercase username (UTF-16LE, zero-padded to 16 bytes)
   - Bytes 36..63: domain name and extended metadata
   - Bytes 64..67: iteration count (DCC2 only; `0x2800` = 10240)
4. Decrypt the hash: the `HKLM\SECURITY\Cache` value `NL$IterationCount` (REG_DWORD) overrides the default iteration count. The wrapping key derives from the boot key (syskey) and the per-record iteration count.
5. secretsdump pipeline: `secretsdump.py -security security.hive -system system.hive LOCAL` → `username:DCC2:iteration_count:hex1:hex2` lines. Hashcat mode `2100` (MSCASHv2) cracks at ~1.2M H/s on a single RTX 4090 — domain-cred cracking remains expensive but feasible with a small candidate set.
6. Mimikatz equivalent: `lsadump::cache` (in-memory) reads via `LsaEnumerateLogonSessions` indirectly, NOT via registry — but the underlying blob is the same.

### Variant 5: HKLM\SYSTEM\CurrentControlSet\Services → Service/Driver Inventory

1. Open `HKLM\SYSTEM\CurrentControlSet\Services`. No elevation needed — readable by `BUILTIN\Users`. `CurrentControlSet` is an aliased view of `ControlSet001` or `ControlSet002`, selected at boot via `HKLM\SYSTEM\Select\Current` (REG_DWORD). The alias is a `_CM_KEY_NODE` with `Parent` pointing to `HKLM\SYSTEM` and a special registry link entry — reads transparently redirect to `ControlSet00X`.
2. Enumerate subkeys — each is one service or driver. Per subkey read the canonical values:
   - `ImagePath` (REG_EXPAND_SZ): absolute path to the executable or `.sys` driver binary; for `svchost`-hosted shared services this is `%SystemRoot%\system32\svchost.exe -k <group>` and the real DLL is at `Parameters\ServiceDll` subkey.
   - `DisplayName` (REG_SZ): friendly name shown in `services.msc`
   - `Description` (REG_SZ): longer human-readable description
   - `Start` (REG_DWORD): `0`=Boot | `1`=System | `2`=Auto | `3`=Manual/Demand | `4`=Disabled. Drivers can be `0`/`1` (loaded by `bootvid`/`ntldr` before SCM).
   - `Type` (REG_DWORD): `0x10`=`SERVICE_WIN32_OWN_PROCESS`, `0x20`=`SERVICE_WIN32_SHARE_PROCESS`, `0x50`=interactive variant of own-process, `0x100`+interactive flag, `0x01`=`SERVICE_KERNEL_DRIVER`, `0x02`=`SERVICE_FILE_SYSTEM_DRIVER`.
   - `ObjectName` (REG_SZ): service account — `LocalSystem` / `NT AUTHORITY\LocalService` / `NT AUTHORITY\NetworkService` / `DOMAIN\user` / UPN. Only populated for Win32 services, not drivers.
   - `DependOnService` / `DependOnGroup` (REG_MULTI_SZ): dependency lists.
   - `FailureActions` (REG_BINARY): `SC_ACTION` array — reboot / restart / run-command paths.
   - `DelayedAutostart` (REG_DWORD `1`): triggers SCM's delayed-auto-start pool (~30s post-boot).
3. Pivot surfaces: (a) `ImagePath` with unquoted path containing spaces (e.g., `C:\Program Files\My Service\svc.exe`) → unquoted-service-path persistence; (b) `ObjectName` = `DOMAIN\user` → token impersonation target if the service exposes any IPC; (c) `Start == 2 && DelayedAutostart == 1` → persistence installation candidate (modify `ImagePath` or `FailureActions` to gain boot-early execution).
4. Driver inventory pivot: `HKLM\SYSTEM\CurrentControlSet\Enum\< enumerator >\<instance>` cross-references hardware instances to loaded drivers; `HKLM\SYSTEM\CurrentControlSet\Services\<drv>\Enum` (REG_MULTI_SZ) lists the instances the driver claims.

### Variant 6: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall → Installed Software

1. Open `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` — readable without elevation. Enumerate subkeys. Each is `{GUID}` for MSI/MSIX installs or a free-form name (e.g., `Mozilla Firefox 115.0`) for legacy installers.
2. Per subkey, read:
   - `DisplayName` (REG_SZ): product name
   - `DisplayVersion` (REG_SZ): version string
   - `Publisher` (REG_SZ): vendor
   - `InstallDate` (REG_SZ `YYYYMMDD`): install date (sourced from the local clock at install time — spoofable)
   - `InstallLocation` (REG_SZ): root directory (often absent for MSI installs — the MSI manifest holds the real layout)
   - `UninstallString` (REG_SZ): command line to uninstall — `MsiExec /X{GUID}` for MSI, custom uninstaller for legacy.
   - `QuietUninstallString` (REG_SZ): silent uninstall command — useful when you need to remove a security product before further ops.
   - `WindowsInstaller` (REG_DWORD `1`): MSI-managed (vs. NSIS/Inno/legacy).
3. Also enumerate `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` — the WOW64 redirector silently maps a 32-bit app writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` here instead. Skipping this branch misses every 32-bit install on x64 Windows.
4. Also enumerate `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` — per-user installs (no admin elevation required) like ClickOnce, App-V, and many Electron app installers.

### Variant 7: HKCU\Software → User App Config and Persistence Surface

1. Open `HKEY_CURRENT_USER\Software` — auto-maps to the impersonating thread's `HKU\<SID>`. In a default token context, this is the logged-on user's hive (loaded from `%USERPROFILE%\NTUSER.DAT` via `NtLoadKeyEx` by `userinit.exe` at logon).
2. Recon targets:
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — user-context autorun (REG_SZ `name`=`command`). Live persistence — invoked by `explorer.exe` at user-logon.
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` — single-shot persistence.
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` and `User Shell Folders` — default loot paths: `Personal` (`%USERPROFILE%\Documents`), `Desktop`, `My Pictures`, `Favorites`. The `User Shell Folders` variant uses REG_EXPAND_SZ with env vars.
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` — MRU list of recent files (REG_BINARY records holding the path + link-resolved target).
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` — typed Explorer address-bar history.
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` — typed Run-dialog history (REG_SZ `a`=first entry, `b`=second, etc., and `MRUList`=ordering).
3. App-specific config: `HKCU\Software\Microsoft\Office\<ver>\...\Security\Trusted Sites`, `HKCU\Software\Google\Chrome\...`, `HKCU\Software\JetBrains\...`, `HKCU\Software\Microsoft\Terminal Server Client\Default` (saved RDP targets with MRU).
4. Cross-session dump: an attacker with another user's `NTUSER.DAT` can `reg load HKU\offlineload C:\path\NTUSER.DAT`, enumerate `HKU\offlineload\Software`, then `reg unload HKU\offlineload` — same hive bytes, no logon session required. This bypasses per-user security boundaries entirely if the file is readable (it is, by default, ACL'd to the owning user only — but Administrators can take ownership).

## OS Internals Context

**REGF hive file format**. The on-disk hive begins with a 4 KB base block — the `_HBASE_BLOCK`. Its signature at offset `0x0` is `"regf"` (`0x66676572`). Header fields of operational interest: `Sequence` at `0x4` (monotonic, bumped on every hive flush), `TimeStamp` at `0x8` (FILETIME of last write), `Major` at `0x14` (`1`), `Minor` at `0x18` (`5` for Vista+, `3` for XP), `Type` at `0x1C`, `Format` at `0x20` (`1` for memory, `0` for file), `RootCellOffset` at `0x24` (relative to the end of the base block, usually `0x1000`), `HiveBinCount` at `0x28`, `HiveLength` at `0x2C` (size of the body in bytes), `Checksum` at `0x1FC` (XOR of the first `0x1FB` DWORDs — used to detect corruption). At offset `0x30` begins a 64-UTF-16-byte filename field, set by `CmpInitializeHive` from the hive's mount name (e.g., `\Device\HarddiskVolume3\Windows\System32\config\SAM`).

Each subsequent hbin begins with signature `"hbin"` at offset `0x0`, `Offset` at `0x4` (the bin's offset within the hive body, not the file), `Size` at `0x8` (multiple of 4 KB), reserved fields to `0x20`. Cells follow from `0x20`. A cell's first DWORD is its length, sign-encoded: bit `0x80000000` clear means used (positive), set means free. Inside a used cell, the cell-type signature is the first two bytes:
- `nk` (`0x6E6B`) — named key node. Fields: `LastWritten` (FILETIME at `0x4`), `AccessBits` at `0xC`, `Parent` (cell offset at `0x10`), `SubkeyCountStable` at `0x18`, `SubkeyCountVolatile` at `0x1C`, `SubkeysOffsetStable` at `0x20`, `SubkeysOffsetVolatile` at `0x24`, `ValueList.Count` at `0x28`, `ValueList.Offset` at `0x2C`, `Security` at `0x30`, `ClassName` at `0x34`, `MaxNameLen` at `0x40`, `MaxClassLen` at `0x44`, `Flags` at `0x48` (`KEY_HIVE_EXIT` `0x0004`, `KEY_HIVE_ENTRY` `0x0002`, `KEY_NO_DELETE` `0x0008`, `KEY_VOLATILE` `0x0001`), `NameLen` at `0x4C`, then the UTF-16 name (variable length).
- `vk` (`0x766B`) — value key node. Fields: `NameLength` at `0xC`, `DataSize` at `0x10` (low 31 bits = size, top bit set = data is in the cell after the `vk`; clear = data in a separate cell at offset `DataOffset`), `DataOffset` at `0x14`, `DataType` at `0x18` (`REG_NONE` `0`, `REG_SZ` `1`, `REG_EXPAND_SZ` `2`, `REG_BINARY` `3`, `REG_DWORD` `4` big-endian-as-stored, `REG_MULTI_SZ` `7`, `REG_QWORD` `11`), `Flags` at `0x1C`, `Padding` at `0x1E`, then UTF-16 name (variable).
- Subkey-list cells: `lf` (leaf — index of `nk` pointers with name for sequential scan), `lh` (hash leaf — index plus name-hash for O(1) lookups, post-Win2k), `li` (subkey list with no hash, used for very large indices), `ri` (root index — list of subkey-list cells for keys whose child set exceeds one leaf).

**Configuration Manager and KCB tree**. In kernel memory, `nt!Cmp` owns one `_CMHIVE` per loaded hive, linked via `HiveList` into `cmhiveListHead`. Each `_CMHIVE` embeds an `_HHIVE Hive` field with `Storage[Stable]` and `Storage[Volatile]` — each is a `HCELL` array (`_DUAL` structure) of cells indexed by cell offset, parsed on demand. The KCB tree (`_CM_KEY_CONTROL_BLOCK`) is the in-memory mirror of the nk hierarchy; `ConvKey` is the hash of the full path used for `CmpCacheHashTable` lookup, and `ParentKcb` chains to the root. Every `OpenKey` walks the cached KCB tree rather than re-parsing hive bytes — which is why `reg save` reads from the in-memory CM cache, not from `lsass.exe`'s file lock on the on-disk hive.

**ACL on SAM and SECURITY**. The Security Descriptor applied to the `HKLM\SAM\SAM` root key during `CmpInitializeHive` grants `GENERIC_READ | GENERIC_WRITE` to `NT AUTHORITY\SYSTEM` alone — Administrators are explicitly absent from the DACL and the SACL on the SAM hive is empty for read access. The same pattern holds for `HKLM\SECURITY`. `SeAccessCheck` enforces this at `NtOpenKey` time; `SeBackupPrivilege` is NOT consulted at this site. The privilege matters only when the destination file is created by `RegSaveKeyEx` (which uses `NtCreateFile` and checks `SeBackupPrivilege` for the FILE_WRITE_DATA access right bypass). The mitigation `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` (`0x1` for restricted RDP admin) does not affect SAM access — these are independent enforcement points.

**`RegSaveKeyEx` semantics**. `RegSaveKeyExW(KeyHandleRoot, lpFile, lpType, REG_LATEST_FORMAT)` resolves through `advapi32` → `ntdll!NtSaveKeyEx(KeyHandle, FileHandle, Format)`. The CM allocates a new file, then walks the source hive's cells (starting at the root cell indicated by `KeyHandle`'s KCB), writes them to the destination file in REGF format (with the `regf` base block at offset 0, bin headers preserved, free cells zeroed — though some implementations preserve the original free-cell bytes for hive-fidelity). The destination file is a byte-identical dump of the hive's cells, modulo free-cell content. secretsdump and `hivex` parse this directly without needing the live system.

**Boot key derivation**. The 16-byte syskey is split across four `REG_SZ` values under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`: `JD`, `Skew1`, `GBG`, `Data`. Each holds 8 hex characters as UTF-16LE; decode to 8 ASCII bytes, hex-decode to 4 raw bytes. Concatenating all four yields 16 bytes. Apply the fixed scramble `[8, 5, 4, 2, 11, 9, 13, 3, 7, 1, 12, 14, 6, 0, 10, 15]` — `output[i] = input[scramble[i]]` — to produce the final 16-byte boot key. The scramble defeats simple byte-pattern signatures; impacket implements it in `impacket/examples/secretsdump.py`.

**CurrentControlSet aliased view**. At boot, `Winload.efi` reads `HKLM\SYSTEM\Select\Current` (REG_DWORD, typically `1`). The value selects the live `ControlSet00X`. `HKLM\SYSTEM\CurrentControlSet` is a symbolic link constructed by `CmpCreateControlSet` — its `_CM_KEY_NODE` has `Flags |= KEY_HIVE_EXIT` and a special registry link cell. The Configuration Manager's open path (`CmpLookupKey`) detects the alias and re-targets to `ControlSet001` (or whichever is selected). `HKLM\SYSTEM\Select\LastKnownGood` points to the LKG control set, used when the boot menu selects LKG. Dumping `HKLM\SYSTEM` saves both control sets — analysts must know which one was live at extraction time.

**DCC2 storage and PBKDF2**. Windows Vista+ stores cached domain credentials as MSCASHv2 — PBKDF2-HMAC-SHA1 over `password || username_lowercased`, with `iteration_count = 10240` (default; overridable via `HKLM\SECURITY\Cache\NL$IterationCount`). The 16-byte PBKDF2 output is wrapped by an encryption scheme seeded from the boot key, then stored at `NL$<n>+0x4..0x14`. The username's UTF-16LE lowercased form (zero-padded to 16 bytes) is stored at `NL$<n>+0x14..0x24`. Cracking a captured DCC2 hash with hashcat mode `2100` requires the candidate AND the lowercase username as the salt — that is why DCC2 hashes are typed in hashcat as `$DCC2$<iterations>#<username>#<hash>`.

## Variant Comparison Table

| Variant | Hive Path | Privilege | Operational Use | Detection Surface |
|---|---|---|---|---|
| ProfileList | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` | None (Users) | SID↔username enumeration | `RegEnumKeyExW` ETW-TI opcode |
| HKU Session Map | `HKEY_USERS` root | None | Active session enumeration | `RegEnumKeyExW` ETW-TI opcode |
| SAM Hashes | `HKLM\SAM\SAM\Domains\Account\Users\*` | `NT AUTHORITY\SYSTEM` | NTLM hash extraction | `NtSaveKeyEx` + `NtOpenKey(SAM)` + token-impersonation chain |
| NL$ Cache | `HKLM\SECURITY\Cache\NL$*` | `NT AUTHORITY\SYSTEM` | Domain cred exfiltration | `NtSaveKeyEx` + `NtOpenKey(SECURITY)` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services` | None (Users) | Service/driver inventory, persistence pivot | `RegEnumKeyExW` + `RegQueryValueExW` |
| Uninstall | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | None (Users) | Installed-software inventory | `RegEnumKeyExW` ETW-TI opcode |
| HKCU\Software | `HKCU\Software\*` | Per-user token | User-app config + Run-key persistence | `RegEnumKeyExW` + `RegSetValueExW` (when persisting) |

## Key Implementation Details

The SYSTEM-token requirement for SAM/SECURITY is the single most common implementation pitfall. `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey)` returns `ERROR_ACCESS_DENIED` (`5`) for any non-SYSTEM token, including Administrators with `SeBackupPrivilege` enabled. The hive Security Descriptor grants `KEY_READ` to `NT AUTHORITY\SYSTEM` exclusively — `SeBackupPrivilege` is consulted later, at the destination-file write site, not at the source-key open site. Operators frequently misremember this and waste cycles enabling `SeBackupPrivilege` on a non-SYSTEM token expecting the privilege to grant key open. It does not. The reliable recipe is to obtain a SYSTEM token — `PsExec64.exe -s` for an immediate interactive shell, or `NtDuplicateToken` against `lsass.exe` for in-process impersonation — then run `reg save` from that context.

The boot key extraction is brittle to a missing SYSTEM hive. `secretsdump.py -sam sam.hive LOCAL` without `-system system.hive` produces empty hashes — the program prints `[-] SAM hashes not found in this OS version` because it cannot decrypt without the syskey. Always collect all three hives together: `reg save HKLM\SAM C:\Windows\Temp\sam.hive /y && reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y && reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y`. The `SYSTEM` hive must be saved even if the operator only wants SAM hashes — boot key derivation depends on the `Lsa\JD/Skew1/GBG/Data` values, which live there.

The Wow6432Node redirector silently remaps 32-bit applications writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` to `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`. Enumerating only the non-Wow6432Node path misses every 32-bit-installed product — a substantial fraction of legacy software including many enterprise agents, older VPN clients, and unsigned drivers' userland helpers. The same redirect applies to `HKLM\SOFTWARE\Classes` and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — both have Wow6432Node mirrors. Operators who hardcode a single path frequently report false negatives.

The `CurrentControlSet` aliased view is only valid for the live system; the saved SYSTEM hive contains `ControlSet001` and `ControlSet002` directly. secretsdump probes `HKLM\SYSTEM\Select\Current` first to determine which control set was live, then walks `ControlSet00X\Control\Lsa\JD` etc. If the analyst saves the SYSTEM hive from a Windows machine running under LKG boot, the live control set is whatever `Select\LastKnownGood` points to — secretsdump may pick the wrong set and produce an incorrect boot key. Manually verify `Select\Current` matches the probed control set.

## Composition with Other Techniques

The canonical credential-extraction kill chain reaches the SAM hive via a SYSTEM-token acquisition step. A typical operator sequence:

1. Land with an Administrator-level beacon via WMI or service-creation (covered by T-017 if it is the cross-session delivery primitive).
2. Obtain a SYSTEM token — either by `NtImpersonateThread` against a `services.exe`-hosted LocalSystem thread, or by `CreateProcessWithTokenW` against a token duplicated from `wininit.exe`. T-017 enumerates the SYSTEM-token acquisition paths.
3. From SYSTEM, execute `reg save HKLM\SAM C:\Windows\Temp\sam.hive /y && reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y && reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y`. Three hives are required together.
4. Stage the hives out via the beacon's exfiltration channel (C2 channel typically; alt: SMB share to a controlled relay).
5. Offline: `secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL` produces NTLM + DCC2 hash set.
6. NTLM hashes go directly to lateral-movement tooling (`crackmapexec --ntlm`, `wmiexec.py --hashes`, `atexec.py`). DCC2 hashes go to hashcat mode `2100` for offline cracking — successful recoveries grant domain cred for further pivots.

The Services enumeration (Variant 5) feeds downstream persistence planning: services with `Start=2` and a weak `ImagePath` (unquoted, spaces, writable parent) are persistence-installation candidates, compose with the IFEO/SilentProcessExit technique (T-034) or with the Service-ImagePath tamper primitive covered separately in the persistence cluster.

The Uninstall enumeration (Variant 6) feeds downstream EDR-evasion planning: knowing the DisplayName and Publisher lets the operator match against detection signatures and select evasion primitives — for example, if `DisplayName="Crowdstrike Sensor` is present, the EDR-evasion cards on tampering with `CSFalconService.exe` and bypassing `mssecflt.sys` callbacks become relevant.

## Why It Matters

Every successful discovery on Windows ultimately reads one of these hives. The ProfileList enumeration is the cheapest, lowest-friction SID discovery on the platform — no privilege, no IPC, no API call into a sensitive syscall. It is the canonical first step of lateral-movement planning: SID-to-username mapping is required to target `\\<host>\C$\Users\<username>\...` paths and to populate Kerberos tickets. SAM and NL$ cache enumeration is the local-credential-extraction backbone — without these hives the operator has no local password material to crack or pass-the-hash with. Services enumeration tells the operator what is running, what services are candidates for hijack, and what drivers loaded into the kernel — directly informing the EDR-evasion surface. The Uninstall enumeration tells the operator what software is installed — and therefore what detection rules apply. The HKCU\Software enumeration tells the operator what the user does and where their data lives.

Vault cards T-017 and T-023 consume this substrate: T-017's SYSTEM-token acquisition is the prerequisite for SAM/SECURITY access, and T-023's host-recon flow is downstream of the Services and Uninstall enumerations produced here. This card sits upstream of both as a navigable map of where to look and what privilege each lookup requires. Cards like T-034 (IFEO / SilentProcessExit) and the broader persistence cluster compose with the Services enumeration documented here — T-034's IFEO writes happen in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, adjacent to but distinct from this card's ProfileList subkey.

## Detection Considerations

- **Telemetry sources**: `NtSaveKey` and `NtSaveKeyEx` are surfaced by the `Microsoft-Windows-Kernel-Registry` ETW provider (GUID `AE437328-C4A0-4D29-A4A7-1A3A0`-ish, channel Operational). The Event ID `4` (RegSaveKey) and Event ID `5` (RegRestoreKey) events log the caller PID and target file path. Sysmon Event IDs `12` (RegKeyCreate/Delete), `13` (RegValueSet), `14` (RegKeyRename) do NOT capture `RegSaveKey` — they capture set/delete/rename ops only. For SAM/SECURITY access via token impersonation, `Microsoft-Windows-Threat-Intelligence` provider opcodes on `NtOpenKey` (with `KeyName` containing `\Registry\Machine\SAM\SAM` or `\Registry\Machine\Security`) and on `NtDuplicateToken` from `lsass.exe` provide primary signal. MiniFilter file-system callbacks (`IRP_MJ_CREATE` on `C:\Windows\Temp\sam.hive`) capture the destination-file write.
- **Bypass options**: reading the on-disk hive file directly via `CreateFileW(L"C:\\Windows\\System32\\config\\SAM", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)` bypasses CM entirely but is locked by `lsass.exe` for FILE_SHARE_WRITE. Use Volume Shadow Copy (`vssadmin create shadow /for=C:` then read from `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`) — produces a `Microsoft-Windows-VSS` provider event but no `RegSaveKey` event. Alternatively, `esentutl.exe /y /vss /d C:\Windows\System32\config\SAM /vss C:\Windows\Temp\sam.hive` is a native-file-copy primitive that uses VSS underneath. Mimikatz `lsadump::sam` from a SYSTEM-context process reads in-memory via `NtOpenKey`+`NtQueryValueKey` — avoids `RegSaveKey` but generates `NtQueryValueKey` telemetry on `HKLM\SAM\SAM\Domains\Account\Users\*`.
- **Residual artifacts**: on the host after a SAM-extraction run, you find three `.hive` files in a writable temp directory (typically `C:\Windows\Temp\` or `C:\Users\<user>\AppData\Local\Temp\`), the `reg.exe save` process in the `Microsoft-Windows-Kernel-Process` ETW event ID `1` log, and the shadow-copy creation event if VSS was used. The SYSTEM hive's `Select\Current` value at extraction time is preserved in the saved hive bytes — analysts can verify which control set was live. For NL$ cache extraction, the iteration-count field in `HKLM\SECURITY\Cache\NL$<n>` is preserved as written. Mimikatz in-memory operation leaves no `.hive` files but produces `lsass.exe` handle-acquisition events in `Microsoft-Windows-Kernel-Object` (Event ID `4`) on the process-token-duplication path.

## Common Mistakes

1. **Forgetting to save the SYSTEM hive alongside SAM and SECURITY** — secretsdump prints `SAM hashes not found in this OS version` because the boot key is missing. Always collect all three hives as a single command pipeline.
2. **Expecting `SeBackupPrivilege` to bypass the SAM hive ACL** — it does not. The privilege is consulted at the destination-file write only, not at the source-key open. A non-SYSTEM Administrator with `SeBackupPrivilege` enabled still gets `ERROR_ACCESS_DENIED` from `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", ...)`.
3. **Enumerating only `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and missing `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`** — every 32-bit-installed product lives in the Wow6432Node mirror. False negatives are severe on enterprise hosts.
4. **Conflating `HKU\.DEFAULT` with `HKU\S-1-5-18`** — `.DEFAULT` is the on-disk hive `config\default` mounted by `Winlogon` for the lock-screen UI and SYSTEM-account services. `S-1-5-18` is a SID alias to the same SYSTEM account but is mounted from `config\system` — the SYSTEM hive, not `.DEFAULT`. They are different hive files.
5. **Reading `HKCU\Software` from a beacon that runs under `LocalSystem`** — `HKCU` of the SYSTEM account is `HKU\.DEFAULT`-backed and points to `C:\Windows\System32\config\systemprofile`. If the operator expects the user's `NTUSER.DAT`, they must impersonate the user's token before reading `HKCU\Software`.
6. **Picking the wrong control set** — if the host booted Last-Known-Good, the live control set is at `Select\LastKnownGood`, not `Select\Current`. secretsdump handles this internally when reading the live hive, but offline analysts dumping a hive copied at a different boot state must verify.

## Related Techniques

- **T-017** — composes upstream by yielding the SYSTEM token that the SAM and SECURITY hive reads require; this card consumes that token to operate the secrets-dump pipeline.
- **T-023** — extends downward, using the Services and Uninstall enumerations produced here as input for the broader host-recon flow.
- **T-034** — alternative persistence surface that lives in the adjacent `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` subtree, paired with this card's ProfileList path within the same parent hive.