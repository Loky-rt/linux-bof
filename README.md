# Linux BOFs

A collection of **Linux Beacon Object Files** designed to run through the [ELF BOF SDK](https://github.com/Loky-rt/elf-bof).

BOFs are agent-agnostic — they depend only on the Beacon/Ax\* API provided by the SDK. Any Linux C2 agent that integrates the SDK can execute them without modification.

This repository includes `bof.axs` for AdaptixC2 integration, but the BOFs themselves are not tied to any specific C2 framework.

---

## BOFs

| BOF | Description | Privileges | Mode |
|-----|-------------|------------|------|
| `arp` | ARP / neighbor table enumeration | — | Sync |
| `container_detect` | Docker / K8s / LXC detection + escape vectors | — | Sync |
| `cred_harvest` | AWS / GCP / Azure / K8s / Git credentials + env secrets | — | Sync |
| `host_recon` | System info, interfaces, users, groups, CPU | — | Sync |
| `kernel_exploit_check` | Kernel CVE checks + security features | — | Sync |
| `keylogger_start` | Start keylogger (async, all keyboards) | root or `input` group | Async |
| `keylogger_dump` | Retrieve captured keystrokes | — | Sync |
| `krb` | Kerberos credential cache enumeration | — | Sync |
| `ld_preload_check` | Detect LD\_PRELOAD hooks in processes | — | Sync |
| `net_enum` | Interfaces, routes, ARP, DNS, TCP connections | — | Sync |
| `nslookup` | DNS lookup via raw UDP (no libc resolver) | — | Sync |
| `persist_cron` | Cron-based persistence | write access to crontab | Sync |
| `persist_systemd` | Systemd-based persistence | root | Sync |
| `portscan` | TCP port scanner with banner grab | — | Async |
| `proc_enum` | Process tree (USER/PID/PPID/STATE/CMD) | — | Sync |
| `service_enum` | Listening ports, root daemons, systemd units | — | Sync |
| `shadow_dump` | `/etc/shadow` hash extraction | root | Sync |
| `ssh_keys` | SSH private keys, authorized\_keys, configs | — | Sync |
| `sudo_check` | Sudoers audit + privilege group membership | — | Sync |
| `suid_scan` | SUID/SGID scanner with GTFOBins hints | — | Sync |
| `timestomp` | File timestamp manipulation (atime/mtime) | write access | Sync |
| `uptime` | System uptime, RAM, process count | — | Sync |
| `chown` | change the owner and the group | - | Sync |
| `chmod` | change permissions | - | Sync |
| `df` | show the amount of available and used space on the disk file systems | - | Sync |
| `load_elf` | Loader ELF in Memory | - | Async |
| `mv` | move or rename files and directories | - | Sync |
| `recon_lb` | Locate LIBXXX in system processes | - | Sync |
| `so_inject` | Inject a .so into a running process via remote dlopen | - | Sync |

---

## Supported Architectures

| Architecture | Status |
|---|---|
| x86\_64 | ✅ |
| ARM64 / AArch64 | ✅ |

---

## Requirements

### Build

```bash
# x86_64 (default)
sudo apt install gcc

# ARM64 cross-compilation
sudo apt install gcc-aarch64-linux-gnu
```

### Runtime

An agent integrating the [ELF BOF SDK](https://github.com/Loky-rt/elf-bof). The SDK provides the ELF loader, symbol resolution, Beacon/Ax\* API, and async execution.

---

## Building

```bash
make          # Build x64 + arm64
make x64      # Build x64 only
make arm64    # Build arm64 only
make clean    # Remove compiled BOFs
```

Output goes to `bofs_compile/`:

```
bofs_compile/
├── arp.x64.o
├── arp.arm64.o
├── host_recon.x64.o
├── host_recon.arm64.o
└── ...
```

---

## AdaptixC2 Integration

`bof.axs` provides AdaptixC2 command registration. It selects the correct `.o` per architecture:

```javascript
let bof_path = ax.script_dir() + "bofs_compile/mybof." + ax.arch(id) + ".o";
ax.execute_alias(id, cmdline, `bof "${bof_path}" ${bof_params}`, "BOF: mybof");
```

---

## Disclaimer

For authorized security research, penetration testing, red team operations, and security tooling development only. Use only on systems where you have explicit authorization.
