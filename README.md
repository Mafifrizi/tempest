# Tempest

**Native C11/C++20 Linux Kernel & Kerberos Runtime Companion for [Tanuki](https://github.com/Mafifrizi/tanuki)**

Tempest closes the three **runtime lifecycle gaps** left open after initial Active Directory / Kerberos enrollment on Linux workstations and containers:

1. **Silent Keyring & KCM Exposure (`Souei`)** — Detects cross-session keyring permission leaks (`perm & 0x0000ffff != 0` in `/proc/keys`), resolves KCM UNIX socket peer credentials (`SO_PEERCRED` PID/UID/GID & `/proc/<pid>/exe`), and captures real-time `.keytab`/CCACHE access via Linux `inotify`.
2. **Temporal CCACHE Expiry & Clock-Skew Lockouts (`Chronoa`)** — Parses MIT CCACHE v4 (`0x0504`) and v3 (`0x0503`) caches with zero `libkrb5` dependency, detects weak ciphers (RC4 `23`, DES/3DES), enforces the RFC 4120 `300s` clock-skew ceiling, and triggers pre-expiry renewal hooks safely.
3. **Shared Session Keyring Bleed & Plaintext Artifacts (`Ranga` + `libranga.so`)** — Isolates worker processes into fresh anonymous Linux session keyrings restricted to possessor-only permissions (`0x3f000000`) via `SYS_keyctl` (`KEYCTL_JOIN_SESSION_KEYRING`, `KEYCTL_SETPERM`) both through `LD_PRELOAD` and CLI execution, and purges credential files using 3-pass NIST SP 800-88 overwrite (`0x00`, `0xFF`, random) + `explicit_bzero` + optional session keyring revocation.

---

## Architecture & Zero-Dependency Discipline

All components compile cleanly with `-O2 -Wall -Wextra -Werror` using only standard C11/C++20, glibc, and Linux UAPI headers (`<linux/keyctl.h>`, `<sys/syscall.h>`, `<sys/socket.h>`, `<sys/inotify.h>`). No external `-lkeyutils` or `-lkrb5` development libraries are required.

```text
tanuki CLI (Rust / Python)
   ├──> souei   (C++20) ── /proc/keys, SO_PEERCRED, inotify
   ├──> chronoa (C++20) ── MIT CCACHE v4/v3 parser, RFC 4120 300s skew check, renew hook
   └──> ranga   (C11)   ── bin/libranga.so (LD_PRELOAD) + NIST SP 800-88 3-pass purge
```

### Shared Semantic Exit Contract (`include/tempest_contract.h`)

| Exit Code | Constant | Meaning |
| --- | --- | --- |
| `0` | `TEMPEST_EXIT_OK` | Check healthy / isolation or purge succeeded |
| `1` | `TEMPEST_EXIT_USAGE` | Invalid CLI flag or argument |
| `2` | `TEMPEST_EXIT_POLICY_STOP` | Security/policy violation (expired, weak cipher, clock skew > 300s, insecure ACL/mode, non-regular purge target) |
| `3` | `TEMPEST_EXIT_MISSING` | Target file, socket, or credential missing |
| `4` | `TEMPEST_EXIT_PARSE_ERR` | Corrupt or unsupported CCACHE binary layout |

---

## Operatives & CLI Reference

### `bin/souei` (C++20 Shadow Telemetry)

```bash
./bin/souei --probe [--json]
./bin/souei --kcm-socket /run/.heim_org.h5l.kcm-socket [--json]
./bin/souei --watch-file /tmp/krb5cc_1000 --timeout-ms 500 [--json]
```

### `bin/chronoa` (C++20 Temporal CCACHE Watchdog)

```bash
./bin/chronoa --ccache /tmp/krb5cc_1000 --warn-window-sec 300 --once [--json]
./bin/chronoa --ccache /tmp/krb5cc_1000 --now 1700000500 --kdc-time 1700000000 --json
./bin/chronoa --ccache /tmp/krb5cc_1000 --renew-cmd "kinit -R" --watch --interval-sec 30
```

### `bin/ranga` & `bin/libranga.so` (C11 Keyring Isolator & Purge)

```bash
# Inspect active Linux kernel session keyring permissions
./bin/ranga --status [--json]

# Isolate a workload via LD_PRELOAD constructor/destructor
RANGA_REVOKE_ON_EXIT=1 LD_PRELOAD=./bin/libranga.so ./bin/ranga --status --json

# Isolate a workload via wrapper fork/exec
./bin/ranga --isolate -- ./bin/ranga --status --json

# 3-pass NIST SP 800-88 file wipe + unlink + optional session keyring revoke
./bin/ranga --purge /tmp/krb5cc_temp --revoke-session [--json]
```

Environment toggles recognized by `libranga.so`:
- `RANGA_DISABLE=1`: bypass keyring isolation on load
- `RANGA_REVOKE_ON_EXIT=1`: execute `KEYCTL_REVOKE` after `KEYCTL_CLEAR` in destructor
- `RANGA_VERBOSE=1`: emit keyring serial diagnostic line to `stderr`

---

## Build & Verification (Linux / WSL2 Ubuntu)

```bash
make clean && make
make test
```

## Post-Hackathon Tanuki Integration Plan

After hackathon evaluation, Tanuki (`tanuki-repo`) delegates Linux runtime checks directly to Tempest's compiled binaries (`--json` + exit codes `0..4`) instead of duplicating Python/Rust low-level probes:
- `tanuki doctor` security/runtime checks -> `souei` + `chronoa`
- Isolated command wrappers & credential teardown -> `ranga` + `libranga.so`
