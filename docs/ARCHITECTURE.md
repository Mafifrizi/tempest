# Architecture

Tempest is Cycle 2 of the four-cycle Linux identity security architecture. It provides a native C11 and C++20 post-authentication runtime guard layer that protects active Kerberos credentials, UNIX KCM sockets, and Linux kernel session keyrings with zero external library dependencies beyond glibc and standard Linux kernel headers.

## Build Artifacts and Binary Layout

All targets are compiled from C11 (-std=c11 -O2 -Wall -Wextra -Werror) and C++20 (-std=c++20 -O2 -Wall -Wextra -Werror) sources against include/tempest_contract.h with zero external link libraries (no libkeyutils-dev dependency).

- **bin/souei** (C++20, src/souei.cpp): passive /proc/keys and session keyring auditor, KCM UNIX stream socket peer-credential verifier (AF_UNIX SO_PEERCRED), and Linux inotify credential-file watcher.
- **bin/chronoa** (C++20, src/chronoa.cpp): MIT Kerberos CCACHE v3 (0x0503) and v4 (0x0504) binary parser, weak-enctype policy enforcer, RFC 4120 300-second clock-skew guard, and non-shell ticket renewal watchdog.
- **bin/ranga** (C11, src/ranga.c): kernel session keyring inspector, fork and execvp isolated process launcher (0x3f000000), and three-pass NIST SP 800-88 file purge and session revocation utility.
- **bin/libranga.so** (C11 PIC shared object, src/libranga.c): LD_PRELOAD runtime keyring isolator registering static ELF .init_array and .fini_array lifecycle hooks.

```text
+-------------------------------------------------------------------+
| Ciel Teamserver / Operator Shell (Cycle 4 / Host Process)         |
+-------------------------------------------------------------------+
   |                    |                     |                |
   v                    v                     v                v
bin/souei          bin/chronoa            bin/ranga      LD_PRELOAD
(C++20)            (C++20)                (C11)          bin/libranga.so
   |                    |                     |                |
   +--> SYS_keyctl      +--> CCACHE 0x0503/4  +--> SYS_keyctl  +--> .init_array
   +--> /proc/keys      +--> RFC 4120 skew    +--> getrandom(2)+--> .fini_array
   +--> lstat+SO_PEERCRED+--> execvp renew    +--> O_NOFOLLOW 3-pass wipe
   +--> inotify+poll
```

## Header ABI and Library Surface

### include/tempest_contract.h

The shared extern "C" header defines constants, the five-state exit code contract, and inline primitives used across all four artifacts:

- **Version and Policy Constants**: TEMPEST_VERSION (1.0.0), RFC4120_MAX_CLOCK_SKEW_SEC (300), TEMPEST_POSSESSOR_ONLY_PERM (0x3f000000U).
- **Five-State Exit Contract**: TEMPEST_EXIT_OK (0), TEMPEST_EXIT_USAGE (1), TEMPEST_EXIT_POLICY_STOP (2), TEMPEST_EXIT_MISSING (3), TEMPEST_EXIT_PARSE_ERR (4).
- **tempest_keyctl**: direct syscall(SYS_keyctl, ...) wrapper avoiding external libkeyutils-dev linkage.
- **tempest_read_be16 and tempest_read_be32**: big-endian unsigned integer readers for CCACHE binary parsing.
- **tempest_fprint_json_str**: JSON string writer escaping quotes, backslashes, control whitespace, and sub-0x20 bytes as \u00xx.
- **tempest_enctype_name**: maps Kerberos encryption type IDs 1 (des-cbc-crc), 2 (des-cbc-md4), 3 (des-cbc-md5), 16 (des3-cbc-sha1), 17 (aes128-cts-hmac-sha1-96), 18 (aes256-cts-hmac-sha1-96), 19 (aes128-cts-hmac-sha256-128), 20 (aes256-cts-hmac-sha384-192), 23 (rc4-hmac), and default unknown.

### bin/libranga.so Lifecycle Hooks

bin/libranga.so exports zero custom public C ABI symbols. Both lifecycle routines are static ELF hooks registered in .init_array and .fini_array that preserve errno across execution:

- **tempest_ranga_ctor** (.init_array constructor): checks RANGA_DISABLE=1; joins an anonymous session keyring via KEYCTL_JOIN_SESSION_KEYRING (arg2=0); applies TEMPEST_POSSESSOR_ONLY_PERM (0x3f000000U) via KEYCTL_SETPERM; logs to stderr when RANGA_VERBOSE=1.
- **tempest_ranga_dtor** (.fini_array destructor): clears the isolated keyring via KEYCTL_CLEAR and, when RANGA_REVOKE_ON_EXIT=1, revokes it via KEYCTL_REVOKE.

## Linux Kernel Primitives and Security Boundaries

### Kernel Session Keyring Isolation (SYS_keyctl)

- **Anonymous Keyring Detachment**: KEYCTL_JOIN_SESSION_KEYRING with NULL description creates a per-process session keyring detached from the shared KEY_SPEC_USER_SESSION_KEYRING.
- **Possessor-Only ACLs**: KEYCTL_SETPERM enforces 0x3f000000 (possessor view, read, write, search, link, setattr only; zero user, group, and other permission bits). souei flags any non-zero low 16 bits (perm & 0x0000ffffU) on the session keyring or Kerberos entries in /proc/keys; ranga checks all low 24 bits (perm & 0x00ffffffU).
- **Inspection and Revocation**: KEYCTL_DESCRIBE parses type;uid;gid;perm_hex;description, KEYCTL_READ counts up to 256 child key serials, and purge revocation strictly requires KEYCTL_REVOKE to return 0 before setting session_revoked=true (failing closed with TEMPEST_EXIT_POLICY_STOP on lookup or revocation failure).

### KCM UNIX Socket Trust Boundary (lstat and SO_PEERCRED)

- **Symlink Rejection**: souei inspects the KCM socket path with lstat() before socket() or connect(), rejecting S_ISLNK targets before evaluating mode bits or connecting.
- **Permission Enforcement**: rejects non-socket filesystem objects and group or world permission bits (mode & 0077U != 0).
- **Kernel Peer Credentials**: connects via AF_UNIX SOCK_STREAM and queries getsockopt(SOL_SOCKET, SO_PEERCRED) for kernel-authenticated pid, uid, and gid, resolving /proc/<pid>/exe via readlink(). Errors from getsockopt(SO_PEERCRED) (including truncated length or unmapped uid (uid_t)-1) are reported distinctly as SO_PEERCRED failures rather than peer UID mismatches. Accepted peers must match the caller UID or UID 0.

### Credential File Watching (inotify and poll)

- **Symlink-Safe Watch**: watch_file_inotify verifies the target with lstat() (refusing symlinks) and calls inotify_add_watch() with IN_OPEN | IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_DONT_FOLLOW.
- **Bounded Event Collection**: polls the non-blocking inotify descriptor for --timeout-ms (default 100 ms, clamped to 1..60000 ms).

### CCACHE Binary Parsing and RFC 4120 Policy Enforcement

- **Bounds-Checked Parser**: parses MIT CCACHE v3 (0x0503) and v4 (0x0504) up to 16 MiB, enforcing component count caps (64), principal/realm length caps (1024 B), key length caps (65536 B), and address/authdata entry caps (1024). Config entries (endtime == 0 or server starting with krb5_ccache_conf_data/) are skipped during primary ticket selection.
- **Weak Cipher Block**: blocks DES (1, 2, 3), 3DES (16), and RC4-HMAC (23).
- **Clock Skew Guard**: enforces RFC 4120 limit max(|now - kdc_time|, max(0, authtime - now)) <= 300 seconds.
- **Non-Shell Renewal and Watchdog Bounds**: parses --renew-cmd into an argv vector, rejecting unquoted shell operators (;, &, |, backtick, <, >, newlines, (, ), ${, $() and unterminated quotes while preserving Active Directory machine principals containing $ (such as naga$@REALM), and executes directly via execvp() without /bin/sh. Watch polling intervals are clamped safely to [1, UINT_MAX] before sleep().

### NIST SP 800-88 Three-Pass Purge and CSPRNG Safety

- **TOCTOU-Safe Target Validation**: validates regular file via lstat(), opens with O_RDWR | O_NOFOLLOW | O_CLOEXEC, verifies fstat() reports S_ISREG with identical st_dev and st_ino, and re-verifies lstat() st_dev and st_ino prior to unlink().
- **Fail-Closed Random Overwrite**: executes three full-file passes (0x00, 0xFF, and CSPRNG bytes) in 4096-byte buffers wiped with explicit_bzero() and flushed via fsync(), followed by ftruncate(fd, 0) and fsync(). Pass 3 sources entropy from getrandom(2) (falling back to O_RDONLY | O_CLOEXEC /dev/urandom only on ENOSYS or EPERM) and fails closed with TEMPEST_EXIT_POLICY_STOP without unlinking if cryptographic randomness fails.

## Ecosystem Integration

Ciel Teamserver (Cycle 4) invokes bin/souei, bin/chronoa, bin/ranga, and bin/libranga.so using structured --json output and the five-state exit contract defined in include/tempest_contract.h. Ciel resolves system KCM sockets for souei probes, invokes kinit -R directly when renewing tickets before re-evaluating with chronoa, isolates processes with libranga.so or ranga --isolate, and wipes transient credential caches with ranga --purge.
