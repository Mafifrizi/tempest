# CLI Reference

All Tempest operatives emit structured JSON with --json and follow the shared five-state exit code contract defined in include/tempest_contract.h.

## Exit Codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | TEMPEST_EXIT_OK | Probe, isolation, renewal, or purge succeeded cleanly |
| 1 | TEMPEST_EXIT_USAGE | Invalid flag, missing option argument, invalid integer, or unsafe --renew-cmd syntax |
| 2 | TEMPEST_EXIT_POLICY_STOP | Keyring ACL leak, symlink or insecure KCM socket, weak cipher, RFC 4120 skew (>300s), expired ticket, renewal failure, purge TOCTOU/symlink/CSPRNG/revoke failure, or EACCES |
| 3 | TEMPEST_EXIT_MISSING | Missing or unlistening KCM socket, missing watch file, missing CCACHE, unsupported KRB5CCNAME scheme, empty CCACHE (NO_CREDENTIALS), missing session keyring, or execvp target not found |
| 4 | TEMPEST_EXIT_PARSE_ERR | Truncated, oversized (>16 MiB), bad-magic (not 0x0503 or 0x0504), or corrupt CCACHE binary |

## souei

Passive keyring auditor, KCM UNIX socket peer-credential verifier, and Linux inotify credential-file watcher.

### Synopsis

```sh
souei [--probe] [--kcm-socket <PATH>] [--watch-file <PATH>] [--timeout-ms <MS>] [--json]
souei -h | --help | -V | --version
```

### Options

- **--probe**: run passive /proc/keys and session keyring audit (default when no flags are passed).
- **--kcm-socket PATH**: check socket with lstat() (rejects symlinks), verify permissions (no group/other bits), connect, query SO_PEERCRED, and verify peer UID matches caller UID or 0.
- **--watch-file PATH**: monitor credential file with lstat() + inotify_add_watch(..., IN_DONT_FOLLOW) for IN_OPEN, IN_ACCESS, IN_MODIFY, IN_ATTRIB, and IN_DELETE_SELF.
- **--timeout-ms MS**: inotify poll timeout in milliseconds (default 100, clamped to 1..60000).
- **--json**: emit structured JSON to stdout.
- **-h, --help / -V, --version**: print usage or souei 1.0.0.

### Status Values and JSON Output

Status values are OK, POLICY_STOP, RESOURCE_MISSING, and PARSE_ERROR.

```json
{
  "agent": "souei",
  "version": "1.0.0",
  "status": "OK",
  "exit_code": 0,
  "uid": 1000,
  "session_keyring_id": 123456789,
  "user_session_keyring_id": 987654321,
  "isolated_session_keyring": true,
  "session_perm_hex": "3f000000",
  "proc_keys_readable": true,
  "keyring_entries_count": 2,
  "kcm_socket": {
    "checked": true,
    "path": "/run/.heim_org.h5l.kcm-socket",
    "exists": true,
    "is_socket": true,
    "mode_octal": "600",
    "connected": true,
    "peer_pid": 4321,
    "peer_uid": 0,
    "peer_gid": 0,
    "peer_exe": "/usr/libexec/kcm",
    "error": ""
  },
  "inotify": {
    "watched": false,
    "path": "",
    "error": "",
    "events": []
  },
  "policy_violations": []
}
```

## chronoa

MIT Kerberos CCACHE v3/v4 parser, weak-enctype guard, RFC 4120 clock-skew enforcer, and non-shell ticket renewal watchdog.

### Synopsis

```sh
chronoa [--ccache <PATH>] [--now <EPOCH>] [--kdc-time <EPOCH>] [--warn-window-sec <SEC>] [--renew-cmd <CMD>] [--once | --watch] [--interval-sec <SEC>] [--json]
chronoa -h | --help | -V | --version
```

### Options and CCACHE Resolution

CCACHE path precedence is --ccache, then KRB5CCNAME, then /tmp/krb5cc_<uid>. Literal FILE: prefixes are stripped; empty FILE: paths return usage error (exit 1) when passed via --ccache or MISSING (exit 3) when set in KRB5CCNAME. Non-FILE schemes such as KCM: or DIR: fail with exit 3 (MISSING).

- **--ccache PATH**: CCACHE file path (optional FILE: prefix).
- **--now EPOCH**: override current UNIX epoch seconds for deterministic checks.
- **--kdc-time EPOCH**: reference KDC UNIX epoch seconds for RFC 4120 300-second skew check.
- **--warn-window-sec SEC**: pre-expiry warning and renewal threshold in seconds (default 300).
- **--renew-cmd CMD**: command tokenized into argv (quote-aware, rejecting unquoted shell operators and shell expansions while preserving Active Directory $ principals) and executed directly via execvp() when ticket is expiring or expired (skipped if skew violation or weak enctype is active).
- **--once / --watch**: evaluate once and exit (default) or poll continuously until SIGINT/SIGTERM.
- **--interval-sec SEC**: polling interval in seconds for --watch (default 30, clamped to [1, UINT_MAX] before sleep()).
- **--json**: emit structured single-line JSON per evaluation.
- **-h, --help / -V, --version**: print usage or chronoa 1.0.0.

### Status Values and JSON Output

Status values with exit 0: HEALTHY, EXPIRING_SOON, RENEWED.
Status values with exit 2: CLOCK_SKEW_VIOLATION, WEAK_ENCTYPE, RENEW_FAILED, EXPIRED, POLICY_STOP.
Status values with exit 3: MISSING, NO_CREDENTIALS.
Status value with exit 4: PARSE_ERROR.

```json
{
  "agent": "chronoa",
  "version": "1.0.0",
  "status": "HEALTHY",
  "exit_code": 0,
  "ccache_path": "/tmp/krb5cc_1000",
  "ccache_format": "0x0504",
  "default_principal": "ely@TANUKI.LOCAL",
  "now_epoch": 1700000000,
  "has_kdc_time": true,
  "kdc_time_epoch": 1700000012,
  "skew_sec": 12,
  "max_skew_sec": 300,
  "skew_violation": false,
  "warn_window_sec": 300,
  "ttl_sec": 3600,
  "renew_ttl_sec": 86400,
  "weak_enctype": false,
  "expired": false,
  "expiring_soon": false,
  "renew_attempted": false,
  "renew_exit_code": -1,
  "renewed": false,
  "primary_ticket": {
    "client": "ely@TANUKI.LOCAL",
    "server": "krbtgt/TANUKI.LOCAL@TANUKI.LOCAL",
    "enctype": 18,
    "enctype_name": "aes256-cts-hmac-sha1-96",
    "authtime": 1699999940,
    "starttime": 1699999940,
    "endtime": 1700003600,
    "renew_till": 1700086400
  },
  "ticket_count": 1,
  "error": ""
}
```

## ranga

Kernel session keyring inspector, isolated process launcher, and NIST SP 800-88 three-pass purge utility.

### Synopsis

```sh
ranga --status [--json]
ranga --isolate -- <CMD> [ARGS...]
ranga --purge <FILE> [--revoke-session] [--json]
ranga -h | --help | -V | --version
```

### Modes and Options

- **--status** (default when invoked with no arguments): inspects KEY_SPEC_SESSION_KEYRING via KEYCTL_GET_KEYRING_ID, KEYCTL_DESCRIBE, and KEYCTL_READ. Exits 0 on success or 3 if no session keyring is attached.
- **--isolate -- CMD [ARGS...]**: forks a child process, joins a new anonymous session keyring via KEYCTL_JOIN_SESSION_KEYRING, sets 0x3f000000 via KEYCTL_SETPERM, and calls execvp(). Propagates child exit status (or 128 + signal); child exits 3 if execvp() fails.
- **--purge FILE [--revoke-session]**: checks lstat() regular file, opens with O_RDWR | O_NOFOLLOW | O_CLOEXEC, checks fstat() st_dev/st_ino match, overwrites three passes (0x00, 0xFF, fail-closed CSPRNG via getrandom(2) or /dev/urandom) with fsync(), runs ftruncate(fd, 0) + fsync(), re-verifies lstat() st_dev/st_ino, and calls unlink(). With --revoke-session, runs KEYCTL_CLEAR and KEYCTL_REVOKE, setting session_revoked=true only when KEYCTL_REVOKE succeeds (otherwise exiting 2).
- **--json**: emit structured JSON for --status or --purge.
- **-h, --help / -V, --version**: print usage or ranga 1.0.0.

### JSON Output (status mode)

```json
{
  "agent": "ranga",
  "version": "1.0.0",
  "mode": "status",
  "exit_code": 0,
  "session_keyring_id": 123456789,
  "type": "keyring",
  "uid_gid": "1000:1000",
  "perm_hex": "3f000000",
  "possessor_only": true,
  "child_key_count": 0,
  "description": "_ses",
  "error": ""
}
```

### JSON Output (purge mode)

```json
{
  "agent": "ranga",
  "version": "1.0.0",
  "mode": "purge",
  "exit_code": 0,
  "path": "/tmp/krb5cc_1000",
  "wiped_bytes": 4096,
  "passes": 3,
  "removed": true,
  "session_revoked": true,
  "error": ""
}
```

## libranga.so (LD_PRELOAD)

Transparent ELF .init_array and .fini_array keyring isolator with zero exported C symbols.

```sh
LD_PRELOAD=./bin/libranga.so RANGA_VERBOSE=1 RANGA_REVOKE_ON_EXIT=1 ./bin/ranga --status --json
```

### Environment Variables

- **RANGA_DISABLE=1**: skip constructor keyring isolation.
- **RANGA_VERBOSE=1**: print [libranga] isolated session keyring diagnostics to stderr.
- **RANGA_REVOKE_ON_EXIT=1**: revoke the isolated session keyring in addition to clearing it during destructor execution.
