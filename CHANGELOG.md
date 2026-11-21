# Changelog

## v1.0.0 (2026-11-22)

- Hardened `chronoa` CCACHE file ingestion with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, `fstat` regular-file validation, and non-negative bounds enforcement on `--now` and `--kdc-time`.
- Hardened `libranga.so` destructor with `g_owner_pid = getpid()` fork guard so forked child processes do not clear or revoke the parent's isolated session keyring.
- Expanded `tests/test_tempest.py` with fork PID guard, `O_NOFOLLOW`/`S_ISREG`, and negative epoch bounds tests, and enabled `ruff` and `mypy --strict` static gates in CI.
