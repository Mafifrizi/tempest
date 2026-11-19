## Description

<!-- Provide a concise summary of the change, fix, or new capability. -->

## Type of Change

- [ ] Bug fix (fix:)
- [ ] New feature (feat:)
- [ ] Documentation update (docs:)
- [ ] Refactoring (refactor:)
- [ ] Test or CI enhancement (test: / ci:)

## Runtime & Quality Checklist

- [ ] Compiles cleanly under -std=c11 / -std=c++20 with -Wall -Wextra -Werror and zero external dependencies.
- [ ] Passes make clean && make test with all operative assertions green.
- [ ] Preserves unprivileged execution, symlink/protected-path purge guards, and 0x3f000000 keyring isolation.
- [ ] Preserves the five-state semantic exit contract (0..4) and structured JSON output.
- [ ] Documentation stays concise without inline backtick clutter or unicode em dashes.
