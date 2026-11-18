#include "tempest_contract.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>

static void print_usage(void) {
    printf(
        "ranga v%s - Tempest C11 Kernel Keyring Isolator & NIST SP 800-88 Purge\n\n"
        "USAGE:\n"
        "    ranga --status [--json]\n"
        "    ranga --isolate [-- <CMD> [ARGS...]]\n"
        "    ranga --purge <FILE> [--revoke-session] [--json]\n\n"
        "OPTIONS:\n"
        "    --status             Inspect current session keyring ID, permissions, and key count\n"
        "    --isolate            Join fresh anonymous session keyring (0x3f000000) and exec <CMD>\n"
        "    --purge <FILE>       NIST SP 800-88 3-pass overwrite (0x00, 0xFF, random) + unlink\n"
        "    --revoke-session     With --purge, also clear and revoke the current session keyring\n"
        "    --json               Output structured JSON (--status / --purge)\n"
        "    -h, --help           Show this help\n"
        "    -V, --version        Show version\n",
        TEMPEST_VERSION
    );
}

struct KeyringStatus {
    long session_id;
    uint32_t perm;
    bool possessor_only;
    size_t child_count;
    char type[64];
    char uid_gid[64];
    char perm_hex[32];
    char description[256];
    char error[256];
};

static bool query_session_status(struct KeyringStatus *st) {
    memset(st, 0, sizeof(*st));
    st->session_id = tempest_keyctl(
        KEYCTL_GET_KEYRING_ID,
        (unsigned long)(long)KEY_SPEC_SESSION_KEYRING,
        0UL,
        0UL,
        0UL
    );
    if (st->session_id <= 0) {
        snprintf(st->error, sizeof(st->error),
                 "KEYCTL_GET_KEYRING_ID failed: %s", strerror(errno));
        return false;
    }

    char desc_buf[512];
    memset(desc_buf, 0, sizeof(desc_buf));
    long dlen = tempest_keyctl(
        KEYCTL_DESCRIBE,
        (unsigned long)st->session_id,
        (unsigned long)desc_buf,
        (unsigned long)(sizeof(desc_buf) - 1),
        0UL
    );
    if (dlen < 0) {
        snprintf(st->error, sizeof(st->error),
                 "KEYCTL_DESCRIBE failed: %s", strerror(errno));
        return false;
    }
    desc_buf[sizeof(desc_buf) - 1] = '\0';

    /* Kernel format: "type;uid;gid;perm_hex;description" */
    char *p1 = strchr(desc_buf, ';');
    char *p2 = p1 ? strchr(p1 + 1, ';') : NULL;
    char *p3 = p2 ? strchr(p2 + 1, ';') : NULL;
    char *p4 = p3 ? strchr(p3 + 1, ';') : NULL;
    if (p1 && p2 && p3 && p4) {
        size_t l_type = (size_t)(p1 - desc_buf);
        if (l_type >= sizeof(st->type)) l_type = sizeof(st->type) - 1;
        memcpy(st->type, desc_buf, l_type);

        size_t l_uid = (size_t)(p3 - (p1 + 1));
        char ug_tmp[64];
        if (l_uid >= sizeof(ug_tmp)) l_uid = sizeof(ug_tmp) - 1;
        memcpy(ug_tmp, p1 + 1, l_uid);
        ug_tmp[l_uid] = '\0';
        for (char *q = ug_tmp; *q; ++q) {
            if (*q == ';') *q = ':';
        }
        snprintf(st->uid_gid, sizeof(st->uid_gid), "%s", ug_tmp);

        size_t l_perm = (size_t)(p4 - (p3 + 1));
        if (l_perm >= sizeof(st->perm_hex)) l_perm = sizeof(st->perm_hex) - 1;
        memcpy(st->perm_hex, p3 + 1, l_perm);
        st->perm = (uint32_t)strtoul(st->perm_hex, NULL, 16);
        st->possessor_only = ((st->perm & 0x00ffffffU) == 0U) &&
                             ((st->perm & TEMPEST_POSSESSOR_ONLY_PERM) != 0U);

        snprintf(st->description, sizeof(st->description), "%s", p4 + 1);
    }

    int32_t keys_buf[256];
    long rlen = tempest_keyctl(
        KEYCTL_READ,
        (unsigned long)st->session_id,
        (unsigned long)keys_buf,
        (unsigned long)sizeof(keys_buf),
        0UL
    );
    if (rlen > 0) {
        st->child_count = (size_t)rlen / sizeof(int32_t);
    }
    return true;
}

static int run_status(bool json_mode) {
    struct KeyringStatus st;
    bool ok = query_session_status(&st);
    int exit_code = ok ? TEMPEST_EXIT_OK : TEMPEST_EXIT_MISSING;

    if (json_mode) {
        printf("{");
        printf("\"agent\":\"ranga\",");
        printf("\"version\":\"%s\",", TEMPEST_VERSION);
        printf("\"mode\":\"status\",");
        printf("\"exit_code\":%d,", exit_code);
        printf("\"session_keyring_id\":%ld,", st.session_id);
        printf("\"type\":");
        tempest_fprint_json_str(stdout, st.type);
        printf(",\"uid_gid\":");
        tempest_fprint_json_str(stdout, st.uid_gid);
        printf(",\"perm_hex\":");
        tempest_fprint_json_str(stdout, st.perm_hex);
        printf(",\"possessor_only\":%s,", st.possessor_only ? "true" : "false");
        printf("\"child_key_count\":%zu,", st.child_count);
        printf("\"description\":");
        tempest_fprint_json_str(stdout, st.description);
        printf(",\"error\":");
        tempest_fprint_json_str(stdout, st.error);
        printf("}\n");
    } else {
        if (!ok) {
            fprintf(stderr, "[ranga] status failed: %s\n", st.error);
        } else {
            printf("[ranga] session_keyring_id=%ld type=%s uid:gid=%s perm=0x%s possessor_only=%s keys=%zu desc=%s\n",
                   st.session_id, st.type, st.uid_gid, st.perm_hex,
                   st.possessor_only ? "yes" : "no", st.child_count, st.description);
        }
    }
    return exit_code;
}

static int run_isolate(int cmd_argc, char **cmd_argv) {
    if (cmd_argc <= 0 || !cmd_argv || !cmd_argv[0]) {
        fprintf(stderr, "ranga: --isolate requires a command after '--'\n");
        return TEMPEST_EXIT_USAGE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("ranga: fork");
        return TEMPEST_EXIT_POLICY_STOP;
    }

    if (pid == 0) {
        long kid = tempest_keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0UL, 0UL, 0UL, 0UL);
        if (kid <= 0) {
            perror("ranga: KEYCTL_JOIN_SESSION_KEYRING");
            _exit(TEMPEST_EXIT_POLICY_STOP);
        }
        if (tempest_keyctl(
                KEYCTL_SETPERM,
                (unsigned long)kid,
                (unsigned long)TEMPEST_POSSESSOR_ONLY_PERM,
                0UL,
                0UL) < 0) {
            perror("ranga: KEYCTL_SETPERM");
            _exit(TEMPEST_EXIT_POLICY_STOP);
        }
        execvp(cmd_argv[0], cmd_argv);
        fprintf(stderr, "ranga: execvp(%s): %s\n", cmd_argv[0], strerror(errno));
        _exit(TEMPEST_EXIT_MISSING);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("ranga: waitpid");
            return TEMPEST_EXIT_POLICY_STOP;
        }
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return TEMPEST_EXIT_POLICY_STOP;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void fill_random_bytes(uint8_t *buf, size_t len) {
    int ufd = open("/dev/urandom", O_RDONLY);
    size_t off = 0;
    if (ufd >= 0) {
        while (off < len) {
            ssize_t n = read(ufd, buf + off, len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(ufd);
    }
    while (off < len) {
        buf[off] = (uint8_t)((off * 131U + 0xA5U) & 0xffU);
        ++off;
    }
}

static int overwrite_pass(int fd, off_t size, int mode) {
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    uint8_t buf[4096];
    off_t remaining = size;
    while (remaining > 0) {
        size_t chunk = (remaining > (off_t)sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        if (mode == 0) {
            memset(buf, 0x00, chunk);
        } else if (mode == 1) {
            memset(buf, 0xff, chunk);
        } else {
            fill_random_bytes(buf, chunk);
        }
        if (write_all(fd, buf, chunk) < 0) {
            explicit_bzero(buf, sizeof(buf));
            return -1;
        }
        remaining -= (off_t)chunk;
    }
    explicit_bzero(buf, sizeof(buf));
    if (fsync(fd) < 0 && errno != EINVAL) return -1;
    return 0;
}

static int run_purge(const char *path, bool revoke_session, bool json_mode) {
    struct stat lst;
    int exit_code = TEMPEST_EXIT_OK;
    off_t wiped_bytes = 0;
    int passes = 0;
    bool file_removed = false;
    bool session_revoked = false;
    char err_msg[256] = {0};

    if (lstat(path, &lst) < 0) {
        if (errno == ENOENT) {
            exit_code = TEMPEST_EXIT_MISSING;
            snprintf(err_msg, sizeof(err_msg), "Target file does not exist: %s", path);
        } else {
            exit_code = TEMPEST_EXIT_POLICY_STOP;
            snprintf(err_msg, sizeof(err_msg), "lstat failed: %s", strerror(errno));
        }
    } else if (!S_ISREG(lst.st_mode)) {
        exit_code = TEMPEST_EXIT_POLICY_STOP;
        snprintf(err_msg, sizeof(err_msg), "Refusing to purge non-regular file: %s", path);
    } else {
        int fd = open(path, O_RDWR | O_NOFOLLOW);
        if (fd < 0) {
            exit_code = (errno == ENOENT) ? TEMPEST_EXIT_MISSING : TEMPEST_EXIT_POLICY_STOP;
            snprintf(err_msg, sizeof(err_msg), "Failed to open target file: %s", strerror(errno));
        } else {
            struct stat fst;
            if (fstat(fd, &fst) < 0 || !S_ISREG(fst.st_mode)) {
                exit_code = TEMPEST_EXIT_POLICY_STOP;
                snprintf(err_msg, sizeof(err_msg), "File type changed before overwrite");
            } else {
                wiped_bytes = fst.st_size;
                for (int p = 0; p < 3; ++p) {
                    if (overwrite_pass(fd, fst.st_size, p) < 0) {
                        exit_code = TEMPEST_EXIT_POLICY_STOP;
                        snprintf(err_msg, sizeof(err_msg),
                                 "Overwrite pass %d failed: %s", p + 1, strerror(errno));
                        break;
                    }
                    ++passes;
                }
                if (exit_code == TEMPEST_EXIT_OK) {
                    if (ftruncate(fd, 0) == 0) {
                        (void)fsync(fd);
                    }
                }
            }
            close(fd);

            if (exit_code == TEMPEST_EXIT_OK) {
                if (unlink(path) < 0) {
                    exit_code = TEMPEST_EXIT_POLICY_STOP;
                    snprintf(err_msg, sizeof(err_msg), "unlink failed: %s", strerror(errno));
                } else {
                    file_removed = true;
                }
            }
        }
    }

    if (revoke_session) {
        long kid = tempest_keyctl(
            KEYCTL_GET_KEYRING_ID,
            (unsigned long)(long)KEY_SPEC_SESSION_KEYRING,
            0UL,
            0UL,
            0UL
        );
        if (kid > 0) {
            long c_rc = tempest_keyctl(KEYCTL_CLEAR, (unsigned long)kid, 0UL, 0UL, 0UL);
            long r_rc = tempest_keyctl(KEYCTL_REVOKE, (unsigned long)kid, 0UL, 0UL, 0UL);
            if (c_rc == 0 || r_rc == 0) {
                session_revoked = true;
            }
        }
    }

    if (json_mode) {
        printf("{");
        printf("\"agent\":\"ranga\",");
        printf("\"version\":\"%s\",", TEMPEST_VERSION);
        printf("\"mode\":\"purge\",");
        printf("\"exit_code\":%d,", exit_code);
        printf("\"path\":");
        tempest_fprint_json_str(stdout, path);
        printf(",\"wiped_bytes\":%lld,", (long long)wiped_bytes);
        printf("\"passes\":%d,", passes);
        printf("\"removed\":%s,", file_removed ? "true" : "false");
        printf("\"session_revoked\":%s,", session_revoked ? "true" : "false");
        printf("\"error\":");
        tempest_fprint_json_str(stdout, err_msg);
        printf("}\n");
    } else if (exit_code == TEMPEST_EXIT_OK) {
        printf("[ranga] purged %s (%lld bytes, %d passes, removed=%s, session_revoked=%s)\n",
               path, (long long)wiped_bytes, passes,
               file_removed ? "yes" : "no",
               session_revoked ? "yes" : "no");
    } else {
        fprintf(stderr, "[ranga] purge failed: %s\n", err_msg);
    }

    return exit_code;
}

int main(int argc, char **argv) {
    bool status_mode = false;
    bool isolate_mode = false;
    const char *purge_path = NULL;
    bool revoke_session = false;
    bool json_mode = false;
    int cmd_index = -1;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_index = i + 1;
            break;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return TEMPEST_EXIT_OK;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("ranga %s\n", TEMPEST_VERSION);
            return TEMPEST_EXIT_OK;
        } else if (strcmp(argv[i], "--status") == 0) {
            status_mode = true;
        } else if (strcmp(argv[i], "--isolate") == 0) {
            isolate_mode = true;
        } else if (strcmp(argv[i], "--revoke-session") == 0) {
            revoke_session = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_mode = true;
        } else if (strcmp(argv[i], "--purge") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "ranga: --purge requires a file path\n");
                return TEMPEST_EXIT_USAGE;
            }
            purge_path = argv[++i];
        } else {
            fprintf(stderr, "ranga: unknown option: %s\n", argv[i]);
            return TEMPEST_EXIT_USAGE;
        }
    }

    if (isolate_mode) {
        if (cmd_index < 0) {
            fprintf(stderr, "ranga: --isolate requires '-- <cmd> [args...]'\n");
            return TEMPEST_EXIT_USAGE;
        }
        return run_isolate(argc - cmd_index, &argv[cmd_index]);
    }
    if (purge_path != NULL) {
        return run_purge(purge_path, revoke_session, json_mode);
    }
    if (status_mode || argc == 1) {
        return run_status(json_mode);
    }

    print_usage();
    return TEMPEST_EXIT_USAGE;
}
