#include "tempest_contract.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

struct CcacheCred {
    std::string client;
    std::string server;
    uint16_t enctype = 0;
    uint32_t authtime = 0;
    uint32_t starttime = 0;
    uint32_t endtime = 0;
    uint32_t renew_till = 0;
    uint32_t tktflags = 0;
    bool is_config = false;
    bool weak_enctype = false;
};

struct CcacheReport {
    int exit_code = TEMPEST_EXIT_OK;
    std::string ccache_path;
    uint16_t version = 0;
    std::string default_principal;
    std::vector<CcacheCred> creds;
    int primary_index = -1;

    int64_t now_epoch = 0;
    bool has_kdc_time = false;
    int64_t kdc_time_epoch = 0;
    int64_t skew_sec = 0;
    bool skew_violation = false;

    int64_t warn_window_sec = 300;
    int64_t ttl_sec = 0;
    int64_t renew_ttl_sec = 0;

    bool weak_enctype = false;
    bool expired = false;
    bool expiring_soon = false;

    bool renew_attempted = false;
    int renew_exit_code = -1;
    bool renewed = false;

    std::string status = "HEALTHY";
    std::string error;
};

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_usage(void) {
    printf(
        "chronoa v%s - Tempest C++20 CCACHE Watchdog & RFC 4120 Clock-Skew Enforcer\n\n"
        "USAGE:\n"
        "    chronoa [OPTIONS]\n\n"
        "OPTIONS:\n"
        "    --ccache <PATH>           Path to MIT Kerberos CCACHE file (default: $KRB5CCNAME or /tmp/krb5cc_<uid>)\n"
        "    --now <EPOCH>             Override current UNIX epoch seconds (deterministic check)\n"
        "    --kdc-time <EPOCH>        Reference KDC UNIX epoch seconds for RFC 4120 300s skew check\n"
        "    --warn-window-sec <SEC>   Pre-expiry warning/renewal threshold in seconds (default: 300)\n"
        "    --renew-cmd <CMD>         Command parsed into argv and executed via execvp (no shell) when expiring/expired\n"
        "    --once                    Evaluate once and exit (default)\n"
        "    --watch                   Poll continuously every --interval-sec seconds until SIGINT/SIGTERM\n"
        "    --interval-sec <SEC>      Watch polling interval in seconds (default: 30)\n"
        "    --json                    Output structured JSON\n"
        "    -h, --help                Show this help\n"
        "    -V, --version             Show version\n",
        TEMPEST_VERSION
    );
}

static bool parse_int64_arg(const char *s, int64_t &out) {
    if (!s || *s == '\0') return false;
    if (std::isspace(static_cast<unsigned char>(*s))) return false;
    errno = 0;
    char *end = nullptr;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return false;
    if (v < std::numeric_limits<int64_t>::min() ||
        v > std::numeric_limits<int64_t>::max()) {
        return false;
    }
    out = static_cast<int64_t>(v);
    return true;
}

static bool is_weak_enctype(uint16_t etype) {
    return etype == 1 || etype == 2 || etype == 3 || etype == 16 || etype == 23;
}

static bool resolve_default_ccache_path(std::string &out_path, std::string &err) {
    const char *env = getenv("KRB5CCNAME");
    if (!env || *env == '\0') {
        out_path = "/tmp/krb5cc_" + std::to_string((unsigned long)getuid());
        return true;
    }
    std::string raw(env);
    if (raw.rfind("FILE:", 0) == 0) {
        out_path = raw.substr(5);
        if (out_path.empty()) {
            err = "Empty FILE: path in KRB5CCNAME";
            return false;
        }
        return true;
    }
    if (raw.find(':') != std::string::npos && raw[0] != '/') {
        err = "Unsupported non-FILE KRB5CCNAME scheme: " + raw;
        return false;
    }
    out_path = raw;
    return true;
}

static bool read_u16(const std::vector<uint8_t> &buf, size_t &cur, uint16_t &out) {
    if (cur + 2 > buf.size()) return false;
    out = tempest_read_be16(&buf[cur]);
    cur += 2;
    return true;
}

static bool read_u32(const std::vector<uint8_t> &buf, size_t &cur, uint32_t &out) {
    if (cur + 4 > buf.size()) return false;
    out = tempest_read_be32(&buf[cur]);
    cur += 4;
    return true;
}

static bool skip_bytes(const std::vector<uint8_t> &buf, size_t &cur, size_t n) {
    if (n > buf.size() - cur) return false;
    cur += n;
    return true;
}

static bool read_principal(const std::vector<uint8_t> &buf, size_t &cur, std::string &out) {
    uint32_t name_type = 0;
    uint32_t num_components = 0;
    uint32_t realm_len = 0;
    if (!read_u32(buf, cur, name_type)) return false;
    (void)name_type;
    if (!read_u32(buf, cur, num_components) || num_components > 64) return false;
    if (!read_u32(buf, cur, realm_len) || realm_len > 1024 || realm_len > buf.size() - cur) return false;

    std::string realm(reinterpret_cast<const char *>(&buf[cur]), realm_len);
    cur += realm_len;

    std::string assembled;
    for (uint32_t i = 0; i < num_components; ++i) {
        uint32_t comp_len = 0;
        if (!read_u32(buf, cur, comp_len) || comp_len > 1024 || comp_len > buf.size() - cur) return false;
        if (i > 0) assembled += "/";
        assembled.append(reinterpret_cast<const char *>(&buf[cur]), comp_len);
        cur += comp_len;
    }
    out = assembled + "@" + realm;
    return true;
}

static bool load_and_parse_ccache(
    const std::string &path,
    uint16_t &version_out,
    std::string &default_principal_out,
    std::vector<CcacheCred> &creds_out,
    int &exit_code_out,
    std::string &err_out
) {
    creds_out.clear();
    default_principal_out.clear();
    version_out = 0;

    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        int saved = errno;
        if (saved == ENOENT) {
            exit_code_out = TEMPEST_EXIT_MISSING;
            err_out = "CCACHE file not found: " + path;
        } else if (saved == ELOOP) {
            exit_code_out = TEMPEST_EXIT_POLICY_STOP;
            err_out = "Refusing symbolic link CCACHE path: " + path;
        } else if (saved == EACCES || saved == EPERM) {
            exit_code_out = TEMPEST_EXIT_POLICY_STOP;
            err_out = "Permission denied reading CCACHE file: " + path;
        } else {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = std::string("Failed to open CCACHE file: ") + strerror(saved);
        }
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        exit_code_out = TEMPEST_EXIT_PARSE_ERR;
        err_out = std::string("Failed to stat CCACHE file: ") + strerror(saved);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        exit_code_out = TEMPEST_EXIT_POLICY_STOP;
        err_out = "Refusing non-regular CCACHE file: " + path;
        return false;
    }
    constexpr off_t kMaxCcacheSize = 16 * 1024 * 1024;
    if (st.st_size < 2 || st.st_size > kMaxCcacheSize) {
        close(fd);
        exit_code_out = TEMPEST_EXIT_PARSE_ERR;
        err_out = "Invalid CCACHE file size";
        return false;
    }

    const size_t expected = static_cast<size_t>(st.st_size);
    std::vector<uint8_t> buf(expected);
    size_t total = 0;
    while (total < expected) {
        ssize_t n = read(fd, buf.data() + total, expected - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            close(fd);
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = std::string("Failed to read CCACHE bytes: ") + strerror(saved);
            return false;
        }
        if (n == 0) {
            close(fd);
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated CCACHE read before expected size";
            return false;
        }
        total += static_cast<size_t>(n);
    }
    close(fd);

    size_t cur = 0;
    uint16_t fmt = 0;
    if (!read_u16(buf, cur, fmt)) {
        exit_code_out = TEMPEST_EXIT_PARSE_ERR;
        err_out = "Truncated CCACHE header";
        return false;
    }
    if (fmt != 0x0504 && fmt != 0x0503) {
        exit_code_out = TEMPEST_EXIT_PARSE_ERR;
        err_out = "Unsupported CCACHE format magic (expected 0x0504 or 0x0503)";
        return false;
    }
    version_out = fmt;

    if (fmt == 0x0504) {
        uint16_t header_len = 0;
        if (!read_u16(buf, cur, header_len) || !skip_bytes(buf, cur, header_len)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated CCACHE v4 header tags";
            return false;
        }
    }

    if (!read_principal(buf, cur, default_principal_out)) {
        exit_code_out = TEMPEST_EXIT_PARSE_ERR;
        err_out = "Failed to parse CCACHE default principal";
        return false;
    }

    while (cur < buf.size()) {
        CcacheCred c;
        if (!read_principal(buf, cur, c.client) || !read_principal(buf, cur, c.server)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Corrupt credential principal in CCACHE";
            return false;
        }

        uint32_t key_len = 0;
        if (!read_u16(buf, cur, c.enctype) ||
            !read_u32(buf, cur, key_len) ||
            key_len > 65536 ||
            !skip_bytes(buf, cur, key_len)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Corrupt session keyblock in CCACHE";
            return false;
        }

        if (!read_u32(buf, cur, c.authtime) ||
            !read_u32(buf, cur, c.starttime) ||
            !read_u32(buf, cur, c.endtime) ||
            !read_u32(buf, cur, c.renew_till)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated credential timestamps in CCACHE";
            return false;
        }

        uint8_t is_skey = 0;
        if (cur >= buf.size()) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated credential flags in CCACHE";
            return false;
        }
        is_skey = buf[cur++];
        (void)is_skey;

        if (!read_u32(buf, cur, c.tktflags)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated ticket flags in CCACHE";
            return false;
        }

        uint32_t addr_count = 0;
        if (!read_u32(buf, cur, addr_count) || addr_count > 1024) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Invalid address count in CCACHE";
            return false;
        }
        for (uint32_t i = 0; i < addr_count; ++i) {
            uint16_t addrtype = 0;
            uint32_t alen = 0;
            if (!read_u16(buf, cur, addrtype) || !read_u32(buf, cur, alen) || !skip_bytes(buf, cur, alen)) {
                exit_code_out = TEMPEST_EXIT_PARSE_ERR;
                err_out = "Truncated address entry in CCACHE";
                return false;
            }
            (void)addrtype;
        }

        uint32_t ad_count = 0;
        if (!read_u32(buf, cur, ad_count) || ad_count > 1024) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Invalid authdata count in CCACHE";
            return false;
        }
        for (uint32_t i = 0; i < ad_count; ++i) {
            uint16_t adtype = 0;
            uint32_t dlen = 0;
            if (!read_u16(buf, cur, adtype) || !read_u32(buf, cur, dlen) || !skip_bytes(buf, cur, dlen)) {
                exit_code_out = TEMPEST_EXIT_PARSE_ERR;
                err_out = "Truncated authdata entry in CCACHE";
                return false;
            }
            (void)adtype;
        }

        uint32_t tkt_len = 0;
        if (!read_u32(buf, cur, tkt_len) || !skip_bytes(buf, cur, tkt_len)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated ticket payload in CCACHE";
            return false;
        }

        uint32_t s2_len = 0;
        if (!read_u32(buf, cur, s2_len) || !skip_bytes(buf, cur, s2_len)) {
            exit_code_out = TEMPEST_EXIT_PARSE_ERR;
            err_out = "Truncated second ticket payload in CCACHE";
            return false;
        }

        c.is_config = (c.endtime == 0) || (c.server.rfind("krb5_ccache_conf_data/", 0) == 0);
        c.weak_enctype = !c.is_config && is_weak_enctype(c.enctype);
        creds_out.push_back(c);
    }

    return true;
}

static int select_primary_cred(const std::vector<CcacheCred> &creds) {
    int fallback = -1;
    for (size_t i = 0; i < creds.size(); ++i) {
        if (creds[i].is_config) continue;
        if (creds[i].server.rfind("krbtgt/", 0) == 0) {
            return (int)i;
        }
        if (fallback < 0 || creds[i].endtime > creds[(size_t)fallback].endtime) {
            fallback = (int)i;
        }
    }
    return fallback;
}

static bool is_disallowed_shell_operator(char c) {
    return c == ';' || c == '&' || c == '|' || c == '`' ||
           c == '<' || c == '>' || c == '\n' || c == '\r' ||
           c == '(' || c == ')';
}

static bool parse_renew_argv(
    const std::string &cmd,
    std::vector<std::string> &argv_out,
    std::string &err_out
) {
    argv_out.clear();
    err_out.clear();

    std::string current;
    bool in_token = false;
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < cmd.size(); ++i) {
        char c = cmd[i];
        if (c == '\n' || c == '\r') {
            err_out = "Newline characters are not permitted in --renew-cmd";
            return false;
        }

        if (in_single) {
            if (c == '\'') {
                in_single = false;
            } else {
                current.push_back(c);
            }
            continue;
        }

        if (in_double) {
            if (c == '"') {
                in_double = false;
            } else if (c == '\\') {
                if (i + 1 >= cmd.size()) {
                    err_out = "Trailing backslash inside double quotes in --renew-cmd";
                    return false;
                }
                char nxt = cmd[i + 1];
                if (nxt == '\n' || nxt == '\r') {
                    err_out = "Newline characters are not permitted in --renew-cmd";
                    return false;
                }
                if (nxt == '"' || nxt == '\\' || nxt == '$' || nxt == '`') {
                    current.push_back(nxt);
                    ++i;
                } else {
                    current.push_back(c);
                }
            } else if (c == '`' || (c == '$' && i + 1 < cmd.size() && (cmd[i + 1] == '(' || cmd[i + 1] == '{'))) {
                err_out = "Shell expansion syntax is not permitted in --renew-cmd";
                return false;
            } else {
                current.push_back(c);
            }
            continue;
        }

        if (is_disallowed_shell_operator(c)) {
            err_out = "Shell metacharacters/operators are not permitted in --renew-cmd";
            return false;
        }
        if (c == '$' && i + 1 < cmd.size() && (cmd[i + 1] == '(' || cmd[i + 1] == '{')) {
            err_out = "Shell expansion syntax (${ / $() is not permitted in --renew-cmd";
            return false;
        }

        if (std::isspace(static_cast<unsigned char>(c))) {
            if (in_token) {
                argv_out.push_back(std::move(current));
                current.clear();
                in_token = false;
            }
        } else if (c == '\'') {
            in_single = true;
            in_token = true;
        } else if (c == '"') {
            in_double = true;
            in_token = true;
        } else if (c == '\\') {
            if (i + 1 >= cmd.size()) {
                err_out = "Trailing backslash in --renew-cmd";
                return false;
            }
            char nxt = cmd[++i];
            if (nxt == '\n' || nxt == '\r') {
                err_out = "Newline characters are not permitted in --renew-cmd";
                return false;
            }
            current.push_back(nxt);
            in_token = true;
        } else {
            current.push_back(c);
            in_token = true;
        }
    }

    if (in_single || in_double) {
        err_out = "Unterminated quote in --renew-cmd";
        return false;
    }
    if (in_token) {
        argv_out.push_back(std::move(current));
    }
    if (argv_out.empty()) {
        err_out = "--renew-cmd must not be empty";
        return false;
    }
    return true;
}

// Run --renew-cmd directly via execvp (no shell) with stdout -> /dev/null so --json stays valid.
static int run_renew_command(const std::vector<std::string> &argv) {
    if (argv.empty()) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            if (devnull != STDOUT_FILENO) {
                dup2(devnull, STDOUT_FILENO);
                close(devnull);
            }
        }
        std::vector<char *> c_argv;
        c_argv.reserve(argv.size() + 1);
        for (const auto &s : argv) {
            c_argv.push_back(const_cast<char *>(s.c_str()));
        }
        c_argv.push_back(nullptr);
        execvp(c_argv[0], c_argv.data());
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static void evaluate_once(
    const std::string &ccache_path,
    bool has_now_override,
    int64_t now_override,
    bool has_kdc_time,
    int64_t kdc_time_epoch,
    int64_t warn_window_sec,
    const std::vector<std::string> &renew_argv,
    CcacheReport &rep
) {
    rep = CcacheReport{};
    rep.ccache_path = ccache_path;
    rep.now_epoch = has_now_override ? now_override : (int64_t)time(nullptr);
    rep.has_kdc_time = has_kdc_time;
    rep.kdc_time_epoch = kdc_time_epoch;
    rep.warn_window_sec = warn_window_sec;

    if (!load_and_parse_ccache(
            ccache_path, rep.version, rep.default_principal, rep.creds, rep.exit_code, rep.error)) {
        if (rep.exit_code == TEMPEST_EXIT_MISSING) {
            rep.status = "MISSING";
        } else if (rep.exit_code == TEMPEST_EXIT_POLICY_STOP) {
            rep.status = "POLICY_STOP";
        } else {
            rep.status = "PARSE_ERROR";
        }
        return;
    }

    rep.primary_index = select_primary_cred(rep.creds);
    if (rep.primary_index < 0) {
        rep.exit_code = TEMPEST_EXIT_MISSING;
        rep.status = "NO_CREDENTIALS";
        rep.error = "CCACHE parsed cleanly but contains no active credentials";
        return;
    }

    auto assess_state = [&]() {
        rep.weak_enctype = false;
        for (const auto &c : rep.creds) {
            if (!c.is_config && c.weak_enctype) {
                rep.weak_enctype = true;
            }
        }
        const CcacheCred &p = rep.creds[(size_t)rep.primary_index];
        rep.ttl_sec = (int64_t)p.endtime - rep.now_epoch;
        rep.renew_ttl_sec = (p.renew_till > 0) ? ((int64_t)p.renew_till - rep.now_epoch) : 0;

        int64_t ticket_future_skew = ((int64_t)p.authtime > rep.now_epoch)
                                         ? ((int64_t)p.authtime - rep.now_epoch)
                                         : 0;
        int64_t kdc_skew = rep.has_kdc_time ? llabs(rep.now_epoch - rep.kdc_time_epoch) : 0;
        rep.skew_sec = (kdc_skew > ticket_future_skew) ? kdc_skew : ticket_future_skew;
        rep.skew_violation = rep.skew_sec > RFC4120_MAX_CLOCK_SKEW_SEC;

        rep.expired = (rep.ttl_sec <= 0);
        rep.expiring_soon = (!rep.expired && rep.ttl_sec <= rep.warn_window_sec);
    };

    assess_state();

    if (!renew_argv.empty() && !rep.skew_violation && !rep.weak_enctype &&
        (rep.expired || rep.expiring_soon)) {
        rep.renew_attempted = true;
        rep.renew_exit_code = run_renew_command(renew_argv);

        uint16_t post_ver = 0;
        std::string post_princ, post_err;
        std::vector<CcacheCred> post_creds;
        int post_exit = TEMPEST_EXIT_OK;
        if (load_and_parse_ccache(
                ccache_path, post_ver, post_princ, post_creds, post_exit, post_err)) {
            int post_idx = select_primary_cred(post_creds);
            if (post_idx >= 0) {
                int64_t prev_end = rep.creds[(size_t)rep.primary_index].endtime;
                rep.version = post_ver;
                rep.default_principal = post_princ;
                rep.creds = std::move(post_creds);
                rep.primary_index = post_idx;
                if ((int64_t)rep.creds[(size_t)rep.primary_index].endtime > prev_end) {
                    rep.renewed = true;
                }
                assess_state();
            }
        }
    }

    if (rep.skew_violation) {
        rep.exit_code = TEMPEST_EXIT_POLICY_STOP;
        rep.status = "CLOCK_SKEW_VIOLATION";
    } else if (rep.weak_enctype) {
        rep.exit_code = TEMPEST_EXIT_POLICY_STOP;
        rep.status = "WEAK_ENCTYPE";
    } else if (rep.renew_attempted && rep.renew_exit_code != 0) {
        rep.exit_code = TEMPEST_EXIT_POLICY_STOP;
        rep.status = "RENEW_FAILED";
    } else if (rep.expired) {
        rep.exit_code = TEMPEST_EXIT_POLICY_STOP;
        rep.status = "EXPIRED";
    } else if (rep.renewed) {
        rep.exit_code = TEMPEST_EXIT_OK;
        rep.status = "RENEWED";
    } else if (rep.expiring_soon) {
        rep.exit_code = TEMPEST_EXIT_OK;
        rep.status = "EXPIRING_SOON";
    } else {
        rep.exit_code = TEMPEST_EXIT_OK;
        rep.status = "HEALTHY";
    }
}

static void print_json_report(const CcacheReport &rep) {
    printf("{");
    printf("\"agent\":\"chronoa\",");
    printf("\"version\":\"%s\",", TEMPEST_VERSION);
    printf("\"status\":");
    tempest_fprint_json_str(stdout, rep.status.c_str());
    printf(",\"exit_code\":%d,", rep.exit_code);
    printf("\"ccache_path\":");
    tempest_fprint_json_str(stdout, rep.ccache_path.c_str());
    printf(",\"ccache_format\":\"0x%04x\",", (unsigned int)rep.version);
    printf("\"default_principal\":");
    tempest_fprint_json_str(stdout, rep.default_principal.c_str());
    printf(",\"now_epoch\":%lld,", (long long)rep.now_epoch);
    printf("\"has_kdc_time\":%s,", rep.has_kdc_time ? "true" : "false");
    printf("\"kdc_time_epoch\":%lld,", (long long)rep.kdc_time_epoch);
    printf("\"skew_sec\":%lld,", (long long)rep.skew_sec);
    printf("\"max_skew_sec\":%d,", RFC4120_MAX_CLOCK_SKEW_SEC);
    printf("\"skew_violation\":%s,", rep.skew_violation ? "true" : "false");
    printf("\"warn_window_sec\":%lld,", (long long)rep.warn_window_sec);
    printf("\"ttl_sec\":%lld,", (long long)rep.ttl_sec);
    printf("\"renew_ttl_sec\":%lld,", (long long)rep.renew_ttl_sec);
    printf("\"weak_enctype\":%s,", rep.weak_enctype ? "true" : "false");
    printf("\"expired\":%s,", rep.expired ? "true" : "false");
    printf("\"expiring_soon\":%s,", rep.expiring_soon ? "true" : "false");
    printf("\"renew_attempted\":%s,", rep.renew_attempted ? "true" : "false");
    printf("\"renew_exit_code\":%d,", rep.renew_exit_code);
    printf("\"renewed\":%s,", rep.renewed ? "true" : "false");

    if (rep.primary_index >= 0) {
        const CcacheCred &p = rep.creds[(size_t)rep.primary_index];
        printf("\"primary_ticket\":{");
        printf("\"client\":");
        tempest_fprint_json_str(stdout, p.client.c_str());
        printf(",\"server\":");
        tempest_fprint_json_str(stdout, p.server.c_str());
        printf(",\"enctype\":%u,", (unsigned int)p.enctype);
        printf("\"enctype_name\":");
        tempest_fprint_json_str(stdout, tempest_enctype_name((int32_t)p.enctype));
        printf(",\"authtime\":%u,\"starttime\":%u,\"endtime\":%u,\"renew_till\":%u",
               p.authtime, p.starttime, p.endtime, p.renew_till);
        printf("},");
    } else {
        printf("\"primary_ticket\":null,");
    }

    printf("\"ticket_count\":%zu,", rep.creds.size());
    printf("\"error\":");
    tempest_fprint_json_str(stdout, rep.error.c_str());
    printf("}\n");
    fflush(stdout);
}

static void print_text_report(const CcacheReport &rep) {
    printf("[chronoa] status=%s exit=%d ccache=%s\n",
           rep.status.c_str(), rep.exit_code, rep.ccache_path.c_str());
    if (!rep.error.empty()) {
        printf("  error          : %s\n", rep.error.c_str());
    }
    if (!rep.default_principal.empty()) {
        printf("  principal      : %s (format 0x%04x)\n",
               rep.default_principal.c_str(), (unsigned int)rep.version);
    }
    if (rep.primary_index >= 0) {
        const CcacheCred &p = rep.creds[(size_t)rep.primary_index];
        printf("  primary server : %s\n", p.server.c_str());
        printf("  enctype        : %s (%u)%s\n",
               tempest_enctype_name((int32_t)p.enctype),
               (unsigned int)p.enctype,
               rep.weak_enctype ? " [WEAK/POLICY STOP]" : "");
        printf("  ttl / renew    : %lld sec / %lld sec (warn window %lld sec)\n",
               (long long)rep.ttl_sec,
               (long long)rep.renew_ttl_sec,
               (long long)rep.warn_window_sec);
    }
    if (rep.has_kdc_time || rep.skew_sec > 0) {
        printf("  clock skew     : %lld sec (RFC 4120 limit %ds)%s\n",
               (long long)rep.skew_sec,
               RFC4120_MAX_CLOCK_SKEW_SEC,
               rep.skew_violation ? " [VIOLATION]" : "");
    }
    if (rep.renew_attempted) {
        printf("  renew action   : exit=%d renewed=%s\n",
               rep.renew_exit_code, rep.renewed ? "yes" : "no");
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    std::string ccache_path;
    bool has_ccache_arg = false;
    bool has_now_override = false;
    int64_t now_override = 0;
    bool has_kdc_time = false;
    int64_t kdc_time = 0;
    int64_t warn_window_sec = 300;
    std::string renew_cmd;
    std::vector<std::string> renew_argv;
    bool has_renew_cmd = false;
    bool watch_mode = false;
    int64_t interval_sec = 30;
    bool json_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return TEMPEST_EXIT_OK;
        } else if (arg == "-V" || arg == "--version") {
            printf("chronoa %s\n", TEMPEST_VERSION);
            return TEMPEST_EXIT_OK;
        } else if (arg == "--json") {
            json_mode = true;
        } else if (arg == "--once") {
            watch_mode = false;
        } else if (arg == "--watch") {
            watch_mode = true;
        } else if (arg == "--ccache") {
            if (i + 1 >= argc) {
                fprintf(stderr, "chronoa: --ccache requires an argument\n");
                return TEMPEST_EXIT_USAGE;
            }
            ccache_path = argv[++i];
            has_ccache_arg = true;
        } else if (arg == "--now") {
            if (i + 1 >= argc || !parse_int64_arg(argv[i + 1], now_override) ||
                now_override < 0) {
                fprintf(stderr, "chronoa: --now requires a non-negative integer epoch\n");
                return TEMPEST_EXIT_USAGE;
            }
            has_now_override = true;
            ++i;
        } else if (arg == "--kdc-time") {
            if (i + 1 >= argc || !parse_int64_arg(argv[i + 1], kdc_time) ||
                kdc_time < 0) {
                fprintf(stderr, "chronoa: --kdc-time requires a non-negative integer epoch\n");
                return TEMPEST_EXIT_USAGE;
            }
            has_kdc_time = true;
            ++i;
        } else if (arg == "--warn-window-sec") {
            if (i + 1 >= argc || !parse_int64_arg(argv[i + 1], warn_window_sec) || warn_window_sec < 0) {
                fprintf(stderr, "chronoa: --warn-window-sec requires a non-negative integer\n");
                return TEMPEST_EXIT_USAGE;
            }
            ++i;
        } else if (arg == "--renew-cmd") {
            if (i + 1 >= argc) {
                fprintf(stderr, "chronoa: --renew-cmd requires a command\n");
                return TEMPEST_EXIT_USAGE;
            }
            renew_cmd = argv[++i];
            has_renew_cmd = true;
        } else if (arg == "--interval-sec") {
            if (i + 1 >= argc || !parse_int64_arg(argv[i + 1], interval_sec) || interval_sec <= 0) {
                fprintf(stderr, "chronoa: --interval-sec requires a positive integer\n");
                return TEMPEST_EXIT_USAGE;
            }
            ++i;
        } else {
            fprintf(stderr, "chronoa: unknown option: %s\n", arg.c_str());
            return TEMPEST_EXIT_USAGE;
        }
    }

    if (has_renew_cmd) {
        std::string renew_err;
        if (!parse_renew_argv(renew_cmd, renew_argv, renew_err)) {
            fprintf(stderr, "chronoa: invalid --renew-cmd: %s\n", renew_err.c_str());
            return TEMPEST_EXIT_USAGE;
        }
    }

    if (has_ccache_arg) {
        if (ccache_path.rfind("FILE:", 0) == 0) {
            ccache_path = ccache_path.substr(5);
        }
        if (ccache_path.empty()) {
            fprintf(stderr, "chronoa: --ccache requires a non-empty file path\n");
            return TEMPEST_EXIT_USAGE;
        }
        size_t colon = ccache_path.find(':');
        size_t slash = ccache_path.find('/');
        if (colon != std::string::npos && ccache_path[0] != '/' &&
            (slash == std::string::npos || colon < slash)) {
            std::string scheme_err = "Unsupported non-FILE CCACHE scheme: " + ccache_path;
            if (json_mode) {
                CcacheReport err_rep;
                err_rep.exit_code = TEMPEST_EXIT_MISSING;
                err_rep.status = "MISSING";
                err_rep.error = scheme_err;
                print_json_report(err_rep);
            } else {
                fprintf(stderr, "chronoa: %s\n", scheme_err.c_str());
            }
            return TEMPEST_EXIT_MISSING;
        }
    }

    if (ccache_path.empty()) {
        std::string resolve_err;
        if (!resolve_default_ccache_path(ccache_path, resolve_err)) {
            if (json_mode) {
                CcacheReport err_rep;
                err_rep.exit_code = TEMPEST_EXIT_MISSING;
                err_rep.status = "MISSING";
                err_rep.error = resolve_err;
                print_json_report(err_rep);
            } else {
                fprintf(stderr, "chronoa: %s\n", resolve_err.c_str());
            }
            return TEMPEST_EXIT_MISSING;
        }
    }

    if (watch_mode) {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
    }

    CcacheReport rep;
    do {
        evaluate_once(
            ccache_path,
            has_now_override,
            now_override,
            has_kdc_time,
            kdc_time,
            warn_window_sec,
            renew_argv,
            rep
        );
        if (json_mode) {
            print_json_report(rep);
        } else {
            print_text_report(rep);
        }
        if (!watch_mode || g_stop) break;
        int64_t clamped_sleep = interval_sec;
        if (clamped_sleep < 1) {
            clamped_sleep = 1;
        }
        int64_t max_sleep = (int64_t)std::numeric_limits<unsigned int>::max();
        if (clamped_sleep > max_sleep) {
            clamped_sleep = max_sleep;
        }
        sleep((unsigned int)clamped_sleep);
    } while (!g_stop);

    return rep.exit_code;
}
