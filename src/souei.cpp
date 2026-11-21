#include "tempest_contract.h"

#include <errno.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

struct KeyringEntry {
    std::string serial;
    std::string flags;
    std::string perm_hex;
    uint32_t perm = 0;
    std::string uid_gid;
    std::string type;
    std::string description;
    bool insecure_acl = false;
};

struct InotifyRecord {
    uint32_t mask = 0;
    std::string events;
};

struct KcmPeerInfo {
    bool checked = false;
    bool exists = false;
    bool is_symlink = false;
    bool is_socket = false;
    bool connected = false;
    bool peercred_ok = false;
    uint32_t mode = 0;
    bool insecure_mode = false;
    int connect_errno = 0;
    int peercred_errno = 0;
    pid_t pid = -1;
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    std::string exe_path;
    std::string error;
};

static void print_usage(void) {
    printf(
        "souei v%s - Tempest C++20 Shadow Telemetry & KCM/Keyring Observer\n\n"
        "USAGE:\n"
        "    souei [OPTIONS]\n\n"
        "OPTIONS:\n"
        "    --probe                  Run passive /proc/keys and session keyring audit (default)\n"
        "    --kcm-socket <PATH>      Inspect UNIX socket permissions and peer SO_PEERCRED\n"
        "    --watch-file <PATH>      Monitor .keytab/.ccache access via Linux inotify\n"
        "    --timeout-ms <MS>        Inotify watch timeout in milliseconds (default: 100)\n"
        "    --json                   Output structured JSON\n"
        "    -h, --help               Show this help\n"
        "    -V, --version            Show version\n",
        TEMPEST_VERSION
    );
}

static bool parse_describe_string(const std::string &desc, KeyringEntry &out) {
    // Kernel KEYCTL_DESCRIBE format: "type;uid;gid;perm_hex;description"
    std::vector<std::string> parts;
    std::stringstream ss(desc);
    std::string item;
    while (std::getline(ss, item, ';')) {
        parts.push_back(item);
    }
    if (parts.size() < 4) return false;
    out.type = parts[0];
    out.uid_gid = parts[1] + ":" + parts[2];
    out.perm_hex = parts[3];
    out.perm = (uint32_t)strtoul(out.perm_hex.c_str(), nullptr, 16);
    out.insecure_acl = (out.perm & 0x0000ffffU) != 0;
    if (parts.size() >= 5) {
        out.description = parts[4];
        for (size_t i = 5; i < parts.size(); ++i) {
            out.description += ";" + parts[i];
        }
    }
    return true;
}

static std::vector<KeyringEntry> audit_proc_keys(bool &proc_keys_readable) {
    std::vector<KeyringEntry> entries;
    std::ifstream in("/proc/keys");
    if (!in.is_open()) {
        proc_keys_readable = false;
        return entries;
    }
    proc_keys_readable = true;
    std::string line;
    while (std::getline(in, line)) {
        // /proc/keys columns: serial flags usage expr perm uid gid type desc...
        std::istringstream ls(line);
        std::string serial, flags, usage, expr, perm_hex, uid_s, gid_s, type;
        if (!(ls >> serial >> flags >> usage >> expr >> perm_hex >> uid_s >> gid_s >> type)) {
            continue;
        }
        std::string rest;
        std::getline(ls, rest);
        size_t first = rest.find_first_not_of(" \t");
        std::string desc = (first == std::string::npos) ? "" : rest.substr(first);

        if (type == "keyring" || desc.find("krb") != std::string::npos || desc.find("_ses") != std::string::npos) {
            KeyringEntry e;
            e.serial = serial;
            e.flags = flags;
            e.perm_hex = perm_hex;
            e.perm = (uint32_t)strtoul(perm_hex.c_str(), nullptr, 16);
            e.uid_gid = uid_s + ":" + gid_s;
            e.type = type;
            e.description = desc;
            e.insecure_acl = (e.perm & 0x0000ffffU) != 0;
            entries.push_back(e);
        }
    }
    return entries;
}

static KcmPeerInfo inspect_kcm_socket(const std::string &sock_path) {
    KcmPeerInfo info;
    info.checked = true;

    struct stat st;
    if (lstat(sock_path.c_str(), &st) != 0) {
        info.error = strerror(errno);
        return info;
    }
    info.exists = true;
    info.mode = (uint32_t)(st.st_mode & 0777U);
    if (S_ISLNK(st.st_mode)) {
        info.is_symlink = true;
        info.is_socket = false;
        info.error = "KCM socket path is a symbolic link (refusing symlink redirection)";
        return info;
    }
    info.is_socket = S_ISSOCK(st.st_mode);

    if (!info.is_socket) {
        info.error = "Path exists but is not a UNIX domain socket";
        return info;
    }
    info.insecure_mode = (info.mode & 0077U) != 0; // group or world rwx

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        info.connect_errno = errno;
        info.error = strerror(info.connect_errno);
        return info;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (sock_path.size() >= sizeof(addr.sun_path)) {
        close(fd);
        info.error = "Socket path exceeds sun_path limit";
        return info;
    }
    memcpy(addr.sun_path, sock_path.c_str(), sock_path.size() + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        info.connect_errno = errno;
        info.error = strerror(info.connect_errno);
        close(fd);
        return info;
    }
    info.connected = true;

    struct ucred cred;
    socklen_t len = sizeof(cred);
    memset(&cred, 0, sizeof(cred));
    int gs_rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);
    if (gs_rc == 0 && len == sizeof(cred) && cred.uid != (uid_t)-1) {
        info.peercred_ok = true;
        info.pid = cred.pid;
        info.uid = cred.uid;
        info.gid = cred.gid;
        if (cred.pid > 0) {
            char proc_exe[64];
            char exe_buf[512];
            snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", (int)cred.pid);
            ssize_t n = readlink(proc_exe, exe_buf, sizeof(exe_buf) - 1);
            if (n > 0) {
                exe_buf[n] = '\0';
                info.exe_path = exe_buf;
            }
        }
    } else {
        int saved = (gs_rc != 0 && errno != 0) ? errno : EINVAL;
        info.peercred_errno = saved;
        info.error = std::string("getsockopt(SO_PEERCRED) failed: ") + strerror(saved);
    }

    close(fd);
    return info;
}

static std::string format_inotify_mask(uint32_t mask) {
    std::vector<std::string> parts;
    if (mask & IN_OPEN)   parts.push_back("IN_OPEN");
    if (mask & IN_ACCESS) parts.push_back("IN_ACCESS");
    if (mask & IN_MODIFY) parts.push_back("IN_MODIFY");
    if (mask & IN_ATTRIB) parts.push_back("IN_ATTRIB");
    if (mask & IN_DELETE_SELF) parts.push_back("IN_DELETE_SELF");
    if (parts.empty()) return "OTHER";
    std::string out = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) out += "|" + parts[i];
    return out;
}

static bool watch_file_inotify(
    const std::string &path,
    int timeout_ms,
    std::vector<InotifyRecord> &records,
    std::string &err_out
) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        err_out = strerror(errno);
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        err_out = "Refusing to watch symbolic link";
        return false;
    }

    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        err_out = strerror(errno);
        return false;
    }

    int wd = inotify_add_watch(
        ifd, path.c_str(),
        IN_OPEN | IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_DONT_FOLLOW
    );
    if (wd < 0) {
        err_out = strerror(errno);
        close(ifd);
        return false;
    }

    struct pollfd pfd;
    pfd.fd = ifd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int pr = poll(&pfd, 1, timeout_ms);
    if (pr > 0 && (pfd.revents & POLLIN)) {
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t n = read(ifd, buf, sizeof(buf));
        if (n > 0) {
            ssize_t off = 0;
            while (off + (ssize_t)sizeof(struct inotify_event) <= n) {
                const struct inotify_event *ev = (const struct inotify_event *)(buf + off);
                InotifyRecord rec;
                rec.mask = ev->mask;
                rec.events = format_inotify_mask(ev->mask);
                records.push_back(rec);
                off += (ssize_t)sizeof(struct inotify_event) + (ssize_t)ev->len;
            }
        }
    }

    inotify_rm_watch(ifd, wd);
    close(ifd);
    return true;
}

int main(int argc, char **argv) {
    bool json_out = false;
    bool run_probe = true;
    std::string kcm_socket;
    std::string watch_file;
    int timeout_ms = 100;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return TEMPEST_EXIT_OK;
        } else if (arg == "-V" || arg == "--version") {
            printf("souei %s\n", TEMPEST_VERSION);
            return TEMPEST_EXIT_OK;
        } else if (arg == "--json") {
            json_out = true;
        } else if (arg == "--probe") {
            run_probe = true;
        } else if (arg == "--kcm-socket") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for --kcm-socket\n");
                return TEMPEST_EXIT_USAGE;
            }
            kcm_socket = argv[++i];
        } else if (arg == "--watch-file") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for --watch-file\n");
                return TEMPEST_EXIT_USAGE;
            }
            watch_file = argv[++i];
        } else if (arg == "--timeout-ms") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for --timeout-ms\n");
                return TEMPEST_EXIT_USAGE;
            }
            timeout_ms = atoi(argv[++i]);
            if (timeout_ms < 1) timeout_ms = 1;
            if (timeout_ms > 60000) timeout_ms = 60000;
        } else {
            fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            return TEMPEST_EXIT_USAGE;
        }
    }

    (void)run_probe;

    uid_t uid = getuid();
    long sess_id = tempest_keyctl(KEYCTL_GET_KEYRING_ID, (unsigned long)KEY_SPEC_SESSION_KEYRING, 0, 0, 0);
    long user_sess_id = tempest_keyctl(KEYCTL_GET_KEYRING_ID, (unsigned long)KEY_SPEC_USER_SESSION_KEYRING, 0, 0, 0);
    bool isolated_session = (sess_id > 0 && user_sess_id > 0 && sess_id != user_sess_id);

    KeyringEntry sess_desc;
    bool has_sess_desc = false;
    if (sess_id > 0) {
        char dbuf[512];
        long dlen = tempest_keyctl(KEYCTL_DESCRIBE, (unsigned long)KEY_SPEC_SESSION_KEYRING, (unsigned long)dbuf, sizeof(dbuf) - 1, 0);
        if (dlen > 0) {
            size_t safe_len = (size_t)dlen < sizeof(dbuf) ? (size_t)dlen : sizeof(dbuf) - 1;
            dbuf[safe_len] = '\0';
            has_sess_desc = parse_describe_string(dbuf, sess_desc);
        }
    }

    bool proc_keys_readable = false;
    std::vector<KeyringEntry> proc_entries = audit_proc_keys(proc_keys_readable);

    std::vector<std::string> violations;
    if (has_sess_desc && sess_desc.insecure_acl) {
        violations.push_back("Session keyring grants non-owner ACL permissions (" + sess_desc.perm_hex + ")");
    }
    for (const auto &e : proc_entries) {
        if (e.insecure_acl && e.description.find("krb") != std::string::npos) {
            violations.push_back("Kerberos key in /proc/keys exposes group/other bits: " + e.serial + " (" + e.perm_hex + ")");
        }
    }

    KcmPeerInfo kcm_info;
    int exit_code = TEMPEST_EXIT_OK;
    if (!kcm_socket.empty()) {
        kcm_info = inspect_kcm_socket(kcm_socket);
        if (!kcm_info.exists) {
            exit_code = TEMPEST_EXIT_MISSING;
        } else if (kcm_info.is_symlink) {
            violations.push_back("KCM path is a symbolic link (refusing symlink redirection)");
        } else if (!kcm_info.is_socket) {
            violations.push_back("KCM path exists but is not a UNIX domain socket");
        } else {
            if (kcm_info.insecure_mode) {
                if ((kcm_info.mode & 0007U) != 0) {
                    violations.push_back("KCM socket permissions allow world access");
                } else {
                    violations.push_back("KCM socket permissions allow group access");
                }
            }
            if (!kcm_info.connected) {
                if (kcm_info.connect_errno == EACCES || kcm_info.connect_errno == EPERM) {
                    violations.push_back("KCM socket connection denied: " + kcm_info.error);
                } else {
                    exit_code = TEMPEST_EXIT_MISSING;
                }
            } else if (!kcm_info.peercred_ok) {
                violations.push_back(
                    kcm_info.error.empty()
                        ? "KCM socket SO_PEERCRED failed"
                        : "KCM socket " + kcm_info.error
                );
            } else if (kcm_info.uid != uid && kcm_info.uid != 0) {
                violations.push_back("KCM socket peer UID mismatch against expected daemon UID");
            }
        }
    }

    std::vector<InotifyRecord> inotify_events;
    bool watch_ok = true;
    std::string watch_err;
    if (!watch_file.empty()) {
        watch_ok = watch_file_inotify(watch_file, timeout_ms, inotify_events, watch_err);
        if (!watch_ok && exit_code == TEMPEST_EXIT_OK) {
            exit_code = TEMPEST_EXIT_MISSING;
        }
    }

    if (!violations.empty()) {
        exit_code = TEMPEST_EXIT_POLICY_STOP;
    }

    const char *status_str =
        (exit_code == TEMPEST_EXIT_OK) ? "OK" :
        (exit_code == TEMPEST_EXIT_POLICY_STOP) ? "POLICY_STOP" :
        (exit_code == TEMPEST_EXIT_PARSE_ERR) ? "PARSE_ERROR" : "RESOURCE_MISSING";

    if (json_out) {
        printf("{\n");
        printf("  \"agent\": \"souei\",\n");
        printf("  \"version\": \"%s\",\n", TEMPEST_VERSION);
        printf("  \"status\": \"%s\",\n", status_str);
        printf("  \"exit_code\": %d,\n", exit_code);
        printf("  \"uid\": %u,\n", (unsigned int)uid);
        printf("  \"session_keyring_id\": %ld,\n", sess_id);
        printf("  \"user_session_keyring_id\": %ld,\n", user_sess_id);
        printf("  \"isolated_session_keyring\": %s,\n", isolated_session ? "true" : "false");
        printf("  \"session_perm_hex\": ");
        tempest_fprint_json_str(stdout, has_sess_desc ? sess_desc.perm_hex.c_str() : "");
        printf(",\n");
        printf("  \"proc_keys_readable\": %s,\n", proc_keys_readable ? "true" : "false");
        printf("  \"keyring_entries_count\": %zu,\n", proc_entries.size());

        printf("  \"kcm_socket\": {\n");
        printf("    \"checked\": %s,\n", kcm_info.checked ? "true" : "false");
        printf("    \"path\": "); tempest_fprint_json_str(stdout, kcm_socket.c_str()); printf(",\n");
        printf("    \"exists\": %s,\n", kcm_info.exists ? "true" : "false");
        printf("    \"is_socket\": %s,\n", kcm_info.is_socket ? "true" : "false");
        printf("    \"mode_octal\": \"%03o\",\n", kcm_info.mode);
        printf("    \"connected\": %s,\n", kcm_info.connected ? "true" : "false");
        printf("    \"peer_pid\": %d,\n", (int)kcm_info.pid);
        printf("    \"peer_uid\": %d,\n", (int)kcm_info.uid);
        printf("    \"peer_gid\": %d,\n", (int)kcm_info.gid);
        printf("    \"peer_exe\": "); tempest_fprint_json_str(stdout, kcm_info.exe_path.c_str()); printf(",\n");
        printf("    \"error\": "); tempest_fprint_json_str(stdout, kcm_info.error.c_str()); printf("\n");
        printf("  },\n");

        printf("  \"inotify\": {\n");
        printf("    \"watched\": %s,\n", (!watch_file.empty() && watch_ok) ? "true" : "false");
        printf("    \"path\": "); tempest_fprint_json_str(stdout, watch_file.c_str()); printf(",\n");
        printf("    \"error\": "); tempest_fprint_json_str(stdout, watch_err.c_str()); printf(",\n");
        printf("    \"events\": [");
        for (size_t i = 0; i < inotify_events.size(); ++i) {
            if (i > 0) printf(", ");
            tempest_fprint_json_str(stdout, inotify_events[i].events.c_str());
        }
        printf("]\n");
        printf("  },\n");

        printf("  \"policy_violations\": [");
        for (size_t i = 0; i < violations.size(); ++i) {
            if (i > 0) printf(", ");
            tempest_fprint_json_str(stdout, violations[i].c_str());
        }
        printf("]\n");
        printf("}\n");
    } else {
        printf("[SOUEI v%s] Shadow Telemetry & KCM Sensor (%s)\n", TEMPEST_VERSION, status_str);
        printf("  UID              : %u\n", (unsigned int)uid);
        printf("  Session Keyring  : %ld (isolated=%s, perm=%s)\n",
               sess_id, isolated_session ? "yes" : "no", has_sess_desc ? sess_desc.perm_hex.c_str() : "n/a");
        printf("  /proc/keys Audit : %zu matching entries\n", proc_entries.size());
        if (kcm_info.checked) {
            printf("  KCM Socket       : %s (exists=%s, connected=%s, peer_pid=%d, peer_uid=%d)\n",
                   kcm_socket.c_str(), kcm_info.exists ? "yes" : "no",
                   kcm_info.connected ? "yes" : "no", (int)kcm_info.pid, (int)kcm_info.uid);
        }
        if (!watch_file.empty()) {
            printf("  Inotify Watch    : %s (%zu events)\n", watch_file.c_str(), inotify_events.size());
        }
        for (const auto &v : violations) {
            printf("  [POLICY_STOP]    : %s\n", v.c_str());
        }
    }

    return exit_code;
}
