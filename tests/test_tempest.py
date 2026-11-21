#!/usr/bin/env python3
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SOUEI = str(BIN / "souei")
CHRONOA = str(BIN / "chronoa")
RANGA = str(BIN / "ranga")
LIBRANGA = str(BIN / "libranga.so")


def run_cmd(cmd, env=None, timeout=10, cwd=None):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
        timeout=timeout,
        cwd=cwd,
    )


def compile_interposer(td, name, c_source):
    gcc = shutil.which("gcc")
    if not gcc:
        return None
    src_path = os.path.join(td, f"{name}.c")
    so_path = os.path.join(td, f"{name}.so")
    with open(src_path, "w", encoding="utf-8") as f:
        f.write(c_source)
    res = subprocess.run(
        [gcc, "-shared", "-fPIC", "-O2", "-o", so_path, src_path, "-ldl"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    assert res.returncode == 0, f"Failed to compile test interposer {name}: {res.stderr}"
    return so_path


def pack_principal(components, realm, name_type=1):
    r_bytes = realm.encode("ascii")
    out = bytearray()
    out += struct.pack(">III", name_type, len(components), len(r_bytes))
    out += r_bytes
    for comp in components:
        cb = comp.encode("ascii")
        out += struct.pack(">I", len(cb)) + cb
    return bytes(out)


def build_ccache_v4(
    principal_comps,
    realm,
    server_comps,
    enctype,
    authtime,
    starttime,
    endtime,
    renew_till,
):
    data = bytearray()
    # Format 0x0504 (CCACHE v4) + header_len = 0
    data += struct.pack(">HH", 0x0504, 0)
    client_p = pack_principal(principal_comps, realm, name_type=1)
    server_p = pack_principal(server_comps, realm, name_type=2)
    data += client_p  # default principal

    # 1st credential entry
    data += client_p
    data += server_p
    dummy_key = b"\xaa" * 16
    data += struct.pack(">HI", enctype, len(dummy_key)) + dummy_key
    data += struct.pack(">IIII", authtime, starttime, endtime, renew_till)
    data += struct.pack(">BI", 0, 0x40E10000)  # is_skey=0, tktflags
    data += struct.pack(">II", 0, 0)  # addr_count=0, authdata_count=0
    dummy_tkt = b"\x55" * 32
    data += struct.pack(">II", len(dummy_tkt), 0)  # ticket len, second_ticket len=0
    data[len(data) - 4 : len(data) - 4] = dummy_tkt
    return bytes(data)


def test_build_artifacts_and_usage():
    for path in (SOUEI, CHRONOA, RANGA, LIBRANGA):
        assert os.path.exists(path), f"Missing built artifact: {path}"
    for tool in (SOUEI, CHRONOA, RANGA):
        res = run_cmd([tool, "--version"])
        assert res.returncode == 0, f"{tool} --version failed: {res.stderr}"
        res_h = run_cmd([tool, "--help"])
        assert res_h.returncode == 0, f"{tool} --help failed: {res_h.stderr}"
        res_bad = run_cmd([tool, "--definitely-unknown-flag"])
        assert res_bad.returncode == 1, f"{tool} unknown flag expected 1, got {res_bad.returncode}"
    print("[PASS] build artifacts & CLI usage/version contract")


def test_souei_probe_kcm_and_inotify():
    res = run_cmd([SOUEI, "--probe", "--json"])
    assert res.returncode in (0, 2), f"souei --probe unexpected rc={res.returncode}: {res.stderr}"
    probe = json.loads(res.stdout)
    assert probe["agent"] == "souei"
    assert isinstance(probe["session_keyring_id"], int) and probe["session_keyring_id"] > 0

    with tempfile.TemporaryDirectory() as td:
        sock_path = os.path.join(td, "kcm.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        os.chmod(sock_path, 0o600)
        srv.listen(4)

        stop_evt = threading.Event()

        def accept_loop():
            srv.settimeout(0.2)
            while not stop_evt.is_set():
                try:
                    conn, _ = srv.accept()
                    time.sleep(0.05)
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()
        try:
            kcm_res = run_cmd([SOUEI, "--kcm-socket", sock_path, "--json"])
            assert kcm_res.returncode == 0, f"souei kcm 0600 rc={kcm_res.returncode}: {kcm_res.stdout}"
            kdata = json.loads(kcm_res.stdout)
            ks = kdata["kcm_socket"]
            assert ks["exists"] is True and ks["is_socket"] is True
            assert ks["connected"] is True
            assert ks["peer_pid"] == os.getpid(), f"Expected peer pid {os.getpid()}, got {ks['peer_pid']}"
            assert ks["peer_uid"] == os.getuid()
            assert "python" in ks["peer_exe"].lower(), f"Unexpected peer_exe: {ks['peer_exe']}"

            # Verify insecure world-readable socket policy violation (exit 2)
            os.chmod(sock_path, 0o666)
            bad_res = run_cmd([SOUEI, "--kcm-socket", sock_path, "--json"])
            assert bad_res.returncode == 2, f"Expected exit 2 for 0666 KCM socket, got {bad_res.returncode}"
            bad_data = json.loads(bad_res.stdout)
            assert len(bad_data["policy_violations"]) >= 1

            # Verify insecure group-accessible socket policy violation (0660 -> exit 2)
            os.chmod(sock_path, 0o660)
            grp_res = run_cmd([SOUEI, "--kcm-socket", sock_path, "--json"])
            assert grp_res.returncode == 2, f"Expected exit 2 for 0660 KCM socket, got {grp_res.returncode}"
            grp_data = json.loads(grp_res.stdout)
            assert len(grp_data["policy_violations"]) >= 1

            # Verify symlink KCM socket is rejected via lstat before connect (exit 2)
            os.chmod(sock_path, 0o600)
            sym_sock = os.path.join(td, "kcm_sym.sock")
            os.symlink(sock_path, sym_sock)
            sym_res = run_cmd([SOUEI, "--kcm-socket", sym_sock, "--json"])
            assert sym_res.returncode == 2, f"Expected exit 2 for symlink KCM socket, got {sym_res.returncode}"
            sym_data = json.loads(sym_res.stdout)
            assert sym_data["kcm_socket"]["exists"] is True
            assert sym_data["kcm_socket"]["is_socket"] is False
            assert sym_data["kcm_socket"]["connected"] is False
            assert len(sym_data["policy_violations"]) >= 1
            assert "symbolic link" in " ".join(sym_data["policy_violations"]).lower(), sym_data

            # Verify getsockopt(SO_PEERCRED) failure is reported distinctly from UID mismatch
            peercred_so = compile_interposer(
                td,
                "fail_peercred",
                """
                #define _GNU_SOURCE
                #include <dlfcn.h>
                #include <errno.h>
                #include <stddef.h>
                #include <sys/socket.h>
                int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
                    static int (*real_getsockopt)(int, int, int, void *, socklen_t *) = NULL;
                    if (!real_getsockopt) {
                        real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
                    }
                    if (level == SOL_SOCKET && optname == SO_PEERCRED) {
                        errno = EPERM;
                        return -1;
                    }
                    return real_getsockopt(sockfd, level, optname, optval, optlen);
                }
                """,
            )
            if peercred_so:
                pc_res = run_cmd(
                    [SOUEI, "--kcm-socket", sock_path, "--json"],
                    env={"LD_PRELOAD": peercred_so},
                )
                assert pc_res.returncode == 2, f"Expected exit 2 on SO_PEERCRED failure, got {pc_res.returncode}"
                pc_data = json.loads(pc_res.stdout)
                assert pc_data["kcm_socket"]["connected"] is True
                joined_v = " ".join(pc_data["policy_violations"])
                assert "mismatch" not in joined_v.lower(), pc_data
                assert "SO_PEERCRED" in (joined_v + " " + pc_data["kcm_socket"]["error"]), pc_data
        finally:
            stop_evt.set()
            srv.close()
            t.join(timeout=2)

        # Verify stale/unlistening 0600 socket (ECONNREFUSED -> non-zero exit 3, not silent 0 OK)
        stale_sock = os.path.join(td, "stale.sock")
        stale_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale_srv.bind(stale_sock)
        os.chmod(stale_sock, 0o600)
        stale_srv.close()
        refused_res = run_cmd([SOUEI, "--kcm-socket", stale_sock, "--json"])
        assert refused_res.returncode == 3, f"Expected exit 3 for ECONNREFUSED socket, got {refused_res.returncode}: {refused_res.stdout}"
        refused_data = json.loads(refused_res.stdout)
        assert refused_data["kcm_socket"]["exists"] is True
        assert refused_data["kcm_socket"]["is_socket"] is True
        assert refused_data["kcm_socket"]["connected"] is False
        assert refused_data["kcm_socket"]["error"] != ""

        # Verify non-socket existing path -> exit 2 POLICY_STOP
        non_sock = os.path.join(td, "not_a_socket.txt")
        with open(non_sock, "wb") as f:
            f.write(b"regular-file")
        os.chmod(non_sock, 0o600)
        ns_res = run_cmd([SOUEI, "--kcm-socket", non_sock, "--json"])
        assert ns_res.returncode == 2, f"Expected exit 2 for non-socket path, got {ns_res.returncode}: {ns_res.stdout}"
        ns_data = json.loads(ns_res.stdout)
        assert ns_data["kcm_socket"]["exists"] is True
        assert ns_data["kcm_socket"]["is_socket"] is False
        assert len(ns_data["policy_violations"]) >= 1

        miss_res = run_cmd([SOUEI, "--kcm-socket", os.path.join(td, "missing.sock"), "--json"])
        assert miss_res.returncode == 3, f"Expected exit 3 for missing socket, got {miss_res.returncode}"

        # Real Linux inotify open/access watch
        target_file = os.path.join(td, "krb5cc_watch")
        with open(target_file, "wb") as f:
            f.write(b"watchme")

        proc = subprocess.Popen(
            [SOUEI, "--watch-file", target_file, "--timeout-ms", "1200", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.15)
        with open(target_file, "rb") as f:
            _ = f.read()
        stdout_w, stderr_w = proc.communicate(timeout=5)
        assert proc.returncode == 0, f"souei watch rc={proc.returncode}: {stderr_w}"
        wdata = json.loads(stdout_w)
        assert wdata["inotify"]["watched"] is True
        events_joined = ",".join(wdata["inotify"]["events"])
        assert "OPEN" in events_joined or "ACCESS" in events_joined, f"Missing inotify events: {wdata}"

    print("[PASS] souei /proc/keys probe, AF_UNIX SO_PEERCRED, mode 0666 policy stop, inotify watch")


def test_chronoa_ccache_and_skew():
    now = 1700000000
    with tempfile.TemporaryDirectory() as td:
        cc_ok = os.path.join(td, "cc_healthy")
        with open(cc_ok, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    18, now - 60, now - 60, now + 3600, now + 86400
                )
            )
        r_ok = run_cmd([CHRONOA, "--ccache", cc_ok, "--now", str(now), "--kdc-time", str(now + 12), "--json"])
        assert r_ok.returncode == 0, f"healthy expected 0, got {r_ok.returncode}: {r_ok.stdout}"
        d_ok = json.loads(r_ok.stdout)
        assert d_ok["status"] == "HEALTHY"
        assert d_ok["ttl_sec"] == 3600
        assert d_ok["skew_sec"] == 12
        assert d_ok["primary_ticket"]["enctype"] == 18

        r_pref = run_cmd([CHRONOA, "--ccache", "FILE:" + cc_ok, "--now", str(now), "--json"])
        assert r_pref.returncode == 0 and json.loads(r_pref.stdout)["status"] == "HEALTHY", r_pref.stdout

        # RFC 4120 boundary: 300s is allowed, 301s triggers policy stop (exit 2)
        r_300 = run_cmd([CHRONOA, "--ccache", cc_ok, "--now", str(now), "--kdc-time", str(now + 300), "--json"])
        assert r_300.returncode == 0
        r_301 = run_cmd([CHRONOA, "--ccache", cc_ok, "--now", str(now), "--kdc-time", str(now + 301), "--json"])
        assert r_301.returncode == 2
        d_301 = json.loads(r_301.stdout)
        assert d_301["status"] == "CLOCK_SKEW_VIOLATION"
        assert d_301["skew_violation"] is True and d_301["skew_sec"] == 301

        # Expiring within warn window triggers --renew-cmd and re-evaluates fresh ticket
        cc_renew = os.path.join(td, "cc_renew")
        with open(cc_renew, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    18, now - 3500, now - 3500, now + 120, now + 86400
                )
            )
        renewer_py = os.path.join(td, "mock_renew.py")
        with open(renewer_py, "w", encoding="utf-8") as f:
            f.write(
                "import pathlib\n"
                f"pathlib.Path({cc_renew!r}).write_bytes(pathlib.Path({cc_ok!r}).read_bytes())\n"
            )
        r_ren = run_cmd([
            CHRONOA, "--ccache", cc_renew, "--now", str(now),
            "--warn-window-sec", "300", "--renew-cmd", f"python3 {renewer_py}", "--once", "--json"
        ])
        assert r_ren.returncode == 0, f"renew expected 0, got {r_ren.returncode}: {r_ren.stdout}"
        d_ren = json.loads(r_ren.stdout)
        assert d_ren["renew_attempted"] is True and d_ren["renew_exit_code"] == 0
        assert d_ren["renewed"] is True and d_ren["status"] == "RENEWED" and d_ren["ttl_sec"] == 3600

        # Non-shell --renew-cmd preserves AD '$' principals and rejects shell injection
        with open(cc_renew, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    18, now - 3500, now - 3500, now + 120, now + 86400
                )
            )
        ad_arg_py = os.path.join(td, "check_ad_arg.py")
        with open(ad_arg_py, "w", encoding="utf-8") as f:
            f.write(
                "import pathlib, sys\n"
                "assert sys.argv[1] == 'naga$@TANUKI.LOCAL', sys.argv\n"
                f"pathlib.Path({cc_renew!r}).write_bytes(pathlib.Path({cc_ok!r}).read_bytes())\n"
            )
        r_ad = run_cmd([
            CHRONOA, "--ccache", cc_renew, "--now", str(now),
            "--warn-window-sec", "300", "--renew-cmd", f"python3 {ad_arg_py} naga$@TANUKI.LOCAL",
            "--once", "--json",
        ])
        assert r_ad.returncode == 0, f"AD $ principal renew failed: {r_ad.stdout} {r_ad.stderr}"
        assert json.loads(r_ad.stdout)["status"] == "RENEWED"

        pwn = os.path.join(td, "pwned")
        for bad_cmd in (
            f"python3 {renewer_py}; touch {pwn}",
            f"python3 {renewer_py} && touch {pwn}",
            f"$(touch {pwn})",
            "kinit -R | id",
        ):
            r_inj = run_cmd([
                CHRONOA, "--ccache", cc_renew, "--now", str(now),
                "--warn-window-sec", "300", "--renew-cmd", bad_cmd, "--once", "--json",
            ])
            assert r_inj.returncode == 1, f"Expected USAGE (1) for {bad_cmd!r}, got {r_inj.returncode}"
            assert not os.path.exists(pwn), f"Shell injection executed for {bad_cmd!r}"

        r_nobin = run_cmd([
            CHRONOA, "--ccache", cc_exp if False else cc_ok, "--now", str(now),
            "--warn-window-sec", "7200", "--renew-cmd", "/nonexistent/bin/renew_noop",
            "--once", "--json",
        ])
        assert r_nobin.returncode == 2, f"Expected POLICY_STOP (2) for missing renew binary, got {r_nobin.returncode}"
        d_nobin = json.loads(r_nobin.stdout)
        assert d_nobin["status"] == "RENEW_FAILED"
        assert d_nobin["renew_attempted"] is True and d_nobin["renew_exit_code"] != 0

        # Empty FILE: prefix must not open literal "./FILE:" and must return USAGE (1) or MISSING (3)
        literal_file_scheme = os.path.join(td, "FILE:")
        with open(literal_file_scheme, "wb") as f:
            f.write(b"dummy")
        r_empty_file = run_cmd([CHRONOA, "--ccache", "FILE:", "--json"], cwd=td)
        assert r_empty_file.returncode == 1, f"Expected USAGE (1) for --ccache FILE:, got {r_empty_file.returncode}"

        r_env_empty_file = run_cmd([CHRONOA, "--json"], env={"KRB5CCNAME": "FILE:"}, cwd=td)
        assert r_env_empty_file.returncode == 3, f"Expected MISSING (3) for KRB5CCNAME=FILE:, got {r_env_empty_file.returncode}"
        assert json.loads(r_env_empty_file.stdout)["error"] != ""

        r_kcm_scheme = run_cmd([CHRONOA, "--ccache", "KCM:1000", "--json"], cwd=td)
        assert r_kcm_scheme.returncode == 3, f"Expected MISSING (3) for KCM: scheme, got {r_kcm_scheme.returncode}"
        assert "Unsupported non-FILE" in json.loads(r_kcm_scheme.stdout)["error"]

        # Watch interval >= 2^32 must clamp cleanly and never wrap sleep() to 0
        watch_proc = subprocess.Popen(
            [CHRONOA, "--ccache", cc_ok, "--now", str(now), "--watch", "--interval-sec", "4294967296", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.4)
        watch_proc.send_signal(signal.SIGINT)
        w_out, w_err = watch_proc.communicate(timeout=3)
        w_lines = [ln for ln in w_out.splitlines() if ln.strip()]
        assert len(w_lines) == 1, f"Expected 1 watch line (no sleep(0) spin), got {len(w_lines)}: {w_err}"
        assert json.loads(w_lines[0])["status"] == "HEALTHY"

        # Expired ticket -> exit 2
        cc_exp = os.path.join(td, "cc_expired")
        with open(cc_exp, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    18, now - 7200, now - 7200, now - 10, now + 3600
                )
            )
        r_exp = run_cmd([CHRONOA, "--ccache", cc_exp, "--now", str(now), "--json"])
        assert r_exp.returncode == 2 and json.loads(r_exp.stdout)["status"] == "EXPIRED"

        # Weak enctype (RC4 = 23) -> exit 2
        cc_rc4 = os.path.join(td, "cc_rc4")
        with open(cc_rc4, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    23, now - 60, now - 60, now + 3600, now + 86400
                )
            )
        r_rc4 = run_cmd([CHRONOA, "--ccache", cc_rc4, "--now", str(now), "--json"])
        assert r_rc4.returncode == 2
        d_rc4 = json.loads(r_rc4.stdout)
        assert d_rc4["status"] == "WEAK_ENCTYPE" and d_rc4["weak_enctype"] is True

        # Weak enctype (des-cbc-md4 = 2) -> exit 2
        cc_des_md4 = os.path.join(td, "cc_des_md4")
        with open(cc_des_md4, "wb") as f:
            f.write(
                build_ccache_v4(
                    ["ely"], "TANUKI.LOCAL", ["krbtgt", "TANUKI.LOCAL"],
                    2, now - 60, now - 60, now + 3600, now + 86400
                )
            )
        r_des_md4 = run_cmd([CHRONOA, "--ccache", cc_des_md4, "--now", str(now), "--json"])
        assert r_des_md4.returncode == 2, f"des-cbc-md4 expected 2, got {r_des_md4.returncode}: {r_des_md4.stdout}"
        d_des_md4 = json.loads(r_des_md4.stdout)
        assert d_des_md4["status"] == "WEAK_ENCTYPE" and d_des_md4["weak_enctype"] is True
        assert d_des_md4["primary_ticket"]["enctype_name"] == "des-cbc-md4", d_des_md4

        # Missing CCACHE -> exit 3
        r_miss = run_cmd([CHRONOA, "--ccache", os.path.join(td, "missing_cc"), "--json"])
        assert r_miss.returncode == 3 and json.loads(r_miss.stdout)["status"] == "MISSING"

        # Corrupt CCACHE -> exit 4
        cc_bad = os.path.join(td, "cc_corrupt")
        with open(cc_bad, "wb") as f:
            f.write(b"\xde\xad\xbe\xef" * 4)
        r_bad = run_cmd([CHRONOA, "--ccache", cc_bad, "--json"])
        assert r_bad.returncode == 4 and json.loads(r_bad.stdout)["status"] == "PARSE_ERROR"

        # Permission-denied CCACHE -> exit 2 POLICY_STOP (when unprivileged)
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            cc_perm = os.path.join(td, "cc_noperm")
            with open(cc_perm, "wb") as f:
                f.write(b"locked")
            os.chmod(cc_perm, 0o000)
            try:
                r_perm = run_cmd([CHRONOA, "--ccache", cc_perm, "--json"])
                assert r_perm.returncode == 2 and json.loads(r_perm.stdout)["status"] == "POLICY_STOP", r_perm.stdout
            finally:
                os.chmod(cc_perm, 0o600)

    print("[PASS] chronoa healthy, RFC 4120 300s skew, --renew-cmd, expired, RC4, missing, corrupt")


def test_ranga_isolation_and_purge():
    r_base = run_cmd([RANGA, "--status", "--json"])
    assert r_base.returncode == 0, f"ranga baseline --status failed: {r_base.stderr}"
    d_base = json.loads(r_base.stdout)
    parent_kid = d_base["session_keyring_id"]
    assert parent_kid > 0

    # LD_PRELOAD=bin/libranga.so constructor creates isolated possessor-only session keyring
    r_pre = run_cmd([RANGA, "--status", "--json"], env={"LD_PRELOAD": LIBRANGA, "RANGA_REVOKE_ON_EXIT": "1"})
    assert r_pre.returncode == 0, f"LD_PRELOAD ranga failed: {r_pre.stderr}"
    d_pre = json.loads(r_pre.stdout)
    assert d_pre["session_keyring_id"] != parent_kid, (
        f"Expected LD_PRELOAD session keyring != parent {parent_kid}, got {d_pre}"
    )
    assert d_pre["possessor_only"] is True and d_pre["perm_hex"] == "3f000000", d_pre

    # Wrapper --isolate isolates child keyring via syscall before execvp
    r_iso = run_cmd([RANGA, "--isolate", "--", RANGA, "--status", "--json"])
    assert r_iso.returncode == 0, f"ranga --isolate failed: {r_iso.stderr}"
    d_iso = json.loads(r_iso.stdout)
    assert d_iso["session_keyring_id"] != parent_kid
    assert d_iso["possessor_only"] is True and d_iso["perm_hex"] == "3f000000", d_iso

    with tempfile.TemporaryDirectory() as td:
        secret = os.path.join(td, "secret_ccache.bin")
        payload = b"KERBEROS_SECRET_KEY_MATERIAL" * 300
        with open(secret, "wb") as f:
            f.write(payload)

        r_purge = run_cmd([RANGA, "--purge", secret, "--json"])
        assert r_purge.returncode == 0, f"ranga --purge failed: {r_purge.stderr}"
        d_purge = json.loads(r_purge.stdout)
        assert d_purge["removed"] is True
        assert d_purge["passes"] == 3
        assert d_purge["wiped_bytes"] == len(payload)
        assert not os.path.exists(secret)

        # Refuse to purge symlink (policy stop = 2)
        target = os.path.join(td, "real_target.txt")
        link = os.path.join(td, "sym_target.txt")
        with open(target, "wb") as f:
            f.write(b"keep-me")
        os.symlink(target, link)
        r_sym = run_cmd([RANGA, "--purge", link, "--json"])
        assert r_sym.returncode == 2, f"Expected exit 2 for symlink purge, got {r_sym.returncode}"
        assert os.path.exists(target)

        # Missing target -> exit 3
        r_miss = run_cmd([RANGA, "--purge", os.path.join(td, "nope"), "--json"])
        assert r_miss.returncode == 3

        # --revoke-session positive check MUST run inside ranga --isolate so host keyring is untouched
        secret_iso = os.path.join(td, "secret_iso.bin")
        with open(secret_iso, "wb") as f:
            f.write(b"ISOLATED_SESSION_PURGE_MATERIAL" * 10)
        r_iso_rev = run_cmd([
            RANGA, "--isolate", "--", RANGA, "--purge", secret_iso, "--revoke-session", "--json"
        ])
        assert r_iso_rev.returncode == 0, f"Isolated --revoke-session failed: {r_iso_rev.stdout} {r_iso_rev.stderr}"
        d_iso_rev = json.loads(r_iso_rev.stdout)
        assert d_iso_rev["removed"] is True and d_iso_rev["session_revoked"] is True
        assert not os.path.exists(secret_iso)

        # Fail-closed CSPRNG: getrandom() + /dev/urandom failure must fail closed with exit 2 and not unlink
        csprng_so = compile_interposer(
            td,
            "fail_csprng",
            """
            #define _GNU_SOURCE
            #include <dlfcn.h>
            #include <errno.h>
            #include <fcntl.h>
            #include <stdarg.h>
            #include <string.h>
            #include <sys/types.h>
            ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
                (void)buf; (void)buflen; (void)flags;
                errno = ENOSYS;
                return -1;
            }
            int open(const char *pathname, int flags, ...) {
                static int (*real_open)(const char *, int, ...) = NULL;
                if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
                if (pathname && strcmp(pathname, "/dev/urandom") == 0) {
                    errno = EACCES;
                    return -1;
                }
                if (flags & O_CREAT) {
                    va_list ap;
                    va_start(ap, flags);
                    mode_t mode = (mode_t)va_arg(ap, int);
                    va_end(ap);
                    return real_open(pathname, flags, mode);
                }
                return real_open(pathname, flags);
            }
            """,
        )
        if csprng_so:
            secret_csprng = os.path.join(td, "secret_csprng.bin")
            with open(secret_csprng, "wb") as f:
                f.write(b"CSPRNG_FAIL_CLOSED" * 32)
            r_csprng = run_cmd(
                [RANGA, "--purge", secret_csprng, "--json"],
                env={"LD_PRELOAD": csprng_so},
            )
            assert r_csprng.returncode == 2, f"Expected exit 2 on CSPRNG failure, got {r_csprng.returncode}"
            d_csprng = json.loads(r_csprng.stdout)
            assert d_csprng["removed"] is False and d_csprng["passes"] < 3
            assert os.path.exists(secret_csprng)

        # lstat + fstat st_ino mismatch must fail closed (exit 2) without overwriting/unlinking
        fstat_so = compile_interposer(
            td,
            "mismatch_fstat",
            """
            #define _GNU_SOURCE
            #include <dlfcn.h>
            #include <stddef.h>
            #include <sys/stat.h>
            int fstat(int fd, struct stat *statbuf) {
                static int (*real_fstat)(int, struct stat *) = NULL;
                if (!real_fstat) real_fstat = dlsym(RTLD_NEXT, "fstat");
                int rc = real_fstat(fd, statbuf);
                if (rc == 0 && fd > 2 && S_ISREG(statbuf->st_mode)) {
                    statbuf->st_ino ^= 0x1234ULL;
                }
                return rc;
            }
            """,
        )
        if fstat_so:
            secret_ino = os.path.join(td, "secret_ino.bin")
            orig_bytes = b"DO_NOT_WIPE_INODE_MISMATCH" * 8
            with open(secret_ino, "wb") as f:
                f.write(orig_bytes)
            r_ino = run_cmd(
                [RANGA, "--purge", secret_ino, "--json"],
                env={"LD_PRELOAD": fstat_so},
            )
            assert r_ino.returncode == 2, f"Expected exit 2 on fstat mismatch, got {r_ino.returncode}"
            d_ino = json.loads(r_ino.stdout)
            assert d_ino["removed"] is False and d_ino["passes"] == 0
            assert "identity" in d_ino["error"].lower(), d_ino
            with open(secret_ino, "rb") as f:
                assert f.read() == orig_bytes

        # KEYCTL_REVOKE failure must keep session_revoked=false and exit 2 even if KEYCTL_CLEAR succeeds
        revoke_so = compile_interposer(
            td,
            "fail_revoke",
            """
            #define _GNU_SOURCE
            #include <dlfcn.h>
            #include <errno.h>
            #include <linux/keyctl.h>
            #include <stdarg.h>
            #include <stddef.h>
            #include <sys/syscall.h>
            long syscall(long number, ...) {
                static long (*real_syscall)(long, ...) = NULL;
                if (!real_syscall) real_syscall = dlsym(RTLD_NEXT, "syscall");
                va_list ap;
                va_start(ap, number);
                unsigned long a1 = va_arg(ap, unsigned long);
                unsigned long a2 = va_arg(ap, unsigned long);
                unsigned long a3 = va_arg(ap, unsigned long);
                unsigned long a4 = va_arg(ap, unsigned long);
                unsigned long a5 = va_arg(ap, unsigned long);
                unsigned long a6 = va_arg(ap, unsigned long);
                va_end(ap);
                if (number == SYS_keyctl && (int)a1 == KEYCTL_REVOKE) {
                    errno = EPERM;
                    return -1;
                }
                return real_syscall(number, a1, a2, a3, a4, a5, a6);
            }
            """,
        )
        if revoke_so:
            secret_revfail = os.path.join(td, "secret_revfail.bin")
            with open(secret_revfail, "wb") as f:
                f.write(b"REVOKE_FAIL_MATERIAL" * 8)
            r_revfail = run_cmd([
                RANGA, "--isolate", "--", "env", f"LD_PRELOAD={revoke_so}",
                RANGA, "--purge", secret_revfail, "--revoke-session", "--json",
            ])
            assert r_revfail.returncode == 2, f"Expected exit 2 on KEYCTL_REVOKE failure, got {r_revfail.returncode}"
            d_revfail = json.loads(r_revfail.stdout)
            assert d_revfail["session_revoked"] is False
            assert "KEYCTL_REVOKE" in d_revfail["error"], d_revfail

    print("[PASS] ranga LD_PRELOAD libranga.so isolation (0x3f000000), --isolate, 3-pass NIST purge")


if __name__ == "__main__":
    test_build_artifacts_and_usage()
    test_souei_probe_kcm_and_inotify()
    test_chronoa_ccache_and_skew()
    test_ranga_isolation_and_purge()
    print("\nALL TEMPEST VERIFICATION CHECKS PASSED")
