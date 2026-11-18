#!/usr/bin/env python3
import json
import os
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


def run_cmd(cmd, env=None, timeout=10):
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
    )


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
        finally:
            stop_evt.set()
            srv.close()
            t.join(timeout=2)

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

        # Missing CCACHE -> exit 3
        r_miss = run_cmd([CHRONOA, "--ccache", os.path.join(td, "missing_cc"), "--json"])
        assert r_miss.returncode == 3 and json.loads(r_miss.stdout)["status"] == "MISSING"

        # Corrupt CCACHE -> exit 4
        cc_bad = os.path.join(td, "cc_corrupt")
        with open(cc_bad, "wb") as f:
            f.write(b"\xde\xad\xbe\xef" * 4)
        r_bad = run_cmd([CHRONOA, "--ccache", cc_bad, "--json"])
        assert r_bad.returncode == 4 and json.loads(r_bad.stdout)["status"] == "PARSE_ERROR"

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

    print("[PASS] ranga LD_PRELOAD libranga.so isolation (0x3f000000), --isolate, 3-pass NIST purge")


if __name__ == "__main__":
    test_build_artifacts_and_usage()
    test_souei_probe_kcm_and_inotify()
    test_chronoa_ccache_and_skew()
    test_ranga_isolation_and_purge()
    print("\nALL TEMPEST VERIFICATION CHECKS PASSED")
