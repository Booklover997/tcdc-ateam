#!/usr/bin/env python3
"""
outbound_guard.py — Monitor and individually block outbound connections
based on SOURCE PORT.

Checks the local source port of every outbound connection. If a process
sends traffic from a port not in the allowed list, it gets an individual
iptables DROP rule (--sport) and the connection is killed. Destination
IP/port don't matter.

NO default-deny-all rule. Each blocked source port gets its own specific
iptables rule.

Three interception modes (auto-selected, best available):
  1. nfqueue  — inspects each outbound packet before it leaves.
  2. conntrack — monitors conntrack events, adds rules reactively.
  3. polling  — scans /proc/net, adds rules reactively.

Tested on Ubuntu Server 24.04 LTS (iptables-nft backend, Python 3.12+).

Usage:
    sudo python3 outbound_guard.py --ports 80,443,53,22
    sudo python3 outbound_guard.py --ports 80,443 --log /var/log/guard.log
    sudo python3 outbound_guard.py --config ports.conf
    sudo python3 outbound_guard.py --check
    sudo python3 outbound_guard.py --teardown

Requires root (iptables).
"""

import argparse
import atexit
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

CHAIN_NAME = "OUTBOUND_GUARD"
NFQUEUE_NUM = 42


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def check_root():
    if os.geteuid() != 0:
        print("Error: must run as root (iptables requires it).", file=sys.stderr)
        sys.exit(1)


def run(cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def has_cmd(name):
    return shutil.which(name) is not None


def parse_ports(spec):
    """Parse comma-separated ports / ranges like 80,443,8000-8010."""
    ports = set()
    for token in spec.split(","):
        token = token.strip()
        if not token or token.startswith("#"):
            continue
        if "-" in token:
            lo, hi = token.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"invalid range: {token}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def load_config_file(path):
    tokens = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tokens.append(line)
    return parse_ports(",".join(tokens))


def conntrack_available():
    """Check if conntrack subsystem is functional (module loaded or built-in)."""
    # Check /proc/modules (loaded as module)
    try:
        with open("/proc/modules") as f:
            if "nf_conntrack" in f.read():
                return True
    except OSError:
        pass
    # Check /proc/net/nf_conntrack (built into kernel — common in containers)
    if Path("/proc/net/nf_conntrack").exists():
        return True
    # Check sysctl (another built-in indicator)
    if Path("/proc/sys/net/netfilter/nf_conntrack_max").exists():
        return True
    # Last resort: try to load the module
    modprobe = shutil.which("modprobe") or "/sbin/modprobe"
    try:
        r = run([modprobe, "nf_conntrack"], check=False)
        if r.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    return False


def ensure_conntrack_module():
    """Ensure conntrack subsystem is available."""
    if conntrack_available():
        return True
    print("[!] Warning: conntrack subsystem not available", file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# Process lookup — works with or without ss
# ---------------------------------------------------------------------------

def find_process(dst_ip, dst_port, proto):
    """Best-effort process lookup. Tries ss first, falls back to /proc/net."""
    if has_cmd("ss"):
        return _find_process_ss(dst_ip, dst_port, proto)
    return _find_process_proc(dst_ip, dst_port, proto)


def _find_process_ss(dst_ip, dst_port, proto):
    flag = "-tnp" if proto == "tcp" else "-unp"
    result = run(["ss", flag, "dst", f"{dst_ip}:{dst_port}"], check=False)
    if result.returncode == 0:
        for line in result.stdout.splitlines()[1:]:
            match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if match:
                return f"{match.group(1)}[{match.group(2)}]"
    return None


def _find_process_proc(dst_ip, dst_port, proto):
    """Parse /proc/net/tcp or /proc/net/udp to find the owning process."""
    try:
        proc_file = f"/proc/net/{proto}"
        dst_hex = _ip_to_hex(dst_ip)
        port_hex = f"{dst_port:04X}"

        with open(proc_file) as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if len(fields) < 10:
                    continue
                rem_addr = fields[2]
                rem_ip, rem_port = rem_addr.split(":")
                if rem_ip == dst_hex and rem_port == port_hex:
                    inode = fields[9]
                    return _inode_to_process(inode)
    except (OSError, ValueError):
        pass
    return None


def _ip_to_hex(ip_str):
    """Convert dotted IP to the hex format used in /proc/net/*."""
    packed = socket.inet_aton(ip_str)
    return f"{struct.unpack('<I', packed)[0]:08X}"


def _inode_to_process(inode):
    """Find the process owning a socket inode by scanning /proc/*/fd."""
    target = f"socket:[{inode}]"
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            for fd in fd_dir.iterdir():
                try:
                    if os.readlink(str(fd)) == target:
                        comm = (pid_dir / "comm").read_text().strip()
                        return f"{comm}[{pid_dir.name}]"
                except OSError:
                    continue
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Individual rule tracker
# ---------------------------------------------------------------------------

class RuleTracker:
    def __init__(self, log_file=None, log_allowed=False):
        self._lock = threading.Lock()
        self._blocked = set()
        self._stats = defaultdict(int)
        self._log_allowed = log_allowed
        self._log_fh = None
        if log_file:
            self._log_fh = open(log_file, "a", buffering=1)

    def already_blocked(self, proto, src_port):
        return (proto, src_port) in self._blocked

    def add_individual_rule(self, proto, src_port):
        """Add a DROP rule for a specific outbound source port."""
        key = (proto, src_port)
        with self._lock:
            if key in self._blocked:
                return
            run([
                "iptables", "-A", CHAIN_NAME,
                "-p", proto,
                "--sport", str(src_port),
                "-j", "DROP",
            ])
            self._blocked.add(key)
            self._stats[src_port] += 1

    def log(self, proto, src_ip, src_port, dst_ip, dst_port, action, proc=None):
        if action == "ALLOWED" and not self._log_allowed:
            return
        proc_str = f"  proc={proc}" if proc else ""
        msg = (f"[{action}] {ts()}  {proto.upper()} "
               f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}{proc_str}")
        print(msg)
        if self._log_fh:
            self._log_fh.write(msg + "\n")

    def print_summary(self):
        with self._lock:
            if not self._blocked:
                print("\n--- No connections were blocked ---")
                return
            print(f"\n--- Summary: {len(self._blocked)} individual source-port block rules ---")
            for proto, port in sorted(self._blocked):
                count = self._stats[port]
                print(f"  {proto.upper()} sport {port}: blocked ({count} connections seen)")

    def close(self):
        if self._log_fh:
            self._log_fh.close()


# ---------------------------------------------------------------------------
# iptables chain management — NO default deny
# ---------------------------------------------------------------------------

def setup_chain():
    teardown_chain()
    run(["iptables", "-N", CHAIN_NAME])


def setup_nfqueue(protocols):
    for proto in protocols:
        run([
            "iptables", "-I", "OUTPUT", "1",
            "-p", proto,
            "-j", "NFQUEUE", "--queue-num", str(NFQUEUE_NUM),
        ])


def setup_chain_jump(protocols):
    """Jump OUTPUT into our chain — no ctstate filter so persistent
    DROP --sport rules block ALL packets from that source port."""
    for proto in protocols:
        run([
            "iptables", "-I", "OUTPUT", "1",
            "-p", proto,
            "-j", CHAIN_NAME,
        ])


def teardown_chain():
    for proto in ("tcp", "udp"):
        # Remove NFQUEUE jumps
        while True:
            r = run(["iptables", "-D", "OUTPUT",
                      "-p", proto,
                      "-j", "NFQUEUE", "--queue-num", str(NFQUEUE_NUM)],
                     check=False)
            if r.returncode != 0:
                break
        # Remove chain jumps
        while True:
            r = run(["iptables", "-D", "OUTPUT",
                      "-p", proto,
                      "-j", CHAIN_NAME], check=False)
            if r.returncode != 0:
                break
    run(["iptables", "-F", CHAIN_NAME], check=False)
    run(["iptables", "-X", CHAIN_NAME], check=False)


def show_rules():
    r = run(["iptables", "-L", CHAIN_NAME, "-n", "--line-numbers"], check=False)
    if r.returncode == 0 and r.stdout.strip():
        print(f"\n--- {CHAIN_NAME} individual rules ---")
        print(r.stdout)


# ---------------------------------------------------------------------------
# Mode 1: NFQUEUE
# ---------------------------------------------------------------------------

def run_nfqueue_mode(allowed_ports, protocols, tracker):
    from netfilterqueue import NetfilterQueue

    allowed_set = set(allowed_ports)

    def packet_handler(pkt):
        try:
            payload = pkt.get_payload()
            ip_proto = payload[9]
            src_ip = ".".join(str(b) for b in payload[12:16])
            dst_ip = ".".join(str(b) for b in payload[16:20])
            ihl = (payload[0] & 0x0F) * 4

            # src_port = bytes 0-1, dst_port = bytes 2-3 of transport header
            if ip_proto in (6, 17):
                src_port = (payload[ihl] << 8) | payload[ihl + 1]
                dst_port = (payload[ihl + 2] << 8) | payload[ihl + 3]
                proto = "tcp" if ip_proto == 6 else "udp"
            else:
                pkt.accept()
                return

            if dst_ip == "127.0.0.1" or src_port in allowed_set:
                pkt.accept()
                return

            pkt.drop()
            proc = find_process(dst_ip, dst_port, proto)
            tracker.log(proto, src_ip, src_port, dst_ip, dst_port, "BLOCKED", proc)
            tracker.add_individual_rule(proto, src_port)

        except Exception as e:
            print(f"[!] Packet handler error: {e}", file=sys.stderr)
            pkt.accept()

    setup_chain()
    setup_chain_jump(protocols)
    setup_nfqueue(protocols)

    nfq = NetfilterQueue()
    nfq.bind(NFQUEUE_NUM, packet_handler)
    print("[+] NFQUEUE mode active — inspecting each connection individually")
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfq.unbind()


# ---------------------------------------------------------------------------
# Mode 2: conntrack monitor
# ---------------------------------------------------------------------------

def kill_connection(proto, src_port, dst_ip=None, dst_port=None):
    """Kill a connection by source port."""
    if has_cmd("conntrack"):
        run([
            "conntrack", "-D",
            "-p", proto, "--sport", str(src_port),
        ], check=False)
    if proto == "tcp" and has_cmd("ss") and dst_ip and dst_port:
        run(["ss", "-K", "sport", "=", str(src_port),
             "dst", dst_ip, "dport", "=", str(dst_port)],
            check=False)


def run_conntrack_mode(allowed_ports, protocols, tracker):
    allowed_set = set(allowed_ports)

    setup_chain()
    setup_chain_jump(protocols)

    cmd = ["conntrack", "-E", "-e", "NEW", "-o", "extended"]
    print("[+] Conntrack monitor mode — checking source port of each new connection")
    print("    (first packet may leave before the rule is added)")

    pattern = re.compile(
        r"src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)"
    )
    proto_pattern = re.compile(r"proto=(\d+)")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        for line in proc.stdout:
            if "127.0.0.1" in line:
                continue

            pm = proto_pattern.search(line)
            if not pm:
                continue
            ip_proto = int(pm.group(1))
            if ip_proto == 6:
                proto = "tcp"
            elif ip_proto == 17:
                proto = "udp"
            else:
                continue

            if proto not in protocols:
                continue

            m = pattern.search(line)
            if not m:
                continue

            src_ip, dst_ip = m.group(1), m.group(2)
            src_port = int(m.group(3))
            dst_port = int(m.group(4))

            if src_port in allowed_set:
                tracker.log(proto, src_ip, src_port, dst_ip, dst_port, "ALLOWED")
                continue

            if tracker.already_blocked(proto, src_port):
                continue

            proc_name = find_process(dst_ip, dst_port, proto)
            tracker.log(proto, src_ip, src_port, dst_ip, dst_port, "BLOCKED", proc_name)
            tracker.add_individual_rule(proto, src_port)
            kill_connection(proto, src_port, dst_ip, dst_port)

    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


# ---------------------------------------------------------------------------
# Mode 3: polling via /proc/net (no ss or conntrack needed)
# ---------------------------------------------------------------------------

def _parse_proc_net(proto):
    """Parse /proc/net/tcp or /proc/net/udp.
    Returns (src_ip, src_port, dst_ip, dst_port, inode) for each active connection."""
    conns = []
    proc_path = f"/proc/net/{proto}"
    try:
        with open(proc_path) as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if len(fields) < 10:
                    continue
                local = fields[1]
                remote = fields[2]
                state = fields[3]

                # TCP: SYN_SENT(02), ESTABLISHED(01)
                if proto == "tcp" and state not in ("01", "02"):
                    continue

                rem_ip_hex, rem_port_hex = remote.split(":")
                loc_ip_hex, loc_port_hex = local.split(":")

                src_port = int(loc_port_hex, 16)
                dst_port = int(rem_port_hex, 16)
                if dst_port == 0:
                    continue

                dst_ip_int = int(rem_ip_hex, 16)
                dst_ip = socket.inet_ntoa(struct.pack("<I", dst_ip_int))

                src_ip_int = int(loc_ip_hex, 16)
                src_ip = socket.inet_ntoa(struct.pack("<I", src_ip_int))

                inode = fields[9]
                conns.append((src_ip, src_port, dst_ip, dst_port, inode))
    except OSError:
        pass
    return conns


def run_polling_mode(allowed_ports, protocols, tracker, interval=0.5):
    allowed_set = set(allowed_ports)

    setup_chain()
    setup_chain_jump(protocols)

    print(f"[+] Polling mode (/proc/net) — scanning source ports every {interval}s")
    print("    (first packet may leave before the rule is added)")

    seen = set()

    while True:
        for proto in protocols:
            for src_ip, src_port, dst_ip, dst_port, inode in _parse_proc_net(proto):
                if dst_ip in ("127.0.0.1", "0.0.0.0"):
                    continue

                conn_key = (proto, src_ip, src_port, dst_ip, dst_port)
                if conn_key in seen:
                    continue
                seen.add(conn_key)

                if src_port in allowed_set:
                    tracker.log(proto, src_ip, src_port, dst_ip, dst_port, "ALLOWED")
                    continue

                if tracker.already_blocked(proto, src_port):
                    continue

                proc_name = _inode_to_process(inode)
                tracker.log(proto, src_ip, src_port, dst_ip, dst_port, "BLOCKED", proc_name)
                tracker.add_individual_rule(proto, src_port)
                kill_connection(proto, src_port, dst_ip, dst_port)

        time.sleep(interval)


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

def check_dependencies(requested_mode):
    """Check and report what's available, what's missing."""
    print("=== Dependency Check (Ubuntu Server 24.04) ===\n")

    # iptables
    ok = has_cmd("iptables")
    ver = run(["iptables", "--version"], check=False).stdout.strip() if ok else ""
    backend = "(nf_tables)" if "nf_tables" in ver else "(legacy)"
    _dep_line("iptables", ok, ver, "sudo apt install iptables")
    if ok and "nf_tables" in ver:
        print(f"         backend: nf_tables — compatible\n")

    # conntrack CLI
    ok_ct = has_cmd("conntrack")
    _dep_line("conntrack", ok_ct, "", "sudo apt install conntrack")

    # ss (iproute2)
    ok_ss = has_cmd("ss")
    _dep_line("ss (iproute2)", ok_ss, "", "sudo apt install iproute2")

    # nf_conntrack subsystem (module or built-in)
    ct_ok = conntrack_available()
    ct_note = ""
    if ct_ok:
        if Path("/proc/net/nf_conntrack").exists() or \
           Path("/proc/sys/net/netfilter/nf_conntrack_max").exists():
            ct_note = " (built-in)"
    _dep_line("nf_conntrack", ct_ok, f"available{ct_note}" if ct_ok else "",
              "sudo modprobe nf_conntrack  (or: sudo apt install kmod)")

    # Python NetfilterQueue
    nfq = False
    try:
        import netfilterqueue  # noqa: F401
        nfq = True
    except ImportError:
        pass
    _dep_line("NetfilterQueue (python)", nfq, "",
              "sudo apt install python3-dev libnetfilter-queue-dev && pip install NetfilterQueue")

    # Mode availability
    print("\n--- Mode availability ---")
    modes = {
        "nfqueue":   nfq and ok and ct_ok,
        "conntrack": ok_ct and ok and ct_ok,
        "polling":   ok,  # only needs iptables + /proc/net
    }
    for mode, avail in modes.items():
        status = "READY" if avail else "missing deps"
        marker = "+" if avail else "!"
        print(f"  [{marker}] {mode:12s} {status}")

    if requested_mode and requested_mode != "auto":
        if not modes.get(requested_mode, False):
            print(f"\n[!] Requested mode '{requested_mode}' is not available. "
                  f"Install the missing dependencies above.")
            return False

    best = next((m for m, a in modes.items() if a), None)
    if best:
        print(f"\n[+] Best available mode: {best}")
    else:
        print("\n[!] No mode available — install at least iptables.")
        return False

    return True


def _dep_line(name, ok, ver, install_cmd):
    marker = "+" if ok else "!"
    status = "installed" if ok else "MISSING"
    ver_str = f" ({ver})" if ver else ""
    print(f"  [{marker}] {name:25s} {status}{ver_str}")
    if not ok:
        print(f"         install: {install_cmd}")


# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------

def select_mode():
    try:
        import netfilterqueue  # noqa: F401
        if has_cmd("iptables"):
            return "nfqueue"
    except ImportError:
        pass
    if has_cmd("conntrack") and has_cmd("iptables"):
        return "conntrack"
    if has_cmd("iptables"):
        return "polling"
    print("Error: iptables not found.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Monitor and block outbound connections by SOURCE PORT. "
                    "If a process sends from a port not in the allowed list, "
                    "it gets an individual iptables --sport DROP rule.",
        epilog="Ubuntu 24.04: sudo apt install iptables conntrack iproute2",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--ports", type=str,
        help="Comma-separated allowed SOURCE ports/ranges (e.g. 80,443,53,22)")
    group.add_argument(
        "--config", type=str,
        help="Config file with one port/range per line")
    group.add_argument(
        "--teardown", action="store_true",
        help="Remove all outbound_guard rules and exit")
    group.add_argument(
        "--check", action="store_true",
        help="Check dependencies and available modes, then exit")
    parser.add_argument(
        "--log", type=str, default=None,
        help="Log file path for blocked connections")
    parser.add_argument(
        "--proto", type=str, default="tcp,udp",
        help="Protocols to filter (default: tcp,udp)")
    parser.add_argument(
        "--mode", choices=["nfqueue", "conntrack", "polling", "auto"],
        default="auto",
        help="Interception mode (default: auto-detect best available)")
    parser.add_argument(
        "--poll-interval", type=float, default=0.5,
        help="Seconds between polls in polling mode (default: 0.5)")
    parser.add_argument(
        "--log-allowed", action="store_true",
        help="Also log allowed connections (verbose)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print config and exit without installing rules")
    args = parser.parse_args()

    check_root()

    if args.check:
        ok = check_dependencies(args.mode if args.mode != "auto" else None)
        sys.exit(0 if ok else 1)

    if args.teardown:
        teardown_chain()
        print("[+] All outbound_guard iptables rules removed.")
        return

    if args.ports:
        allowed = parse_ports(args.ports)
    else:
        allowed = load_config_file(args.config)

    protocols = [p.strip().lower() for p in args.proto.split(",")]

    if not allowed:
        print("Error: no allowed ports specified.", file=sys.stderr)
        sys.exit(1)

    # Ensure kernel module is loaded
    ensure_conntrack_module()

    mode = args.mode if args.mode != "auto" else select_mode()

    # Validate the chosen mode's dependencies
    if mode == "nfqueue":
        try:
            import netfilterqueue  # noqa: F401
        except ImportError:
            print("Error: NetfilterQueue not installed. Install it with:", file=sys.stderr)
            print("  sudo apt install python3-dev libnetfilter-queue-dev", file=sys.stderr)
            print("  pip install NetfilterQueue", file=sys.stderr)
            print("Or use --mode conntrack / --mode polling", file=sys.stderr)
            sys.exit(1)
    elif mode == "conntrack":
        if not has_cmd("conntrack"):
            print("Error: conntrack not installed: sudo apt install conntrack",
                  file=sys.stderr)
            sys.exit(1)

    print(f"[*] Allowed ports: {', '.join(str(p) for p in allowed)}")
    print(f"[*] Protocols:     {', '.join(p.upper() for p in protocols)}")
    print(f"[*] Mode:          {mode}")
    print(f"[*] Policy:        INDIVIDUAL (no default-deny-all)")
    if args.log:
        print(f"[*] Log file:      {args.log}")

    if args.dry_run:
        print("[*] Dry run — no rules installed.")
        return

    tracker = RuleTracker(log_file=args.log, log_allowed=args.log_allowed)

    def cleanup():
        tracker.print_summary()
        tracker.close()
        teardown_chain()
        print("[+] All outbound_guard rules removed. Clean exit.")

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    print()
    if mode == "nfqueue":
        run_nfqueue_mode(allowed, protocols, tracker)
    elif mode == "conntrack":
        run_conntrack_mode(allowed, protocols, tracker)
    else:
        run_polling_mode(allowed, protocols, tracker, interval=args.poll_interval)


if __name__ == "__main__":
    main()
