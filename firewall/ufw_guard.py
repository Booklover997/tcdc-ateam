#!/usr/bin/env python3
"""
ufw_guard.py — Monitor /var/log/ufw.log for outbound ALLOW entries and
block any whose source port is not in the whitelist.

Reactive approach:
  1. UFW allows all outbound by default and logs it
  2. This script tails /var/log/ufw.log in real time
  3. When it sees [UFW ALLOW] outbound with a source port NOT in the
     whitelist, it runs: ufw deny out proto <tcp|udp> from any port <sport>
  4. That UFW rule blocks all future outbound traffic from that port

The first connection gets through (that's how it appears in the log),
then the rule catches everything after.

Prerequisites (installed automatically with --setup):
  - ufw (enabled, default allow outgoing, logging high)
  - rsyslog (writes kernel log to /var/log/ufw.log)

Usage:
    sudo python3 ufw_guard.py --setup                # one-time setup
    sudo python3 ufw_guard.py --ports 80,443,53,22
    sudo python3 ufw_guard.py --config ports.conf --log /var/log/guard.log
    sudo python3 ufw_guard.py --teardown             # remove added rules

Requires root.
"""

import argparse
import atexit
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

UFW_LOG = "/var/log/ufw.log"
RULE_COMMENT = "ufw_guard_auto"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def check_root():
    if os.geteuid() != 0:
        print("Error: must run as root.", file=sys.stderr)
        sys.exit(1)


def run(cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def has_cmd(name):
    return shutil.which(name) is not None


def parse_ports(spec):
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


# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------

def setup():
    """Install and configure ufw + rsyslog for outbound logging."""
    print("[*] Installing ufw and rsyslog...")
    r = run(["apt-get", "install", "-y", "-qq", "ufw", "rsyslog"], check=False)
    if r.returncode != 0:
        print(f"[!] apt-get failed: {r.stderr.strip()}", file=sys.stderr)

    # Start rsyslog
    run(["pkill", "rsyslogd"], check=False)
    time.sleep(0.5)
    run(["rsyslogd"], check=False)

    # Enable UFW
    run(["ufw", "--force", "enable"], check=False)
    run(["ufw", "default", "allow", "outgoing"], check=False)
    run(["ufw", "logging", "high"], check=False)

    # Ensure log file exists
    if not os.path.exists(UFW_LOG):
        with open(UFW_LOG, "w"):
            pass

    # Verify rsyslog has the ufw config
    r = run(["grep", "-r", "UFW", "/etc/rsyslog.d/"], check=False)
    if r.returncode != 0:
        print("[!] No UFW rsyslog config found in /etc/rsyslog.d/")
        print("    Creating /etc/rsyslog.d/20-ufw.conf...")
        with open("/etc/rsyslog.d/20-ufw.conf", "w") as f:
            f.write(':msg,contains,"[UFW " /var/log/ufw.log\n')
        run(["pkill", "-HUP", "rsyslogd"], check=False)

    # Verify
    time.sleep(1)
    pgrep = run(["pgrep", "-a", "rsyslog"], check=False)
    ufw_status = run(["ufw", "status", "verbose"], check=False)

    print()
    print("[+] Setup complete:")
    print(f"    rsyslog: {'running' if pgrep.returncode == 0 else 'NOT running'}")
    print(f"    ufw: enabled, logging high")
    print(f"    log file: {UFW_LOG}")
    print()
    if "allow (outgoing)" in ufw_status.stdout:
        print("[+] UFW default outgoing: allow — outbound traffic will be logged")
    else:
        print("[!] Warning: UFW outgoing policy may not be 'allow'")
    print()
    print("You can now run:")
    print("    sudo python3 ufw_guard.py --ports 80,443,53,22")


def teardown():
    """Remove all ufw rules added by this script."""
    print("[*] Removing ufw_guard rules...")
    r = run(["ufw", "status", "numbered"], check=False)
    if r.returncode != 0:
        print("[!] Could not get ufw status")
        return

    # Find rules we added (they have the comment marker)
    # Parse numbered output and delete in reverse order
    rules_to_delete = []
    for line in r.stdout.splitlines():
        # Match lines like: [ 1] ... (ufw_guard_auto)
        m = re.match(r"\[\s*(\d+)\]", line)
        if m and RULE_COMMENT in line:
            rules_to_delete.append(int(m.group(1)))

    if not rules_to_delete:
        # Fallback: find deny out rules with sport
        for line in r.stdout.splitlines():
            m = re.match(r"\[\s*(\d+)\]", line)
            if m and "DENY OUT" in line:
                rules_to_delete.append(int(m.group(1)))

    # Delete in reverse order so indices don't shift
    for num in sorted(rules_to_delete, reverse=True):
        run(["ufw", "--force", "delete", str(num)], check=False)
        print(f"    Removed rule #{num}")

    if rules_to_delete:
        print(f"[+] Removed {len(rules_to_delete)} rules.")
    else:
        print("[+] No ufw_guard rules found to remove.")


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------

class RuleManager:
    def __init__(self, log_file=None):
        self._blocked = {}  # {(proto, dst_ip, dst_port): timestamp}
        self._log_fh = None
        if log_file:
            self._log_fh = open(log_file, "a", buffering=1)

    def is_blocked(self, proto, dst_ip, dst_port):
        return (proto, dst_ip, dst_port) in self._blocked

    def add_block(self, proto, src_port, src_ip, dst_ip, dst_port):
        """Add a UFW deny rule for the destination IP and port."""
        key = (proto, dst_ip, dst_port)
        if key in self._blocked:
            return

        ufw_proto = proto.lower()
        r = run([
            "ufw", "deny", "out",
            "proto", ufw_proto,
            "to", dst_ip, "port", str(dst_port),
            "comment", RULE_COMMENT,
        ], check=False)

        if r.returncode == 0:
            self._blocked[key] = ts()
            self._log(f"[BLOCKED] {ts()}  {proto.upper()} "
                      f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
                      f"ufw deny out proto {ufw_proto} to {dst_ip} port {dst_port}")
        else:
            err = r.stderr.strip() or r.stdout.strip()
            self._log(f"[ERROR] {ts()}  Failed to add rule for {dst_ip}:{dst_port}: {err}")

    def _log(self, msg):
        print(msg)
        if self._log_fh:
            self._log_fh.write(msg + "\n")

    def log_allowed(self, proto, src_port, src_ip, dst_ip, dst_port):
        self._log(f"[ALLOWED] {ts()}  {proto.upper()} "
                  f"sport={src_port} ({src_ip} -> {dst_ip}:{dst_port})")

    def print_summary(self):
        if not self._blocked:
            print("\n--- No destinations were blocked ---")
            return
        print(f"\n--- Summary: {len(self._blocked)} destinations blocked via ufw ---")
        for (proto, dst_ip, dst_port), when in sorted(self._blocked.items()):
            print(f"  ufw deny out proto {proto} to {dst_ip} port {dst_port}  (added {when})")
        print("\nTo remove all rules: sudo python3 ufw_guard.py --teardown")

    def close(self):
        if self._log_fh:
            self._log_fh.close()


# ---------------------------------------------------------------------------
# Log tailer
# ---------------------------------------------------------------------------

UFW_ALLOW_PATTERN = re.compile(
    r"\[UFW ALLOW\]"
    r".*?IN=\s*"            # empty IN = outbound
    r"OUT=(\S+)"            # OUT=eth0
    r".*?SRC=(\S+)"
    r".*?DST=(\S+)"
    r".*?PROTO=(\S+)"
    r".*?SPT=(\d+)"
    r".*?DPT=(\d+)"
)

# Also catch AUDIT entries (logged at high level for outbound)
UFW_AUDIT_PATTERN = re.compile(
    r"\[UFW AUDIT\]"
    r".*?IN=\s*"
    r"OUT=(\S+)"
    r".*?SRC=(\S+)"
    r".*?DST=(\S+)"
    r".*?PROTO=(\S+)"
    r".*?SPT=(\d+)"
    r".*?DPT=(\d+)"
)


def tail_ufw_log(allowed_set, manager, log_allowed=False):
    """Tail /var/log/ufw.log and react to outbound ALLOW/AUDIT entries."""

    # Start from end of file
    proc = subprocess.Popen(
        ["tail", "-F", "-n", "0", UFW_LOG],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    seen_conns = set()

    try:
        for line in proc.stdout:
            # Try ALLOW first, then AUDIT
            m = UFW_ALLOW_PATTERN.search(line)
            if not m:
                m = UFW_AUDIT_PATTERN.search(line)
            if not m:
                continue

            iface = m.group(1)
            src_ip = m.group(2)
            dst_ip = m.group(3)
            proto = m.group(4).lower()
            src_port = int(m.group(5))
            dst_port = int(m.group(6))

            # Only outbound (has OUT=, empty IN=)
            if not iface:
                continue

            # Skip loopback
            if dst_ip == "127.0.0.1":
                continue

            if src_port in allowed_set:
                if log_allowed:
                    manager.log_allowed(proto, src_port, src_ip, dst_ip, dst_port)
                continue

            # Dedup: only process each (proto, dst_ip, dst_port) once
            conn_key = (proto, dst_ip, dst_port)
            if conn_key in seen_conns:
                continue
            seen_conns.add(conn_key)

            if manager.is_blocked(proto, dst_ip, dst_port):
                continue

            manager.add_block(proto, src_port, src_ip, dst_ip, dst_port)

    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Monitor UFW logs for outbound connections and block "
                    "any whose source port is not in the whitelist.",
        epilog="Requires: ufw, rsyslog. Run --setup first.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--ports", type=str,
        help="Comma-separated allowed source ports/ranges (e.g. 80,443,53,22)")
    group.add_argument(
        "--config", type=str,
        help="Config file with one port/range per line")
    group.add_argument(
        "--setup", action="store_true",
        help="Install and configure ufw + rsyslog, then exit")
    group.add_argument(
        "--teardown", action="store_true",
        help="Remove all ufw rules added by this script")
    parser.add_argument(
        "--log", type=str, default=None,
        help="Log file for blocked/allowed entries")
    parser.add_argument(
        "--log-allowed", action="store_true",
        help="Also log allowed connections (verbose)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print config and exit without monitoring")
    args = parser.parse_args()

    check_root()

    if args.setup:
        setup()
        return

    if args.teardown:
        teardown()
        return

    if args.ports:
        allowed = parse_ports(args.ports)
    else:
        allowed = load_config_file(args.config)

    if not allowed:
        print("Error: no allowed ports specified.", file=sys.stderr)
        sys.exit(1)

    allowed_set = set(allowed)

    # Preflight checks
    if not has_cmd("ufw"):
        print("Error: ufw not installed. Run: sudo python3 ufw_guard.py --setup",
              file=sys.stderr)
        sys.exit(1)

    r = run(["ufw", "status"], check=False)
    if "inactive" in r.stdout.lower():
        print("Error: ufw is not enabled. Run: sudo python3 ufw_guard.py --setup",
              file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(UFW_LOG):
        print(f"Error: {UFW_LOG} does not exist. Run: sudo python3 ufw_guard.py --setup",
              file=sys.stderr)
        sys.exit(1)

    pgrep = run(["pgrep", "rsyslogd"], check=False)
    if pgrep.returncode != 0:
        print("[!] rsyslog not running — starting it...")
        run(["rsyslogd"], check=False)
        time.sleep(1)

    print(f"[*] Allowed source ports: {', '.join(str(p) for p in allowed)}")
    print(f"[*] Watching: {UFW_LOG}")
    print(f"[*] Method: ufw deny out proto <tcp|udp> to <dst_ip> port <dst_port>")
    if args.log:
        print(f"[*] Log file: {args.log}")

    if args.dry_run:
        print("[*] Dry run — not monitoring.")
        return

    manager = RuleManager(log_file=args.log)

    def cleanup():
        manager.print_summary()
        manager.close()

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    print(f"\n[+] Monitoring outbound connections (Ctrl+C to stop)...")
    print(f"    First connection from a non-allowed source port goes through,")
    print(f"    then ufw blocks all future traffic to that destination IP:port.\n")

    tail_ufw_log(allowed_set, manager, log_allowed=args.log_allowed)


if __name__ == "__main__":
    main()

