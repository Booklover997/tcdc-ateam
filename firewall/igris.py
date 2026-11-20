#!/usr/bin/env python3
"""
igris.py — Monitor /var/log/ufw.log for outbound connections and block
destinations reached from non-whitelisted source ports.

Reactive approach:
  1. UFW allows all outbound by default and logs it
  2. This script tails /var/log/ufw.log in real time
  3. When it sees an outbound connection with a source port NOT in the
     whitelist, it runs: ufw deny out proto <tcp|udp> to <dst_ip> port <dport>
  4. That UFW rule blocks all future outbound traffic to that destination

The first connection gets through (that's how it appears in the log),
then the rule catches everything after.

IP Whitelist:
  --whitelist-ips lets you pre-allow destination IPs (e.g. package repos).
  These IPs are added as UFW allow rules with comment 'igris_whitelist'.
  --remove-whitelist removes all whitelist rules (toggle off).

Prerequisites (installed automatically with --setup):
  - ufw (enabled, default allow outgoing, logging high)
  - rsyslog (writes kernel log to /var/log/ufw.log)

Usage:
    sudo python3 igris.py --setup
    sudo python3 igris.py --ports 22,2222,80
    sudo python3 igris.py --ports 22,2222 --whitelist-ips 91.189.91.83,185.125.190.36
    sudo python3 igris.py --remove-whitelist
    sudo python3 igris.py --teardown

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
RULE_COMMENT = "igris_auto"
WHITELIST_COMMENT = "igris_whitelist"

DEFAULT_WHITELISTED_IPS = [
    "10.112.10.53",
]

UBUNTU_PACKAGE_IPS = [
    "91.189.91.83",
    "91.189.91.82",
    "185.125.190.36",
    "185.125.190.39",
    "91.189.88.142",
    "91.189.88.152",
    "91.189.91.81",
    "91.189.91.80",
]

UBUNTU_PACKAGE_HOSTS = [
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ppa.launchpad.net",
    "changelogs.ubuntu.com",
]


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


def resolve_hosts(hosts):
    """Resolve hostnames to IPs."""
    ips = set()
    for host in hosts:
        try:
            r = run(["getent", "hosts", host], check=False)
            if r.returncode == 0:
                for line in r.stdout.strip().splitlines():
                    ip = line.split()[0]
                    ips.add(ip)
        except Exception:
            pass
    return sorted(ips)


# ---------------------------------------------------------------------------
# IP Whitelist
# ---------------------------------------------------------------------------

def add_whitelist(ips):
    """Add UFW allow out rules for whitelisted destination IPs."""
    added = 0
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        r = run([
            "ufw", "allow", "out",
            "to", ip,
            "comment", WHITELIST_COMMENT,
        ], check=False)
        if r.returncode == 0:
            print(f"    ufw allow out to {ip}")
            added += 1
        elif "existing" in (r.stdout + r.stderr).lower():
            print(f"    (already exists) ufw allow out to {ip}")
        else:
            err = r.stderr.strip() or r.stdout.strip()
            print(f"    [!] Failed: {ip}: {err}")
    return added


def remove_whitelist():
    """Remove all UFW rules with the whitelist comment."""
    print("[*] Removing igris whitelist rules...")
    r = run(["ufw", "status", "numbered"], check=False)
    if r.returncode != 0:
        print("[!] Could not get ufw status")
        return

    rules_to_delete = []
    for line in r.stdout.splitlines():
        m = re.match(r"\[\s*(\d+)\]", line)
        if m and WHITELIST_COMMENT in line:
            rules_to_delete.append(int(m.group(1)))

    for num in sorted(rules_to_delete, reverse=True):
        run(["ufw", "--force", "delete", str(num)], check=False)
        print(f"    Removed whitelist rule #{num}")

    if rules_to_delete:
        print(f"[+] Removed {len(rules_to_delete)} whitelist rules.")
    else:
        print("[+] No whitelist rules found.")


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
    print("    sudo python3 igris.py --ports 22,2222,80")


def teardown():
    """Remove all ufw rules added by this script (blocks + whitelist)."""
    print("[*] Removing igris rules...")
    r = run(["ufw", "status", "numbered"], check=False)
    if r.returncode != 0:
        print("[!] Could not get ufw status")
        return

    rules_to_delete = []
    for line in r.stdout.splitlines():
        m = re.match(r"\[\s*(\d+)\]", line)
        if m and (RULE_COMMENT in line or WHITELIST_COMMENT in line or "igris_dns" in line):
            rules_to_delete.append(int(m.group(1)))

    if not rules_to_delete:
        for line in r.stdout.splitlines():
            m = re.match(r"\[\s*(\d+)\]", line)
            if m and "DENY OUT" in line:
                rules_to_delete.append(int(m.group(1)))

    for num in sorted(rules_to_delete, reverse=True):
        run(["ufw", "--force", "delete", str(num)], check=False)
        print(f"    Removed rule #{num}")

    if rules_to_delete:
        print(f"[+] Removed {len(rules_to_delete)} rules.")
    else:
        print("[+] No igris rules found to remove.")


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------

class RuleManager:
    def __init__(self, log_file=None, whitelisted_ips=None):
        self._blocked = {}  # {(proto, dst_ip, dst_port): timestamp}
        self._whitelisted_ips = set(whitelisted_ips or [])
        self._base_whitelisted_ips = set(DEFAULT_WHITELISTED_IPS)
        self._log_fh = None
        if log_file:
            self._log_fh = open(log_file, "a", buffering=1)

    def reload_whitelist_from_ufw(self):
        """Re-read UFW rules to rebuild the whitelist from current state."""
        new_wl = set(self._base_whitelisted_ips)
        r = run(["ufw", "status"], check=False)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if WHITELIST_COMMENT in line:
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        new_wl.add(m.group(1))
        old = self._whitelisted_ips
        self._whitelisted_ips = new_wl
        added = new_wl - old
        removed = old - new_wl
        self._log(f"[RELOAD] {ts()}  Whitelist reloaded: "
                  f"{len(new_wl)} IPs (added {len(added)}, removed {len(removed)})")

    def is_whitelisted(self, dst_ip):
        return dst_ip in self._whitelisted_ips

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

    def log_emergency(self, proto, src_port, src_ip, dst_ip, dst_port):
        msg = (f"[EMERGENCY] {ts()}  {proto.upper()} "
               f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
               f"UDP payload likely sent before rule applied")
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
        print("\nTo remove all rules: sudo python3 igris.py --teardown")

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

    proc = subprocess.Popen(
        ["tail", "-F", "-n", "0", UFW_LOG],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    seen_conns = set()

    try:
        for line in proc.stdout:
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

            if not iface:
                continue

            if dst_ip.startswith("127.") or dst_ip == src_ip:
                continue

            if src_port in allowed_set:
                if log_allowed:
                    manager.log_allowed(proto, src_port, src_ip, dst_ip, dst_port)
                continue

            if manager.is_whitelisted(dst_ip):
                continue

            conn_key = (proto, dst_ip, dst_port)
            if conn_key in seen_conns:
                continue
            seen_conns.add(conn_key)

            if manager.is_blocked(proto, dst_ip, dst_port):
                continue

            if proto == "udp":
                manager.log_emergency(proto, src_port, src_ip, dst_ip, dst_port)
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
                    "destinations reached from non-whitelisted source ports.",
        epilog="Requires: ufw, rsyslog. Run --setup first.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--ports", type=str,
        help="Comma-separated allowed source ports/ranges (e.g. 22,2222,80)")
    group.add_argument(
        "--config", type=str,
        help="Config file with one port/range per line")
    group.add_argument(
        "--setup", action="store_true",
        help="Install and configure ufw + rsyslog, then exit")
    group.add_argument(
        "--teardown", action="store_true",
        help="Remove all ufw rules added by this script")
    group.add_argument(
        "--remove-whitelist", action="store_true",
        help="Remove all whitelist allow rules (toggle off)")
    group.add_argument(
        "--add-whitelist", action="store_true",
        help="Add whitelist rules and exit (use with --whitelist-packages / --whitelist-ips)")
    parser.add_argument(
        "--whitelist-ips", type=str, default=None,
        help="Comma-separated destination IPs to allow (bypass blocking)")
    parser.add_argument(
        "--whitelist-packages", action="store_true",
        help="Auto-whitelist Ubuntu package repository IPs")
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

    if args.remove_whitelist:
        remove_whitelist()
        return

    if args.add_whitelist:
        wl_ips = set()
        if args.whitelist_ips:
            for ip in args.whitelist_ips.split(","):
                ip = ip.strip()
                if ip:
                    wl_ips.add(ip)
        if args.whitelist_packages:
            print("[*] Resolving package repository IPs...")
            resolved = resolve_hosts(UBUNTU_PACKAGE_HOSTS)
            wl_ips |= set(UBUNTU_PACKAGE_IPS) | set(resolved)
        if not wl_ips:
            print("Error: use --whitelist-packages and/or --whitelist-ips with --add-whitelist",
                  file=sys.stderr)
            sys.exit(1)
        print(f"[*] Adding {len(wl_ips)} whitelist allow rules...")
        add_whitelist(wl_ips)
        run(["ufw", "reload"], check=False)
        print(f"[+] Whitelist active. Remove with: sudo python3 igris.py --remove-whitelist")
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
        print("Error: ufw not installed. Run: sudo python3 igris.py --setup",
              file=sys.stderr)
        sys.exit(1)

    r = run(["ufw", "status"], check=False)
    if "inactive" in r.stdout.lower():
        print("Error: ufw is not enabled. Run: sudo python3 igris.py --setup",
              file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(UFW_LOG):
        print(f"Error: {UFW_LOG} does not exist. Run: sudo python3 igris.py --setup",
              file=sys.stderr)
        sys.exit(1)

    pgrep = run(["pgrep", "rsyslogd"], check=False)
    if pgrep.returncode != 0:
        print("[!] rsyslog not running — starting it...")
        run(["rsyslogd"], check=False)
        time.sleep(1)

    # Build IP whitelist
    whitelisted_ips = set(DEFAULT_WHITELISTED_IPS)
    if args.whitelist_ips:
        for ip in args.whitelist_ips.split(","):
            ip = ip.strip()
            if ip:
                whitelisted_ips.add(ip)

    if args.whitelist_packages:
        print("[*] Resolving Ubuntu package repository IPs...")
        resolved = resolve_hosts(UBUNTU_PACKAGE_HOSTS)
        pkg_ips = set(UBUNTU_PACKAGE_IPS) | set(resolved)
        whitelisted_ips |= pkg_ips
        print(f"    Found {len(pkg_ips)} package repo IPs")

    if whitelisted_ips:
        print(f"[*] Adding {len(whitelisted_ips)} whitelist allow rules...")
        add_whitelist(whitelisted_ips)
        run(["ufw", "reload"], check=False)
        print(f"[+] Whitelist active. Remove with: sudo python3 igris.py --remove-whitelist")

    print(f"[*] Allowed source ports: {', '.join(str(p) for p in allowed)}")
    if whitelisted_ips:
        print(f"[*] Whitelisted IPs: {', '.join(sorted(whitelisted_ips))}")
    print(f"[*] Watching: {UFW_LOG}")
    print(f"[*] Method: ufw deny out proto <tcp|udp> to <dst_ip> port <dst_port>")
    if args.log:
        print(f"[*] Log file: {args.log}")

    if args.dry_run:
        print("[*] Dry run — not monitoring.")
        return

    manager = RuleManager(log_file=args.log, whitelisted_ips=whitelisted_ips)

    def cleanup():
        manager.print_summary()
        manager.close()

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGHUP, lambda *_: manager.reload_whitelist_from_ufw())

    print(f"\n[+] Monitoring outbound connections (Ctrl+C to stop)...")
    print(f"    First connection from a non-allowed source port goes through,")
    print(f"    then ufw blocks all future traffic to that destination IP:port.\n")

    tail_ufw_log(allowed_set, manager, log_allowed=args.log_allowed)


if __name__ == "__main__":
    main()

