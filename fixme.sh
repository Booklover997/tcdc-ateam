#!/bin/bash
# TCDC Ubuntu access recovery. Run from an existing root shell or VM recovery console.
# bash fixme.sh                    Preview
# bash fixme.sh --apply            Repair the verified changes
# bash fixme.sh --help             Select a setup run or a reviewed policy file
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
exec /usr/bin/python3 -I - "$@" <<'PY'
import argparse
import fcntl
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/root")
LOG_DIR = Path("/var/log")
AUTH = Path("/etc/pam.d/common-auth")
FLAG_FILES = tuple(map(Path, (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/ssh/sshd_config",
)))
PAM_NAMES = set("common-auth common-account common-password common-session "
                "common-session-noninteractive sshd sudo sudo-i login su su-l passwd".split())
STAMP = re.compile(r"[0-9]{8}-[0-9]{6}")


def trusted(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (path.resolve(strict=True) != path or not kind(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise ValueError(f"Unsafe ownership, permissions, type or symlink at {path}")
    return path


def snapshot_path(backup, path):
    return backup / path.relative_to("/")


def sudo_policy(path):
    return path == Path("/etc/sudoers") or path.parent == Path("/etc/sudoers.d")


def safe_policy(path):
    if path.parent == Path("/etc/pam.d"):
        return path.name in PAM_NAMES
    if path == Path("/etc/sudoers"):
        return True
    return (path.parent == Path("/etc/sudoers.d")
            and re.fullmatch(r"[a-zA-Z0-9_-]+", path.name)
            and not re.search("blackteam|whiteteam|wazuh|ossec|audit|cloud|xen|xe-guest",
                              path.name, re.I))


def original_pam_edit(path, saved, log):
    # Only reproduce removals actually recorded by this run, and its literal nullok edit.
    prefix = f"FAIL removed PAM line from {path}: ".encode()
    removed = {line[len(prefix):] for line in log if line.startswith(prefix)}
    stripped = f"FAIL stripped nullok in {path}".encode() in log
    result = []
    for line in saved.splitlines(keepends=True):
        if line.rstrip(b"\n") in removed:
            continue
        if stripped and b"pam_unix" in line:
            line = line.replace(b"nullok_secure", b"").replace(b"nullok", b"")
        result.append(line)
    return b"".join(result)


def permit_repair(saved, live, log):
    # Accept the exact stock fallback order. Only insert the one proven lost rule.
    # Leave all current Unix password options (including a removed nullok) as found.
    lines = saved.splitlines(keepends=True)
    rules = [(i, row.split(b"#", 1)[0].split()) for i, row in enumerate(lines)]
    rules = [(i, words) for i, words in rules if words]
    hits = [(n, i) for n, (i, words) in enumerate(rules)
            if words == [b"auth", b"required", b"pam_permit.so"]]
    if len(hits) != 1:
        return None
    n, i = hits[0]
    if n < 2 or rules[n-1][1] != [b"auth", b"requisite", b"pam_deny.so"]:
        return None
    # In the generated primary stack a successful Unix login jumps over pam_deny.
    if not any(words[0] == b"auth" and b"pam_unix.so" in words
               and re.search(rb"\bsuccess=" + str(n-j-1).encode() + rb"\b", b" ".join(words[1:]))
               for j, (_, words) in enumerate(rules[:n-1])):
        return None
    for strip_nullok in (False, True):
        variant = [row.replace(b"nullok_secure", b"").replace(b"nullok", b"")
                   if strip_nullok and b"pam_unix" in row else row for row in lines]
        working = b"".join(variant)
        if live == working:
            return live
        event = f"FAIL removed PAM line from {AUTH}: ".encode() + lines[i].rstrip(b"\n")
        if event in log and live == b"".join(variant[:i] + variant[i+1:]):
            return working
    return None


def attrs(path):
    result = subprocess.run(["lsattr", "-d", str(path)], capture_output=True, check=True)
    fields = result.stdout.split()
    if len(fields) < 2:
        raise ValueError(f"Could not read filesystem attributes for {path}")
    return fields[0]


def replace_bytes(path, expected, data, *, sudoers=False):
    # Stage on the same filesystem, retain the live file's mode/ACLs, then rename.
    fd, name = tempfile.mkstemp(prefix=".hawk-fixme-", dir=path.parent)
    os.close(fd)
    temp = Path(name)
    try:
        subprocess.run(["cp", "--preserve=all", "--", path, temp], check=True)
        with temp.open("wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if sudoers:
            subprocess.run(["visudo", "-c", "-f", temp], check=True)
        if trusted(path).read_bytes() != expected:
            raise ValueError(f"{path} changed during recovery; inspect it again")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def apply(files, flags):
    saved = Path(tempfile.mkdtemp(prefix="hawk-fixme-", dir=ROOT))
    print(f"Pre-repair copies and flag list: {saved}", flush=True)
    for path, (old, _) in files.items():
        dest = snapshot_path(saved, path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "--preserve=all", "--", path, dest], check=True)
        if dest.read_bytes() != old:
            raise ValueError(f"{path} changed before repair")
    (saved / "immutable-before.txt").write_text("".join(f"{p}\n" for p in flags))

    clearing, writing = [], []
    try:
        for path in flags:
            trusted(path)
            if b"i" in attrs(path):
                clearing.append(path)
                subprocess.run(["chattr", "-i", str(path)], check=True)
                if b"i" in attrs(path):
                    raise ValueError(f"Immutable flag still present on {path}")
                print(f"Cleared immutable flag on {path}")
        for path, (old, new) in files.items():
            writing.append(path)
            replace_bytes(path, old, new, sudoers=sudo_policy(path))
            print(f"Repaired {path}")
        if any(sudo_policy(path) for path in files):
            subprocess.run(["visudo", "-c"], check=True)
    except BaseException:
        print(f"Repair interrupted or failed. Reverting this attempt. Copies: {saved}", file=sys.stderr)
        for path in reversed(writing):
            try:
                old, new = files[path]
                now = trusted(path).read_bytes()
                if now == new:
                    replace_bytes(path, new, old)
                elif now != old:
                    print(f"MANUAL: {path} changed concurrently; compare with {saved}{path}", file=sys.stderr)
            except (OSError, ValueError, subprocess.SubprocessError) as err:
                print(f"MANUAL rollback of {path}: {err}", file=sys.stderr)
        for path in reversed(clearing):
            try:
                subprocess.run(["chattr", "+i", str(trusted(path))], check=True)
            except (OSError, ValueError, subprocess.SubprocessError) as err:
                print(f"MANUAL rollback of immutable flag for {path}: {err}", file=sys.stderr)
        raise


def main():
    p = argparse.ArgumentParser(prog="bash fixme.sh", description="Preview or repair Ubuntu setup access damage.")
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true", help="apply the displayed repair plan (default is read-only)")
    modes.add_argument("--check", action="store_true", help="preview changes and run diagnostics (default)")
    p.add_argument("--run", metavar="YYYYMMDD-HHMMSS", help="timestamp of the setup run that broke access")
    p.add_argument("--restore-reviewed", metavar="/etc/FILE", type=Path, action="append", default=[],
                   help="restore an explicitly reviewed PAM or sudoers backup if live content matches the setup edit")
    args = p.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        p.exit(1, "Run on the affected Ubuntu box in a retained root shell or root recovery console.\n")
    os.umask(0o077)
    runs = sorted(d.name[len("hawk-backup-"):] for d in ROOT.glob("hawk-backup-*")
                  if STAMP.fullmatch(d.name[len("hawk-backup-"):]) and d.is_dir())
    stamp = args.run or (runs[0] if len(runs) == 1 else None)
    if stamp not in runs:
        p.exit(2, f"Available setup backups: {', '.join(runs) or 'none'}\n"
               "Select the run that first broke access with --run YYYYMMDD-HHMMSS. "
               "If its backup is missing, use a trusted VM snapshot or matching known-good PAM policy.\n")
    backup = trusted(ROOT / f"hawk-backup-{stamp}", directory=True)
    log = set(trusted(LOG_DIR / f"hawk-ubuntu-setup-{stamp}.log").read_bytes().splitlines())
    reviewed = set(args.restore_reviewed)
    rewrites = {Path(os.fsdecode(line[len(b"OK rewrote "):])) for line in log if line.startswith(b"OK rewrote ")}
    if any(not safe_policy(path) or path not in rewrites for path in reviewed):
        p.error("--restore-reviewed requires an eligible policy path that this setup run logged rewriting")

    files, flags, issues = {}, [], []
    print(f"{'Apply' if args.apply else 'Preview'} for setup run {stamp}")
    for path in sorted(rewrites):
        if not safe_policy(path):
            if path.parent == Path("/etc/pam.d") or path == Path("/etc/pam.conf"):
                issues.append(f"Review the setup edit to {str(path)!r} with its service owner.")
            continue
        source = snapshot_path(backup, path)
        try:
            old, live = trusted(source).read_bytes(), trusted(path).read_bytes()
        except (OSError, ValueError) as err:
            issues.append(str(err))
            continue
        if live == old:
            print(f"Already matches backup: {path}")
            continue
        if path.parent == Path("/etc/pam.d"):
            after = original_pam_edit(path, old, log)
        else:
            after = b"".join(line for line in old.splitlines(keepends=True)
                             if line.startswith(b"#") or not any(x in line for x in (b"/tmp", b"/dev/shm", b"/var/tmp")))
        new = None
        if path == AUTH:
            new = permit_repair(old, live, log)
        if path in reviewed and live == after:
            new = old
        if new == live:
            print(f"Expected PAM fallback already present in {path}")
        elif new is not None:
            files[path] = (live, new)
            print(f"Repair {path}" + (" from reviewed backup" if new == old and path in reviewed else " (one PAM rule)"))
        elif live == after:
            issues.append(f"Review: diff -u -- {shlex.quote(str(path))} {shlex.quote(str(source))}\n"
                          f"  If approved, add --restore-reviewed {shlex.quote(str(path))}.")
        else:
            issues.append(f"Later or unrecognized edits at {path}. Merge manually with {source}.")

    if AUTH not in rewrites:
        print("No successful common-auth rewrite recorded in this run. Check earlier runs if sudo still fails.")
    for path in FLAG_FILES:
        if f"OK immutable {path}".encode() not in log:
            continue
        try:
            if b"i" in attrs(trusted(path)):
                flags.append(path)
                print(f"Clear setup's immutable flag on {path}")
        except (OSError, ValueError, subprocess.SubprocessError) as err:
            issues.append(f"Check attributes on {path}: {err}")

    if args.apply and (files or flags):
        apply(files, flags)
    elif files or flags:
        print("Preview complete. Re-run with the same options and --apply to perform the listed repairs.")
    else:
        print("No verified automatic changes pending for this run.")

    for n in range(1, 6):
        user = f"nigel{n}"
        entry = subprocess.run(["getent", "-s", "files", "passwd", user], capture_output=True)
        fields = os.fsdecode(entry.stdout).rstrip("\n").split(":")
        home = Path(fields[5]) if len(fields) == 7 else Path("/home") / user
        if len(fields) == 7:
            if fields[-1] in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
                issues.append(f"{user} has login shell {fields[-1]}.")
            status = subprocess.run(["passwd", "-S", user], capture_output=True)
            if status.returncode or status.stdout.split()[1:2] != [b"P"]:
                issues.append(f"Check password status with passwd -S {user}.")
            policy = subprocess.run(["sudo", "-n", "-l", "-U", user, "/usr/bin/id", "-u"], capture_output=True)
            if policy.returncode:
                issues.append(f"Check the sudo authorization for {user} with sudo -l -U {user}.")
        for name in ("authorized_keys", "authorized_keys2"):
            path = home / ".ssh" / name
            if f"OK removed {path}".encode() in log and not path.exists():
                source = snapshot_path(backup, path)
                issues.append(f"Missing {path}. Verify the team key fingerprint before restoring it; backup: {source}")
    locked = sorted(os.fsdecode(line[11:]) for line in log if line.startswith(b"OK LOCKED: ")
                    and re.fullmatch(rb"[a-z_][a-z0-9_-]*", line[11:]) and line[11:] not in (b"root", b"blackteam", b"whiteteam"))
    if locked:
        issues.append("Setup logged locking these accounts. Check whether your SSH login is on the list: " + ", ".join(locked))
    for msg in issues:
        print("REVIEW:", msg)
    # These are configuration checks. The access test must be performed by the SSH user.
    for command in (["visudo", "-c"], ["sshd", "-t"]):
        result = subprocess.run(command, check=False)
        if result.returncode:
            print(f"CHECK FAILED: {' '.join(command)}")
            issues.append(command[0])
    print("Keep this root shell open. In a second SSH login as a team admin run: id; sudo -k; sudo id -u")
    print("Expected result: 0. Use the current password for that SSH account when prompted.")
    return 2 if issues else 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        if sys.platform == "linux" and os.geteuid() == 0:
            lock_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("Stopped. Keep the root console open and review the messages above.")
    except (OSError, ValueError, subprocess.SubprocessError) as err:
        sys.exit(f"STOP: {err}")
PY
