#!/usr/bin/env python3
"""Manage one non-attached, enforcing CI profile; never disable host protection."""

import argparse
import contextlib
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

from ci import identity, write


def profile_name():
    name = os.environ["REDJOHN_CI_APPARMOR_PROFILE"]
    if not re.fullmatch(r"redjohn-ci-[0-9]+-[0-9]+-(X64|ARM64)", name):
        raise ValueError("invalid_owned_profile_name")
    return name


def command(*argv):
    result = subprocess.run(argv, check=False, text=True, capture_output=True, timeout=30)
    return {"exit_code": result.returncode, "stdout": result.stdout[-12000:], "stderr": result.stderr[-12000:]}


def restrictions():
    return {key: Path("/proc/sys/kernel", key).read_text().strip() for key in (
        "apparmor_restrict_unprivileged_userns", "apparmor_restrict_unprivileged_unconfined")}


def outside_write_negative_control(name):
    """A user-writable path outside the profile allowlist must be denied."""
    probe = Path.home() / f".redjohn-apparmor-probe-{os.getpid()}"
    result = command(
        "aa-exec", "-p", name, "--", sys.executable, "-c",
        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('x')", str(probe),
    )
    with contextlib.suppress(OSError):
        probe.unlink()
    if result["exit_code"] == 0:
        raise RuntimeError("profile_outside_write_not_denied")
    return result


def prepare():
    if os.getuid() == 0:
        raise RuntimeError("prepare_requires_original_runner_uid")
    name = profile_name()
    result = {**identity(), "profile": name, "restrictions_before": restrictions()}
    try:
        # Preserve the hosted runner's namespace hardening. Harden profile
        # transitions too: aa-exec by an unprivileged process must not grant
        # the scoped profile's namespace permission.
        if result["restrictions_before"]["apparmor_restrict_unprivileged_userns"] != "1":
            raise RuntimeError("host_userns_restriction_must_already_be_enabled")
        subprocess.run(["sudo", "sysctl", "-w", "kernel.apparmor_restrict_unprivileged_unconfined=1"], check=True)
        result["unprofiled_namespace"] = command("unshare", "-Urn", "/usr/bin/true")
        if result["unprofiled_namespace"]["exit_code"] == 0:
            raise RuntimeError("unprofiled_namespace_negative_control_failed")
        policy = Path(".github/policies/redjohn-ci.apparmor").read_text().replace("@REDJOHN_CI_PROFILE@", name)
        result["policy_sha256"] = hashlib.sha256(policy.encode()).hexdigest()
        path = Path("artifacts/apparmor-policy.txt")
        path.parent.mkdir(exist_ok=True)
        path.write_text(policy)
        target = "/etc/apparmor.d/" + name
        # Unique run/attempt/architecture identity: never replace another job's
        # profile. The installed policy is root-owned and has no attachment.
        if Path(target).exists():
            raise RuntimeError("owned_profile_already_exists")
        subprocess.run(["sudo", "install", "-m", "0600", "-o", "root", "-g", "root", str(path), target], check=True)
        subprocess.run(["sudo", "apparmor_parser", "-a", target], check=True)
        result["unprivileged_profile_namespace"] = command("aa-exec", "-p", name, "--", "unshare", "-Urn", "/usr/bin/true")
        if result["unprivileged_profile_namespace"]["exit_code"] == 0:
            raise RuntimeError("unprivileged_profile_entry_bypassed_restriction")
        result["outside_write_negative_control"] = outside_write_negative_control(name)
        result["restrictions_after"] = restrictions()
        if set(result["restrictions_after"].values()) != {"1"}:
            raise RuntimeError("host_restrictions_changed")
        result["loaded"] = True
        return 0
    finally:
        write("apparmor-setup.json", result)


def cleanup():
    name = profile_name()
    result = {**identity(), "profile": name, "restrictions_after_tests": restrictions()}
    active = []
    for path in Path("/proc").glob("[0-9]*/attr/current"):
        try:
            if name in path.read_text():
                active.append(int(path.parents[1].name))
        except OSError:
            continue
    result["active_profile_pids"] = active
    if active:
        write("apparmor-cleanup.json", {**result, "removed": False, "success": False})
        raise RuntimeError("refusing_to_unconfine_surviving_profile_processes")
    target = Path("/etc/apparmor.d") / name
    if target.exists():
        subprocess.run(["sudo", "apparmor_parser", "-R", str(target)], check=True)
        subprocess.run(["sudo", "rm", "--", str(target)], check=True)
    result["removed"] = not target.exists()
    result["unprofiled_namespace"] = command("unshare", "-Urn", "/usr/bin/true")
    result["success"] = (result["removed"] and set(result["restrictions_after_tests"].values()) == {"1"}
                         and result["unprofiled_namespace"]["exit_code"] != 0)
    write("apparmor-cleanup.json", result)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prepare", "cleanup"))
    raise SystemExit(prepare() if parser.parse_args().phase == "prepare" else cleanup())
