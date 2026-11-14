#!/usr/bin/env python3
"""Probe launchd domains using only unique ELAN-owned service names."""
import json
import os
import plistlib
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parent
binary = root / "NativeNamespaceProbe"
uid = os.getuid()
if uid != 501 or not binary.is_file():
    raise SystemExit("Expected Xiaomi user 501 and the colocated probe")
name = f"io.github.hackintosh-tools.elan-namespace-{os.getpid()}"
study = root / name
study.mkdir(mode=0o700)
jobs = []
result = {"service": name, "uid": uid, "apple_services_changed": False, "operations": []}


def command(args):
    process = subprocess.run(args, text=True, capture_output=True, timeout=10)
    value = {"command": args, "status": process.returncode,
             "stdout": process.stdout, "stderr": process.stderr}
    result["operations"].append(value)
    return value


def job(domain, suffix, arguments, mach=False):
    label = name + "." + suffix
    stdout = study / (suffix + ".out")
    path = study / (suffix + ".plist")
    content = {"Label": label, "ProgramArguments": [str(binary), *arguments],
               "StandardOutPath": str(stdout), "StandardErrorPath": str(study / (suffix + ".err")),
               "RunAtLoad": not mach, "ProcessType": "Background"}
    if mach:
        content["MachServices"] = {name: True}
    path.write_bytes(plistlib.dumps(content))
    target = f"{domain}/{uid}/{label}"
    # Do not adopt any pre-existing job, even if a previous PID happened to match.
    if command(["/bin/launchctl", "print", target])["status"] == 0:
        raise RuntimeError("Job already present")
    loaded = command(["/bin/launchctl", "bootstrap", f"{domain}/{uid}", str(path)])
    current = command(["/bin/launchctl", "print", target])
    if current["status"] == 0:
        jobs.append(target)
    return loaded["status"] == 0, stdout


try:
    user_ok, _ = job("user", "user-server", ["--server", name, "20"], mach=True)
    result["user_registered"] = user_ok
    if user_ok:
        result["ssh_before_gui"] = command([str(binary), "--client", name])
    gui_ok, _ = job("gui", "gui-server", ["--server", name, "40"], mach=True)
    result["gui_registered"] = gui_ok
    if gui_ok:
        result["ssh_after_gui"] = command([str(binary), "--client", name])
        client_ok, output = job("gui", "gui-client", ["--client", name])
        result["gui_client_loaded"] = client_ok
        if client_ok:
            for _ in range(80):
                text = output.read_text() if output.is_file() else ""
                if "valid=" in text:
                    break
                time.sleep(0.1)
            result["gui_client_output"] = text
finally:
    result["cleanup"] = []
    for target in reversed(jobs):
        stopped = command(["/bin/launchctl", "bootout", target])
        state = command(["/bin/launchctl", "print", target])
        result["cleanup"].append({"target": target, "stop": stopped["status"], "absent": state["status"] != 0})
    result["post_cleanup_lookup"] = command([str(binary), "--client", name])
    result["logs"] = {p.name: p.read_text() for p in study.iterdir() if p.suffix in (".out", ".err")}
    (root / "namespace-study.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
