"""Run a one-shot Aqua LaunchEvents test against an existing diagnostics binary."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import uuid


def launchctl(*args):
    return subprocess.run(["/bin/launchctl", *args], text=True, capture_output=True, timeout=6)


def main(binary, usb_only, settings_reader=None):
    binary = binary.resolve(strict=True)
    if os.geteuid() == 0:
        raise SystemExit("Run as the logged-in user.")
    domain = f"gui/{os.getuid()}"
    label = "io.github.hackintosh-tools.elan-usb.check-" + uuid.uuid4().hex
    service = "io.hackmac." + uuid.uuid4().hex[:12] if settings_reader else label
    with tempfile.TemporaryDirectory(prefix="usb-event-", dir=binary.parent) as folder:
        path = Path(folder)
        output = path / "event.json"
        job = path / (label + ".plist")
        name = "ELANFingerprintUSB"
        event = dict(IOProviderClass=name, IOMatchLaunchStream=True)
        if usb_only:
            name = "ELANUsbInterface"
            event = dict(IOProviderClass="IOUSBHostInterface", idVendor=0x04f3, idProduct=0x0c1a,
                         bConfigurationValue=1, bInterfaceNumber=0, IOMatchLaunchStream=True)
        job.write_bytes(plistlib.dumps(dict(Label=label, LimitLoadToSessionType="Aqua",
            ProgramArguments=[str(binary), "--on-attach", service], MachServices={service: True}, StandardOutPath=str(output),
            StandardErrorPath=str(path / "stderr"), LaunchEvents={"com.apple.iokit.matching": {name: event}})))
        start = launchctl("bootstrap", domain, str(job))
        if start.returncode:
            raise SystemExit(start.stderr.strip() or "bootstrap failed")
        try:
            for _ in range(32):
                if output.exists() and output.read_bytes().endswith(b"\n"):
                    result = json.loads(output.read_bytes())
                    print(json.dumps(result, sort_keys=True), flush=True)
                    if not result.get("usb_event_verified") or result.get("uid") != os.getuid():
                        return 1
                    args = [str(settings_reader.resolve(strict=True)), service] if settings_reader else [str(binary), "--read-discovery", service]
                    peer = subprocess.run(args, timeout=8)
                    return peer.returncode
                time.sleep(.25)
            state = launchctl("print", domain + "/" + label)
            print("\n".join(line.strip() for line in state.stdout.splitlines()
                            if line.strip().startswith(("state =", "runs =", "last exit code ="))), file=sys.stderr)
            return 1
        finally:
            stop = launchctl("bootout", domain + "/" + label)
            if stop.returncode:
                raise RuntimeError(f"bootout {domain}/{label}: {stop.stderr}")
            for _ in range(20):
                absent = launchctl("print", domain + "/" + label)
                if absent.returncode == 113:
                    print("Temporary job removed", flush=True)
                    break
                time.sleep(.1)
            else:
                raise RuntimeError(f"Removal unconfirmed for {domain}/{label}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--settings-reader", type=Path, help="Read the device using Apple's BKDevice in an isolated client")
    parser.add_argument("--usb-only", action="store_true", help="Test physical USB arrival before installing the kext")
    args = parser.parse_args()
    sys.exit(main(args.binary, args.usb_only, args.settings_reader))
