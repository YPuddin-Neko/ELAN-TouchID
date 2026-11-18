#!/usr/bin/env python3
"""Disassemble selected system methods copied by our own metadata process."""
import base64
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

root = Path(__file__).resolve().parents[2]
evidence = root / "evidence/elan-0c1a/native-ecosystem-01"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, default=evidence / "native-enrollment-ui-code.json")
parser.add_argument("--output", type=Path, default=evidence / "native-enrollment-ui-disassembly.txt")
parser.add_argument("--objects", type=Path, default=root / "build/research/native-ecosystem-01/ui-code")
args = parser.parse_args()
source = json.loads(args.source.read_text())
out = args.objects
out.mkdir(parents=True, exist_ok=True)
references = {int(key): value for key, value in source["references"].items()}
references.update({int(key): value for key, value in source["symbols"].items()})
sections = [(item["name"], item["address"], base64.b64decode(item["bytes"])) for item in source.get("sections", [])]
reports = []
for function in source["functions"]:
    code = base64.b64decode(function["bytes"])
    address = function["address"]
    header = struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 1, 1, 152, 0, 0)
    segment = struct.pack("<II16s4Q4I", 0x19, 152, b"__TEXT", address, len(code), 184, len(code), 7, 5, 1, 0)
    section = struct.pack("<16s16s2Q8I", b"__text", b"__TEXT", address, len(code), 184, 0, 0, 0, 0x80000400, 0, 0, 0)
    binary = out / (function["name"].replace(":", "_") + ".o")
    binary.write_bytes(header + segment + section + code)
    result = subprocess.run(["xcrun", "otool", "-tvV", str(binary)], capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    for index, line in enumerate(lines):
        instruction = re.match(r"^([0-9a-f]{16})\s+", line)
        if not instruction:
            continue
        next_address = None
        if index + 1 < len(lines):
            following = re.match(r"^([0-9a-f]{16})\s+", lines[index + 1])
            if following:
                next_address = int(following.group(1), 16)
        comments = []
        rip = re.search(r"(-?0x[0-9a-f]+)\(%rip\)", line)
        if rip and next_address is not None:
            target = next_address + int(rip.group(1), 16)
            if target in references:
                comments.append(references[target])
            else:
                for name, base, data in sections:
                    offset = target - base
                    if 0 <= offset <= len(data) - 4:
                        value = struct.unpack_from("<I", data, offset)[0]
                        if name == "__objc_ivar" and str(value) in source.get("ivars", {}):
                            comments.append("ivar-offset:" + source["ivars"][str(value)])
                        elif name == "__const":
                            comments.append(f"constant:u32={value} float={struct.unpack_from('<f', data, offset)[0]}")
        direct = re.search(r"\b(?:callq|jmp)\s+0x([0-9a-f]+)", line)
        if direct and int(direct.group(1), 16) in references:
            comments.append(references[int(direct.group(1), 16)])
        if comments:
            lines[index] = line + " ; " + " | ".join(comments)
    reports.append(function["name"] + "\n" + "\n".join(lines) + "\n")
args.output.write_text("\n".join(reports))
print(json.dumps({"methods": len(reports), "system_service_changed": False}))
