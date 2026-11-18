#!/usr/bin/env python3
"""Annotate the copied 24H32 Settings executable without launching it."""
from pathlib import Path
import json
import re
import struct
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
folder = root / "build/research/native-ecosystem-01"
binary = folder / "TouchIDSettings.target"
data = binary.read_bytes()
assert struct.unpack_from(">I", data)[0] == 0xCAFEBABE
for index in range(struct.unpack_from(">I", data, 4)[0]):
    cpu, _, offset, size, _ = struct.unpack_from(">5I", data, 8 + index * 20)
    if cpu == 0x01000007:
        data = data[offset:offset + size]
        break
else:
    raise RuntimeError("No x86_64 slice")
assert struct.unpack_from("<I", data)[0] == 0xFEEDFACF
sections = []
offset = 32
image_uuid = None
pointer_formats = []
for _ in range(struct.unpack_from("<I", data, 16)[0]):
    command, size = struct.unpack_from("<II", data, offset)
    if command == 0x19:
        segment = struct.unpack_from("<II16s4Q4I", data, offset)
        for index in range(segment[-2]):
            section = struct.unpack_from("<16s16s2Q8I", data, offset + 72 + index * 80)
            sections.append((section[0].rstrip(b"\0").decode(), *section[2:5]))
    elif command == 0x1B:
        image_uuid = str(uuid.UUID(bytes=data[offset + 8:offset + 24])).upper()
    elif command == 0x80000034:
        start = struct.unpack_from("<I", data, offset + 8)[0]
        starts = start + struct.unpack_from("<I", data, start + 4)[0]
        for index in range(struct.unpack_from("<I", data, starts)[0]):
            relative = struct.unpack_from("<I", data, starts + 4 + index * 4)[0]
            if relative:
                pointer_formats.append(struct.unpack_from("<H", data, starts + relative + 6)[0])
    offset += size
assert image_uuid == "418ECD95-E742-3847-9621-84135A94B634" and pointer_formats and set(pointer_formats) == {6}


def read(address, count):
    for _, start, size, file_offset in sections:
        if start <= address and address + count <= start + size:
            begin = file_offset + address - start
            return data[begin:begin + count]
    raise ValueError(f"Address outside sections: {address:x}")


def pointer(value):
    assert not value >> 63
    return 0x100000000 + (value & ((1 << 36) - 1))


references = {}
for name, start, size, _ in sections:
    if name == "__objc_selrefs":
        for address in range(start, start + size, 8):
            target = pointer(struct.unpack("<Q", read(address, 8))[0])
            content = bytearray()
            while read(target + len(content), 1) != b"\0":
                content.extend(read(target + len(content), 1))
            references[address] = "selector:" + content.decode()
    elif name == "__cfstring":
        for address in range(start, start + size, 32):
            _, flags, raw, length = struct.unpack("<4Q", read(address, 32))
            if flags & 0x10 or length > 4096:
                continue
            try:
                references[address] = "string:" + read(pointer(raw), length).decode()
            except (AssertionError, ValueError, UnicodeError):
                pass
text = subprocess.check_output(["xcrun", "otool", "-arch", "x86_64", "-tvV", str(binary)], text=True)
lines = text.splitlines()
for index, line in enumerate(lines[:-1]):
    rip = re.search(r"(-?0x[0-9a-f]+)\(%rip\)", line)
    following = re.match(r"^([0-9a-f]{16})\s", lines[index + 1])
    if rip and following:
        target = int(following[1], 16) + int(rip[1], 16)
        if target in references:
            lines[index] += " ; " + references[target]
(folder / "settings-disassembly.txt").write_text("\n".join(lines) + "\n")
evidence = root / "evidence/elan-0c1a/native-ecosystem-01"
ranges = [(0x6FB1, 0x72EF, "PSBiometricIdentity device and support"),
          (0xDE4C, 0xE434, "SecurityShared notifications and capability")]
selected = []
for begin, end, name in ranges:
    selected.append(name)
    for line in lines:
        match = re.match(r"^([0-9a-f]{16})\s", line)
        if match and 0x100000000 + begin <= int(match[1], 16) < 0x100000000 + end:
            selected.append(line)
(evidence / "settings-capability-disassembly.txt").write_text("\n".join(selected) + "\n")
print(json.dumps({"uuid": image_uuid, "pointer_formats": pointer_formats, "references": len(references), "process_started": False}))
