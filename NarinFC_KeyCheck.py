#!/usr/bin/env python3
"""Check NarinFC-H7 bootloader and firmware artifacts for public keys and signatures."""

import base64
import io
import json
import struct
import tarfile
import zlib

DESC = bytes([0x4E, 0xCF, 0x4E, 0xA5, 0xA6, 0xB6, 0xF7, 0x29])
SIG = bytes([0x41, 0xA3, 0xE5, 0xF2, 0x65, 0x69, 0x92, 0x07])
SIG_LEN = 72
SIG_VER = 30437

TARGETS = [
    "Tools/bootloaders/NarinFC-H7_bl.bin",
    "Tools/bootloaders/NarinFC-H7_bl.elf",
    "Tools/bootloaders/NarinFC-H7_bl.hex",
    "build/NarinFC-H7/bin/AP_Bootloader.apj",
    "build/NarinFC-H7/bin/AP_Bootloader.bin",
    "build/NarinFC-H7/bin/AP_Bootloader.hex",
    "build/NarinFC-H7/bin/arducopter",
    "build/NarinFC-H7/bin/arducopter.apj",
    "build/NarinFC-H7/bin/arducopter.bin",
    "build/NarinFC-H7/bin/arducopter_with_bl.hex",
    "build/NarinFC-H7/bin/arduplane",
    "build/NarinFC-H7/bin/arduplane.apj",
    "build/NarinFC-H7/bin/arduplane.bin",
    "build/NarinFC-H7/bin/arduplane_with_bl.hex",
]


def load_key(path, kind):
    text = open(path).read().strip()
    prefix = kind + "_KEYV1:"
    raw = base64.b64decode(text.split(":", 1)[1]) if text.startswith(prefix) else b""
    print(f"{path}: prefix={text.startswith(prefix)} bytes={len(raw)}")
    return raw


def decode_ihex(text):
    """Return contiguous data runs from an Intel HEX file."""
    runs = []
    upper = 0
    cur = None
    cur_end = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(":") or len(line) < 11:
            continue
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError:
            continue
        count = raw[0]
        addr = (raw[1] << 8) | raw[2]
        rtype = raw[3]
        data = raw[4:4 + count]
        if len(data) != count:
            continue
        if rtype == 0:
            abs_addr = upper + addr
            if cur is not None and abs_addr == cur_end:
                cur.extend(data)
                cur_end += len(data)
            else:
                cur = bytearray(data)
                runs.append(cur)
                cur_end = abs_addr + len(data)
        elif rtype == 4 and len(data) == 2:
            upper = int.from_bytes(data, "big") << 16
        elif rtype == 2 and len(data) == 2:
            upper = int.from_bytes(data, "big") << 4
        elif rtype == 1:
            break
    return [bytes(run) for run in runs]


def key_slots(blob, pub):
    """Return (indexes matching pub, used slot count) for a real key table."""
    found = []
    start = 0
    while True:
        off = blob.find(DESC, start)
        if off < 0:
            break
        start = off + 1
        end = off + 8 + 320
        if end > len(blob):
            continue
        keys = [blob[off + 8 + i * 32:off + 40 + i * 32] for i in range(10)]
        kinds = []
        for key in keys:
            zeros = key.count(0)
            if zeros == 32:
                kinds.append("empty")
            elif zeros <= 3:
                kinds.append("key")
            else:
                kinds.append("invalid")
        if "invalid" in kinds:
            continue
        used = kinds.count("key")
        if kinds != ["key"] * used + ["empty"] * (10 - used):
            continue
        match = [i for i, key in enumerate(keys) if key == pub]
        found.append((match, used))
    if not found:
        return None
    matched = [item for item in found if item[0]]
    return matched[0] if matched else found[0]


def signature(blob):
    start = 0
    while True:
        off = blob.find(SIG, start)
        if off < 0:
            return None
        start = off + 1
        if off + 100 > len(blob):
            continue
        siglen, sigver = struct.unpack_from("<IQ", blob, off + 24)
        if siglen == SIG_LEN and sigver == SIG_VER:
            nonzero = any(blob[off + 36:off + 100])
            return siglen, sigver, nonzero
    return None


def payloads_of(name, data):
    """Decode a file into the blobs that should be searched."""
    lower = name.lower()
    note = None
    if lower.endswith(".hex"):
        return note, decode_ihex(data.decode("ascii", errors="replace"))
    if lower.endswith(".apj"):
        apj = json.loads(data.decode("utf-8"))
        note = "board_id={board_id} image_size={image_size}".format(
            board_id=apj.get("board_id"),
            image_size=apj.get("image_size"),
        )
        img = zlib.decompress(base64.b64decode(apj["image"]))
        return note, [img]
    return note, [data]


def report(parts, pub, priv, indent="  "):
    slots = None
    sig = None
    for blob in parts:
        found = key_slots(blob, pub)
        if found is not None and (slots is None or found[0] or (slots[1] == 0 and found[1] > 0)):
            slots = found
        if sig is None:
            sig = signature(blob)
    pub_inside = any(pub in blob for blob in parts)
    priv_inside = any(priv in blob for blob in parts)
    print(f"{indent}public-key-slots {slots} public-key-inside {pub_inside} private-key-inside {priv_inside}")
    if sig is None:
        print(f"{indent}signature signed-descriptor-absent")
    else:
        siglen, sigver, nonzero = sig
        print(f"{indent}signature siglen={siglen} ver={sigver} nonzero={nonzero}")
    priv_mark = "O" if priv_inside else "X"
    pub_mark = "O" if pub_inside else "X"
    sig_mark = "O" if sig is not None and sig[2] else "X"
    print(f"{indent}private_key : {priv_mark} / public_key : {pub_mark} / signature : {sig_mark}")


def check_path(path, pub, priv):
    try:
        data = open(path, "rb").read()
    except FileNotFoundError:
        print(path)
        print("  존재하지 않음")
        return
    except OSError as exc:
        print(path)
        print(f"  unreadable {exc}")
        return
    print(f"{path} ({len(data)} bytes)")
    if path.lower().endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            if not members:
                print("  empty-archive")
            for member in members:
                extracted = archive.extractfile(member)
                payload = extracted.read() if extracted is not None else b""
                print(f"  member {member.name} ({len(payload)} bytes)")
                note, parts = payloads_of(member.name, payload)
                if note:
                    print(f"    {note}")
                report(parts, pub, priv, indent="    ")
        return
    note, parts = payloads_of(path, data)
    if note:
        print(f"  {note}")
    report(parts, pub, priv)


def main():
    priv = load_key("NarinFC_private_key.dat", "PRIVATE")
    pub = load_key("NarinFC_public_key.dat", "PUBLIC")
    print()
    for path in TARGETS:
        check_path(path, pub, priv)
        print()


if __name__ == "__main__":
    main()
