#!/usr/bin/env python3
"""
Decrypt NarinFC-H7-style ArduPilot SD logs written with Monocypher crypto_lock
(XChaCha20-Poly1305). Requires pymonocypher 3.1.3.2:
  python3 -m pip install pymonocypher==3.1.3.2

File layout:
  - 32-byte header: magic b'APLGXC20', version u8, 7 reserved, 16-byte salt
  - repeating records: be32 plaintext_len, be64 seq, 16-byte MAC, ciphertext
    Nonce for each record: salt (16) || seq (8 big-endian).
"""

import argparse
import struct
import sys

MAGIC = b"APLGXC20"
HDR_SIZE = 32
REC_PREFIX = 12  # len + seq


def main():
    ap = argparse.ArgumentParser(description="Decrypt AP SD log (XChaCha20-Poly1305 / Monocypher)")
    ap.add_argument("encrypted", help="Input .BIN from FC")
    ap.add_argument("output", help="Output plain DataFlash log")
    ap.add_argument(
        "--key-hex",
        required=True,
        help="32-byte AES-style key as 64 hex chars (must match HAL_LOGGING_FILE_XCHACHA20_KEY)",
    )
    args = ap.parse_args()

    try:
        import monocypher
    except ImportError:
        print("Install pymonocypher: python3 -m pip install pymonocypher==3.1.3.2", file=sys.stderr)
        return 1
    if getattr(monocypher, "__version__", None) != "3.1.3.2":
        print("Expected pymonocypher 3.1.3.2 (ArduPilot toolchain pin)", file=sys.stderr)
        return 1

    key = bytes.fromhex(args.key_hex)
    if len(key) != 32:
        print("--key-hex must decode to 32 bytes", file=sys.stderr)
        return 1

    with open(args.encrypted, "rb") as inf:
        buf = inf.read()
    if len(buf) < HDR_SIZE or buf[:8] != MAGIC:
        print("Not an APLGXC20 log (bad magic or too short)", file=sys.stderr)
        return 1
    ver = buf[8]
    if ver != 1:
        print(f"Unsupported version {ver}", file=sys.stderr)
        return 1
    salt = buf[16:32]
    off = HDR_SIZE
    out = bytearray()

    while off + REC_PREFIX + 16 <= len(buf):
        plen, seq = struct.unpack(">IQ", buf[off : off + REC_PREFIX])
        off += REC_PREFIX
        mac = buf[off : off + 16]
        off += 16
        if plen > len(buf) - off:
            print("Truncated ciphertext", file=sys.stderr)
            return 1
        ct = buf[off : off + plen]
        off += plen
        nonce = salt + struct.pack(">Q", seq)
        plain = monocypher.unlock(key, nonce, mac, ct)
        if plain is None:
            print(f"Decrypt/auth failed at seq={seq}", file=sys.stderr)
            return 1
        out.extend(plain)

    with open(args.output, "wb") as o:
        o.write(out)
    print(f"Wrote {len(out)} bytes to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
