#!/usr/bin/env python3
"""
Manage AUTH credential DB(auth.dat): add, update, upsert, delete, list users.

Record format (80 bytes):
  user_id[32] | pw_hash[32] | user_salt[16]
Total records: 10
"""

import argparse
import hashlib
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

MAX_USERS = 10
USER_ID_LEN = 32
PW_HASH_LEN = 32
USER_SALT_LEN = 16
RECORD_LEN = USER_ID_LEN + PW_HASH_LEN + USER_SALT_LEN
EXPECTED_DB_LEN = MAX_USERS * RECORD_LEN
USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,31}$")


@dataclass
class AuthRecord:
    user_id: bytes
    pw_hash: bytes
    user_salt: bytes

    def is_empty(self) -> bool:
        return (
            self.user_id[0] == 0
            and self.pw_hash == b"\x00" * PW_HASH_LEN
            and self.user_salt == b"\x00" * USER_SALT_LEN
        )

    def user_str(self) -> str:
        raw = self.user_id.split(b"\x00", 1)[0]
        return raw.decode("ascii", errors="replace")

    def to_bytes(self) -> bytes:
        return self.user_id + self.pw_hash + self.user_salt


def parse_user(user: str) -> str:
    user = user.strip()
    if not USER_ID_PATTERN.fullmatch(user):
        raise ValueError(
            f"invalid user_id '{user}' (allowed: a-z A-Z 0-9 . _ -, len 1..31)"
        )
    return user


def parse_password(password: str) -> None:
    if len(password.encode("utf-8")) > 128:
        raise ValueError("password exceeds 128 bytes")


def pack_user_id(user: str) -> bytes:
    raw = user.encode("ascii")
    return raw + b"\x00" * (USER_ID_LEN - len(raw))


def empty_record() -> AuthRecord:
    return AuthRecord(
        user_id=b"\x00" * USER_ID_LEN,
        pw_hash=b"\x00" * PW_HASH_LEN,
        user_salt=b"\x00" * USER_SALT_LEN,
    )


def empty_db() -> list[AuthRecord]:
    return [empty_record() for _ in range(MAX_USERS)]


def make_record(user: str, password: str) -> AuthRecord:
    user_salt = secrets.token_bytes(USER_SALT_LEN)
    pw_hash = hashlib.sha256(password.encode("utf-8") + user_salt).digest()
    return AuthRecord(user_id=pack_user_id(user), pw_hash=pw_hash, user_salt=user_salt)


def load_db(path: Path) -> list[AuthRecord]:
    blob = path.read_bytes()
    if len(blob) != EXPECTED_DB_LEN:
        raise ValueError(
            f"invalid db size: {len(blob)} (expected {EXPECTED_DB_LEN})"
        )

    records: list[AuthRecord] = []
    for i in range(MAX_USERS):
        start = i * RECORD_LEN
        rec = blob[start : start + RECORD_LEN]
        records.append(
            AuthRecord(
                user_id=rec[:USER_ID_LEN],
                pw_hash=rec[USER_ID_LEN : USER_ID_LEN + PW_HASH_LEN],
                user_salt=rec[USER_ID_LEN + PW_HASH_LEN :],
            )
        )
    return records


def save_db(path: Path, records: list[AuthRecord]) -> None:
    if len(records) != MAX_USERS:
        raise ValueError(f"record count must be {MAX_USERS}")
    blob = bytearray()
    for rec in records:
        blob.extend(rec.to_bytes())
    path.write_bytes(blob)


def find_user_index(records: list[AuthRecord], user: str) -> int:
    for idx, rec in enumerate(records):
        if not rec.is_empty() and rec.user_str() == user:
            return idx
    return -1


def find_empty_index(records: list[AuthRecord]) -> int:
    for idx, rec in enumerate(records):
        if rec.is_empty():
            return idx
    return -1


def list_users(records: list[AuthRecord], show_empty: bool = False) -> None:
    used = 0
    print("-" * 80)
    for idx, rec in enumerate(records):
        if rec.is_empty() and not show_empty:
            continue
        if not rec.is_empty():
            used += 1
        display_idx = idx + 1
        state = "USED " if not rec.is_empty() else "EMPTY"
        print(f"[{display_idx:02d}] {state}")
        print(f"  user_id   : {rec.user_str() if not rec.is_empty() else '(empty)'}")
        print(f"  pw_hash   : {rec.pw_hash.hex()}")
        print(f"  user_salt : {rec.user_salt.hex()}")
        print("-" * 80)
    print(f"Users: {used}/{MAX_USERS}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage AUTH credential DB(auth.dat)."
    )
    parser.add_argument(
        "--input",
        default="auth.dat",
        help="input auth.dat path (default: auth.dat)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="output path (default: overwrite --input)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list registered users")
    p_list.add_argument(
        "--show-empty",
        action="store_true",
        help="show empty slots too",
    )

    p_add = sub.add_parser("add", help="add new user (fails if user exists)")
    p_add.add_argument("--user", required=True, help="user_id")
    p_add.add_argument("--password", required=True, help="password")

    p_update = sub.add_parser("update", help="update password (fails if user not found)")
    p_update.add_argument("--user", required=True, help="user_id")
    p_update.add_argument("--password", required=True, help="new password")

    p_upsert = sub.add_parser("upsert", help="add user or update password")
    p_upsert.add_argument("--user", required=True, help="user_id")
    p_upsert.add_argument("--password", required=True, help="new password")

    p_delete = sub.add_parser("delete", help="delete user")
    p_delete.add_argument("--user", required=True, help="user_id")

    args = parser.parse_args()
    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else in_path

    if not in_path.exists():
        if args.cmd in ("add", "upsert"):
            records = empty_db()
            print(f"[INFO] input file not found, creating new db: {in_path}")
        else:
            print(f"[ERROR] file not found: {in_path}")
            return 1
    else:
        try:
            records = load_db(in_path)
        except ValueError as e:
            print(f"[ERROR] {e}")
            return 1

    if args.cmd == "list":
        list_users(records, show_empty=args.show_empty)
        return 0

    if args.cmd in ("add", "update", "upsert"):
        try:
            user = parse_user(args.user)
            parse_password(args.password)
        except ValueError as e:
            print(f"[ERROR] {e}")
            return 1

        idx = find_user_index(records, user)
        if args.cmd == "add":
            if idx >= 0:
                print(f"[ERROR] user already exists: '{user}'")
                return 1
            empty_idx = find_empty_index(records)
            if empty_idx < 0:
                print("[ERROR] no empty slot available (max users reached)")
                return 1
            records[empty_idx] = make_record(user, args.password)
            print(f"Added user '{user}' at slot {empty_idx}")
        elif args.cmd == "update":
            if idx < 0:
                print(f"[ERROR] user not found: '{user}'")
                return 1
            records[idx] = make_record(user, args.password)
            print(f"Updated user '{user}' at slot {idx}")
        else:
            if idx >= 0:
                records[idx] = make_record(user, args.password)
                print(f"Updated user '{user}' at slot {idx}")
            else:
                empty_idx = find_empty_index(records)
                if empty_idx < 0:
                    print("[ERROR] no empty slot available (max users reached)")
                    return 1
                records[empty_idx] = make_record(user, args.password)
                print(f"Added user '{user}' at slot {empty_idx}")

    if args.cmd == "delete":
        try:
            user = parse_user(args.user)
        except ValueError as e:
            print(f"[ERROR] {e}")
            return 1

        idx = find_user_index(records, user)
        if idx < 0:
            print(f"[ERROR] user not found: '{user}'")
            return 1
        records[idx] = empty_record()
        print(f"Deleted user '{user}' from slot {idx}")

    try:
        save_db(out_path, records)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1

    print(f"Wrote {out_path} ({EXPECTED_DB_LEN} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
