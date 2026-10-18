#!/usr/bin/env python3
"""
GCS-side AUTH smoke test:
AUTH_REQUEST -> AUTH_CHALLENGE -> AUTH_RESPONSE -> AUTH_RESULT
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

# Force MAVLink2 and prefer in-repo pymavlink so this script works
# from a fresh shell without manual environment setup.
REPO_ROOT = Path(__file__).resolve().parents[2]
PYMAVLINK_PARENT = REPO_ROOT / "modules" / "mavlink"
if str(PYMAVLINK_PARENT) not in sys.path:
    sys.path.insert(0, str(PYMAVLINK_PARENT))
os.environ.setdefault("MAVLINK20", "1")

from pymavlink import mavutil  # noqa: E402


def wait_msg(master: mavutil.mavfile, msg_type: str, timeout: float):
    msg = master.recv_match(type=msg_type, blocking=True, timeout=timeout)
    if msg is None:
        raise TimeoutError(f"timeout waiting for {msg_type}")
    return msg


def to_bytes(field, expected_len: int, field_name: str) -> bytes:
    data = bytes(field)
    if len(data) != expected_len:
        raise ValueError(f"{field_name} length mismatch: {len(data)} != {expected_len}")
    return data


def run_auth(
    master: mavutil.mavfile,
    target_system: int,
    user: str,
    password: str,
    timeout: float,
    replay_check: bool,
) -> int:
    user_ascii = user.encode("ascii")
    if len(user_ascii) > 31:
        raise ValueError("user must be <=31 ascii chars")

    print(f"[1] AUTH_REQUEST -> user='{user}'")
    master.mav.auth_request_send(target_system, 0, user_ascii)

    challenge = wait_msg(master, "AUTH_CHALLENGE", timeout)
    challenge_nonce = to_bytes(challenge.challenge, 8, "challenge")
    user_salt = to_bytes(challenge.user_salt, 16, "user_salt")
    ts = int(challenge.timestamp)
    print(
        f"[2] AUTH_CHALLENGE <- challenge={challenge_nonce.hex()} "
        f"salt={user_salt.hex()} ts={ts}"
    )

    h = hashlib.sha256(password.encode("utf-8") + user_salt).digest()
    r = hashlib.sha256(h + challenge_nonce).digest()
    print(f"[3] AUTH_RESPONSE -> R={r.hex()[:32]}...")
    master.mav.auth_response_send(r, ts)

    result = wait_msg(master, "AUTH_RESULT", timeout)
    accepted = int(result.result) == 0
    print(f"[4] AUTH_RESULT <- {'ACCEPTED' if accepted else 'FAILED'}")
    if not accepted:
        return 2

    if replay_check:
        print("[5] REPLAY_CHECK -> resend same AUTH_RESPONSE")
        master.mav.auth_response_send(r, ts)
        replay_res = wait_msg(master, "AUTH_RESULT", timeout)
        replay_ok = int(replay_res.result) != 0
        print(f"[6] REPLAY_RESULT <- {'FAILED(expected)' if replay_ok else 'ACCEPTED(unexpected)'}")
        if not replay_ok:
            return 3
    return 0


def connect(link: str, source_system: int, source_component: int) -> mavutil.mavfile:
    mavutil.set_dialect("storm32")
    if not hasattr(mavutil.mavlink.MAVLink(None), "auth_request_send"):
        raise RuntimeError(
            "storm32 AUTH dialect not loaded. Regenerate dialect with:\n"
            "python3 modules/mavlink/pymavlink/tools/mavgen.py "
            "--lang Python --wire-protocol 2.0 "
            "--output modules/mavlink/pymavlink/dialects/v20/storm32.py "
            "modules/mavlink/message_definitions/v1.0/storm32.xml"
        )
    master = mavutil.mavlink_connection(
        link,
        source_system=source_system,
        source_component=source_component,
    )
    return master


def stream_messages(master: mavutil.mavfile, timeout: float, only_statustext: bool) -> None:
    print("Streaming MAVLink messages... (Ctrl+C to stop)")
    while True:
        msg = master.recv_match(blocking=True, timeout=timeout)
        if msg is None:
            continue

        mtype = msg.get_type()
        if mtype == "BAD_DATA":
            continue
        if only_statustext and mtype != "STATUSTEXT":
            continue

        src_sys = msg.get_srcSystem()
        src_comp = msg.get_srcComponent()
        print(f"[RX] {mtype} sys={src_sys} comp={src_comp} {msg.to_dict()}")


def main() -> int:
    parser = argparse.ArgumentParser(description="AUTH login smoke test using pymavlink.")
    parser.add_argument("--link", default="udp:127.0.0.1:14550", help="mavlink link string")
    parser.add_argument("--user", required=True, help="user id")
    parser.add_argument("--password", required=True, help="password")
    parser.add_argument("--target-system", type=int, default=1)
    parser.add_argument("--source-system", type=int, default=255)
    parser.add_argument("--source-component", type=int, default=190)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--wait-heartbeat",
        action="store_true",
        help="wait for heartbeat before sending AUTH_REQUEST",
    )
    parser.add_argument(
        "--replay-check",
        action="store_true",
        help="resend same AUTH_RESPONSE once and expect FAILED",
    )
    parser.add_argument(
        "--stream-after-login",
        action="store_true",
        help="keep receiving and printing MAVLink messages after login success until Ctrl+C",
    )
    parser.add_argument(
        "--stream-statustext-only",
        action="store_true",
        help="when streaming, print only STATUSTEXT messages",
    )
    args = parser.parse_args()

    try:
        print(f"Using pymavlink: {mavutil.__file__}")
        master = connect(args.link, args.source_system, args.source_component)
        if args.wait_heartbeat:
            print("Waiting heartbeat ...")
            hb = wait_msg(master, "HEARTBEAT", args.timeout)
            print(f"Heartbeat from sys={hb.get_srcSystem()} comp={hb.get_srcComponent()}")

        rc = run_auth(
            master=master,
            target_system=args.target_system,
            user=args.user,
            password=args.password,
            timeout=args.timeout,
            replay_check=args.replay_check,
        )
        if rc == 0:
            print("Authentication smoke test: PASS")
            if args.stream_after_login:
                stream_messages(master, args.timeout, args.stream_statustext_only)
        else:
            print("Authentication smoke test: FAIL")
        return rc
    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
