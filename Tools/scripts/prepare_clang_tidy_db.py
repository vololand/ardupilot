#!/usr/bin/env python3
"""
Prepare a clang-tidy friendly compile_commands.json from a cross-compiler DB.
"""

import argparse
import json
import os
import pathlib
import shlex
from typing import Any, Dict, List


DROP_FLAGS = {
    "-mno-thumb-interwork",
}


def _is_cpp_source(path: str) -> bool:
    return pathlib.Path(path).suffix.lower() in {".cc", ".cpp", ".cxx", ".c++", ".cp"}


def _ensure_list(entry: Dict[str, Any]) -> List[str]:
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return list(entry["arguments"])
    if "command" in entry and isinstance(entry["command"], str):
        return shlex.split(entry["command"])
    raise ValueError("Each compile DB entry must contain either 'arguments' or 'command'")


def _inject_toolchain_args(args: List[str], toolchain_root: str, target: str) -> List[str]:
    out = []
    if not args:
        return out

    out.append(args[0])
    out.append(f"--target={target}")

    cpp_root = os.path.join(toolchain_root, target, "include", "c++")
    if os.path.isdir(cpp_root):
        versions = sorted(
            [name for name in os.listdir(cpp_root) if os.path.isdir(os.path.join(cpp_root, name))]
        )
        if versions:
            cpp_ver = os.path.join(cpp_root, versions[-1])
            out.append(f"-isystem{cpp_ver}")

            target_cpp = os.path.join(cpp_ver, target)
            if os.path.isdir(target_cpp):
                out.append(f"-isystem{target_cpp}")

            backward = os.path.join(cpp_ver, "backward")
            if os.path.isdir(backward):
                out.append(f"-isystem{backward}")

    c_inc = os.path.join(toolchain_root, target, "include")
    if os.path.isdir(c_inc):
        out.append(f"-isystem{c_inc}")

    gcc_base = os.path.join(toolchain_root, "lib", "gcc", target)
    if os.path.isdir(gcc_base):
        versions = sorted(
            [name for name in os.listdir(gcc_base) if os.path.isdir(os.path.join(gcc_base, name))]
        )
        if versions:
            gcc_inc = os.path.join(gcc_base, versions[-1], "include")
            if os.path.isdir(gcc_inc):
                out.append(f"-isystem{gcc_inc}")

    out.extend(args[1:])
    return out


def transform_entry(entry: Dict[str, Any], toolchain_root: str, target: str) -> Dict[str, Any]:
    original_args = _ensure_list(entry)
    if not original_args:
        return entry

    new_entry: Dict[str, Any] = dict(entry)
    file_path = entry.get("file", "")
    is_cpp = _is_cpp_source(file_path)

    transformed = [arg for arg in original_args if arg not in DROP_FLAGS]
    transformed[0] = "clang++-15" if is_cpp else "clang-15"
    transformed = _inject_toolchain_args(transformed, toolchain_root, target)

    new_entry["arguments"] = transformed
    if "command" in new_entry:
        del new_entry["command"]
    return new_entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a clang-tidy friendly compile_commands.json for cross builds."
    )
    parser.add_argument("--input", required=True, help="Path to input compile_commands.json")
    parser.add_argument("--output", required=True, help="Path to output compile_commands.json")
    parser.add_argument(
        "--toolchain-root",
        default="/opt/gcc-arm-none-eabi-10-2020-q4-major",
        help="Toolchain root that contains bin/, lib/, and <target>/include",
    )
    parser.add_argument("--target", default="arm-none-eabi", help="Compilation target triple")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        db = json.load(f)

    if not isinstance(db, list):
        raise ValueError("compile_commands.json must contain a JSON list")

    transformed = [transform_entry(entry, args.toolchain_root, args.target) for entry in db]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(transformed, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(transformed)} entries to {args.output}")


if __name__ == "__main__":
    main()
