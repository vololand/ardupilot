#!/usr/bin/env python3
"""
Run NarinFC-X3 static analysis pipeline (cppcheck + clang-tidy).

AP_FLAKE8_CLEAN
"""

import argparse
import collections
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, "../.."))

HIGH_CWES = {
    119, 120, 121, 122, 124, 125, 126, 127, 131, 134, 190, 191, 415, 416, 476, 787, 788
}
MEDIUM_CWES = {401, 457, 704, 758}


def run_cmd(cmd: List[str], cwd: str, desc: str, check: bool = True) -> int:
    print(f"[run] {desc}", flush=True)
    print("      " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=cwd, check=False)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return proc.returncode


def classify_priority(cwe: int, severity: str, err_id: str, msg: str) -> str:
    if err_id == "preprocessorErrorDirective" and "Unknown compiler" in msg:
        # Tool configuration issue in vendor headers, not an application vulnerability.
        return "Low"
    if cwe in HIGH_CWES:
        return "High"
    if cwe in MEDIUM_CWES:
        return "Medium"
    if severity == "error":
        return "High"
    if severity == "warning":
        return "Medium"
    return "Low"


def generate_cwe_priority_report(cppcheck_xml: str, report_file: str) -> None:
    if not os.path.exists(cppcheck_xml) or os.path.getsize(cppcheck_xml) == 0:
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# CWE Priority Report (cppcheck)\n\n")
            f.write("cppcheck XML is missing or empty.\n")
        return

    try:
        tree = ET.parse(cppcheck_xml)
    except ET.ParseError:
        with open(cppcheck_xml, "r", encoding="utf-8", errors="replace") as src:
            raw_preview = src.read(512).strip()
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# CWE Priority Report (cppcheck)\n\n")
            f.write("cppcheck output is not valid XML.\n\n")
            f.write("Raw output preview:\n")
            f.write(raw_preview + "\n")
        return

    root = tree.getroot()
    errors = root.findall(".//error")

    grouped: Dict[str, List[Tuple[int, str]]] = {"High": [], "Medium": [], "Low": []}
    cwe_counter: Dict[str, collections.Counter] = {
        "High": collections.Counter(),
        "Medium": collections.Counter(),
        "Low": collections.Counter(),
    }
    detail_lines: Dict[str, List[str]] = {"High": [], "Medium": [], "Low": []}

    for err in errors:
        severity = err.get("severity", "unknown")
        err_id = err.get("id", "unknown")
        msg = err.get("msg", "").strip()
        cwe_raw = err.get("cwe", "")
        try:
            cwe = int(cwe_raw) if cwe_raw else 0
        except ValueError:
            cwe = 0
        priority = classify_priority(cwe, severity, err_id, msg)
        cwe_label = f"CWE-{cwe}" if cwe > 0 else "CWE-N/A"
        grouped[priority].append((cwe, severity))
        cwe_counter[priority][cwe_label] += 1

        location = err.find("location")
        loc = ""
        if location is not None:
            file_path = location.get("file", "")
            line = location.get("line", "")
            if file_path:
                loc = f"{file_path}:{line}" if line else file_path
        detail_lines[priority].append(f"- [{cwe_label}] ({severity}) {err_id} :: {loc} :: {msg}")

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# CWE Priority Report (cppcheck)\n\n")
        total = sum(len(v) for v in grouped.values())
        f.write(f"- Total findings: {total}\n")
        f.write(f"- High: {len(grouped['High'])}\n")
        f.write(f"- Medium: {len(grouped['Medium'])}\n")
        f.write(f"- Low: {len(grouped['Low'])}\n\n")

        for level in ("High", "Medium", "Low"):
            f.write(f"## {level}\n")
            if not grouped[level]:
                f.write("- None\n\n")
                continue
            f.write("- Top CWE counts:\n")
            for cwe_label, count in cwe_counter[level].most_common(10):
                f.write(f"  - {cwe_label}: {count}\n")
            f.write("- Findings:\n")
            for line in detail_lines[level][:50]:
                f.write(f"  {line}\n")
            if len(detail_lines[level]) > 50:
                f.write(f"  - ... truncated ({len(detail_lines[level]) - 50} more)\n")
            f.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run static analysis for NarinFC-X3 using cppcheck and clang-tidy."
    )
    parser.add_argument("--board", default="NarinFC-X3", help="WAF board name")
    parser.add_argument("--out", default="build_x3_scan", help="WAF output directory")
    parser.add_argument("--target", default="copter", help="WAF target to build")
    parser.add_argument(
        "--file-filter",
        default="libraries/AP_MultiHeap/*.cpp",
        help="cppcheck --file-filter pattern",
    )
    parser.add_argument(
        "--clang-files",
        nargs="*",
        default=[
            "libraries/AP_MultiHeap/AP_MultiHeap.cpp",
            "libraries/AP_MultiHeap/MultiHeap_chibios.cpp",
            "libraries/AP_MultiHeap/MultiHeap_malloc.cpp",
        ],
        help="Source files passed to clang-tidy",
    )
    parser.add_argument(
        "--clang-checks",
        default="-*,clang-analyzer-*,bugprone-*,cert-*",
        help="clang-tidy checks expression",
    )
    parser.add_argument(
        "--clang-header-filter",
        default="",
        help="Optional clang-tidy -header-filter regex for user headers",
    )
    parser.add_argument(
        "--toolchain-root",
        default="/opt/gcc-arm-none-eabi-10-2020-q4-major",
        help="ARM GCC toolchain root used by compile DB sanitizer",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip waf configure/build and use existing compile database",
    )
    parser.add_argument(
        "--skip-cppcheck",
        action="store_true",
        help="Skip cppcheck stage",
    )
    parser.add_argument(
        "--skip-clang-tidy",
        action="store_true",
        help="Skip clang-tidy stage",
    )
    parser.add_argument(
        "--strict-exit",
        action="store_true",
        help="Return non-zero if cppcheck/clang-tidy returns non-zero",
    )
    parser.add_argument(
        "--skip-cwe-report",
        action="store_true",
        help="Skip generating CWE priority report from cppcheck XML",
    )
    args = parser.parse_args()

    out_dir = os.path.join(ROOT_DIR, args.out)
    compile_db = os.path.join(out_dir, args.board, "compile_commands.json")
    clang_db_dir = os.path.join(out_dir, f"{args.board}-clang-tidy")
    clang_db = os.path.join(clang_db_dir, "compile_commands.json")
    cppcheck_xml = os.path.join(out_dir, "cppcheck_x3.xml")
    cwe_report = os.path.join(out_dir, "cppcheck_cwe_priority_report.txt")
    clang_tidy_log = os.path.join(out_dir, "clang_tidy_x3.txt")
    sanitizer_script = os.path.join(ROOT_DIR, "Tools/scripts/prepare_clang_tidy_db.py")

    os.makedirs(out_dir, exist_ok=True)

    try:
        if not args.skip_build:
            run_cmd(
                ["./waf", "configure", "--board", args.board, "--out", args.out],
                cwd=ROOT_DIR,
                desc="Configure board build",
            )
            run_cmd(
                ["./waf", "--out", args.out, args.target],
                cwd=ROOT_DIR,
                desc="Build target",
            )

        if not os.path.exists(compile_db):
            print(f"[error] compile_commands.json not found: {compile_db}")
            return 2

        run_cmd(
            [
                sys.executable,
                sanitizer_script,
                "--input",
                compile_db,
                "--output",
                clang_db,
                "--toolchain-root",
                args.toolchain_root,
            ],
            cwd=ROOT_DIR,
            desc="Prepare clang-tidy compile database",
        )

        if not args.skip_cppcheck:
            print(f"[run] cppcheck xml output -> {cppcheck_xml}", flush=True)
            cppcheck_cmd = [
                "cppcheck",
                f"--project={compile_db}",
                f"--file-filter={args.file_filter}",
                "--enable=warning,style,performance,portability",
                "--inconclusive",
                "--suppress=missingIncludeSystem",
                "--suppress=preprocessorErrorDirective:modules/ChibiOS/os/common/ext/ARM/CMSIS/Core/Include/cmsis_compiler.h",
                "--xml",
                "--xml-version=2",
            ]
            with open(cppcheck_xml, "w", encoding="utf-8") as xml_file:
                proc = subprocess.run(cppcheck_cmd, cwd=ROOT_DIR, stdout=subprocess.DEVNULL, stderr=xml_file)
            if os.path.getsize(cppcheck_xml) == 0:
                # Retry with a more permissive file filter for project-path mismatches.
                print("[warn] cppcheck XML was empty; retrying with fallback file filter", flush=True)
                fallback_cmd = [
                    "--file-filter=*AP_MultiHeap*.cpp" if arg.startswith("--file-filter=") else arg
                    for arg in cppcheck_cmd
                ]
                with open(cppcheck_xml, "w", encoding="utf-8") as xml_file:
                    retry_proc = subprocess.run(
                        fallback_cmd,
                        cwd=ROOT_DIR,
                        stdout=subprocess.DEVNULL,
                        stderr=xml_file,
                    )
                proc = retry_proc
            if os.path.getsize(cppcheck_xml) == 0:
                # Some environments can emit XML on stdout. Retry once with swapped streams.
                print("[warn] cppcheck XML still empty; retrying with stdout capture", flush=True)
                fallback_cmd = [
                    "--file-filter=*AP_MultiHeap*.cpp" if arg.startswith("--file-filter=") else arg
                    for arg in cppcheck_cmd
                ]
                with open(cppcheck_xml, "w", encoding="utf-8") as xml_file:
                    retry_proc = subprocess.run(
                        fallback_cmd,
                        cwd=ROOT_DIR,
                        stdout=xml_file,
                        stderr=subprocess.DEVNULL,
                    )
                proc = retry_proc
            if proc.returncode != 0:
                msg = f"[warn] cppcheck returned exit code {proc.returncode}"
                if args.strict_exit:
                    print(msg.replace("[warn]", "[error]"), flush=True)
                    return proc.returncode
                print(msg + " (continuing; use --strict-exit to fail)", flush=True)

        if not args.skip_cppcheck and not args.skip_cwe_report:
            print(f"[run] cwe report output -> {cwe_report}", flush=True)
            generate_cwe_priority_report(cppcheck_xml, cwe_report)

        if not args.skip_clang_tidy:
            print(f"[run] clang-tidy log -> {clang_tidy_log}", flush=True)
            clang_cmd = [
                "clang-tidy-15",
                "-p",
                clang_db_dir,
                *args.clang_files,
                f"-checks={args.clang_checks}",
                "--extra-arg=-Wno-unknown-warning-option",
                "--extra-arg=-Wno-ignored-optimization-argument",
                "--extra-arg=-Wno-error=unused-command-line-argument",
            ]
            if args.clang_header_filter:
                clang_cmd.append(f"-header-filter={args.clang_header_filter}")
            with open(clang_tidy_log, "w", encoding="utf-8") as log_file:
                proc = subprocess.run(clang_cmd, cwd=ROOT_DIR, stdout=log_file, stderr=subprocess.STDOUT)
            if proc.returncode != 0:
                msg = f"[warn] clang-tidy returned exit code {proc.returncode}"
                if args.strict_exit:
                    print(msg.replace("[warn]", "[error]"), flush=True)
                    print(f"[hint] inspect {clang_tidy_log}", flush=True)
                    return proc.returncode
                print(msg + " (continuing; use --strict-exit to fail)", flush=True)
                print(f"[hint] inspect {clang_tidy_log}", flush=True)

    except subprocess.CalledProcessError as err:
        print(f"[error] command failed ({err.returncode}): {' '.join(err.cmd)}", flush=True)
        return err.returncode

    print("[done] static analysis pipeline completed", flush=True)
    print(f"       compile DB  : {compile_db}", flush=True)
    print(f"       clang DB    : {clang_db}", flush=True)
    if not args.skip_cppcheck:
        print(f"       cppcheck xml: {cppcheck_xml}", flush=True)
        if not args.skip_cwe_report:
            print(f"       cwe report  : {cwe_report}", flush=True)
    if not args.skip_clang_tidy:
        print(f"       clang log   : {clang_tidy_log}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
