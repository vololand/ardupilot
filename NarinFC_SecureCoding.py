#!/usr/bin/env python3
"""NarinFC-H7 Plane/Copter 펌웨어 보안약점 점검 3단계.

filelist는 NarinFC-H7-secure-coding-report_YYYY_MM_DD_HH_MI_SS 폴더를 만든다.
cppcheck와 classify는 가장 최근의 그 폴더를 사용한다.
copter와 plane은 ./waf로 해당 기체만 빌드한다.
all은 copter와 plane을 빌드한 뒤 filelist, cppcheck, classify를 실행한다.

사용 예:
  python3 NarinFC_SecureCoding.py copter
  python3 NarinFC_SecureCoding.py plane
  python3 NarinFC_SecureCoding.py filelist
  python3 NarinFC_SecureCoding.py filelist plane
  python3 NarinFC_SecureCoding.py filelist copter
  python3 NarinFC_SecureCoding.py cppcheck
  python3 NarinFC_SecureCoding.py classify
  python3 NarinFC_SecureCoding.py all
"""

import csv
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_PREFIX = "NarinFC-H7-secure-coding-report"
REPORT_DIR_PATTERN = re.compile(
    r"^NarinFC-H7-secure-coding-report_\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}$"
)
COMPILE_DB_SRC = os.path.join(REPO_DIR, "build", "NarinFC-H7", "compile_commands.json")

CATEGORY_NAMES = {
    0: "7항목 제외",
    1: "입력 데이터 검증 및 표현",
    2: "보안기능",
    3: "시간 및 상태",
    4: "에러 처리",
    5: "코드오류",
    6: "캡슐화",
    7: "API 오용",
}

# Cppcheck id -> (항목 번호, 확신, 이유)
ID_MAP = {
    "objectIndex": (1, "낮음", "지역 변수 주소를 배열처럼 인덱싱"),
    "uninitMemberVar": (5, "낮음", "생성자에서 멤버 초기화가 보이지 않음"),
    "uninitMemberVarPrivate": (5, "낮음", "private 멤버 미초기화"),
    "invalidPointerCast": (5, "낮음", "표현이 다른 포인터 간 캐스트"),
    "memsetClassFloat": (5, "중간", "부동소수를 포함한 객체를 memset"),
    "duplicateExpression": (5, "중간", "같은 식이 연산자 양쪽에 있음"),
    "duplicateCondition": (5, "중간", "같은 조건이 반복됨"),
    "unsignedLessThanZero": (5, "낮음", "부호 없는 값과 0 비교"),
    "redundantCondition": (5, "낮음", "항상 참/거짓이 되는 조건"),
    "redundantAssignment": (5, "낮음", "덮어쓰이는 대입"),
    "knownConditionTrueFalse": (5, "낮음", "항상 참 또는 거짓인 조건"),
    "sizeofCalculation": (5, "중간", "sizeof 안에 계산식"),
    "shadowVariable": (5, "낮음", "바깥 변수와 이름이 같은 지역 변수"),
    "shadowFunction": (5, "낮음", "함수 이름 가림"),
    "noCopyConstructor": (5, "낮음", "자원을 가진 클래스에 복사 생성자가 없음"),
    "noOperatorEq": (5, "낮음", "자원을 가진 클래스에 대입 연산자가 없음"),
    "unusedPrivateFunction": (6, "낮음", "private 함수가 쓰이지 않음"),
    "unusedStructMember": (6, "낮음", "구조체 멤버가 쓰이지 않음"),
    "syntaxError": (0, "도구", "Cppcheck 문법 해석 실패"),
    "preprocessorErrorDirective": (0, "도구", "Cppcheck가 #error 분기를 탐"),
}

STYLE_IDS = {
    "funcArgNamesDifferent",
    "noExplicitConstructor",
    "functionConst",
    "functionStatic",
    "noConstructor",
    "variableScope",
    "constParameter",
    "constVariable",
    "useInitializationList",
    "duplInheritedMember",
    "unreadVariable",
    "cstyleCast",
}

CSV_FIELDS = [
    "source",
    "category_no",
    "category_name",
    "confidence",
    "rule",
    "cppcheck_id",
    "severity",
    "cwe",
    "inconclusive",
    "file",
    "line",
    "column",
    "message",
    "primary_location",
]

PATTERNS = [
    (1, "범위 없는 복사", re.compile(r"\b(strcpy|strcat|vsprintf|sprintf|gets)\s*\(")),
    (1, "scanf 계열", re.compile(r"\b(scanf|sscanf|fscanf)\s*\(")),
    (1, "외부 명령 실행", re.compile(r"\b(system|popen)\s*\(")),
    (7, "atoi/atol/atof", re.compile(r"\b(atoi|atol|atof)\s*\(")),
    (7, "strtok", re.compile(r"\bstrtok\s*\(")),
    (7, "alloca", re.compile(r"\balloca\s*\(")),
]


def report_file(report_dir, name):
    """결과 폴더 안의 파일 경로를 만든다."""
    return os.path.join(report_dir, name)


def create_report_dir():
    """생성 시각이 붙은 결과 폴더를 새로 만든다."""
    stamp = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    folder_name = "%s_%s" % (REPORT_PREFIX, stamp)
    report_dir = os.path.join(REPO_DIR, folder_name)
    if os.path.exists(report_dir):
        raise FileExistsError("결과 폴더가 이미 있습니다: %s" % report_dir)
    else:
        try:
            os.makedirs(report_dir)
        except OSError as exc:
            raise OSError("결과 폴더를 만들 수 없습니다: %s" % report_dir) from exc
        else:
            print("결과 폴더: %s" % report_dir)
            return report_dir


def latest_report_dir():
    """가장 최근에 만든 시각 접미사 결과 폴더를 찾는다."""
    try:
        names = os.listdir(REPO_DIR)
    except OSError as exc:
        raise OSError("저장소 폴더를 읽을 수 없습니다: %s" % REPO_DIR) from exc
    else:
        found = []
        for name in names:
            folder_path = os.path.join(REPO_DIR, name)
            if REPORT_DIR_PATTERN.match(name) and os.path.isdir(folder_path):
                found.append(name)
            else:
                continue
        if len(found) == 0:
            raise FileNotFoundError(
                "시간 정보가 붙은 결과 폴더가 없습니다. 먼저 filelist를 실행하세요"
            )
        else:
            found.sort()
            return os.path.join(REPO_DIR, found[-1])


def relative_path(path):
    """저장소 기준 상대 경로로 바꾼다."""
    if not path:
        return ""
    else:
        prefix = REPO_DIR + os.sep
        abs_path = os.path.abspath(path)
        if abs_path.startswith(prefix):
            return abs_path[len(prefix):]
        else:
            return abs_path


def load_compile_commands(path):
    """컴파일 기록 JSON을 읽는다."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise OSError("컴파일 기록을 열 수 없습니다: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError("컴파일 기록 JSON이 올바르지 않습니다: %s" % path) from exc
    else:
        if not isinstance(data, list):
            raise ValueError("컴파일 기록은 배열이어야 합니다: %s" % path)
        else:
            return data


def command_file_path(entry):
    """compile_commands 항목 하나의 소스 경로를 절대 경로로 만든다."""
    path = entry.get("file")
    if not path:
        raise ValueError("compile_commands 항목에 file이 없습니다")
    else:
        if os.path.isabs(path):
            return os.path.abspath(path)
        else:
            directory = entry.get("directory") or REPO_DIR
            return os.path.abspath(os.path.normpath(os.path.join(directory, path)))


def filelist_prefixes(selection):
    """검사 목록에 남길 경로 접두사를 고른다."""
    if selection == "both":
        return ("ArduPlane/", "ArduCopter/", "libraries/")
    elif selection == "plane":
        return ("ArduPlane/", "libraries/")
    elif selection == "copter":
        return ("ArduCopter/", "libraries/")
    else:
        raise ValueError("filelist 기체는 plane, copter 또는 생략(둘 다)만 가능합니다: %s" % selection)


def write_filelist(report_dir, selection="both"):
    """선택한 기체와 libraries만 남긴 검사 목록을 저장한다."""
    prefixes = filelist_prefixes(selection)
    if not os.path.isfile(COMPILE_DB_SRC):
        raise FileNotFoundError(
            "NarinFC-H7 컴파일 기록이 없습니다. 먼저 Plane과 Copter를 빌드하세요: %s" % COMPILE_DB_SRC
        )
    else:
        commands = load_compile_commands(COMPILE_DB_SRC)

    keep = []
    vehicle_count = 0
    for entry in commands:
        rel = relative_path(command_file_path(entry))
        if rel.startswith(prefixes):
            keep.append(entry)
            if rel.startswith(("ArduPlane/", "ArduCopter/")):
                vehicle_count += 1
            else:
                continue
        else:
            continue

    if selection == "plane" and vehicle_count == 0:
        raise ValueError("컴파일 기록에 ArduPlane 소스가 없습니다. 먼저 ./waf plane 을 실행하세요")
    elif selection == "copter" and vehicle_count == 0:
        raise ValueError("컴파일 기록에 ArduCopter 소스가 없습니다. 먼저 ./waf copter 를 실행하세요")
    elif len(keep) == 0:
        raise ValueError("직접 작성 코드가 컴파일 기록에 없습니다")
    else:
        destination = report_file(report_dir, "compile_commands-firstparty.json")
        try:
            with open(destination, "w", encoding="utf-8") as handle:
                json.dump(keep, handle)
        except OSError as exc:
            raise OSError("검사 목록을 저장할 수 없습니다: %s" % destination) from exc
        else:
            print("filelist %s: %d개 (기체 소스 %d개) -> %s" % (selection, len(keep), vehicle_count, destination))
            return len(keep)


def cppcheck_command(compile_db_path):
    """이전 점검과 같은 Cppcheck 인자 목록을 만든다."""
    return [
        "cppcheck",
        "--project=%s" % compile_db_path,
        "--enable=warning,style,portability,performance",
        "--inconclusive",
        "--inline-suppr",
        "--suppress=missingIncludeSystem",
        "--suppress=missingInclude",
        "--suppress=unmatchedSuppression",
        "--suppress=unusedFunction",
        "--suppress=toomanyconfigs",
        "-j20",
        "--quiet",
        "--xml",
        "--xml-version=2",
    ]


def run_cppcheck(report_dir):
    """필터된 목록으로 Cppcheck를 실행하고 XML 원본을 저장한다."""
    compile_db_path = report_file(report_dir, "compile_commands-firstparty.json")
    stdout_path = report_file(report_dir, "cppcheck-stdout.txt")
    xml_path = report_file(report_dir, "cppcheck-raw.xml")
    cppcheck_bin = shutil.which("cppcheck")
    if cppcheck_bin is None:
        raise FileNotFoundError("cppcheck 명령을 찾을 수 없습니다")
    else:
        if not os.path.isfile(compile_db_path):
            raise FileNotFoundError(
                "검사 목록이 없습니다. 먼저 filelist를 실행하세요: %s" % compile_db_path
            )
        else:
            print("결과 폴더: %s" % report_dir)

    command = cppcheck_command(compile_db_path)
    command[0] = cppcheck_bin
    print("cppcheck:", " ".join(command))
    try:
        with open(stdout_path, "w", encoding="utf-8") as stdout_handle, open(
            xml_path, "w", encoding="utf-8"
        ) as xml_handle:
            result = subprocess.run(
                command,
                cwd=REPO_DIR,
                stdout=stdout_handle,
                stderr=xml_handle,
                check=False,
            )
    except OSError as exc:
        raise OSError("cppcheck를 실행할 수 없습니다") from exc
    else:
        if result.returncode != 0:
            raise RuntimeError("cppcheck 종료 코드 %s. 원본: %s" % (result.returncode, xml_path))
        else:
            print("cppcheck 종료 코드 0")
            print("stdout -> %s" % stdout_path)
            print("xml -> %s" % xml_path)
            return result.returncode


def classify_cppcheck_id(checker_id):
    """Cppcheck id를 7항목 번호와 이유에 대응한다."""
    if checker_id in ID_MAP:
        return ID_MAP[checker_id]
    elif checker_id in STYLE_IDS:
        return (0, "스타일", "보안약점 7항목으로 보지 않은 스타일 경고")
    else:
        return (0, "미분류", "분류 규칙에 없는 Cppcheck id")


def blank_row():
    """CSV 한 행의 빈 틀을 만든다."""
    row = {}
    for field in CSV_FIELDS:
        row[field] = ""
    return row


def append_cppcheck_rows(rows, report_dir):
    """XML 원본의 error를 행으로 추가한다."""
    xml_path = report_file(report_dir, "cppcheck-raw.xml")
    if not os.path.isfile(xml_path):
        raise FileNotFoundError("Cppcheck XML이 없습니다. 먼저 cppcheck를 실행하세요: %s" % xml_path)
    else:
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as exc:
            raise ValueError("Cppcheck XML을 해석할 수 없습니다: %s" % xml_path) from exc
        else:
            errors = list(root.iter("error"))

    for err in errors:
        checker_id = err.get("id") or ""
        category_no, confidence, reason = classify_cppcheck_id(checker_id)
        locations = err.findall("location")
        if len(locations) == 0:
            locations = [None]
        else:
            locations = locations
        for index, loc in enumerate(locations):
            row = blank_row()
            row["source"] = "cppcheck"
            row["category_no"] = category_no
            row["category_name"] = CATEGORY_NAMES[category_no]
            row["confidence"] = confidence
            row["rule"] = reason
            row["cppcheck_id"] = checker_id
            row["severity"] = err.get("severity") or ""
            row["cwe"] = err.get("cwe") or ""
            row["inconclusive"] = err.get("inconclusive") or ""
            if loc is None:
                row["file"] = relative_path(err.get("file0"))
                row["line"] = ""
                row["column"] = ""
            else:
                row["file"] = relative_path(loc.get("file"))
                row["line"] = loc.get("line") or ""
                row["column"] = loc.get("column") or ""
            row["message"] = err.get("msg") or ""
            if index == 0:
                row["primary_location"] = "yes"
            else:
                row["primary_location"] = "no"
            rows.append(row)
    return len(errors)


def is_bundled_source(path):
    """펌웨어에 포함되지만 직접 고치기 어려운 번들 소스인지 구분한다."""
    if "/lua/src/" in path or "/sagetech-sdk/" in path or path.endswith("monocypher.cpp"):
        return True
    else:
        return False


def append_pattern_rows(rows, report_dir):
    """위험 함수 패턴을 검사 목록의 소스에서 찾아 행으로 추가한다."""
    compile_db_path = report_file(report_dir, "compile_commands-firstparty.json")
    if not os.path.isfile(compile_db_path):
        raise FileNotFoundError("검사 목록이 없습니다. 먼저 filelist를 실행하세요: %s" % compile_db_path)
    else:
        commands = load_compile_commands(compile_db_path)

    added = 0
    for entry in commands:
        path = command_file_path(entry)
        bundled = is_bundled_source(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError as exc:
            print("READ_FAIL %s %s" % (path, exc), file=sys.stderr)
            continue
        else:
            for lineno, line in enumerate(lines, 1):
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                else:
                    code = line.split("//", 1)[0]
                    for category_no, rule, pattern in PATTERNS:
                        if pattern.search(code):
                            row = blank_row()
                            if bundled:
                                row["source"] = "pattern-bundled"
                                row["rule"] = rule + " (번들 소스)"
                            else:
                                row["source"] = "pattern"
                                row["rule"] = rule
                            row["category_no"] = category_no
                            row["category_name"] = CATEGORY_NAMES[category_no]
                            row["confidence"] = "패턴"
                            row["file"] = relative_path(path)
                            row["line"] = str(lineno)
                            row["message"] = code.strip()[:240]
                            row["primary_location"] = "yes"
                            rows.append(row)
                            added += 1
                        else:
                            continue
    return added


def write_findings_csv(rows, report_dir):
    """분류된 전체 행을 CSV로 저장한다."""
    csv_path = report_file(report_dir, "findings-seven-categories.csv")
    try:
        with open(csv_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    except OSError as exc:
        raise OSError("CSV를 저장할 수 없습니다: %s" % csv_path) from exc
    else:
        return csv_path


def category_number(row):
    """CSV에서 읽은 항목 번호를 정수로 맞춘다."""
    try:
        return int(row["category_no"])
    except (TypeError, ValueError) as exc:
        raise ValueError("category_no가 정수가 아닙니다: %s" % row.get("category_no")) from exc


def cppcheck_command_markdown(compile_db_path, stdout_path, xml_path):
    """사람이 읽기 쉬운 여러 줄 Cppcheck 명령을 만든다."""
    args = cppcheck_command(compile_db_path)
    lines = []
    lines.append("%s %s \\" % (args[0], args[1]))
    index = 2
    while index < len(args):
        if index < len(args) - 1 and args[index] == "--xml" and args[index + 1] == "--xml-version=2":
            lines.append("  --xml --xml-version=2 \\")
            break
        else:
            lines.append("  %s \\" % args[index])
            index += 1
    lines.append("  > %s \\" % stdout_path)
    lines.append("  2> %s" % xml_path)
    return "\n".join(lines)


def compile_db_file_count(report_dir):
    """검사 목록에 들어 있는 소스 파일 수를 센다."""
    compile_db_path = report_file(report_dir, "compile_commands-firstparty.json")
    if not os.path.isfile(compile_db_path):
        raise FileNotFoundError("검사 목록이 없습니다: %s" % compile_db_path)
    else:
        return len(load_compile_commands(compile_db_path))


def write_findings_md(rows, report_dir):
    """원래 보고서와 같은 구성으로 Markdown 요약을 저장한다."""
    for row in rows:
        row["category_no"] = category_number(row)
    primary = []
    for row in rows:
        if row["primary_location"] == "yes":
            primary.append(row)
        else:
            continue
    cpp_primary = []
    for row in primary:
        if row["source"] == "cppcheck":
            cpp_primary.append(row)
        else:
            continue
    counts = Counter((row["source"], row["category_no"]) for row in primary)
    id_counts = Counter((row["category_no"], row["cppcheck_id"]) for row in cpp_primary)
    severity_counts = Counter(row["severity"] for row in cpp_primary)
    file_count = compile_db_file_count(report_dir)
    compile_db_path = report_file(report_dir, "compile_commands-firstparty.json")
    stdout_path = report_file(report_dir, "cppcheck-stdout.txt")
    xml_path = report_file(report_dir, "cppcheck-raw.xml")
    stdout_empty = True
    if os.path.isfile(stdout_path) and os.path.getsize(stdout_path) > 0:
        stdout_empty = False
    else:
        stdout_empty = True
    lines = []
    lines.append("# NarinFC-H7 보안약점 분석 결과")
    lines.append("")
    lines.append("대상은 NarinFC-H7용 ArduPlane, ArduCopter 펌웨어에 컴파일된 직접 작성 코드 %d개입니다." % file_count)
    lines.append("부트로더, `build/` 생성물, lwIP, DroneCAN은 이 목록에 넣지 않았습니다.")
    lines.append("")
    lines.append("## 사용한 명령")
    lines.append("")
    lines.append("작업 디렉터리: `%s`" % REPO_DIR)
    lines.append("")
    lines.append("도구: Cppcheck 2.7 (`/usr/bin/cppcheck`)")
    lines.append("")
    if stdout_empty:
        lines.append("종료 코드 0. 표준 출력은 비어 있고, 결과 XML은 표준 오류로 나왔습니다.")
    else:
        lines.append("종료 코드 0. 결과 XML은 표준 오류로 나왔습니다.")
    lines.append("")
    lines.append("```bash")
    lines.append(cppcheck_command_markdown(compile_db_path, stdout_path, xml_path))
    lines.append("```")
    lines.append("")
    lines.append("| 옵션 | 의미 |")
    lines.append("|---|---|")
    lines.append("| `--project=...json` | NarinFC-H7 컴파일 기록 중 직접 작성 코드 %d개만 남긴 목록 |" % file_count)
    lines.append("| `--enable=warning,style,portability,performance` | 경고, 스타일, 이식성, 성능 검사. `all`은 쓰지 않음 |")
    lines.append("| `--inconclusive` | 단정이 어려운 경고도 출력 |")
    lines.append("| `--inline-suppr` | 소스의 cppcheck-suppress 주석을 인정 |")
    lines.append("| `--suppress=missingIncludeSystem` | 시스템 헤더 누락 경고 제외 |")
    lines.append("| `--suppress=missingInclude` | 프로젝트 헤더 누락 경고 제외 |")
    lines.append("| `--suppress=unmatchedSuppression` | 맞지 않는 억제 주석 경고 제외 |")
    lines.append("| `--suppress=unusedFunction` | 미사용 함수 검사 제외. 파일 단위 분석에서는 오탐이 큼 |")
    lines.append("| `--suppress=toomanyconfigs` | 매크로 조합이 너무 많다는 경고 제외 |")
    lines.append("| `-j20` | 작업 20개 동시 실행 |")
    lines.append("| `--quiet` | 진행 문구 숨김 |")
    lines.append("| `--xml --xml-version=2` | 결과 형식 XML 2 |")
    lines.append("")
    lines.append("`--project`에 넣은 목록은 `build/NarinFC-H7/compile_commands.json`에서 `ArduPlane/`, `ArduCopter/`, `libraries/`만 남긴 것입니다. 같은 파일이 이 폴더의 `compile_commands-firstparty.json`입니다.")
    lines.append("")
    lines.append("## 원본 파일")
    lines.append("")
    lines.append("| 파일 | 내용 |")
    lines.append("|---|---|")
    lines.append("| `cppcheck-raw.xml` | Cppcheck XML 원본. error %d건 |" % len(cpp_primary))
    lines.append("| `cppcheck-stdout.txt` | 표준 출력 원본. 비어 있음 |" if stdout_empty else "| `cppcheck-stdout.txt` | 표준 출력 원본 |")
    lines.append("| `compile_commands-firstparty.json` | `--project`에 넘긴 입력 |")
    lines.append("| `findings-seven-categories.csv` | 원본 경고와 추가 확인을 항목 번호로 나눈 전체 행 |")
    lines.append("")
    severity_order = ["style", "warning", "performance", "portability", "error"]
    severity_parts = []
    for severity in severity_order:
        if severity_counts.get(severity, 0) > 0:
            severity_parts.append("%s %d" % (severity, severity_counts[severity]))
        else:
            continue
    lines.append("Cppcheck 원본 %d건의 심각도: %s." % (len(cpp_primary), ", ".join(severity_parts)))
    plane_hits = 0
    copter_hits = 0
    for row in cpp_primary:
        if str(row["file"]).startswith("ArduPlane/"):
            plane_hits += 1
        elif str(row["file"]).startswith("ArduCopter/"):
            copter_hits += 1
        else:
            continue
    if id_counts.get((0, "syntaxError"), 0) > 0 or id_counts.get((0, "preprocessorErrorDirective"), 0) > 0:
        tool_note = "error %d건은 펌웨어 결함이 아니라 분석기 한계입니다. `mavlink_types.h`의 `MAVPACKED` 구문, CMSIS `#error`입니다. 이 헤더를 포함하는 파일은 분석이 얕을 수 있습니다." % severity_counts.get("error", 0)
    else:
        tool_note = "분석기 한계로 표시된 error는 이번 원본에 없습니다."
    if plane_hits == 0 and copter_hits == 0:
        lines.append(tool_note + " `ArduPlane/`, `ArduCopter/`에 Cppcheck 경고가 0건인 이유 중 하나입니다.")
    else:
        lines.append(tool_note)
        lines.append("`ArduPlane/` Cppcheck 경고 %d건, `ArduCopter/` Cppcheck 경고 %d건입니다." % (plane_hits, copter_hits))
    lines.append("")
    lines.append("## 분류 규칙")
    lines.append("")
    lines.append("Cppcheck id를 일곱 항목에 대응했습니다. 보안약점으로 보기 어려운 스타일 경고는 `7항목 제외`입니다.")
    lines.append("패턴 검색과 코드 확인은 Cppcheck 원본에 없는 항목이며, CSV의 `source`가 `pattern`, `pattern-bundled`, `code-review`입니다.")
    lines.append("")
    lines.append("| Cppcheck id | 항목 |")
    lines.append("|---|---|")
    for checker_id, (category_no, confidence, _reason) in sorted(ID_MAP.items(), key=lambda item: (item[1][0], item[0])):
        lines.append("| `%s` | %d. %s (%s) |" % (checker_id, category_no, CATEGORY_NAMES[category_no], confidence))
    lines.append("| 그 외 스타일 id | 0. 7항목 제외 |")
    lines.append("")
    lines.append("## 집계")
    lines.append("")
    lines.append("Cppcheck 건수는 경고 1건당 1회로 세었습니다. 위치가 여러 줄인 경고도 1건입니다. CSV에는 추가 위치 행이 더 있습니다.")
    lines.append("")
    lines.append("| 번호 | 항목 | Cppcheck | 패턴(직접 코드) | 패턴(번들) | 코드 확인 |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for category_no in range(0, 8):
        lines.append(
            "| %d | %s | %d | %d | %d | %d |"
            % (
                category_no,
                CATEGORY_NAMES[category_no],
                counts.get(("cppcheck", category_no), 0),
                counts.get(("pattern", category_no), 0),
                counts.get(("pattern-bundled", category_no), 0),
                counts.get(("code-review", category_no), 0),
            )
        )
    lines.append("")
    lines.append("### Cppcheck를 항목 안에서 id로 나눈 수")
    lines.append("")
    lines.append("| 항목 | id | 건수 |")
    lines.append("|---|---|---:|")
    for (category_no, checker_id), count in sorted(id_counts.items(), key=lambda item: (item[0][0], -item[1], item[0][1])):
        lines.append("| %d. %s | `%s` | %d |" % (category_no, CATEGORY_NAMES[category_no], checker_id, count))
    lines.append("")
    lines.append("## 코드 확인으로 우선 볼 항목")
    lines.append("")
    lines.append("이 절은 Cppcheck XML에 없는 내용입니다.")
    lines.append("")
    review_rows = []
    for row in primary:
        if row["source"] == "code-review":
            review_rows.append(row)
        else:
            continue
    if len(review_rows) == 0:
        lines.append("이번 실행의 CSV에는 코드 확인 행이 없습니다.")
    else:
        for index, row in enumerate(review_rows, 1):
            lines.append(
                "%d. %s. `%s` %s행. %s %s"
                % (index, row["category_name"], row["file"], row["line"], row["rule"], row["message"])
            )
    lines.append("")
    lines.append("## 항목별 패턴 위치")
    lines.append("")
    lines.append("주석 줄은 세지 않았습니다. 번들 Lua, sagetech-sdk, monocypher는 따로 표시합니다.")
    lines.append("")
    for category_no in range(1, 8):
        lines.append("### %d. %s" % (category_no, CATEGORY_NAMES[category_no]))
        lines.append("")
        section_rows = []
        for row in primary:
            if row["category_no"] == category_no and row["source"] in ("pattern", "pattern-bundled", "code-review"):
                section_rows.append(row)
            else:
                continue
        if len(section_rows) == 0:
            lines.append("패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.")
            lines.append("")
        else:
            section_rows.sort(key=lambda item: (item["file"], int(item["line"] or 0)))
            for row in section_rows:
                lines.append("- [%s] %s:%s %s — %s" % (row["source"], row["file"], row["line"], row["rule"], row["message"]))
            lines.append("")
    lines.append("## 읽는 순서")
    lines.append("")
    lines.append("도구가 그대로 출력한 내용은 `cppcheck-raw.xml`입니다.")
    lines.append("같은 경고에 항목 번호를 붙인 전체 행은 `findings-seven-categories.csv`입니다.")
    lines.append("사람이 결함으로 확인한 내용은 이 파일의 「코드 확인으로 우선 볼 항목」입니다.")
    lines.append("")
    md_path = report_file(report_dir, "findings-seven-categories.md")
    try:
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as exc:
        raise OSError("요약을 저장할 수 없습니다: %s" % md_path) from exc
    else:
        seven = 0
        for row in cpp_primary:
            if row["category_no"] in (1, 2, 3, 4, 5, 6, 7):
                seven += 1
            else:
                continue
        print("cppcheck primary: %d" % len(cpp_primary))
        print("seven categories: %d" % seven)
        print("summary -> %s" % md_path)
        return seven


def classify(report_dir):
    """Cppcheck XML과 패턴 검색 결과를 7항목 CSV와 요약으로 저장한다."""
    print("결과 폴더: %s" % report_dir)
    rows = []
    error_count = append_cppcheck_rows(rows, report_dir)
    pattern_count = append_pattern_rows(rows, report_dir)
    csv_path = write_findings_csv(rows, report_dir)
    write_findings_md(rows, report_dir)
    print("cppcheck errors: %d" % error_count)
    print("pattern rows: %d" % pattern_count)
    print("csv -> %s" % csv_path)
    return error_count


def run_waf(vehicle):
    """NarinFC-H7 보드 설정으로 선택한 기체를 빌드한다."""
    if vehicle == "copter":
        waf_target = "copter"
    elif vehicle == "plane":
        waf_target = "plane"
    else:
        raise ValueError("지원하지 않는 기체입니다: %s" % vehicle)
    waf_path = os.path.join(REPO_DIR, "waf")
    if not os.path.isfile(waf_path):
        raise FileNotFoundError("waf가 없습니다: %s" % waf_path)
    else:
        command = [waf_path, waf_target]
    print("빌드: ./waf %s" % waf_target)
    try:
        result = subprocess.run(command, cwd=REPO_DIR, check=False)
    except OSError as exc:
        raise OSError("./waf %s 를 실행할 수 없습니다" % waf_target) from exc
    else:
        if result.returncode != 0:
            raise RuntimeError("./waf %s 종료 코드 %s" % (waf_target, result.returncode))
        else:
            print("./waf %s 종료 코드 0" % waf_target)
            return result.returncode


def print_usage():
    """실행 방법을 출력한다."""
    print("사용법: python3 NarinFC_SecureCoding.py <copter|plane|filelist [plane|copter]|cppcheck|classify|all>")
    print("  copter            ./waf copter 로 멀티콥터 펌웨어 빌드")
    print("  plane             ./waf plane 으로 비행기 펌웨어 빌드")
    print("  filelist          1. Plane과 Copter 검사 목록을 저장")
    print("  filelist plane    1. Plane 검사 목록만 저장")
    print("  filelist copter   1. Copter 검사 목록만 저장")
    print("  cppcheck          2. 가장 최근 결과 폴더의 목록으로 Cppcheck 실행")
    print("  classify          3. 가장 최근 결과 폴더의 XML을 7항목으로 분류")
    print("  all               copter와 plane을 빌드한 뒤 1, 2, 3을 같은 결과 폴더에서 실행")
    print("결과 폴더 이름: %s_YYYY_MM_DD_HH_MI_SS" % REPORT_PREFIX)


def filelist_selection(argv):
    """filelist 뒤의 기체 인자를 읽는다. 없으면 Plane과 Copter를 함께 고른다."""
    if len(argv) == 2:
        return "both"
    elif len(argv) == 3 and argv[2] in ("plane", "copter"):
        return argv[2]
    else:
        raise ValueError("filelist 인자는 plane 또는 copter 만 가능합니다")


def main(argv):
    """선택한 단계만 실행한다."""
    if len(argv) < 2 or len(argv) > 3:
        print_usage()
        return 2
    elif len(argv) == 3 and argv[1] != "filelist":
        print_usage()
        return 2
    else:
        command = argv[1]
        match command:
            case "copter":
                run_waf("copter")
                return 0
            case "plane":
                run_waf("plane")
                return 0
            case "filelist":
                selection = filelist_selection(argv)
                write_filelist(create_report_dir(), selection)
                return 0
            case "cppcheck":
                run_cppcheck(latest_report_dir())
                return 0
            case "classify":
                classify(latest_report_dir())
                return 0
            case "all":
                run_waf("copter")
                run_waf("plane")
                report_dir = create_report_dir()
                write_filelist(report_dir, "both")
                run_cppcheck(report_dir)
                classify(report_dir)
                return 0
            case _:
                print_usage()
                return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:
        print("오류: %s" % exc, file=sys.stderr)
        sys.exit(1)
