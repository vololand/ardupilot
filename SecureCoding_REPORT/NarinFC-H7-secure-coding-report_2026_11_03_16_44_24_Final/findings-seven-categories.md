# NarinFC-H7 보안약점 분석 결과

대상은 NarinFC-H7용 ArduPlane 펌웨어에 컴파일된 직접 작성 코드 953개입니다.
구성은 `ArduPlane/` 64개, `libraries/` 889개입니다.
부트로더, `build/` 생성물, lwIP, DroneCAN은 이 목록에 넣지 않았습니다.

## 사용한 명령

작업 디렉터리: `/home/jobs/ProjectGit/vololand/ArduPilot`

도구: Cppcheck 2.7 (`/usr/bin/cppcheck`)

종료 코드 0. 표준 출력은 비어 있고, 결과 XML은 표준 오류로 나왔습니다.

```bash
cppcheck --project=/home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_16_44_24/compile_commands-firstparty.json \
  --enable=warning,style,portability,performance \
  --inconclusive \
  --inline-suppr \
  --suppress=missingIncludeSystem \
  --suppress=missingInclude \
  --suppress=unmatchedSuppression \
  --suppress=unusedFunction \
  --suppress=toomanyconfigs \
  -j20 \
  --quiet \
  --xml --xml-version=2 \
  > /home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_16_44_24/cppcheck-stdout.txt \
  2> /home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_16_44_24/cppcheck-raw.xml
```

| 옵션 | 의미 |
|---|---|
| `--project=...json` | NarinFC-H7 컴파일 기록 중 직접 작성 코드 953개만 남긴 목록 |
| `--enable=warning,style,portability,performance` | 경고, 스타일, 이식성, 성능 검사. `all`은 쓰지 않음 |
| `--inconclusive` | 단정이 어려운 경고도 출력 |
| `--inline-suppr` | 소스의 cppcheck-suppress 주석을 인정 |
| `--suppress=missingIncludeSystem` | 시스템 헤더 누락 경고 제외 |
| `--suppress=missingInclude` | 프로젝트 헤더 누락 경고 제외 |
| `--suppress=unmatchedSuppression` | 맞지 않는 억제 주석 경고 제외 |
| `--suppress=unusedFunction` | 미사용 함수 검사 제외. 파일 단위 분석에서는 오탐이 큼 |
| `--suppress=toomanyconfigs` | 매크로 조합이 너무 많다는 경고 제외 |
| `-j20` | 작업 20개 동시 실행 |
| `--quiet` | 진행 문구 숨김 |
| `--xml --xml-version=2` | 결과 형식 XML 2 |

`--project`에 넣은 목록은 `build/NarinFC-H7/compile_commands.json`에서 `ArduPlane/`, `libraries/`만 남긴 것입니다. 같은 파일이 이 폴더의 `compile_commands-firstparty.json`입니다.

## 원본 파일

| 파일 | 내용 |
|---|---|
| `cppcheck-raw.xml` | Cppcheck XML 원본. error 1346건 |
| `cppcheck-stdout.txt` | 표준 출력 원본. 비어 있음 |
| `compile_commands-firstparty.json` | `--project`에 넘긴 입력 |
| `findings-seven-categories.csv` | 원본 경고와 추가 확인을 항목 번호로 나눈 전체 행 |

Cppcheck 원본 1346건의 심각도: style 983, warning 314, performance 46, portability 1, error 2.
error 2건은 펌웨어 결함이 아니라 분석기 한계입니다. `mavlink_types.h`의 `MAVPACKED` 구문, CMSIS `#error`입니다. 이 헤더를 포함하는 파일은 분석이 얕을 수 있습니다. `ArduPlane/`에 Cppcheck 경고가 0건인 이유 중 하나입니다.

## 분류 규칙

Cppcheck id를 일곱 항목에 대응했습니다. 보안약점으로 보기 어려운 스타일 경고는 `7항목 제외`입니다.
패턴 검색과 코드 확인은 Cppcheck 원본에 없는 항목이며, CSV의 `source`가 `pattern`, `pattern-bundled`, `code-review`입니다.

| Cppcheck id | 항목 |
|---|---|
| `objectIndex` | 1. 입력 데이터 검증 및 표현 (낮음) |
| `duplicateCondition` | 5. 코드오류 (중간) |
| `duplicateExpression` | 5. 코드오류 (중간) |
| `invalidPointerCast` | 5. 코드오류 (낮음) |
| `knownConditionTrueFalse` | 5. 코드오류 (낮음) |
| `memsetClassFloat` | 5. 코드오류 (중간) |
| `noCopyConstructor` | 5. 코드오류 (낮음) |
| `noOperatorEq` | 5. 코드오류 (낮음) |
| `redundantAssignment` | 5. 코드오류 (낮음) |
| `redundantCondition` | 5. 코드오류 (낮음) |
| `shadowFunction` | 5. 코드오류 (낮음) |
| `shadowVariable` | 5. 코드오류 (낮음) |
| `sizeofCalculation` | 5. 코드오류 (중간) |
| `uninitMemberVar` | 5. 코드오류 (낮음) |
| `uninitMemberVarPrivate` | 5. 코드오류 (낮음) |
| `unsignedLessThanZero` | 5. 코드오류 (낮음) |
| `unusedPrivateFunction` | 6. 캡슐화 (낮음) |
| `unusedStructMember` | 6. 캡슐화 (낮음) |

## 집계

Cppcheck 건수는 경고 1건당 1회로 세었습니다. 위치가 여러 줄인 경고도 1건입니다. CSV에는 추가 위치 행이 더 있습니다.

| 번호 | 항목 | Cppcheck | 패턴(직접 코드) | 패턴(번들) | 코드 확인 |
|---|---|---:|---:|---:|---:|
| 1 | 입력 데이터 검증 및 표현 | 16 | 1 | 5 | 0 |
| 2 | 보안기능 | 0 | 0 | 0 | 0 |
| 3 | 시간 및 상태 | 0 | 0 | 0 | 0 |
| 4 | 에러 처리 | 0 | 0 | 0 | 0 |
| 5 | 코드오류 | 301 | 0 | 0 | 0 |
| 6 | 캡슐화 | 24 | 0 | 0 | 0 |
| 7 | API 오용 | 0 | 0 | 0 | 0 |

### Cppcheck를 항목 안에서 id로 나눈 수

| 항목 | id | 건수 |
|---|---|---:|
| 1. 입력 데이터 검증 및 표현 | `objectIndex` | 16 |
| 5. 코드오류 | `uninitMemberVar` | 260 |
| 5. 코드오류 | `uninitMemberVarPrivate` | 18 |
| 5. 코드오류 | `noCopyConstructor` | 7 |
| 5. 코드오류 | `noOperatorEq` | 7 |
| 5. 코드오류 | `knownConditionTrueFalse` | 5 |
| 5. 코드오류 | `redundantAssignment` | 2 |
| 5. 코드오류 | `invalidPointerCast` | 1 |
| 5. 코드오류 | `sizeofCalculation` | 1 |
| 6. 캡슐화 | `unusedPrivateFunction` | 18 |
| 6. 캡슐화 | `unusedStructMember` | 6 |

## 코드 확인으로 우선 볼 항목

이 절은 Cppcheck XML에 없는 내용입니다.

이번 실행의 CSV에는 코드 확인 행이 없습니다.

## 항목별 패턴 위치

주석 줄은 세지 않았습니다. 번들 Lua, sagetech-sdk, monocypher는 따로 표시합니다.

### 1. 입력 데이터 검증 및 표현

- [pattern] libraries/AP_HAL/utility/dsm.cpp:545 scanf 계열 — if (sscanf(argv[i], "%02x", &v) != 1 || v > 255) {
- [pattern-bundled] libraries/AP_Scripting/lua/src/liolib.c:61 외부 명령 실행 (번들 소스) — #define l_popen(L,c,m)		(fflush(NULL), popen(c,m))
- [pattern-bundled] libraries/AP_Scripting/lua/src/loslib.c:135 범위 없는 복사 (번들 소스) — strcpy(b, LUA_TMPNAMTEMPLATE); \
- [pattern-bundled] libraries/AP_Scripting/lua/src/loslib.c:156 외부 명령 실행 (번들 소스) — int stat = system(cmd);
- [pattern-bundled] libraries/AP_Scripting/lua/src/lstrlib.c:1017 범위 없는 복사 (번들 소스) — strcpy(form + l - 1, lenmod);
- [pattern-bundled] libraries/AP_Scripting/lua/src/luac.c:268 범위 없는 복사 (번들 소스) — sprintf(buff,LUA_NUMBER_FMT,fltvalue(o));

### 2. 보안기능

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.

### 3. 시간 및 상태

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.

### 4. 에러 처리

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.

### 5. 코드오류

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.

### 6. 캡슐화

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.

### 7. API 오용

패턴 검색과 코드 확인에서 이 항목으로 넣은 추가 행은 없습니다. Cppcheck 건수는 위 집계 표를 봅니다.