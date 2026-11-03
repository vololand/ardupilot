# NarinFC-H7 보안약점 분석 결과

대상은 NarinFC-H7 펌웨어에 컴파일된 직접 작성 코드 953개입니다.
구성은 그 외 953개입니다.
부트로더, `build/` 생성물, lwIP, DroneCAN은 이 목록에 넣지 않았습니다.

## 사용한 명령

작업 디렉터리: `/home/jobs/ProjectGit/vololand/ArduPilot`

도구: Cppcheck 2.7 (`/usr/bin/cppcheck`)

종료 코드 0. 표준 출력은 비어 있고, 결과 XML은 표준 오류로 나왔습니다.

```bash
cppcheck --project=/home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_10_46_12/compile_commands-firstparty.json \
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
  > /home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_10_46_12/cppcheck-stdout.txt \
  2> /home/jobs/ProjectGit/vololand/ArduPilot/NarinFC-H7-secure-coding-report_2026_11_03_10_46_12/cppcheck-raw.xml
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

`--project`에 넣은 목록은 `build/NarinFC-H7/compile_commands.json`에서 직접 작성 코드만 남긴 것입니다. 같은 파일이 이 폴더의 `compile_commands-firstparty.json`입니다.

## 원본 파일

| 파일 | 내용 |
|---|---|
| `cppcheck-raw.xml` | Cppcheck XML 원본. error 1391건 |
| `cppcheck-stdout.txt` | 표준 출력 원본. 비어 있음 |
| `compile_commands-firstparty.json` | `--project`에 넘긴 입력 |
| `findings-seven-categories.csv` | 원본 경고와 추가 확인을 항목 번호로 나눈 전체 행 |

Cppcheck 원본 1391건의 심각도: style 1017, warning 314, performance 46, portability 12, error 2.
error 2건은 펌웨어 결함이 아니라 분석기 한계입니다. `mavlink_types.h`의 `MAVPACKED` 구문, CMSIS `#error`입니다. 이 헤더를 포함하는 파일은 분석이 얕을 수 있습니다.

## 분류 규칙

Cppcheck id를 일곱 항목에 대응했습니다. 보안약점으로 보기 어려운 스타일 경고는 `7항목 제외`입니다.
패턴 검색과 코드 확인은 Cppcheck 원본에 없는 항목이며, CSV의 `source`가 `pattern`, `pattern-bundled`, `code-review`입니다.

| Cppcheck id | 항목 |
|---|---|
| `preprocessorErrorDirective` | 0. 7항목 제외 (도구) |
| `syntaxError` | 0. 7항목 제외 (도구) |
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
| 그 외 스타일 id | 0. 7항목 제외 |

## 집계

Cppcheck 건수는 경고 1건당 1회로 세었습니다. 위치가 여러 줄인 경고도 1건입니다. CSV에는 추가 위치 행이 더 있습니다.

| 번호 | 항목 | Cppcheck | 패턴(직접 코드) | 패턴(번들) | 코드 확인 |
|---|---|---:|---:|---:|---:|
| 0 | 7항목 제외 | 1004 | 0 | 0 | 0 |
| 1 | 입력 데이터 검증 및 표현 | 16 | 12 | 8 | 0 |
| 2 | 보안기능 | 0 | 0 | 0 | 0 |
| 3 | 시간 및 상태 | 0 | 0 | 0 | 0 |
| 4 | 에러 처리 | 0 | 0 | 0 | 0 |
| 5 | 코드오류 | 326 | 0 | 0 | 0 |
| 6 | 캡슐화 | 45 | 0 | 0 | 0 |
| 7 | API 오용 | 0 | 33 | 0 | 0 |

### Cppcheck를 항목 안에서 id로 나눈 수

| 항목 | id | 건수 |
|---|---|---:|
| 0. 7항목 제외 | `funcArgNamesDifferent` | 736 |
| 0. 7항목 제외 | `noExplicitConstructor` | 74 |
| 0. 7항목 제외 | `functionConst` | 51 |
| 0. 7항목 제외 | `functionStatic` | 40 |
| 0. 7항목 제외 | `noConstructor` | 22 |
| 0. 7항목 제외 | `unreadVariable` | 20 |
| 0. 7항목 제외 | `variableScope` | 19 |
| 0. 7항목 제외 | `constParameter` | 17 |
| 0. 7항목 제외 | `cstyleCast` | 8 |
| 0. 7항목 제외 | `useInitializationList` | 6 |
| 0. 7항목 제외 | `constVariable` | 4 |
| 0. 7항목 제외 | `funcArgOrderDifferent` | 4 |
| 0. 7항목 제외 | `duplInheritedMember` | 1 |
| 0. 7항목 제외 | `preprocessorErrorDirective` | 1 |
| 0. 7항목 제외 | `syntaxError` | 1 |
| 1. 입력 데이터 검증 및 표현 | `objectIndex` | 16 |
| 5. 코드오류 | `uninitMemberVar` | 260 |
| 5. 코드오류 | `uninitMemberVarPrivate` | 18 |
| 5. 코드오류 | `invalidPointerCast` | 8 |
| 5. 코드오류 | `knownConditionTrueFalse` | 7 |
| 5. 코드오류 | `noCopyConstructor` | 7 |
| 5. 코드오류 | `noOperatorEq` | 7 |
| 5. 코드오류 | `duplicateExpression` | 5 |
| 5. 코드오류 | `memsetClassFloat` | 4 |
| 5. 코드오류 | `duplicateCondition` | 2 |
| 5. 코드오류 | `redundantAssignment` | 2 |
| 5. 코드오류 | `redundantCondition` | 2 |
| 5. 코드오류 | `shadowFunction` | 1 |
| 5. 코드오류 | `shadowVariable` | 1 |
| 5. 코드오류 | `sizeofCalculation` | 1 |
| 5. 코드오류 | `unsignedLessThanZero` | 1 |
| 6. 캡슐화 | `unusedPrivateFunction` | 23 |
| 6. 캡슐화 | `unusedStructMember` | 22 |

## 코드 확인으로 우선 볼 항목

이 절은 Cppcheck XML에 없는 내용입니다.

이번 실행의 CSV에는 코드 확인 행이 없습니다.

## 항목별 패턴 위치

주석 줄은 세지 않았습니다. 번들 Lua, sagetech-sdk, monocypher는 따로 표시합니다.

### 1. 입력 데이터 검증 및 표현

- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_ADSB/sagetech-sdk/sgDecodeFlightId.c:37 범위 없는 복사 (번들 소스) — strcpy(id->flightId, sgId.flightId);
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_ADSB/sagetech-sdk/sgDecodeInstall.c:63 범위 없는 복사 (번들 소스) — strcpy(stl->reg,      sgStl.registration);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_AIS/AP_AIS.cpp:872 범위 없는 복사 — strcpy(_incoming.payload,_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Filesystem/AP_Filesystem_FATFS.cpp:90 범위 없는 복사 — strcpy(fname, pathname);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Filesystem/AP_Filesystem_Param.cpp:274 범위 없는 복사 — strcpy(c.last_name, name);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_HAL/utility/dsm.cpp:545 scanf 계열 — if (sscanf(argv[i], "%02x", &v) != 1 || v > 255) {
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/liolib.c:61 외부 명령 실행 (번들 소스) — #define l_popen(L,c,m)		(fflush(NULL), popen(c,m))
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/lobject.c:286 범위 없는 복사 (번들 소스) — strcpy(buff, s);  /* copy string to buffer */
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/loslib.c:135 범위 없는 복사 (번들 소스) — strcpy(b, LUA_TMPNAMTEMPLATE); \
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/loslib.c:156 외부 명령 실행 (번들 소스) — int stat = system(cmd);
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/lstrlib.c:1017 범위 없는 복사 (번들 소스) — strcpy(form + l - 1, lenmod);
- [pattern-bundled] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua/src/luac.c:268 범위 없는 복사 (번들 소스) — sprintf(buff,LUA_NUMBER_FMT,fltvalue(o));
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:316 범위 없는 복사 — strcpy(label_cat,"TimeUS,");
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:317 범위 없는 복사 — strcat(label_cat,labels);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:319 범위 없는 복사 — strcpy(fmt_cat,"Q");
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:320 범위 없는 복사 — strcat(fmt_cat,fmt);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:346 범위 없는 복사 — strcpy(units_cat,"s");
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:347 범위 없는 복사 — strcat(units_cat,units);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:349 범위 없는 복사 — strcpy(multipliers_cat,"F");
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Scripting/lua_bindings.cpp:350 범위 없는 복사 — strcat(multipliers_cat,multipliers);

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

- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:588 atoi/atol/atof — _new_satellite_count = atol(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:601 atoi/atol/atof — _new_date = atol(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:646 atoi/atol/atof — _phd.msg_class = atol(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:649 atoi/atol/atof — _phd.msg_id = atol(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:655 atoi/atol/atof — _phd.fields[_term_number-6] = atol(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:658 atoi/atol/atof — _ksxt.fields[_term_number-1] = atof(_term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:701 atoi/atol/atof — ag.rtk_status = atol(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:704 atoi/atol/atof — ag.heading_status = atol(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:707 atoi/atol/atof — ag.vel_NED[term_number-25] = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:711 atoi/atol/atof — ag.vel_NED.z = -atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:714 atoi/atol/atof — ag.vel_stddev[term_number-28] = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:717 atoi/atol/atof — ag.lat = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:720 atoi/atol/atof — ag.lng = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:723 atoi/atol/atof — ag.alt = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:726 atoi/atol/atof — ag.itow = atol(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:729 atoi/atol/atof — ag.pos_stddev[term_number-37] = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:732 atoi/atol/atof — ag.undulation = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:757 atoi/atol/atof — uh.baseline_length = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:760 atoi/atol/atof — uh.heading = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:763 atoi/atol/atof — uh.pitch = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_GPS/AP_GPS_NMEA.cpp:766 atoi/atol/atof — uh.heading_sd = atof(term);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Viewpro.cpp:297 atoi/atol/atof — const uint8_t major_ver = atoi((const char*)fw_major_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Viewpro.cpp:298 atoi/atol/atof — const uint8_t minor_ver = atoi((const char*)fw_minor_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Viewpro.cpp:299 atoi/atol/atof — const uint8_t patch_ver = atoi((const char*)fw_patch_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Xacti.cpp:665 atoi/atol/atof — const uint8_t major_ver_num = atoi(major_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Xacti.cpp:666 atoi/atol/atof — const uint8_t minor_ver_num = atoi(minor_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Xacti.cpp:667 atoi/atol/atof — const uint8_t patch_ver_num = atoi(patch_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_Mount/AP_Mount_Xacti.cpp:668 atoi/atol/atof — const uint8_t dev_ver_num = atoi(dev_str) & 0xFF;
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_OpenDroneID/AP_OpenDroneID.cpp:141 atoi/atol/atof — pkt_basic_id.id_type = atoi(id_type);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_OpenDroneID/AP_OpenDroneID.cpp:142 atoi/atol/atof — pkt_basic_id.ua_type = atoi(ua_type);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/AP_RangeFinder/AP_RangeFinder_MaxsonarSerialLV.cpp:54 atoi/atol/atof — sum += (int)atoi(linebuf);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/GCS_MAVLink/GCS_Common.cpp:6637 atoi/atol/atof — const uint32_t mavlink_id = atoi(mavlink_id_str);
- [pattern] /home/jobs/ProjectGit/vololand/ArduPilot/libraries/GCS_MAVLink/GCS_Common.cpp:6648 atoi/atol/atof — const uint16_t interval = atoi(interval_str);

## 읽는 순서

도구가 그대로 출력한 내용은 `cppcheck-raw.xml`입니다.
같은 경고에 항목 번호를 붙인 전체 행은 `findings-seven-categories.csv`입니다.
사람이 결함으로 확인한 내용은 이 파일의 「코드 확인으로 우선 볼 항목」입니다.

