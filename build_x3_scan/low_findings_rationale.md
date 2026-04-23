# Low 항목 조치 보류 사유서

작성일: 2026-04-23  
기준 리포트: `build_x3_scan/cppcheck_cwe_priority_report.txt`  
대상 건수: Low 15건 (`CWE-398` 14건, `CWE-N/A` 1건)

## 1) `noExplicitConstructor` - `quaternion.h` (1건)

- 항목:
  - `libraries/AP_Math/quaternion.h` (`QuaternionT` 단일 인자 생성자)
- 보류 사유:
  - 해당 생성자에 `explicit` 적용 시 기존 코드의 배열 기반 대입/초기화 패턴과 충돌해 실제 빌드 에러가 발생한 이력이 있음.
  - 보안 취약점(메모리 오염/경계 초과/권한 상승 등)으로 직접 연결되는 항목이 아니라 스타일 성격(`CWE-398`)임.
  - 호환성 리스크 대비 보안 개선 효과가 낮아, 현재는 유지가 합리적임.

## 2) `noExplicitConstructor` - `RingBuffer.h` (1건)

- 항목:
  - `libraries/AP_HAL/utility/RingBuffer.h` (`ObjectBuffer<float>` 템플릿 인스턴스)
- 보류 사유:
  - 템플릿 타입의 단일 인자 생성자에 `explicit` 강제 시, 프로젝트 전역의 암묵적 생성 호출부에서 광범위한 시그니처 변경이 연쇄적으로 필요할 수 있음.
  - 본 경고는 API 설계 스타일 개선 권고이며, 현재 입력 길이 검증/경계 보호 관점의 즉시 취약점과는 성격이 다름.
  - 회귀 범위가 커서 별도 리팩토링 배치로 분리하는 것이 안전함.

## 3) `noExplicitConstructor` - `OwnPtr.h` (6건)

- 항목:
  - `libraries/AP_HAL/utility/OwnPtr.h`  
    (`OwnPtr<SPIDevice>` 3건, `OwnPtr<WSPIDevice>` 3건)
- 보류 사유:
  - `nullptr`, raw pointer, move 변환 등 기존 HAL 경로에서 암묵 변환을 실제로 사용 중임.
  - `explicit` 적용 시 다수 경로에서 대입/반환 호환성이 깨져 빌드 실패가 발생한 이력이 있음.
  - 스타일 경고 해소를 위해 호환성을 깨뜨리는 것은 현재 보안 하드닝 목표(취약점 저감)와 우선순위가 다름.

## 4) `noExplicitConstructor` - `functor.h` (6건)

- 항목:
  - `libraries/AP_HAL/utility/functor.h` (템플릿 인스턴스 6건)
- 보류 사유:
  - 콜백 초기화/해제에서 `nullptr`의 암묵 변환을 사용하는 패턴이 존재함.
  - `explicit` 적용 시 `Functor` 타입에 대한 `nullptr` 대입/초기화가 깨져 빌드 오류가 재현된 이력이 있음.
  - 해당 경고 역시 설계 스타일 권고이며, 현재 보안 취약점 제거 작업의 즉시 대상은 아님.

## 5) `preprocessorErrorDirective` - `cmsis_compiler.h` (1건)

- 항목:
  - `modules/ChibiOS/os/common/ext/ARM/CMSIS/Core/Include/cmsis_compiler.h:261`
  - 메시지: `#error Unknown compiler.`
- 보류 사유:
  - 사용자 애플리케이션 코드 결함이 아니라, 정적분석 도구의 전처리 환경/크로스 컴파일 해석 차이에서 발생하는 진단임.
  - 벤더(CMSIS/ChibiOS) 헤더 직접 수정은 추후 업스트림 동기화/유지보수 비용을 크게 증가시킴.
  - 현재 파이프라인에서는 해당 항목을 Low/제외 대상으로 분류 및 suppress 처리함.

## 결론

- Low 15건은 모두 **스타일/도구환경성 항목**이며, 현 단계에서 보안 취약점 직접 저감 효과보다 **호환성/회귀 리스크가 더 큼**.
- 따라서 본 배치에서는 패치를 보류하고, 아래 조건에서 별도 개선 배치로 분리 권고:
  - 대규모 API 호출부 자동 수정(리팩토링) 준비 완료
  - 빌드/테스트 회귀 범위(보드별) 확보
  - 벤더 헤더 이슈는 업스트림/도구체인 기준으로 별도 관리
