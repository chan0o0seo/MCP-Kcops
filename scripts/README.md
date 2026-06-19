# 로컬 테스트 스크립트

PowerShell에서 프로젝트 루트 기준으로 실행한다.

| 스크립트 | 역할 |
|---|---|
| `start.ps1` | bootJar 빌드(필요 시) → mock 서버(8090) + 프록시(8080) 기동 후 헬스 체크 |
| `demo.ps1` | 프록시에 대표 시나리오(ALLOW/BLOCK/REQUIRE_APPROVAL/인젝션/인코딩 우회) 전송 후 결정 출력 |
| `stop.ps1` | mcp-kcops jar로 기동된 java 프로세스만 종료 |

## 빠른 시작

```powershell
# 1) 기동 (관리자 API 토큰을 secret 으로 활성화)
.\scripts\start.ps1 -AdminToken secret

# 2) 데모 실행 (관리자 API 시나리오 포함)
.\scripts\demo.ps1 -AdminToken secret

# 3) 종료
.\scripts\stop.ps1
```

옵션:

- `start.ps1 -SkipBuild` : 이미 빌드된 `build/libs/*.jar` 재사용(빠른 재기동).
- `start.ps1` (토큰 생략) : 관리자 API는 fail-closed로 비활성(`/admin/**` → 503).
- `demo.ps1 -Proxy http://host:port/mcp` : 프록시 주소 변경.

## 직접 보내보기 (curl 예시)

```bash
# 정상 요청 → 원본 응답 전달
curl -s -X POST http://localhost:8080/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"url":"https://company.internal/calendar","query":"meeting"}}}'

# 관리자 API (토큰 필요)
curl -s -H "Authorization: Bearer secret" http://localhost:8080/admin/audit/verify
```

감사 로그는 `logs/audit.jsonl` (SHA-256 해시 체인)에 기록된다.
