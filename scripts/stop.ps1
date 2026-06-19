# MCP Kcops 로컬 테스트 서버 종료 — mcp-kcops jar로 기동된 java 프로세스만 정리한다.
$procs = Get-CimInstance Win32_Process -Filter "name='java.exe'" |
    Where-Object { $_.CommandLine -like '*mcp-kcops*' }

if (-not $procs) {
    Write-Host "[stop] 실행 중인 mcp-kcops 프로세스 없음" -ForegroundColor DarkYellow
    return
}

foreach ($p in $procs) {
    Write-Host "[stop] PID $($p.ProcessId) 종료" -ForegroundColor Yellow
    Stop-Process -Id $p.ProcessId -Force
}
Write-Host "[stop] 완료" -ForegroundColor Green
