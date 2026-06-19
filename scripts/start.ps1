# MCP Kcops 로컬 테스트 환경 기동 스크립트
# - mock MCP 서버(8090) + 프록시 방화벽(8080)을 별도 창으로 띄우고 헬스 체크까지 대기한다.
# 사용법:
#   .\scripts\start.ps1                 # 기본(관리자 API 비활성: admin token 미설정)
#   .\scripts\start.ps1 -AdminToken secret   # 관리자 API 활성(토큰=secret)
param(
    [string]$AdminToken = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$jar = Join-Path $root "build\libs\mcp-kcops-0.0.1-SNAPSHOT.jar"

if (-not $SkipBuild -or -not (Test-Path $jar)) {
    Write-Host "[start] bootJar 빌드 중..." -ForegroundColor Cyan
    & "$root\gradlew.bat" bootJar -q
    if ($LASTEXITCODE -ne 0) { throw "빌드 실패" }
}

if (-not (Test-Path $jar)) { throw "jar 없음: $jar" }

function Wait-Health($url, $name) {
    Write-Host "[start] $name 기동 대기: $url" -ForegroundColor Cyan
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $url -Method Post -Body '{}' -ContentType 'application/json' -TimeoutSec 2 -UseBasicParsing
            return $true
        } catch {
            # 4xx/5xx 응답이라도 포트가 열렸으면 기동된 것으로 간주
            if ($_.Exception.Response) { return $true }
        }
        Start-Sleep -Milliseconds 1000
    }
    return $false
}

# mock 서버 기동(8090)
Write-Host "[start] mock MCP 서버(8090) 기동..." -ForegroundColor Green
Start-Process -FilePath "java" `
    -ArgumentList "-jar", "`"$jar`"", "--spring.profiles.active=mock" `
    -WindowStyle Minimized

# 프록시 기동(8080)
$proxyArgs = @("-jar", "`"$jar`"")
if ($AdminToken -ne "") {
    $proxyArgs += "--kcops.admin.token=$AdminToken"
    Write-Host "[start] 관리자 API 토큰 활성: $AdminToken" -ForegroundColor Yellow
} else {
    Write-Host "[start] 관리자 API 비활성(토큰 미설정 → /admin/** 503)" -ForegroundColor DarkYellow
}
Write-Host "[start] 프록시 방화벽(8080) 기동..." -ForegroundColor Green
Start-Process -FilePath "java" -ArgumentList $proxyArgs -WindowStyle Minimized

if (Wait-Health "http://localhost:8090/mcp" "mock(8090)") {
    Write-Host "[start] mock(8090) OK" -ForegroundColor Green
} else {
    Write-Host "[start] mock(8090) 응답 없음" -ForegroundColor Red
}
if (Wait-Health "http://localhost:8080/mcp" "proxy(8080)") {
    Write-Host "[start] proxy(8080) OK" -ForegroundColor Green
} else {
    Write-Host "[start] proxy(8080) 응답 없음" -ForegroundColor Red
}

Write-Host ""
Write-Host "준비 완료. 테스트: .\scripts\demo.ps1   종료: .\scripts\stop.ps1" -ForegroundColor Cyan
