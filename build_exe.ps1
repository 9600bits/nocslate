param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$FrontendDist = Join-Path $Root "frontend\dist"

Push-Location (Join-Path $Root "frontend")
try {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "前端构建失败" }
}
finally {
    Pop-Location
}

if (-not (Test-Path (Join-Path $FrontendDist "index.html"))) {
    throw "未找到 frontend/dist/index.html"
}

& $Python -m PyInstaller --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "未检测到 PyInstaller。请先执行: python -m pip install -r backend\requirements.txt"
}

& $Python -m PyInstaller `
    --noconfirm `
    --onefile `
    --name PacketLens `
    --add-data "$FrontendDist;static" `
    --collect-all scapy `
    (Join-Path $Root "backend\run.py")

if ($LASTEXITCODE -ne 0) { throw "PyInstaller 打包失败" }

Write-Host ""
Write-Host "打包完成: $(Join-Path $Root "dist\PacketLens.exe")"
