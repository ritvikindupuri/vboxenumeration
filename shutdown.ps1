Write-Host "Stopping VBoxAuditor..." -ForegroundColor Cyan

$pythonProcs = Get-Process -Name "python*" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "main.py"
}
if ($pythonProcs) {
    $pythonProcs | Stop-Process -Force
    Write-Host "Stopped Python process(es)" -ForegroundColor Green
} else {
    Write-Host "No Python process found" -ForegroundColor Yellow
}

$portProcs = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
if ($portProcs) {
    $owningPids = $portProcs | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($pid in $owningPids) {
        Stop-Process -Id $pid -Force
        Write-Host "Stopped process $pid holding port 8080" -ForegroundColor Green
    }
}

Write-Host "VBoxAuditor shutdown complete." -ForegroundColor Cyan
