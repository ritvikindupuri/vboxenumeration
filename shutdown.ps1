param([switch]$Force)

Write-Host "========================================" -ForegroundColor Red
Write-Host "  FalcoHive - Full Shutdown" -ForegroundColor Red
Write-Host "========================================`n" -ForegroundColor Red

if (-not $Force) {
    Write-Host "[!] This will stop and remove ALL containers." -ForegroundColor Yellow
    $confirm = Read-Host "Type 'shutdown' to confirm"
    if ($confirm -ne 'shutdown') { Write-Host "Cancelled"; exit }
}

Write-Host "[1/4] Stopping Docker Compose services..." -ForegroundColor Yellow
docker compose -f "$PSScriptRoot\..\docker-compose.yml" down --volumes 2>$null
Write-Host "  -> Docker Compose stopped"

Write-Host "[2/4] Stopping Falco..." -ForegroundColor Yellow
docker stop soc-falco falco-soc-agent 2>$null
docker rm soc-falco falco-soc-agent 2>$null 2>$null
Write-Host "  -> Falco stopped"

Write-Host "[3/4] Stopping honeypots..." -ForegroundColor Yellow
docker stop honeypot-web honeypot-redis honeypot-python soc-falco soc-elasticsearch soc-kibana soc-ai-engine 2>$null
docker rm honeypot-web honeypot-redis honeypot-python soc-falco soc-elasticsearch soc-kibana soc-ai-engine 2>$null
Write-Host "  -> Honeypots removed"

Write-Host "[4/4] Pruning unused resources..." -ForegroundColor Yellow
docker system prune -f --volumes 2>$null
Write-Host "  -> Pruned"

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  FalcoHive fully shut down" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
