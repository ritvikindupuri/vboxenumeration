docker stop honeypot-web honeypot-redis honeypot-python soc-falco 2>$null
docker rm honeypot-web honeypot-redis honeypot-python soc-falco 2>$null
Write-Host "Cleaned up all containers" -ForegroundColor Green
