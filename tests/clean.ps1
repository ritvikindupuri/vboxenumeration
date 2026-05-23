docker stop $(docker ps -q -f "name=falco") 2>$null
docker stop $(docker ps -q -f "name=honeypot") 2>$null
docker stop $(docker ps -q -f "name=soc-") 2>$null
docker system prune -f 2>$null
Write-Host "FalcoHive stopped & cleaned" -ForegroundColor Green
