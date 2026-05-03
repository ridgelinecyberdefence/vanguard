package usecases

// linuxUseCases returns UC-LNX-001 through UC-LNX-012.
//
// Step commands favour POSIX shell + standard tools (ps, ss, find, journalctl,
// systemctl, cat) so the workflows produce useful output on minimal Linux
// hosts.
func linuxUseCases() []UseCase {
	return []UseCase{
		ucLnxWebCompromise(),
		ucLnxSSHBruteForce(),
		ucLnxCryptominer(),
		ucLnxContainerEscape(),
		ucLnxRootkit(),
		ucLnxPersistence(),
		ucLnxPrivEsc(),
		ucLnxLogTampering(),
		ucLnxCloudCreds(),
		ucLnxFullTriage(),
		ucLnxNetworkIntrusion(),
		ucLnxSupplyChain(),
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-001 Web Server Compromise
// ---------------------------------------------------------------------------

func ucLnxWebCompromise() UseCase {
	return UseCase{
		Name:          "Web Server Compromise",
		ID:            "UC-LNX-001",
		Description:   "Investigate compromise of an Apache/Nginx host: access-log analysis, web-shell discovery, web-process anomalies, file-integrity sweeps.",
		Platform:      PlatformLinux,
		Severity:      SeverityCritical,
		EstimatedTime: "40-50 minutes",
		MITREAttack:   []string{"T1190", "T1505.003", "T1059.004"},
		Phases: []UseCasePhase{
			{
				Name: "Access-log signals",
				Steps: []UseCaseStep{
					{Name: "Top error responses", Type: StepCommand, Platform: PlatformLinux,
						Command: `for f in /var/log/apache2/access.log* /var/log/nginx/access.log* /var/log/httpd/access_log*; do [ -f "$f" ] && grep -E ' (403|404|500|502|503) ' "$f" 2>/dev/null | tail -200; done`},
					{Name: "SQL/XSS/path-traversal patterns", Type: StepCommand, Platform: PlatformLinux,
						Command: `for f in /var/log/apache2/access.log* /var/log/nginx/access.log* /var/log/httpd/access_log*; do [ -f "$f" ] && grep -iE 'union\+select|select.*from|drop\+table|/etc/passwd|\.\./|<script|onerror=|onload=' "$f" 2>/dev/null | tail -200; done`},
					{Name: "Suspicious user agents", Type: StepCommand, Platform: PlatformLinux,
						Command: `for f in /var/log/apache2/access.log* /var/log/nginx/access.log*; do [ -f "$f" ] && grep -iE 'sqlmap|nikto|nmap|nessus|wpscan|dirb|gobuster|ffuf' "$f" 2>/dev/null | tail -100; done`},
				},
			},
			{
				Name: "Web shell discovery",
				Steps: []UseCaseStep{
					{Name: "Recently modified web files", Type: StepCommand, Platform: PlatformLinux,
						Command: `find /var/www /usr/share/nginx /srv 2>/dev/null -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' -o -name '*.cgi' \) -mtime -30 -ls`,
						Timeout: 600},
					{Name: "Suspicious code patterns", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -RIn -E 'eval\(.*base64|system\(\$_|passthru\(|shell_exec\(|exec\(\$_' /var/www /usr/share/nginx /srv 2>/dev/null | head -200`,
						Timeout: 900},
				},
			},
			{
				Name: "Process & network anomalies",
				Steps: []UseCaseStep{
					{Name: "Web user running shell", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo user,pid,ppid,cmd | awk '($1 ~ /^(www-data|apache|nginx|httpd)$/) && ($0 ~ /sh|bash|nc|perl|python|wget|curl/)'`},
					{Name: "Web process network", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tulpan 2>/dev/null | grep -E 'apache2|nginx|httpd|php-fpm|www-data' || netstat -tulpan 2>/dev/null | grep -E 'apache2|nginx|httpd'`},
				},
			},
			{
				Name: "File integrity",
				Steps: []UseCaseStep{
					{Name: "Recently modified system binaries", Type: StepCommand, Platform: PlatformLinux,
						Command: `find /usr/bin /usr/sbin /bin /sbin -type f -mtime -30 -ls 2>/dev/null`,
						Timeout: 300},
					{Name: "Package verification (best effort)", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | head -200; command -v rpm >/dev/null && rpm -Va 2>/dev/null | head -200`,
						Timeout: 600},
				},
			},
		},
		AnalysisGuide: []string{
			"Cluster access-log hits by source IP — a single source generating SQLi/path-traversal patterns is your starting point.",
			"Confirm web-shell findings with file-modification timestamps relative to the access-log activity.",
			"Web user (www-data) running an interactive shell is high-fidelity post-exploitation.",
		},
		FollowUp: []string{"UC-LNX-007: Privilege Escalation", "UC-LNX-006: Persistence Discovery (Linux)"},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-002 SSH Brute Force Investigation
// ---------------------------------------------------------------------------

func ucLnxSSHBruteForce() UseCase {
	return UseCase{
		Name:          "SSH Brute Force Investigation",
		ID:            "UC-LNX-002",
		Description:   "Failed-SSH cluster analysis, post-success activity, authorized_keys + ssh_config tampering checks.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1110.001", "T1078", "T1098.004"},
		Phases: []UseCasePhase{
			{
				Name: "Auth log triage",
				Steps: []UseCaseStep{
					{Name: "Failed SSH attempts (top sources)", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -h 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -40`},
					{Name: "Successful SSH from external", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -h 'Accepted ' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -200`},
					{Name: "Targeted accounts", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -h 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="for"||$i=="user") {print $(i+1); break}}' | sort | uniq -c | sort -rn | head -40`},
				},
			},
			{
				Name: "Authorized keys & config",
				Steps: []UseCaseStep{
					{Name: "All authorized_keys", Type: StepCommand, Platform: PlatformLinux,
						Command: `for h in /root /home/*; do [ -f "$h/.ssh/authorized_keys" ] && echo "=== $h ===" && cat "$h/.ssh/authorized_keys"; done`},
					{Name: "SSH config (sshd)", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/ssh/sshd_config 2>/dev/null; echo '---'; ls -la /etc/ssh/sshd_config.d/ 2>/dev/null`},
					{Name: "SSH service journal", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `journalctl --no-pager -u ssh -u sshd --since '7 days ago' 2>/dev/null | tail -300`},
				},
			},
			{
				Name: "Post-compromise indicators",
				Steps: []UseCaseStep{
					{Name: "Recent commands by attacker accounts", Type: StepCommand, Platform: PlatformLinux,
						Command: `for u in $(getent passwd | cut -d: -f1); do home=$(getent passwd "$u" | cut -d: -f6); [ -f "$home/.bash_history" ] && echo "=== $u ===" && tail -50 "$home/.bash_history"; done`},
					{Name: "New accounts", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/passwd; echo '---'; grep -h 'new user\|useradd' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -100`},
				},
			},
		},
		AnalysisGuide: []string{
			"A successful login from a brute-force source is the highest-priority signal.",
			"Compare authorized_keys content against known-good configs — attacker-added keys grant persistence.",
		},
		FollowUp: []string{"UC-LNX-006: Persistence Discovery (Linux)", "UC-LNX-007: Privilege Escalation"},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-003 Cryptominer Detection
// ---------------------------------------------------------------------------

func ucLnxCryptominer() UseCase {
	return UseCase{
		Name:          "Cryptominer Detection",
		ID:            "UC-LNX-003",
		Description:   "High-CPU process review, miner-pool connections, persistence via cron with wget/curl, modified binaries.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1496", "T1543.002", "T1059.004"},
		Phases: []UseCasePhase{
			{
				Name: "Process indicators",
				Steps: []UseCaseStep{
					{Name: "High-CPU processes", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,user,pcpu,pmem,cmd --sort=-pcpu | head -20`},
					{Name: "Known miner names", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,user,cmd | grep -iE 'xmrig|minerd|kdevtmpfsi|kinsing|cnrig|cpuminer|ccminer|stratum' | grep -v grep`},
					{Name: "Process binaries on disk", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ls -la /proc/*/exe 2>/dev/null | head -200`},
				},
			},
			{
				Name: "Network indicators",
				Steps: []UseCaseStep{
					{Name: "Connections to mining ports", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tupan 2>/dev/null | grep -E ':3333|:5555|:7777|:8888|:14444|:14433|:9999' || netstat -tupan 2>/dev/null | grep -E ':3333|:5555|:7777|:8888|:14444'`},
					{Name: "Outbound established", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ss -tupan state established 2>/dev/null | head -100 || netstat -tupan 2>/dev/null | grep ESTABLISHED | head -100`},
				},
			},
			{
				Name: "Persistence",
				Steps: []UseCaseStep{
					{Name: "Cron with wget/curl", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -RIn -E 'wget|curl' /etc/cron* /var/spool/cron 2>/dev/null | head -100`},
					{Name: "Per-user crontabs", Type: StepCommand, Platform: PlatformLinux,
						Command: `for u in $(getent passwd | cut -d: -f1); do echo "=== $u ==="; crontab -u "$u" -l 2>/dev/null; done`},
					{Name: "Modified system binaries", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 -ls 2>/dev/null`},
				},
			},
		},
		AnalysisGuide: []string{
			"Sustained high CPU + traffic to port 3333/5555/7777 is a high-fidelity miner signal.",
			"kdevtmpfsi / kinsing are well-known cryptominer families — their presence alone justifies remediation.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-004 Container Escape
// ---------------------------------------------------------------------------

func ucLnxContainerEscape() UseCase {
	return UseCase{
		Name:          "Container Escape",
		ID:            "UC-LNX-004",
		Description:   "Privileged-container artifacts, capability misuse, mount-namespace abuse, Docker-socket exposure, host-FS access.",
		Platform:      PlatformLinux,
		Severity:      SeverityCritical,
		EstimatedTime: "35-45 minutes",
		MITREAttack:   []string{"T1611", "T1610", "T1068"},
		Phases: []UseCasePhase{
			{
				Name: "Container inventory",
				Steps: []UseCaseStep{
					{Name: "Docker containers", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v docker >/dev/null && docker ps -a --no-trunc 2>/dev/null`},
					{Name: "Container processes", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,user,nspid,cmd 2>/dev/null | head -100; ls -la /proc/*/ns/pid 2>/dev/null | sort -u | head -40`},
				},
			},
			{
				Name: "Capability & socket exposure",
				Steps: []UseCaseStep{
					{Name: "Process capabilities", Type: StepCommand, Platform: PlatformLinux,
						Command: `for pid in $(ls /proc | grep -E '^[0-9]+$' | head -100); do c=$(cat /proc/$pid/status 2>/dev/null | grep -E '^CapEff'); [ -n "$c" ] && echo "$pid $c"; done | head -50`},
					{Name: "Docker socket mounted in containers", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v docker >/dev/null && docker ps -q 2>/dev/null | xargs -I{} docker inspect {} 2>/dev/null | grep -E 'docker.sock|Source.*sock' | head -50`},
					{Name: "Host /proc/1/root accessible", Type: StepCommand, Platform: PlatformLinux,
						Command: `ls -la /proc/1/root 2>/dev/null; readlink /proc/1/root 2>/dev/null`},
				},
			},
			{
				Name: "Filesystem & namespace anomalies",
				Steps: []UseCaseStep{
					{Name: "Cgroup mounts", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `cat /proc/self/mountinfo 2>/dev/null | head -100`},
					{Name: "Suspicious privileged binaries in container", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -200`,
						Timeout: 600},
				},
			},
		},
		AnalysisGuide: []string{
			"CAP_SYS_ADMIN inside a container is effectively root on the host.",
			"docker.sock exposed inside a workload container is a guaranteed escape vector.",
		},
		FollowUp: []string{"UC-LNX-007: Privilege Escalation"},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-005 Rootkit Detection
// ---------------------------------------------------------------------------

func ucLnxRootkit() UseCase {
	return UseCase{
		Name:          "Rootkit Detection",
		ID:            "UC-LNX-005",
		Description:   "Process/file hiding checks, kernel-module integrity, LD_PRELOAD abuse, package verification, optional chkrootkit/rkhunter.",
		Platform:      PlatformLinux,
		Severity:      SeverityCritical,
		EstimatedTime: "30-40 minutes",
		MITREAttack:   []string{"T1014", "T1547.006", "T1574.006"},
		Phases: []UseCasePhase{
			{
				Name: "Process & file hiding",
				Steps: []UseCaseStep{
					{Name: "ps vs /proc count", Type: StepCommand, Platform: PlatformLinux,
						Command: `echo "ps count: $(ps -ef | wc -l)"; echo "/proc count: $(ls /proc | grep -E '^[0-9]+$' | wc -l)"`},
					{Name: "Hidden /tmp and /var/tmp files", Type: StepCommand, Platform: PlatformLinux,
						Command: `find /tmp /var/tmp /dev/shm -name '.*' -type f 2>/dev/null | head -100`},
				},
			},
			{
				Name: "Kernel & loader integrity",
				Steps: []UseCaseStep{
					{Name: "Kernel modules", Type: StepCommand, Platform: PlatformLinux,
						Command: `lsmod 2>/dev/null`},
					{Name: "Modules per /proc/modules", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /proc/modules 2>/dev/null`},
					{Name: "LD_PRELOAD config", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/ld.so.preload 2>/dev/null; env | grep -i LD_PRELOAD`},
					{Name: "Loaded shared libs in PID 1", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `cat /proc/1/maps 2>/dev/null | awk '{print $6}' | sort -u | head -100`},
				},
			},
			{
				Name: "Package / binary integrity",
				Steps: []UseCaseStep{
					{Name: "Package verification", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 900,
						Command: `command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | head -200; command -v rpm >/dev/null && rpm -Va 2>/dev/null | head -200`},
					{Name: "chkrootkit", Type: StepTool, Tool: "chkrootkit-lnx", Platform: PlatformLinux, Optional: true, Timeout: 900,
						Command: `chkrootkit`},
					{Name: "rkhunter", Type: StepTool, Tool: "rkhunter-lnx", Platform: PlatformLinux, Optional: true, Timeout: 900,
						Command: `rkhunter --check --skip-keypress --report-warnings-only`},
				},
			},
		},
		AnalysisGuide: []string{
			"Mismatched ps vs /proc counts suggest a userland rootkit hooking ps.",
			"Anything in /etc/ld.so.preload that isn't part of standard distro tooling is high-priority.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-006 Persistence Discovery (Linux)
// ---------------------------------------------------------------------------

func ucLnxPersistence() UseCase {
	return UseCase{
		Name:          "Persistence Discovery",
		ID:            "UC-LNX-006",
		Description:   "Cron, systemd, init.d, shell profiles, authorized_keys, kernel modules, PAM, udev rules.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1053.003", "T1543.002", "T1546.004", "T1098.004"},
		Phases: []UseCasePhase{
			{
				Name: "Cron, systemd, init",
				Steps: []UseCaseStep{
					{Name: "Cron config + drops", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; for u in $(getent passwd | cut -d: -f1); do echo "=== $u ==="; crontab -u "$u" -l 2>/dev/null; done`},
					{Name: "Systemd unit listing", Type: StepCommand, Platform: PlatformLinux,
						Command: `systemctl list-unit-files --type=service --no-pager 2>/dev/null; systemctl list-timers --all --no-pager 2>/dev/null`},
					{Name: "/etc/init.d", Type: StepCommand, Platform: PlatformLinux,
						Command: `ls -la /etc/init.d/ 2>/dev/null`},
				},
			},
			{
				Name: "Shell profiles & SSH",
				Steps: []UseCaseStep{
					{Name: "Modified bash profiles", Type: StepCommand, Platform: PlatformLinux,
						Command: `for h in /root /home/*; do for f in .bashrc .bash_profile .profile .zshrc; do [ -f "$h/$f" ] && echo "=== $h/$f ===" && stat "$h/$f" && cat "$h/$f"; done; done | head -300`},
					{Name: "authorized_keys per user", Type: StepCommand, Platform: PlatformLinux,
						Command: `for h in /root /home/*; do [ -f "$h/.ssh/authorized_keys" ] && echo "=== $h ===" && cat "$h/.ssh/authorized_keys"; done`},
				},
			},
			{
				Name: "Kernel & PAM hooks",
				Steps: []UseCaseStep{
					{Name: "Kernel modules", Type: StepCommand, Platform: PlatformLinux,
						Command: `lsmod 2>/dev/null`},
					{Name: "PAM modules", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ls -la /etc/pam.d/ 2>/dev/null; ls -la /lib/x86_64-linux-gnu/security 2>/dev/null; ls -la /lib64/security 2>/dev/null`},
					{Name: "udev rules", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ls -la /etc/udev/rules.d/ /lib/udev/rules.d/ 2>/dev/null`},
					{Name: "LD_PRELOAD", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/ld.so.preload 2>/dev/null`},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-007 Privilege Escalation
// ---------------------------------------------------------------------------

func ucLnxPrivEsc() UseCase {
	return UseCase{
		Name:          "Privilege Escalation",
		ID:            "UC-LNX-007",
		Description:   "SUID/SGID inventory, sudo policy review, capabilities, writable PATH dirs, polkit, kernel-exploit remnants.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1068", "T1548.003", "T1548.001"},
		Phases: []UseCasePhase{
			{
				Name: "SUID / capabilities",
				Steps: []UseCaseStep{
					{Name: "SUID/SGID binaries", Type: StepCommand, Platform: PlatformLinux,
						Command: `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -200`,
						Timeout: 600},
					{Name: "File capabilities", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 600,
						Command: `command -v getcap >/dev/null && getcap -r / 2>/dev/null | head -200`},
				},
			},
			{
				Name: "Sudo policy",
				Steps: []UseCaseStep{
					{Name: "Sudoers", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null; for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "=== $f ===" && cat "$f"; done`},
					{Name: "NOPASSWD entries", Type: StepCommand, Platform: PlatformLinux,
						Command: `grep -RIn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null`},
				},
			},
			{
				Name: "PATH & exploit remnants",
				Steps: []UseCaseStep{
					{Name: "Writable PATH dirs", Type: StepCommand, Platform: PlatformLinux,
						Command: `IFS=:; for p in $PATH; do [ -d "$p" ] && [ -w "$p" ] && echo "writable: $p"; done`},
					{Name: "Recent /tmp executables", Type: StepCommand, Platform: PlatformLinux,
						Command: `find /tmp /var/tmp /dev/shm -type f -executable -mtime -14 -ls 2>/dev/null`},
					{Name: "Docker group members", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `getent group docker 2>/dev/null`},
					{Name: "Polkit / pkexec", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ls -la /usr/bin/pkexec 2>/dev/null; pkexec --version 2>/dev/null`},
				},
			},
		},
		AnalysisGuide: []string{
			"Compare SUID list against the distro's known-good baseline (gtfobins is a useful reference for risky entries).",
			"NOPASSWD ALL rules are usually misconfigurations — investigate when the rule was added.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-008 Log Tampering Detection
// ---------------------------------------------------------------------------

func ucLnxLogTampering() UseCase {
	return UseCase{
		Name:          "Log Tampering Detection",
		ID:            "UC-LNX-008",
		Description:   "Log gaps, truncated files, journal integrity, syslog forwarding status, auditd state.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "20-30 minutes",
		MITREAttack:   []string{"T1070.002", "T1070.003"},
		Phases: []UseCasePhase{
			{
				Name: "File-level integrity",
				Steps: []UseCaseStep{
					{Name: "Log file sizes & timestamps", Type: StepCommand, Platform: PlatformLinux,
						Command: `ls -la /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/kern.log* 2>/dev/null`},
					{Name: "Truncated logs (size = 0)", Type: StepCommand, Platform: PlatformLinux,
						Command: `find /var/log -maxdepth 2 -type f -size 0 -ls 2>/dev/null`},
					{Name: "Auth log sample tail", Type: StepCommand, Platform: PlatformLinux,
						Command: `tail -200 /var/log/auth.log 2>/dev/null; tail -200 /var/log/secure 2>/dev/null`},
				},
			},
			{
				Name: "Journal & syslog",
				Steps: []UseCaseStep{
					{Name: "Journal verify", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `journalctl --verify 2>&1 | tail -100`},
					{Name: "Journal boots", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `journalctl --list-boots --no-pager 2>/dev/null`},
					{Name: "Rsyslog forwarding config", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `cat /etc/rsyslog.conf 2>/dev/null; ls /etc/rsyslog.d/ 2>/dev/null`},
				},
			},
			{
				Name: "auditd",
				Steps: []UseCaseStep{
					{Name: "auditd status", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v auditctl >/dev/null && { auditctl -s; auditctl -l; } 2>/dev/null`},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-009 Cloud Credential Theft
// ---------------------------------------------------------------------------

func ucLnxCloudCreds() UseCase {
	return UseCase{
		Name:          "Cloud Credential Theft",
		ID:            "UC-LNX-009",
		Description:   "AWS/Azure/GCP credentials, Kubernetes service-account tokens, Docker registry creds, SSH keys, env vars.",
		Platform:      PlatformLinux,
		Severity:      SeverityCritical,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1552.001", "T1552.005", "T1552.007"},
		Phases: []UseCasePhase{
			{
				Name: "Cloud SDK credentials",
				Steps: []UseCaseStep{
					{Name: "AWS profiles", Type: StepCommand, Platform: PlatformLinux,
						Command: `for h in /root /home/*; do for f in .aws/credentials .aws/config; do [ -f "$h/$f" ] && echo "=== $h/$f ===" && stat "$h/$f"; done; done`},
					{Name: "Azure profile", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `for h in /root /home/*; do [ -d "$h/.azure" ] && ls -la "$h/.azure"; done`},
					{Name: "GCP config", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `for h in /root /home/*; do [ -d "$h/.config/gcloud" ] && ls -la "$h/.config/gcloud"; done`},
				},
			},
			{
				Name: "Kubernetes & Docker",
				Steps: []UseCaseStep{
					{Name: "Kube configs", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `for h in /root /home/*; do [ -f "$h/.kube/config" ] && echo "=== $h ===" && stat "$h/.kube/config"; done`},
					{Name: "Service-account tokens (in-pod)", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `find /var/run/secrets/kubernetes.io -type f 2>/dev/null | head -20`},
					{Name: "Docker registry config", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `for h in /root /home/*; do [ -f "$h/.docker/config.json" ] && echo "=== $h ===" && cat "$h/.docker/config.json"; done`},
				},
			},
			{
				Name: "SSH keys & env",
				Steps: []UseCaseStep{
					{Name: "Per-user SSH keys", Type: StepCommand, Platform: PlatformLinux,
						Command: `for h in /root /home/*; do [ -d "$h/.ssh" ] && echo "=== $h ===" && ls -la "$h/.ssh"; done`},
					{Name: "Env vars (current shell scope)", Type: StepCommand, Platform: PlatformLinux,
						Command: `env | grep -E 'AWS_|AZURE_|GOOGLE_|GCP_|VAULT_|TOKEN|KEY' 2>/dev/null`},
					{Name: "IMDS reachability (best effort)", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 30,
						Command: `curl -sS --max-time 3 http://169.254.169.254/latest/meta-data/ 2>&1 | head -10`},
				},
			},
		},
		AnalysisGuide: []string{
			"Look for credentials.txt / .pem / .json with cloud-credential prefixes outside the normal config dirs.",
			"IMDS reachability + a curl to 169.254.169.254 is a classic cloud-cred-theft pattern in containers.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-010 Full Linux Triage
// ---------------------------------------------------------------------------

func ucLnxFullTriage() UseCase {
	return UseCase{
		Name:          "Full Linux Triage",
		ID:            "UC-LNX-010",
		Description:   "Comprehensive Linux triage: system info, processes, network, logs, persistence, users, packages, file analysis.",
		Platform:      PlatformLinux,
		Severity:      SeverityMedium,
		EstimatedTime: "45-60 minutes",
		Phases: []UseCasePhase{
			{
				Name: "System snapshot",
				Steps: []UseCaseStep{
					{Name: "uname / OS / uptime", Type: StepCommand, Platform: PlatformLinux,
						Command: `uname -a; cat /etc/os-release 2>/dev/null; uptime; hostnamectl 2>/dev/null`},
					{Name: "Whoami / id / groups", Type: StepCommand, Platform: PlatformLinux,
						Command: `whoami; id; groups`},
				},
			},
			{
				Name: "Processes & network",
				Steps: []UseCaseStep{
					{Name: "Process tree", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps auxwwf`},
					{Name: "Sockets", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tulpan 2>/dev/null || netstat -tulpan 2>/dev/null`},
					{Name: "Interfaces / routes / arp", Type: StepCommand, Platform: PlatformLinux,
						Command: `ip addr show; ip route show; ip neigh show`},
				},
			},
			{
				Name: "Persistence & users",
				Steps: []UseCaseStep{
					{Name: "Cron + systemd timers", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; for u in $(getent passwd | cut -d: -f1); do echo "=== $u ==="; crontab -u "$u" -l 2>/dev/null; done; systemctl list-timers --all --no-pager 2>/dev/null`},
					{Name: "Logged-on / last", Type: StepCommand, Platform: PlatformLinux,
						Command: `who; w; last -50; lastb -50 2>/dev/null`},
					{Name: "Users / sudoers", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/passwd; echo '---'; cat /etc/group; echo '---'; cat /etc/sudoers 2>/dev/null`},
				},
			},
			{
				Name: "Logs & packages",
				Steps: []UseCaseStep{
					{Name: "Auth log tail", Type: StepCommand, Platform: PlatformLinux,
						Command: `tail -200 /var/log/auth.log 2>/dev/null; tail -200 /var/log/secure 2>/dev/null`},
					{Name: "Journal recent", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `journalctl --no-pager --since '24 hours ago' 2>/dev/null | tail -300`},
					{Name: "Installed packages", Type: StepCommand, Platform: PlatformLinux,
						Command: `dpkg -l 2>/dev/null || rpm -qa --last 2>/dev/null | head -200`},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-011 Network Intrusion
// ---------------------------------------------------------------------------

func ucLnxNetworkIntrusion() UseCase {
	return UseCase{
		Name:          "Network Intrusion",
		ID:            "UC-LNX-011",
		Description:   "Active connections, listening ports, reverse-shell indicators, tunnel artifacts (ssh -R, socat, chisel), DNS cache.",
		Platform:      PlatformLinux,
		Severity:      SeverityHigh,
		EstimatedTime: "30-40 minutes",
		MITREAttack:   []string{"T1059.004", "T1572", "T1071", "T1090"},
		Phases: []UseCasePhase{
			{
				Name: "Connections & listeners",
				Steps: []UseCaseStep{
					{Name: "Active connections", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tupan 2>/dev/null || netstat -tupan 2>/dev/null`},
					{Name: "Listening ports", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null`},
					{Name: "Connection-table summary", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -s 2>/dev/null`},
				},
			},
			{
				Name: "Reverse-shell / tunnel indicators",
				Steps: []UseCaseStep{
					{Name: "Bash -i / /dev/tcp", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,user,cmd | grep -E 'bash -i|/dev/tcp/|/dev/udp/|nc -e|ncat -e|socat ' | grep -v grep`},
					{Name: "Tunneling tools running", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,user,cmd | grep -iE 'socat|chisel|frpc|ssh -R|ssh -D|ngrok' | grep -v grep`},
				},
			},
			{
				Name: "DNS / firewall",
				Steps: []UseCaseStep{
					{Name: "Resolv conf + hosts", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/resolv.conf 2>/dev/null; echo '---'; cat /etc/hosts 2>/dev/null`},
					{Name: "iptables / nftables", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `iptables-save 2>/dev/null; nft list ruleset 2>/dev/null`},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// UC-LNX-012 Supply Chain Compromise
// ---------------------------------------------------------------------------

func ucLnxSupplyChain() UseCase {
	return UseCase{
		Name:          "Supply Chain Compromise",
		ID:            "UC-LNX-012",
		Description:   "Package verification, recently installed packages, repo config, language-package suspiciousness (pip/npm).",
		Platform:      PlatformLinux,
		Severity:      SeverityCritical,
		EstimatedTime: "35-45 minutes",
		MITREAttack:   []string{"T1195.001", "T1195.002"},
		Phases: []UseCasePhase{
			{
				Name: "Package integrity",
				Steps: []UseCaseStep{
					{Name: "dpkg --verify", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 900,
						Command: `command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | head -300`},
					{Name: "rpm -Va", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 900,
						Command: `command -v rpm >/dev/null && rpm -Va 2>/dev/null | head -300`},
				},
			},
			{
				Name: "Recent package activity",
				Steps: []UseCaseStep{
					{Name: "Recently installed (apt)", Type: StepCommand, Platform: PlatformLinux,
						Command: `[ -f /var/log/apt/history.log ] && tail -300 /var/log/apt/history.log 2>/dev/null`},
					{Name: "Recently installed (yum/dnf)", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v yum >/dev/null && yum history list 2>/dev/null | head -60; command -v dnf >/dev/null && dnf history list 2>/dev/null | head -60`},
					{Name: "Recently installed (rpm last)", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v rpm >/dev/null && rpm -qa --last 2>/dev/null | head -100`},
				},
			},
			{
				Name: "Repos & language packages",
				Steps: []UseCaseStep{
					{Name: "APT sources", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `cat /etc/apt/sources.list 2>/dev/null; ls /etc/apt/sources.list.d/ 2>/dev/null; cat /etc/apt/sources.list.d/*.list 2>/dev/null | head -200`},
					{Name: "YUM repos", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `ls /etc/yum.repos.d/ 2>/dev/null; cat /etc/yum.repos.d/*.repo 2>/dev/null | head -300`},
					{Name: "pip / npm packages", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `command -v pip >/dev/null && pip list 2>/dev/null | head -200; command -v pip3 >/dev/null && pip3 list 2>/dev/null | head -200; command -v npm >/dev/null && npm list -g 2>/dev/null | head -200`},
				},
			},
		},
		AnalysisGuide: []string{
			"dpkg --verify failures (5 = MD5, M = mode, U = user) flag binary tampering.",
			"Recently added repos that aren't on the company's allow-list are major red flags.",
		},
	}
}
