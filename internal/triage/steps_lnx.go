package triage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// LinuxSteps returns the ordered list of Linux triage collection steps.
func LinuxSteps() []StepDef {
	return []StepDef{
		{Name: "System Information", SubDir: "system", RunFunc: lnxSystemInfo},
		{Name: "Process Listing", SubDir: "processes", RunFunc: lnxProcesses},
		{Name: "Network Connections", SubDir: "network", RunFunc: lnxNetwork},
		{Name: "Log Collection", SubDir: "logs", RunFunc: lnxLogCollection},
		{Name: "Persistence Check", SubDir: "persistence", RunFunc: lnxPersistence},
		{Name: "User Activity", SubDir: "users", RunFunc: lnxUserActivity},
		{Name: "System Info Extended", SubDir: "system", RunFunc: lnxSystemInfoExtended},
	}
}

// LinuxFullTriageIndices returns the indices for a full triage run.
func LinuxFullTriageIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6}
}

// LinuxProcessNetworkIndices returns indices for Process & Network Snapshot.
func LinuxProcessNetworkIndices() []int {
	return []int{1, 2}
}

// LinuxLogIndices returns indices for Log Collection.
func LinuxLogIndices() []int {
	return []int{3}
}

// LinuxPersistenceIndices returns indices for Persistence Check.
func LinuxPersistenceIndices() []int {
	return []int{4}
}

// LinuxUserActivityIndices returns indices for User Activity.
func LinuxUserActivityIndices() []int {
	return []int{5}
}

// LinuxSystemInfoIndices returns indices for System Information + Extended.
func LinuxSystemInfoIndices() []int {
	return []int{0, 6}
}

// LinuxCronServicesIndices returns indices for Cron & Services (same as persistence).
func LinuxCronServicesIndices() []int {
	return []int{4}
}

// ---------------------------------------------------------------------------
// Step implementations
// ---------------------------------------------------------------------------

// lnxCmd is a convenience for shell commands on Linux.
type lnxCmd struct {
	outFile string
	command string
}

func runLnxCmds(ctx context.Context, outDir string, logger *logging.Logger, name string, cmds []lnxCmd) StepResult {
	result := StepResult{Name: name, Status: StepSuccess}
	succeeded := 0
	total := len(cmds)

	for _, c := range cmds {
		outPath := ""
		if c.outFile != "" {
			outPath = filepath.Join(outDir, c.outFile)
		}
		_, err := runShell(ctx, outPath, c.command)
		if err != nil {
			warning := fmt.Sprintf("%s: %v", c.outFile, err)
			result.Warnings = append(result.Warnings, warning)
			if logger != nil {
				logger.Warn("triage", "%s — %s", name, warning)
			}
		} else {
			succeeded++
		}
	}

	if succeeded == 0 && total > 0 {
		result.Status = StepFailed
	} else if succeeded < total {
		result.Status = StepPartial
	}

	return result
}

// ---------------------------------------------------------------------------
// System Information
// ---------------------------------------------------------------------------

func lnxSystemInfo(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	cmds := []lnxCmd{
		{"uname.txt", "uname -a"},
		{"os_release.txt", "cat /etc/os-release 2>/dev/null"},
		{"hostname.txt", "hostname"},
		{"uptime.txt", "uptime"},
		{"date.txt", "date"},
		{"current_user.txt", "id"},
		{"logged_in_users.txt", "who"},
		{"user_activity.txt", "w"},
		{"last_logins.txt", "last -100"},
		{"failed_logins.txt", "lastb -100 2>/dev/null"},
		{"disk_usage.txt", "df -h"},
		{"mounts.txt", "mount"},
		{"block_devices.txt", "lsblk 2>/dev/null"},
		{"memory.txt", "free -h"},
		{"cpuinfo.txt", "cat /proc/cpuinfo"},
	}
	return runLnxCmds(ctx, outDir, logger, "System Information", cmds)
}

// ---------------------------------------------------------------------------
// Process Listing
// ---------------------------------------------------------------------------

func lnxProcesses(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	cmds := []lnxCmd{
		{"ps_full.txt", "ps auxwwf"},
		{"ps_sorted.txt", "ps -eo pid,ppid,user,comm,args,etime,start --sort=-start"},
		{"proc_exe_links.txt", "ls -la /proc/*/exe 2>/dev/null"},
		{"proc_cmdlines.txt", "for p in /proc/[0-9]*/cmdline; do pid=$(echo $p | grep -o '[0-9]*'); printf \"PID %s: \" \"$pid\"; cat $p 2>/dev/null | tr '\\0' ' '; echo; done"},
	}
	return runLnxCmds(ctx, outDir, logger, "Process Listing", cmds)
}

// ---------------------------------------------------------------------------
// Network Connections
// ---------------------------------------------------------------------------

func lnxNetwork(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	cmds := []lnxCmd{
		{"ss_connections.txt", "ss -tulpan"},
		{"netstat.txt", "netstat -tulpan 2>/dev/null"},
		{"ip_addr.txt", "ip addr"},
		{"ip_route.txt", "ip route"},
		{"arp.txt", "ip neigh"},
		{"resolv.txt", "cat /etc/resolv.conf 2>/dev/null"},
		{"iptables.txt", "iptables -L -n -v 2>/dev/null"},
		{"ip6tables.txt", "ip6tables -L -n -v 2>/dev/null"},
	}
	return runLnxCmds(ctx, outDir, logger, "Network Connections", cmds)
}

// ---------------------------------------------------------------------------
// Log Collection
// ---------------------------------------------------------------------------

func lnxLogCollection(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	result := StepResult{Name: "Log Collection", Status: StepSuccess}
	succeeded := 0

	// Copy log files using shell glob expansion.
	logSources := []string{
		"/var/log/auth.log*",
		"/var/log/secure*",
		"/var/log/syslog*",
		"/var/log/messages*",
		"/var/log/kern.log*",
		"/var/log/cron*",
		"/var/log/apt/history.log*",
		"/var/log/yum.log*",
		"/var/log/dnf.log*",
		"/var/log/apache2/access.log*",
		"/var/log/nginx/access.log*",
		"/var/log/httpd/access_log*",
	}

	for _, pattern := range logSources {
		cmd := fmt.Sprintf("cp %s '%s/' 2>/dev/null", pattern, outDir)
		_, err := runShell(ctx, "", cmd)
		if err == nil {
			succeeded++
		}
		// Not finding a log is expected — don't warn.
	}

	// Journal.
	journalPath := filepath.Join(outDir, "journal_recent.txt")
	_, err := runShell(ctx, journalPath, "journalctl --no-pager -n 10000 2>/dev/null")
	if err == nil {
		succeeded++
	}

	if succeeded == 0 {
		result.Status = StepPartial
		result.Warnings = append(result.Warnings, "No log files could be collected")
	}

	return result
}

// ---------------------------------------------------------------------------
// Persistence Check
// ---------------------------------------------------------------------------

func lnxPersistence(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	result := StepResult{Name: "Persistence Check", Status: StepSuccess}
	succeeded := 0
	total := 0

	// Basic commands.
	basicCmds := []lnxCmd{
		{"crontab_current_user.txt", "crontab -l 2>/dev/null"},
		{"cron_d.txt", "ls -la /etc/cron.d/ 2>/dev/null"},
		{"cron_daily.txt", "ls -la /etc/cron.daily/ 2>/dev/null"},
		{"cron_hourly.txt", "ls -la /etc/cron.hourly/ 2>/dev/null"},
		{"cron_weekly.txt", "ls -la /etc/cron.weekly/ 2>/dev/null"},
		{"cron_monthly.txt", "ls -la /etc/cron.monthly/ 2>/dev/null"},
		{"etc_crontab.txt", "cat /etc/crontab 2>/dev/null"},
		{"systemd_services.txt", "systemctl list-units --type=service --all 2>/dev/null"},
		{"systemd_unit_files.txt", "systemctl list-unit-files --type=service 2>/dev/null"},
		{"rc_local.txt", "cat /etc/rc.local 2>/dev/null"},
		{"init_d.txt", "ls -la /etc/init.d/ 2>/dev/null"},
		{"custom_systemd.txt", "find /etc/systemd/system -name '*.service' -exec ls -la {} \\; 2>/dev/null"},
		{"kernel_modules.txt", "lsmod"},
	}

	for _, c := range basicCmds {
		total++
		outPath := filepath.Join(outDir, c.outFile)
		_, err := runShell(ctx, outPath, c.command)
		if err == nil {
			succeeded++
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", c.outFile, err))
		}
	}

	// Per-user crontabs.
	passwdData, err := os.ReadFile("/etc/passwd")
	if err == nil {
		for _, line := range strings.Split(string(passwdData), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 7 {
				continue
			}
			user := fields[0]
			shell := fields[6]
			if shell == "/usr/sbin/nologin" || shell == "/bin/false" || shell == "" {
				continue
			}
			total++
			outPath := filepath.Join(outDir, fmt.Sprintf("crontab_%s.txt", user))
			_, err := runShell(ctx, outPath,
				fmt.Sprintf("crontab -u %s -l 2>/dev/null", user))
			if err == nil {
				succeeded++
			}
		}
	}

	if succeeded == 0 && total > 0 {
		result.Status = StepFailed
	} else if succeeded < total {
		result.Status = StepPartial
	}

	return result
}

// ---------------------------------------------------------------------------
// User Activity
// ---------------------------------------------------------------------------

func lnxUserActivity(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	result := StepResult{Name: "User Activity", Status: StepSuccess}
	succeeded := 0
	total := 0

	// System files.
	sysCmds := []lnxCmd{
		{"passwd.txt", "cat /etc/passwd"},
		{"group.txt", "cat /etc/group"},
		{"shadow.txt", "cat /etc/shadow 2>/dev/null"},
		{"sudoers.txt", "cat /etc/sudoers 2>/dev/null"},
		{"sudoers_d.txt", "ls -la /etc/sudoers.d/ 2>/dev/null"},
	}

	for _, c := range sysCmds {
		total++
		outPath := filepath.Join(outDir, c.outFile)
		_, err := runShell(ctx, outPath, c.command)
		if err == nil {
			succeeded++
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", c.outFile, err))
		}
	}

	// Per-user home directories.
	homes := []string{"/root"}
	entries, err := os.ReadDir("/home")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}

	for _, home := range homes {
		user := filepath.Base(home)
		artifacts := []struct {
			src     string
			outName string
		}{
			{filepath.Join(home, ".bash_history"), fmt.Sprintf("%s_bash_history.txt", user)},
			{filepath.Join(home, ".zsh_history"), fmt.Sprintf("%s_zsh_history.txt", user)},
			{filepath.Join(home, ".ssh", "authorized_keys"), fmt.Sprintf("%s_authorized_keys.txt", user)},
			{filepath.Join(home, ".ssh", "known_hosts"), fmt.Sprintf("%s_known_hosts.txt", user)},
		}

		for _, a := range artifacts {
			total++
			dst := filepath.Join(outDir, a.outName)
			if err := runCopyFile(a.src, dst); err == nil {
				succeeded++
			}
		}

		// SSH directory listing.
		total++
		sshDir := filepath.Join(home, ".ssh")
		outPath := filepath.Join(outDir, fmt.Sprintf("%s_ssh_dir.txt", user))
		_, err := runShell(ctx, outPath,
			fmt.Sprintf("ls -la '%s' 2>/dev/null", sshDir))
		if err == nil {
			succeeded++
		}
	}

	if succeeded == 0 && total > 0 {
		result.Status = StepFailed
	} else if succeeded < total {
		result.Status = StepPartial
	}

	return result
}

// ---------------------------------------------------------------------------
// System Info Extended
// ---------------------------------------------------------------------------

func lnxSystemInfoExtended(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	cmds := []lnxCmd{
		{"installed_packages_dpkg.txt", "dpkg -l 2>/dev/null"},
		{"installed_packages_rpm.txt", "rpm -qa 2>/dev/null"},
		{"pip_packages.txt", "pip list 2>/dev/null"},
		{"suid_files.txt", "find / -perm -4000 -type f 2>/dev/null"},
		{"sgid_files.txt", "find / -perm -2000 -type f 2>/dev/null"},
		{"temp_files.txt", "find /tmp /var/tmp /dev/shm -type f 2>/dev/null"},
	}
	return runLnxCmds(ctx, outDir, logger, "System Info Extended", cmds)
}
