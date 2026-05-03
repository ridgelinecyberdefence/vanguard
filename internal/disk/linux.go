package disk

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// LinuxCollector executes native Linux disk-artifact collection commands.
type LinuxCollector struct {
	RootDir string
	Logger  *logging.Logger
}

// NewLinuxCollector creates a Linux collector.
func NewLinuxCollector(rootDir string, logger *logging.Logger) *LinuxCollector {
	return &LinuxCollector{RootDir: rootDir, Logger: logger}
}

// ---------------------------------------------------------------------------
// Common collection helpers
// ---------------------------------------------------------------------------

// runStep wraps a collection function so callers get consistent timing,
// counting, and error capture.
func (c *LinuxCollector) runStep(name, outDir string, fn func() error) CollectionResult {
	result := CollectionResult{Name: name, OutputDir: outDir}
	started := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		result.Status = StatusFailed
		result.Error = "creating output dir: " + err.Error()
		result.Duration = time.Since(started)
		return result
	}

	err := fn()
	result.Duration = time.Since(started)
	files, bytes := countDirContents(outDir)
	result.Files = files
	result.Bytes = bytes

	if err != nil {
		// Partial success when something landed on disk despite the error.
		if files > 0 {
			result.Status = StatusPartial
			result.Warnings = append(result.Warnings, err.Error())
		} else {
			result.Status = StatusFailed
			result.Error = err.Error()
		}
		return result
	}
	result.Status = StatusSuccess
	if files == 0 {
		result.Status = StatusPartial
		result.Warnings = append(result.Warnings, "no files collected")
	}
	return result
}

// runShellTo executes a shell command and writes stdout to outFile.
// Errors are logged into the result's warnings; does not abort the step.
func (c *LinuxCollector) runShellTo(ctx context.Context, outFile, command string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if outFile != "" {
		if werr := os.WriteFile(outFile, out, 0o644); werr != nil {
			return fmt.Errorf("writing %s: %w", outFile, werr)
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	return nil
}

// copyFileBest copies src to dst preserving metadata via cp -a; falls back to
// a plain Go copy on platforms without cp. Missing source files are silently
// skipped — many of these paths legitimately don't exist on every distro.
func copyFileBest(ctx context.Context, src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return nil // missing → skip silently
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if _, err := exec.LookPath("cp"); err == nil {
		cmd := exec.CommandContext(ctx, "cp", "-a", src, dst)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("cp -a %s %s: %v: %s", src, dst, err, string(out))
		}
		return nil
	}
	return goCopy(src, dst)
}

// copyGlobBest copies any path matched by the shell glob to outDir.
func copyGlobBest(ctx context.Context, glob, outDir string) {
	matches, _ := filepath.Glob(glob)
	for _, m := range matches {
		_ = copyFileBest(ctx, m, filepath.Join(outDir, filepath.Base(m)))
	}
}

// copyTreeBest recursively copies a directory if it exists.
func copyTreeBest(ctx context.Context, src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if _, err := exec.LookPath("cp"); err == nil {
		cmd := exec.CommandContext(ctx, "cp", "-a", src+"/.", dst)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("cp -a %s/. %s: %v: %s", src, dst, err, string(out))
		}
		return nil
	}
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return goCopy(p, target)
	})
}

func goCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

// CollectSystemLogs gathers /var/log system logs.
func (c *LinuxCollector) CollectSystemLogs(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("System Logs", outDir, func() error {
		patterns := []string{
			"/var/log/syslog*", "/var/log/messages*",
			"/var/log/kern.log*", "/var/log/daemon.log*",
			"/var/log/boot.log*", "/var/log/dmesg*",
			"/var/log/dpkg.log*", "/var/log/yum.log*", "/var/log/dnf.log*",
		}
		for _, g := range patterns {
			copyGlobBest(ctx, g, outDir)
		}
		_ = copyTreeBest(ctx, "/var/log/apt", filepath.Join(outDir, "apt"))
		// Live snapshot of dmesg in case ring buffer differs from log file.
		_ = c.runShellTo(ctx, filepath.Join(outDir, "dmesg_now.txt"), "dmesg 2>/dev/null")
		return nil
	})
}

// CollectAuthLogs gathers authentication/login logs.
func (c *LinuxCollector) CollectAuthLogs(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Auth Logs", outDir, func() error {
		patterns := []string{
			"/var/log/auth.log*", "/var/log/secure*",
			"/var/log/faillog", "/var/log/lastlog",
			"/var/log/wtmp", "/var/log/btmp",
		}
		for _, g := range patterns {
			copyGlobBest(ctx, g, outDir)
		}
		_ = c.runShellTo(ctx, filepath.Join(outDir, "last.txt"), "last -100")
		_ = c.runShellTo(ctx, filepath.Join(outDir, "lastb.txt"), "lastb -100 2>/dev/null")
		_ = c.runShellTo(ctx, filepath.Join(outDir, "who.txt"), "who")
		_ = c.runShellTo(ctx, filepath.Join(outDir, "w.txt"), "w")
		return nil
	})
}

// CollectWebServerLogs gathers Apache/Nginx logs and configs.
func (c *LinuxCollector) CollectWebServerLogs(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Web Server Logs", outDir, func() error {
		_ = copyTreeBest(ctx, "/var/log/apache2", filepath.Join(outDir, "apache2", "logs"))
		_ = copyTreeBest(ctx, "/var/log/httpd", filepath.Join(outDir, "httpd", "logs"))
		_ = copyTreeBest(ctx, "/etc/apache2", filepath.Join(outDir, "apache2", "config"))
		_ = copyTreeBest(ctx, "/var/log/nginx", filepath.Join(outDir, "nginx", "logs"))
		_ = copyTreeBest(ctx, "/etc/nginx", filepath.Join(outDir, "nginx", "config"))
		_ = copyTreeBest(ctx, "/var/log/lighttpd", filepath.Join(outDir, "lighttpd"))
		_ = copyTreeBest(ctx, "/var/log/caddy", filepath.Join(outDir, "caddy"))
		return nil
	})
}

// CollectAppLogs gathers common database / mail / container log directories.
func (c *LinuxCollector) CollectAppLogs(ctx context.Context, outDir, customPath string) CollectionResult {
	return c.runStep("Application Logs", outDir, func() error {
		if customPath != "" {
			return copyTreeBest(ctx, customPath, filepath.Join(outDir, filepath.Base(customPath)))
		}
		paths := []string{
			"/var/log/mysql", "/var/log/mariadb",
			"/var/log/postgresql",
			"/var/log/redis",
			"/var/log/mongodb",
			"/var/log/docker", "/var/log/containers",
		}
		for _, p := range paths {
			_ = copyTreeBest(ctx, p, filepath.Join(outDir, filepath.Base(p)))
		}
		copyGlobBest(ctx, "/var/log/mail.log*", outDir)
		copyGlobBest(ctx, "/var/log/maillog*", outDir)
		return nil
	})
}

// CollectJournal queries systemd journal in several useful slices.
func (c *LinuxCollector) CollectJournal(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Journal Logs", outDir, func() error {
		commands := map[string]string{
			"journal_full.json":     "journalctl --no-pager --output=json",
			"journal_errors.txt":    "journalctl --no-pager -p err",
			"journal_warnings.txt":  "journalctl --no-pager -p warning",
			"journal_7days.txt":     "journalctl --no-pager --since='7 days ago'",
			"journal_sshd.txt":      "journalctl --no-pager -u sshd",
			"journal_docker.txt":    "journalctl --no-pager -u docker",
			"journal_boots.txt":     "journalctl --list-boots",
		}
		for name, cmd := range commands {
			_ = c.runShellTo(ctx, filepath.Join(outDir, name), cmd+" 2>/dev/null")
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// User artifacts
// ---------------------------------------------------------------------------

// listUserHomes returns paths to user home directories worth collecting.
func listUserHomes() []string {
	var homes []string
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	if _, err := os.Stat("/root"); err == nil {
		homes = append(homes, "/root")
	}
	return homes
}

// userArtifactPaths returns the per-user artifact files/dirs to collect.
func userArtifactPaths() []string {
	return []string{
		".bash_history", ".zsh_history", ".fish_history",
		".bash_profile", ".bashrc", ".profile", ".zshrc",
		".ssh", ".gnupg",
		".aws", ".azure", ".gcloud",
		".docker/config.json", ".kube/config",
		".gitconfig", ".git-credentials",
		".viminfo", ".lesshst", ".python_history",
		".local/share/Trash",
	}
}

// CollectUserHomes copies a curated set of artifacts from each user home.
func (c *LinuxCollector) CollectUserHomes(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("User Home Directories", outDir, func() error {
		for _, home := range listUserHomes() {
			user := filepath.Base(home)
			userDir := filepath.Join(outDir, user)
			if err := os.MkdirAll(userDir, 0o700); err != nil {
				continue
			}
			for _, art := range userArtifactPaths() {
				src := filepath.Join(home, art)
				if info, err := os.Stat(src); err == nil {
					dst := filepath.Join(userDir, art)
					if info.IsDir() {
						_ = copyTreeBest(ctx, src, dst)
					} else {
						_ = copyFileBest(ctx, src, dst)
					}
				}
			}
			// File listing (no contents) for Desktop/ and Downloads/.
			_ = c.runShellTo(ctx,
				filepath.Join(userDir, "file_listing.txt"),
				fmt.Sprintf("ls -laR %s 2>/dev/null", home))
		}
		return nil
	})
}

// CollectShellHistory copies bash/zsh/fish histories for every user.
func (c *LinuxCollector) CollectShellHistory(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Shell History", outDir, func() error {
		for _, home := range listUserHomes() {
			user := filepath.Base(home)
			userDir := filepath.Join(outDir, user)
			_ = os.MkdirAll(userDir, 0o700)
			for _, h := range []string{".bash_history", ".zsh_history", ".fish_history"} {
				_ = copyFileBest(ctx, filepath.Join(home, h), filepath.Join(userDir, h))
			}
		}
		return nil
	})
}

// CollectSSHArtifacts copies SSH config + keys for each user, plus system SSH config.
func (c *LinuxCollector) CollectSSHArtifacts(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("SSH Artifacts", outDir, func() error {
		for _, home := range listUserHomes() {
			user := filepath.Base(home)
			_ = copyTreeBest(ctx, filepath.Join(home, ".ssh"),
				filepath.Join(outDir, "users", user, "ssh"))
		}
		sysDir := filepath.Join(outDir, "etc_ssh")
		_ = os.MkdirAll(sysDir, 0o700)
		_ = copyFileBest(ctx, "/etc/ssh/sshd_config", filepath.Join(sysDir, "sshd_config"))
		_ = copyFileBest(ctx, "/etc/ssh/ssh_config", filepath.Join(sysDir, "ssh_config"))
		// Public host keys only — never copy host private keys.
		copyGlobBest(ctx, "/etc/ssh/ssh_host_*_key.pub", sysDir)
		return nil
	})
}

// CollectCron gathers system cron config and per-user crontabs.
func (c *LinuxCollector) CollectCron(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Cron Jobs", outDir, func() error {
		_ = copyFileBest(ctx, "/etc/crontab", filepath.Join(outDir, "crontab"))
		for _, dir := range []string{
			"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
			"/etc/cron.weekly", "/etc/cron.monthly",
		} {
			_ = copyTreeBest(ctx, dir, filepath.Join(outDir, filepath.Base(dir)))
		}
		// Per-user crontab dump via crontab -u {user} -l.
		for _, home := range listUserHomes() {
			user := filepath.Base(home)
			_ = c.runShellTo(ctx,
				filepath.Join(outDir, user+"_crontab.txt"),
				fmt.Sprintf("crontab -u %s -l 2>/dev/null", user))
		}
		_ = copyTreeBest(ctx, "/var/spool/cron", filepath.Join(outDir, "spool"))
		return nil
	})
}

// ---------------------------------------------------------------------------
// System artifacts
// ---------------------------------------------------------------------------

// CollectPackages dumps installed packages and package-manager logs.
func (c *LinuxCollector) CollectPackages(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Packages", outDir, func() error {
		commands := map[string]string{
			"installed_packages_dpkg.txt": "dpkg -l 2>/dev/null",
			"package_selections.txt":      "dpkg --get-selections 2>/dev/null",
			"apt_installed.txt":           "apt list --installed 2>/dev/null",
			"installed_packages_rpm.txt":  "rpm -qa --last 2>/dev/null",
			"yum_history.txt":             "yum history list 2>/dev/null",
			"pip_packages.txt":            "pip list 2>/dev/null",
			"pip3_packages.txt":           "pip3 list 2>/dev/null",
			"npm_global.txt":              "npm list -g 2>/dev/null",
			"snap_list.txt":               "snap list 2>/dev/null",
			"flatpak_list.txt":            "flatpak list 2>/dev/null",
		}
		for name, cmd := range commands {
			_ = c.runShellTo(ctx, filepath.Join(outDir, name), cmd)
		}
		copyGlobBest(ctx, "/var/log/dpkg.log*", outDir)
		copyGlobBest(ctx, "/var/log/apt/history.log*", outDir)
		copyGlobBest(ctx, "/var/log/yum.log*", outDir)
		_ = copyFileBest(ctx, "/etc/apt/sources.list", filepath.Join(outDir, "sources.list"))
		_ = copyTreeBest(ctx, "/etc/apt/sources.list.d", filepath.Join(outDir, "sources.list.d"))
		_ = copyTreeBest(ctx, "/etc/yum.repos.d", filepath.Join(outDir, "yum.repos.d"))
		return nil
	})
}

// CollectSystemd dumps systemd unit files and current service state.
func (c *LinuxCollector) CollectSystemd(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Systemd Units", outDir, func() error {
		commands := map[string]string{
			"all_services.txt": "systemctl list-units --all --type=service --no-pager 2>/dev/null",
			"unit_files.txt":   "systemctl list-unit-files --type=service --no-pager 2>/dev/null",
			"timers.txt":       "systemctl list-timers --all --no-pager 2>/dev/null",
			"system_status.txt": "systemctl status --no-pager 2>/dev/null",
		}
		for name, cmd := range commands {
			_ = c.runShellTo(ctx, filepath.Join(outDir, name), cmd)
		}
		_ = copyTreeBest(ctx, "/etc/systemd/system", filepath.Join(outDir, "etc_systemd"))
		_ = copyTreeBest(ctx, "/usr/lib/systemd/system", filepath.Join(outDir, "lib_systemd"))
		// Run-time units (best effort).
		_ = c.runShellTo(ctx,
			filepath.Join(outDir, "run_units.txt"),
			"find /run/systemd -name '*.service' 2>/dev/null")
		return nil
	})
}

// CollectNetwork gathers network configuration and live state.
func (c *LinuxCollector) CollectNetwork(ctx context.Context, outDir string) CollectionResult {
	return c.runStep("Network Configuration", outDir, func() error {
		commands := map[string]string{
			"interfaces.txt":      "ip addr show 2>/dev/null",
			"routes.txt":          "ip route show 2>/dev/null",
			"arp.txt":             "ip neigh show 2>/dev/null",
			"connections.txt":     "ss -tulpan 2>/dev/null",
			"iptables_rules.txt":  "iptables-save 2>/dev/null",
			"ip6tables_rules.txt": "ip6tables-save 2>/dev/null",
			"sysctl_all.txt":      "sysctl -a 2>/dev/null",
			"nm_connections.txt":  "ls /etc/NetworkManager/system-connections/ 2>/dev/null",
			"nft_ruleset.txt":     "nft list ruleset 2>/dev/null",
		}
		for name, cmd := range commands {
			_ = c.runShellTo(ctx, filepath.Join(outDir, name), cmd)
		}
		for _, src := range []string{
			"/etc/resolv.conf", "/etc/hosts", "/etc/hostname",
			"/etc/network/interfaces", "/etc/sysctl.conf",
			"/etc/hosts.allow", "/etc/hosts.deny",
		} {
			_ = copyFileBest(ctx, src, filepath.Join(outDir, filepath.Base(src)))
		}
		return nil
	})
}

// CollectDocker gathers container runtime artefacts. Best effort — many of
// these commands need root or a running daemon.
func (c *LinuxCollector) CollectDocker(ctx context.Context, outDir string) CollectionResult {
	if _, err := exec.LookPath("docker"); err != nil {
		// Docker not installed — try podman or report cleanly.
		if _, perr := exec.LookPath("podman"); perr != nil {
			return CollectionResult{
				Name: "Docker/Containers", OutputDir: outDir,
				Status: StatusSkipped,
				Error:  "Docker/Podman not found on this system",
			}
		}
	}

	return c.runStep("Docker/Containers", outDir, func() error {
		commands := map[string]string{
			"docker_containers_all.txt": "docker ps -a 2>/dev/null",
			"docker_images.txt":         "docker images 2>/dev/null",
			"docker_networks.txt":       "docker network ls 2>/dev/null",
			"docker_volumes.txt":        "docker volume ls 2>/dev/null",
			"docker_inspect_all.json":   "docker inspect $(docker ps -aq 2>/dev/null) 2>/dev/null",
			"docker_config.json":        "cat /etc/docker/daemon.json 2>/dev/null",
			"podman_containers.txt":     "podman ps -a 2>/dev/null",
			"podman_images.txt":         "podman images 2>/dev/null",
			"k8s_pods.txt":              "kubectl get pods --all-namespaces 2>/dev/null",
			"k8s_services.txt":          "kubectl get services --all-namespaces 2>/dev/null",
		}
		for name, cmd := range commands {
			_ = c.runShellTo(ctx, filepath.Join(outDir, name), cmd)
		}

		// Per-container logs (last 1000 lines).
		idsCmd := exec.CommandContext(ctx, "sh", "-c", "docker ps -q 2>/dev/null")
		if out, err := idsCmd.Output(); err == nil {
			ids := strings.Fields(string(out))
			for _, id := range ids {
				_ = c.runShellTo(ctx,
					filepath.Join(outDir, "container_"+id+"_logs.txt"),
					fmt.Sprintf("docker logs --tail 1000 %s 2>&1", id))
			}
		}

		copyGlobBest(ctx, "/var/lib/docker/containers/*/config.v2.json", outDir)
		return nil
	})
}
