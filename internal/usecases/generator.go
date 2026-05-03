package usecases

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// GenerateDefaultFiles writes one YAML file per built-in use case into dir,
// creating the directory if necessary. Files are named "{ID}_{name}.yaml"
// with spaces replaced by underscores.
//
// Existing files are NOT overwritten — the runner is meant to seed an empty
// directory once, then leave operator edits alone.
func GenerateDefaultFiles(dir string) (written []string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating dir: %w", err)
	}
	for _, uc := range Defaults() {
		path := filepath.Join(dir, defaultFilename(&uc))
		if _, err := os.Stat(path); err == nil {
			continue // don't trample customised copies
		}
		data, err := yaml.Marshal(&uc)
		if err != nil {
			return written, fmt.Errorf("marshal %s: %w", uc.ID, err)
		}
		header := fmt.Sprintf("# VanGuard built-in use case — %s\n# Edit freely; "+
			"the loader prefers this file over the embedded definition.\n\n", uc.ID)
		if err := os.WriteFile(path, append([]byte(header), data...), 0o644); err != nil {
			return written, fmt.Errorf("writing %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// defaultFilename produces "UC-WIN-001_Ransomware_Investigation.yaml".
func defaultFilename(uc *UseCase) string {
	name := strings.ReplaceAll(uc.Name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "&", "and")
	return fmt.Sprintf("%s_%s.yaml", uc.ID, name)
}

// CustomTemplate is the YAML content the "Create Custom Use Case Template"
// menu item drops into usecases/. It's a fully-commented skeleton so users
// can fill in the gaps without consulting the source code.
const CustomTemplate = `# Custom VanGuard use case template.
# Save this file as usecases/UC-CUSTOM-XXX_Your_Name.yaml after editing.
# Run via: VanGuard sidebar [C] Use Cases — your custom case will appear in
# the "CUSTOM INVESTIGATIONS" section.

name: "My Custom Investigation"
id: "UC-CUSTOM-001"               # must start with UC-CUSTOM-
description: "What this investigation looks for and when to run it."
platform: "windows"               # windows | linux | cross-platform
severity: "medium"                # critical | high | medium | low | varies
estimated_time: "15-25 minutes"

# Optional: MITRE ATT&CK technique IDs this use case targets.
mitre_attack:
  - T1059.001

# Optional human-readable prerequisites.
prerequisites:
  - "Active case"
  - "Local Administrator"

# Optional parameters — prompted before execution.
# Substituted into commands via {parameter_name} placeholders.
parameters:
  - name: target_user
    description: "Username to investigate"
    required: false
    type: string

# Phases run sequentially; each phase's steps run in order.
phases:
  - name: "Initial Triage"
    description: "Collect baseline state"
    steps:
      - name: "Process snapshot"
        type: command
        platform: windows           # windows | linux | both
        command: |
          Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | ConvertTo-Csv -NoTypeInformation
        timeout: 60                 # seconds; 0 → 300 default
        optional: false
        description: "Capture all running processes"

      - name: "User-targeted process search"
        type: command
        platform: windows
        command: |
          Get-CimInstance Win32_Process | Where-Object { $_.GetOwner().User -eq '{target_user}' } | ConvertTo-Csv -NoTypeInformation
        optional: true

# Step types:
#   command       Runs via PowerShell (Windows) or sh -c (Linux).
#   tool          Invokes a registered tool. Set 'tool' to its ID
#                 (e.g. hayabusa-win, chainsaw-win, loki-win).
#   manual        Skipped automatically; the description is shown to the
#                 analyst as guidance.

# Optional output config.
output:
  format: txt
  include_timeline: false

# Optional rendered hints in the post-run summary.
analysis_guidance:
  - "Look for unexpected child processes from {target_user} sessions."

follow_up:
  - "UC-WIN-008: PowerShell Attack Investigation"
`

// WriteCustomTemplate writes the CustomTemplate text to a fresh file under
// dir, using the next-available UC-CUSTOM-NNN_Template.yaml name. Returns
// the path written.
func WriteCustomTemplate(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating dir: %w", err)
	}
	for n := 1; n <= 999; n++ {
		path := filepath.Join(dir,
			fmt.Sprintf("UC-CUSTOM-%03d_Template.yaml", n))
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.WriteFile(path, []byte(CustomTemplate), 0o644); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("ran out of UC-CUSTOM-NNN slots — clean up existing templates first")
}
