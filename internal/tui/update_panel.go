package tui

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
	"github.com/ridgelinecyberdefence/vanguard/internal/updates"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type updateView int

const (
	updateViewNone updateView = iota
	updateViewMenu
	updateViewError
	updateViewMessage

	updateViewChecking
	updateViewCheckDone

	updateViewConfirmAll
	updateViewUpdating

	updateViewBundleSelect    // checkbox component picker
	updateViewBundleCreating
	updateViewBundleDone
	updateViewBundleApply     // result of apply

	updateViewVanGuardCheck

	// [3] Update Specific Tool — list of installed updateable tools.
	updateViewToolPick

	// [9] Apply Offline Update Bundle — interactive path entry.
	updateViewApplyPath
)

// UpdateState carries panel state.
type UpdateState struct {
	view updateView

	// Menu selection.
	menuCursor int

	// Active operation tracking.
	operation string
	startTime time.Time
	elapsed   time.Duration

	errorMsg     string
	messageTitle string
	messageLines []string

	// Check results (used by both the global "check" view and the per-tool
	// update flow).
	report     *updates.CheckReport
	updateRows []updates.CheckResult // filtered to "update_available" rows

	// Update outcomes (single op view).
	outcomes []updates.UpdateOutcome

	// Bundle creator state.
	bundleSpec    updates.BundleSpec
	bundleOptions []bundleOpt
	bundleCursor  int
	bundleResult  *updates.CreateResult

	// Bundle apply state.
	bundleApply *updates.ApplyResult

	// [3] Update Specific Tool — picker state.
	toolPickItems  []tools.ToolStatus
	toolPickCursor int

	// [9] Apply Offline Update Bundle — path input state.
	pathInput textinput.Model
}

// bundleOpt represents one toggleable component in the bundle picker.
type bundleOpt struct {
	Label    string
	Selected bool
	ToolID   string
	Kind     updates.ItemKind
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type updateTickMsg time.Time

type updateCheckDoneMsg struct {
	report *updates.CheckReport
	err    string
}

type updateApplyDoneMsg struct {
	outcomes []updates.UpdateOutcome
}

type updateBundleCreateDoneMsg struct {
	res *updates.CreateResult
	err string
}

type updateBundleApplyDoneMsg struct {
	res *updates.ApplyResult
	err string
}

type updateVanGuardDoneMsg struct {
	latest    string
	body      string
	hasUpdate bool
	err       string
}

func updateTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return updateTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Sidebar entry point
// ---------------------------------------------------------------------------

func (m Model) openUpdates() (Model, tea.Cmd) {
	m.clearPanelState()
	m.updateState = UpdateState{view: updateViewMenu}
	m.state = stateResult
	return m, nil
}

func (m Model) updateMgr() *updates.Manager {
	return updates.New(m.ctx.RootDir, m.ctx.ToolManager, m.ctx.Logger)
}

// ---------------------------------------------------------------------------
// Tick + async handlers
// ---------------------------------------------------------------------------

func (m Model) handleUpdateTick() (Model, tea.Cmd) {
	switch m.updateState.view {
	case updateViewChecking, updateViewUpdating, updateViewBundleCreating:
		m.updateState.elapsed = time.Since(m.updateState.startTime)
		return m, updateTickCmd()
	}
	return m, nil
}

func (m Model) handleUpdateCheckDone(msg updateCheckDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.updateState.view = updateViewError
		m.updateState.errorMsg = msg.err
		return m, nil
	}
	m.updateState.view = updateViewCheckDone
	m.updateState.report = msg.report
	m.updateState.updateRows = nil
	for _, r := range msg.report.Results {
		if r.Status == updates.StatusUpdateAvail {
			m.updateState.updateRows = append(m.updateState.updateRows, r)
		}
	}
	return m, nil
}

func (m Model) handleUpdateApplyDone(msg updateApplyDoneMsg) (Model, tea.Cmd) {
	m.updateState.view = updateViewMessage
	m.updateState.outcomes = msg.outcomes
	m.updateState.messageTitle = "Update Results"
	return m, nil
}

func (m Model) handleUpdateBundleCreateDone(msg updateBundleCreateDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.updateState.view = updateViewError
		m.updateState.errorMsg = msg.err
		return m, nil
	}
	m.updateState.view = updateViewBundleDone
	m.updateState.bundleResult = msg.res
	return m, nil
}

func (m Model) handleUpdateBundleApplyDone(msg updateBundleApplyDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.updateState.view = updateViewError
		m.updateState.errorMsg = msg.err
		return m, nil
	}
	m.updateState.view = updateViewBundleApply
	m.updateState.bundleApply = msg.res
	return m, nil
}

func (m Model) handleUpdateVanGuardDone(msg updateVanGuardDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.updateState.view = updateViewError
		m.updateState.errorMsg = msg.err
		return m, nil
	}
	m.updateState.view = updateViewVanGuardCheck
	m.updateState.messageTitle = "VanGuard Self-Version Check"
	if msg.hasUpdate {
		m.updateState.messageLines = []string{
			"Current:   v" + m.ctx.Version,
			"Latest:    " + msg.latest,
			"",
			"Release Notes:",
		}
		notes := msg.body
		if len(notes) > 500 {
			notes = notes[:500] + "…"
		}
		m.updateState.messageLines = append(m.updateState.messageLines,
			strings.Split(notes, "\n")...)
		m.updateState.messageLines = append(m.updateState.messageLines, "",
			"Download from: https://github.com/ridgelinecyberdefence/vanguard/releases/latest",
			"",
			"VanGuard cannot self-update. Download the new version manually and replace the binary.")
	} else {
		m.updateState.messageLines = []string{
			"VanGuard v" + m.ctx.Version + " is the latest version.",
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Key dispatch
// ---------------------------------------------------------------------------

func (m Model) updateUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.updateState.view == updateViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.updateState.view {
	case updateViewError, updateViewMessage, updateViewVanGuardCheck,
		updateViewBundleDone, updateViewBundleApply:
		m.updateState.view = updateViewMenu
		return m, nil, true

	case updateViewChecking, updateViewUpdating, updateViewBundleCreating:
		return m, nil, true // block

	case updateViewMenu:
		return m.updateHandleMenu(key)

	case updateViewCheckDone:
		switch key {
		case "esc":
			m.updateState.view = updateViewMenu
			return m, nil, true
		case "a", "A":
			if len(m.updateState.updateRows) == 0 {
				return m, nil, true
			}
			mm, cmd := m.updateBeginApplyAll()
			return mm, cmd, true
		}
		return m, nil, true

	case updateViewConfirmAll:
		switch key {
		case "y", "Y":
			mm, cmd := m.updateBeginApplyAll()
			return mm, cmd, true
		default:
			m.updateState.view = updateViewMenu
			return m, nil, true
		}

	case updateViewBundleSelect:
		return m.updateHandleBundleSelect(key)

	case updateViewToolPick:
		return m.updateHandleToolPick(key)

	case updateViewApplyPath:
		return m.updateHandleApplyPath(msg, key)
	}
	return m, nil, false
}

// updateHandleApplyPath drives the [9] path-entry view.
func (m Model) updateHandleApplyPath(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.updateState.view = updateViewMenu
		m.statusMessage = "Apply cancelled."
		return m, nil, true
	case "enter":
		path := strings.TrimSpace(m.updateState.pathInput.Value())
		if path == "" {
			m.statusMessage = "Path is required."
			return m, nil, true
		}
		if _, err := os.Stat(path); err != nil {
			m.updateState.view = updateViewError
			m.updateState.errorMsg = "Bundle not found: " + err.Error()
			return m, nil, true
		}
		mm, cmd := m.updateApplyBundleStart(path)
		return mm, cmd, true
	default:
		var cmd tea.Cmd
		m.updateState.pathInput, cmd = m.updateState.pathInput.Update(msg)
		return m, cmd, true
	}
}

// updateHandleMenu drives the top-level update menu.
func (m Model) updateHandleMenu(key string) (Model, tea.Cmd, bool) {
	rows := updateMenuItems()
	switch key {
	case "esc":
		m.updateState.view = updateViewNone
		m.state = stateMainMenu
		m.focus = paneSidebar
		return m, nil, true
	case "up", "k":
		if m.updateState.menuCursor > 0 {
			m.updateState.menuCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.updateState.menuCursor < len(rows)-1 {
			m.updateState.menuCursor++
		}
		return m, nil, true
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
		idx := updateMenuShortcutIndex(key, rows)
		if idx >= 0 {
			m.updateState.menuCursor = idx
			mm, cmd := m.updateActivateMenuItem(rows[idx].action)
			return mm, cmd, true
		}
	case "enter":
		if m.updateState.menuCursor < len(rows) {
			mm, cmd := m.updateActivateMenuItem(rows[m.updateState.menuCursor].action)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

// updateMenuItems is the static menu list used for both rendering and key
// dispatch.
type updateMenuRow struct{ shortcut, label, action string }

func updateMenuItems() []updateMenuRow {
	return []updateMenuRow{
		{"1", "Check for Updates (All)", "check"},
		{"2", "Update All Tools", "update_all"},
		{"3", "Update Specific Tool", "update_one"},
		{"4", "Update Sigma Rules", "update_sigma"},
		{"5", "Update YARA Rules", "update_yara"},
		{"6", "Update Hayabusa Rules", "update_hayabusa"},
		{"7", "Update All Rules", "update_all_rules"},
		{"8", "Create Offline Update Bundle", "bundle_create"},
		{"9", "Apply Offline Update Bundle", "bundle_apply"},
		{"0", "Check for VanGuard Update", "vanguard_check"},
	}
}

func updateMenuShortcutIndex(key string, rows []updateMenuRow) int {
	for i, r := range rows {
		if r.shortcut == key {
			return i
		}
	}
	return -1
}

// updateActivateMenuItem dispatches one of the static menu actions.
func (m Model) updateActivateMenuItem(action string) (Model, tea.Cmd) {
	switch action {
	case "check":
		return m.updateBeginCheck()
	case "update_all":
		return m.updateBeginCheckThenAll()
	case "update_one":
		return m.updateBeginToolPick()
	case "update_sigma":
		return m.updateBeginRuleSet("sigma-rules", "Sigma Rules")
	case "update_yara":
		return m.updateBeginRuleSet("yara-rules", "YARA Rules")
	case "update_hayabusa":
		return m.updateBeginRuleSet("hayabusa-rules", "Hayabusa Rules")
	case "update_all_rules":
		return m.updateBeginAllRules()
	case "bundle_create":
		return m.updateBeginBundleSelect()
	case "bundle_apply":
		return m.updateBeginBundleApply()
	case "vanguard_check":
		return m.updateBeginVanGuardCheck()
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Check + apply flows
// ---------------------------------------------------------------------------

func (m Model) updateBeginCheck() (Model, tea.Cmd) {
	m.updateState.view = updateViewChecking
	m.updateState.operation = "Checking for updates"
	m.updateState.startTime = time.Now()
	mgr := m.updateMgr()
	cmd := func() tea.Msg {
		return updateCheckDoneMsg{report: mgr.CheckAll()}
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// updateBeginCheckThenAll runs the check and immediately confirms an apply-all
// via the same view path. Phase 1: check; Phase 2: ask.
func (m Model) updateBeginCheckThenAll() (Model, tea.Cmd) {
	mm, cmd := m.updateBeginCheck()
	mm.updateState.operation = "Update All Tools — checking versions"
	return mm, cmd
}

// updateBeginApplyAll fans out updates for every "update available" row
// captured by the most recent check. Runs each item sequentially in one
// tea.Cmd goroutine so the TUI stays responsive; emits a single applyDone
// message when finished.
func (m Model) updateBeginApplyAll() (Model, tea.Cmd) {
	rows := m.updateState.updateRows
	if len(rows) == 0 {
		m.updateState.view = updateViewMessage
		m.updateState.messageTitle = "Update All"
		m.updateState.messageLines = []string{"All tools are up to date — nothing to do."}
		return m, nil
	}
	m.updateState.view = updateViewUpdating
	m.updateState.operation = "Updating tools and rule sets"
	m.updateState.startTime = time.Now()

	mgr := m.updateMgr()
	rowCopy := append([]updates.CheckResult(nil), rows...)
	cmd := func() tea.Msg {
		var outcomes []updates.UpdateOutcome
		for _, r := range rowCopy {
			if r.Kind == updates.ItemRuleSet {
				outcomes = append(outcomes, mgr.UpdateRuleSet(r.ToolID))
			} else {
				outcomes = append(outcomes, mgr.UpdateTool(r.ToolID))
			}
		}
		return updateApplyDoneMsg{outcomes: outcomes}
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// updateBeginRuleSet kicks off a single rule-set update.
func (m Model) updateBeginRuleSet(toolID, label string) (Model, tea.Cmd) {
	m.updateState.view = updateViewUpdating
	m.updateState.operation = "Updating " + label
	m.updateState.startTime = time.Now()
	mgr := m.updateMgr()
	cmd := func() tea.Msg {
		return updateApplyDoneMsg{outcomes: []updates.UpdateOutcome{mgr.UpdateRuleSet(toolID)}}
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// updateBeginAllRules runs sigma + yara + hayabusa updates sequentially.
func (m Model) updateBeginAllRules() (Model, tea.Cmd) {
	m.updateState.view = updateViewUpdating
	m.updateState.operation = "Updating all rule sets"
	m.updateState.startTime = time.Now()
	mgr := m.updateMgr()
	cmd := func() tea.Msg {
		var outs []updates.UpdateOutcome
		for _, id := range []string{"sigma-rules", "yara-rules", "hayabusa-rules"} {
			outs = append(outs, mgr.UpdateRuleSet(id))
		}
		return updateApplyDoneMsg{outcomes: outs}
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// Bundle creator
// ---------------------------------------------------------------------------

func (m Model) updateBeginBundleSelect() (Model, tea.Cmd) {
	tm := m.ctx.ToolManager
	opts := []bundleOpt{}
	for _, id := range []string{"velociraptor-win", "velociraptor-lnx",
		"hayabusa-win", "hayabusa-lnx", "chainsaw-win", "chainsaw-lnx",
		"loki-win", "loki-lnx", "winpmem", "avml-lnx"} {
		t := tm.GetTool(id)
		if t == nil || !t.Installed {
			continue
		}
		opts = append(opts, bundleOpt{
			Label: t.Name + " (" + t.Platform + ")", Selected: true,
			ToolID: id, Kind: updates.ItemTool,
		})
	}
	for _, id := range []string{"sigma-rules", "yara-rules", "hayabusa-rules"} {
		t := tm.GetTool(id)
		if t == nil {
			continue
		}
		opts = append(opts, bundleOpt{
			Label: t.Name, Selected: true,
			ToolID: id, Kind: updates.ItemRuleSet,
		})
	}
	opts = append(opts, bundleOpt{
		Label: "VanGuard binary (this analyst host)", Selected: false,
		Kind: updates.ItemVanGuard,
	})
	m.updateState.bundleOptions = opts
	m.updateState.bundleCursor = 0
	m.updateState.view = updateViewBundleSelect
	return m, nil
}

func (m Model) updateHandleBundleSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.updateState.view = updateViewMenu
		return m, nil, true
	case "up", "k":
		if m.updateState.bundleCursor > 0 {
			m.updateState.bundleCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.updateState.bundleCursor < len(m.updateState.bundleOptions)-1 {
			m.updateState.bundleCursor++
		}
		return m, nil, true
	case " ":
		i := m.updateState.bundleCursor
		if i < len(m.updateState.bundleOptions) {
			m.updateState.bundleOptions[i].Selected = !m.updateState.bundleOptions[i].Selected
		}
		return m, nil, true
	case "a", "A":
		for i := range m.updateState.bundleOptions {
			m.updateState.bundleOptions[i].Selected = true
		}
		return m, nil, true
	case "n", "N":
		for i := range m.updateState.bundleOptions {
			m.updateState.bundleOptions[i].Selected = false
		}
		return m, nil, true
	case "enter":
		mm, cmd := m.updateBeginBundleCreate()
		return mm, cmd, true
	}
	return m, nil, true
}

func (m Model) updateBeginBundleCreate() (Model, tea.Cmd) {
	spec := updates.BundleSpec{
		OutputDir:       filepath.Join(m.ctx.RootDir, "output"),
		CreatedBy:       m.ctx.Config.VanGuard.Analyst,
		VanGuardVersion: m.ctx.Version,
	}
	for _, opt := range m.updateState.bundleOptions {
		if !opt.Selected {
			continue
		}
		switch opt.Kind {
		case updates.ItemTool:
			spec.IncludeTools = append(spec.IncludeTools, opt.ToolID)
		case updates.ItemRuleSet:
			spec.IncludeRuleSets = append(spec.IncludeRuleSets, opt.ToolID)
		case updates.ItemVanGuard:
			spec.IncludeVanGuard = true
		}
	}
	if execPath := vanguardBinaryPath(); execPath != "" {
		spec.VanGuardBinary = execPath
	}
	m.updateState.bundleSpec = spec

	m.updateState.view = updateViewBundleCreating
	m.updateState.operation = "Creating offline update bundle"
	m.updateState.startTime = time.Now()

	mgr := m.updateMgr()
	cmd := func() tea.Msg {
		res, err := mgr.CreateBundle(spec)
		msg := updateBundleCreateDoneMsg{res: &res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// vanguardBinaryPath returns the on-disk path to the running binary, "" on error.
func vanguardBinaryPath() string {
	p, err := osExecutable()
	if err != nil {
		return ""
	}
	return p
}

// ---------------------------------------------------------------------------
// Bundle apply
// ---------------------------------------------------------------------------

// updateBeginBundleApply prompts the analyst for a bundle path.
func (m Model) updateBeginBundleApply() (Model, tea.Cmd) {
	ti := textinput.New()
	ti.Placeholder = "Path to bundle directory or .zip"
	ti.CharLimit = 512
	ti.Width = 60
	// Pre-fill with the most recent bundle the user created on this host
	// when one exists, so the common case is a single Enter.
	if guess := mostRecentBundlePath(m.ctx.RootDir); guess != "" {
		ti.SetValue(guess)
	}
	ti.Focus()
	m.updateState.pathInput = ti
	m.updateState.view = updateViewApplyPath
	return m, ti.Focus()
}

// mostRecentBundlePath returns the newest output/vanguard_updates_* path,
// preferring .zip over a directory when both exist.
func mostRecentBundlePath(rootDir string) string {
	entries, err := os.ReadDir(filepath.Join(rootDir, "output"))
	if err != nil {
		return ""
	}
	var bestName string
	var bestMod time.Time
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "vanguard_updates_") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestMod) {
			bestMod = info.ModTime()
			bestName = name
		}
	}
	if bestName == "" {
		return ""
	}
	full := filepath.Join(rootDir, "output", bestName)
	// Prefer the .zip flavour when present.
	if zip := full + ".zip"; fileExistsAny(zip) {
		return zip
	}
	return full
}

func fileExistsAny(p string) bool {
	if _, err := os.Stat(p); err == nil {
		return true
	}
	return false
}

// updateApplyBundleStart kicks off the actual bundle apply once a path is
// supplied. Runs in a goroutine; emits updateBundleApplyDoneMsg when done.
func (m Model) updateApplyBundleStart(path string) (Model, tea.Cmd) {
	m.updateState.view = updateViewUpdating
	m.updateState.operation = "Applying offline update bundle"
	m.updateState.startTime = time.Now()
	mgr := m.updateMgr()
	cmd := func() tea.Msg {
		res, err := mgr.ApplyBundle(path)
		msg := updateBundleApplyDoneMsg{res: res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// [3] Update Specific Tool — picker
// ---------------------------------------------------------------------------

// updateBeginToolPick lists installed, github_release-managed tools so the
// analyst can update one at a time.
func (m Model) updateBeginToolPick() (Model, tea.Cmd) {
	statuses := m.ctx.ToolManager.GetStatus()
	items := make([]tools.ToolStatus, 0, len(statuses))
	for _, s := range statuses {
		t := m.ctx.ToolManager.GetTool(s.ID)
		if t == nil || t.GitHubRepo == "" {
			continue
		}
		// Only offer downloadable tools (rule sets too — they refresh via
		// repo_archive). Manual-only tools have no GitHubRepo so they're
		// already filtered out above.
		items = append(items, s)
	}
	m.updateState.toolPickItems = items
	m.updateState.toolPickCursor = 0
	m.updateState.view = updateViewToolPick
	return m, nil
}

func (m Model) updateHandleToolPick(key string) (Model, tea.Cmd, bool) {
	items := m.updateState.toolPickItems
	switch key {
	case "esc":
		m.updateState.view = updateViewMenu
		return m, nil, true
	case "up", "k":
		if m.updateState.toolPickCursor > 0 {
			m.updateState.toolPickCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.updateState.toolPickCursor < len(items)-1 {
			m.updateState.toolPickCursor++
		}
		return m, nil, true
	case "enter":
		if m.updateState.toolPickCursor >= len(items) {
			return m, nil, true
		}
		s := items[m.updateState.toolPickCursor]
		mm, cmd := m.updateBeginSingleTool(s)
		return mm, cmd, true
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx >= 0 && idx < len(items) {
			s := items[idx]
			mm, cmd := m.updateBeginSingleTool(s)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

// updateBeginSingleTool dispatches one update for the picked tool. Rule sets
// route to UpdateRuleSet; everything else to UpdateTool.
func (m Model) updateBeginSingleTool(s tools.ToolStatus) (Model, tea.Cmd) {
	m.updateState.view = updateViewUpdating
	m.updateState.operation = "Updating " + s.Name
	m.updateState.startTime = time.Now()
	mgr := m.updateMgr()
	id := s.ID
	cmd := func() tea.Msg {
		var out updates.UpdateOutcome
		if strings.HasPrefix(strings.ToLower(s.Path), "rules/") {
			out = mgr.UpdateRuleSet(id)
		} else {
			out = mgr.UpdateTool(id)
		}
		return updateApplyDoneMsg{outcomes: []updates.UpdateOutcome{out}}
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// VanGuard self-check
// ---------------------------------------------------------------------------

func (m Model) updateBeginVanGuardCheck() (Model, tea.Cmd) {
	m.updateState.view = updateViewChecking
	m.updateState.operation = "Checking VanGuard release feed"
	m.updateState.startTime = time.Now()
	current := m.ctx.Version
	cmd := func() tea.Msg {
		latest, body, hasUpd, err := updates.VanGuardCheck("ridgelinecyberdefence/vanguard", current)
		msg := updateVanGuardDoneMsg{latest: latest, body: body, hasUpdate: hasUpd}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(updateTickCmd(), cmd)
}
