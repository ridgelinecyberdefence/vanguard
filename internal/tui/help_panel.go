package tui

import (
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/help"
	"github.com/ridgelinecyberdefence/vanguard/internal/usecases"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type helpView int

const (
	helpViewNone helpView = iota
	helpViewMenu
	helpViewPage
)

// HelpState carries panel state for the [H] Help submenu.
type HelpState struct {
	view helpView

	// Menu cursor.
	menuCursor int

	// Active page.
	currentPage   help.PageID
	currentTitle  string
	pageLines     []string
	scroll        int // top visible line index

	// Cached use case library — built once on first access so the catalog
	// reflects whatever's on disk at panel-open time.
	library *usecases.Library
}

// ---------------------------------------------------------------------------
// Sidebar entry point
// ---------------------------------------------------------------------------

// openHelp routes the sidebar [H] action into the help panel. Loads the use
// case library once (best-effort) so the dynamic Use Case Reference page is
// ready when the analyst opens it.
func (m Model) openHelp() (Model, tea.Cmd) {
	m.clearPanelState()
	st := HelpState{view: helpViewMenu}
	if lib, err := usecases.Load(filepath.Join(m.ctx.RootDir, "usecases")); err == nil {
		st.library = lib
	}
	m.helpState = st
	m.state = stateResult
	return m, nil
}

// ---------------------------------------------------------------------------
// Key dispatch
// ---------------------------------------------------------------------------

func (m Model) helpUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.helpState.view == helpViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.helpState.view {
	case helpViewMenu:
		return m.helpHandleMenu(key)
	case helpViewPage:
		return m.helpHandlePage(key)
	}
	return m, nil, false
}

func (m Model) helpHandleMenu(key string) (Model, tea.Cmd, bool) {
	items := help.Menu()
	switch key {
	case "esc":
		m.helpState.view = helpViewNone
		m.state = stateMainMenu
		m.focus = paneSidebar
		return m, nil, true
	case "up", "k":
		if m.helpState.menuCursor > 0 {
			m.helpState.menuCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.helpState.menuCursor < len(items)-1 {
			m.helpState.menuCursor++
		}
		return m, nil, true
	case "enter":
		if m.helpState.menuCursor < len(items) {
			return m.helpOpenPage(items[m.helpState.menuCursor]), nil, true
		}
	}
	// Number / letter shortcuts — consult the menu items.
	upper := strings.ToUpper(key)
	for _, it := range items {
		if it.Shortcut == upper || it.Shortcut == key {
			return m.helpOpenPage(it), nil, true
		}
	}
	return m, nil, true
}

// helpOpenPage fills the page state by rendering the requested PageID.
func (m Model) helpOpenPage(item help.MenuItem) Model {
	text := help.Render(item.Page,
		m.helpState.library, m.ctx.ToolManager,
		m.ctx.Version, m.ctx.BuildDate, m.ctx.Commit, m.ctx.Platform)
	m.helpState.currentPage = item.Page
	m.helpState.currentTitle = item.Title
	m.helpState.pageLines = strings.Split(strings.TrimRight(text, "\n"), "\n")
	m.helpState.scroll = 0
	m.helpState.view = helpViewPage
	return m
}

// helpHandlePage drives keyboard navigation inside a rendered page.
func (m Model) helpHandlePage(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc", "backspace":
		m.helpState.view = helpViewMenu
		return m, nil, true
	case "up", "k":
		if m.helpState.scroll > 0 {
			m.helpState.scroll--
		}
		return m, nil, true
	case "down", "j":
		max := m.helpMaxScroll()
		if m.helpState.scroll < max {
			m.helpState.scroll++
		}
		return m, nil, true
	case "pgup", "b":
		m.helpState.scroll -= m.helpViewportRows()
		if m.helpState.scroll < 0 {
			m.helpState.scroll = 0
		}
		return m, nil, true
	case "pgdown", "pgdn", " ", "f":
		m.helpState.scroll += m.helpViewportRows()
		max := m.helpMaxScroll()
		if m.helpState.scroll > max {
			m.helpState.scroll = max
		}
		return m, nil, true
	case "home", "g":
		m.helpState.scroll = 0
		return m, nil, true
	case "end", "G":
		m.helpState.scroll = m.helpMaxScroll()
		return m, nil, true
	}
	return m, nil, true
}

// helpViewportRows returns how many text rows the page area can display.
//
// The chrome above the page (breadcrumb + section + rule + 4 padding lines)
// and below it (status hint line) take ~7 rows; the rest is scroll viewport.
func (m Model) helpViewportRows() int {
	contentH := m.height - 6
	if contentH < 10 {
		contentH = 10
	}
	rows := contentH - 7
	if rows < 6 {
		rows = 6
	}
	return rows
}

// helpMaxScroll returns the largest valid scroll offset for the active page.
func (m Model) helpMaxScroll() int {
	max := len(m.helpState.pageLines) - m.helpViewportRows()
	if max < 0 {
		return 0
	}
	return max
}
