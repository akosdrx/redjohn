package app

import (
	"encoding/json"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/redjohn-ai/redjohn/tui/internal/protocol"
	"github.com/redjohn-ai/redjohn/tui/internal/render"
)

const pickerPage = 12

var effortLevels = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"}

type pickerPhase int

const (
	pickerList pickerPhase = iota
	pickerKey
	pickerWait
	pickerModels
)

type pickerEntry struct {
	ID       string        `json:"id"`
	Label    string        `json:"label"`
	Auth     string        `json:"auth"`
	Children []pickerEntry `json:"children"`
}

type pickerSection struct {
	Title   string        `json:"title"`
	Entries []pickerEntry `json:"entries"`
}

type pickerFrame struct {
	title    string
	sections []pickerSection
	cursor   int
	query    string
}

type pickerState struct {
	phase        pickerPhase
	title        string
	stack        []pickerFrame
	frame        pickerFrame
	models       pickerFrame
	key          string
	url          string
	userCode     string
	message      string
	note         string
	err          string
	pollInFlight bool
	leafID       string
}

type pickerRow struct {
	header     string
	entry      pickerEntry
	selectable int
}

var slashCommands = []string{"/models", "/effort"}

// slashGhost is the untyped tail of the one command the current line prefixes.
// "/" alone matches both commands, so it stays blank until the next letter.
func slashGhost(value string) string {
	if value == "" || strings.ContainsAny(value, "\n ") {
		return ""
	}
	lower := strings.ToLower(value)
	match := ""
	for _, command := range slashCommands {
		if strings.HasPrefix(command, lower) && command != lower {
			if match != "" {
				return ""
			}
			match = command
		}
	}
	if match == "" || len(value) > len(match) {
		return ""
	}
	return match[len(value):]
}

func completeSlash(value string) (string, bool) {
	ghost := slashGhost(value)
	if ghost == "" {
		return "", false
	}
	return value + ghost, true
}

func (m *Model) interceptSlash(value string) (tea.Cmd, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return nil, false
	}
	switch strings.ToLower(fields[0]) {
	case "/models":
		return m.openModelPicker(), true
	case "/effort":
		m.openEffortPicker()
		return nil, true
	default:
		return nil, false
	}
}

func (m *Model) openModelPicker() tea.Cmd {
	m.modal = modalPicker
	m.input.Blur()
	m.picker = pickerState{
		phase:   pickerList,
		title:   "Select model",
		message: "Loading…",
	}
	return send(m.client, "llm.catalog", map[string]any{})
}

func (m *Model) openEffortPicker() {
	m.modal = modalPicker
	m.input.Blur()
	current := strings.TrimSpace(m.snapshot.ReasoningEffort)
	if current == "" {
		current = "high"
	}
	entries := make([]pickerEntry, 0, len(effortLevels))
	cursor := 0
	for index, level := range effortLevels {
		label := level
		if level == current {
			label += "  ●"
			cursor = index
		}
		entries = append(entries, pickerEntry{ID: level, Label: label, Auth: "effort"})
	}
	m.picker = pickerState{
		phase: pickerList,
		title: "Select effort",
		frame: pickerFrame{
			title:    "Select effort",
			sections: []pickerSection{{Entries: entries}},
			cursor:   cursor,
		},
	}
}

func (m Model) updatePicker(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc", "ctrl+c":
		return m, m.backPicker()
	case "up", "ctrl+p":
		m.movePicker(-1)
		return m, nil
	case "down", "ctrl+n":
		m.movePicker(1)
		return m, nil
	case "pgup":
		m.movePicker(-pickerPage)
		return m, nil
	case "pgdown":
		m.movePicker(pickerPage)
		return m, nil
	case "enter":
		return m, m.activatePicker()
	case "backspace", "ctrl+h":
		m.editPicker(-1, "")
		return m, nil
	}
	if key.Type == tea.KeyRunes && len(key.Runes) > 0 {
		m.editPicker(0, string(key.Runes))
	}
	return m, nil
}

func (m *Model) movePicker(delta int) {
	frame := m.activeFrame()
	if frame == nil {
		return
	}
	count := selectableCount(frame.rows())
	if count == 0 {
		frame.cursor = 0
		return
	}
	frame.cursor += delta
	if frame.cursor < 0 {
		frame.cursor = 0
	}
	if frame.cursor >= count {
		frame.cursor = count - 1
	}
}

func (m *Model) editPicker(drop int, insert string) {
	switch m.picker.phase {
	case pickerKey:
		if drop < 0 && m.picker.key != "" {
			runes := []rune(m.picker.key)
			m.picker.key = string(runes[:len(runes)-1])
		}
		if insert != "" {
			m.picker.key += insert
		}
	case pickerList:
		editQuery(&m.picker.frame, drop, insert)
	case pickerModels:
		editQuery(&m.picker.models, drop, insert)
	}
}

func editQuery(frame *pickerFrame, drop int, insert string) {
	if drop < 0 && frame.query != "" {
		runes := []rune(frame.query)
		frame.query = string(runes[:len(runes)-1])
	}
	if insert != "" {
		frame.query += insert
	}
	frame.cursor = 0
}

func (m *Model) activatePicker() tea.Cmd {
	switch m.picker.phase {
	case pickerKey:
		if strings.TrimSpace(m.picker.key) == "" {
			m.picker.err = "API key is required"
			return nil
		}
		m.picker.phase = pickerWait
		m.picker.message = "Checking the key…"
		m.picker.err = ""
		return send(m.client, "llm.connect", map[string]any{
			"id":      m.entryID(),
			"api_key": m.picker.key,
		})
	case pickerWait:
		return nil
	default:
		entry, ok := m.selectedEntry()
		if !ok {
			return nil
		}
		return m.chooseEntry(entry)
	}
}

func (m *Model) chooseEntry(entry pickerEntry) tea.Cmd {
	if len(entry.Children) > 0 {
		m.picker.stack = append(m.picker.stack, m.picker.frame)
		m.picker.frame = pickerFrame{
			title:    entry.Label,
			sections: []pickerSection{{Entries: entry.Children}},
		}
		m.picker.title = entry.Label
		m.picker.err = ""
		return nil
	}
	switch entry.Auth {
	case "model":
		m.picker.message = "Saving…"
		return send(m.client, "llm.select_model", map[string]any{"model": entry.ID})
	case "effort":
		return send(m.client, "llm.set_effort", map[string]any{"effort": entry.ID})
	case "api_key":
		m.picker.phase = pickerKey
		m.picker.title = entry.Label
		m.picker.key = ""
		m.picker.err = ""
		m.picker.leafID = entry.ID
		return nil
	default:
		m.picker.phase = pickerWait
		m.picker.title = entry.Label
		m.picker.message = "Waiting for sign-in…"
		m.picker.url = ""
		m.picker.userCode = ""
		m.picker.err = ""
		m.picker.leafID = entry.ID
		return send(m.client, "llm.connect", map[string]any{"id": entry.ID})
	}
}

func (m *Model) entryID() string {
	return m.picker.leafID
}

func (m *Model) backPicker() tea.Cmd {
	var cmd tea.Cmd
	switch m.picker.phase {
	case pickerKey:
		m.picker.phase = pickerList
		m.picker.key = ""
		m.picker.err = ""
		m.picker.title = m.picker.frame.title
		if m.picker.title == "" {
			m.picker.title = "Select model"
		}
		return nil
	case pickerWait, pickerModels:
		cmd = send(m.client, "llm.auth_cancel", map[string]any{})
		m.picker.phase = pickerList
		m.picker.pollInFlight = false
		m.picker.err = ""
		m.picker.message = ""
		m.picker.title = m.picker.frame.title
		if m.picker.title == "" {
			m.picker.title = "Select model"
		}
		return cmd
	}
	if len(m.picker.stack) > 0 {
		m.picker.frame = m.picker.stack[len(m.picker.stack)-1]
		m.picker.stack = m.picker.stack[:len(m.picker.stack)-1]
		m.picker.title = m.picker.frame.title
		if m.picker.title == "" {
			m.picker.title = "Select model"
		}
		m.picker.err = ""
		return nil
	}
	m.closeModal()
	return nil
}

func (m *Model) pollPicker() tea.Cmd {
	if m.modal != modalPicker || m.picker.phase != pickerWait || m.picker.pollInFlight {
		return nil
	}
	m.picker.pollInFlight = true
	return send(m.client, "llm.auth_status", map[string]any{})
}

func (m *Model) failPicker(message string) {
	if m.modal != modalPicker {
		m.errorText = message
		return
	}
	m.picker.err = message
	m.picker.pollInFlight = false
	if m.picker.phase == pickerWait {
		m.picker.message = message
	}
}

func (m *Model) handleLLMResult(result protocol.CommandResult) tea.Cmd {
	if m.modal != modalPicker {
		return nil
	}
	m.picker.pollInFlight = false
	switch result.Command {
	case "llm.catalog":
		var data struct {
			Title    string          `json:"title"`
			Sections []pickerSection `json:"sections"`
		}
		if err := json.Unmarshal(result.Result, &data); err != nil {
			m.failPicker(err.Error())
			return nil
		}
		title := data.Title
		if title == "" {
			title = "Select model"
		}
		m.picker.phase = pickerList
		m.picker.title = title
		m.picker.stack = nil
		m.picker.frame = pickerFrame{title: title, sections: data.Sections}
		m.picker.message = ""
		m.picker.err = ""
	case "llm.connect", "llm.auth_status":
		return m.applyAuthStatus(result.Result)
	case "llm.select_model":
		return m.finishSaved(result.Result, "Model saved")
	case "llm.set_effort":
		return m.finishSaved(result.Result, "Effort saved")
	case "llm.auth_cancel":
		return nil
	}
	return nil
}

func (m *Model) applyAuthStatus(raw json.RawMessage) tea.Cmd {
	var data struct {
		Phase    string `json:"phase"`
		URL      string `json:"url"`
		UserCode string `json:"user_code"`
		Message  string `json:"message"`
		Note     string `json:"note"`
		Provider string `json:"provider"`
		Models   []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		m.failPicker(err.Error())
		return nil
	}
	switch data.Phase {
	case "models":
		entries := make([]pickerEntry, 0, len(data.Models))
		for _, model := range data.Models {
			label := model.Label
			if label == "" {
				label = model.ID
			}
			entries = append(entries, pickerEntry{ID: model.ID, Label: label, Auth: "model"})
		}
		title := data.Provider
		if title == "" {
			title = "Select model"
		}
		m.picker.phase = pickerModels
		m.picker.title = title
		m.picker.key = ""
		m.picker.note = data.Note
		m.picker.err = ""
		m.picker.message = ""
		m.picker.models = pickerFrame{title: title, sections: []pickerSection{{Entries: entries}}}
		return nil
	case "error":
		m.failPicker(data.Message)
		return nil
	case "browser", "device", "pending":
		m.picker.phase = pickerWait
		if data.URL != "" {
			m.picker.url = data.URL
		}
		if data.UserCode != "" {
			m.picker.userCode = data.UserCode
		}
		if data.Message != "" {
			m.picker.message = data.Message
		}
		return pickerPoll()
	default:
		if m.picker.phase == pickerWait {
			return pickerPoll()
		}
	}
	return nil
}

func (m *Model) finishSaved(raw json.RawMessage, fallback string) tea.Cmd {
	var data struct {
		Model   string `json:"model"`
		Effort  string `json:"effort"`
		Applied string `json:"applied"`
	}
	_ = json.Unmarshal(raw, &data)
	text := fallback
	if data.Applied == "next_scan" {
		text = "Saved for the next scan"
	} else if data.Model != "" {
		text = "Model set to " + data.Model
	} else if data.Effort != "" {
		text = "Effort set to " + data.Effort
	}
	m.closeModal()
	m.picker = pickerState{}
	return m.showToast(text)
}

func pickerPoll() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return pickerPollMsg{} })
}

func (m *Model) activeFrame() *pickerFrame {
	if m.picker.phase == pickerModels {
		return &m.picker.models
	}
	if m.picker.phase == pickerList {
		return &m.picker.frame
	}
	return nil
}

func (m *Model) selectedEntry() (pickerEntry, bool) {
	frame := m.activeFrame()
	if frame == nil {
		return pickerEntry{}, false
	}
	rows := frame.rows()
	frame.cursor = clampedCursor(frame.cursor, selectableCount(rows))
	for _, row := range rows {
		if row.selectable == frame.cursor {
			return row.entry, true
		}
	}
	return pickerEntry{}, false
}

func clampedCursor(cursor, count int) int {
	if count <= 0 {
		return 0
	}
	if cursor < 0 {
		return 0
	}
	if cursor >= count {
		return count - 1
	}
	return cursor
}

func (frame pickerFrame) rows() []pickerRow {
	query := strings.ToLower(strings.TrimSpace(frame.query))
	var rows []pickerRow
	selectable := 0
	for _, section := range frame.sections {
		var matched []pickerEntry
		for _, entry := range section.Entries {
			if query == "" || strings.Contains(strings.ToLower(entry.Label), query) {
				matched = append(matched, entry)
			}
		}
		if len(matched) == 0 {
			continue
		}
		if strings.TrimSpace(section.Title) != "" {
			rows = append(rows, pickerRow{header: section.Title, selectable: -1})
		}
		for _, entry := range matched {
			rows = append(rows, pickerRow{entry: entry, selectable: selectable})
			selectable++
		}
	}
	return rows
}

func selectableCount(rows []pickerRow) int {
	count := 0
	for _, row := range rows {
		if row.selectable >= 0 {
			count++
		}
	}
	return count
}

func (m Model) pickerView() string {
	width := min(62, max(36, m.width-8))
	inner := width - 4
	title := m.picker.title
	if title == "" {
		title = "Select model"
	}
	head := render.Bold(white).Render(truncate(title, max(1, inner-6)))
	esc := render.Dim().Render("esc")
	gap := max(1, inner-lipgloss.Width(head)-lipgloss.Width(esc))
	lines := []string{head + strings.Repeat(" ", gap) + esc}

	switch m.picker.phase {
	case pickerKey:
		lines = append(lines, m.pickerKeyBody(inner)...)
	case pickerWait:
		lines = append(lines, m.pickerWaitBody(inner)...)
	default:
		lines = append(lines, m.pickerListBody(inner)...)
	}
	if m.picker.err != "" && m.picker.phase != pickerWait {
		lines = append(lines, render.Col(red).Render(truncate(m.picker.err, inner)))
	}
	body := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Width(width).Border(lipgloss.RoundedBorder()).
		BorderForeground(dark).Background(black).Padding(0, 1).Render(body)
}

func (m Model) pickerKeyBody(inner int) []string {
	masked := strings.Repeat("•", min(len([]rune(m.picker.key)), 24))
	if masked == "" {
		masked = " "
	}
	return []string{
		"",
		render.Dim().Render("API key"),
		lipgloss.NewStyle().Foreground(white).Background(lipgloss.Color("#1c1917")).Width(inner).Render(masked),
		"",
		render.Dim().Render("enter save"),
	}
}

func (m Model) pickerWaitBody(inner int) []string {
	lines := []string{""}
	if m.picker.message != "" {
		lines = append(lines, wrapPicker(m.picker.message, inner)...)
	}
	if m.picker.url != "" {
		lines = append(lines, "", render.Col(lightBlue).Render(truncate(m.picker.url, inner)))
	}
	if m.picker.userCode != "" {
		lines = append(lines, "", render.Bold(amber).Render(truncate("Code  "+m.picker.userCode, inner)))
	}
	if m.picker.err != "" {
		lines = append(lines, "", render.Col(red).Render(truncate(m.picker.err, inner)))
	}
	lines = append(lines, "", render.Dim().Render("esc cancel"))
	return lines
}

func (m Model) pickerListBody(inner int) []string {
	frame := m.picker.frame
	if m.picker.phase == pickerModels {
		frame = m.picker.models
	}
	query := frame.query
	if query == "" {
		query = " "
	}
	lines := []string{
		render.Dim().Render("Search"),
		lipgloss.NewStyle().Foreground(white).Width(inner).Render(truncate(query, inner)),
		"",
	}
	if m.picker.note != "" && m.picker.phase == pickerModels {
		lines = append(lines, render.Dim().Render(truncate(m.picker.note, inner)), "")
	}
	rows := frame.rows()
	cursor := clampedCursor(frame.cursor, selectableCount(rows))
	if len(rows) == 0 {
		message := "No matches"
		if m.picker.message != "" && len(frame.sections) == 0 {
			message = m.picker.message
		}
		lines = append(lines, render.Dim().Render(truncate(message, inner)))
		return lines
	}
	selectedVisual := 0
	type drawn struct {
		text     string
		selected bool
	}
	var drawnRows []drawn
	for _, row := range rows {
		if row.selectable < 0 {
			drawnRows = append(drawnRows, drawn{
				text: render.Col(lightBlue).Render(truncate(row.header, inner)),
			})
			continue
		}
		label := "  " + row.entry.Label
		selected := row.selectable == cursor
		if selected {
			selectedVisual = len(drawnRows)
			label = lipgloss.NewStyle().Background(amber).Foreground(black).Width(inner).Render(truncate(label, inner))
		} else {
			label = lipgloss.NewStyle().Foreground(textColor).Width(inner).Render(truncate(label, inner))
		}
		drawnRows = append(drawnRows, drawn{text: label, selected: selected})
	}
	page := pickerPage
	if m.height > 0 {
		page = min(pickerPage, max(4, m.height-12))
	}
	start := 0
	if selectedVisual >= page {
		start = selectedVisual - page + 1
	}
	end := min(len(drawnRows), start+page)
	for _, row := range drawnRows[start:end] {
		lines = append(lines, row.text)
	}
	lines = append(lines, "", render.Dim().Render("enter select"))
	return lines
}

func wrapPicker(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 || width < 8 {
		return []string{render.Col(textColor).Render(truncate(text, max(1, width)))}
	}
	var lines []string
	current := ""
	for _, word := range words {
		next := word
		if current != "" {
			next = current + " " + word
		}
		if lipgloss.Width(next) > width && current != "" {
			lines = append(lines, render.Col(textColor).Render(current))
			current = word
			continue
		}
		current = next
	}
	if current != "" {
		lines = append(lines, render.Col(textColor).Render(truncate(current, width)))
	}
	return lines
}
