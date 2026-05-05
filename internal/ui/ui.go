package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kanywst/rapg/internal/core"
	"github.com/kanywst/rapg/internal/storage"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/pquerna/otp/totp"
)

// Styles
var (
	appStyle = lipgloss.NewStyle().Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#25A065")).
			Padding(0, 1)

	statusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#04B575"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	detailStyle = lipgloss.NewStyle().
			PaddingLeft(2).
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color("#3C3C3C"))

	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D7D7D"))
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	totpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00A0FF")).Bold(true)
)

type sessionState int

const (
	stateInit sessionState = iota
	stateLogin
	stateVault
	stateAdd
)

type item struct {
	id       uint
	service  string
	username string
}

func (i item) Title() string       { return i.service }
func (i item) Description() string { return i.username }
func (i item) FilterValue() string { return i.service + " " + i.username }

type Model struct {
	state         sessionState
	list          list.Model
	inputs        []textinput.Model
	focusedInput  int
	statusMessage string
	errorMessage  string
	windowWidth   int
	windowHeight  int

	// Detail View
	selectedSecret *storage.SecretData
	viewport       viewport.Model

	// Login/Init Input
	authInput textinput.Model
}

func NewModel() Model {
	// Vault List
	delegate := list.NewDefaultDelegate()
	l := list.New([]list.Item{}, delegate, 0, 0)
	l.Title = "Rapg Vault"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = titleStyle

	// Add Form Inputs
	inputs := make([]textinput.Model, 6)
	labels := []string{"Service", "Username", "Password (Empty to Gen)", "TOTP Secret (Optional)", "Env Key (e.g. DATABASE_URL)", "Notes"}

	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Placeholder = labels[i]
		inputs[i].CharLimit = 200
		inputs[i].Width = 30
	}
	inputs[2].EchoMode = textinput.EchoPassword // Password

	// Auth Input
	ai := textinput.New()
	ai.Placeholder = "Master Password"
	ai.EchoMode = textinput.EchoPassword
	ai.Focus()
	ai.Width = 30

	initialState := stateLogin
	if !core.IsInitialized() {
		initialState = stateInit
		ai.Placeholder = "Create Master Password"
	}

	return Model{
		state:     initialState,
		list:      l,
		inputs:    inputs,
		authInput: ai,
		viewport:  viewport.New(0, 0),
	}
}

func loadItems() []list.Item {
	entries, err := core.ListEntries()
	if err != nil {
		return []list.Item{}
	}
	items := make([]list.Item, len(entries))
	for i, e := range entries {
		items[i] = item{id: e.ID, service: e.Service, username: e.Username}
	}
	return items
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tickCmd())
}

// Tick for TOTP updates
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height

		// Split View Layout
		listWidth := msg.Width / 3
		if listWidth < 30 {
			listWidth = 30
		}

		m.list.SetSize(listWidth, msg.Height-4)
		m.viewport.Width = msg.Width - listWidth - 6
		m.viewport.Height = msg.Height - 4

	case tickMsg:
		// Refresh detail view for TOTP
		if m.state == stateVault && m.selectedSecret != nil && m.selectedSecret.TOTP != "" {
			m.updateDetailView()
		}
		cmds = append(cmds, tickCmd())

	case tea.KeyMsg:
		// Global Quits
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		switch m.state {
		case stateInit:
			switch msg.String() {
			case "enter":
				pass := m.authInput.Value()
				strength := zxcvbn.PasswordStrength(pass, nil)
				if len(pass) < 12 {
					m.errorMessage = "Password must be at least 12 characters"
				} else if strength.Score < 3 {
					m.errorMessage = fmt.Sprintf("Password too weak (Score: %d/4). Use a more complex passphrase.", strength.Score)
				} else {
					if err := core.InitializeVault([]byte(pass)); err != nil {
						m.errorMessage = err.Error()
					} else {
						m.state = stateVault
						m.authInput.SetValue("")
						m.list.SetItems(loadItems())
					}
				}
			}
		case stateLogin:
			switch msg.String() {
			case "enter":
				pass := m.authInput.Value()
				if err := core.UnlockVault([]byte(pass)); err != nil {
					m.errorMessage = "Invalid Password"
					m.authInput.SetValue("")
				} else {
					m.state = stateVault
					m.errorMessage = ""
					m.authInput.SetValue("")
					m.list.SetItems(loadItems())
				}
			}

		case stateVault:
			// If filtering, list handles keys
			if m.list.FilterState() == list.Filtering {
				break
			}

			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "n":
				m.state = stateAdd
				m.resetInputs()
				return m, nil

			// Navigation
			case "up", "k", "down", "j":
				m.list, cmd = m.list.Update(msg)
				// Clear detail view on navigation to avoid lag from decryption
				m.selectedSecret = nil
				m.viewport.SetContent("")
				return m, cmd

			case "v", "space":
				m.loadSelectedDetail()
				return m, nil

			case "enter":
				// Load detail if not loaded (to get the secret)
				if m.selectedSecret == nil {
					m.loadSelectedDetail()
				}
				// Copy Password
				if m.selectedSecret != nil {
					if err := clipboard.WriteAll(m.selectedSecret.Password); err != nil {
						return m, m.flashMessage("Failed to copy password")
					}
					return m, m.flashMessage("Password Copied!")
				}

			case "ctrl+t":
				// Load detail if not loaded
				if m.selectedSecret == nil {
					m.loadSelectedDetail()
				}
				// Copy TOTP
				if m.selectedSecret != nil && m.selectedSecret.TOTP != "" {
					code, err := totp.GenerateCode(m.selectedSecret.TOTP, time.Now())
					if err != nil {
						return m, m.flashMessage("Failed to generate TOTP: invalid secret")
					}
					if err := clipboard.WriteAll(code); err != nil {
						return m, m.flashMessage("Failed to copy TOTP")
					}
					return m, m.flashMessage("TOTP Code Copied!")
				}

			case "d":
				if i, ok := m.list.SelectedItem().(item); ok {
					if err := core.DeleteEntry(i.id); err != nil {
						return m, m.flashMessage("Delete failed: " + err.Error())
					}
					m.list.SetItems(loadItems())
					m.selectedSecret = nil
					m.viewport.SetContent("")
					return m, m.flashMessage("Deleted " + i.service)
				}
			}

		case stateAdd:
			switch msg.String() {
			case "esc":
				m.state = stateVault
				return m, nil
			case "tab", "down", "enter":
				if msg.String() == "enter" && m.focusedInput == len(m.inputs)-1 {
					return m, m.submitAdd()
				}
				cmd = m.nextInput()
				return m, cmd
			case "shift+tab", "up":
				cmd = m.prevInput()
				return m, cmd
			}
		}

	case hideStatusMsg:
		m.statusMessage = ""
	}

	// Update Components based on state
	switch m.state {
	case stateInit, stateLogin:
		m.authInput, cmd = m.authInput.Update(msg)
		cmds = append(cmds, cmd)
	case stateVault:
		// Only update list if not already handled in KeyMsg special cases
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	case stateAdd:
		cmd = m.updateInputs(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) loadSelectedDetail() {
	if i, ok := m.list.SelectedItem().(item); ok {
		entry, err := storage.FindByID(i.id)
		if err == nil {
			secret, err := core.GetEntry(*entry)
			if err == nil {
				m.selectedSecret = secret
				m.updateDetailView()
			}
		}
	}
}

func (m *Model) updateDetailView() {
	if m.selectedSecret == nil {
		m.viewport.SetContent("")
		return
	}

	ss := m.selectedSecret
	var b strings.Builder

	b.WriteString(titleStyle.Render("DETAILS") + "\n\n")

	// Password
	b.WriteString(labelStyle.Render("Password: ") + valueStyle.Render("••••••••") + " (Enter to copy)\n")

	// Env Key
	if ss.EnvKey != "" {
		b.WriteString(labelStyle.Render("Env Key:  ") + valueStyle.Render(ss.EnvKey) + "\n")
	}

	// TOTP
	if ss.TOTP != "" {
		code, err := totp.GenerateCode(ss.TOTP, time.Now())
		if err == nil {
			b.WriteString(labelStyle.Render("2FA Code: ") + totpStyle.Render(code) + " (Ctrl+T to copy)\n")
		} else {
			b.WriteString(labelStyle.Render("2FA Code: ") + errorStyle.Render("Invalid Secret") + "\n")
		}
	}

	// Notes
	if ss.Notes != "" {
		b.WriteString("\n" + labelStyle.Render("Notes:") + "\n")
		b.WriteString(valueStyle.Render(ss.Notes) + "\n")
	}

	m.viewport.SetContent(detailStyle.Render(b.String()))
}

func (m *Model) submitAdd() tea.Cmd {
	service := m.inputs[0].Value()
	username := m.inputs[1].Value()
	pass := m.inputs[2].Value()
	totpSecret := m.inputs[3].Value()
	envKey := m.inputs[4].Value()
	notes := m.inputs[5].Value()

	if service == "" || username == "" {
		return nil
	}

	if pass == "" {
		var err error
		pass, err = core.GenerateRandomPassword(24)
		if err != nil {
			return m.flashMessage("Failed to generate password: " + err.Error())
		}
	}

	data := storage.SecretData{
		Password: pass,
		TOTP:     totpSecret,
		EnvKey:   envKey,
		Notes:    notes,
	}

	// Namespace stays empty in the TUI form for now; project-scoped entries
	// will be added in PR-B's TUI commit.
	if err := core.AddEntry("", service, username, data); err != nil {
		return m.flashMessage("Add failed: " + err.Error())
	}
	m.list.SetItems(loadItems())
	m.state = stateVault
	return m.flashMessage("Added " + service)
}

// Helpers
func (m *Model) resetInputs() {
	for i := range m.inputs {
		m.inputs[i].SetValue("")
	}
	m.focusedInput = 0
	m.inputs[0].Focus()
}

func (m *Model) nextInput() tea.Cmd {
	m.focusedInput = (m.focusedInput + 1) % len(m.inputs)
	return m.focusInput()
}

func (m *Model) prevInput() tea.Cmd {
	m.focusedInput--
	if m.focusedInput < 0 {
		m.focusedInput = len(m.inputs) - 1
	}
	return m.focusInput()
}

func (m *Model) focusInput() tea.Cmd {
	var cmds []tea.Cmd
	for i := 0; i < len(m.inputs); i++ {
		if i == m.focusedInput {
			cmds = append(cmds, m.inputs[i].Focus())
		} else {
			m.inputs[i].Blur()
		}
	}
	return tea.Batch(cmds...)
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd
	for i := range m.inputs {
		var cmd tea.Cmd
		m.inputs[i], cmd = m.inputs[i].Update(msg)
		cmds = append(cmds, cmd)
	}
	return tea.Batch(cmds...)
}

func (m *Model) flashMessage(msg string) tea.Cmd {
	m.statusMessage = statusMessageStyle.Render(msg)
	return tea.Tick(time.Second*2, func(_ time.Time) tea.Msg {
		return hideStatusMsg{}
	})
}

type hideStatusMsg struct{}

func (m Model) View() string {
	if m.state == stateInit || m.state == stateLogin {
		title := "UNLOCK VAULT"
		subtitle := "Enter your master password to access your secrets."
		if m.state == stateInit {
			title = "WELCOME TO RAPG"
			subtitle = "Create a master password to secure your vault.\n  Requirements: Min 12 chars & strong complexity.\n  This password is never stored and CANNOT be recovered."
		}

		return appStyle.Render(
			fmt.Sprintf("\n  %s\n\n  %s\n\n  %s\n\n  %s",
				titleStyle.Render(title),
				labelStyle.Render(subtitle),
				m.authInput.View(),
				errorStyle.Render(m.errorMessage),
			),
		)
	}

	if m.state == stateAdd {
		var b strings.Builder
		b.WriteString(titleStyle.Render("ADD NEW ENTRY") + "\n\n")
		for i, input := range m.inputs {
			b.WriteString(input.View() + "\n")
			if i < len(m.inputs)-1 {
				b.WriteRune('\n')
			}
		}
		b.WriteString("\n(esc to cancel, enter to submit)")
		return appStyle.Render(b.String())
	}

	// Vault View (Split)
	return appStyle.Render(
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			m.list.View(),
			m.viewport.View(),
		) + "\n" + m.statusMessage,
	)
}
