# vhs script for demo.gif
# Re-run with: make demo  (which builds ./rapg first then runs `vhs demo.tape`)
# CI re-generates on master push via .github/workflows/demo.yml.

Output demo.gif

Set FontSize 22
Set Width 1200
Set Height 800
Set TypingSpeed 60ms
Set Theme "Catppuccin Mocha"

# ---- Hidden cleanup (vault wipe + clear screen) ----
Hide
Type "rm -rf ~/.rapg && clear"
Enter
Sleep 500ms
Show

# ---- Frame the problem ----
Type "# Your AI agent needs an API key. Where do you keep it?"
Enter
Sleep 1.5s
Type "ls .env 2>/dev/null || echo '(no .env file on disk — good)'"
Enter
Sleep 2s
Type "clear"
Enter
Sleep 500ms

# ---- Open the vault ----
Type "./rapg"
Enter
Sleep 2.5s

# Master password (zxcvbn-strong)
Type "purple-monkey-dishwasher-99"
Sleep 800ms
Enter
Sleep 2s

# ---- Add ANTHROPIC_API_KEY ----
Type "n"
Sleep 1.2s
Type "anthropic"
Enter
Sleep 700ms
Type "dev"
Enter
Sleep 700ms
Type "sk-ant-demo-not-a-real-key-1234567890"
Enter
Sleep 700ms
# No TOTP
Enter
Sleep 700ms
Type "ANTHROPIC_API_KEY"
Enter
Sleep 700ms
# Notes empty -> Enter to submit
Enter
Sleep 2.5s

# ---- Add DATABASE_URL ----
Type "n"
Sleep 1.2s
Type "postgres"
Enter
Sleep 700ms
Type "app"
Enter
Sleep 700ms
Type "postgres://user:s3cret@localhost:5432/app"
Enter
Sleep 700ms
# No TOTP
Enter
Sleep 700ms
Type "DATABASE_URL"
Enter
Sleep 700ms
Enter
Sleep 2.5s

# ---- Quit TUI ----
Type "q"
Sleep 1s

# ---- Inject into a child process (the wedge) ----
Type "# Inject into any process — agent, dev server, script"
Enter
Sleep 1.5s
Type "./rapg run -- sh -c 'echo agent sees: $ANTHROPIC_API_KEY'"
Enter
Sleep 1.5s
Type "purple-monkey-dishwasher-99"
Enter
Sleep 3s

# ---- Prove disk footprint is zero ----
Type "ls .env 2>/dev/null || echo '(still no .env on disk)'"
Enter
Sleep 3s
