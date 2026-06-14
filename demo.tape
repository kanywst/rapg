# vhs script for demo-v2.gif
# Re-run with: make demo  (which builds ./rapg first then runs `vhs demo.tape`)
# CI re-generates on master push via .github/workflows/demo.yml.

Output demo-v2.gif

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
Type "# Your AI agent needs ANTHROPIC_API_KEY. rapg keeps it off the agent."
Enter
Sleep 1.8s
Type "clear"
Enter
Sleep 400ms

# ---- Open the vault ----
Type "./rapg"
Enter
Sleep 2.5s

# Master password (zxcvbn-strong)
Type "purple-monkey-dishwasher-99"
Sleep 700ms
Enter
Sleep 2s

# ---- Add ANTHROPIC_API_KEY ----
# Fields in order: Service, Username, Password, TOTP, Namespace, Env Key, Notes
Type "n"
Sleep 1s
Type "anthropic"
Enter
Sleep 500ms
Type "dev"
Enter
Sleep 500ms
Type "sk-ant-demo-not-a-real-key-1234567890"
Enter
Sleep 500ms
# TOTP: empty
Enter
Sleep 400ms
# Namespace: empty (global)
Enter
Sleep 400ms
Type "ANTHROPIC_API_KEY"
Enter
Sleep 500ms
# Notes: empty -> submit
Enter
Sleep 2s

# ---- Add DATABASE_URL ----
Type "n"
Sleep 1s
Type "postgres"
Enter
Sleep 500ms
Type "app"
Enter
Sleep 500ms
Type "postgres://user:s3cret@localhost:5432/app"
Enter
Sleep 500ms
# TOTP: empty
Enter
Sleep 400ms
# Namespace: empty (global)
Enter
Sleep 400ms
Type "DATABASE_URL"
Enter
Sleep 500ms
# Notes: empty -> submit
Enter
Sleep 2s

# ---- Quit TUI ----
Type "q"
Sleep 1s
Type "clear"
Enter
Sleep 400ms

# ---- The hero: rapg proxy ----
Type "# rapg proxy holds the real key; the agent only ever sees a short-lived token"
Enter
Sleep 1.8s
Type "./rapg proxy --provider anthropic -- sh -c 'echo BASE=$ANTHROPIC_BASE_URL; echo TOKEN=$ANTHROPIC_AUTH_TOKEN; echo DB=$DATABASE_URL'"
Enter
Sleep 1.2s
Type "purple-monkey-dishwasher-99"
Enter
Sleep 3.5s

# ---- Point it out ----
Type "# BASE -> local proxy.  TOKEN -> ephemeral, NOT the sk-ant key.  DB injected too."
Enter
Sleep 3.5s
