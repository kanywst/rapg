# Where should we write the GIF?
Output demo.gif

# Set up a 1200x600 terminal with 46px font.
Set FontSize 22
Set Width 1200
Set Height 800
Set TypingSpeed 75ms

# Cleanup and Build (Hidden)
Hide
Type "rm -rf ~/.rapg"
Enter
Type "go build -o rapg cmd/rapg/main.go"
Enter
Ctrl+l
Sleep 500ms
Show

# 1. Start Rapg
Type "./rapg"
Sleep 500ms
Enter

# Wait for the UI to start and show "SETUP VAULT" clearly
Sleep 2.5s

# 2. Initial Setup
# Use a strong password to satisfy zxcvbn requirements
Type "purple-monkey-dishwasher-99"
Sleep 1s
Enter
Sleep 2s

# 3. Add a Secret with Env Injection
Type "n"
Sleep 1.5s
Type "Production DB"
Enter
Sleep 1s
Type "admin"
Enter
Sleep 1s
# Leave password blank for generation (Index 2)
Enter
Sleep 1s
# No TOTP (Index 3)
Enter
Sleep 1s
# Set Env Key (Index 4)
Type "DB_PASSWORD"
Enter
Sleep 1s
# Notes (Index 5) - Enter to Submit
Type "Production DB Password"
Sleep 1s
Enter
Enter
# Wait for list to update and flash message
Sleep 3s

# 4. Add a Secret with TOTP
Type "n"
Sleep 1.5s
Type "google.com"
Enter
Sleep 1s
Type "kanywst@gmail.com"
Enter
Sleep 1s
# Leave password blank
Enter
Sleep 1s
# Set TOTP Secret
Type "JBSWY3DPEHPK3PXP"
Enter
Sleep 1s
# No Env Key
Enter
Sleep 1s
# No Notes (Submit)
Enter
Sleep 3s

# 5. View Details (Google)
# "google.com" should be the second item. Move down.
Type "j" 
Sleep 1s
# Enter to View Details (and copy password)
Enter
Sleep 2s

# Copy TOTP
Ctrl+T
Sleep 1.5s

# 6. Exit TUI
Type "q"
Sleep 1s

# 7. Demonstrate Process Injection
# Use single quotes to prevent the outer shell from expanding the variable
Type "./rapg run -- sh -c 'echo Injected: $DB_PASSWORD'"
Enter
# Wait for "Master Password: " prompt to appear and echo to be disabled
Sleep 2s
Type "purple-monkey-dishwasher-99"
Enter
Sleep 4s
