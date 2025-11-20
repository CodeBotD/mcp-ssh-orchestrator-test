# Switch to Main Branch

Help me safely switch to the main branch, handling any uncommitted changes appropriately.

## Steps to follow

1. **Check current status:**
   - Get the current branch name
   - If already on `main`, check if it's up to date with remote and pull if needed
   - Check for uncommitted changes (both staged and unstaged)

2. **Handle uncommitted changes (if any):**
   - If there are uncommitted changes, present options to the user:
     - **Option 1: Stash** (recommended) - Save changes for later with a descriptive message
     - **Option 2: Commit** - Guide user to commit changes first
     - **Option 3: Discard** - Warn about data loss and confirm before proceeding
     - **Option 4: Cancel** - Abort the operation
   - Wait for user's choice before proceeding

3. **Switch to main branch:**
   - Fetch latest changes from remote: `git fetch origin`
   - Switch to main: `git checkout main`
   - Pull latest changes: `git pull origin main`

4. **Post-switch actions:**
   - Show current git status
   - If we switched from a feature branch, ask if user wants to delete the local feature branch
   - If changes were stashed, remind the user:
     - How to see stashed changes: `git stash list`
     - How to restore: `git stash pop` or `git stash apply`

5. **Confirm completion:**
   - Verify we're on main branch
   - Confirm branch is up to date
   - Provide summary of actions taken

## Important notes

- Always preserve user's work - prefer stashing over discarding
- Warn clearly about destructive actions (discarding changes, deleting branches)
- Be helpful and explain what each action does
- If already on main, just ensure it's up to date
