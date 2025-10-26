#!/bin/bash
# manual-wiki-sync.sh
# Manual script to sync wiki content

set -e

echo "🔄 Manual Wiki Sync Script"
echo "=========================="

# Configuration
REPO_NAME="samerfarida/mcp-ssh-orchestrator"
WIKI_URL="https://github.com/${REPO_NAME}.wiki.git"
WIKI_DIR="temp-wiki-sync"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: Not in mcp-ssh-orchestrator root directory"
    exit 1
fi

# Check if docs/wiki directory exists
if [ ! -d "docs/wiki" ]; then
    echo "❌ Error: docs/wiki directory not found"
    exit 1
fi

echo "📁 Source directory: docs/wiki/"
echo "🎯 Target: ${WIKI_URL}"

# Clean up any existing temp directory
if [ -d "$WIKI_DIR" ]; then
    echo "🧹 Cleaning up existing temp directory..."
    rm -rf "$WIKI_DIR"
fi

# Clone the wiki repository
echo "📥 Cloning wiki repository..."
git clone "$WIKI_URL" "$WIKI_DIR"
cd "$WIKI_DIR"

# Ensure we're on the master branch (wikis use master, not main)
git checkout master

# Show current wiki content
echo "📋 Current wiki content:"
ls -la *.md 2>/dev/null || echo "No markdown files found"

# Copy new content (preserve .git directory)
echo "📋 Copying wiki content..."
rsync -av --delete --exclude='.git' ../docs/wiki/ ./

# Show what will be added/changed
echo "📝 Changes to be committed:"
git add .
git status

# Check if there are changes
if ! git diff --staged --quiet; then
    echo "📝 Changes detected, committing..."
    
    # Get list of changed files
    CHANGED_FILES=$(git diff --staged --name-only | head -10)
    
    git commit -m "Manual sync: Update wiki content

    Synced from local docs/wiki/ directory
    Changed files:
    $CHANGED_FILES
    
    [skip ci]"
    
    # Push to wiki repository
    echo "🚀 Pushing to wiki repository..."
    echo "Current remote: $(git remote -v)"
    git push origin master
    
    echo "✅ Wiki synced successfully!"
    
    # Show final content
    echo "📋 Final wiki content:"
    ls -la *.md | head -20
    
else
    echo "ℹ️ No changes to sync"
fi

# Clean up
cd ..
rm -rf "$WIKI_DIR"

echo ""
echo "🎉 Manual wiki sync completed!"
echo "🔗 Wiki available at: https://github.com/${REPO_NAME}/wiki"
echo ""
echo "📋 Next steps:"
echo "1. Visit the wiki URL to verify content"
echo "2. Check that all 16 sections are present"
echo "3. Test navigation and links"
echo "4. Run the GitHub Actions workflow to automate future syncs"
