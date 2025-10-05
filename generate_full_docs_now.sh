#!/bin/bash
# Generate comprehensive documentation from the entire codebase
# This is for catching up on all existing code that was pushed before docs automation was fixed

set -e

echo "🚀 Vivified Documentation Generator - Full Repository Scan"
echo "=========================================================="
echo ""

# Check for OpenAI API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY environment variable not set"
    echo "Please set it: export OPENAI_API_KEY=your-api-key"
    exit 1
fi

echo "✅ OpenAI API key found"
echo ""

# Check current branch
CURRENT_BRANCH=$(git branch --show-current)
echo "📍 Current branch: $CURRENT_BRANCH"

# Fetch latest from development
echo "📥 Fetching latest from origin/development..."
git fetch origin development

# Switch to development to get all the latest code
echo "🔄 Checking out development branch to scan all existing code..."
git checkout development
git pull origin development

echo ""
echo "📚 Generating comprehensive documentation from entire codebase..."
echo "This will scan ALL files in the repository and create complete documentation."
echo ""

# Run the documentation generator with full scan flag
python tools/scripts/docs_autopilot_enhanced.py --full-scan

echo ""
echo "✅ Documentation generation complete!"
echo ""
echo "📝 Files have been created/updated in the docs/ directory"
echo ""

# Switch back to original branch
echo "🔄 Switching back to $CURRENT_BRANCH..."
git checkout $CURRENT_BRANCH

echo ""
echo "Next steps:"
echo "1. Review the generated documentation in docs/"
echo "2. Commit the changes: git add docs/ && git commit -m 'docs: comprehensive documentation from full repository scan'"
echo "3. Push to trigger deployment: git push origin $CURRENT_BRANCH"
echo ""
echo "The documentation will be automatically deployed to https://docs.vivified.dev after merge to mkdocs branch."
