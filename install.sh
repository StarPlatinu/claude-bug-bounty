#!/bin/bash
# Claude Bug Bounty — install skills into ~/.claude/skills/

set -e

INSTALL_DIR="${HOME}/.claude/skills"
mkdir -p "${INSTALL_DIR}"

echo "Installing Claude Bug Bounty skills..."
echo ""

# Copy all skills
for skill_dir in skills/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "${INSTALL_DIR}/${skill_name}"
    cp "${skill_dir}SKILL.md" "${INSTALL_DIR}/${skill_name}/SKILL.md"
    echo "✓ Installed skill: ${skill_name}"
done

# Install commands
COMMANDS_DIR="${HOME}/.claude/commands"
mkdir -p "${COMMANDS_DIR}"

for cmd_file in commands/*.md; do
    cmd_name=$(basename "$cmd_file")
    cp "$cmd_file" "${COMMANDS_DIR}/${cmd_name}"
    echo "✓ Installed command: ${cmd_name}"
done

echo ""
echo "Done! Skills installed to ${INSTALL_DIR}"
echo "Commands installed to ${COMMANDS_DIR}"
echo ""

# Offer Burp MCP setup
echo "─────────────────────────────────────────────"
echo "Optional: Burp Suite MCP Integration"
echo "─────────────────────────────────────────────"
echo ""
echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
echo "See mcp/burp-mcp-client/README.md for setup instructions."
echo ""
read -p "Set up Burp MCP now? (y/N): " setup_burp
if [[ "$setup_burp" =~ ^[Yy]$ ]]; then
    echo ""
    echo "To connect Burp MCP, add this to your Claude Code settings:"
    echo ""
    echo "  claude config edit"
    echo ""
    echo "Then add to the mcpServers section:"
    cat mcp/burp-mcp-client/config.json | grep -A 10 '"burp"'
    echo ""
    echo "And set your Burp API key:"
    echo "  export BURP_API_KEY=\"your-api-key-here\""
    echo ""
fi


# ── Python dependencies for claudebbp CLI ─────────────────────────────────────
echo "─────────────────────────────────────────────"
echo "Installing Python dependencies for claudebbp…"
echo "─────────────────────────────────────────────"

pip install typer rich requests certifi 2>/dev/null || \
    pip3 install typer rich requests certifi 2>/dev/null || \
    echo "⚠ pip not found — install manually: pip install typer rich requests certifi"

# Make CLI executable
if [ -f "claudebbp.py" ]; then
    chmod +x claudebbp.py
    echo "✓ claudebbp.py is now executable"

    # Optional: symlink to /usr/local/bin
    if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
        ln -sf "$(pwd)/claudebbp.py" /usr/local/bin/claudebbp
        echo "✓ Symlinked: claudebbp → /usr/local/bin/claudebbp"
    else
        echo "  Add to PATH: export PATH=\"$(pwd):\$PATH\""
    fi
fi

# Create state directory
mkdir -p "${HOME}/.claudebbp/state"
mkdir -p "${HOME}/.claudebbp/reports"
mkdir -p "${HOME}/.claudebbp/recon"
echo "✓ State dirs: ~/.claudebbp/{state,reports,recon}"

echo ""
echo "Start hunting (CLI mode):"
echo "  python claudebbp.py /recon target.com"
echo "  python claudebbp.py /hunt target.com"
echo "  python claudebbp.py /validate target.com"
echo "  python claudebbp.py /report target.com"
echo ""
echo "Or in Claude Code (slash-command mode):"
echo "  /recon target.com"
echo "  /hunt target.com"
echo "  /validate"
echo "  /report"
