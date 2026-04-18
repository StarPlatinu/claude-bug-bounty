# claudebbp — Bug Bounty Scanner

AI-powered recon and vulnerability scanner. Automates subdomain discovery, live host detection, URL crawling, nuclei scanning, and vuln hunting. Results are displayed in a web dashboard — you review findings and submit manually to the bounty platform.

---

## Requirements

- Python 3.8+
- Go 1.21+ (for scanning tools)
- [Claude Code](https://claude.ai/claude-code) (optional — for AI-driven mode)

---

## Install

**1. Clone the repo**

```bash
git clone https://github.com/StarPlatinu/claude-bug-bounty.git
cd claude-bug-bounty
```

**2. Install scanning tools** (subfinder, httpx, nuclei, katana, dalfox, etc.)

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

Or install manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/hahwul/dalfox/v2@latest
```

**3. Install Python dependencies and skills**

```bash
chmod +x install.sh && ./install.sh
```

---

## Usage

### Option A — Web Dashboard (recommended)

Start the dashboard, then add targets and scan from the browser:

```bash
./start_ui.sh
# Open http://localhost:8080
```

- **Add a target** in the left sidebar (e.g. `example.com`)
- Click **▶ Scan** to run full recon + vuln hunt
- View results in **Recon** tab (subdomains, live hosts, URLs, nuclei hits) and **Vulnerabilities** tab (findings with description, steps, PoC, remediation)
- Stream live output in the **Terminal** tab

---

### Option B — CLI

Run any command directly from the terminal:

```bash
python3 claudebbp.py /recon target.com
python3 claudebbp.py /hunt target.com
python3 claudebbp.py /validate
python3 claudebbp.py /surface target.com
python3 claudebbp.py /intel target.com
```

Focus on a specific vulnerability class:

```bash
python3 claudebbp.py /hunt target.com --vuln-class ssrf
python3 claudebbp.py /hunt target.com --vuln-class idor
python3 claudebbp.py /hunt target.com --vuln-class xss
python3 claudebbp.py /hunt target.com --vuln-class oauth
```

Autopilot — runs the full loop automatically:

```bash
python3 claudebbp.py /autopilot target.com --mode normal    # confirms before each step
python3 claudebbp.py /autopilot target.com --mode paranoid  # confirms every action
```

---

### Option C — Claude Code (AI-driven)

```bash
claude   # open Claude Code in the project folder
```

Then use slash commands directly in the chat:

```
/recon target.com
/hunt target.com
/validate
/surface target.com
/intel target.com
/chain
/scope <asset>
/pickup target.com
/web3-audit contracts/Vault.sol
/token-scan 0xAbCd...
```

---

## Commands Reference

| Command | What it does |
|---|---|
| `/recon target.com` | Subdomain enum → live hosts → URL crawl → nuclei scan |
| `/hunt target.com` | Vuln checks (IDOR, XSS, SSRF, SQLi, OAuth, CVE…) |
| `/validate` | 7-Question Gate — scores 0–11, threshold 7 to submit |
| `/surface target.com` | Ranked attack surface from recon data |
| `/intel target.com` | CVEs + disclosed HackerOne reports for target |
| `/chain` | Find A→B→C exploit chains (17 patterns) |
| `/triage` | Quick go/no-go check before hunting deeper |
| `/scope <asset>` | Verify asset is in scope before testing |
| `/pickup target.com` | Resume previous hunt — history + untested endpoints |
| `/autopilot target.com` | Full autonomous loop (recon → hunt → validate) |
| `/remember` | Log finding to persistent hunt journal |
| `/web3-audit <file.sol>` | Slither + Mythril + pattern scan on Solidity contract |
| `/token-scan <contract>` | Rug-pull and honeypot detection (EVM + Solana) |

---

## State & Data

All findings and recon data are saved to:

```
~/.claudebbp/state/<target>.json
```

Every command shares the same state — recon data from `/recon` is available to `/hunt`, and findings persist between sessions.

---

## Optional API Keys

Better subdomain coverage with these free keys:

```bash
export CHAOS_API_KEY="your-key"          # chaos.projectdiscovery.io
export VIRUSTOTAL_API_KEY="your-key"     # virustotal.com
export SECURITYTRAILS_API_KEY="your-key" # securitytrails.com
```

Add to `~/.zshrc` or `~/.bashrc` to persist.

---

**For authorized security testing only.** Only test targets within an approved bug bounty program scope.
