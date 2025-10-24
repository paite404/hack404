# hack404
HACK404: Advanced automated penetration testing framework. Complete security assessments from reconnaissance to reporting. Features evasion payloads, multi-format exploits, automated scanning, and professional reports. All-in-one tool for ethical hackers and security professionals

# Files that should NOT be committed to version control

# =====================
# SCAN RESULTS & OUTPUT
# =====================
# Auto-generated scan directories
hack404_scan_*/
scans/
results/
output/
reports/auto_generated/

# =============
# PAYLOADS & BINARIES
# =============
# Generated payloads
payloads/*.exe
payloads/*.elf
payloads/*.dll
payloads/*.bin
payloads/*.war
payloads/*.hta
payloads/*.vbs

# =============
# SENSITIVE DATA
# =============
# Credentials and findings
*_creds.txt
*_passwords.txt
*_findings.txt
loot/
exploits/credentials/
*.key
*.pem
*.p12
*.pfx

# =============
# METASPLOIT FILES
# =============
# Metasploit database and logs
.msf4/
*.msf
*.rc
metasploit.log

# =============
# SYSTEM & EDITOR FILES
# =============
# OS files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Editor files
*.swp
*.swo
*~
.vscode/
.idea/
*.sublime-*

# =============
# LOGS & TEMP FILES
# =============
*.log
logs/
temp/
tmp/
*.tmp
*.temp

# =============
# BACKUP FILES
# =============
*.bak
*.backup
*.old
*.orig

# =============
# DOCUMENTATION
# =============
# Auto-generated docs
docs/_build/
*.pdf

# =============
# PYTHON
# =============
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
env.bak/
venv.bak/

# =============
# SHELL & SCRIPT FILES
# =============
# Script outputs and sessions
*.out
*.session
*.history

# =============
# CONFIGURATION OVERRIDES
# =============
# Local configuration overrides
config.local.ini
settings.local.py
.local.env
.env.local

# =============
# LARGE FILES
# =============
# Wordlists and large data files
wordlists/custom/
*.large
*.huge

# =============
# TEST & DEVELOPMENT
# =============
# Test results and coverage
.coverage
.pytest_cache/
test_results/
