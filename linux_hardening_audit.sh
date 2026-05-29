#!/usr/bin/env bash
# Linux Hardening Audit Script
# Checks common security misconfigurations on Linux systems
# Usage: sudo bash linux_hardening_audit.sh [--json]

set -euo pipefail

JSON_MODE=false
[[ "${1:-}" == "--json" ]] && JSON_MODE=true

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

declare -a JSON_RESULTS=()

log() {
    local status="$1" label="$2" detail="$3"
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"status\":\"$status\",\"check\":\"$label\",\"detail\":\"$detail\"}")
    else
        case "$status" in
            PASS) echo -e "${GREEN}[PASS]${NC} $label — $detail" ; ((PASS++)) ;;
            WARN) echo -e "${YELLOW}[WARN]${NC} $label — $detail" ; ((WARN++)) ;;
            FAIL) echo -e "${RED}[FAIL]${NC} $label — $detail" ; ((FAIL++)) ;;
        esac
    fi
    [[ "$status" == "PASS" ]] && ((PASS++)) || true
    [[ "$status" == "WARN" ]] && ((WARN++)) || true
    [[ "$status" == "FAIL" ]] && ((FAIL++)) || true
}

require_root() {
    [[ "$EUID" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }
}

# --- SSH Configuration ---
check_ssh() {
    local sshd_conf="/etc/ssh/sshd_config"
    [[ -f "$sshd_conf" ]] || { log WARN "SSH" "sshd_config not found — SSH may not be installed"; return; }

    local val
    val=$(grep -Ei '^\s*PermitRootLogin\s+' "$sshd_conf" | awk '{print tolower($2)}' | tail -1)
    [[ "$val" == "no" || "$val" == "prohibit-password" ]] \
        && log PASS "SSH PermitRootLogin" "$val" \
        || log FAIL "SSH PermitRootLogin" "set to '${val:-unset}' (should be no or prohibit-password)"

    val=$(grep -Ei '^\s*PasswordAuthentication\s+' "$sshd_conf" | awk '{print tolower($2)}' | tail -1)
    [[ "$val" == "no" ]] \
        && log PASS "SSH PasswordAuthentication" "disabled" \
        || log WARN "SSH PasswordAuthentication" "enabled — prefer key-based auth"

    val=$(grep -Ei '^\s*Protocol\s+' "$sshd_conf" | awk '{print $2}' | tail -1)
    [[ -z "$val" || "$val" == "2" ]] \
        && log PASS "SSH Protocol" "Protocol 2 (default)" \
        || log FAIL "SSH Protocol" "set to $val — must be 2"

    val=$(grep -Ei '^\s*X11Forwarding\s+' "$sshd_conf" | awk '{print tolower($2)}' | tail -1)
    [[ "$val" == "no" || -z "$val" ]] \
        && log PASS "SSH X11Forwarding" "disabled" \
        || log WARN "SSH X11Forwarding" "enabled — disable unless required"

    val=$(grep -Ei '^\s*MaxAuthTries\s+' "$sshd_conf" | awk '{print $2}' | tail -1)
    if [[ -n "$val" && "$val" -le 4 ]]; then
        log PASS "SSH MaxAuthTries" "$val"
    else
        log WARN "SSH MaxAuthTries" "${val:-unset} — recommend <= 4"
    fi
}

# --- Firewall ---
check_firewall() {
    if command -v ufw &>/dev/null; then
        local status
        status=$(ufw status 2>/dev/null | head -1 | awk '{print tolower($2)}')
        [[ "$status" == "active" ]] \
            && log PASS "Firewall (UFW)" "active" \
            || log FAIL "Firewall (UFW)" "inactive — run: ufw enable"
    elif command -v firewall-cmd &>/dev/null; then
        local state
        state=$(firewall-cmd --state 2>/dev/null || echo "not running")
        [[ "$state" == "running" ]] \
            && log PASS "Firewall (firewalld)" "running" \
            || log FAIL "Firewall (firewalld)" "not running"
    elif command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo 0)
        [[ "$rules" -gt 0 ]] \
            && log PASS "Firewall (iptables)" "$rules INPUT rules defined" \
            || log WARN "Firewall (iptables)" "no INPUT rules found"
    else
        log WARN "Firewall" "no known firewall tool found (ufw/firewalld/iptables)"
    fi
}

# --- Automatic Updates ---
check_auto_updates() {
    if dpkg -l unattended-upgrades &>/dev/null 2>&1; then
        local enabled
        enabled=$(grep -r '^\s*"${distro_id}:${distro_codename}"' /etc/apt/apt.conf.d/ 2>/dev/null | wc -l)
        [[ "$enabled" -gt 0 ]] \
            && log PASS "Unattended Upgrades" "configured" \
            || log WARN "Unattended Upgrades" "package installed but not configured"
    elif command -v dnf &>/dev/null && dnf info dnf-automatic &>/dev/null 2>&1; then
        log WARN "Auto Updates (dnf-automatic)" "check if timer is enabled: systemctl is-enabled dnf-automatic.timer"
    else
        log WARN "Automatic Updates" "unattended-upgrades not installed"
    fi
}

# --- Accounts with Empty Passwords ---
check_empty_passwords() {
    local empty
    empty=$(awk -F: '($2 == "" || $2 == "!!" ) {print $1}' /etc/shadow 2>/dev/null || echo "")
    [[ -z "$empty" ]] \
        && log PASS "Empty Passwords" "none found" \
        || log FAIL "Empty Passwords" "accounts with no password: $empty"
}

# --- SUID/SGID Binaries (unexpected) ---
check_suid() {
    local known_suid=("/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/newgrp"
                      "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/gpasswd" "/usr/bin/pkexec"
                      "/usr/bin/mount" "/usr/bin/umount" "/usr/sbin/unix_chkpwd"
                      "/bin/su" "/bin/mount" "/bin/umount" "/bin/ping")
    local found unexpected=0
    mapfile -t found < <(find / -xdev -perm /6000 -type f 2>/dev/null)
    for f in "${found[@]}"; do
        local is_known=false
        for k in "${known_suid[@]}"; do [[ "$f" == "$k" ]] && is_known=true && break; done
        $is_known || { log WARN "Unexpected SUID/SGID" "$f"; ((unexpected++)); }
    done
    [[ "$unexpected" -eq 0 ]] && log PASS "SUID/SGID Binaries" "no unexpected binaries found"
}

# --- World-Writable Files outside /tmp /proc /sys ---
check_world_writable() {
    local count
    count=$(find / -xdev -type f -perm -o+w \
        ! -path "/tmp/*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" \
        2>/dev/null | wc -l)
    [[ "$count" -eq 0 ]] \
        && log PASS "World-Writable Files" "none found outside /tmp /proc /sys" \
        || log WARN "World-Writable Files" "$count file(s) found — run: find / -xdev -type f -perm -o+w"
}

# --- Core Dumps ---
check_core_dumps() {
    local limit
    limit=$(ulimit -c 2>/dev/null)
    [[ "$limit" == "0" ]] \
        && log PASS "Core Dumps" "disabled" \
        || log WARN "Core Dumps" "limit is '$limit' — disable with: echo '* hard core 0' >> /etc/security/limits.conf"
}

# --- /tmp Mounted noexec ---
check_tmp_noexec() {
    local opts
    opts=$(findmnt -no OPTIONS /tmp 2>/dev/null || echo "")
    if echo "$opts" | grep -q "noexec"; then
        log PASS "/tmp noexec" "mount option set"
    else
        log WARN "/tmp noexec" "not set — add noexec to /tmp mount options"
    fi
}

# --- Sudo Logging ---
check_sudo_log() {
    if grep -rq 'log_input\|log_output\|logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log PASS "Sudo Logging" "configured"
    else
        log WARN "Sudo Logging" "no log_input/log_output in sudoers — add: Defaults logfile=/var/log/sudo.log"
    fi
}

# --- Failed Login Attempts ---
check_login_failures() {
    if command -v lastb &>/dev/null; then
        local fails
        fails=$(lastb -n 20 2>/dev/null | grep -v "^btmp\|^$" | wc -l)
        [[ "$fails" -lt 10 ]] \
            && log PASS "Recent Failed Logins" "$fails in last 20 attempts" \
            || log WARN "Recent Failed Logins" "$fails in last 20 — possible brute-force"
    else
        log WARN "Failed Logins" "lastb not available"
    fi
}

# --- Listening Services ---
check_listening_ports() {
    if command -v ss &>/dev/null; then
        local count
        count=$(ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0)
        if [[ "$count" -le 10 ]]; then
            log PASS "Listening Ports" "$count open (run: ss -tlnp)"
        else
            log WARN "Listening Ports" "$count open — review with: ss -tlnp"
        fi
    fi
}

# --- Main ---
require_root

if ! $JSON_MODE; then
    echo "======================================"
    echo " Linux Hardening Audit"
    echo " Host: $(hostname)  Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "======================================"
    echo
fi

check_ssh
check_firewall
check_auto_updates
check_empty_passwords
check_suid
check_world_writable
check_core_dumps
check_tmp_noexec
check_sudo_log
check_login_failures
check_listening_ports

if $JSON_MODE; then
    echo "{"
    echo "  \"host\": \"$(hostname)\","
    echo "  \"date\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
    echo "  \"summary\": {\"pass\": $PASS, \"warn\": $WARN, \"fail\": $FAIL},"
    echo "  \"results\": ["
    local IFS=','
    echo "    $(IFS=','; echo "${JSON_RESULTS[*]}")"
    echo "  ]"
    echo "}"
else
    echo
    echo "======================================"
    echo -e " PASS: ${GREEN}$PASS${NC}  WARN: ${YELLOW}$WARN${NC}  FAIL: ${RED}$FAIL${NC}"
    echo "======================================"
fi
