#!/usr/bin/env bash
#
#  antivirus.sh — all-in-one security scanner & hardening tool for Linux servers
#
#  Website : https://antivirus.sh
#  Source  : https://github.com/TARGET_PLEVEHOLDER/antivirus.sh
#  License : MIT
#
#  Quick start:
#      curl -fsSL https://antivirus.sh/antivirus.sh -o antivirus.sh
#      sudo bash antivirus.sh
#
#  What it does:
#    * scans files and processes for malware, rootkits, miners and backdoors
#    * audits network security: open ports, firewall, connections, DNS
#    * audits system security: SSH, accounts, permissions, kernel, updates
#    * fixes problems interactively, automatically (--fix) or hardens a
#      fresh VM end-to-end (--harden), with backups and full rollback
#
#  Designed for Ubuntu (every supported and most unsupported releases).
#  Works in best-effort mode on Debian, RHEL/CentOS/Alma/Rocky, Fedora,
#  Arch, openSUSE and other systemd or sysvinit distributions.
#
VERSION="1.1.0"

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
export LC_ALL=C LANG=C
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
umask 077

if [ -z "${BASH_VERSION:-}" ]; then
    echo "antivirus.sh must be run with bash, not sh." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    case " $* " in
        *" --help "*|*" -h "*|*" --version "*) : ;;
        *)
            echo "antivirus.sh supports Linux only (detected: $(uname -s))." >&2
            exit 1 ;;
    esac
fi

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
MODE=""                  # interactive | audit | fix | harden
SCOPE_SYSTEM=0
SCOPE_NETWORK=0
SCOPE_MALWARE=0
SCOPE_ALL=1
QUICK=0
FULL=0
ASSUME_YES=0
NO_COLOR=0
NO_EXTERNAL=0
DO_CREATE_USER=0
DO_INSTALL_TOOLS=0
DO_ROLLBACK=0
ROLLBACK_TS=""
REPORT_FILE=""
SCAN_PATHS=()
EXCLUDE_PATHS=()

N_OK=0; N_INFO=0; N_WARN=0; N_CRIT=0; N_FIXED=0; N_FAILEDFIX=0
RECOMMENDATIONS=()
IS_ROOT=0
INTERACTIVE_TTY=0
PKG=""                   # apt | dnf | yum | zypper | pacman | apk | none
APT_UPDATED=0
HAS_SYSTEMD=0
HAS_CONTAINERS=0
OS_PRETTY=""
SSHD_T=""
START_TS="$(date +%Y%m%d-%H%M%S)"

BASE_DIR="/var/lib/antivirus.sh"
LOG_DIR="/var/log/antivirus.sh"
BK_DIR=""                # set on first backup
QDIR=""

# Key issuance & one-time HTTPS delivery (see issue_and_deliver_key)
KEY_DELIVER=""           # key | archive  (empty = ask interactively)
KEY_TTL_MIN=10           # lifetime of the one-time download link, minutes
KEYWORK=""               # tmpfs workdir holding the private key until download
KEYFW_KIND=""            # ufw | firewalld — temporary rule to remove on exit
KEYFW_PORT=""
CREATED_USER=""
SSH_TEST_CMD=""

# Suspicious content patterns (reverse shells, droppers, miners, backdoors)
SUS_ERE='(/dev/tcp/|/dev/udp/|bash -i[[:space:]>]|sh -i[[:space:]>]|nc(\.traditional|\.openbsd)?[[:space:]][^|;]*-e[[:space:]]|ncat[[:space:]][^|;]*(-e[[:space:]]|--exec)|socat[[:space:]][^|;]*exec:|base64[[:space:]]+(-d|--decode)[^|;]*\|[[:space:]]*(ba|da|z)?sh|curl[^|;]*\|[[:space:]]*(ba|da|z)?sh|wget[^|;]*\|[[:space:]]*(ba|da|z)?sh|wget[^|;]*-O-[^|;]*\|[[:space:]]*sh|eval.*base64|stratum\+tcp|stratum\+ssl|xmrig|minerd|kdevtmpfsi|kinsing|kerberods|watchdogs|minexmr|supportxmr|nanopool\.org|moneroocean|c3pool|chmod[[:space:]]+\+?[0-7]*x?[[:space:]]+/tmp/|/dev/shm/[^[:space:]]*\.(sh|py|pl|elf|bin)|python[23]?[[:space:]]+-c[[:space:]].{0,40}socket|perl[[:space:]]+-e[[:space:]].{0,40}socket|exec[[:space:]]+[0-9]+<>/dev/tcp|LD_PRELOAD=)'

# Known malicious / miner process names
BAD_PROC_ERE='^(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|kerberods|watchdogs|ddgs|qW3xT|2t3ik|sysrv|sysrv012|tsm32|tsm64|kthreaddi|dbused|networkservice|sysupdate|sysguard|solrd|orgfs|pamdicks)$'

# Suspicious kernel modules (known rootkits)
BAD_KMOD_ERE='(diamorphine|reptile|suterusu|rootkit|adore|enyelkm|kbeast|wkmr|sysemptyrect)'

# Whitelisted SUID/SGID basenames (standard on Ubuntu/Debian/RHEL families)
SUID_WHITELIST=" sudo su passwd chsh chfn gpasswd newgrp newuidmap newgidmap mount umount fusermount fusermount3 pkexec ssh-keysign ping ping6 crontab at expiry chage mtr-packet ntfs-3g pppd exim4 dmcrypt-get-device snap-confine vmware-user-suid-wrapper Xorg Xorg.wrap sudoedit doas polkit-agent-helper-1 dbus-daemon-launch-helper traceroute6.iputils unix_chkpwd unix2_chkpwd pam_extrausers_chkpwd ssh-agent wall write write.ul bwrap mail-lock mail-unlock mail-touchlock dotlockfile utempter uuidd locate plocate chrome-sandbox lxc-user-nic mount.cifs mount.nfs umount.nfs umount.nfs4 mount.nfs4 cgexec procmail screen sg X postdrop postqueue timedc fdmount kismet_capture authopen "

# Ports that deserve attention when exposed to the world
declare -A RISKY_PORTS=(
    [21]="FTP (cleartext credentials)"
    [23]="Telnet (cleartext, must never be exposed)"
    [25]="SMTP (verify it is not an open relay)"
    [69]="TFTP (no authentication)"
    [111]="rpcbind (amplification & info leak)"
    [135]="MS-RPC"
    [137]="NetBIOS"
    [138]="NetBIOS"
    [139]="NetBIOS/SMB"
    [445]="SMB"
    [512]="rexec (legacy, insecure)"
    [513]="rlogin (legacy, insecure)"
    [514]="rsh/syslog (legacy, insecure)"
    [873]="rsync daemon (often unauthenticated)"
    [1433]="MS SQL Server"
    [1521]="Oracle DB"
    [2049]="NFS"
    [2375]="Docker API WITHOUT TLS (instant root for anyone!)"
    [2376]="Docker API (verify TLS client auth)"
    [3306]="MySQL/MariaDB"
    [3389]="RDP"
    [5432]="PostgreSQL"
    [5900]="VNC"
    [5901]="VNC"
    [6379]="Redis (unauthenticated by default!)"
    [9200]="Elasticsearch (unauthenticated by default)"
    [11211]="memcached (amplification attacks)"
    [27017]="MongoDB (verify authentication)"
)

# Outbound ports typical for mining pools / IRC botnets
MINER_PORTS_ERE='^(3333|3334|3335|4444|5555|7777|14444|14433|45700|6667|6697)$'

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
setup_colors() {
    if [[ "$NO_COLOR" == 1 || ! -t 1 ]]; then
        C_R="" ; C_G="" ; C_Y="" ; C_B="" ; C_C="" ; C_M="" ; C_W="" ; C_0="" ; C_DIM=""
    else
        C_R=$'\033[1;31m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_B=$'\033[1;34m'
        C_C=$'\033[1;36m'; C_M=$'\033[1;35m'; C_W=$'\033[1;37m'; C_0=$'\033[0m'
        C_DIM=$'\033[2m'
    fi
}

out() {
    # print to terminal and append color-stripped copy to the report file
    printf '%s\n' "$1"
    if [[ -n "$REPORT_FILE" ]]; then
        printf '%s\n' "$1" | sed -e 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE" 2>/dev/null
    fi
}

hdr()   { out ""; out "${C_B}==>${C_0} ${C_W}$1${C_0}"; }
ok()    { N_OK=$((N_OK+1));     out "  ${C_G}[ OK ]${C_0} $1"; }
info()  { N_INFO=$((N_INFO+1)); out "  ${C_C}[INFO]${C_0} $1"; }
warn()  { N_WARN=$((N_WARN+1)); out "  ${C_Y}[WARN]${C_0} $1"; }
crit()  { N_CRIT=$((N_CRIT+1)); out "  ${C_R}[CRIT]${C_0} $1"; }
fixed() { N_FIXED=$((N_FIXED+1)); out "  ${C_G}[FIX ]${C_0} $1"; }
note()  { out "         ${C_DIM}$1${C_0}"; }

reco() {
    local r="$1" e
    for e in "${RECOMMENDATIONS[@]:-}"; do [[ "$e" == "$r" ]] && return 0; done
    RECOMMENDATIONS+=("$r")
    out "         ${C_M}-> recommendation:${C_0} $r"
}

ask() {
    # ask "question" [default y|n]; returns 0 = yes
    local q="$1" def="${2:-n}" ans hint
    [[ "$ASSUME_YES" == 1 ]] && return 0
    if [[ "$INTERACTIVE_TTY" != 1 ]]; then
        [[ "$def" == "y" ]] && return 0 || return 1
    fi
    [[ "$def" == "y" ]] && hint="[Y/n]" || hint="[y/N]"
    while true; do
        printf '  %s?%s %s %s ' "$C_Y" "$C_0" "$q" "$hint"
        if ! read -r ans </dev/tty; then echo; return 1; fi
        ans="$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')"
        case "$ans" in
            y|yes|d|da) return 0 ;;
            n|no)       return 1 ;;
            "")         [[ "$def" == "y" ]] && return 0 || return 1 ;;
            *)          echo "  please answer y or n" ;;
        esac
    done
}

offer_fix() {
    # offer_fix <crit|warn|info> <risky 0|1> <problem> <fix description> [fix_fn args...]
    local sev="$1" risky="$2" problem="$3" fixtext="$4"
    shift 4
    case "$sev" in
        crit) crit "$problem" ;;
        warn) warn "$problem" ;;
        info) info "$problem" ;;
    esac
    [[ $# -eq 0 ]] && return 0

    if [[ "$MODE" == "audit" ]]; then
        reco "$fixtext"
        return 0
    fi

    local do_it=0
    if [[ "$risky" == 1 ]]; then
        note "this fix can affect remote access — backups and safety checks are applied"
        if [[ "$INTERACTIVE_TTY" == 1 || "$ASSUME_YES" == 1 ]]; then
            if ask "RISKY fix: $fixtext — apply" n; then do_it=1; fi
        else
            reco "$fixtext (risky: re-run interactively or with --yes)"
            return 0
        fi
    else
        case "$MODE" in
            fix|harden) do_it=1 ;;
            interactive)
                if ask "Apply fix: $fixtext" y; then do_it=1; fi
                ;;
        esac
    fi

    if [[ "$do_it" == 1 ]]; then
        if "$@"; then
            fixed "$fixtext"
        else
            N_FAILEDFIX=$((N_FAILEDFIX+1))
            warn "fix FAILED: $fixtext"
        fi
    else
        reco "$fixtext"
    fi
}

# ---------------------------------------------------------------------------
# Platform detection, dirs, packages, services
# ---------------------------------------------------------------------------
detect_platform() {
    [[ "$(id -u)" == 0 ]] && IS_ROOT=1
    if [[ -t 1 && -r /dev/tty ]]; then INTERACTIVE_TTY=1; fi

    if [[ -r /etc/os-release ]]; then
        OS_PRETTY="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$NAME}")"
    else
        OS_PRETTY="$(uname -sr)"
    fi

    if command -v apt-get >/dev/null 2>&1; then PKG=apt
    elif command -v dnf >/dev/null 2>&1; then PKG=dnf
    elif command -v yum >/dev/null 2>&1; then PKG=yum
    elif command -v zypper >/dev/null 2>&1; then PKG=zypper
    elif command -v pacman >/dev/null 2>&1; then PKG=pacman
    elif command -v apk >/dev/null 2>&1; then PKG=apk
    else PKG=none
    fi

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        HAS_SYSTEMD=1
    fi

    if command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1 \
       || command -v kubelet >/dev/null 2>&1 || [[ -d /var/lib/docker ]]; then
        HAS_CONTAINERS=1
    fi
}

init_dirs() {
    if [[ "$IS_ROOT" != 1 ]]; then
        BASE_DIR="${HOME}/.antivirus.sh"
        LOG_DIR="${HOME}/.antivirus.sh/log"
    fi
    mkdir -p "$BASE_DIR" "$LOG_DIR" 2>/dev/null
    QDIR="$BASE_DIR/quarantine"
    BK_DIR="$BASE_DIR/backups/$START_TS"
    if [[ -z "$REPORT_FILE" ]]; then
        REPORT_FILE="$LOG_DIR/report-$START_TS.log"
    fi
    : > "$REPORT_FILE" 2>/dev/null || REPORT_FILE=""
}

pkg_refresh() {
    case "$PKG" in
        apt)
            [[ "$APT_UPDATED" == 1 ]] && return 0
            apt-get update -qq >/dev/null 2>&1 && APT_UPDATED=1
            ;;
        *) return 0 ;;
    esac
}

pkg_install() {
    [[ "$IS_ROOT" == 1 ]] || return 1
    case "$PKG" in
        apt)    pkg_refresh
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
        dnf)    dnf install -y -q "$@" >/dev/null 2>&1 ;;
        yum)    yum install -y -q "$@" >/dev/null 2>&1 ;;
        zypper) zypper --non-interactive install "$@" >/dev/null 2>&1 ;;
        pacman) pacman -S --noconfirm --needed "$@" >/dev/null 2>&1 ;;
        apk)    apk add -q "$@" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

pkg_installed() {
    case "$PKG" in
        apt)    dpkg -s "$1" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
        pacman) pacman -Qi "$1" >/dev/null 2>&1 ;;
        apk)    apk info -e "$1" >/dev/null 2>&1 ;;
        *)      command -v "$1" >/dev/null 2>&1 ;;
    esac
}

svc_enable_now() {
    local svc="$1"
    if [[ "$HAS_SYSTEMD" == 1 ]]; then
        systemctl enable "$svc" >/dev/null 2>&1
        systemctl restart "$svc" >/dev/null 2>&1 || systemctl start "$svc" >/dev/null 2>&1
    else
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d "$svc" defaults >/dev/null 2>&1
        command -v chkconfig  >/dev/null 2>&1 && chkconfig "$svc" on >/dev/null 2>&1
        service "$svc" restart >/dev/null 2>&1 || service "$svc" start >/dev/null 2>&1
    fi
}

svc_active() {
    if [[ "$HAS_SYSTEMD" == 1 ]]; then
        systemctl is-active --quiet "$1" 2>/dev/null
    else
        service "$1" status >/dev/null 2>&1
    fi
}

# ---------------------------------------------------------------------------
# Backup / rollback / quarantine
# ---------------------------------------------------------------------------
ensure_bk() {
    [[ -z "$BK_DIR" ]] && BK_DIR="$BASE_DIR/backups/$START_TS"
    mkdir -p "$BK_DIR"
}

backup_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    ensure_bk
    mkdir -p "$BK_DIR$(dirname "$f")"
    cp -a "$f" "$BK_DIR$f" 2>/dev/null
    grep -qxF "FILE $f" "$BK_DIR/MANIFEST" 2>/dev/null || echo "FILE $f" >> "$BK_DIR/MANIFEST"
}

record_new() {  # a file created by us; rollback will delete it
    ensure_bk
    echo "NEW $1" >> "$BK_DIR/MANIFEST"
}

record_undo() { # a command that reverses an action
    ensure_bk
    echo "CMD $*" >> "$BK_DIR/MANIFEST"
}

write_managed_file() {  # write_managed_file <path>  (content on stdin)
    local f="$1"
    if [[ -e "$f" ]]; then backup_file "$f"; else record_new "$f"; fi
    mkdir -p "$(dirname "$f")"
    cat > "$f"
}

do_rollback() {
    local ts="$ROLLBACK_TS" dir line f
    if [[ -z "$ts" ]]; then
        ts="$(ls -1 "$BASE_DIR/backups" 2>/dev/null | sort | tail -1)"
    fi
    dir="$BASE_DIR/backups/$ts"
    if [[ -z "$ts" || ! -f "$dir/MANIFEST" ]]; then
        echo "No backup found in $BASE_DIR/backups — nothing to roll back." >&2
        exit 1
    fi
    echo "Rolling back changes recorded in $dir ..."
    # restore files first, then undo commands
    while IFS= read -r line; do
        case "$line" in
            FILE\ *)
                f="${line#FILE }"
                if cp -a "$dir$f" "$f" 2>/dev/null; then
                    echo "  restored: $f"
                else
                    echo "  FAILED to restore: $f" >&2
                fi
                ;;
            NEW\ *)
                f="${line#NEW }"
                rm -f "$f" && echo "  removed:  $f"
                ;;
        esac
    done < "$dir/MANIFEST"
    while IFS= read -r line; do
        case "$line" in
            CMD\ *)
                echo "  undo: ${line#CMD }"
                eval "${line#CMD }" >/dev/null 2>&1
                ;;
        esac
    done < "$dir/MANIFEST"
    command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1
    if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then
        restart_ssh
        echo "  sshd config validated and reloaded"
    fi
    echo "Rollback complete."
    exit 0
}

quarantine_file() {
    local f="$1" dst
    [[ -e "$f" ]] || return 1
    mkdir -p "$QDIR"
    dst="$QDIR/$(date +%s)-$(basename "$f")"
    command -v chattr >/dev/null 2>&1 && chattr -i -a "$f" 2>/dev/null
    if mv -f "$f" "$dst" 2>/dev/null; then
        chmod 000 "$dst" 2>/dev/null
        echo "$(date '+%F %T')  $f  ->  $dst" >> "$QDIR/quarantine.log"
        note "quarantined to $dst (mv it back to restore)"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
load_sshd_config() {
    local bin
    bin="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
    SSHD_T=""
    if [[ -x "$bin" && "$IS_ROOT" == 1 ]]; then
        SSHD_T="$("$bin" -T 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    fi
    if [[ -z "$SSHD_T" && -r /etc/ssh/sshd_config ]]; then
        SSHD_T="$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
                  | grep -vE '^[[:space:]]*#' | grep -vE '^[[:space:]]*$' \
                  | tr '[:upper:]' '[:lower:]')"
    fi
}

sshd_opt() {  # sshd_opt <key-lowercase> <default>
    local v
    v="$(awk -v k="$1" '$1==k {print $2; exit}' <<<"$SSHD_T")"
    printf '%s' "${v:-$2}"
}

get_ssh_ports() {
    local ports=""
    [[ -n "$SSHD_T" ]] && ports="$(awk '$1=="port"{print $2}' <<<"$SSHD_T")"
    if command -v ss >/dev/null 2>&1; then
        ports="$ports
$(ss -tlnp 2>/dev/null | grep -E 'sshd' | awk '{print $4}' | sed 's/.*://')"
    fi
    [[ -n "${SSH_CONNECTION:-}" ]] && ports="$ports
${SSH_CONNECTION##* }"
    ports="$(printf '%s\n' "$ports" | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ')"
    [[ -z "${ports// }" ]] && ports="22"
    printf '%s' "$ports"
}

restart_ssh() {
    if [[ "$HAS_SYSTEMD" == 1 ]]; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    else
        service ssh restart >/dev/null 2>&1 || service sshd restart >/dev/null 2>&1
    fi
}

ssh_server_present() {
    [[ -f /etc/ssh/sshd_config ]] && command -v sshd >/dev/null 2>&1
}

# any sudo-capable human user with a non-empty authorized_keys?
keybased_admin_exists() {
    local g members u home
    for g in sudo wheel admin; do
        members="$(getent group "$g" 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')"
        for u in $members; do
            home="$(getent passwd "$u" | awk -F: '{print $6}')"
            [[ -s "$home/.ssh/authorized_keys" ]] && return 0
        done
    done
    return 1
}

current_user_has_key() {
    local u="${SUDO_USER:-$USER}" home
    home="$(getent passwd "$u" 2>/dev/null | awk -F: '{print $6}')"
    [[ -s "$home/.ssh/authorized_keys" ]]
}

# any successful key-based SSH login in the recent auth logs?
recent_pubkey_login() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -q --since "2 days ago" -t sshd -t ssh 2>/dev/null \
            | grep -q 'Accepted publickey' && return 0
    fi
    grep -qs 'Accepted publickey' /var/log/auth.log /var/log/secure && return 0
    return 1
}

# ---------------------------------------------------------------------------
# Key issuance & one-time HTTPS delivery
#
# Generates an ed25519 keypair for a user ON the server, installs the public
# half into authorized_keys and serves the private half exactly once over a
# self-expiring HTTPS link.  Secrets (key passphrase / archive password) are
# printed to this terminal only — two separate channels, so intercepting the
# link alone is useless.  The private key lives on tmpfs and is shredded on
# every exit path.
# ---------------------------------------------------------------------------
rand_str() {  # rand_str <len> [charset]
    LC_ALL=C tr -dc "${2:-A-Za-z0-9}" </dev/urandom | head -c "$1"
}

rand_pw() {   # passwords/passphrases: letters, digits, shell-safe symbols
    rand_str "$1" 'A-Za-z0-9_@%+='
}

ask_secret() {  # ask_secret <prompt> <minlen>  -> echoes the secret
    local s1 s2
    while true; do
        printf '  %s (min %s chars): ' "$1" "$2" >&2
        IFS= read -rs s1 </dev/tty; echo >&2
        if (( ${#s1} < $2 )); then echo "  too short, try again" >&2; continue; fi
        printf '  repeat: ' >&2
        IFS= read -rs s2 </dev/tty; echo >&2
        if [[ "$s1" != "$s2" ]]; then echo "  values do not match, try again" >&2; continue; fi
        printf '%s' "$s1"
        return 0
    done
}

key_cleanup() {
    if [[ -n "$KEYFW_KIND" ]]; then
        case "$KEYFW_KIND" in
            ufw)       ufw delete allow "$KEYFW_PORT/tcp" >/dev/null 2>&1 ;;
            firewalld) firewall-cmd --remove-port="$KEYFW_PORT/tcp" >/dev/null 2>&1 ;;
        esac
        KEYFW_KIND=""
    fi
    if [[ -n "$KEYWORK" && -d "$KEYWORK" ]]; then
        command -v shred >/dev/null 2>&1 \
            && find "$KEYWORK" -type f -exec shred -fu {} + 2>/dev/null
        rm -rf "$KEYWORK"
        KEYWORK=""
    fi
}

detect_public_host() {  # echoes the address clients should connect to
    local h=""
    # 3rd field of SSH_CONNECTION = the server address the admin connected to
    [[ -n "${SSH_CONNECTION:-}" ]] && h="$(awk '{print $3}' <<<"$SSH_CONNECTION")"
    if [[ -z "$h" ]] && command -v curl >/dev/null 2>&1; then
        h="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null)"
    fi
    if [[ -z "$h" ]]; then
        h="$(ip route get 1.1.1.1 2>/dev/null \
            | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
    fi
    [[ -n "$h" ]] || return 1
    printf '%s' "$h"
}

pick_free_port() {
    local _i p
    for _i in $(seq 1 50); do
        p=$(( (RANDOM % 20001) + 40000 ))
        ss -tln 2>/dev/null | grep -qE "[:.]$p([[:space:]]|$)" || { printf '%s' "$p"; return 0; }
    done
    return 1
}

key_make_cert() {  # key_make_cert <host>
    local host="$1" san
    if [[ "$host" =~ ^[0-9.]+$ || "$host" == *:* ]]; then
        san="subjectAltName=IP:$host"
    else
        san="subjectAltName=DNS:$host"
    fi
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$KEYWORK/tls.key" -out "$KEYWORK/tls.crt" \
        -subj "/CN=$host" -addext "$san" >/dev/null 2>&1 \
    || openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$KEYWORK/tls.key" -out "$KEYWORK/tls.crt" \
        -subj "/CN=$host" >/dev/null 2>&1
}

key_write_server() {
    cat > "$KEYWORK/server.py" <<'PYEOF'
import http.server, os, ssl, sys, threading

token  = os.environ["AV_TOKEN"]
fpath  = os.environ["AV_FILE"]
fname  = os.environ["AV_NAME"]
port   = int(os.environ["AV_PORT"])
ttl    = int(os.environ["AV_TTL"])
allow  = os.environ.get("AV_ALLOW", "")
cert   = os.environ["AV_CERT"]
keyf   = os.environ["AV_KEYF"]
logf   = os.environ["AV_LOG"]

state = {"served": False}
lock = threading.Lock()

def log(line):
    with lock:
        with open(logf, "a") as f:
            f.write(line + "\n")

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "antivirus.sh"
    sys_version = ""

    def log_message(self, fmt, *args):
        log("%s %s" % (self.client_address[0], fmt % args))

    def do_GET(self):
        ip = self.client_address[0]
        if allow and ip != allow:
            log("DENY (ip not allowed): %s" % ip)
            self.send_error(403)
            return
        if self.path != "/%s/%s" % (token, fname):
            log("DENY (bad path) from %s: %s" % (ip, self.path[:120]))
            self.send_error(404)
            return
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except OSError:
            self.send_error(410)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % fname)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        log("SERVED to %s" % ip)
        state["served"] = True
        threading.Thread(target=srv.shutdown, daemon=True).start()

srv = http.server.HTTPServer(("0.0.0.0", port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, keyf)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

timer = threading.Timer(ttl, srv.shutdown)
timer.daemon = True
timer.start()

try:
    srv.serve_forever()
except KeyboardInterrupt:
    pass
timer.cancel()
sys.exit(0 if state["served"] else 3)
PYEOF
}

serve_key_once() {  # serve_key_once <file> <name> <user> <key|archive>
    local file="$1" name="$2" uname="$3" deliver="$4"
    local host port token certfp lf url rc=0

    host="$(detect_public_host)" || { warn "cannot detect the public IP of this server"; return 1; }
    port="$(pick_free_port)"     || { warn "no free port for the download server"; return 1; }
    token="$(rand_str 32 'a-f0-9')"
    key_make_cert "$host"        || { warn "TLS certificate generation failed"; return 1; }
    certfp="$(openssl x509 -in "$KEYWORK/tls.crt" -noout -fingerprint -sha256 2>/dev/null \
              | sed 's/^.*Fingerprint=//')"
    key_write_server

    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$port/tcp" comment 'antivirus.sh key delivery' >/dev/null 2>&1 \
            && { KEYFW_KIND=ufw; KEYFW_PORT=$port; }
        note "ufw: port $port/tcp opened temporarily (auto-closed after delivery)"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --add-port="$port/tcp" >/dev/null 2>&1 \
            && { KEYFW_KIND=firewalld; KEYFW_PORT=$port; }
        note "firewalld: port $port/tcp opened temporarily (auto-closed after delivery)"
    fi

    lf="$LOG_DIR/key-delivery-$START_TS.log"
    : > "$lf" 2>/dev/null || lf="$KEYWORK/access.log"
    url="https://$host:$port/$token/$name"

    out ""
    out "  ${C_W}one-time download link (expires in $KEY_TTL_MIN min):${C_0}"
    out "    ${C_G}$url${C_0}"
    out "  TLS certificate SHA256 (verify before trusting the self-signed cert):"
    out "    ${C_C}$certfp${C_0}"
    out "  from your own device (chmod 600 is REQUIRED — ssh rejects keys with open permissions):"
    if [[ "$deliver" == "archive" ]]; then
        out "    curl -k -o $name '$url'"
        out "    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in $name -out keys.tar.gz"
        out "    tar xzf keys.tar.gz && rm keys.tar.gz $name && chmod 600 ${uname}_ed25519"
    else
        out "    curl -k -o $name '$url' && chmod 600 $name"
    fi
    out "  (downloaded with a browser instead? then run: chmod 600 ~/Downloads/$name)"
    info "waiting for the download (one-shot; Ctrl-C aborts and wipes the key)..."

    AV_TOKEN="$token" AV_FILE="$file" AV_NAME="$name" AV_PORT="$port" \
    AV_TTL="$(( KEY_TTL_MIN * 60 ))" AV_ALLOW="" AV_CERT="$KEYWORK/tls.crt" \
    AV_KEYF="$KEYWORK/tls.key" AV_LOG="$lf" python3 "$KEYWORK/server.py" || rc=$?

    SSH_TEST_CMD="ssh -i ${uname}_ed25519 ${uname}@${host}"
    case "$rc" in
        0)  fixed "private key downloaded — wiping it from this server now"
            note "on YOUR device run first: chmod 600 ${uname}_ed25519 (else ssh refuses the key)"
            note "access log: $lf"
            return 0 ;;
        3)  warn "link expired, nothing was downloaded — the private key is wiped"
            reco "issue a fresh key for '$uname': sudo bash $0 --create-user (or re-run this fix)"
            return 1 ;;
        *)  warn "download server exited unexpectedly (code $rc) — the private key is wiped"
            return 1 ;;
    esac
}

issue_and_deliver_key() {  # issue_and_deliver_key <username>
    local uname="$1" home keyname keyfile keypass keypass_shown=0 fp
    local deliver servefile servename archpass="" archpass_shown=0 rc

    command -v python3 >/dev/null 2>&1 \
        || { warn "python3 is required for HTTPS key delivery — paste a public key instead"; return 1; }
    home="$(getent passwd "$uname" | awk -F: '{print $6}')"
    [[ -n "$home" ]] || { warn "cannot determine home directory of '$uname'"; return 1; }

    # workdir on tmpfs so the private key never touches the disk
    KEYWORK="$(mktemp -d /dev/shm/antivirus-key.XXXXXX 2>/dev/null \
               || mktemp -d /tmp/antivirus-key.XXXXXX)" || return 1
    chmod 700 "$KEYWORK"
    keyname="${uname}_ed25519"
    keyfile="$KEYWORK/$keyname"

    if ask "generate a random passphrase for the private key (otherwise you type your own)" y; then
        keypass="$(rand_pw 24)"; keypass_shown=1
    else
        keypass="$(ask_secret "passphrase for the SSH key" 8)"
    fi

    if ! ssh-keygen -t ed25519 -a 100 -f "$keyfile" -N "$keypass" \
            -C "${uname}@$(hostname -s 2>/dev/null || echo vps)-$(date +%Y%m%d)" >/dev/null; then
        warn "ssh-keygen failed"
        key_cleanup
        return 1
    fi
    fp="$(ssh-keygen -lf "$keyfile.pub" 2>/dev/null | awk '{print $2}')"

    mkdir -p "$home/.ssh"
    cat "$keyfile.pub" >> "$home/.ssh/authorized_keys"
    chmod 700 "$home/.ssh"
    chmod 600 "$home/.ssh/authorized_keys"
    chown -R "$uname:$uname" "$home/.ssh"
    fixed "ed25519 public key installed for '$uname' (fingerprint: $fp)"

    deliver="$KEY_DELIVER"
    if [[ -z "$deliver" ]]; then
        if ask "wrap the key into an AES-256 encrypted archive (otherwise the raw key file is served)" n; then
            deliver=archive
        else
            deliver=key
        fi
    fi
    servefile="$keyfile"; servename="$keyname"
    if [[ "$deliver" == "archive" ]]; then
        if ask "generate a random archive password (otherwise you type your own)" y; then
            archpass="$(rand_pw 24)"; archpass_shown=1
        else
            archpass="$(ask_secret "archive password" 8)"
        fi
        servename="${uname}_keys.tar.gz.enc"
        servefile="$KEYWORK/$servename"
        if ! tar -C "$KEYWORK" -czf "$KEYWORK/payload.tar.gz" "$keyname" "$keyname.pub" \
           || ! AV_ARCH_PASS="$archpass" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
                    -in "$KEYWORK/payload.tar.gz" -out "$servefile" -pass env:AV_ARCH_PASS; then
            warn "archive encryption failed"
            key_cleanup
            return 1
        fi
        rm -f "$KEYWORK/payload.tar.gz"
    fi

    out ""
    out "  ${C_W}credentials — shown ONCE, stored nowhere on this server:${C_0}"
    [[ "$keypass_shown"  == 1 ]] && out "    key passphrase:   ${C_G}$keypass${C_0}"
    [[ "$archpass_shown" == 1 ]] && out "    archive password: ${C_G}$archpass${C_0}"
    out "    ${C_Y}save these in a password manager NOW${C_0}"

    serve_key_once "$servefile" "$servename" "$uname" "$deliver"
    rc=$?
    key_cleanup
    return $rc
}

offer_post_key_hardening() {  # called right after a key is installed & delivered
    local uname="$1"
    ssh_server_present || return 0
    out ""
    note "TEST the key login NOW from your own device, in a NEW terminal"
    note "(keep this session open!):  ${SSH_TEST_CMD:-ssh ${uname}@<server-ip>}"
    if ask "key login VERIFIED in a separate session — disable SSH root login and password auth now" n; then
        fix_ssh_disable_root      && fixed "PermitRootLogin no"
        fix_ssh_disable_passwords && fixed "PasswordAuthentication no"
        note "existing sessions are not dropped — keep this one until re-tested"
    else
        info "SSH lockdown postponed — verify the key login first"
        reco "after the key login works: sudo bash $0 --harden (it will offer key-only SSH)"
    fi
}

# ---------------------------------------------------------------------------
# Fix functions
# ---------------------------------------------------------------------------
fix_enable_firewall() {
    local p ports
    ports="$(get_ssh_ports)"
    if [[ "$PKG" == "apt" ]] || command -v ufw >/dev/null 2>&1; then
        command -v ufw >/dev/null 2>&1 || pkg_install ufw || return 1
        for p in $ports; do ufw allow "$p/tcp" >/dev/null 2>&1; done
        note "allowed SSH port(s) before enabling: $ports"
        ufw --force enable >/dev/null 2>&1 || return 1
        record_undo "ufw disable"
        return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 || [[ "$PKG" =~ ^(dnf|yum|zypper)$ ]]; then
        command -v firewall-cmd >/dev/null 2>&1 || pkg_install firewalld || return 1
        svc_enable_now firewalld
        for p in $ports; do firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1; done
        firewall-cmd --reload >/dev/null 2>&1
        record_undo "systemctl disable --now firewalld"
        return 0
    fi
    return 1
}

fix_install_fail2ban() {
    pkg_install fail2ban || return 1
    write_managed_file /etc/fail2ban/jail.d/antivirus-sh.local <<'EOF'
# created by antivirus.sh — https://antivirus.sh
[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
    svc_enable_now fail2ban
}

fix_auto_updates() {
    case "$PKG" in
        apt)
            pkg_install unattended-upgrades || return 1
            write_managed_file /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
            ;;
        dnf|yum)
            pkg_install dnf-automatic 2>/dev/null || pkg_install yum-cron || return 1
            svc_enable_now dnf-automatic.timer 2>/dev/null || svc_enable_now yum-cron
            ;;
        *) return 1 ;;
    esac
}

fix_apply_updates() {
    case "$PKG" in
        apt)
            pkg_refresh
            DEBIAN_FRONTEND=noninteractive apt-get -y -qq \
                -o Dpkg::Options::=--force-confdef \
                -o Dpkg::Options::=--force-confold upgrade >/dev/null 2>&1
            ;;
        dnf)    dnf upgrade -y -q >/dev/null 2>&1 ;;
        yum)    yum update -y -q >/dev/null 2>&1 ;;
        zypper) zypper --non-interactive update >/dev/null 2>&1 ;;
        pacman) pacman -Syu --noconfirm >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

fix_sysctl_hardening() {
    {
        cat <<'EOF'
# created by antivirus.sh — https://antivirus.sh
# Network hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
        if [[ "$HAS_CONTAINERS" != 1 ]]; then
            echo "net.ipv4.ip_forward = 0"
            echo "net.ipv6.conf.all.forwarding = 0"
        fi
    } | write_managed_file /etc/sysctl.d/99-antivirus-sh.conf
    if command -v sysctl >/dev/null 2>&1; then
        sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-antivirus-sh.conf >/dev/null 2>&1
    fi
    note "unknown-key warnings on very old kernels are harmless"
    return 0
}

_sshd_write_settings() {  # _sshd_write_settings <<< "Key value\nKey value..."
    local settings target key
    settings="$(cat)"
    backup_file /etc/ssh/sshd_config
    if [[ -d /etc/ssh/sshd_config.d ]] \
       && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config 2>/dev/null; then
        target=/etc/ssh/sshd_config.d/10-antivirus-sh.conf
        {
            echo "# created by antivirus.sh — https://antivirus.sh"
            [[ -f "$target" ]] && grep -v '^#' "$target"
            printf '%s\n' "$settings"
        } | awk '!seen[tolower($1)]++ || $1 ~ /^#/' | write_managed_file "$target"
    else
        # first-match wins in sshd_config: comment out old directives, then append
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            key="${line%% *}"
            sed -ri "s/^[[:space:]]*(${key})([[:space:]])/#antivirus.sh# \1\2/I" /etc/ssh/sshd_config
        done <<< "$settings"
        {
            echo ""
            echo "# --- added by antivirus.sh — https://antivirus.sh ---"
            printf '%s\n' "$settings"
        } >> /etc/ssh/sshd_config
    fi
    if sshd -t >/dev/null 2>&1; then
        restart_ssh
        note "sshd config validated; existing SSH sessions are NOT dropped"
        return 0
    fi
    # invalid config -> restore and abort
    [[ -n "$BK_DIR" && -f "$BK_DIR/etc/ssh/sshd_config" ]] && cp -a "$BK_DIR/etc/ssh/sshd_config" /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/10-antivirus-sh.conf 2>/dev/null
    warn "new sshd config failed validation — change reverted, sshd untouched"
    return 1
}

fix_ssh_safe_harden() {
    _sshd_write_settings <<'EOF'
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
EOF
}

fix_ssh_disable_passwords() {
    # dead-end removal: instead of a flat refusal, offer to create the missing
    # key-based sudo user right here (interactive sessions only)
    if ! keybased_admin_exists && ! current_user_has_key; then
        if [[ "$INTERACTIVE_TTY" == 1 && "$IS_ROOT" == 1 ]] \
           && ask "no user has an SSH key yet — create a sudo user with a key now (one-time download link)" y; then
            local SKIP_POST_KEY_OFFER=1
            run_create_user
        fi
        if ! keybased_admin_exists && ! current_user_has_key; then
            warn "refused: no sudo-capable user has an SSH key — you would lock yourself out"
            reco "add your public key to ~/.ssh/authorized_keys (or run --create-user), then re-run"
            return 1
        fi
    fi
    # second gate: a key in authorized_keys is not proof it works — look for a
    # real successful key login before cutting off password access
    if [[ "$INTERACTIVE_TTY" == 1 && "$ASSUME_YES" != 1 ]] && ! recent_pubkey_login; then
        warn "auth logs show NO successful key-based login yet"
        note "test from your device first: ${SSH_TEST_CMD:-ssh -i <keyfile> <user>@<server-ip>}"
        if ! ask "key login NOT verified — disable password authentication anyway" n; then
            reco "verify the key login from your device, then re-run this fix"
            return 1
        fi
    fi
    _sshd_write_settings <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
}

fix_ssh_disable_root() {
    if ! keybased_admin_exists; then
        if [[ "$INTERACTIVE_TTY" == 1 && "$IS_ROOT" == 1 ]] \
           && ask "no sudo user with an SSH key exists — create one now (one-time download link)" y; then
            local SKIP_POST_KEY_OFFER=1
            run_create_user
        fi
        if ! keybased_admin_exists; then
            warn "refused: no sudo-capable user with an SSH key exists — create one first (--create-user)"
            return 1
        fi
    fi
    _sshd_write_settings <<'EOF'
PermitRootLogin no
EOF
}

fix_create_admin_user() {
    # full guided flow: user + key + one-time HTTPS delivery; afterwards
    # run_create_user itself offers root/password lockdown behind the
    # "key login verified" gate
    run_create_user || return 1
    load_sshd_config   # the flow above may have changed sshd settings
    keybased_admin_exists
}

fix_perms_critical() {
    _perm() {  # _perm <path> <mode> [owner:group]
        [[ -e "$1" ]] || return 0
        backup_file "$1"
        chmod "$2" "$1" 2>/dev/null
        [[ -n "${3:-}" ]] && chown "$3" "$1" 2>/dev/null
        return 0
    }
    _perm /etc/passwd        644 root:root
    _perm /etc/group         644 root:root
    _perm /etc/shadow        640
    _perm /etc/gshadow       640
    _perm /etc/sudoers       440 root:root
    _perm /etc/crontab       600 root:root
    _perm /etc/ssh/sshd_config 600 root:root
    _perm /root              700
    _perm /boot/grub/grub.cfg  600 root:root
    _perm /boot/grub2/grub.cfg 600 root:root
    local k
    for k in /etc/ssh/ssh_host_*_key; do
        [[ -e "$k" ]] && _perm "$k" 600
    done
    return 0
}

FIX_WW_LIST=""
fix_world_writable_files() {
    local f n=0
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        chmod o-w "$f" 2>/dev/null && n=$((n+1))
    done <<< "$FIX_WW_LIST"
    note "removed world-write bit from $n file(s)"
    return 0
}

FIX_STICKY_LIST=""
fix_sticky_dirs() {
    local d n=0
    while IFS= read -r d; do
        [[ -d "$d" ]] || continue
        chmod +t "$d" 2>/dev/null && n=$((n+1))
    done <<< "$FIX_STICKY_LIST"
    note "added sticky bit to $n world-writable dir(s)"
    return 0
}

fix_lock_user() {
    passwd -l "$1" >/dev/null 2>&1 && record_undo "passwd -u $1"
}

fix_install_pkg() {     # generic: fix_install_pkg <pkg> [service-to-enable]
    pkg_install "$1" || return 1
    [[ -n "${2:-}" ]] && svc_enable_now "$2"
    return 0
}

fix_enable_ntp() {
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true 2>/dev/null && return 0
    fi
    pkg_install chrony 2>/dev/null && svc_enable_now chronyd 2>/dev/null && return 0
    pkg_install ntp 2>/dev/null && svc_enable_now ntp 2>/dev/null
}

fix_login_defs() {
    backup_file /etc/login.defs
    _ldef() {
        if grep -qE "^[#[:space:]]*$1\b" /etc/login.defs; then
            sed -ri "s/^[#[:space:]]*($1)[[:space:]].*/\1\t$2/" /etc/login.defs
        else
            echo -e "$1\t$2" >> /etc/login.defs
        fi
    }
    _ldef PASS_MAX_DAYS 365
    _ldef PASS_MIN_DAYS 1
    _ldef PASS_WARN_AGE 14
    _ldef UMASK 027
    return 0
}

fix_pwquality() {
    case "$PKG" in
        apt) pkg_install libpam-pwquality || return 1 ;;
        dnf|yum) pkg_install libpwquality || return 1 ;;
        *) return 1 ;;
    esac
    if [[ -f /etc/security/pwquality.conf ]]; then
        backup_file /etc/security/pwquality.conf
        sed -ri 's/^[#[:space:]]*minlen[[:space:]]*=.*/minlen = 12/'     /etc/security/pwquality.conf
        sed -ri 's/^[#[:space:]]*minclass[[:space:]]*=.*/minclass = 3/' /etc/security/pwquality.conf
        grep -qE '^minlen'   /etc/security/pwquality.conf || echo 'minlen = 12'  >> /etc/security/pwquality.conf
        grep -qE '^minclass' /etc/security/pwquality.conf || echo 'minclass = 3' >> /etc/security/pwquality.conf
    fi
    return 0
}

fix_secure_shm() {
    backup_file /etc/fstab
    if grep -qE '^[^#]*[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
        sed -ri 's%^([^#]*[[:space:]]/dev/shm[[:space:]]+tmpfs[[:space:]]+)[^[:space:]]+%\1defaults,noexec,nosuid,nodev%' /etc/fstab
    else
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi
    mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null
    return 0
}

fix_core_dumps() {
    write_managed_file /etc/security/limits.d/99-antivirus-sh.conf <<'EOF'
# created by antivirus.sh — disable core dumps
* hard core 0
* soft core 0
EOF
    command -v sysctl >/dev/null 2>&1 && sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1
    return 0
}

fix_journald_persistent() {
    mkdir -p /var/log/journal 2>/dev/null
    command -v systemd-tmpfiles >/dev/null 2>&1 && systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
    systemctl restart systemd-journald >/dev/null 2>&1
    return 0
}

fix_login_banner() {
    backup_file /etc/issue.net
    cat > /etc/issue.net <<'EOF'
*****************************************************************
*  Authorized access only. All activity is monitored and logged. *
*****************************************************************
EOF
    return 0
}

fix_tmout() {
    write_managed_file /etc/profile.d/99-antivirus-sh-tmout.sh <<'EOF'
# created by antivirus.sh — auto-logout idle shells after 15 minutes
TMOUT=900
readonly TMOUT 2>/dev/null
export TMOUT
EOF
    return 0
}

fix_kill_pid() {
    kill -9 "$1" 2>/dev/null
    sleep 1
    ! kill -0 "$1" 2>/dev/null
}

fix_disable_unit() {
    local unit="$1" file="$2"
    systemctl disable --now "$unit" >/dev/null 2>&1
    [[ -n "$file" && -f "$file" ]] && quarantine_file "$file"
    systemctl daemon-reload >/dev/null 2>&1
    return 0
}

fix_docker_sock_perms() {
    chmod 660 /var/run/docker.sock 2>/dev/null
}

fix_enable_apparmor() {
    pkg_install apparmor apparmor-utils 2>/dev/null
    svc_enable_now apparmor
    svc_active apparmor
}

# ---------------------------------------------------------------------------
# Check modules
# ---------------------------------------------------------------------------
chk_sysinfo() {
    hdr "System information"
    info "host: $(hostname 2>/dev/null)  |  $OS_PRETTY  |  kernel $(uname -r)"
    info "uptime:$(uptime 2>/dev/null | sed 's/.*up/ up/;s/,.*user.*//')"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local v
        v="$(systemd-detect-virt 2>/dev/null)"
        [[ -n "$v" && "$v" != "none" ]] && info "virtualization: $v" || info "virtualization: none detected (bare metal?)"
    fi
    if [[ "$IS_ROOT" != 1 ]]; then
        warn "running WITHOUT root — coverage is limited (shadow, process owners, firewall state, fixes)"
        reco "re-run with: sudo bash $0"
    else
        ok "running as root — full coverage available"
    fi
    local du
    du="$(df -P / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')"
    if [[ -n "$du" ]]; then
        if (( du >= 90 )); then warn "root filesystem ${du}% full — logging and updates may fail"; else ok "root filesystem ${du}% used"; fi
    fi
}

chk_updates() {
    hdr "Updates & patching"
    case "$PKG" in
        apt)
            if [[ "$IS_ROOT" == 1 ]]; then pkg_refresh; fi
            local n nsec
            n="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ')"
            nsec="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst ' | grep -ci securi)"
            if [[ "${n:-0}" -gt 0 ]]; then
                offer_fix warn 0 "$n package update(s) pending ($nsec security)" \
                    "install pending package updates (apt upgrade)" fix_apply_updates
            else
                ok "no pending package updates"
            fi
            if pkg_installed unattended-upgrades \
               && grep -qs '^APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
                ok "automatic security updates enabled (unattended-upgrades)"
            else
                offer_fix warn 0 "automatic security updates are NOT enabled" \
                    "install & enable unattended-upgrades" fix_auto_updates
            fi
            ;;
        dnf|yum)
            if svc_active dnf-automatic.timer || pkg_installed yum-cron; then
                ok "automatic updates configured"
            else
                offer_fix warn 0 "automatic security updates are NOT enabled" \
                    "install & enable dnf-automatic/yum-cron" fix_auto_updates
            fi
            ;;
        *)
            info "package manager '$PKG' — automatic update check not implemented, verify manually"
            ;;
    esac
    if [[ -f /var/run/reboot-required ]]; then
        warn "system reboot REQUIRED to finish security updates (likely a kernel patch)"
        reco "reboot at the next maintenance window"
    else
        ok "no pending reboot"
    fi
    # EOL check (Ubuntu)
    if [[ -r /etc/os-release ]]; then
        local osid osver
        osid="$(. /etc/os-release; echo "$ID")"
        osver="$(. /etc/os-release; echo "${VERSION_ID:-}")"
        if [[ "$osid" == "ubuntu" && -n "$osver" ]]; then
            case "$osver" in
                12.04|14.04|16.04|18.04|21.*|23.*|25.04)
                    warn "Ubuntu $osver no longer receives free standard security updates (EOL/interim)"
                    reco "upgrade the release or enable Ubuntu Pro ESM" ;;
                *) ok "Ubuntu $osver — supported release" ;;
            esac
        fi
    fi
}

chk_accounts() {
    hdr "Accounts & authentication"
    # UID 0 accounts
    local uid0
    uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root)"
    if [[ -n "$uid0" ]]; then
        crit "extra UID-0 (root-equivalent) account(s): $(tr '\n' ' ' <<<"$uid0") — classic backdoor"
        reco "verify origin; if unknown, lock immediately: usermod -L <user> && usermod -s /usr/sbin/nologin <user>"
    else
        ok "root is the only UID-0 account"
    fi
    # shadowed passwords
    if awk -F: '$2 != "x" && $2 != "*" && $2 != "" {exit 1}' /etc/passwd; then
        ok "no password hashes stored in world-readable /etc/passwd"
    else
        crit "password hash present in /etc/passwd (world-readable!) — move to /etc/shadow (pwconv)"
    fi
    # empty passwords
    if [[ "$IS_ROOT" == 1 && -r /etc/shadow ]]; then
        local empties u
        empties="$(awk -F: '($2==""){print $1}' /etc/shadow)"
        if [[ -n "$empties" ]]; then
            for u in $empties; do
                offer_fix crit 1 "account '$u' has an EMPTY password — anyone can log in" \
                    "lock account '$u' (passwd -l)" fix_lock_user "$u"
            done
        else
            ok "no accounts with empty passwords"
        fi
    fi
    # duplicate UIDs / names
    local dup
    dup="$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | tr '\n' ' ')"
    [[ -n "${dup// }" ]] && warn "duplicate UID(s) in /etc/passwd: $dup" || ok "no duplicate UIDs"
    dup="$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d | tr '\n' ' ')"
    [[ -n "${dup// }" ]] && crit "duplicate username(s) in /etc/passwd: $dup"
    # system accounts with login shells
    local sysshell
    sysshell="$(awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1"("$7")"}' /etc/passwd | tr '\n' ' ')"
    if [[ -n "${sysshell// }" ]]; then
        warn "system account(s) with a login shell: $sysshell"
        reco "set shell to nologin unless required: usermod -s /usr/sbin/nologin <user>"
    else
        ok "no system accounts with login shells"
    fi
    # sudo membership
    local g sudoers=""
    for g in sudo wheel admin; do
        sudoers="$sudoers $(getent group "$g" 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')"
    done
    sudoers="$(tr ' ' '\n' <<<"$sudoers" | grep -v '^$' | sort -u | tr '\n' ' ')"
    [[ -n "${sudoers// }" ]] && info "sudo-capable users:$([[ -n "$sudoers" ]] && echo " $sudoers")" \
                             || info "no users in sudo/wheel groups (root-only administration)"
    # NOPASSWD sudo
    if [[ "$IS_ROOT" == 1 ]]; then
        local nopass
        nopass="$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -5)"
        if [[ -n "$nopass" ]]; then
            warn "passwordless sudo (NOPASSWD) configured:"
            while IFS= read -r l; do note "$l"; done <<<"$nopass"
            reco "remove NOPASSWD unless strictly needed (visudo)"
        else
            ok "no passwordless sudo rules"
        fi
    fi
    # password aging policy
    local maxd
    maxd="$(grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')"
    if [[ -n "$maxd" && "$maxd" -gt 365 ]]; then
        offer_fix warn 0 "password max age is $maxd days (no rotation policy)" \
            "set sane password aging policy in /etc/login.defs (365/1/14, umask 027)" fix_login_defs
    else
        ok "password aging policy: PASS_MAX_DAYS=${maxd:-unset}"
    fi
    # pwquality (harden)
    if [[ "$MODE" == "harden" && "$PKG" == "apt" ]] && ! pkg_installed libpam-pwquality; then
        offer_fix info 0 "no password-strength enforcement (pam_pwquality missing)" \
            "install libpam-pwquality (minlen 12, 3 character classes)" fix_pwquality
    fi
    # PATH sanity (current shell environment)
    case ":$PATH:" in
        *::*|*:.:*) warn "PATH contains '.' or an empty element — trojan-binary risk" ;;
        *) ok "PATH contains no relative entries" ;;
    esac
    # legacy r-files
    local rf
    for rf in /root/.rhosts /etc/hosts.equiv; do
        [[ -f "$rf" ]] && crit "legacy trust file exists: $rf — remove it (rsh-era backdoor vector)"
    done
    # failed login attempts
    if [[ "$IS_ROOT" == 1 ]] && command -v lastb >/dev/null 2>&1; then
        local nb
        nb="$(lastb 2>/dev/null | head -200 | grep -cvE '^(btmp begins|[[:space:]]*$)')"
        if (( nb >= 100 )); then
            warn "100+ failed login attempts in /var/log/btmp — you are being brute-forced"
            reco "enable fail2ban and key-only SSH (see SSH section)"
        elif (( nb > 0 )); then
            info "$nb recent failed login attempt(s) recorded"
        else
            ok "no recent failed login attempts"
        fi
    fi
    # active sessions
    local sess
    sess="$(who 2>/dev/null | wc -l)"
    info "active login sessions: $sess"
    who 2>/dev/null | head -5 | while IFS= read -r l; do note "$l"; done
}

chk_ssh() {
    hdr "SSH server"
    if ! ssh_server_present; then
        ok "OpenSSH server not installed — nothing exposed via SSH"
        return 0
    fi
    load_sshd_config

    # lockout-safety first: a sudo user with an SSH key must exist before any
    # root/password lockdown below can be applied safely
    if keybased_admin_exists; then
        ok "a sudo-capable user with an SSH key exists (lockout-safe)"
    elif [[ "$MODE" != "audit" && "$INTERACTIVE_TTY" == 1 && "$IS_ROOT" == 1 ]]; then
        offer_fix warn 0 "no sudo user with an SSH key — the root password is the single point of access" \
            "create a sudo user with an SSH key (one-time HTTPS download link), then lock down root login" \
            fix_create_admin_user
    else
        warn "no sudo user with an SSH key — the root password is the single point of access"
        reco "create one interactively: sudo bash $0 --create-user"
    fi

    local v
    v="$(sshd_opt permitrootlogin prohibit-password)"
    case "$v" in
        yes)
            offer_fix crit 1 "PermitRootLogin=yes — root can log in over SSH with a password" \
                "disable SSH root login (PermitRootLogin no)" fix_ssh_disable_root ;;
        no) ok "SSH root login disabled" ;;
        *)  info "PermitRootLogin=$v (key-based root login allowed)"
            [[ "$MODE" == "harden" ]] && offer_fix info 1 "root SSH login still possible with keys" \
                "fully disable SSH root login (PermitRootLogin no)" fix_ssh_disable_root ;;
    esac
    v="$(sshd_opt passwordauthentication yes)"
    if [[ "$v" == "yes" ]]; then
        offer_fix warn 1 "SSH password authentication enabled — brute-force surface" \
            "switch SSH to key-only authentication (PasswordAuthentication no)" fix_ssh_disable_passwords
    else
        ok "SSH password authentication disabled (key-only)"
    fi
    v="$(sshd_opt permitemptypasswords no)"
    [[ "$v" == "yes" ]] && offer_fix crit 0 "PermitEmptyPasswords=yes — empty-password SSH logins allowed" \
            "apply safe SSH hardening preset" fix_ssh_safe_harden \
        || ok "empty-password SSH logins not permitted"
    local needsafe=0
    v="$(sshd_opt x11forwarding no)";        [[ "$v" == "yes" ]] && { warn "X11Forwarding enabled (rarely needed on servers)"; needsafe=1; }
    v="$(sshd_opt maxauthtries 6)";          [[ "$v" -gt 4 ]] 2>/dev/null && { warn "MaxAuthTries=$v (high)"; needsafe=1; }
    v="$(sshd_opt logingracetime 120)";      :
    v="$(sshd_opt clientaliveinterval 0)";   [[ "$v" == "0" ]] && needsafe=1
    v="$(sshd_opt hostbasedauthentication no)"; [[ "$v" == "yes" ]] && { warn "HostbasedAuthentication enabled"; needsafe=1; }
    if [[ "$needsafe" == 1 || "$MODE" == "harden" ]]; then
        offer_fix info 0 "SSH daemon can be tightened further (timeouts, retries, X11, rhosts)" \
            "apply safe SSH hardening preset (never drops current sessions, validated with sshd -t)" fix_ssh_safe_harden
    else
        ok "SSH daemon options look sane"
    fi
    v="$(sshd_opt port 22)"
    [[ "$v" == "22" ]] && { info "SSH listens on default port 22"; reco "optional: move SSH to a non-standard port to cut log noise (not real security)"; }
    if [[ -z "$(sshd_opt allowusers "")$(sshd_opt allowgroups "")" ]]; then
        reco "optional: restrict SSH with AllowUsers/AllowGroups in sshd_config"
    fi
    # fail2ban
    if svc_active fail2ban; then
        ok "fail2ban is active (brute-force protection)"
    else
        offer_fix warn 0 "no brute-force protection (fail2ban not running)" \
            "install & enable fail2ban with an sshd jail" fix_install_fail2ban
    fi
}

normalize_listeners() {
    # output: proto|addr|port|process
    if command -v ss >/dev/null 2>&1; then
        ss -tulpen 2>/dev/null | awk 'NR>1 {
            proto=$1; local=$5;
            n=split(local, a, ":"); port=a[n];
            addr=substr(local, 1, length(local)-length(port)-1);
            gsub(/%[a-zA-Z0-9_.-]+/, "", addr);
            proc="-";
            if (match($0, /users:\(\("[^"]+"/)) {
                proc=substr($0, RSTART+9, RLENGTH-9); sub(/"$/,"",proc);
            }
            print proto"|"addr"|"port"|"proc
        }'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpen 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
            proto=$1; local=$4;
            n=split(local, a, ":"); port=a[n];
            addr=substr(local, 1, length(local)-length(port)-1);
            proc=$NF; sub(/^[0-9]+\//,"",proc);
            print proto"|"addr"|"port"|"proc
        }'
    fi
}

is_loopback() {
    case "$1" in
        127.*|::1|\[::1\]|localhost) return 0 ;;
        *) return 1 ;;
    esac
}

chk_network() {
    hdr "Network: listening ports"
    local lst
    lst="$(normalize_listeners | sort -t'|' -k3 -n -u)"
    if [[ -z "$lst" ]]; then
        warn "could not enumerate listening sockets (ss/netstat missing?)"
    else
        local nl
        nl="$(grep -c . <<<"$lst")"
        info "$nl listening socket(s):"
        local proto addr port proc line seen_ports=""
        while IFS='|' read -r proto addr port proc; do
            [[ -z "$port" ]] && continue
            local exposure="exposed"
            is_loopback "$addr" && exposure="local-only"
            note "$(printf '%-4s %-25s port %-6s %-12s %s' "$proto" "$addr" "$port" "($proc)" "[$exposure]")"
        done <<<"$lst"
        # flag risky exposed ports
        while IFS='|' read -r proto addr port proc; do
            [[ -z "$port" ]] && continue
            is_loopback "$addr" && continue
            case " $seen_ports " in *" $port "*) continue ;; esac
            seen_ports="$seen_ports $port"
            if [[ -n "${RISKY_PORTS[$port]:-}" ]]; then
                case "$port" in
                    23|512|513|514|2375|69)
                        crit "port $port exposed: ${RISKY_PORTS[$port]} (process: $proc)"
                        reco "stop/remove the service or firewall the port immediately" ;;
                    6379|9200|27017|11211|3306|5432|1433|1521)
                        warn "database/cache port $port exposed to the network: ${RISKY_PORTS[$port]} (process: $proc)"
                        reco "bind it to 127.0.0.1 or restrict with the firewall" ;;
                    *)
                        warn "port $port exposed: ${RISKY_PORTS[$port]} (process: $proc)" ;;
                esac
            fi
        done <<<"$lst"
        ok "port review complete"
    fi

    hdr "Network: active connections"
    if command -v ss >/dev/null 2>&1; then
        local est
        est="$(ss -tnp state established 2>/dev/null | awk 'NR>1')"
        local n
        n="$(grep -c . <<<"$est" 2>/dev/null)"
        info "${n:-0} established TCP connection(s)"
        local bad=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local peer pport
            peer="$(awk '{print $4}' <<<"$line")"
            # ss 'established' filter shifts columns: Recv Send Local Peer [proc]
            pport="${peer##*:}"
            if grep -qE "$MINER_PORTS_ERE" <<<"$pport"; then
                crit "outbound connection to $peer — port typical for crypto-mining pools / IRC botnets"
                note "$line"
                bad=1
            fi
        done <<<"$est"
        [[ "$bad" == 0 ]] && ok "no connections to known mining-pool/botnet ports"
    fi

    hdr "Network: configuration"
    # promiscuous interfaces
    local prom
    prom="$(ip link 2>/dev/null | grep -i promisc | awk -F: '{print $2}' | tr '\n' ' ')"
    [[ -n "${prom// }" ]] && warn "interface(s) in PROMISCUOUS mode (sniffer?):$prom" \
                          || ok "no interfaces in promiscuous mode"
    # ARP duplicates (possible spoofing)
    local arpdup
    arpdup="$(ip neigh 2>/dev/null | awk '$NF!="FAILED" {print $5}' | grep -E ':' | sort | uniq -d | head -3)"
    if [[ -n "$arpdup" ]]; then
        warn "duplicate MAC addresses in ARP table (possible ARP spoofing): $(tr '\n' ' ' <<<"$arpdup")"
        reco "verify your gateway MAC with the network provider"
    else
        ok "no duplicate MACs in ARP table"
    fi
    # DNS
    local ns
    ns="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    [[ -n "${ns// }" ]] && info "DNS resolvers: $ns" || warn "no nameservers configured in /etc/resolv.conf"
    # /etc/hosts hijacks
    local hij
    hij="$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null \
          | grep -iE '(google|github|microsoft|apple|mozilla|ubuntu|debian|clamav|virustotal|cloudflare|amazon)\.' \
          | grep -vE '^(127\.|::1|0\.0\.0\.0|255\.|ff02::|fe00::)')"
    if [[ -n "$hij" ]]; then
        crit "/etc/hosts redirects well-known domains (DNS hijack?):"
        while IFS= read -r l; do note "$l"; done <<<"$hij"
    else
        ok "/etc/hosts contains no suspicious redirects"
    fi
}

chk_firewall() {
    hdr "Firewall"
    local fw_ok=0
    if command -v ufw >/dev/null 2>&1; then
        if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
            ok "UFW firewall is ACTIVE"
            fw_ok=1
            local nrules
            nrules="$(ufw status numbered 2>/dev/null | grep -c '^\[')"
            info "UFW rules: $nrules"
            if grep -qs '^IPV6=yes' /etc/default/ufw; then
                ok "UFW also filters IPv6"
            else
                warn "UFW IPv6 filtering disabled (IPV6=no in /etc/default/ufw)"
            fi
        fi
    fi
    if [[ "$fw_ok" == 0 ]] && command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            ok "firewalld is ACTIVE"
            fw_ok=1
        fi
    fi
    if [[ "$fw_ok" == 0 ]] && command -v nft >/dev/null 2>&1 && [[ "$IS_ROOT" == 1 ]]; then
        local nftn
        nftn="$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|tcp|udp|iif|accept|drop|reject)')"
        if (( nftn > 3 )); then
            ok "nftables ruleset present ($nftn rule lines)"
            fw_ok=1
        fi
    fi
    if [[ "$fw_ok" == 0 ]] && command -v iptables >/dev/null 2>&1 && [[ "$IS_ROOT" == 1 ]]; then
        local iptn
        iptn="$(iptables -S 2>/dev/null | grep -vc '^-P')"
        local pol
        pol="$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print $3}')"
        if [[ "$pol" == "DROP" || "$pol" == "REJECT" ]] || (( iptn > 3 )); then
            ok "iptables rules present (INPUT policy: ${pol:-?}, $iptn rules)"
            fw_ok=1
        fi
    fi
    if [[ "$fw_ok" == 0 ]]; then
        offer_fix crit 1 "NO active firewall detected — every listening service is fully exposed" \
            "enable a firewall (UFW/firewalld) with SSH port(s) pre-allowed so you are not locked out" \
            fix_enable_firewall
    fi
}

chk_sysctl() {
    hdr "Kernel & sysctl hardening"
    [[ ! -r /proc/sys ]] && { warn "/proc/sys not readable"; return 0; }
    local bad=0
    _sysctl_want() {  # key expected description
        local cur
        cur="$(sysctl -n "$1" 2>/dev/null)"
        [[ -z "$cur" ]] && return 0
        if [[ "$cur" != "$2" ]]; then
            warn "$1 = $cur (recommended: $2) — $3"
            bad=1
        fi
    }
    _sysctl_want kernel.randomize_va_space 2 "full ASLR"
    _sysctl_want net.ipv4.tcp_syncookies 1 "SYN-flood protection"
    _sysctl_want net.ipv4.conf.all.rp_filter 1 "anti-spoofing source validation"
    _sysctl_want net.ipv4.conf.all.accept_redirects 0 "ignore ICMP redirects (MITM)"
    _sysctl_want net.ipv4.conf.all.send_redirects 0 "do not send ICMP redirects"
    _sysctl_want net.ipv4.conf.all.accept_source_route 0 "ignore source-routed packets"
    _sysctl_want net.ipv4.conf.all.log_martians 1 "log spoofed packets"
    _sysctl_want net.ipv4.icmp_echo_ignore_broadcasts 1 "ignore broadcast pings (smurf)"
    _sysctl_want net.ipv6.conf.all.accept_redirects 0 "ignore IPv6 ICMP redirects"
    _sysctl_want fs.suid_dumpable 0 "no core dumps from SUID binaries"
    _sysctl_want kernel.kptr_restrict 2 "hide kernel pointers"
    _sysctl_want kernel.dmesg_restrict 1 "restrict kernel log access"
    _sysctl_want kernel.yama.ptrace_scope 1 "restrict process tracing"
    _sysctl_want fs.protected_symlinks 1 "symlink attack protection"
    _sysctl_want fs.protected_hardlinks 1 "hardlink attack protection"
    if [[ "$HAS_CONTAINERS" != 1 ]]; then
        _sysctl_want net.ipv4.ip_forward 0 "this host is not a router"
    else
        info "container runtime detected — IP forwarding left as-is"
    fi
    if [[ "$bad" == 1 ]]; then
        offer_fix warn 0 "kernel/network sysctl values are not hardened (see items above)" \
            "write /etc/sysctl.d/99-antivirus-sh.conf with hardened values and apply" fix_sysctl_hardening
    else
        ok "all checked sysctl values already hardened"
    fi
}

chk_fs_perms() {
    hdr "Filesystem & permissions"
    local p m fixneeded=0
    _check_perm() {  # path maxmode
        [[ -e "$1" ]] || return 0
        m="$(stat -c '%a' "$1" 2>/dev/null)"
        # numeric compare per-digit: every permission bit beyond reference is a violation
        local cur=$((8#$m)) ref=$((8#$2))
        if (( (cur | ref) != ref )); then
            warn "$1 has mode $m (expected $2 or stricter)"
            fixneeded=1
        fi
    }
    _check_perm /etc/passwd 644
    _check_perm /etc/group 644
    _check_perm /etc/shadow 640
    _check_perm /etc/gshadow 640
    _check_perm /etc/sudoers 440
    _check_perm /etc/crontab 644
    _check_perm /etc/ssh/sshd_config 644
    _check_perm /root 750
    for p in /etc/ssh/ssh_host_*_key; do
        [[ -e "$p" ]] && _check_perm "$p" 640
    done
    [[ -e /boot/grub/grub.cfg ]] && _check_perm /boot/grub/grub.cfg 644
    if [[ "$fixneeded" == 1 || "$MODE" == "harden" ]]; then
        offer_fix info 0 "critical file permissions can be tightened to CIS-recommended values" \
            "tighten permissions on passwd/shadow/sudoers/sshd_config/crontab/host keys/grub" fix_perms_critical
    else
        ok "critical system file permissions look correct"
    fi

    if [[ "$QUICK" == 1 ]]; then
        info "quick mode: skipping full-disk permission sweeps"
        return 0
    fi

    local PRUNE=( -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /snap -prune -o -path /var/lib/docker -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -path /dev -prune )

    # world-writable files
    local ww
    ww="$(find / -xdev "${PRUNE[@]}" -o -type f -perm -0002 -print 2>/dev/null | head -100)"
    if [[ -n "$ww" ]]; then
        local nww
        nww="$(grep -c . <<<"$ww")"
        FIX_WW_LIST="$ww"
        offer_fix warn 0 "$nww world-writable file(s) found (any user can modify them):" \
            "remove the world-write bit (chmod o-w) from the files found" fix_world_writable_files
        head -8 <<<"$ww" | while IFS= read -r f; do note "$f"; done
    else
        ok "no world-writable files on the root filesystem"
    fi

    # world-writable dirs without sticky bit
    local wd
    wd="$(find / -xdev "${PRUNE[@]}" -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -50)"
    if [[ -n "$wd" ]]; then
        FIX_STICKY_LIST="$wd"
        offer_fix warn 0 "$(grep -c . <<<"$wd") world-writable dir(s) without sticky bit (file-hijack risk)" \
            "add the sticky bit (chmod +t) to those directories" fix_sticky_dirs
        head -5 <<<"$wd" | while IFS= read -r d; do note "$d"; done
    else
        ok "all world-writable directories have the sticky bit"
    fi

    # unowned files
    local orph
    orph="$(find / -xdev "${PRUNE[@]}" -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -20)"
    if [[ -n "$orph" ]]; then
        warn "$(grep -c . <<<"$orph") file(s) without a valid owner (leftovers from deleted users?):"
        head -5 <<<"$orph" | while IFS= read -r f; do note "$f"; done
        reco "review and chown or delete unowned files"
    else
        ok "no unowned files"
    fi

    # SUID/SGID audit
    local suid f base unknown=0
    suid="$(find / -xdev "${PRUNE[@]}" -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)"
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        base="$(basename "$f")"
        if [[ "$SUID_WHITELIST" != *" $base "* ]]; then
            unknown=$((unknown+1))
            if [[ "$PKG" == "apt" ]] && ! dpkg -S "$f" >/dev/null 2>&1; then
                crit "SUID/SGID binary NOT owned by any package: $f — possible privilege-escalation backdoor"
                reco "investigate: ls -la '$f'; strings '$f' | head; remove bit: chmod -s '$f'"
            else
                warn "non-standard SUID/SGID binary: $f — verify it is expected"
            fi
            (( unknown >= 25 )) && { note "...stopping after 25 non-standard SUID findings"; break; }
        fi
    done <<<"$suid"
    [[ "$unknown" == 0 ]] && ok "all SUID/SGID binaries match the standard whitelist"

    # immutable files in system dirs
    if command -v lsattr >/dev/null 2>&1; then
        local imm
        imm="$(lsattr -R /etc /usr/bin /usr/sbin /bin /sbin 2>/dev/null | awk '$1 ~ /i/ && $1 ~ /^-/ {print $2}' | head -10)"
        if [[ -n "$imm" ]]; then
            warn "immutable (+i) system file(s) — malware often locks its files this way:"
            while IFS= read -r f; do note "$f"; done <<<"$imm"
            reco "review each; clear with: chattr -i <file>"
        else
            ok "no unexpected immutable files in system directories"
        fi
    fi

    # mount options
    local opts
    if command -v findmnt >/dev/null 2>&1; then
        opts="$(findmnt -no OPTIONS /dev/shm 2>/dev/null)"
        if [[ -n "$opts" ]] && ! grep -q noexec <<<"$opts"; then
            offer_fix warn 0 "/dev/shm is mounted WITHOUT noexec (popular malware launchpad)" \
                "remount /dev/shm with noexec,nosuid,nodev and persist in /etc/fstab" fix_secure_shm
        else
            ok "/dev/shm mount options: ${opts:-n/a}"
        fi
        opts="$(findmnt -no OPTIONS /tmp 2>/dev/null)"
        if [[ -z "$opts" ]]; then
            reco "optional: mount /tmp as a separate tmpfs with noexec,nosuid,nodev"
        elif ! grep -q nosuid <<<"$opts"; then
            warn "/tmp mounted without nosuid"
        else
            ok "/tmp mount options: $opts"
        fi
    fi
}

chk_persistence() {
    hdr "Persistence & startup points"
    local hits f

    # ld.so.preload — classic userland rootkit
    if [[ -s /etc/ld.so.preload ]]; then
        crit "/etc/ld.so.preload is NOT empty — classic userland rootkit technique:"
        while IFS= read -r l; do note "$l"; done < /etc/ld.so.preload
        offer_fix crit 1 "libraries are force-preloaded into every process" \
            "quarantine /etc/ld.so.preload (preloaded libs stay on disk for analysis)" \
            quarantine_file /etc/ld.so.preload
    else
        ok "/etc/ld.so.preload absent or empty"
    fi
    if grep -qsE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment; then
        warn "LD_PRELOAD/LD_LIBRARY_PATH set globally in /etc/environment — verify why"
    fi

    # cron sweep
    local cronfiles=(/etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*)
    local found_cron=0
    for f in "${cronfiles[@]}"; do
        [[ -f "$f" && -r "$f" ]] || continue
        hits="$(grep -nE "$SUS_ERE" "$f" 2>/dev/null | head -5)"
        if [[ -n "$hits" ]]; then
            found_cron=1
            crit "suspicious content in cron file $f:"
            while IFS= read -r l; do note "$l"; done <<<"$hits"
            case "$f" in
                /etc/crontab) reco "review and clean $f manually (system file — not auto-quarantined)" ;;
                *) offer_fix crit 1 "cron persistence in $f" "quarantine cron file $f" quarantine_file "$f" ;;
            esac
        fi
    done
    [[ "$found_cron" == 0 ]] && ok "no suspicious patterns in cron jobs"
    if [[ "$IS_ROOT" == 1 ]]; then
        local uc
        uc="$(ls /var/spool/cron/crontabs 2>/dev/null || ls /var/spool/cron 2>/dev/null)"
        [[ -n "$uc" ]] && info "users with personal crontabs: $(tr '\n' ' ' <<<"$uc")"
    fi
    command -v atq >/dev/null 2>&1 && { local na; na="$(atq 2>/dev/null | wc -l)"; (( na > 0 )) && info "$na pending at-job(s) — review with: atq; at -c <id>"; }

    # systemd units
    if [[ "$HAS_SYSTEMD" == 1 ]]; then
        local found_unit=0 u
        for u in /etc/systemd/system/*.service /etc/systemd/system/*/*.service /usr/local/lib/systemd/system/*.service; do
            [[ -f "$u" ]] || continue
            hits="$(grep -nE "$SUS_ERE" "$u" 2>/dev/null | head -3)"
            local tmpexec
            tmpexec="$(grep -nE '^Exec(Start|StartPre|StartPost)=.*(/tmp/|/var/tmp/|/dev/shm/)' "$u" 2>/dev/null | head -3)"
            if [[ -n "$hits" || -n "$tmpexec" ]]; then
                found_unit=1
                crit "suspicious systemd unit: $u"
                [[ -n "$hits" ]]    && while IFS= read -r l; do note "$l"; done <<<"$hits"
                [[ -n "$tmpexec" ]] && while IFS= read -r l; do note "$l"; done <<<"$tmpexec"
                offer_fix crit 1 "malicious-looking systemd service $(basename "$u")" \
                    "disable unit $(basename "$u") and quarantine its file" \
                    fix_disable_unit "$(basename "$u")" "$u"
            fi
        done
        [[ "$found_unit" == 0 ]] && ok "no suspicious custom systemd units"
    fi

    # rc.local
    if [[ -f /etc/rc.local ]]; then
        hits="$(grep -nE "$SUS_ERE" /etc/rc.local 2>/dev/null | head -5)"
        if [[ -n "$hits" ]]; then
            crit "suspicious content in /etc/rc.local:"
            while IFS= read -r l; do note "$l"; done <<<"$hits"
        elif [[ -x /etc/rc.local ]]; then
            info "/etc/rc.local exists and is executable — review its contents"
        fi
    fi

    # shell startup files
    local found_rc=0 home user
    local rcglobs=(/etc/profile /etc/bash.bashrc /etc/profile.d/* /etc/update-motd.d/*)
    while IFS=: read -r user _ uid _ _ home _; do
        if [[ -d "$home" && ( "$uid" -ge 1000 || "$uid" == 0 ) ]]; then
            rcglobs+=("$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.bash_login" "$home/.bash_logout" "$home/.zshrc")
        fi
    done < /etc/passwd
    for f in "${rcglobs[@]}"; do
        [[ -f "$f" && -r "$f" ]] || continue
        hits="$(grep -nE "$SUS_ERE" "$f" 2>/dev/null | grep -vE '^\s*[0-9]+:\s*#' | head -3)"
        if [[ -n "$hits" ]]; then
            found_rc=1
            crit "suspicious content in startup file $f:"
            while IFS= read -r l; do note "$l"; done <<<"$hits"
            reco "review $f and remove the malicious lines (file left untouched)"
        fi
    done
    [[ "$found_rc" == 0 ]] && ok "no suspicious patterns in shell/MOTD startup files"

    # udev rules
    for f in /etc/udev/rules.d/*; do
        [[ -f "$f" ]] || continue
        hits="$(grep -nE "$SUS_ERE" "$f" 2>/dev/null | head -3)"
        if [[ -n "$hits" ]]; then
            crit "suspicious udev rule in $f:"
            while IFS= read -r l; do note "$l"; done <<<"$hits"
        fi
    done

    # SSH authorized_keys audit
    local nk
    while IFS=: read -r user _ uid _ _ home _; do
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -s "$f" ]] || continue
            nk="$(grep -cE '^(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null)"
            if (( uid > 0 && uid < 1000 )); then
                crit "SYSTEM account '$user' (uid $uid) has SSH keys: $f — strong backdoor indicator"
                offer_fix crit 1 "unexpected SSH access for system account '$user'" \
                    "quarantine $f" quarantine_file "$f"
            else
                info "user '$user': $nk authorized SSH key(s) in $f"
            fi
        done
    done < /etc/passwd
    reco "review every authorized_keys entry — delete keys you do not recognize"

    # third-party APT repos
    if [[ "$PKG" == "apt" ]]; then
        local repos
        repos="$(grep -rhE '^(deb|deb-src) ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
                | grep -vE '(ubuntu\.com|debian\.org|canonical\.com|launchpad\.net)' | sort -u | head -8)"
        if [[ -n "$repos" ]]; then
            info "third-party APT repositories configured:"
            while IFS= read -r l; do note "$l"; done <<<"$repos"
            reco "remove repositories you do not recognize (/etc/apt/sources.list.d/)"
        else
            ok "only official package repositories configured"
        fi
    fi
}

chk_processes() {
    hdr "Processes & memory"
    # top CPU consumers
    info "top CPU consumers:"
    ps -eo pid,pcpu,pmem,user,comm --sort=-pcpu 2>/dev/null | head -6 | tail -5 \
        | while IFS= read -r l; do note "$l"; done

    # known-bad process names
    local bad=0 pid comm args
    while read -r pid comm; do
        [[ -z "$pid" ]] && continue
        if grep -qE "$BAD_PROC_ERE" <<<"$comm"; then
            bad=1
            args="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 160)"
            crit "KNOWN MALWARE process name: '$comm' (pid $pid)"
            note "cmdline: ${args:-?}"
            offer_fix crit 1 "malware process '$comm' running" "kill -9 process $pid ($comm)" fix_kill_pid "$pid"
        fi
    done < <(ps -eo pid=,comm= 2>/dev/null)
    # miner indicators in command lines
    while read -r pid args; do
        [[ -z "$pid" ]] && continue
        if grep -qE '(stratum\+tcp|stratum\+ssl|minexmr|supportxmr|nanopool|moneroocean|c3pool|--donate-level)' <<<"$args"; then
            bad=1
            crit "crypto-miner command line detected (pid $pid): $(head -c 140 <<<"$args")"
            offer_fix crit 1 "crypto-miner process running" "kill -9 process $pid" fix_kill_pid "$pid"
        fi
    done < <(ps -eo pid=,args= 2>/dev/null)
    [[ "$bad" == 0 ]] && ok "no known malware/miner process signatures"

    # processes running from deleted binaries or tmp dirs
    local d exe path shown=0
    for d in /proc/[0-9]*; do
        pid="${d#/proc/}"
        exe="$(readlink "$d/exe" 2>/dev/null)"
        [[ -z "$exe" ]] && continue
        args="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | head -c 120)"
        case "$exe" in
            /memfd:*)
                crit "FILELESS process (memfd, no file on disk): pid $pid — $args"
                offer_fix crit 1 "fileless in-memory executable (pid $pid)" "kill -9 process $pid" fix_kill_pid "$pid"
                ;;
            *" (deleted)")
                path="${exe% (deleted)}"
                case "$path" in
                    /tmp/*|/var/tmp/*|/dev/shm/*)
                        crit "process pid $pid runs from a DELETED file in tmp: $path — $args"
                        offer_fix crit 1 "self-deleting malware behaviour (pid $pid)" "kill -9 process $pid" fix_kill_pid "$pid"
                        ;;
                    *)
                        if (( shown < 5 )); then
                            warn "pid $pid runs a deleted binary: $path (often just a pending service restart after upgrade)"
                            shown=$((shown+1))
                        fi
                        ;;
                esac
                ;;
            /tmp/*|/var/tmp/*|/dev/shm/*)
                crit "process pid $pid executes from a tmp directory: $exe — $args"
                offer_fix crit 1 "binary executing from tmp (pid $pid)" "kill -9 process $pid and quarantine $exe" fix_kill_pid "$pid"
                [[ -f "$exe" ]] && offer_fix crit 1 "malicious binary on disk: $exe" "quarantine $exe" quarantine_file "$exe"
                ;;
        esac
    done
    (( shown > 0 )) && reco "restart services using deleted libraries/binaries (or reboot) — e.g. run: needrestart"

    # hidden process detection (rootkit readdir hiding)
    if [[ "$IS_ROOT" == 1 && "$QUICK" != 1 ]]; then
        local pid_max hidden=0 tgid
        pid_max="$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)"
        (( pid_max > 65536 )) && pid_max=65536
        local visible
        visible=" $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | tr '\n' ' ') "
        for (( pid=2; pid<=pid_max; pid++ )); do
            kill -0 "$pid" 2>/dev/null || continue
            [[ "$visible" == *" $pid "* ]] && continue
            tgid="$(awk '/^Tgid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
            [[ -n "$tgid" && "$tgid" != "$pid" ]] && continue   # thread, not a process
            # re-verify against a fresh listing (race protection)
            if kill -0 "$pid" 2>/dev/null && ! ls /proc 2>/dev/null | grep -qx "$pid"; then
                tgid="$(awk '/^Tgid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
                [[ -n "$tgid" && "$tgid" != "$pid" ]] && continue
                hidden=1
                crit "HIDDEN process pid $pid (alive but invisible in /proc listing) — kernel rootkit indicator"
                note "cmd: $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 120)"
            fi
        done
        [[ "$hidden" == 0 ]] && ok "no hidden processes (readdir-hiding rootkit test passed)"
    fi

    # suspicious kernel modules
    if command -v lsmod >/dev/null 2>&1; then
        local kbad
        kbad="$(lsmod 2>/dev/null | awk '{print $1}' | grep -iE "$BAD_KMOD_ERE" | tr '\n' ' ')"
        if [[ -n "${kbad// }" ]]; then
            crit "kernel module matching known rootkit name loaded: $kbad"
            reco "investigate immediately; consider rebuilding the machine from a clean image"
        else
            ok "no kernel modules matching known rootkit names"
        fi
    fi
}

chk_malware_files() {
    hdr "Malware file scan (heuristics)"
    local paths=("${SCAN_PATHS[@]}")
    if [[ ${#paths[@]} -eq 0 ]]; then
        paths=(/tmp /var/tmp /dev/shm /root /home /etc/init.d /usr/local/bin /usr/local/sbin /opt /var/www /srv)
        [[ "$FULL" == 1 ]] && paths=(/)
    fi
    local exarg=() e
    for e in "${EXCLUDE_PATHS[@]}"; do exarg+=( -path "$e" -prune -o ); done

    # hidden executables / hidden dirs in tmp & dev
    local hid
    hid="$(find /tmp /var/tmp /dev -maxdepth 3 \( -name ".*" ! -name "." ! -name ".." \) \
            \( -type f -perm /111 -o -type d \) 2>/dev/null \
          | grep -vE '^/dev/(\.udev|shm/\.org\.chromium|shm/\.com\.)' | sort -u | head -15)"
    if [[ -n "$hid" ]]; then
        warn "hidden file(s)/dir(s) in tmp or /dev (common malware stash):"
        while IFS= read -r f; do
            note "$f"
            [[ -f "$f" ]] && offer_fix warn 1 "hidden executable $f" "quarantine $f" quarantine_file "$f"
        done <<<"$hid"
    else
        ok "no hidden executables in /tmp, /var/tmp, /dev/shm, /dev"
    fi

    # executables in tmp dirs
    local tmpx
    tmpx="$(find /tmp /var/tmp /dev/shm -maxdepth 4 -type f \( -perm /111 -o -name '*.sh' -o -name '*.elf' -o -name '*.bin' -o -name '*.py' \) 2>/dev/null | head -20)"
    if [[ -n "$tmpx" ]]; then
        warn "executable file(s) in temporary directories:"
        while IFS= read -r f; do note "$f"; done <<<"$tmpx"
        reco "verify each; quarantine anything unexpected"
    else
        ok "no executables parked in temporary directories"
    fi

    # suspicious-content sweep over scan paths (scripts only, bounded)
    local hits n f
    info "content scan of: ${paths[*]} (patterns: reverse shells, droppers, miners)"
    n=0
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        hits="$(grep -lE "$SUS_ERE" "$f" 2>/dev/null)"
        if [[ -n "$hits" ]]; then
            n=$((n+1))
            warn "suspicious pattern inside: $f"
            grep -nE "$SUS_ERE" "$f" 2>/dev/null | head -2 | while IFS= read -r l; do note "$l"; done
            (( n >= 20 )) && { note "...stopping after 20 findings"; break; }
        fi
    done < <(find "${paths[@]}" "${exarg[@]}" -xdev -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.php' -o -perm /111 \) -size -2M 2>/dev/null \
             | grep -vE '^(/usr/(bin|sbin|lib)|/bin|/sbin|/etc/init\.d|/lib)' | head -4000)
    [[ "$n" == 0 ]] && ok "no reverse-shell/dropper/miner patterns found in scanned paths"

    # package integrity verification
    if [[ "$QUICK" != 1 && "$IS_ROOT" == 1 ]]; then
        local pkgs verify_out
        case "$PKG" in
            apt)
                if command -v dpkg >/dev/null 2>&1 && dpkg --help 2>/dev/null | grep -q -- --verify; then
                    info "verifying integrity of security-critical packages (dpkg -V)..."
                    pkgs="bash coreutils login passwd sudo openssh-server openssh-client procps util-linux findutils grep curl wget"
                    [[ "$FULL" == 1 ]] && pkgs="$(dpkg-query -f '${Package} ' -W 2>/dev/null)"
                    verify_out="$(dpkg -V $pkgs 2>/dev/null | grep -vE ' c /etc/' | head -15)"
                    if [[ -n "$verify_out" ]]; then
                        crit "system binaries MODIFIED since installation (possible trojaned binaries):"
                        while IFS= read -r l; do note "$l"; done <<<"$verify_out"
                        reco "reinstall affected packages: apt-get install --reinstall <package>"
                    else
                        ok "core system binaries match package checksums"
                    fi
                fi
                ;;
            dnf|yum|zypper)
                info "verifying integrity of security-critical packages (rpm -V)..."
                verify_out="$(rpm -V bash coreutils sudo openssh-server procps-ng util-linux 2>/dev/null | grep -E '^..5' | grep -v ' c /' | head -15)"
                if [[ -n "$verify_out" ]]; then
                    crit "system binaries MODIFIED since installation:"
                    while IFS= read -r l; do note "$l"; done <<<"$verify_out"
                else
                    ok "core system binaries match package checksums"
                fi
                ;;
        esac
    fi
}

chk_external_scanners() {
    hdr "External scanners (ClamAV / rkhunter / chkrootkit)"
    if [[ "$NO_EXTERNAL" == 1 ]]; then
        info "--no-external: skipping third-party scanners"
        return 0
    fi
    local missing=()

    # ClamAV
    if command -v clamscan >/dev/null 2>&1; then
        if [[ "$QUICK" == 1 ]]; then
            info "ClamAV present (skipped in --quick mode)"
        else
            command -v freshclam >/dev/null 2>&1 && [[ "$IS_ROOT" == 1 ]] \
                && timeout 240 freshclam --quiet >/dev/null 2>&1
            local cpaths=(/tmp /var/tmp /dev/shm /root /home)
            [[ "$FULL" == 1 ]] && cpaths=(/)
            info "running ClamAV scan of: ${cpaths[*]} (this can take a while)..."
            local cl_out
            cl_out="$(clamscan -r -i --no-summary --exclude-dir='^/(sys|proc|dev|snap|var/lib/docker)' "${cpaths[@]}" 2>/dev/null | head -25)"
            if [[ -n "$cl_out" ]]; then
                while IFS= read -r l; do
                    crit "ClamAV: $l"
                    f="${l%%:*}"
                    [[ -f "$f" ]] && offer_fix crit 1 "infected file $f" "quarantine $f" quarantine_file "$f"
                done <<<"$cl_out"
            else
                ok "ClamAV: no infected files found"
            fi
        fi
    else
        missing+=(clamav)
    fi

    # rkhunter
    if command -v rkhunter >/dev/null 2>&1; then
        if [[ "$QUICK" == 1 || "$IS_ROOT" != 1 ]]; then
            info "rkhunter present (needs root, skipped in --quick mode)"
        else
            info "running rkhunter (rootkit hunter)..."
            local rk_out
            rk_out="$(timeout 900 rkhunter --check --sk --rwo --nocolors 2>/dev/null | head -20)"
            if [[ -n "$rk_out" ]]; then
                warn "rkhunter reported warnings (review — some are known false positives):"
                while IFS= read -r l; do note "$l"; done <<<"$rk_out"
                reco "details: /var/log/rkhunter.log"
            else
                ok "rkhunter: no warnings"
            fi
        fi
    else
        missing+=(rkhunter)
    fi

    # chkrootkit
    if command -v chkrootkit >/dev/null 2>&1; then
        if [[ "$QUICK" == 1 || "$IS_ROOT" != 1 ]]; then
            info "chkrootkit present (needs root, skipped in --quick mode)"
        else
            info "running chkrootkit..."
            local ck_out
            ck_out="$(timeout 600 chkrootkit -q 2>/dev/null | grep -viE '(not infected|not found|nothing found|nothing deleted|no suspect)' | grep -vE '^\s*$' | head -15)"
            if [[ -n "$ck_out" ]]; then
                warn "chkrootkit findings (review — false positives are common):"
                while IFS= read -r l; do note "$l"; done <<<"$ck_out"
            else
                ok "chkrootkit: clean"
            fi
        fi
    else
        missing+=(chkrootkit)
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        if [[ "$DO_INSTALL_TOOLS" == 1 || "$MODE" == "harden" ]]; then
            offer_fix info 0 "extra scanners not installed: ${missing[*]}" \
                "install ${missing[*]} for signature-based & rootkit scanning" \
                pkg_install "${missing[@]}"
        else
            info "optional scanners not installed: ${missing[*]}"
            reco "install for deeper scans: sudo bash $0 --install-tools  (or: apt install ${missing[*]})"
        fi
    fi
}

chk_docker() {
    command -v docker >/dev/null 2>&1 || return 0
    hdr "Containers (Docker)"
    # docker group = root equivalent
    local dgrp
    dgrp="$(getent group docker 2>/dev/null | awk -F: '{print $4}')"
    if [[ -n "$dgrp" ]]; then
        warn "users in 'docker' group (this is ROOT-equivalent access): $dgrp"
    else
        ok "no extra users in the docker group"
    fi
    # socket permissions
    if [[ -S /var/run/docker.sock ]]; then
        local sm
        sm="$(stat -c '%a' /var/run/docker.sock 2>/dev/null)"
        if [[ "$sm" == "666" || "$sm" == "777" ]]; then
            offer_fix crit 0 "/var/run/docker.sock is world-writable (mode $sm) — any user gets root" \
                "chmod 660 /var/run/docker.sock" fix_docker_sock_perms
        else
            ok "docker socket permissions: $sm"
        fi
    fi
    # TCP API exposure is flagged in the ports section (2375/2376)
    if [[ "$IS_ROOT" == 1 ]] && timeout 5 docker info >/dev/null 2>&1; then
        local priv
        priv="$(docker ps -q 2>/dev/null | while read -r c; do
            docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} pidmode={{.HostConfig.PidMode}}' "$c" 2>/dev/null
        done | grep -E '(privileged=true|pidmode=host)')"
        if [[ -n "$priv" ]]; then
            warn "container(s) running with privileged/host access:"
            while IFS= read -r l; do note "$l"; done <<<"$priv"
            reco "avoid --privileged and --pid=host unless absolutely required"
        else
            ok "no privileged containers running"
        fi
    fi
}

chk_platform_services() {
    hdr "Platform services & kernel protections"
    # MAC: AppArmor / SELinux
    local mac=0
    if command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
        ok "AppArmor is enabled"
        mac=1
    elif [[ "$HAS_SYSTEMD" == 1 ]] && svc_active apparmor; then
        ok "AppArmor service is active"
        mac=1
    fi
    if [[ "$mac" == 0 ]] && command -v getenforce >/dev/null 2>&1; then
        local se
        se="$(getenforce 2>/dev/null)"
        if [[ "$se" == "Enforcing" ]]; then ok "SELinux is enforcing"; mac=1
        elif [[ "$se" == "Permissive" ]]; then warn "SELinux is in permissive mode (logging only)"; mac=1
        fi
    fi
    if [[ "$mac" == 0 ]]; then
        offer_fix warn 0 "no mandatory access control (AppArmor/SELinux) active" \
            "install & enable AppArmor" fix_enable_apparmor
    fi
    # auditd
    if svc_active auditd; then
        ok "auditd is recording system events"
    else
        if [[ "$MODE" == "harden" ]]; then
            offer_fix info 0 "no audit daemon (auditd) — forensic trail unavailable" \
                "install & enable auditd" fix_install_pkg auditd auditd
        else
            info "auditd not active (optional, recommended for servers)"
            reco "install auditd for a forensic event trail"
        fi
    fi
    # time sync
    local ntp_ok=0
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl 2>/dev/null | grep -qiE '(NTP service: active|synchronized: yes|NTP enabled: yes)' && ntp_ok=1
    fi
    svc_active chronyd && ntp_ok=1
    svc_active ntp && ntp_ok=1
    svc_active systemd-timesyncd && ntp_ok=1
    if [[ "$ntp_ok" == 1 ]]; then
        ok "system clock is synchronized (NTP)"
    else
        offer_fix warn 0 "clock NOT synchronized — breaks TLS validation and forensic timelines" \
            "enable NTP time synchronization" fix_enable_ntp
    fi
    # logging
    if svc_active rsyslog || svc_active syslog-ng || [[ -d /run/systemd/journal ]]; then
        ok "system logging is active"
        if [[ "$HAS_SYSTEMD" == 1 && ! -d /var/log/journal ]]; then
            if [[ "$MODE" == "harden" ]]; then
                offer_fix info 0 "systemd journal is volatile (lost on reboot)" \
                    "enable persistent journald storage (/var/log/journal)" fix_journald_persistent
            else
                reco "enable persistent journald logs: mkdir -p /var/log/journal && systemctl restart systemd-journald"
            fi
        fi
    else
        warn "no system logging daemon detected"
    fi
    # core dumps
    if [[ "$MODE" == "harden" ]]; then
        offer_fix info 0 "core dumps may leak secrets from crashed processes" \
            "disable core dumps (limits.d + fs.suid_dumpable=0)" fix_core_dumps
        offer_fix info 0 "idle shells stay logged in forever" \
            "auto-logout idle shells after 15 min (TMOUT in profile.d)" fix_tmout
        offer_fix info 0 "no pre-login warning banner" \
            "install a standard authorized-use banner (/etc/issue.net)" fix_login_banner
    fi
    # CPU vulnerabilities
    if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
        local vuln
        vuln="$(grep -l 'Vulnerable' /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')"
        if [[ -n "${vuln// }" ]]; then
            warn "CPU vulnerable (no mitigation) to: $vuln"
            reco "update kernel/microcode; on cloud VMs this is mostly the provider's job"
        else
            ok "all known CPU vulnerabilities mitigated or not affected"
        fi
    fi
    # secure boot (informational)
    if command -v mokutil >/dev/null 2>&1; then
        local sb
        sb="$(mokutil --sb-state 2>/dev/null | head -1)"
        [[ -n "$sb" ]] && info "secure boot: $sb"
    fi
    # GRUB password (informational)
    if [[ -r /boot/grub/grub.cfg ]] && ! grep -q 'password' /boot/grub/grub.cfg 2>/dev/null; then
        reco "optional (physical/console access): set a GRUB password to protect boot parameters"
    fi
}

# ---------------------------------------------------------------------------
# User creation
# ---------------------------------------------------------------------------
run_create_user() {
    hdr "Create a secure administrator user"
    if [[ "$IS_ROOT" != 1 ]]; then
        crit "creating users requires root — re-run with sudo"
        return 1
    fi
    if [[ "$INTERACTIVE_TTY" != 1 ]]; then
        crit "--create-user needs an interactive terminal"
        return 1
    fi
    local uname
    while true; do
        printf '  new username: '
        read -r uname </dev/tty
        if [[ ! "$uname" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            echo "  invalid username (lowercase letters, digits, - and _)"
            continue
        fi
        if id "$uname" >/dev/null 2>&1; then
            echo "  user '$uname' already exists, pick another"
            continue
        fi
        break
    done
    useradd -m -s /bin/bash "$uname" || { crit "useradd failed"; return 1; }
    record_undo "userdel -r $uname"
    local admgrp=sudo
    getent group sudo >/dev/null 2>&1 || admgrp=wheel
    usermod -aG "$admgrp" "$uname"
    fixed "user '$uname' created and added to group '$admgrp'"

    if ask "generate a strong random password for '$uname' (otherwise you type one)" y; then
        local pw
        pw="$(tr -dc 'A-Za-z0-9_@#%+=' </dev/urandom | head -c 20)"
        echo "$uname:$pw" | chpasswd
        out ""
        out "  ${C_W}GENERATED PASSWORD for $uname:  ${C_G}$pw${C_0}"
        out "  ${C_Y}store it in a password manager NOW — it is not saved anywhere${C_0}"
        out ""
    else
        passwd "$uname" </dev/tty
    fi

    local keydone=0 kc
    out ""
    out "  SSH key for '$uname':"
    out "    1) generate it HERE and download via a one-time HTTPS link (recommended)"
    out "    2) paste an existing public key (private key never leaves your device)"
    out "    3) skip for now"
    printf '  choice [1]: '
    read -r kc </dev/tty
    case "${kc:-1}" in
        2)
            local key home
            printf '  paste the public key (ssh-ed25519/ssh-rsa ...): '
            read -r key </dev/tty
            if [[ "$key" =~ ^(ssh-|ecdsa-|sk-) ]]; then
                home="$(getent passwd "$uname" | awk -F: '{print $6}')"
                mkdir -p "$home/.ssh"
                printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
                chmod 700 "$home/.ssh"
                chmod 600 "$home/.ssh/authorized_keys"
                chown -R "$uname:$uname" "$home/.ssh"
                fixed "SSH key installed for '$uname'"
                SSH_TEST_CMD="ssh ${uname}@$(detect_public_host 2>/dev/null || echo '<server-ip>')"
                keydone=1
            else
                warn "that does not look like a public key — skipped"
            fi
            ;;
        3)
            info "skipped — add a key before disabling SSH password authentication"
            ;;
        *)
            issue_and_deliver_key "$uname" && keydone=1
            ;;
    esac
    CREATED_USER="$uname"
    if [[ "$keydone" == 1 && "${SKIP_POST_KEY_OFFER:-0}" != 1 ]]; then
        offer_post_key_hardening "$uname"
    fi
    ok "administrator user '$uname' ready"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    local score grade
    score=$(( 100 - N_CRIT*10 - N_WARN*3 ))
    (( score < 0 )) && score=0
    if   (( N_CRIT > 0 ));   then grade="${C_R}F — critical issues found${C_0}"
    elif (( score >= 90 ));  then grade="${C_G}A — hardened${C_0}"
    elif (( score >= 75 ));  then grade="${C_G}B — good${C_0}"
    elif (( score >= 55 ));  then grade="${C_Y}C — needs work${C_0}"
    else                          grade="${C_R}D — weak${C_0}"
    fi
    out ""
    out "${C_B}============================================================${C_0}"
    out "${C_W}  antivirus.sh v$VERSION — summary${C_0}"
    out "${C_B}============================================================${C_0}"
    out "  ${C_G}OK: $N_OK${C_0}   ${C_C}INFO: $N_INFO${C_0}   ${C_Y}WARN: $N_WARN${C_0}   ${C_R}CRIT: $N_CRIT${C_0}   ${C_G}FIXED: $N_FIXED${C_0}"
    out "  security score: ${C_W}$score/100${C_0}  grade: $grade"
    if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
        out ""
        out "  ${C_M}Remaining recommendations:${C_0}"
        local r
        for r in "${RECOMMENDATIONS[@]}"; do
            out "   ${C_M}*${C_0} $r"
        done
    fi
    out ""
    if [[ -n "$CREATED_USER" && -n "$SSH_TEST_CMD" ]]; then
        out "  ${C_W}connect from your own device:${C_0}  ${C_G}$SSH_TEST_CMD${C_0}"
        out "  (keep the current session open until the key login is verified)"
        out ""
    fi
    if [[ "$MODE" == "audit" && $((N_WARN+N_CRIT)) -gt 0 ]]; then
        out "  next step: ${C_W}sudo bash $0 --fix${C_0}   (or interactively: sudo bash $0)"
    fi
    [[ -f "$BK_DIR/MANIFEST" ]] && out "  backups of every modified file: ${C_W}$BK_DIR${C_0}  (undo: $0 --rollback)"
    [[ -n "$REPORT_FILE" ]] && out "  full report saved to: ${C_W}$REPORT_FILE${C_0}"
    [[ -d "$QDIR" ]] && [[ -n "$(ls -A "$QDIR" 2>/dev/null | grep -v quarantine.log)" ]] \
        && out "  quarantined files: ${C_W}$QDIR${C_0}"
    out ""
    out "  ${C_DIM}docs & updates: https://antivirus.sh  |  star us: https://github.com/TARGET_PLEVEHOLDER/antivirus.sh${C_0}"
    out ""
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
antivirus.sh v$VERSION — Linux security scanner & hardening tool
https://antivirus.sh

USAGE:  sudo bash antivirus.sh [options]

MODES (default: interactive — every fix is confirmed):
  --audit            report only, change nothing
  --fix              apply all safe fixes automatically (risky ones still ask)
  --harden           full hardening for a fresh VM (firewall, SSH, sysctl,
                     fail2ban, auto-updates, auditd, policies, ...)
  --create-user      guided creation of a sudo user with an SSH key; the key
                     can be generated here and downloaded via a one-time
                     HTTPS link, or you paste your own public key
  --rollback [TS]    undo changes from the last (or given) run
  --install-tools    install ClamAV, rkhunter, chkrootkit

SCOPE (default: everything):
  --system           system checks only (accounts, SSH, sysctl, files, ...)
  --network          network checks only (ports, firewall, connections, DNS)
  --malware          malware checks only (files, processes, persistence)
  --scan PATH        scan a specific directory for malware
  --exclude PATH     exclude a path from scans (repeatable)

BEHAVIOUR:
  --quick            skip slow scans (full-disk find, ClamAV, rkhunter)
  --full             deepest scan: whole filesystem, all packages verified
  --yes, -y          assume "yes" for every question — INCLUDING RISKY FIXES
  --deliver key|archive  generated private key delivery: raw key file or an
                     AES-256 encrypted archive (default: ask)
  --key-ttl MIN      lifetime of the one-time download link (default: 10)
  --no-external      never run/suggest third-party scanners
  --report FILE      write the report to FILE
  --no-color         disable colored output
  --version          print version
  --help             this help

EXAMPLES:
  sudo bash antivirus.sh                     # interactive audit + fixes
  sudo bash antivirus.sh --audit             # safe read-only report
  sudo bash antivirus.sh --harden            # secure a brand-new VM
  sudo bash antivirus.sh --scan /var/www     # scan a web root for malware
  sudo bash antivirus.sh --fix --report r.txt
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)        MODE=audit ;;
            --fix)          MODE=fix ;;
            --harden)       MODE=harden ;;
            --interactive)  MODE=interactive ;;
            --create-user)  DO_CREATE_USER=1 ;;
            --install-tools) DO_INSTALL_TOOLS=1 ;;
            --rollback)     DO_ROLLBACK=1
                            [[ -n "${2:-}" && "$2" != --* ]] && { ROLLBACK_TS="$2"; shift; } ;;
            --system)       SCOPE_SYSTEM=1; SCOPE_ALL=0 ;;
            --network)      SCOPE_NETWORK=1; SCOPE_ALL=0 ;;
            --malware)      SCOPE_MALWARE=1; SCOPE_ALL=0 ;;
            --scan)         SCOPE_MALWARE=1; SCOPE_ALL=0
                            [[ -n "${2:-}" && "$2" != --* ]] && { SCAN_PATHS+=("$2"); shift; } ;;
            --exclude)      [[ -n "${2:-}" ]] && { EXCLUDE_PATHS+=("$2"); shift; } ;;
            --quick)        QUICK=1 ;;
            --full)         FULL=1 ;;
            --yes|-y)       ASSUME_YES=1 ;;
            --deliver)      case "${2:-}" in
                                key|archive) KEY_DELIVER="$2"; shift ;;
                                *) echo "--deliver needs 'key' or 'archive'" >&2; exit 2 ;;
                            esac ;;
            --key-ttl)      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "--key-ttl needs minutes" >&2; exit 2; }
                            KEY_TTL_MIN="$2"; shift ;;
            --no-external)  NO_EXTERNAL=1 ;;
            --report)       [[ -n "${2:-}" ]] && { REPORT_FILE="$2"; shift; } ;;
            --no-color)     NO_COLOR=1 ;;
            --version)      echo "antivirus.sh v$VERSION"; exit 0 ;;
            --help|-h)      usage; exit 0 ;;
            *)              echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
        esac
        shift
    done
    if [[ -z "$MODE" ]]; then
        if [[ -t 1 && -r /dev/tty ]]; then MODE=interactive; else MODE=audit; fi
    fi
}

banner() {
    local flags=""
    [[ "$QUICK" == 1 ]] && flags=" (quick)"
    [[ "$FULL"  == 1 ]] && flags="$flags (full)"
    out "${C_G}+------------------------------------------------------------+${C_0}"
    out "${C_G}|${C_0}  ${C_W}antivirus.sh v$VERSION${C_0} — Linux security scanner & hardening  ${C_G}|${C_0}"
    out "${C_G}|${C_0}  ${C_DIM}https://antivirus.sh${C_0}                                      ${C_G}|${C_0}"
    out "${C_G}+------------------------------------------------------------+${C_0}"
    out "  mode: ${C_W}$MODE$flags${C_0}"
}

main() {
    parse_args "$@"
    setup_colors
    detect_platform
    [[ "$DO_ROLLBACK" == 1 ]] && { init_dirs; do_rollback; }
    init_dirs
    banner

    if [[ "$DO_CREATE_USER" == 1 ]]; then
        run_create_user
        print_summary
        exit 0
    fi

    if [[ "$DO_INSTALL_TOOLS" == 1 && "$IS_ROOT" == 1 ]]; then
        hdr "Installing scanner tools"
        info "installing clamav, rkhunter, chkrootkit (this may take a few minutes)..."
        pkg_install clamav rkhunter chkrootkit && fixed "scanner tools installed" \
            || warn "some tools failed to install"
    fi

    # Pre-flight for hardening: make sure key-based admin access exists BEFORE
    # any SSH lockdown is offered — removes the lock-yourself-out dead end.
    if [[ "$MODE" == "harden" && "$IS_ROOT" == 1 && "$INTERACTIVE_TTY" == 1 ]] \
       && ! keybased_admin_exists; then
        hdr "Pre-flight: emergency-proof access"
        info "no sudo user with an SSH key exists — without one, key-only SSH cannot be enabled safely"
        if ask "create a sudo user with an SSH key now (downloadable via one-time HTTPS link)" y; then
            run_create_user
        else
            info "skipping — SSH lockdown will stay limited to safe changes"
        fi
    fi

    local run_sys=$SCOPE_ALL run_net=$SCOPE_ALL run_mal=$SCOPE_ALL
    [[ "$SCOPE_SYSTEM"  == 1 ]] && run_sys=1
    [[ "$SCOPE_NETWORK" == 1 ]] && run_net=1
    [[ "$SCOPE_MALWARE" == 1 ]] && run_mal=1

    chk_sysinfo
    [[ "$run_sys" == 1 ]] && chk_updates
    [[ "$run_sys" == 1 ]] && chk_accounts
    [[ "$run_sys" == 1 ]] && chk_ssh
    [[ "$run_net" == 1 ]] && chk_network
    [[ "$run_net" == 1 ]] && chk_firewall
    [[ "$run_sys" == 1 || "$run_net" == 1 ]] && chk_sysctl
    [[ "$run_sys" == 1 ]] && chk_fs_perms
    [[ "$run_mal" == 1 ]] && chk_persistence
    [[ "$run_mal" == 1 ]] && chk_processes
    [[ "$run_mal" == 1 ]] && chk_malware_files
    [[ "$run_mal" == 1 ]] && chk_external_scanners
    [[ "$run_sys" == 1 ]] && chk_docker
    [[ "$run_sys" == 1 ]] && chk_platform_services

    if [[ "$MODE" == "harden" && "$INTERACTIVE_TTY" == 1 && "$IS_ROOT" == 1 ]]; then
        if ! keybased_admin_exists && ask "create a dedicated sudo user with an SSH key now (recommended for new VMs)" y; then
            run_create_user
        fi
    fi

    print_summary

    if   (( N_CRIT > 0 )); then exit 2
    elif (( N_WARN > 0 )); then exit 1
    else exit 0
    fi
}

trap 'key_cleanup; echo; echo "interrupted — partial report: ${REPORT_FILE:-n/a}"; exit 130' INT TERM
trap 'key_cleanup' EXIT

main "$@"
