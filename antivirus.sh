#!/usr/bin/env bash
#
#  antivirus.sh — standalone antivirus & malware scanner for Linux servers
#  (extracted from the antivirus.sh security suite)
#
#  License : MIT
#
#  Quick start:
#      sudo bash antivirus.sh
#
#  What it does:
#    * scans files for malware, droppers, reverse shells and miners (bash heuristics)
#    * inspects processes for known malware names, miners, fileless and hidden processes
#    * audits persistence points: ld.so.preload, cron, systemd units, rc files,
#      udev rules, authorized_keys backdoors
#    * flags outbound connections to known mining-pool / IRC botnet ports
#    * verifies package integrity of security-critical system binaries
#    * runs external scanners when available: ClamAV, rkhunter, chkrootkit
#    * quarantines malicious files interactively or automatically (--fix)
#
#  Designed for Ubuntu; works in best-effort mode on Debian, RHEL/CentOS/Alma/
#  Rocky, Fedora, Arch, openSUSE and other systemd or sysvinit distributions.
#
VERSION="1.0.0"

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
MODE=""                  # interactive | audit | fix
QUICK=0
FULL=0
ASSUME_YES=0
NO_COLOR=0
NO_EXTERNAL=0
DO_INSTALL_TOOLS=0
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
OS_PRETTY=""
START_TS="$(date +%Y%m%d-%H%M%S)"

BASE_DIR="/var/lib/antivirus-whole"
LOG_DIR="/var/log/antivirus-whole"
QDIR=""

# Suspicious content patterns (reverse shells, droppers, miners, backdoors)
SUS_ERE='(/dev/tcp/|/dev/udp/|bash -i[[:space:]>]|sh -i[[:space:]>]|nc(\.traditional|\.openbsd)?[[:space:]][^|;]*-e[[:space:]]|ncat[[:space:]][^|;]*(-e[[:space:]]|--exec)|socat[[:space:]][^|;]*exec:|base64[[:space:]]+(-d|--decode)[^|;]*\|[[:space:]]*(ba|da|z)?sh|curl[^|;]*\|[[:space:]]*(ba|da|z)?sh|wget[^|;]*\|[[:space:]]*(ba|da|z)?sh|wget[^|;]*-O-[^|;]*\|[[:space:]]*sh|eval.*base64|stratum\+tcp|stratum\+ssl|xmrig|minerd|kdevtmpfsi|kinsing|kerberods|watchdogs|minexmr|supportxmr|nanopool\.org|moneroocean|c3pool|chmod[[:space:]]+\+?[0-7]*x?[[:space:]]+/tmp/|/dev/shm/[^[:space:]]*\.(sh|py|pl|elf|bin)|python[23]?[[:space:]]+-c[[:space:]].{0,40}socket|perl[[:space:]]+-e[[:space:]].{0,40}socket|exec[[:space:]]+[0-9]+<>/dev/tcp|LD_PRELOAD=)'

# Known malicious / miner process names
BAD_PROC_ERE='^(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|kerberods|watchdogs|ddgs|qW3xT|2t3ik|sysrv|sysrv012|tsm32|tsm64|kthreaddi|dbused|networkservice|sysupdate|sysguard|solrd|orgfs|pamdicks)$'

# Suspicious kernel modules (known rootkits)
BAD_KMOD_ERE='(diamorphine|reptile|suterusu|rootkit|adore|enyelkm|kbeast|wkmr|sysemptyrect)'

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
        note "this fix kills processes or quarantines files — review before confirming"
        if [[ "$INTERACTIVE_TTY" == 1 || "$ASSUME_YES" == 1 ]]; then
            if ask "RISKY fix: $fixtext — apply" n; then do_it=1; fi
        else
            reco "$fixtext (risky: re-run interactively or with --yes)"
            return 0
        fi
    else
        case "$MODE" in
            fix) do_it=1 ;;
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
# Platform detection, dirs, packages
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
}

init_dirs() {
    if [[ "$IS_ROOT" != 1 ]]; then
        BASE_DIR="${HOME}/.antivirus-whole"
        LOG_DIR="${HOME}/.antivirus-whole/log"
    fi
    mkdir -p "$BASE_DIR" "$LOG_DIR" 2>/dev/null
    QDIR="$BASE_DIR/quarantine"
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

# ---------------------------------------------------------------------------
# Quarantine & fix actions
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Check modules
# ---------------------------------------------------------------------------
chk_sysinfo() {
    hdr "System information"
    info "host: $(hostname 2>/dev/null)  |  $OS_PRETTY  |  kernel $(uname -r)"
    info "uptime:$(uptime 2>/dev/null | sed 's/.*up/ up/;s/,.*user.*//')"
    if [[ "$IS_ROOT" != 1 ]]; then
        warn "running WITHOUT root — coverage is limited (process owners, hidden-process test, fixes)"
        reco "re-run with: sudo bash $0"
    else
        ok "running as root — full coverage available"
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
    local nk uid
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
                # print fingerprints+comments so the review takes seconds
                ssh-keygen -lf "$f" 2>/dev/null | head -8 \
                    | while IFS= read -r l; do note "$l"; done
            fi
        done
    done < /etc/passwd
    reco "review every authorized_keys entry above — delete keys you do not recognize"

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

chk_connections() {
    hdr "Network: malware indicators"
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
    else
        info "ss not available — skipping connection check"
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
            local cl_out f
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
        if [[ "$DO_INSTALL_TOOLS" == 1 ]]; then
            offer_fix info 0 "extra scanners not installed: ${missing[*]}" \
                "install ${missing[*]} for signature-based & rootkit scanning" \
                pkg_install "${missing[@]}"
        else
            info "optional scanners not installed: ${missing[*]}"
            reco "install for deeper scans: sudo bash $0 --install-tools  (or: apt install ${missing[*]})"
        fi
    fi
}

print_summary() {
    local verdict
    if   (( N_CRIT > 0 )); then verdict="${C_R}INFECTED OR COMPROMISED — investigate the CRIT findings above${C_0}"
    elif (( N_WARN > 0 )); then verdict="${C_Y}suspicious findings — review the WARN items${C_0}"
    else                        verdict="${C_G}clean — no malware indicators found${C_0}"
    fi
    out ""
    out "${C_B}============================================================${C_0}"
    out "${C_W}  antivirus.sh v$VERSION — scan summary${C_0}"
    out "${C_B}============================================================${C_0}"
    out "  ${C_G}OK: $N_OK${C_0}   ${C_C}INFO: $N_INFO${C_0}   ${C_Y}WARN: $N_WARN${C_0}   ${C_R}CRIT: $N_CRIT${C_0}   ${C_G}FIXED: $N_FIXED${C_0}"
    out "  verdict: $verdict"
    if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
        out ""
        out "  ${C_M}Remaining recommendations:${C_0}"
        local r
        for r in "${RECOMMENDATIONS[@]}"; do
            out "   ${C_M}*${C_0} $r"
        done
    fi
    out ""
    if [[ "$MODE" == "audit" && $((N_WARN+N_CRIT)) -gt 0 ]]; then
        out "  next step: ${C_W}sudo bash $0 --fix${C_0}   (or interactively: sudo bash $0)"
    fi
    [[ -n "$REPORT_FILE" ]] && out "  full report saved to: ${C_W}$REPORT_FILE${C_0}"
    [[ -d "$QDIR" ]] && [[ -n "$(ls -A "$QDIR" 2>/dev/null | grep -v quarantine.log)" ]] \
        && out "  quarantined files: ${C_W}$QDIR${C_0}"
    out ""
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
antivirus.sh v$VERSION — standalone Linux antivirus & malware scanner

USAGE:  sudo bash antivirus.sh [options]

MODES (default: interactive — every fix is confirmed):
  --audit            report only, change nothing
  --fix              apply safe fixes automatically (risky ones still ask)
  --install-tools    install ClamAV, rkhunter, chkrootkit

SCOPE (default: standard malware paths):
  --scan PATH        scan a specific directory for malware (repeatable)
  --exclude PATH     exclude a path from scans (repeatable)

BEHAVIOUR:
  --quick            skip slow scans (ClamAV, rkhunter, hidden-process test)
  --full             deepest scan: whole filesystem, all packages verified
  --yes, -y          assume "yes" for every question — INCLUDING RISKY FIXES
  --no-external      never run/suggest third-party scanners
  --report FILE      write the report to FILE
  --no-color         disable colored output
  --version          print version
  --help             this help

EXAMPLES:
  sudo bash antivirus.sh                     # interactive scan + fixes
  sudo bash antivirus.sh --audit             # safe read-only report
  sudo bash antivirus.sh --scan /var/www     # scan a web root for malware
  sudo bash antivirus.sh --fix --report r.txt
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)        MODE=audit ;;
            --fix)          MODE=fix ;;
            --interactive)  MODE=interactive ;;
            --install-tools) DO_INSTALL_TOOLS=1 ;;
            --scan)         [[ -n "${2:-}" && "$2" != --* ]] && { SCAN_PATHS+=("$2"); shift; } ;;
            --exclude)      [[ -n "${2:-}" ]] && { EXCLUDE_PATHS+=("$2"); shift; } ;;
            --quick)        QUICK=1 ;;
            --full)         FULL=1 ;;
            --yes|-y)       ASSUME_YES=1 ;;
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
    out "${C_G}|${C_0}  ${C_W}antivirus.sh v$VERSION${C_0} — Linux antivirus & malware scanner ${C_G}|${C_0}"
    out "${C_G}+------------------------------------------------------------+${C_0}"
    out "  mode: ${C_W}$MODE$flags${C_0}"
}

main() {
    parse_args "$@"
    setup_colors
    detect_platform
    init_dirs
    banner

    if [[ "$DO_INSTALL_TOOLS" == 1 && "$IS_ROOT" == 1 ]]; then
        hdr "Installing scanner tools"
        info "installing clamav, rkhunter, chkrootkit (this may take a few minutes)..."
        pkg_install clamav rkhunter chkrootkit && fixed "scanner tools installed" \
            || warn "some tools failed to install"
    fi

    chk_sysinfo
    chk_persistence
    chk_processes
    chk_connections
    chk_malware_files
    chk_external_scanners

    print_summary

    if   (( N_CRIT > 0 )); then exit 2
    elif (( N_WARN > 0 )); then exit 1
    else exit 0
    fi
}

trap 'echo; echo "interrupted — partial report: ${REPORT_FILE:-n/a}"; exit 130' INT TERM

main "$@"
