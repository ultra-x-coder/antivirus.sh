#!/usr/bin/env bash
#
#  mkuser-key.sh — create a sudo user with an ed25519 SSH key and serve the
#  private key over a one-time, self-expiring HTTPS link.
#
#  Companion tool for antivirus.sh — run this BEFORE disabling SSH root login
#  or password authentication, so you never lock yourself out.
#
#  Usage:
#      sudo bash mkuser-key.sh --user alice
#      sudo bash mkuser-key.sh --user alice --deliver archive --ttl 5
#
#  Delivery modes:
#      key      serve the raw private key file; its passphrase is printed in
#               this terminal only (two separate channels)
#      archive  serve an AES-256 encrypted archive (key + pubkey inside);
#               you decrypt it locally with the archive password
#
#  License: MIT
#
VERSION="1.0.0"

export LC_ALL=C LANG=C
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
umask 077

set -u

# ---------------------------------------------------------------------------
# Defaults / globals
# ---------------------------------------------------------------------------
USERNAME=""
ADD_SUDO=1
REISSUE=0                # allow existing user: only issue a new key
DELIVER=""               # key | archive
KEY_PASS_MODE=""         # random | ask
USER_PASS_MODE=""        # random | ask
ARCH_PASS_MODE=""        # random | ask
PORT=0
TTL_MIN=10
BIND_IP=""
PUBLIC_HOST=""
NO_SERVE=0

WORK=""
FW_KIND=""               # ufw | firewalld | ""
SERVE_FILE=""
SERVE_NAME=""
LOG_FILE=""
INTERACTIVE=0

C_R=$'\033[1;31m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'
C_W=$'\033[1;37m'; C_C=$'\033[1;36m'; C_0=$'\033[0m'
[[ -t 1 ]] || { C_R=""; C_G=""; C_Y=""; C_W=""; C_C=""; C_0=""; }

say()  { printf '%s\n' "$1"; }
ok()   { printf '  %s[ OK ]%s %s\n' "$C_G" "$C_0" "$1"; }
info() { printf '  %s[INFO]%s %s\n' "$C_C" "$C_0" "$1"; }
warn() { printf '  %s[WARN]%s %s\n' "$C_Y" "$C_0" "$1"; }
die()  { printf '  %s[FAIL]%s %s\n' "$C_R" "$C_0" "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Helpers
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

ask_pick() {  # ask_pick <question> <label1> <label2>  -> echoes 1 or 2
    local ans
    while true; do
        {
            printf '  %s\n' "$1"
            printf '    1) %s\n' "$2"
            printf '    2) %s\n' "$3"
            printf '  choice [1]: '
        } >&2
        IFS= read -r ans </dev/tty
        case "${ans:-1}" in
            1) echo 1; return 0 ;;
            2) echo 2; return 0 ;;
            *) echo "  please answer 1 or 2" >&2 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
mkuser-key.sh v$VERSION — create a sudo user + SSH key, serve it via one-time HTTPS link

USAGE:  sudo bash mkuser-key.sh --user NAME [options]

USER:
  --user NAME            username to create (required)
  --no-sudo              do not add the user to sudo/wheel
  --reissue              user already exists: only generate & install a new key
  --user-pass ask|random account password: type your own or auto-generate
                         (default: asked interactively)

KEY:
  --key-pass ask|random  passphrase of the ed25519 private key
                         (default: asked interactively)

DELIVERY:
  --deliver key|archive  key     = raw private key file, passphrase shown in
                                   this terminal only
                         archive = AES-256 encrypted .tar.gz.enc (key+pub inside)
                         (default: asked interactively)
  --archive-pass ask|random  password of the encrypted archive (archive mode)
  --ttl MIN              link lifetime in minutes (default: 10)
  --port N               HTTPS port (default: random 40000-60000)
  --bind-ip IP           serve the file ONLY to this client IP
  --public-host HOST     host/IP to put into the link (default: auto-detect)
  --no-serve             skip the HTTPS step; leave the key in /root instead

  --help                 this help
  --version              print version

EXAMPLES:
  sudo bash mkuser-key.sh --user alice
  sudo bash mkuser-key.sh --user alice --deliver archive --archive-pass ask
  sudo bash mkuser-key.sh --user alice --bind-ip 198.51.100.7 --ttl 5
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)         USERNAME="${2:-}"; shift ;;
            --no-sudo)      ADD_SUDO=0 ;;
            --reissue)      REISSUE=1 ;;
            --user-pass)    USER_PASS_MODE="${2:-}"; shift ;;
            --key-pass)     KEY_PASS_MODE="${2:-}"; shift ;;
            --deliver)      DELIVER="${2:-}"; shift ;;
            --archive-pass) ARCH_PASS_MODE="${2:-}"; shift ;;
            --ttl)          TTL_MIN="${2:-}"; shift ;;
            --port)         PORT="${2:-}"; shift ;;
            --bind-ip)      BIND_IP="${2:-}"; shift ;;
            --public-host)  PUBLIC_HOST="${2:-}"; shift ;;
            --no-serve)     NO_SERVE=1 ;;
            --version)      echo "mkuser-key.sh v$VERSION"; exit 0 ;;
            --help|-h)      usage; exit 0 ;;
            *)              die "unknown option: $1 (see --help)" ;;
        esac
        shift
    done
    [[ "$TTL_MIN" =~ ^[0-9]+$ ]] && (( TTL_MIN >= 1 )) || die "--ttl must be a positive integer (minutes)"
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "--port must be a number"
    case "$DELIVER"        in ""|key|archive) : ;; *) die "--deliver must be 'key' or 'archive'" ;; esac
    case "$KEY_PASS_MODE"  in ""|ask|random)  : ;; *) die "--key-pass must be 'ask' or 'random'" ;; esac
    case "$USER_PASS_MODE" in ""|ask|random)  : ;; *) die "--user-pass must be 'ask' or 'random'" ;; esac
    case "$ARCH_PASS_MODE" in ""|ask|random)  : ;; *) die "--archive-pass must be 'ask' or 'random'" ;; esac
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
check_env() {
    [[ "$(id -u)" == 0 ]] || die "this script must run as root (sudo bash $0 ...)"
    [[ -t 1 && -r /dev/tty ]] && INTERACTIVE=1

    command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen not found (install openssh-client)"
    command -v openssl    >/dev/null 2>&1 || die "openssl not found"
    command -v useradd    >/dev/null 2>&1 || die "useradd not found"
    if [[ "$NO_SERVE" != 1 ]]; then
        command -v python3 >/dev/null 2>&1 || die "python3 is required for the HTTPS server (or use --no-serve)"
    fi

    if [[ -z "$USERNAME" ]]; then
        [[ "$INTERACTIVE" == 1 ]] || die "--user NAME is required in non-interactive mode"
        printf '  new username: '
        IFS= read -r USERNAME </dev/tty
    fi
    [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
        || die "invalid username '$USERNAME' (lowercase letters, digits, - and _)"

    if id "$USERNAME" >/dev/null 2>&1; then
        [[ "$REISSUE" == 1 ]] || die "user '$USERNAME' already exists (use --reissue to issue a new key for them)"
    else
        [[ "$REISSUE" == 1 ]] && die "--reissue given but user '$USERNAME' does not exist"
    fi
}

resolve_modes() {
    # every unset mode: ask interactively when possible, otherwise safe default
    if [[ -z "$DELIVER" ]]; then
        if [[ "$INTERACTIVE" == 1 ]]; then
            case "$(ask_pick "How to deliver the private key?" \
                "raw key file over HTTPS; its passphrase stays in this terminal" \
                "AES-256 encrypted archive over HTTPS; you decrypt it locally")" in
                1) DELIVER=key ;;
                2) DELIVER=archive ;;
            esac
        else
            DELIVER=key
        fi
    fi
    if [[ -z "$KEY_PASS_MODE" ]]; then
        if [[ "$INTERACTIVE" == 1 ]]; then
            case "$(ask_pick "Passphrase for the SSH private key?" \
                "generate a strong random passphrase (shown once at the end)" \
                "I type my own passphrase now")" in
                1) KEY_PASS_MODE=random ;;
                2) KEY_PASS_MODE=ask ;;
            esac
        else
            KEY_PASS_MODE=random
        fi
    fi
    if [[ -z "$USER_PASS_MODE" && "$REISSUE" != 1 ]]; then
        if [[ "$INTERACTIVE" == 1 ]]; then
            case "$(ask_pick "Password for the new account '$USERNAME' (used by sudo)?" \
                "generate a strong random password (shown once at the end)" \
                "I type my own password now")" in
                1) USER_PASS_MODE=random ;;
                2) USER_PASS_MODE=ask ;;
            esac
        else
            USER_PASS_MODE=random
        fi
    fi
    if [[ "$DELIVER" == "archive" && -z "$ARCH_PASS_MODE" ]]; then
        if [[ "$INTERACTIVE" == 1 ]]; then
            case "$(ask_pick "Password for the encrypted archive?" \
                "generate a strong random password (shown once at the end)" \
                "I type my own password now")" in
                1) ARCH_PASS_MODE=random ;;
                2) ARCH_PASS_MODE=ask ;;
            esac
        else
            ARCH_PASS_MODE=random
        fi
    fi
}

# ---------------------------------------------------------------------------
# Cleanup — runs on every exit path (success, timeout, Ctrl-C)
# ---------------------------------------------------------------------------
close_firewall() {
    case "$FW_KIND" in
        ufw)       ufw delete allow "$PORT/tcp" >/dev/null 2>&1 ;;
        firewalld) firewall-cmd --remove-port="$PORT/tcp" >/dev/null 2>&1 ;;
    esac
    FW_KIND=""
}

cleanup() {
    close_firewall
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        if command -v shred >/dev/null 2>&1; then
            find "$WORK" -type f -exec shred -fu {} + 2>/dev/null
        fi
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
create_user() {
    [[ "$REISSUE" == 1 ]] && { info "user '$USERNAME' exists — reissue mode, skipping creation"; return 0; }

    useradd -m -s /bin/bash "$USERNAME" || die "useradd failed"
    ok "user '$USERNAME' created"

    if [[ "$ADD_SUDO" == 1 ]]; then
        local grp=sudo
        getent group sudo >/dev/null 2>&1 || grp=wheel
        usermod -aG "$grp" "$USERNAME" && ok "added to group '$grp'"
    fi

    if [[ "$USER_PASS_MODE" == "ask" ]]; then
        USER_PW="$(ask_secret "password for '$USERNAME'" 8)"
        USER_PW_SHOWN=0
    else
        USER_PW="$(rand_pw 20)"
        USER_PW_SHOWN=1
    fi
    echo "$USERNAME:$USER_PW" | chpasswd || die "chpasswd failed"
    ok "account password set"
}

generate_key() {
    KEY_FILE="$WORK/${USERNAME}_ed25519"
    SERVE_NAME="${USERNAME}_ed25519"

    if [[ "$KEY_PASS_MODE" == "ask" ]]; then
        KEY_PASS="$(ask_secret "passphrase for the SSH key" 8)"
        KEY_PASS_SHOWN=0
    else
        KEY_PASS="$(rand_pw 24)"
        KEY_PASS_SHOWN=1
    fi

    ssh-keygen -t ed25519 -a 100 -f "$KEY_FILE" -N "$KEY_PASS" \
        -C "${USERNAME}@$(hostname -s 2>/dev/null || echo vps)-$(date +%Y%m%d)" >/dev/null \
        || die "ssh-keygen failed"
    KEY_FP="$(ssh-keygen -lf "$KEY_FILE.pub" 2>/dev/null | awk '{print $2}')"
    ok "ed25519 key generated (fingerprint: $KEY_FP)"

    local home sshdir
    home="$(getent passwd "$USERNAME" | awk -F: '{print $6}')"
    [[ -n "$home" ]] || die "cannot determine home directory of $USERNAME"
    sshdir="$home/.ssh"
    mkdir -p "$sshdir"
    cat "$KEY_FILE.pub" >> "$sshdir/authorized_keys"
    chmod 700 "$sshdir"
    chmod 600 "$sshdir/authorized_keys"
    chown -R "$USERNAME:$USERNAME" "$sshdir"
    ok "public key installed to $sshdir/authorized_keys"
}

prepare_payload() {
    if [[ "$DELIVER" == "key" ]]; then
        SERVE_FILE="$KEY_FILE"
        return 0
    fi

    # archive mode: tar (private + public key) -> AES-256-CBC with PBKDF2
    if [[ "$ARCH_PASS_MODE" == "ask" ]]; then
        ARCH_PASS="$(ask_secret "password for the encrypted archive" 8)"
        ARCH_PASS_SHOWN=0
    else
        ARCH_PASS="$(rand_pw 24)"
        ARCH_PASS_SHOWN=1
    fi

    SERVE_NAME="${USERNAME}_keys.tar.gz.enc"
    SERVE_FILE="$WORK/$SERVE_NAME"
    tar -C "$WORK" -czf "$WORK/payload.tar.gz" \
        "${USERNAME}_ed25519" "${USERNAME}_ed25519.pub" || die "tar failed"
    MK_ARCH_PASS="$ARCH_PASS" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
        -in "$WORK/payload.tar.gz" -out "$SERVE_FILE" -pass env:MK_ARCH_PASS \
        || die "openssl encryption failed"
    rm -f "$WORK/payload.tar.gz"
    ok "AES-256 encrypted archive prepared ($SERVE_NAME)"
}

detect_public_host() {
    [[ -n "$PUBLIC_HOST" ]] && return 0
    # 3rd field of SSH_CONNECTION = server address the client connected to
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        PUBLIC_HOST="$(awk '{print $3}' <<<"$SSH_CONNECTION")"
    fi
    if [[ -z "$PUBLIC_HOST" ]] && command -v curl >/dev/null 2>&1; then
        PUBLIC_HOST="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    fi
    if [[ -z "$PUBLIC_HOST" ]]; then
        PUBLIC_HOST="$(ip route get 1.1.1.1 2>/dev/null \
            | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')"
    fi
    [[ -n "$PUBLIC_HOST" ]] || die "cannot detect the public IP — pass it via --public-host"
}

pick_port() {
    if (( PORT > 0 )); then
        ss -tln 2>/dev/null | grep -qE "[:.]$PORT([[:space:]]|$)" \
            && die "port $PORT is already in use"
        return 0
    fi
    local _i p
    for _i in $(seq 1 50); do
        p=$(( (RANDOM % 20001) + 40000 ))
        if ! ss -tln 2>/dev/null | grep -qE "[:.]$p([[:space:]]|$)"; then
            PORT=$p
            return 0
        fi
    done
    die "could not find a free port in 40000-60000"
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$PORT/tcp" comment 'mkuser-key temporary' >/dev/null 2>&1 && FW_KIND=ufw
        info "ufw: temporarily allowed port $PORT/tcp (closed automatically on exit)"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --add-port="$PORT/tcp" >/dev/null 2>&1 && FW_KIND=firewalld
        info "firewalld: temporarily opened port $PORT/tcp (closed automatically on exit)"
    else
        info "no local firewall to adjust; if your cloud provider filters traffic,"
        info "allow inbound TCP $PORT in its security group for the next $TTL_MIN minute(s)"
    fi
}

make_cert() {
    local san
    if [[ "$PUBLIC_HOST" =~ ^[0-9.]+$ || "$PUBLIC_HOST" == *:* ]]; then
        san="subjectAltName=IP:$PUBLIC_HOST"
    else
        san="subjectAltName=DNS:$PUBLIC_HOST"
    fi
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
        -subj "/CN=$PUBLIC_HOST" -addext "$san" >/dev/null 2>&1 \
    || openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
        -subj "/CN=$PUBLIC_HOST" >/dev/null 2>&1 \
    || die "openssl certificate generation failed"
    CERT_FP="$(openssl x509 -in "$WORK/tls.crt" -noout -fingerprint -sha256 2>/dev/null \
               | sed 's/^.*Fingerprint=//')"
}

write_server() {
    cat > "$WORK/server.py" <<'PYEOF'
import http.server, os, ssl, sys, threading

token  = os.environ["MK_TOKEN"]
fpath  = os.environ["MK_FILE"]
fname  = os.environ["MK_NAME"]
port   = int(os.environ["MK_PORT"])
ttl    = int(os.environ["MK_TTL"])
allow  = os.environ.get("MK_ALLOW", "")
cert   = os.environ["MK_CERT"]
keyf   = os.environ["MK_KEYF"]
logf   = os.environ["MK_LOG"]

state = {"served": False}
lock = threading.Lock()

def log(line):
    with lock:
        with open(logf, "a") as f:
            f.write(line + "\n")

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "mkuser-key"
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

print_secrets() {
    say ""
    say "${C_W}============================================================${C_0}"
    say "${C_W}  CREDENTIALS — shown ONCE, stored NOWHERE on this server${C_0}"
    say "${C_W}============================================================${C_0}"
    say "  user:              ${C_W}$USERNAME${C_0}$( [[ "$ADD_SUDO" == 1 && "$REISSUE" != 1 ]] && echo ' (sudo)')"
    if [[ "$REISSUE" != 1 && "${USER_PW_SHOWN:-0}" == 1 ]]; then
        say "  account password:  ${C_G}$USER_PW${C_0}   (needed for sudo)"
    fi
    say "  key fingerprint:   $KEY_FP"
    if [[ "${KEY_PASS_SHOWN:-0}" == 1 ]]; then
        say "  key passphrase:    ${C_G}$KEY_PASS${C_0}"
    else
        say "  key passphrase:    (the one you typed)"
    fi
    if [[ "$DELIVER" == "archive" ]]; then
        if [[ "${ARCH_PASS_SHOWN:-0}" == 1 ]]; then
            say "  archive password:  ${C_G}$ARCH_PASS${C_0}"
        else
            say "  archive password:  (the one you typed)"
        fi
    fi
    say ""
    say "  ${C_Y}save these in a password manager NOW${C_0}"
}

print_download_help() {
    local url="https://$PUBLIC_HOST:$PORT/$TOKEN/$SERVE_NAME"
    say ""
    say "${C_W}============================================================${C_0}"
    say "${C_W}  DOWNLOAD LINK — one-time, expires in $TTL_MIN minute(s)${C_0}"
    say "${C_W}============================================================${C_0}"
    say "  ${C_G}$url${C_0}"
    say ""
    say "  TLS certificate SHA256 fingerprint (verify before trusting):"
    say "  ${C_C}$CERT_FP${C_0}"
    [[ -n "$BIND_IP" ]] && say "  served ONLY to client IP: $BIND_IP"
    say ""
    say "  Browser: accept the self-signed certificate warning, but FIRST"
    say "  compare its fingerprint with the value above."
    say ""
    say "  Or from your machine's terminal:"
    say "    # 1) check the certificate fingerprint:"
    say "    openssl s_client -connect $PUBLIC_HOST:$PORT </dev/null 2>/dev/null \\"
    say "      | openssl x509 -noout -fingerprint -sha256"
    say "    # 2) download:"
    say "    curl -k -o $SERVE_NAME '$url'"
    if [[ "$DELIVER" == "archive" ]]; then
        say "    # 3) decrypt and unpack:"
        say "    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \\"
        say "      -in $SERVE_NAME -out keys.tar.gz    # asks the archive password"
        say "    tar xzf keys.tar.gz && rm keys.tar.gz $SERVE_NAME"
        say "    chmod 600 ${USERNAME}_ed25519"
    else
        say "    # 3) protect the file:"
        say "    chmod 600 $SERVE_NAME"
    fi
    say ""
}

print_final_instructions() {
    say ""
    say "${C_Y}============================================================${C_0}"
    say "${C_Y}  BEFORE you disable root login / password authentication:${C_0}"
    say "${C_Y}============================================================${C_0}"
    say "  1. open a NEW terminal on your machine (keep this session alive!)"
    say "  2. test the key login:"
    say "       ${C_W}ssh -i ${USERNAME}_ed25519 $USERNAME@$PUBLIC_HOST${C_0}"
    say "     (it will ask the KEY passphrase, then 'sudo -i' asks the ACCOUNT password)"
    say "  3. only after a successful login run the hardening, e.g.:"
    say "       sudo bash antivirus.sh --harden"
    say ""
    say "  undo hint: this user can be removed with: userdel -r $USERNAME"
    say "  access log of the download server: ${LOG_FILE:-n/a}"
    say ""
}

serve() {
    TOKEN="$(rand_str 32 'a-f0-9')"
    LOG_FILE="/var/log/mkuser-key-$(date +%Y%m%d-%H%M%S).log"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE="$WORK/access.log"

    detect_public_host
    pick_port
    make_cert
    write_server
    open_firewall

    print_secrets
    print_download_help
    info "waiting for the download (Ctrl-C aborts and wipes the key)..."

    local rc=0
    MK_TOKEN="$TOKEN" MK_FILE="$SERVE_FILE" MK_NAME="$SERVE_NAME" \
    MK_PORT="$PORT" MK_TTL="$(( TTL_MIN * 60 ))" MK_ALLOW="$BIND_IP" \
    MK_CERT="$WORK/tls.crt" MK_KEYF="$WORK/tls.key" MK_LOG="$LOG_FILE" \
        python3 "$WORK/server.py" || rc=$?

    close_firewall
    case "$rc" in
        0)
            ok "private key downloaded — it is now being wiped from this server"
            ;;
        3)
            warn "link expired, nothing was downloaded — the key is wiped"
            warn "the public key stays in authorized_keys; issue a fresh private key with:"
            warn "  sudo bash $0 --user $USERNAME --reissue"
            ;;
        *)
            warn "download server exited unexpectedly (code $rc) — the key is wiped"
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    say ""
    say "${C_G}mkuser-key.sh v$VERSION${C_0} — sudo user + SSH key + one-time HTTPS delivery"
    say ""
    check_env
    resolve_modes

    # workdir on tmpfs when possible, so the private key never touches the disk
    WORK="$(mktemp -d /dev/shm/mkuser-key.XXXXXX 2>/dev/null || mktemp -d /tmp/mkuser-key.XXXXXX)" \
        || die "cannot create a working directory"
    chmod 700 "$WORK"

    create_user
    generate_key
    prepare_payload

    if [[ "$NO_SERVE" == 1 ]]; then
        local out="/root/${SERVE_NAME}"
        cp "$SERVE_FILE" "$out" && chmod 600 "$out"
        print_secrets
        ok "--no-serve: payload left at $out — move it off this server and delete it"
        print_final_instructions
        exit 0
    fi

    serve
    print_final_instructions
}

main "$@"
