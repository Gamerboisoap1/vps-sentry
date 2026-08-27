#!/usr/bin/env bash
#
# VPS Sentry installer for Debian / Ubuntu systems with systemd.
#
# Run this from the uploaded project directory as root:
#
#     sudo ./install.sh
#
# It installs to /opt/vps-sentry, creates an unprivileged service account,
# and starts a systemd unit bound to loopback. Re-running it is safe: every
# step checks its own state before acting.
#
# Uninstall with:  sudo ./install.sh --uninstall

set -euo pipefail

INSTALL_DIR="/opt/vps-sentry"
SERVICE_USER="sentry"
SERVICE_NAME="vps-sentry"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SUDOERS_FILE="/etc/sudoers.d/vps-sentry"
BIND_HOST="127.0.0.1"
BIND_PORT="8787"
F2B_JAIL="sshd"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- output ----

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; RESET=$'\033[0m'

step()  { printf '\n%s==>%s %s%s\n' "$BOLD" "$RESET" "$BOLD" "$1$RESET"; }
ok()    { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '    %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail()  { printf '    %s✗%s %s\n' "$RED" "$RESET" "$1"; exit 1; }
note()  { printf '    %s%s%s\n' "$DIM" "$1" "$RESET"; }

# ------------------------------------------------------------ uninstall ----

uninstall() {
    step "Removing VPS Sentry"
    systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$UNIT_FILE" "$SUDOERS_FILE"
    systemctl daemon-reload
    ok "service and sudoers rule removed"
    warn "left in place: $INSTALL_DIR (contains your database)"
    note "remove it with: rm -rf $INSTALL_DIR && userdel $SERVICE_USER"
    exit 0
}

[[ "${1:-}" == "--uninstall" ]] && uninstall

# ------------------------------------------------------------ preflight ----

step "Checking the environment"

[[ $EUID -eq 0 ]] || fail "must run as root — try: sudo ./install.sh"
command -v systemctl >/dev/null 2>&1 || fail "systemd not found; this installer targets systemd hosts"
command -v apt-get   >/dev/null 2>&1 || fail "apt-get not found; this installer targets Debian/Ubuntu"
[[ -f "$SRC_DIR/sentry/api.py" ]]  || fail "run this from inside the project directory"

ok "root, systemd, and apt available"

if [[ -e /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    note "host: ${PRETTY_NAME:-unknown}"
fi

# ---------------------------------------------------------- dependencies ----

step "Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip curl >/dev/null
ok "python3, venv, pip"

# rsyslog matters more than it looks: newer Ubuntu cloud images ship without
# it and log authentication only to journald, so /var/log/auth.log never
# exists and the SSH detector would sit silently at zero.
if [[ ! -f /var/log/auth.log ]]; then
    warn "/var/log/auth.log is missing — installing rsyslog to create it"
    apt-get install -y -qq rsyslog >/dev/null
    systemctl enable --now rsyslog >/dev/null 2>&1 || true
    sleep 2
    if [[ -f /var/log/auth.log ]]; then
        ok "auth.log now present"
    else
        warn "auth.log still missing; the dashboard will report the SSH parser as failed"
    fi
else
    ok "/var/log/auth.log present"
fi

if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed — installing it (the port-scan detector reads its log)"
    apt-get install -y -qq ufw >/dev/null
fi

# UFW logs blocked packets at the "low" level, which is all the scan detector
# needs. Enabling logging does not enable the firewall itself.
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi "logging: off" || [[ ! -f /var/log/ufw.log ]]; then
        ufw logging low >/dev/null 2>&1 || true
        ok "ufw logging enabled (low)"
    else
        ok "ufw logging already on"
    fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    ok "fail2ban present — ban status will be shown"
else
    warn "fail2ban not installed — alerts will show 'ban unknown'"
    note "install it with: apt-get install fail2ban"
fi

# ------------------------------------------------------- service account ----

step "Creating the service account"

# A monitoring daemon should not run as root. The 'adm' group is what grants
# read access to /var/log/auth.log and /var/log/ufw.log on Debian systems.
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    ok "user '$SERVICE_USER' already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "created system user '$SERVICE_USER'"
fi

usermod -aG adm "$SERVICE_USER"
ok "added '$SERVICE_USER' to the 'adm' group (log read access)"

# Least privilege for the fail2ban cross-check: one exact command, nothing
# else, rather than running the whole service as root for one status line.
if command -v fail2ban-client >/dev/null 2>&1; then
    F2B_PATH="$(command -v fail2ban-client)"
    printf '%s ALL=(root) NOPASSWD: %s status %s\n' "$SERVICE_USER" "$F2B_PATH" "$F2B_JAIL" > "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    if visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
        ok "sudoers rule written (only '$(basename "$F2B_PATH") status $F2B_JAIL')"
    else
        rm -f "$SUDOERS_FILE"
        warn "sudoers rule failed validation and was removed; ban status will read 'unknown'"
    fi
fi

# ------------------------------------------------------------- app files ----

step "Installing to $INSTALL_DIR"

mkdir -p "$INSTALL_DIR"
for item in sentry static tools requirements.txt README.md; do
    [[ -e "$SRC_DIR/$item" ]] && cp -r "$SRC_DIR/$item" "$INSTALL_DIR/"
done
mkdir -p "$INSTALL_DIR/data"
ok "application files copied"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
ok "virtualenv built and dependencies installed"

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR/data"
ok "ownership set to '$SERVICE_USER'"

# ------------------------------------------------------------- geolite2 ----

step "GeoIP database"

if [[ -f "$INSTALL_DIR/data/GeoLite2-Country.mmdb" ]]; then
    ok "GeoLite2-Country.mmdb already present"
elif [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
    note "downloading GeoLite2-Country with the supplied licence key"
    TMP="$(mktemp -d)"
    URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    if curl -fsSL "$URL" -o "$TMP/geo.tar.gz" && tar -xzf "$TMP/geo.tar.gz" -C "$TMP"; then
        found="$(find "$TMP" -name '*.mmdb' | head -1)"
        if [[ -n "$found" ]]; then
            install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0644 "$found" "$INSTALL_DIR/data/GeoLite2-Country.mmdb"
            ok "GeoLite2-Country.mmdb installed"
        else
            warn "archive contained no .mmdb file"
        fi
    else
        warn "download failed — check the licence key"
    fi
    rm -rf "$TMP"
else
    warn "no GeoLite2 database — alerts will show no country"
    note "to add it: get a free key at maxmind.com, then re-run with"
    note "  sudo MAXMIND_LICENSE_KEY=your_key ./install.sh"
fi

# -------------------------------------------------------------- service ----

step "Creating the systemd service"

cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=VPS Sentry - SSH brute force and port scan monitor
Documentation=file://$INSTALL_DIR/README.md
After=network.target rsyslog.service
Wants=rsyslog.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
SupplementaryGroups=adm
WorkingDirectory=$INSTALL_DIR

Environment=SENTRY_AUTH_LOG=/var/log/auth.log
Environment=SENTRY_UFW_LOG=/var/log/ufw.log
Environment=SENTRY_DB=$INSTALL_DIR/data/sentry.db
Environment=SENTRY_GEOIP_DB=$INSTALL_DIR/data/GeoLite2-Country.mmdb
Environment=SENTRY_F2B_JAIL=$F2B_JAIL
Environment=SENTRY_HOST=$BIND_HOST
Environment=SENTRY_PORT=$BIND_PORT
Environment=SENTRY_POLL_SECONDS=10

ExecStart=$INSTALL_DIR/.venv/bin/python -m uvicorn sentry.api:app --host $BIND_HOST --port $BIND_PORT
Restart=on-failure
RestartSec=5

# Hardening. NoNewPrivileges is deliberately NOT set: it would block the
# narrow sudo rule used for the fail2ban status check.
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR/data
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"
ok "unit installed and started"

sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "service is running"
else
    warn "service is not running — inspect with: journalctl -u $SERVICE_NAME -n 40"
fi

# ----------------------------------------------------------------- done ----

step "Done"

cat <<DONE

    VPS Sentry is listening on ${BIND_HOST}:${BIND_PORT}.

    It binds to loopback deliberately. Exposing it publicly would publish
    your log data and an unauthenticated endpoint on the machine you are
    trying to protect. Reach it from your laptop with an SSH tunnel:

        ${BOLD}ssh -N -L ${BIND_PORT}:127.0.0.1:${BIND_PORT} $(logname 2>/dev/null || echo user)@$(hostname -I 2>/dev/null | awk '{print $1}')${RESET}

    Then open ${BOLD}http://127.0.0.1:${BIND_PORT}${RESET} in your browser.

    Useful commands:
        systemctl status ${SERVICE_NAME}
        journalctl -u ${SERVICE_NAME} -f
        systemctl restart ${SERVICE_NAME}
        sudo ./install.sh --uninstall

DONE
