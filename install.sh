#!/usr/bin/env bash
# ReRust Agent installer for Ubuntu 26.04 - installs, updates or removes the agent on a game machine.
#
#   curl -fsSL https://github.com/Zand3rsCode/rerust-agent/releases/download/v<version>/install.sh | sudo bash -s -- --panel-ip <panel IP>
#   (the panel's Settings -> Machines shows the same with the installer's checksum)
#
# Options:
#   --panel-ip IP        the panel's address (repeat for more); only it may reach the agent's port
#   --port N             the agent's HTTPS port (default 443)
#   --replace-php-agent  switch off an older ReRust (PHP) install on this machine first; its server folders in
#                        /srv/rust stay and are taken over (same names)
#   --no-firewall        leave the firewall alone
#   --yes                don't ask
#   --uninstall          remove the agent (game servers' folders in /srv/rust stay unless --delete-servers)
#
# What it installs: the agent (/opt/rerust-agent, root's), DepotDownloader (/opt/depotdownloader, a pinned version),
# two users - rerust-agent (the agent) and rerust (the game servers) -, the systemd units rerust-agent.socket +
# .service, rerust-server@.service (one per Rust server, each sees only its own folder), rerust-agent-update.service
# (installs signed updates), a polkit rule (the agent may start/stop only its servers' units) and firewall rules
# (ufw). No PHP, web server, database or certbot. The agent's download is checked against SHA256SUMS, and
# SHA256SUMS against the release signature, before anything is installed.
set -euo pipefail

VERSION="@VERSION@"
REPO="Zand3rsCode/rerust-agent"
# Verifies SHA256SUMS of every release (Ed25519). The same key is built into the agent.
RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAq8p9/zFiaGIkdaZ6RXUimLVSZ8woEY9/AW7yKbWIIYg=
-----END PUBLIC KEY-----'

# DepotDownloader (fetches Rust from Steam): a pinned release, checked by its SHA-256.
DD_VERSION=3.4.0
DD_SHA256_X64=a999dec66b4850fc961bd50366696d23c2d0fad7b18790e6a5647b2f19097a53
DD_SHA256_ARM64=d9fb612ccebc1db8eeea3b4045d2221ec70431381393ce908fb72f01d4f9c812

APP_DIR=/opt/rerust-agent
BIN=$APP_DIR/rerust-agent
CFG_DIR=/etc/rerust-agent
STATE_DIR=/var/lib/rerust-agent
BASE_DIR=/srv/rust
DD_DIR=/opt/depotdownloader
UNIT_DIR=/etc/systemd/system
POLKIT_RULE=/etc/polkit-1/rules.d/50-rerust-agent.rules
AGENT_USER=rerust-agent
GAME_USER=rerust
FW_AGENT='ReRust panel -> agent'
FW_GAME='Rust server 1: game + query'
FW_RUSTPLUS='Rust server 1: Rust+'

PANEL_IPS=() PORT=443 REPLACE_PHP=0 FIREWALL=1 YES=0 UNINSTALL=0 DELETE_SERVERS=0 LOCAL_BINARY=""

say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m  %s\n' "$*"; }
note() { printf '  \033[36m..\033[0m  %s\n' "$*"; }
warn() { printf '  \033[33m!!\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[31mStopped:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# Questions come from the terminal even when this script arrives through a pipe.
confirm() {
    [[ $YES -eq 1 ]] && return 0
    [[ -r /dev/tty ]] || die "can't ask \"$1\" without a terminal - add --yes"
    local answer
    read -r -p "  $1 [y/N] " answer </dev/tty || true
    [[ $answer =~ ^[Yy] ]]
}

# 1 - 65535, no leading zeros (0443 is not 443 everywhere).
valid_port() {
    [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 ))
}

# One address or a small network: never 0.0.0.0, ::, or a range wider than /16 (IPv4) or /48 (IPv6).
valid_panel_ip() {
    local ip=$1 addr prefix="" octet
    addr=${ip%/*}
    [[ $ip == */* ]] && prefix=${ip#*/}
    [[ -z $prefix || $prefix =~ ^[0-9]{1,3}$ ]] || return 1
    if [[ $addr =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for octet in "${BASH_REMATCH[@]:1}"; do
            [[ $octet =~ ^(0|[1-9][0-9]*)$ ]] && (( 10#$octet <= 255 )) || return 1
        done
        [[ $addr != 0.0.0.0 ]] || return 1
        [[ -z $prefix ]] || (( 10#$prefix >= 16 && 10#$prefix <= 32 )) || return 1
        return 0
    fi
    if [[ $addr == *:* && $addr =~ ^[0-9a-fA-F:]+$ ]]; then
        [[ $addr =~ [1-9a-fA-F] ]] || return 1   # ::, ::0 ...
        [[ -z $prefix ]] || (( 10#$prefix >= 48 && 10#$prefix <= 128 )) || return 1
        return 0
    fi
    return 1
}

parse_args() {
    while (( $# > 0 )); do
        case $1 in
            --panel-ip) PANEL_IPS+=("${2:?--panel-ip needs an address}"); shift 2 ;;
            --port) PORT=${2:?--port needs a number}; shift 2 ;;
            --replace-php-agent) REPLACE_PHP=1; shift ;;
            --no-firewall) FIREWALL=0; shift ;;
            --yes|-y) YES=1; shift ;;
            --uninstall) UNINSTALL=1; shift ;;
            --delete-servers) DELETE_SERVERS=1; shift ;;
            --binary) LOCAL_BINARY=${2:?}; shift 2 ;;   # development only: install this file instead of a release
            --version) VERSION=${2#v}; shift 2 ;;
            -h|--help) sed -n '2,23p' "$0" 2>/dev/null || true; exit 0 ;;
            *) die "unknown option $1 (see --help)" ;;
        esac
    done
    valid_port "$PORT" || die "--port must be 1 - 65535 (no leading zeros)"
    local ip
    for ip in "${PANEL_IPS[@]}"; do
        valid_panel_ip "$ip" || die "--panel-ip $ip is not one address (or a network of at most /16 for IPv4, /48 for IPv6)"
    done
}

# The rules ufw has with exactly this comment, as "allow ..." lines (the comment is compared as text - it has a +).
ufw_rules_with() {
    command -v ufw >/dev/null || return 0
    ufw show added 2>/dev/null | awk -v c=" comment '$1'" '
        substr($0, 1, 4) == "ufw " && length($0) > length(c) + 4 && substr($0, length($0) - length(c) + 1) == c {
            print substr($0, 5, length($0) - 4 - length(c))
        }' || true
}

delete_ufw_rules_with() {   # prints how many were removed
    local rule removed=0 args
    while IFS= read -r rule; do
        [[ -n $rule ]] || continue
        read -r -a args <<<"$rule"
        ufw --force delete "${args[@]}" >/dev/null && removed=$((removed + 1))
    done < <(ufw_rules_with "$1")
    printf '%s' "$removed"
}

active_server_units() {
    systemctl list-units 'rerust-server@*.service' --state=active,activating,deactivating --plain --no-legend 2>/dev/null \
        | awk '{ print $1 }' || true
}

# Runs a program as the agent's user (never root: SECURITY.md A3).
as_agent() { runuser -u "$AGENT_USER" -- "$@"; }

# --- units -------------------------------------------------------------------------------------------------------------
# Each is printed by its own function (tests check them with systemd-analyze).

unit_socket() {
    cat <<EOF
[Unit]
Description=ReRust Agent - HTTPS port for the panel

[Socket]
# systemd opens the port, so the agent needs no capability for it (and Rust servers inherit none).
ListenStream=$PORT
BindIPv6Only=both
NoDelay=true

[Install]
WantedBy=sockets.target
EOF
}

# Hardening shared by the agent and the game servers.
unit_sandbox() {
    cat <<EOF
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
EOF
}

unit_agent() {
    cat <<EOF
[Unit]
Description=ReRust Agent (runs Rust servers for a ReRust panel)
Requires=rerust-agent.socket
After=rerust-agent.socket network-online.target
Wants=network-online.target

[Service]
User=$AGENT_USER
Group=$AGENT_USER
# The game's group: the agent and the game servers both work in the server folders.
SupplementaryGroups=$GAME_USER
ExecStart=$BIN serve --config $CFG_DIR/config.json
Restart=always
RestartSec=3
# Game servers are their own units (rerust-server@...): restarting the agent never touches them.
# A DepotDownloader killed for memory must not take the agent down.
OOMPolicy=continue
UMask=0007
Environment=HOME=$STATE_DIR DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_BUNDLE_EXTRACT_BASE_DIR=$STATE_DIR/dotnet
ReadWritePaths=$BASE_DIR $STATE_DIR
$(unit_sandbox)

[Install]
WantedBy=multi-user.target
EOF
}

unit_server() {
    cat <<EOF
[Unit]
Description=ReRust: Rust server %i
After=network-online.target
Wants=network-online.target

[Service]
User=$GAME_USER
Group=$GAME_USER
# Reads .rerust/launch.json (written by the agent) and becomes RustDedicated.
ExecStart=$BIN launch --dir $BASE_DIR/%i
# The panel restarts crashed servers itself (Crash Recovery).
Restart=no
LimitNOFILE=65535
UMask=0007
# Only its own folder: no other server, no backups, nothing of the agent.
TemporaryFileSystem=$BASE_DIR
BindPaths=$BASE_DIR/%i
ReadWritePaths=$BASE_DIR/%i
InaccessiblePaths=-$STATE_DIR -$CFG_DIR -$DD_DIR
ProtectProc=invisible
$(unit_sandbox)
EOF
}

unit_update() {
    cat <<EOF
[Unit]
Description=ReRust Agent update (installs a signed release the agent downloaded)

[Service]
Type=oneshot
# Checks the signature, the version and the checksum itself - it trusts nothing the agent left there.
ExecStart=$BIN install-update --config $CFG_DIR/config.json
RuntimeDirectory=rerust-agent-update
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
UMask=0022
NoNewPrivileges=yes
# Root, but only to read the agent's update folder and write its own program.
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
ProtectSystem=strict
ReadWritePaths=$APP_DIR -$STATE_DIR/update
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
EOF
}

# polkit: the agent's user may start/stop/kill its game servers' units (and pin them to cores), and start its own
# update step - nothing else. Verbs as systemd passes them to polkit.
polkit_rule() {
    cat <<EOF
// ReRust Agent (installed by its install.sh)
polkit.addRule(function (action, subject) {
    if (action.id !== "org.freedesktop.systemd1.manage-units" || subject.user !== "$AGENT_USER") {
        return polkit.Result.NOT_HANDLED;
    }
    var unit = action.lookup("unit") || "";
    var verb = action.lookup("verb") || "";
    if (/^rerust-server@[a-z0-9][a-z0-9_-]{1,31}\.service$/.test(unit) &&
        ["start", "stop", "restart", "kill", "reset-failed", "set-property"].indexOf(verb) >= 0) {
        return polkit.Result.YES;
    }
    if (unit === "rerust-agent-update.service" && verb === "start") {
        return polkit.Result.YES;
    }
    return polkit.Result.NOT_HANDLED;
});
EOF
}

# --- uninstall ---------------------------------------------------------------------------------------------------------

uninstall() {
    step "Removing the ReRust Agent"
    local running
    running=$(active_server_units)
    if [[ -n $running ]]; then
        warn "Rust servers are running: $(paste -sd, <<<"$running")"
        confirm "Stop them and remove the agent? (Stop them in the panel first to save the worlds.)" || die "cancelled - nothing was removed"
        # shellcheck disable=SC2086
        systemctl stop $running || true
        ok "stopped the Rust servers"
    elif pgrep -x RustDedicated >/dev/null; then
        warn "RustDedicated runs outside the agent ($(pgrep -x RustDedicated | paste -sd, -)) - it is left alone."
    fi
    systemctl disable --now rerust-agent.socket rerust-agent.service >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/rerust-agent.socket" "$UNIT_DIR/rerust-agent.service" "$UNIT_DIR/rerust-agent-update.service" \
        "$UNIT_DIR/rerust-server@.service" "$POLKIT_RULE"
    systemctl daemon-reload
    systemctl reset-failed 'rerust-server@*' >/dev/null 2>&1 || true
    ok "removed the services and the polkit rule"
    rm -rf "$APP_DIR" "$CFG_DIR" "$STATE_DIR" "$DD_DIR" /run/rerust-agent-update
    ok "removed $APP_DIR, $CFG_DIR, $STATE_DIR, $DD_DIR"
    if command -v ufw >/dev/null; then
        local removed=0 comment
        for comment in "$FW_AGENT" "$FW_GAME" "$FW_RUSTPLUS"; do
            removed=$((removed + $(delete_ufw_rules_with "$comment")))
        done
        (( removed == 0 )) || ok "removed $removed firewall rule(s) (ufw stays on with SSH and your other rules)"
    fi
    id "$AGENT_USER" >/dev/null 2>&1 && userdel "$AGENT_USER" 2>/dev/null && ok "removed the $AGENT_USER user"
    if [[ $DELETE_SERVERS -eq 1 ]]; then
        if confirm "Delete every server folder in $BASE_DIR (worlds, plugins, backups)?"; then
            rm -rf "$BASE_DIR"
            ok "deleted $BASE_DIR"
            id "$GAME_USER" >/dev/null 2>&1 && userdel "$GAME_USER" 2>/dev/null && ok "removed the $GAME_USER user"
        fi
    elif [[ -d $BASE_DIR ]]; then
        chown root:root "$BASE_DIR" 2>/dev/null || true
        note "kept the server folders in $BASE_DIR and the $GAME_USER user (--delete-servers removes them)"
    fi
    say ""; say "Done. Packages (curl, ufw ...) were left installed."
}

# --- install -----------------------------------------------------------------------------------------------------------

check_machine() {
    step "Checking this machine"
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null || true
    if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 26.04 ]]; then ok "${PRETTY_NAME}"
    else warn "made for Ubuntu 26.04 - this is ${PRETTY_NAME:-unknown}; it may still work"; fi
    case $(uname -m) in
        x86_64) ARCH=amd64 DD_ARCH=x64 DD_SHA256=$DD_SHA256_X64 ;;
        aarch64) ARCH=arm64 DD_ARCH=arm64 DD_SHA256=$DD_SHA256_ARM64
                 warn "arm64: the agent runs, but Rust's dedicated server only exists for x86_64" ;;
        *) die "unsupported CPU $(uname -m)" ;;
    esac
    [[ $VERSION == "@VERSION@" && -z $LOCAL_BINARY ]] && die "this copy of install.sh has no version - use the one from a release, or --version x.y.z"
    if (( ${#PANEL_IPS[@]} == 0 )); then
        if [[ -f $CFG_DIR/config.json ]]; then
            mapfile -t PANEL_IPS < <(sed -n '/"allowed_ips"/,/]/p' "$CFG_DIR/config.json" | grep -oE '"[0-9a-fA-F:.]+(/[0-9]+)?"' | tr -d '"')
            local ip
            for ip in "${PANEL_IPS[@]}"; do valid_panel_ip "$ip" || die "the last install's panel address $ip is not accepted any more - give --panel-ip"; done
        fi
        (( ${#PANEL_IPS[@]} > 0 )) && ok "panel address(es) from the last install: ${PANEL_IPS[*]}" \
            || die "give the panel's IP address: --panel-ip <ip> (only it may use the agent)"
    fi

    # An older ReRust (PHP) install on this machine.
    PHP_UNITS=()
    local u
    for u in rerust-monitor rerust-worker-control rerust-worker-long rerust-php-fpm rerust-keeper; do
        systemctl cat "$u.service" >/dev/null 2>&1 && PHP_UNITS+=("$u")
    done
    if (( ${#PHP_UNITS[@]} > 0 )); then
        [[ $REPLACE_PHP -eq 1 ]] || die "an older ReRust (PHP) install is on this machine (${PHP_UNITS[*]}). Run again with --replace-php-agent to switch it off and take over its servers (folders in /srv/rust stay), or remove it first."
        note "an older ReRust (PHP) install is here (${PHP_UNITS[*]}) - it will be switched off; /srv/rust stays"
        if pgrep -x RustDedicated >/dev/null; then
            warn "Rust servers started by the old install are running - the new agent runs each server as its own service and can't control these. Stop them in the panel first."
            confirm "Continue anyway (they keep running until you stop them by hand)?" || die "cancelled - nothing was changed"
        fi
    fi

    # Nothing else may hold the agent's port.
    STOP_NGINX=0
    local port_user
    port_user=$(ss -Hltnp "sport = :$PORT" 2>/dev/null | grep -oE 'users:\(\("[^"]+' | head -n1 | sed 's/.*"//' || true)
    if [[ -n $port_user && $port_user != systemd && $port_user != rerust-agent ]]; then
        if [[ $REPLACE_PHP -eq 1 && $port_user == nginx ]]; then
            local other
            other=$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name 'rerust*' -printf '%f ' 2>/dev/null || true)
            [[ -z $other ]] || die "nginx holds port $PORT and also serves other sites ($other) - use another port for the agent: --port 8443"
            note "nginx holds port $PORT and serves only the old ReRust site"
            confirm "Stop and switch off nginx (the old install's web server)?" || die "cancelled - use another port for the agent: --port 8443"
            STOP_NGINX=1
        else
            die "port $PORT is taken by $port_user. Stop that program, or use another port: --port 8443"
        fi
    fi

    local pkgs=(ca-certificates curl unzip openssl util-linux procps iproute2 polkitd) icu p
    icu=$(apt-cache search --names-only '^libicu[0-9]+$' 2>/dev/null | awk '{ print $1 }' | sort -V | tail -n1 || true)
    [[ -n $icu ]] && pkgs+=("$icu")   # DepotDownloader is a .NET app: it needs ICU
    [[ $FIREWALL -eq 1 ]] && pkgs+=(ufw)
    MISSING=()
    for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || MISSING+=("$p"); done
    if (( ${#MISSING[@]} > 0 )); then note "will install from Ubuntu: ${MISSING[*]}"; else ok "all needed packages are installed"; fi
    if [[ $(cat "$DD_DIR/.rerust-version" 2>/dev/null) == "$DD_VERSION" && -x $DD_DIR/DepotDownloader ]]; then
        ok "DepotDownloader $DD_VERSION is in $DD_DIR"
    else
        note "will install DepotDownloader $DD_VERSION (fetches Rust from Steam; checked by its SHA-256)"
    fi
    # Only a root-owned program is ever run as root here.
    if [[ -x $BIN && $(stat -c %u "$BIN") == 0 && $(stat -c %u "$APP_DIR") == 0 ]]; then
        note "the agent is installed ($("$BIN" version 2>/dev/null || echo '?')) - it will be updated"
    fi
    if [[ $FIREWALL -eq 1 ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL=0; warn "firewalld is active - ufw is left alone. Open $PORT/tcp for the panel and 28015+28017/udp, 28082/tcp there."
    fi
    [[ $FIREWALL -eq 1 ]] && note "firewall: SSH stays open; $PORT/tcp only for ${PANEL_IPS[*]}; Rust server 1 (28015+28017/udp, 28082/tcp)"
    return 0
}

install_packages() {
    if (( ${#MISSING[@]} > 0 )); then
        step "Packages"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends "${MISSING[@]}" >/dev/null
        ok "installed ${MISSING[*]}"
    fi
    dpkg-query -W -f='${Status}' lib32gcc-s1 2>/dev/null | grep -q 'ok installed' \
        || apt-get install -y -qq --no-install-recommends lib32gcc-s1 >/dev/null 2>&1 || true
}

fetch_agent() {   # into $TMP/rerust-agent, checked
    if [[ -n $LOCAL_BINARY ]]; then
        cp "$LOCAL_BINARY" "$TMP/rerust-agent"
        warn "installing a local build - not checked against a signed release"
        return
    fi
    local url="https://github.com/$REPO/releases/download/v$VERSION" want got
    curl -fsSL -o "$TMP/rerust-agent" "$url/rerust-agent-linux-$ARCH" || die "could not download the agent from $url"
    curl -fsSL -o "$TMP/SHA256SUMS" "$url/SHA256SUMS" || die "could not download SHA256SUMS"
    curl -fsSL -o "$TMP/SHA256SUMS.sig" "$url/SHA256SUMS.sig" || die "could not download SHA256SUMS.sig"
    printf '%s\n' "$RELEASE_KEY" >"$TMP/release.pub"
    openssl pkeyutl -verify -pubin -inkey "$TMP/release.pub" -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/SHA256SUMS.sig" >/dev/null 2>&1 \
        || die "the release's signature is not valid - nothing was installed"
    # The signed version must be this one (an old signed release can't be passed off under a newer tag).
    [[ $(head -n1 "$TMP/SHA256SUMS") == "# rerust-agent $VERSION" ]] || die "the signed release is not v$VERSION - nothing was installed"
    want=$(awk -v f="rerust-agent-linux-$ARCH" '$2 == f || $2 == "*"f { print $1 }' "$TMP/SHA256SUMS")
    got=$(sha256sum "$TMP/rerust-agent" | awk '{ print $1 }')
    [[ -n $want && $want == "$got" ]] || die "the download's checksum differs from the signed SHA256SUMS - nothing was installed"
    ok "download checked: signature, version and SHA-256"
}

switch_off_php() {
    (( ${#PHP_UNITS[@]} > 0 )) || return 0
    local u
    for u in "${PHP_UNITS[@]}"; do systemctl disable --now "$u" >/dev/null 2>&1 || true; done
    ok "switched off the old ReRust services: ${PHP_UNITS[*]} (their files stay - remove them later)"
    if [[ $STOP_NGINX -eq 1 ]]; then
        systemctl disable --now nginx >/dev/null 2>&1 || true
        ok "stopped and switched off nginx (it held port $PORT)"
    fi
    # The old install let the web server's PHP into the game's group - not any more.
    if id -nG www-data 2>/dev/null | tr ' ' '\n' | grep -qx "$GAME_USER"; then
        gpasswd -d www-data "$GAME_USER" >/dev/null && ok "took www-data out of the $GAME_USER group"
    fi
}

make_users() {
    if ! getent group "$GAME_USER" >/dev/null; then groupadd --system "$GAME_USER"; fi
    if ! id "$GAME_USER" >/dev/null 2>&1; then
        useradd --system --gid "$GAME_USER" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$GAME_USER"
        ok "created the $GAME_USER user (runs the game servers)"
    fi
    if ! id "$AGENT_USER" >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
        ok "created the $AGENT_USER user (runs the agent)"
    fi
    usermod -aG "$GAME_USER" "$AGENT_USER"
    # The game's user must not be in the agent's group (the agent's keys are its group's).
    if id -nG "$GAME_USER" | tr ' ' '\n' | grep -qx "$AGENT_USER"; then gpasswd -d "$GAME_USER" "$AGENT_USER" >/dev/null; fi
}

install_agent() {
    step "ReRust Agent"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    fetch_agent
    chmod 755 "$TMP/rerust-agent"
    "$TMP/rerust-agent" version >/dev/null || die "the downloaded agent does not run on this machine"
    switch_off_php
    make_users
    # The program is root's: neither the agent nor a game server can replace it (updates go through
    # rerust-agent-update.service, which checks the signature itself).
    install -d -m 755 -o root -g root "$APP_DIR"
    install -m 755 -o root -g root "$TMP/rerust-agent" "$BIN.new"
    mv -f "$BIN.new" "$BIN"
    install -d -m 700 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE_DIR"
    install -d -m 750 -o root -g "$AGENT_USER" "$CFG_DIR"
    ok "installed $BIN ($("$BIN" version))"

    local ips_json
    ips_json=$(printf '"%s",' "${PANEL_IPS[@]}"); ips_json="[${ips_json%,}]"
    cat >"$CFG_DIR/config.json.new" <<EOF
{
  "listen": ":$PORT",
  "base_dir": "$BASE_DIR",
  "state_dir": "$STATE_DIR",
  "depotdownloader": "$DD_DIR/DepotDownloader",
  "allowed_ips": $ips_json,
  "update_repo": "$REPO"
}
EOF
    chown root:"$AGENT_USER" "$CFG_DIR/config.json.new"; chmod 640 "$CFG_DIR/config.json.new"
    mv -f "$CFG_DIR/config.json.new" "$CFG_DIR/config.json"
    ok "wrote $CFG_DIR/config.json"
}

# /srv/rust: the agent's, setgid with the game's group - every server folder the agent makes gets that group, so the
# agent and the game server can both work in it.
servers_folder() {
    install -d -m 2750 -o "$AGENT_USER" -g "$GAME_USER" "$BASE_DIR"
    chown "$AGENT_USER:$GAME_USER" "$BASE_DIR"; chmod 2750 "$BASE_DIR"
    [[ $REPLACE_PHP -eq 1 ]] || return 0
    # Folders of the old install belong to the game's user: let its group (the agent) write them too. Done AS the
    # game's user (it owns the files) - root never walks a folder a game server can change.
    local dir n=0
    for dir in "$BASE_DIR"/*/; do
        dir=${dir%/}
        [[ -d $dir && ! -L $dir && $(stat -c %U "$dir") == "$GAME_USER" ]] || continue
        runuser -u "$GAME_USER" -- find "$dir" -xdev \( -type d -exec chmod g+rwxs {} + \) -o \( -type f -exec chmod g+rw {} + \) 2>/dev/null || true
        n=$((n + 1))
    done
    (( n == 0 )) || ok "took over $n folder(s) of the old install in $BASE_DIR"
}

install_depotdownloader() {
    [[ $(cat "$DD_DIR/.rerust-version" 2>/dev/null) == "$DD_VERSION" && -x $DD_DIR/DepotDownloader ]] && return 0
    step "DepotDownloader $DD_VERSION"
    curl -fsSL -o "$TMP/dd.zip" "https://github.com/SteamRE/DepotDownloader/releases/download/DepotDownloader_$DD_VERSION/DepotDownloader-linux-$DD_ARCH.zip" \
        || die "could not download DepotDownloader"
    [[ $(sha256sum "$TMP/dd.zip" | awk '{ print $1 }') == "$DD_SHA256" ]] || die "the DepotDownloader download's checksum is not the expected one - nothing was changed"
    mkdir "$TMP/dd"
    unzip -q "$TMP/dd.zip" -d "$TMP/dd"
    [[ -f $TMP/dd/DepotDownloader && ! -L $TMP/dd/DepotDownloader ]] || die "the DepotDownloader download did not contain DepotDownloader"
    # Root's, like the agent: the agent runs it, but can't change it.
    rm -rf "$DD_DIR.new"
    install -d -m 755 -o root -g root "$DD_DIR.new"
    install -m 755 -o root -g root "$TMP/dd/DepotDownloader" "$DD_DIR.new/DepotDownloader"
    if [[ -f $TMP/dd/LICENSE ]]; then install -m 644 -o root -g root "$TMP/dd/LICENSE" "$DD_DIR.new/LICENSE"; fi
    printf '%s\n' "$DD_VERSION" >"$DD_DIR.new/.rerust-version"
    rm -rf "$DD_DIR"
    mv "$DD_DIR.new" "$DD_DIR"
    ok "installed $DD_DIR/DepotDownloader $DD_VERSION (SHA-256 checked)"
}

install_services() {
    step "Services"
    local entry file
    for entry in socket:rerust-agent.socket agent:rerust-agent.service server:rerust-server@.service update:rerust-agent-update.service; do
        file=$UNIT_DIR/${entry#*:}
        "unit_${entry%%:*}" >"$file.new"
        chmod 644 "$file.new"
        mv -f "$file.new" "$file"
    done
    install -d -m 755 "$(dirname "$POLKIT_RULE")"
    polkit_rule >"$POLKIT_RULE.new"; chmod 644 "$POLKIT_RULE.new"; mv -f "$POLKIT_RULE.new" "$POLKIT_RULE"
    ok "wrote rerust-agent.socket/.service, rerust-server@.service, rerust-agent-update.service and the polkit rule"
    systemctl daemon-reload
    systemctl enable rerust-agent.socket rerust-agent.service >/dev/null 2>&1
    # Socket first (the port may have changed); game servers are their own units and keep running.
    systemctl stop rerust-agent.service rerust-agent.socket 2>/dev/null || true
    systemctl start rerust-agent.socket || die "could not open port $PORT - see: journalctl -u rerust-agent.socket -n 30"
    systemctl start rerust-agent.service
    sleep 2
    systemctl is-active --quiet rerust-agent.service || die "the agent did not start - see: journalctl -u rerust-agent -n 30"
    ok "rerust-agent is running on port $PORT"
}

firewall() {
    [[ $FIREWALL -eq 1 ]] || return 0
    step "Firewall (ufw)"
    local ssh_ports p rule keep ip args
    ssh_ports=$( { sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
        ss -Hltnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
        systemctl show -p Listen --value ssh.socket 2>/dev/null | grep -oE ':[0-9]+ \(Stream' | grep -oE '[0-9]+'
    } | grep -E '^[0-9]+$' | sort -un || true)
    [[ -n $ssh_ports ]] || ssh_ports=22
    for p in $ssh_ports; do ufw allow "$p/tcp" comment 'SSH' >/dev/null; done
    # Rules for another panel address or port from an earlier run go.
    while IFS= read -r rule; do
        [[ -n $rule ]] || continue
        keep=0
        for ip in "${PANEL_IPS[@]}"; do [[ $rule == "allow from $ip to any port $PORT proto tcp" ]] && keep=1; done
        if [[ $keep -eq 0 ]]; then read -r -a args <<<"$rule"; ufw --force delete "${args[@]}" >/dev/null; fi
    done < <(ufw_rules_with "$FW_AGENT")
    for ip in "${PANEL_IPS[@]}"; do ufw allow from "$ip" to any port "$PORT" proto tcp comment "$FW_AGENT" >/dev/null; done
    ufw allow 28015,28017/udp comment "$FW_GAME" >/dev/null
    ufw allow 28082/tcp comment "$FW_RUSTPLUS" >/dev/null
    ufw --force enable >/dev/null
    ok "ufw is on: SSH ($(paste -sd, <<<"$ssh_ports")), $PORT/tcp for ${PANEL_IPS[*]}, Rust server 1; RCON stays closed"
    say "    Extra servers use the next +10 block, e.g.: sudo ufw allow 28025,28027/udp && sudo ufw allow 28092/tcp"
}

pairing() {
    step "Pairing with the panel"
    local code err addr port_part=""
    addr=$(hostname -I 2>/dev/null | awk '{ print $1 }')
    [[ -n $addr ]] || addr="<this machine's address>"
    [[ $PORT != 443 ]] && port_part=":$PORT"
    if ! code=$(as_agent "$BIN" pair --config "$CFG_DIR/config.json" 2>"$TMP/pair.err"); then
        err=$(cat "$TMP/pair.err")
        if [[ $err == *"already paired"* ]]; then
            ok "already paired with a panel - nothing to do there (address: https://$addr$port_part)"
            say "    Pair it with another panel (the current one stops working once that completes):"
            say "      sudo -u $AGENT_USER $BIN pair --replace"
            return 0
        fi
        die "could not make a pairing code: $err"
    fi
    say ""
    say "  In the panel: Settings -> Machines -> Add machine"
    say "    Address:      https://$addr$port_part   (or its domain name / public IP)"
    say "    Pairing code: $code"
    say ""
    say "  The code works once, within 60 minutes. A new one: sudo -u $AGENT_USER $BIN pair"
}

main() {
    parse_args "$@"
    [[ $EUID -eq 0 ]] || die "run it as root (sudo)"
    [[ -d /run/systemd/system ]] || die "this machine doesn't run systemd"
    if [[ $UNINSTALL -eq 1 ]]; then
        uninstall
        return
    fi
    check_machine
    confirm "Install the ReRust Agent ${LOCAL_BINARY:+(local build)}${LOCAL_BINARY:-v$VERSION} now?" || die "cancelled - nothing was installed"
    install_packages
    install_agent
    servers_folder
    install_depotdownloader
    install_services
    firewall
    pairing
}

# Last line: a download cut off half-way runs nothing. (Tests source the file with RERUST_AGENT_INSTALL_TEST=1.)
[[ ${RERUST_AGENT_INSTALL_TEST:-} == 1 ]] || main "$@"
