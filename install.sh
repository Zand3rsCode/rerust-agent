#!/usr/bin/env bash
# ReRust Agent installer for Ubuntu 26.04 - installs, updates or removes the agent on a game machine.
#
#   curl -fsSL https://github.com/Zand3rsCode/rerust-agent/releases/download/v<version>/install.sh | sudo bash -s -- --panel-ip <panel IP>
#
# Options:
#   --panel-ip IP        the panel's address (repeat for more); only it may reach the agent's port
#   --port N             the agent's HTTPS port (default 443)
#   --replace-php-agent  stop and switch off an older ReRust (PHP) install on this machine first; its server folders
#                        in /srv/rust stay and are taken over (same names)
#   --no-firewall        leave the firewall alone
#   --yes                don't ask
#   --uninstall          remove the agent (game servers' folders in /srv/rust stay unless --delete-servers)
#
# What it installs: the agent (/opt/rerust-agent), DepotDownloader (/opt/depotdownloader), a `rerust` user, the
# systemd service rerust-agent, and firewall rules (ufw). No PHP, web server, database or certbot.
# The agent's download is checked against SHA256SUMS, and SHA256SUMS against the release signature, before anything
# is installed.
set -euo pipefail

VERSION="@VERSION@"
REPO="Zand3rsCode/rerust-agent"
# Verifies SHA256SUMS of every release (Ed25519). The same key is built into the agent.
RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAq8p9/zFiaGIkdaZ6RXUimLVSZ8woEY9/AW7yKbWIIYg=
-----END PUBLIC KEY-----'

APP_DIR=/opt/rerust-agent
BIN=$APP_DIR/rerust-agent
CFG_DIR=/etc/rerust-agent
STATE_DIR=/var/lib/rerust-agent
BASE_DIR=/srv/rust
DD_DIR=/opt/depotdownloader
UNIT=/etc/systemd/system/rerust-agent.service
USER_NAME=rerust
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
        -h|--help) sed -n '2,19p' "$0" 2>/dev/null || true; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run it as root (sudo)"
[[ -d /run/systemd/system ]] || die "this machine doesn't run systemd"
[[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port must be 1 - 65535"
for ip in "${PANEL_IPS[@]}"; do
    [[ $ip =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "--panel-ip $ip is not an IP address"
done

ufw_rules_with() {   # the rules ufw has with this comment, as "allow ..." lines
    command -v ufw >/dev/null || return 0
    ufw show added 2>/dev/null | sed -nE "s/^ufw (.*) comment '$1'$/\1/p" || true
}

# --- uninstall ------------------------------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
    step "Removing the ReRust Agent"
    if pgrep -x RustDedicated >/dev/null; then
        warn "Rust servers are running: $(pgrep -x RustDedicated | paste -sd, -) - they keep running without the agent."
        confirm "Remove the agent anyway?" || die "cancelled - nothing was removed"
    fi
    if [[ -f $UNIT ]]; then
        systemctl disable --now rerust-agent >/dev/null 2>&1 || true
        rm -f "$UNIT"; systemctl daemon-reload
        ok "service rerust-agent removed"
    fi
    rm -rf "$APP_DIR" "$CFG_DIR" "$STATE_DIR" "$DD_DIR"
    ok "removed $APP_DIR, $CFG_DIR, $STATE_DIR, $DD_DIR"
    removed=0
    for comment in "$FW_AGENT" "$FW_GAME" "$FW_RUSTPLUS"; do
        while IFS= read -r rule; do
            [[ -n $rule ]] || continue
            read -r -a args <<<"$rule"
            ufw --force delete "${args[@]}" >/dev/null && removed=$((removed + 1))
        done < <(ufw_rules_with "$comment")
    done
    (( removed == 0 )) || ok "removed $removed firewall rule(s) (ufw stays on with SSH and your other rules)"
    if [[ $DELETE_SERVERS -eq 1 ]]; then
        confirm "Delete every server folder in $BASE_DIR (worlds, plugins, backups)?" && rm -rf "$BASE_DIR" && ok "deleted $BASE_DIR"
        id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null && ok "removed the $USER_NAME user"
    else
        note "kept the server folders in $BASE_DIR and the $USER_NAME user (--delete-servers removes them)"
    fi
    say ""; say "Done. Packages (curl, ufw ...) were left installed."
    exit 0
fi

# --- checks -----------------------------------------------------------------------------------------------------
step "Checking this machine"
. /etc/os-release 2>/dev/null || true
if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 26.04 ]]; then ok "${PRETTY_NAME}"
else warn "made for Ubuntu 26.04 - this is ${PRETTY_NAME:-unknown}; it may still work"; fi
case $(uname -m) in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64; warn "arm64: the agent runs, but Rust's dedicated server only exists for x86_64" ;;
    *) die "unsupported CPU $(uname -m)" ;;
esac
[[ $VERSION == "@VERSION@" && -z $LOCAL_BINARY ]] && die "this copy of install.sh has no version - use the one from a release, or --version x.y.z"
if (( ${#PANEL_IPS[@]} == 0 )); then
    if [[ -f $CFG_DIR/config.json ]]; then
        mapfile -t PANEL_IPS < <(sed -n '/"allowed_ips"/,/]/p' "$CFG_DIR/config.json" | grep -oE '"[0-9a-fA-F:.]+(/[0-9]+)?"' | tr -d '"')
    fi
    (( ${#PANEL_IPS[@]} > 0 )) && ok "panel address(es) from the last install: ${PANEL_IPS[*]}" \
        || die "give the panel's IP address: --panel-ip <ip> (only it may use the agent)"
fi

# An older ReRust (PHP) install on this machine.
php_units=()
for u in rerust-monitor rerust-worker-control rerust-worker-long rerust-php-fpm rerust-keeper; do
    systemctl list-unit-files "$u.service" >/dev/null 2>&1 && systemctl cat "$u.service" >/dev/null 2>&1 && php_units+=("$u")
done
if (( ${#php_units[@]} > 0 )); then
    if [[ $REPLACE_PHP -eq 1 ]]; then
        note "an older ReRust (PHP) install is here (${php_units[*]}) - it will be stopped and switched off; /srv/rust stays"
    else
        die "an older ReRust (PHP) install is on this machine (${php_units[*]}). Run again with --replace-php-agent to switch it off and take over its servers (folders in /srv/rust stay), or remove it first."
    fi
fi

# Nothing else may hold the agent's port.
port_user=$(ss -Hltnp "sport = :$PORT" 2>/dev/null | grep -oE 'users:\(\("[^"]+' | head -n1 | sed 's/.*"//' || true)
if [[ -n $port_user && $port_user != rerust-agent ]]; then
    if [[ $REPLACE_PHP -eq 1 && $port_user == nginx ]]; then
        note "nginx holds port $PORT (the old install's web server) - it will be stopped and switched off"
    else
        die "port $PORT is taken by $port_user. Stop that program, or use another port: --port 8443"
    fi
fi

pkgs=(ca-certificates curl unzip openssl util-linux procps iproute2)
icu=$(apt-cache search --names-only '^libicu[0-9]+$' 2>/dev/null | awk '{ print $1 }' | sort -V | tail -n1 || true)
[[ -n $icu ]] && pkgs+=("$icu")   # DepotDownloader is a .NET app: it needs ICU
[[ $FIREWALL -eq 1 ]] && pkgs+=(ufw)
missing=()
for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || missing+=("$p"); done
if (( ${#missing[@]} > 0 )); then note "will install from Ubuntu: ${missing[*]}"; else ok "all needed packages are installed"; fi
[[ -x $DD_DIR/DepotDownloader ]] && ok "DepotDownloader is in $DD_DIR" || note "will download DepotDownloader (fetches Rust from Steam)"
if [[ -x $BIN ]]; then note "the agent is installed ($("$BIN" version 2>/dev/null || echo '?')) - it will be updated"; fi
if [[ $FIREWALL -eq 1 ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
    FIREWALL=0; warn "firewalld is active - ufw is left alone. Open $PORT/tcp for the panel and 28015+28017/udp, 28082/tcp there."
fi
[[ $FIREWALL -eq 1 ]] && note "firewall: SSH stays open; $PORT/tcp only for ${PANEL_IPS[*]}; Rust server 1 (28015+28017/udp, 28082/tcp)"

confirm "Install the ReRust Agent ${LOCAL_BINARY:+(local build)}${LOCAL_BINARY:-v$VERSION} now?" || die "cancelled - nothing was installed"

# --- packages --------------------------------------------------------------------------------------------------
if (( ${#missing[@]} > 0 )); then
    step "Packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
    ok "installed ${missing[*]}"
fi
dpkg-query -W -f='${Status}' lib32gcc-s1 2>/dev/null | grep -q 'ok installed' \
    || apt-get install -y -qq --no-install-recommends lib32gcc-s1 >/dev/null 2>&1 || true

# --- the agent ----------------------------------------------------------------------------------------------------
step "ReRust Agent"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [[ -n $LOCAL_BINARY ]]; then
    cp "$LOCAL_BINARY" "$tmp/rerust-agent"
    warn "installing a local build - not checked against a signed release"
else
    url="https://github.com/$REPO/releases/download/v$VERSION"
    curl -fsSL -o "$tmp/rerust-agent" "$url/rerust-agent-linux-$ARCH" || die "could not download the agent from $url"
    curl -fsSL -o "$tmp/SHA256SUMS" "$url/SHA256SUMS" || die "could not download SHA256SUMS"
    curl -fsSL -o "$tmp/SHA256SUMS.sig" "$url/SHA256SUMS.sig" || die "could not download SHA256SUMS.sig"
    printf '%s\n' "$RELEASE_KEY" >"$tmp/release.pub"
    openssl pkeyutl -verify -pubin -inkey "$tmp/release.pub" -rawin -in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1 \
        || die "the release's signature is not valid - nothing was installed"
    want=$(awk -v f="rerust-agent-linux-$ARCH" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")
    got=$(sha256sum "$tmp/rerust-agent" | awk '{ print $1 }')
    [[ -n $want && $want == "$got" ]] || die "the download's checksum differs from the signed SHA256SUMS - nothing was installed"
    ok "download checked: signature and SHA-256"
fi
chmod 755 "$tmp/rerust-agent"
"$tmp/rerust-agent" version >/dev/null || die "the downloaded agent does not run on this machine"

if (( ${#php_units[@]} > 0 )); then
    for u in "${php_units[@]}"; do systemctl disable --now "$u" >/dev/null 2>&1 || true; done
    ok "switched off the old ReRust services: ${php_units[*]} (their files stay - remove them later)"
    if [[ ${port_user:-} == nginx ]]; then
        systemctl disable --now nginx >/dev/null 2>&1 || true
        ok "stopped and switched off nginx (it held port $PORT)"
    fi
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$USER_NAME"
    ok "created the $USER_NAME user"
fi
install -d -m 750 -o "$USER_NAME" -g "$USER_NAME" "$APP_DIR" "$STATE_DIR"
install -d -m 750 -o "$USER_NAME" -g "$USER_NAME" "$BASE_DIR"
install -d -m 750 -o root -g "$USER_NAME" "$CFG_DIR"
# The agent replaces its own binary when the panel updates it: it belongs to the agent's user.
install -m 755 -o "$USER_NAME" -g "$USER_NAME" "$tmp/rerust-agent" "$BIN.new"
mv -f "$BIN.new" "$BIN"
ok "installed $BIN ($("$BIN" version))"

ips_json=$(printf '"%s",' "${PANEL_IPS[@]}"); ips_json="[${ips_json%,}]"
cat >"$CFG_DIR/config.json" <<EOF
{
  "listen": ":$PORT",
  "base_dir": "$BASE_DIR",
  "state_dir": "$STATE_DIR",
  "depotdownloader": "$DD_DIR/DepotDownloader",
  "allowed_ips": $ips_json,
  "update_repo": "$REPO"
}
EOF
chown root:"$USER_NAME" "$CFG_DIR/config.json"; chmod 640 "$CFG_DIR/config.json"
ok "wrote $CFG_DIR/config.json"

# --- DepotDownloader ------------------------------------------------------------------------------------------------
if [[ ! -x $DD_DIR/DepotDownloader ]]; then
    step "DepotDownloader"
    dd_arch=x64; [[ $ARCH == arm64 ]] && dd_arch=arm64
    curl -fsSL -o "$tmp/dd.zip" "https://github.com/SteamRE/DepotDownloader/releases/latest/download/DepotDownloader-linux-$dd_arch.zip" \
        || die "could not download DepotDownloader"
    install -d -m 755 -o "$USER_NAME" -g "$USER_NAME" "$DD_DIR"
    unzip -oq "$tmp/dd.zip" -d "$DD_DIR"
    [[ -f $DD_DIR/DepotDownloader ]] || die "the DepotDownloader download did not contain DepotDownloader"
    chmod 755 "$DD_DIR/DepotDownloader"; chown -R "$USER_NAME:$USER_NAME" "$DD_DIR"
    ok "installed $DD_DIR/DepotDownloader"
fi
# Folders the old install made belong to the agent's user too.
chown "$USER_NAME:$USER_NAME" "$BASE_DIR"

# --- service --------------------------------------------------------------------------------------------------------
step "Service"
cat >"$UNIT" <<EOF
[Unit]
Description=ReRust Agent (runs Rust servers for a ReRust panel)
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
ExecStart=$BIN serve --config $CFG_DIR/config.json
Restart=always
RestartSec=3
# Game servers are started by the agent and must outlive it (updates, restarts): only the agent itself is stopped.
KillMode=process
# A Rust server killed for memory must not take the agent down.
OOMPolicy=continue
# Inherited by Rust (it opens many files).
LimitNOFILE=65535
UMask=0027
# Port $PORT without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
Environment=DOTNET_CLI_TELEMETRY_OPTOUT=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable rerust-agent >/dev/null 2>&1
systemctl restart rerust-agent
sleep 2
systemctl is-active --quiet rerust-agent || die "the agent did not start - see: journalctl -u rerust-agent -n 30"
ok "rerust-agent is running on port $PORT"

# --- firewall -------------------------------------------------------------------------------------------------------
if [[ $FIREWALL -eq 1 ]]; then
    step "Firewall (ufw)"
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
    ok "ufw is on: SSH ($ssh_ports), $PORT/tcp for ${PANEL_IPS[*]}, Rust server 1; RCON stays closed"
    say "    Extra servers use the next +10 block, e.g.: sudo ufw allow 28025,28027/udp && sudo ufw allow 28092/tcp"
fi

# --- pairing ---------------------------------------------------------------------------------------------------------
step "Pairing with the panel"
code=$(sudo -u "$USER_NAME" "$BIN" pair --config "$CFG_DIR/config.json" 2>/dev/null) || die "could not make a pairing code"
addr=$(hostname -I 2>/dev/null | awk '{ print $1 }')
[[ -n $addr ]] || addr="<this machine's address>"
port_part=""; [[ $PORT != 443 ]] && port_part=":$PORT"
say ""
say "  In the panel: Settings -> Machines -> Add machine"
say "    Address:      https://$addr$port_part   (or its domain name / public IP)"
say "    Pairing code: $code"
say ""
say "  The code works once, within 24 hours. A new one: sudo -u $USER_NAME $BIN pair"
