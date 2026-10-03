#!/usr/bin/env bash
# Install LionSeed on a fresh Debian 13 server.
#
#   sudo CONTACT_EMAIL=you@example.org SEED_HOST=seed.example.org NS_HOST=ns-seed.example.org \
#        ./deploy/deploy.sh
#
# Optional: PUBLIC_IP (detected if unset), WITH_TOR=1 and WITH_I2P=1 (install and use tor / i2pd for
# crawling onion and I2P nodes), HEALTHCHECK_PING_URL (https URL pinged every 5 minutes while the
# seed is healthy). Safe to run again: each step checks before it changes anything.
#
# It does not start the service. Create the DNS delegation first (see README), then:
#   sudo systemctl start lionseed

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -r /etc/os-release ] && . /etc/os-release
[ "${ID:-}" = "debian" ] || echo "warning: tested on Debian 13; this is ${PRETTY_NAME:-unknown}" >&2

: "${CONTACT_EMAIL:?set CONTACT_EMAIL (published in the SOA record)}"
: "${SEED_HOST:?set SEED_HOST, e.g. seed.example.org}"
: "${NS_HOST:?set NS_HOST, e.g. ns-seed.example.org}"
[[ "$CONTACT_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "CONTACT_EMAIL does not look like an email address"
[ "$SEED_HOST" != "$NS_HOST" ] || die "SEED_HOST and NS_HOST must be different names"

if [ -z "${PUBLIC_IP:-}" ]; then
    PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
fi
[ -n "$PUBLIC_IP" ] || die "could not detect PUBLIC_IP; set it"
case "$PUBLIC_IP" in
    10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*)
        die "PUBLIC_IP $PUBLIC_IP is not a public address; a seed must be directly reachable on UDP 53" ;;
esac
if [ -n "${HEALTHCHECK_PING_URL:-}" ]; then
    [[ "$HEALTHCHECK_PING_URL" == https://* ]] || die "HEALTHCHECK_PING_URL must start with https://"
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$SRC_DIR/Cargo.toml" ] || die "run this from a LionSeed checkout"

log "installing packages"
PKGS=(build-essential pkg-config curl ca-certificates dnsutils)
[ "${WITH_TOR:-0}" = 1 ] && PKGS+=(tor)
[ "${WITH_I2P:-0}" = 1 ] && PKGS+=(i2pd)
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PKGS[@]}" >/dev/null

# A pinned Rust toolchain in /opt, so the build does not depend on the distribution's compiler.
RUST_HOME=/opt/lionseed-rust
if [ ! -x "$RUST_HOME/cargo/bin/cargo" ]; then
    log "installing Rust into $RUST_HOME"
    curl -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
    RUSTUP_HOME="$RUST_HOME/rustup" CARGO_HOME="$RUST_HOME/cargo" \
        sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable --no-modify-path >/dev/null
fi
export RUSTUP_HOME="$RUST_HOME/rustup" CARGO_HOME="$RUST_HOME/cargo" PATH="$RUST_HOME/cargo/bin:$PATH"

log "building LionSeed"
(cd "$SRC_DIR" && CARGO_BUILD_JOBS="$(nproc)" cargo build --release --locked -q)
install -m 0755 "$SRC_DIR/target/release/lionseed" /usr/local/bin/lionseed
install -m 0755 "$SRC_DIR/deploy/lionseed-healthcheck.sh" /usr/local/bin/lionseed-healthcheck

if ! id lionseed >/dev/null 2>&1; then
    log "creating the lionseed system user"
    useradd --system --home-dir /var/lib/lionseed --shell /usr/sbin/nologin lionseed
fi

ONION_PROXY=none
I2P_PROXY=none
[ "${WITH_TOR:-0}" = 1 ] && ONION_PROXY=127.0.0.1:9050 && systemctl enable --now tor >/dev/null 2>&1 || true
if [ "${WITH_I2P:-0}" = 1 ]; then
    I2P_PROXY=127.0.0.1:4447
    # A seed only needs outbound I2P connections. Do not relay other people's tunnels: that is what
    # makes i2pd grow in memory and bandwidth.
    if ! grep -qE '^[[:space:]]*notransit[[:space:]]*=[[:space:]]*true' /etc/i2pd/i2pd.conf; then
        sed -i 's/^[#[:space:]]*notransit[[:space:]]*=.*/notransit = true/' /etc/i2pd/i2pd.conf
        grep -qE '^notransit = true' /etc/i2pd/i2pd.conf || sed -i '1i notransit = true' /etc/i2pd/i2pd.conf
    fi
    systemctl enable i2pd >/dev/null 2>&1 || true
    systemctl restart i2pd >/dev/null 2>&1 || true
fi

log "writing /etc/systemd/system/lionseed.service"
cat > /etc/systemd/system/lionseed.service <<UNIT
[Unit]
Description=LionSeed DNS seeder for the Bitcoin network
After=network-online.target
Wants=network-online.target

[Service]
User=lionseed
Group=lionseed
StateDirectory=lionseed
WorkingDirectory=/var/lib/lionseed
ExecStart=/usr/local/bin/lionseed \\
    --dns-bind ${PUBLIC_IP}:53 --host ${SEED_HOST} --ns ${NS_HOST} --mbox ${CONTACT_EMAIL} \\
    --snapshot /var/lib/lionseed/state.snapshot --dump /var/lib/lionseed/lionseed.dump \\
    --onion-proxy ${ONION_PROXY} --i2p-proxy ${I2P_PROXY}
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
LimitNOFILE=16384
MemoryMax=512M

# Only what it needs: bind port 53, talk IPv4/IPv6, write its own state directory.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable lionseed >/dev/null 2>&1

if [ -n "${HEALTHCHECK_PING_URL:-}" ]; then
    log "installing the health check timer"
    install -m 0600 /dev/null /etc/default/lionseed-healthcheck
    printf 'PING_URL=%s\nSEED_HOST=%s\nBIND_IP=%s\nCHECK_ONION=%s\nCHECK_I2P=%s\n' "$HEALTHCHECK_PING_URL" \
        "$SEED_HOST" "$PUBLIC_IP" "${WITH_TOR:-0}" "${WITH_I2P:-0}" > /etc/default/lionseed-healthcheck
    cat > /etc/systemd/system/lionseed-healthcheck.service <<UNIT
[Unit]
Description=LionSeed health check
[Service]
Type=oneshot
EnvironmentFile=/etc/default/lionseed-healthcheck
ExecStart=/usr/local/bin/lionseed-healthcheck
UNIT
    cat > /etc/systemd/system/lionseed-healthcheck.timer <<UNIT
[Unit]
Description=LionSeed health check every 5 minutes
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now lionseed-healthcheck.timer >/dev/null 2>&1
fi

cat <<EOF

Installed. Before starting, make sure the DNS delegation exists:
    ${NS_HOST}   A    ${PUBLIC_IP}
    ${SEED_HOST} NS   ${NS_HOST}
Then:
    sudo systemctl start lionseed
    journalctl -u lionseed -f
A new seed needs roughly half an hour before it has nodes good enough to serve.
EOF
