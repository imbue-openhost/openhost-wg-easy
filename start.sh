#!/bin/bash
# Boot wg-easy + auth-proxy sidecar for OpenHost.
#
# Topology:
#
#   browser → OpenHost router (gates zone_auth; stamps
#                              X-OpenHost-Is-Owner: true)
#           → container :8080  (auth_proxy.py, this script)
#                  └─ owner → POST /api/session to wg-easy,
#                              echo Set-Cookie on 302
#                  └─ all → proxy to wg-easy at 127.0.0.1:51821
#
#   wg-client → host :51820/udp → container :51820/udp
#               (wireguard-go inside wg-easy)
#
# First-boot:
#   * Generate a random admin password.
#   * Write it (+ admin username) to $PERSIST/admin-credentials.txt
#     for the auth-proxy to read on every auto-login attempt.
#   * Export INIT_* env so wg-easy's unattended-setup pathway creates
#     the admin user on first launch.
#
# Subsequent boots load the persisted credentials and skip generation;
# wg-easy ignores INIT_* once the database has an admin user.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/wg-easy}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-wg-easy}"

# wg-easy reads/writes its sqlite DB and per-peer keys here.
WG_DATA="$PERSIST/wg-easy"
mkdir -p "$WG_DATA"

# wg-easy v15 expects /etc/wireguard to be its data directory.
# Symlink it to our persisted dir so all state survives container
# rebuilds.
rm -rf /etc/wireguard
ln -sf "$WG_DATA" /etc/wireguard

# -----------------------------------------------------------------
# Admin credentials.  Persisted across reboots; regenerate by
# deleting the file and `cli db:admin:reset` inside the container
# (see README).
# -----------------------------------------------------------------
CRED_FILE="$PERSIST/admin-credentials.txt"
ADMIN_USERNAME="admin"

if [[ ! -f "$CRED_FILE" ]]; then
    # 32 alnum chars ≈ 190 bits of entropy.  wg-easy doesn't enforce
    # complexity at init time, so anything is fine; we use a long
    # random string.
    PASS="$(head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
    umask 077
    cat > "$CRED_FILE" <<EOF
# Generated on first container start.  Used by auth_proxy.py to
# auto-log the OpenHost zone owner in to wg-easy on first
# navigation.  THIS IS A CREDENTIAL — anyone who can read this
# file can manage your VPN (which already gives them the keys
# anyway via the wg-easy SQLite DB next to this file).
export WGEASY_ADMIN_USERNAME='${ADMIN_USERNAME}'
export WGEASY_ADMIN_PASSWORD='${PASS}'
EOF
    chmod 0600 "$CRED_FILE"
    echo "[start.sh] Generated admin credentials at $CRED_FILE"
else
    echo "[start.sh] Loaded existing admin credentials from $CRED_FILE"
fi

# shellcheck disable=SC1090
source "$CRED_FILE"

# -----------------------------------------------------------------
# wg-easy environment.
# -----------------------------------------------------------------
# UI listen: 127.0.0.1:51821 (auth-proxy fronts it on :8080)
export PORT=51821
export HOST=127.0.0.1
# INSECURE=true: tells wg-easy to allow HTTP and to NOT set Secure
# on the session cookie.  Necessary because wg-easy is one HTTP
# hop behind the OpenHost router which terminates TLS.
export INSECURE=true

# Unattended-setup envs.  Wg-easy's setup wizard runs once on the
# first request after INIT_ENABLED=true is observed.  After the
# admin user exists, these envs are ignored.
export INIT_ENABLED=true
export INIT_USERNAME="$WGEASY_ADMIN_USERNAME"
export INIT_PASSWORD="$WGEASY_ADMIN_PASSWORD"
# Tell wg-easy which public host clients should connect to.  This
# becomes the Endpoint in the generated WireGuard configs.
export INIT_HOST="${ZONE_DOMAIN}"
# WireGuard UDP listen port.  Must match the host_port in
# openhost.toml's [[ports]] entry.
export INIT_PORT=51820
# IPv4-only.  IPv6 inside rootless podman is fragile and most
# OpenHost zones don't have a routable IPv6 anyway.  Both INIT_*_CIDR
# vars must be set together (wg-easy's group rule).
export INIT_IPV4_CIDR="10.42.42.0/24"
export INIT_IPV6_CIDR="fdcc:ad94:bacf:61a3::/64"
# Default DNS for clients — Cloudflare's privacy resolver + Quad9
# fallback.  Owners can change this per-peer in the UI.
export INIT_DNS="1.1.1.1,9.9.9.9"
# Route all client traffic through the tunnel by default (full-VPN
# mode).  Owners can flip per-peer to split-tunnel in the UI.
export INIT_ALLOWED_IPS="0.0.0.0/0,::/0"

# Use the userspace WireGuard implementation (wireguard-go).  The
# kernel module isn't loadable in a rootless container without
# CAP_SYS_MODULE, which OpenHost doesn't grant.
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

# -----------------------------------------------------------------
# Sysctls.  ip_forward is namespaced; we own this netns, so we can
# set it without affecting the host.  Best-effort: warn but don't
# abort if /proc/sys is read-only (some sandboxed setups).
# -----------------------------------------------------------------
echo "[start.sh] Enabling IP forwarding inside container netns"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || echo "[start.sh] WARN: could not set net.ipv4.ip_forward=1 — VPN routing may not work" >&2
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# -----------------------------------------------------------------
# Start the auth-proxy first.  It serves /_healthz immediately so
# the OpenHost healthcheck has a stable target during wg-easy's
# ~10s Nuxt cold-start.
# -----------------------------------------------------------------
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080"
export AUTH_PROXY_LISTEN_PORT=8080
export AUTH_PROXY_UPSTREAM_HOST=127.0.0.1
export AUTH_PROXY_UPSTREAM_PORT=51821
export AUTH_PROXY_CRED_FILE="$CRED_FILE"
python3 /opt/openhost-wg-easy/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Start wg-easy.  Upstream CMD is:
#   /usr/bin/dumb-init node server/index.mjs
# WORKDIR is /app in upstream image.  We chdir there explicitly.
# -----------------------------------------------------------------
echo "[start.sh] Starting wg-easy (Nuxt server) on 127.0.0.1:$PORT"
cd /app
/usr/bin/dumb-init node server/index.mjs &
WGEASY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------
trap 'kill -TERM "$PROXY_PID" "$WGEASY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$PROXY_PID" "$WGEASY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] A child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$PROXY_PID" "$WGEASY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
