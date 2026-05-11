# openhost-wg-easy

[wg-easy](https://github.com/wg-easy/wg-easy) — WireGuard VPN server
with a web UI — packaged as an OpenHost app.

## What this gives you

A self-hosted WireGuard VPN server reachable over the public
internet at `<zone>.selfhost.imbue.com:51820/udp`.  Use it to:

- Connect your laptop/phone back to your home network when on the
  road.
- Tunnel all internet traffic through your OpenHost zone (full-VPN
  mode — default).
- Wire several of your devices into the same encrypted overlay
  network (10.42.42.0/24 inside the tunnel).

Any standard WireGuard client works:

```bash
# Arch / EndeavourOS / Manjaro
pacman -S wireguard-tools

# Debian / Ubuntu
apt install wireguard

# macOS
brew install wireguard-tools  # or use the WireGuard.app from the App Store

# iOS / Android
# Install "WireGuard" from the App Store / Play Store
```

## Telemetry

None.  wg-easy doesn't phone home; neither does wireguard-go or
wireguard-tools.  The only network connections this container
makes are inbound WireGuard handshakes on UDP/51820 and outbound
to whatever your peers route through the tunnel.

## Topology

```
browser → OpenHost router (gates zone_auth, stamps
                           X-OpenHost-Is-Owner: true)
        → container :8080  (auth-proxy)
              ├─ owner with no session → POST /api/session →
              │  Set-Cookie wg-easy=<sealed>, 302 back
              └─ everything else → 127.0.0.1:51821 (wg-easy Nuxt)

wireguard-client (laptop, phone) → <zone>:51820/udp
                                 → wireguard-go (in this container)
                                 → routes per peer's AllowedIPs
```

## SSO

Pattern B1 (HTTP login replay).  Single admin account is created on
first boot via wg-easy's `INIT_*` unattended-setup envs.  Password
is random (32 alnum) and persisted at
`$OPENHOST_APP_DATA_DIR/admin-credentials.txt`.

On every owner navigation that lands without a `wg-easy` session
cookie, the auth-proxy POSTs the saved credentials to wg-easy's
`/api/session`, captures the `Set-Cookie`, and 302's back to the
original path with the cookie attached.

### Credentials file

`$OPENHOST_APP_DATA_DIR/admin-credentials.txt` is a credential.
The whole `app_data` dir is already sensitive — it contains
wg-easy's SQLite DB which holds every peer's WireGuard private
key.  An attacker who can read the data dir already controls the
VPN, so the admin password in `admin-credentials.txt` doesn't
meaningfully expand the threat model.  Treat the entire data dir
as secret.

If `file-browser` is installed on the same zone with the default
`access_all_data` permission, it will be able to read this file.
Either:

- don't install file-browser on the same zone, or
- run `oh app permissions file-browser --revoke access_all_data`
  to scope it to only its own data dir.

### Rotating the admin password

```bash
# From the OpenHost host (ssh into the zone):
podman exec -it openhost-wg-easy cli db:admin:reset --password "<new>"

# Then update the credentials file so the auth-proxy can still
# auto-login:
sed -i "s/^export WGEASY_ADMIN_PASSWORD=.*/export WGEASY_ADMIN_PASSWORD='<new>'/" \
  /home/host/.openhost/local_compute_space/persistent_data/app_data/wg-easy/admin-credentials.txt
```

## Adding a client (Arch laptop)

1. Visit `https://wg-easy.<zone>.selfhost.imbue.com/` — you'll be
   auto-logged in.
2. Click **+ New Client**, name it (e.g. `laptop`), submit.
3. Either:
   - Download the `.conf` file and save it to
     `/etc/wireguard/wg0.conf`, then
     `sudo systemctl enable --now wg-quick@wg0`.
   - Or scan the QR code from the WireGuard mobile app.

That's it.  The client will connect to UDP 51820 on your zone and
get an IP in 10.42.42.0/24.

## Configuration knobs

Defaults live in `start.sh`'s `INIT_*` envs (only consumed on
first boot; persisted in the SQLite DB after that):

| Env                | Default            | Meaning                            |
| ------------------ | ------------------ | ---------------------------------- |
| `INIT_HOST`        | `$OPENHOST_ZONE_DOMAIN` | Server endpoint in peer configs   |
| `INIT_PORT`        | `51820`            | UDP listen port                    |
| `INIT_IPV4_CIDR`   | `10.42.42.0/24`    | Tunnel IPv4 subnet                 |
| `INIT_IPV6_CIDR`   | `fdcc:ad94:bacf:61a3::/64` | Tunnel IPv6 subnet         |
| `INIT_DNS`         | `1.1.1.1,9.9.9.9`  | DNS pushed to clients              |
| `INIT_ALLOWED_IPS` | `0.0.0.0/0,::/0`   | Full-VPN by default; per-peer in UI|

To change them after first boot, edit settings in the wg-easy UI
under **Settings** (most knobs are exposed there) or destroy the
container's data dir and re-deploy.

## What's *not* included

- **Kernel-mode WireGuard.**  Rootless podman can't load
  `wireguard.ko` (no `CAP_SYS_MODULE`).  We use `wireguard-go`
  (userspace).  Throughput is ~50-200 Mbit/s on typical hardware
  vs. ~gigabit for kernel WG — fine for streaming / web / SSH;
  bandwidth-bound workloads (large file copies, video editing
  over the tunnel) will be slower.
- **TOTP enrollment via the UI.**  wg-easy v15 supports it, but
  the auth-proxy's login replay doesn't carry a TOTP code.  If
  you enable TOTP on the admin account, auto-login will break;
  log in manually after that.
- **DDNS / dynamic IP.**  The `INIT_HOST` is fixed to the zone
  domain.  As long as the zone's public hostname resolves to a
  reachable IP, clients connect.

## Files

```
openhost.toml           manifest (port 8080 routed; UDP 51820 published)
Dockerfile              wg-easy:15 + python3 + curl + bash + scripts
start.sh                bootstrap (creds, INIT_*, supervisor)
auth_proxy.py           Pattern B1 SSO sidecar
README.md               this file
```

## Authoring notes

- Built per the OpenHost `openhost-app` skill (Pattern B1, single-
  password persisted in `app_data`).
- Modeled on `openhost-joplin/auth_proxy.py` for the login-replay
  pattern.
- Uses OpenHost's `[[ports]]` mechanism to publish UDP/51820
  directly on the host (TCP+UDP both bound, only UDP meaningful
  here).
- Capabilities limited to `NET_ADMIN` + `NET_RAW`; device
  `/dev/net/tun`.  No `SYS_MODULE` (not on the allowlist anyway).
