# openhost-wg-easy
#
# Builds on top of the upstream wg-easy:15 image. We add:
#   * python3 (auth-proxy sidecar)
#   * curl    (auth-proxy uses it to call wg-easy's own login API
#              during the SSO replay)
#   * the auth_proxy.py / bootstrap_admin.sh / start.sh control plane.
#
# wg-easy's CMD is overridden by our start.sh which:
#   1. Generates an admin password on first boot.
#   2. Sets INIT_* env vars so wg-easy's unattended setup creates the
#      admin user on first boot.
#   3. Launches wg-easy (node server/index.mjs) on 127.0.0.1:51821.
#   4. Launches the auth-proxy on 0.0.0.0:8080.
#   5. Supervises both with `wait -n`.
FROM ghcr.io/wg-easy/wg-easy:15

# Alpine apk: python3 + curl + bash (wg-easy's base image is
# node:krypton-alpine, which has /bin/sh = busybox; we want bash
# for the start script).
RUN apk add --no-cache python3 py3-pip curl bash

# Userspace WireGuard fallback.  wg-easy ships wireguard-go already
# (verified in upstream Dockerfile).  WG_QUICK_USERSPACE_IMPLEMENTATION
# tells wg-quick to use it when the kernel module isn't available
# (which is always true in a rootless podman container).
#
# The env var is set both here and baked into a wg-quick wrapper
# because wg-easy's Node server may not propagate the env to
# child processes reliably.
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
RUN mv /usr/bin/wg-quick /usr/bin/wg-quick-real \
 && printf '#!/bin/sh\necho "[wg-quick-wrapper] forcing userspace wireguard-go" >&2\nexport WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go\nexec /usr/bin/wg-quick-real "$@"\n' \
      > /usr/bin/wg-quick \
 && chmod 0755 /usr/bin/wg-quick \
 && cat /usr/bin/wg-quick

# Listen settings expected by us in start.sh.
# PORT is the wg-easy UI port (internal, not OpenHost-routed).
# HOST=127.0.0.1 because the auth-proxy fronts it.
ENV PORT=51821
ENV HOST=127.0.0.1
ENV INSECURE=true

# We supply our own start.sh.
COPY start.sh /opt/openhost-wg-easy/start.sh
COPY auth_proxy.py /opt/openhost-wg-easy/auth_proxy.py
RUN chmod 0755 /opt/openhost-wg-easy/start.sh /opt/openhost-wg-easy/auth_proxy.py

# wg-easy upstream sets WORKDIR /app and its node code expects to be
# launched from there.  We chdir back in start.sh.
WORKDIR /opt/openhost-wg-easy

# Disable the upstream HEALTHCHECK — OpenHost has its own routing-level
# health probe configured in openhost.toml (health_check = "/_healthz").
HEALTHCHECK NONE

CMD ["/opt/openhost-wg-easy/start.sh"]
