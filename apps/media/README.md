# media

Media server and its companion apps, migrated from the `media-prod01` VM. Same images and
versions as the VM, pinned.

| File | What |
|---|---|
| `vpn-stack.yaml` | One pod: a VPN gateway (ProtonVPN, WireGuard) plus the companion apps that should only reach the internet through it. They share the pod's network, so they reach each other on `localhost`. |
| `plex.yaml` | The media server (port 32400 on every node, and `plex.agathla.com`) and its stats app, outside the VPN. |
| `storage.yaml` | The NAS media share (`/volume1/plex`, NFSv3, mounted at `/data` as on the VM) and one Longhorn volume per app config. |
| `external-secret.yaml` | The VPN key from Vault `secret/k8s/media/gluetun`. |
| `ingress.yaml` | `https://<app>.agathla.com` for each web UI. |

**All Deployments start at `replicas: 0`.** Pushing this folder creates the volumes but
runs nothing, so it can't clash with the VM. Two VPN gateways using the same WireGuard
key knock each other offline.

## Before cutover (one-time)

1. **NAS:** the `plex` shared folder's NFS rules allow `10.0.20.0/24`
   (read/write, no mapping, auth_sys).
2. **Vault:** `secret/k8s/media/gluetun` holds `wireguard-private-key`.
3. **DNS:** an Unbound override alias per host in `ingress.yaml` → `10.0.20.10`.
4. **HAProxy:** TCP frontend `10.0.20.10:32400` → nodes `:32400`, for remote access.

## Cutover

1. Stop the stacks on the VM, so configs are no longer written and the VPN key is free.
2. Copy each app's config folder into its `<app>-config` volume (ownership `1000:1000`)
   and update the addresses the apps use to reach each other: the VM's Docker gateway
   (`172.18.0.1`) becomes `localhost` inside the pod. The media server and the stats app
   run outside the VPN pod with fixed cluster IPs (`plex` 172.17.0.200, `tautulli`
   172.17.0.201), because cluster DNS names don't resolve inside the VPN pod.
3. Set `replicas: 1` on all three Deployments, commit, push.
4. Point the OPNsense port forward `WAN:32400` at `10.0.20.10` (was the VM, `10.0.20.30`).
5. Check: the VPN gateway reports a ProtonVPN IP, every UI loads, and the media server
   sees the library and is reachable from outside. In its network settings, set the custom
   access URLs to `https://plex.agathla.com:443,http://10.0.20.11:32400` and add
   `10.0.40.0/24` (WireGuard) to the LAN networks.

## Rollback

Set the replicas back to `0` and push, point the port forward back at `10.0.20.30`, then
start the stacks on the VM again. Keep the VM (stopped) until the cluster version has run
cleanly for a while.
