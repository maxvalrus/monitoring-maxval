#!/usr/bin/env bash
# Route Docker container traffic through the host's ordinary main route.
# Host traffic, including Codex/SSH and manual commands, remains governed by WireGuard.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

unit_path=/etc/systemd/system/monitoring-docker-bypass-wireguard.service

cat >"${unit_path}" <<'EOF'
[Unit]
Description=Route Monitoring Maxval Docker egress outside WireGuard
After=network-online.target docker.service wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Remove both the legacy lower-priority rules and any previous version of this unit.
ExecStartPre=-/usr/sbin/ip rule del priority 10000 from 172.17.0.0/16 lookup main
ExecStartPre=-/usr/sbin/ip rule del priority 10001 from 172.18.0.0/16 lookup main
ExecStartPre=-/usr/sbin/ip rule del priority 10002 from 172.19.0.0/16 lookup main
ExecStartPre=-/usr/sbin/ip rule del priority 9990 from 172.17.0.0/16 lookup main
ExecStartPre=-/usr/sbin/ip rule del priority 9991 from 172.18.0.0/16 lookup main
ExecStartPre=-/usr/sbin/ip rule del priority 9992 from 172.19.0.0/16 lookup main

# These priorities precede WireGuard rules 9998/9999.
ExecStart=/usr/sbin/ip rule add priority 9990 from 172.17.0.0/16 lookup main
ExecStart=/usr/sbin/ip rule add priority 9991 from 172.18.0.0/16 lookup main
ExecStart=/usr/sbin/ip rule add priority 9992 from 172.19.0.0/16 lookup main

ExecStop=-/usr/sbin/ip rule del priority 9990 from 172.17.0.0/16 lookup main
ExecStop=-/usr/sbin/ip rule del priority 9991 from 172.18.0.0/16 lookup main
ExecStop=-/usr/sbin/ip rule del priority 9992 from 172.19.0.0/16 lookup main

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now monitoring-docker-bypass-wireguard.service
systemctl restart monitoring-docker-bypass-wireguard.service

echo
echo "Active Docker bypass rules:"
ip -4 rule show | grep -E '^(999[0-2]|1000[0-2]):' || true
