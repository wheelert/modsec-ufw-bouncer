#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="modsec-ufw-bouncer"

if [[ $EUID -ne 0 ]]; then
  echo "Run ${BASH_SOURCE[0]} with sudo to install system files." >&2
  exit 1
fi

# Preserve an existing configuration if one is already deployed.
if [[ -e /etc/${SERVICE_NAME}.conf ]]; then
  echo "Existing /etc/${SERVICE_NAME}.conf preserved."
else
  install -D -m 0600 "${SCRIPT_DIR}/${SERVICE_NAME}.conf" "/etc/${SERVICE_NAME}.conf"
fi

install -D -m 0755 "${SCRIPT_DIR}/${SERVICE_NAME}.py" "/usr/local/sbin/${SERVICE_NAME}.py"
install -D -m 0644 "${SCRIPT_DIR}/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service"
install -d -m 0750 /var/lib/${SERVICE_NAME}

systemctl daemon-reload

echo "Installation complete."
echo "Before starting, edit /etc/${SERVICE_NAME}.conf and verify log_paths/rules."
echo "Then run:"
echo "  sudo modsec-ufw-bouncer.py --dry-run -v"
echo "  sudo systemctl enable --now ${SERVICE_NAME}.service"
echo
echo "To stop/start later:"
echo "  sudo systemctl stop ${SERVICE_NAME}.service"
echo "  sudo systemctl start ${SERVICE_NAME}.service"
