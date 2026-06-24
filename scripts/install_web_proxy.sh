#!/usr/bin/env bash
set -euo pipefail

SERVER="${1:-nginx}"
CERT_DIR="/etc/ssl/vet-compliance"
CONF_SRC="deploy/${SERVER}/vet-compliance.conf"

if [[ ! -f "${CONF_SRC}" ]]; then
  echo "Unknown server '${SERVER}'. Use nginx or apache." >&2
  exit 1
fi

sudo mkdir -p "${CERT_DIR}"
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout "${CERT_DIR}/vet-compliance.key" \
  -out "${CERT_DIR}/vet-compliance.crt" \
  -subj "/CN=vet-compliance.local"

if [[ "${SERVER}" == "nginx" ]]; then
  sudo cp "${CONF_SRC}" /etc/nginx/conf.d/vet-compliance.conf
  sudo nginx -t
  sudo systemctl reload nginx
else
  sudo cp "${CONF_SRC}" /etc/apache2/sites-available/vet-compliance.conf
  sudo a2enmod ssl proxy proxy_http
  sudo a2ensite vet-compliance.conf
  sudo apachectl configtest
  sudo systemctl reload apache2
fi

