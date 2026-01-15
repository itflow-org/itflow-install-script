#!/usr/bin/env bash
set -euo pipefail

# =========================
# ITFlow Installer (Debian / Ubuntu 24.04)
#
# Highlights:
# - Auto-elevate to root via sudo (fail-fast if unable)
# - Non-interactive apt update/upgrade at start
# - Install prerequisites up front (assume clean base distro)
# - Number-based menus for selection prompts
# - Optional "High performance" mode: php-fpm + mpm_event (better concurrency)
# - Adaptive autotune at EVERY BOOT (and once during install) for:
#     - MariaDB (InnoDB, connections, slow log)
#     - PHP OPcache
#     - PHP-FPM pool sizing (high profile)
#     - systemd limits (nofile)
#     - sysctl (somaxconn, swappiness, etc)
#     - Apache MPM worker settings (prefork or event)
# - LetsEncrypt classic HTTP-01 OR Cloudflare DNS-01
# - UFW gate for classic HTTP-01 (80/443) with prompt
# - Cleanup options + resilient re-runs
# - Fix Apache FQDN warning by setting global ServerName
# - Reboot prompt (Enter = YES), strict Y/n parsing, EXIT after reboot
#
# Cloudflare DNS-01 token permissions:
# - Zone:DNS:Edit (required)
# - Zone:Read (nice-to-have)
# =========================

# ---------
# Elevate
# ---------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[INFO] Not running as root. Attempting to elevate via sudo..."
    exec sudo -E bash "$0" "$@"
  else
    echo "[ERROR] Not running as root and sudo is not installed. Re-run as root." >&2
    exit 1
  fi
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Log
LOG_FILE="/var/log/itflow_install.log"
rm -f "$LOG_FILE" || true
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log() { echo "$(date -Is) : $1" >> "$LOG_FILE"; }
say() { echo -e "${GREEN}$1${NC}"; log "$1"; }
warn() { echo -e "${YELLOW}$1${NC}"; log "WARN: $1"; }
die() { echo -e "${RED}$1${NC}"; log "ERROR: $1"; exit 1; }

# Spinner
spin() {
  local pid=$!
  local delay=0.1
  local spinner='|/-\\'
  local message="$1"
  while kill -0 $pid 2>/dev/null; do
    for i in $(seq 0 3); do
      printf "\r%s %s" "$message" "${spinner:$i:1}"
      sleep $delay
    done
  done
  printf "\r%s... Done!        \n" "$message"
}

usage() {
  cat <<'EOF'

Usage: itflow_install.sh [options]

Core:
  -d, --domain FQDN                 e.g. itflow.example.com
  -t, --timezone ZONE               e.g. America/Denver, America/New_York, UTC
  -b, --branch BRANCH               master|develop (default: master)
  -s, --ssl TYPE                    letsencrypt|letsencrypt-dns-cloudflare|selfsigned|none
  -u, --unattended                  non-interactive run

Access mode (affects notes printed at end):
      --access-mode MODE            direct|proxy|cloudflare-tunnel (default: direct)

Performance profile:
      --performance-profile MODE    balanced|high (default: balanced)
                                    balanced = classic mod_php (prefork)
                                    high     = php-fpm + mpm_event + tuned concurrency

Let's Encrypt (DNS-01 via Cloudflare API Token):
      --email EMAIL                 Let's Encrypt email (required if issuing unattended)
      --cf-token TOKEN              Cloudflare API Token (Zone:DNS:Edit) (required if issuing unattended)
      --cf-propagation SECONDS      DNS propagation wait (default: 60)
      --reuse-cert-name NAME        Reuse existing cert from /etc/letsencrypt/live/NAME/

Cleanup:
      --cleanup-web                 Remove existing webroot + Apache vhosts + cron for this domain
      --cleanup-db                  Drop itflow DB + user (destructive)
      --cleanup-all                 Equivalent to --cleanup-web --cleanup-db

Notes:
- letsencrypt = classic HTTP-01 via Apache plugin (requires inbound port 80 to this server).
- letsencrypt-dns-cloudflare = DNS-01 via Cloudflare token (works behind Cloudflare Tunnel; no inbound ports).
- Autotune runs at EVERY BOOT (and once during install). Re-run anytime:
    sudo /usr/local/sbin/itflow-autotune.sh

EOF
}

export DEBIAN_FRONTEND=noninteractive

# -------------------------
# Defaults + CLI
# -------------------------
unattended=false
domain=""
timezone=""
branch="master"
ssl_type="letsencrypt"
access_mode="direct"                 # direct|proxy|cloudflare-tunnel
perf_profile="balanced"              # balanced|high

le_email=""
cf_token=""
cf_propagation="60"
reuse_cert_name=""

cleanup_web=false
cleanup_db=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) domain="${2:-}"; shift 2 ;;
    -t|--timezone) timezone="${2:-}"; shift 2 ;;
    -b|--branch) branch="${2:-}"; shift 2 ;;
    -s|--ssl) ssl_type="${2:-}"; shift 2 ;;
    -u|--unattended) unattended=true; shift ;;
    --access-mode) access_mode="${2:-}"; shift 2 ;;
    --performance-profile) perf_profile="${2:-}"; shift 2 ;;
    --email) le_email="${2:-}"; shift 2 ;;
    --cf-token) cf_token="${2:-}"; shift 2 ;;
    --cf-propagation) cf_propagation="${2:-60}"; shift 2 ;;
    --reuse-cert-name) reuse_cert_name="${2:-}"; shift 2 ;;
    --cleanup-web) cleanup_web=true; shift ;;
    --cleanup-db) cleanup_db=true; shift ;;
    --cleanup-all) cleanup_web=true; cleanup_db=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

case "$access_mode" in direct|proxy|cloudflare-tunnel) ;; *) die "Invalid --access-mode: $access_mode" ;; esac
case "$perf_profile" in balanced|high) ;; *) die "Invalid --performance-profile: $perf_profile" ;; esac

# -------------------------
# System update + prerequisites up front
# -------------------------
say "Updating system packages (apt-get update/upgrade)..."
{
  apt-get -y update
  apt-get -y upgrade
} & spin "System update"

say "Installing prerequisites (assume clean base distro)..."
{
  apt-get install -y \
    sudo ca-certificates apt-transport-https gnupg lsb-release \
    curl wget unzip \
    git \
    cron \
    dnsutils \
    openssl \
    whois \
    ufw \
    apache2 \
    mariadb-server \
    php libapache2-mod-php \
    php-intl php-mysqli php-gd php-curl php-mbstring php-zip php-xml \
    php-opcache \
    certbot \
    python3 python3-venv python3-pip \
    python3-certbot-dns-cloudflare
} & spin "Installing prerequisites"

# -------------------------
# Menu helpers (interactive)
# -------------------------
choose_access_mode() {
  local default_choice="${1:-1}"
  local choice=""
  echo ""
  echo "Access mode (how will users reach ITFlow?):"
  echo "  1) Direct (public DNS -> this server)            [default]"
  echo "  2) Reverse proxy (Nginx/HAProxy/Caddy in front)"
  echo "  3) Cloudflare Tunnel (Zero Trust)"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) access_mode="direct" ;;
    2) access_mode="proxy" ;;
    3) access_mode="cloudflare-tunnel" ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_access_mode "$default_choice" ;;
  esac
}

choose_perf_profile() {
  local default_choice="${1:-1}"
  local choice=""
  echo ""
  echo "Performance profile:"
  echo "  1) Balanced (classic mod_php + prefork)               [default]"
  echo "  2) High performance (php-fpm + mpm_event)             (better concurrency)"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) perf_profile="balanced" ;;
    2) perf_profile="high" ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_perf_profile "$default_choice" ;;
  esac
}

choose_timezone() {
  local detected="${1:-UTC}"
  local default_choice="${2:-1}"
  local choice=""
  echo ""
  echo "Timezone:"
  echo "  1) Use detected: ${detected}          [default]"
  echo "  2) Use UTC"
  echo "  3) Enter manually (examples: America/Denver, America/New_York, UTC)"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) timezone="$detected" ;;
    2) timezone="UTC" ;;
    3)
      read -r -p "Enter timezone (e.g. America/Denver): " timezone
      timezone="${timezone:-$detected}"
      ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_timezone "$detected" "$default_choice" ;;
  esac
}

choose_branch() {
  local default_choice="${1:-1}"
  local choice=""
  echo ""
  echo "ITFlow branch:"
  echo "  1) master  (stable)  [default]"
  echo "  2) develop (testing)"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) branch="master" ;;
    2) branch="develop" ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_branch "$default_choice" ;;
  esac
}

choose_tls_mode() {
  local default_choice="${1:-1}"
  local choice=""
  echo ""
  echo "TLS mode:"
  echo "  1) Let's Encrypt (classic HTTP-01)        - requires inbound port 80 to this server [default]"
  echo "  2) Let's Encrypt (Cloudflare DNS-01)      - works behind Cloudflare Tunnel (no inbound ports)"
  echo "  3) Self-signed (origin)"
  echo "  4) None (origin HTTP; edge TLS only if using a proxy/Tunnel)"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) ssl_type="letsencrypt" ;;
    2) ssl_type="letsencrypt-dns-cloudflare" ;;
    3) ssl_type="selfsigned" ;;
    4) ssl_type="none" ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_tls_mode "$default_choice" ;;
  esac
}

choose_cleanup() {
  local default_choice="${1:-1}"
  local choice=""
  echo ""
  echo "Cleanup options:"
  echo "  1) No cleanup (default)"
  echo "  2) Cleanup web only (Apache vhosts, webroot, cron for this domain)"
  echo "  3) Cleanup DB only  (DROP database + user)  [DESTRUCTIVE]"
  echo "  4) Cleanup ALL      (web + DB)              [DESTRUCTIVE]"
  read -r -p "Select [${default_choice}]: " choice
  choice="${choice:-$default_choice}"
  case "$choice" in
    1) cleanup_web=false; cleanup_db=false ;;
    2) cleanup_web=true;  cleanup_db=false ;;
    3) cleanup_web=false; cleanup_db=true  ;;
    4) cleanup_web=true;  cleanup_db=true  ;;
    *) echo -e "${YELLOW}Invalid selection. Try again.${NC}"; choose_cleanup "$default_choice" ;;
  esac
}

# -------------------------
# Prompts / validation
# -------------------------
if [[ "$unattended" != true ]]; then
  choose_access_mode 1
  choose_perf_profile 1
fi
say "Access mode: $access_mode"
say "Performance profile: $perf_profile"

detected_tz="${timezone:-$(cat /etc/timezone 2>/dev/null || echo "UTC")}"
if [[ "$unattended" == true ]]; then
  timezone="${timezone:-$detected_tz}"
else
  choose_timezone "$detected_tz" 1
fi
[[ -f "/usr/share/zoneinfo/$timezone" ]] || die "Invalid timezone: $timezone"
timedatectl set-timezone "$timezone"
say "Timezone set to: $timezone"

current_fqdn="$(hostname -f 2>/dev/null || true)"
domain="${domain:-$current_fqdn}"
if [[ "$unattended" != true ]]; then
  read -r -p "FQDN for ITFlow (e.g. itflow.example.com) [${domain}]: " input_domain
  domain="${input_domain:-$domain}"
fi
[[ "$domain" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]] || die "Invalid FQDN: $domain"
say "Domain set to: $domain"

if [[ "$unattended" != true ]]; then
  choose_branch 1
fi
[[ "$branch" == "master" || "$branch" == "develop" ]] || die "Invalid branch: $branch"
say "Branch set to: $branch"

if [[ "$unattended" != true ]]; then
  choose_tls_mode 1
fi
case "$ssl_type" in letsencrypt|letsencrypt-dns-cloudflare|selfsigned|none) ;; *) die "Invalid TLS mode: $ssl_type" ;; esac
say "TLS mode: $ssl_type"

if [[ "$unattended" != true ]]; then
  if [[ "$cleanup_web" == false && "$cleanup_db" == false ]]; then
    choose_cleanup 1
  fi
fi
say "Cleanup selected: web=$cleanup_web db=$cleanup_db"

config_https_only="TRUE"
[[ "$ssl_type" == "none" ]] && config_https_only="FALSE"

# -------------------------
# Derived versions / paths
# -------------------------
PHP_VERSION="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
PHP_FPM_PKG="php${PHP_VERSION}-fpm"

WEBROOT="/var/www/${domain}"
VHOST_HTTP="/etc/apache2/sites-available/${domain}.conf"
VHOST_SSL="/etc/apache2/sites-available/${domain}-ssl.conf"
CRON_FILE="/etc/cron.d/itflow"

# -------------------------
# Cleanup
# -------------------------
cleanup_web_fn() {
  say "Cleanup (web): disabling vhosts, removing webroot, removing cron..."
  a2dissite "${domain}.conf" >/dev/null 2>&1 || true
  a2dissite "${domain}-ssl.conf" >/dev/null 2>&1 || true
  systemctl reload apache2 >/dev/null 2>&1 || true

  rm -f "$VHOST_HTTP" "$VHOST_SSL" || true

  if [[ -d "$WEBROOT" ]]; then
    rm -rf "$WEBROOT"
  fi

  rm -f "$CRON_FILE" || true
  systemctl reload apache2 >/dev/null 2>&1 || true
}

cleanup_db_fn() {
  say "Cleanup (db): dropping itflow database and user (DESTRUCTIVE)..."
  until mysqladmin ping --silent; do sleep 1; done
  mysql -u root <<'SQL'
DROP DATABASE IF EXISTS itflow;
DROP USER IF EXISTS 'itflow'@'localhost';
FLUSH PRIVILEGES;
SQL
}

if [[ "$cleanup_web" == true ]]; then cleanup_web_fn; fi
if [[ "$cleanup_db" == true ]]; then cleanup_db_fn; fi

# -------------------------
# Performance profile setup: php-fpm + mpm_event (optional)
# -------------------------
enable_high_perf_stack() {
  say "Enabling high performance stack: php-fpm + mpm_event..."
  {
    apt-get install -y "$PHP_FPM_PKG"

    a2dismod "php${PHP_VERSION}" >/dev/null 2>&1 || true
    a2dismod mpm_prefork >/dev/null 2>&1 || true
    a2enmod mpm_event >/dev/null 2>&1 || true
    a2enmod proxy_fcgi setenvif >/dev/null 2>&1 || true
    a2enconf "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true

    systemctl enable --now "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
    systemctl restart "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
    systemctl restart apache2
  } & spin "High performance stack"
}

if [[ "$perf_profile" == "high" ]]; then
  enable_high_perf_stack
else
  say "Using balanced stack: classic mod_php (prefork)."
fi

# -------------------------
# PHP baseline tuning (uploads etc)
# -------------------------
PHP_INI_PATH="/etc/php/${PHP_VERSION}/apache2/php.ini"
PHP_FPM_INI_PATH="/etc/php/${PHP_VERSION}/fpm/php.ini"

say "Configuring PHP baseline settings..."
{
  if [[ -f "$PHP_INI_PATH" ]]; then
    sed -i 's/^;\?upload_max_filesize =.*/upload_max_filesize = 500M/' "$PHP_INI_PATH" || true
    sed -i 's/^;\?post_max_size =.*/post_max_size = 500M/' "$PHP_INI_PATH" || true
    sed -i 's/^;\?max_execution_time =.*/max_execution_time = 300/' "$PHP_INI_PATH" || true
  fi

  if [[ -f "$PHP_FPM_INI_PATH" ]]; then
    sed -i 's/^;\?upload_max_filesize =.*/upload_max_filesize = 500M/' "$PHP_FPM_INI_PATH" || true
    sed -i 's/^;\?post_max_size =.*/post_max_size = 500M/' "$PHP_FPM_INI_PATH" || true
    sed -i 's/^;\?max_execution_time =.*/max_execution_time = 300/' "$PHP_FPM_INI_PATH" || true
  fi
} & spin "PHP baseline"

# -------------------------
# Apache global ServerName (fix FQDN warning)
# -------------------------
say "Setting Apache global ServerName..."
{
  echo "ServerName ${domain}" > /etc/apache2/conf-available/servername.conf
  a2enconf servername >/dev/null 2>&1 || true
  systemctl reload apache2
} & spin "Apache ServerName"

# -------------------------
# Apache vhosts (HTTP)
# -------------------------
say "Configuring Apache HTTP vhost..."
{
  a2enmod ssl headers rewrite >/dev/null || true
  mkdir -p "$WEBROOT"

  cat > "$VHOST_HTTP" <<EOF
<VirtualHost *:80>
  ServerName ${domain}
  DocumentRoot ${WEBROOT}

  $( [[ "$ssl_type" != "none" ]] && echo "RewriteEngine On
  RewriteCond %{HTTPS} !=on
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]" )

  <Directory ${WEBROOT}>
    AllowOverride All
    Require all granted
  </Directory>

  ErrorLog \${APACHE_LOG_DIR}/${domain}-error.log
  CustomLog \${APACHE_LOG_DIR}/${domain}-access.log combined
</VirtualHost>
EOF

  a2ensite "${domain}.conf" >/dev/null
  a2dissite 000-default.conf >/dev/null || true
  systemctl reload apache2
} & spin "Apache HTTP vhost"

# -------------------------
# Cert helpers
# -------------------------
cert_ok() {
  local fullchain="$1"
  [[ -f "$fullchain" ]] || return 1
  local now_epoch exp_epoch
  now_epoch="$(date +%s)"
  exp_epoch="$(date -d "$(openssl x509 -in "$fullchain" -noout -enddate | cut -d= -f2)" +%s 2>/dev/null)" || return 1
  (( exp_epoch > now_epoch + 7*24*3600 )) || return 1
  return 0
}

# -------------------------
# UFW helpers for classic LE
# -------------------------
ufw_is_active() { ufw status 2>/dev/null | head -n 1 | grep -qi "Status: active"; }
ufw_has_apache_full_profile() { ufw app list 2>/dev/null | grep -qx "Apache Full"; }
ufw_allows_80_443() {
  local status; status="$(ufw status 2>/dev/null || true)"
  echo "$status" | grep -Eq '(^|\s)(Apache Full)\s' && return 0
  echo "$status" | grep -Eq '(^|\s)80(/tcp)?\s' && echo "$status" | grep -Eq '(^|\s)443(/tcp)?\s' && return 0
  return 1
}
ensure_ufw_ports_for_classic_le() {
  ufw_is_active || { warn "UFW is not active. Skipping UFW port checks for 80/443."; return 0; }
  if ufw_allows_80_443; then say "UFW is active and ports 80/443 appear allowed."; return 0; fi

  warn "UFW is active but ports 80/443 are not clearly allowed."
  warn "Classic Let's Encrypt (HTTP-01) needs inbound port 80 to reach this server."

  if [[ "$unattended" == true ]]; then
    die "Unattended + classic letsencrypt + UFW blocking ports. Open 80/443 in UFW or use letsencrypt-dns-cloudflare."
  fi

  read -r -p "Allow this script to open ports 80 and 443 in UFW now? [Y/n]: " ans
  ans="${ans:-Y}"
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    if ufw_has_apache_full_profile; then
      ufw allow "Apache Full" >/dev/null
      say "UFW: allowed 'Apache Full' (80/443)."
    else
      ufw allow 80/tcp >/dev/null
      ufw allow 443/tcp >/dev/null
      say "UFW: allowed 80/tcp and 443/tcp."
    fi
    ufw reload >/dev/null || true
  else
    die "Ports not opened. Classic letsencrypt will likely fail. Use letsencrypt-dns-cloudflare if behind a Tunnel."
  fi
}

# -------------------------
# TLS setup
# -------------------------
if [[ "$ssl_type" == "letsencrypt" || "$ssl_type" == "letsencrypt-dns-cloudflare" ]]; then
  say "Configuring Let's Encrypt (reuse existing cert if present)..."

  CERT_NAME="${reuse_cert_name:-$domain}"
  LIVE_DIR="/etc/letsencrypt/live/${CERT_NAME}"
  FULLCHAIN="${LIVE_DIR}/fullchain.pem"
  PRIVKEY="${LIVE_DIR}/privkey.pem"

  if [[ -f "$FULLCHAIN" && -f "$PRIVKEY" ]] && cert_ok "$FULLCHAIN"; then
    say "Found existing valid cert at ${LIVE_DIR}. Skipping issuance."
  else
    say "No valid cert found at ${LIVE_DIR}. Issuing a new certificate..."

    if [[ "$unattended" == true ]]; then
      [[ -n "$le_email" ]] || die "Missing --email for unattended issuance"
    else
      if [[ -z "$le_email" ]]; then read -r -p "Let's Encrypt account email (required to issue cert): " le_email; fi
      [[ -n "$le_email" ]] || die "Email is required to issue a new cert."
    fi

    if [[ "$ssl_type" == "letsencrypt" ]]; then
      warn "Classic Let's Encrypt (HTTP-01) requires inbound port 80 to this server."
      warn "If behind Cloudflare Tunnel / no inbound ports, pick DNS-01 option."
      ensure_ufw_ports_for_classic_le

      certbot certonly --apache \
        --non-interactive --agree-tos \
        -m "$le_email" --keep-until-expiring \
        -d "$domain"
    else
      if [[ "$unattended" == true ]]; then
        [[ -n "$cf_token" ]] || die "Missing --cf-token for unattended Cloudflare DNS-01 issuance"
      else
        if [[ -z "$cf_token" ]]; then
          echo -e "${YELLOW}Cloudflare API Token (needs Zone:DNS:Edit) (input hidden):${NC}"
          read -r -s cf_token; echo ""
        fi
        [[ -n "$cf_token" ]] || die "Cloudflare token is required to issue a new cert."
      fi

      CF_CREDS_DIR="/root/.secrets/certbot"
      CF_CREDS_FILE="${CF_CREDS_DIR}/cloudflare.ini"
      mkdir -p "$CF_CREDS_DIR"
      tee "$CF_CREDS_FILE" >/dev/null <<EOF
dns_cloudflare_api_token = ${cf_token}
EOF
      chmod 700 "$CF_CREDS_DIR"
      chmod 600 "$CF_CREDS_FILE"

      certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CF_CREDS_FILE" \
        --preferred-challenges dns-01 \
        --dns-cloudflare-propagation-seconds "$cf_propagation" \
        --non-interactive --agree-tos \
        -m "$le_email" --keep-until-expiring \
        -d "$domain"
    fi

    LIVE_DIR="/etc/letsencrypt/live/${domain}"
    FULLCHAIN="${LIVE_DIR}/fullchain.pem"
    PRIVKEY="${LIVE_DIR}/privkey.pem"
    [[ -f "$FULLCHAIN" && -f "$PRIVKEY" ]] || die "Cert issuance failed; expected files in ${LIVE_DIR}"
  fi

  say "Configuring Apache TLS vhost..."
  cat > "$VHOST_SSL" <<EOF
<VirtualHost *:443>
  ServerName ${domain}
  DocumentRoot ${WEBROOT}

  SSLEngine on
  SSLCertificateFile ${FULLCHAIN}
  SSLCertificateKeyFile ${PRIVKEY}

  <Directory ${WEBROOT}>
    AllowOverride All
    Require all granted
  </Directory>

  ErrorLog \${APACHE_LOG_DIR}/${domain}-ssl-error.log
  CustomLog \${APACHE_LOG_DIR}/${domain}-ssl-access.log combined
</VirtualHost>
EOF

  a2ensite "${domain}-ssl.conf" >/dev/null
  systemctl reload apache2
  say "Apache TLS vhost enabled."

elif [[ "$ssl_type" == "selfsigned" ]]; then
  say "Generating self-signed certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "/etc/ssl/private/${domain}.key" \
    -out "/etc/ssl/certs/${domain}.crt" \
    -subj "/C=US/ST=State/L=City/O=Org/OU=IT/CN=${domain}"

  cat > "$VHOST_SSL" <<EOF
<VirtualHost *:443>
  ServerName ${domain}
  DocumentRoot ${WEBROOT}

  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/${domain}.crt
  SSLCertificateKeyFile /etc/ssl/private/${domain}.key

  <Directory ${WEBROOT}>
    AllowOverride All
    Require all granted
  </Directory>

  ErrorLog \${APACHE_LOG_DIR}/${domain}-ssl-error.log
  CustomLog \${APACHE_LOG_DIR}/${domain}-ssl-access.log combined
</VirtualHost>
EOF

  a2ensite "${domain}-ssl.conf" >/dev/null
  systemctl reload apache2
  say "Self-signed TLS vhost enabled."
else
  warn "No TLS configured. If using a proxy/Tunnel, edge HTTPS can still work, but origin is HTTP."
fi

# -------------------------
# Clone ITFlow
# -------------------------
say "Cloning ITFlow..."
{
  if [[ -d "$WEBROOT" ]] && [[ "$(ls -A "$WEBROOT" 2>/dev/null || true)" != "" ]]; then
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="${WEBROOT}.bak-${ts}"
    warn "Webroot not empty; moving existing ${WEBROOT} to ${backup}"
    mv "$WEBROOT" "$backup"
    mkdir -p "$WEBROOT"
  fi

  git clone --branch "$branch" https://github.com/itflow-org/itflow.git "$WEBROOT"
  chown -R www-data:www-data "$WEBROOT"
} & spin "Cloning ITFlow"

# -------------------------
# Cron
# -------------------------
say "Setting cron jobs..."
PHP_BIN="$(command -v php)"
cat > "$CRON_FILE" <<EOF
0 2 * * * www-data ${PHP_BIN} ${WEBROOT}/cron/cron.php
* * * * * www-data ${PHP_BIN} ${WEBROOT}/cron/ticket_email_parser.php
* * * * * www-data ${PHP_BIN} ${WEBROOT}/cron/mail_queue.php
0 3 * * * www-data ${PHP_BIN} ${WEBROOT}/cron/domain_refresher.php
0 4 * * * www-data ${PHP_BIN} ${WEBROOT}/cron/certificate_refresher.php
EOF
chmod 644 "$CRON_FILE"
chown root:root "$CRON_FILE"

# -------------------------
# MariaDB baseline + ITFlow user (idempotent)
# -------------------------
say "Configuring MariaDB..."
{
  systemctl enable --now mariadb >/dev/null 2>&1 || true
  until mysqladmin ping --silent; do sleep 1; done

  mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS itflow CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'itflow'@'localhost' IDENTIFIED BY 'placeholder';
ALTER USER 'itflow'@'localhost' IDENTIFIED BY 'placeholder';

GRANT ALL PRIVILEGES ON itflow.* TO 'itflow'@'localhost';
FLUSH PRIVILEGES;
SQL
} & spin "MariaDB baseline"

# Generate secrets (no pipes!)
mariadbpwd="$(openssl rand -hex 16)"
INSTALL_ID="$(openssl rand -hex 16)"

say "Setting ITFlow DB password..."
mysql -u root <<SQL
ALTER USER 'itflow'@'localhost' IDENTIFIED BY '${mariadbpwd}';
FLUSH PRIVILEGES;
SQL

# Import DB
SQL_DUMP="${WEBROOT}/db.sql"
if [[ -f "$SQL_DUMP" ]]; then
  say "Importing database dump..."
  mysql -u itflow -p"${mariadbpwd}" itflow < "$SQL_DUMP"
else
  warn "Database dump not found at ${SQL_DUMP} (skipping import)."
fi

# -------------------------
# ITFlow config.php
# -------------------------
say "Writing ITFlow config.php..."
BASE_URL="http://${domain}"
[[ "$ssl_type" != "none" ]] && BASE_URL="https://${domain}"

cat > "${WEBROOT}/config.php" <<EOF
<?php
\$dbhost = 'localhost';
\$dbusername = 'itflow';
\$dbpassword = '${mariadbpwd}';
\$database = 'itflow';
\$mysqli = mysqli_connect(\$dbhost, \$dbusername, \$dbpassword, \$database) or die('Database Connection Failed');
\$config_app_name = 'ITFlow';
\$config_base_url = '${BASE_URL}';
\$config_https_only = ${config_https_only};
\$repo_branch = '${branch}';
\$installation_id = '${INSTALL_ID}';
EOF
chown www-data:www-data "${WEBROOT}/config.php"
chmod 640 "${WEBROOT}/config.php"

# -------------------------
# Autotune engine (adaptive at EVERY BOOT + on-demand)
# -------------------------
say "Installing adaptive autotune (MariaDB + OPcache + PHP-FPM + systemd limits + sysctl + Apache MPM)..."

AUTOTUNE_SCRIPT="/usr/local/sbin/itflow-autotune.sh"
AUTOTUNE_STATE_DIR="/var/lib/itflow-autotune"
AUTOTUNE_UNIT="/etc/systemd/system/itflow-autotune.service"

mkdir -p "$AUTOTUNE_STATE_DIR"

cat > "$AUTOTUNE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/itflow-autotune"
mkdir -p "$STATE_DIR"

FIRST_RUN_MARK="${STATE_DIR}/first_run_done"
force_apply=0
if [[ ! -f "$FIRST_RUN_MARK" ]]; then
  force_apply=1
fi

write_if_changed() {
  local path="$1"
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"

  if [[ "$force_apply" -eq 0 ]] && [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    return 1
  fi

  mkdir -p "$(dirname "$path")"
  mv "$tmp" "$path"
  return 0
}

stat_line() {
  local f="$1"
  if [[ -f "$f" ]]; then
    echo "  - $(basename "$f"): present, mtime=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1 || echo unknown)"
  else
    echo "  - $(basename "$f"): missing"
  fi
}

mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
mem_mb="$((mem_kb / 1024))"
mem_gb="$((mem_mb / 1024))"
cpu="$(nproc)"

PROFILE_FILE="${STATE_DIR}/profile"
PROFILE="balanced"
if [[ -f "$PROFILE_FILE" ]]; then
  PROFILE="$(cat "$PROFILE_FILE" || echo balanced)"
fi

# Ensure mysql log dir exists (some distros don't create it by default)
mkdir -p /var/log/mysql

# -------------------------
# MariaDB tuning (adaptive)
# -------------------------
bp_mb="$(( (mem_mb * 70) / 100 ))"
if (( bp_mb < 256 )); then bp_mb=256; fi

bp_inst="$((bp_mb / 1024))"
if (( bp_inst < 1 )); then bp_inst=1; fi
if (( bp_inst > 8 )); then bp_inst=8; fi

log_mb="$((mem_mb / 16))"
if (( log_mb < 256 )); then log_mb=256; fi
if (( log_mb > 1024 )); then log_mb=1024; fi

max_conn="$(( 100 + (mem_gb * 50) ))"
if (( max_conn < 150 )); then max_conn=150; fi
if (( max_conn > 1000 )); then max_conn=1000; fi

tmp_mb="$((mem_mb / 32))"
if (( tmp_mb < 64 )); then tmp_mb=64; fi
if (( tmp_mb > 512 )); then tmp_mb=512; fi

mariadb_conf="/etc/mysql/mariadb.conf.d/99-itflow-tuning.cnf"
mariadb_changed=0

if write_if_changed "$mariadb_conf" <<CONF
# Managed by itflow-autotune.sh (do not edit directly)
[mysqld]
innodb_buffer_pool_size = ${bp_mb}M
innodb_buffer_pool_instances = ${bp_inst}
innodb_log_file_size = ${log_mb}M
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 1
innodb_file_per_table = 1

max_connections = ${max_conn}
thread_cache_size = 100

tmp_table_size = ${tmp_mb}M
max_heap_table_size = ${tmp_mb}M

wait_timeout = 300
interactive_timeout = 300

slow_query_log = 1
slow_query_log_file = /var/log/mysql/itflow-slow.log
long_query_time = 1
log_queries_not_using_indexes = 0

max_allowed_packet = 64M
CONF
then
  mariadb_changed=1
fi

touch /var/log/mysql/itflow-slow.log || true
chown mysql:mysql /var/log/mysql/itflow-slow.log || true
chmod 640 /var/log/mysql/itflow-slow.log || true

# -------------------------
# PHP OPcache tuning (adaptive)
# -------------------------
opcache_mb=128
if (( mem_gb >= 4 )); then opcache_mb=256; fi
if (( mem_gb >= 16 )); then opcache_mb=512; fi

opcache_files=20000
if (( mem_gb >= 8 )); then opcache_files=40000; fi

php_changed=0
php_ver="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
for sapi in apache2 fpm cli; do
  ini_dir="/etc/php/${php_ver}/${sapi}/conf.d"
  [[ -d "$ini_dir" ]] || continue
  opcache_ini="${ini_dir}/99-itflow-opcache.ini"
  if write_if_changed "$opcache_ini" <<OPC
; Managed by itflow-autotune.sh (do not edit directly)
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=${opcache_mb}
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=${opcache_files}
opcache.validate_timestamps=1
opcache.revalidate_freq=2
opcache.fast_shutdown=1
OPC
  then
    php_changed=1
  fi
done

# -------------------------
# PHP-FPM pool tuning (HIGH profile only)
# -------------------------
phpfpm_changed=0
fpm_svc="php${php_ver}-fpm"
pool="/etc/php/${php_ver}/fpm/pool.d/www.conf"

if [[ "$PROFILE" == "high" ]] && [[ -f "$pool" ]]; then
  # Conservative, safe heuristics:
  # - Estimate per-child RSS ~ 60MB (varies). Use ~50% of RAM for PHP workers.
  # - Bound max_children to prevent thrashing.
  per_child_mb=60
  target_mb="$(( (mem_mb * 50) / 100 ))"
  max_children="$(( target_mb / per_child_mb ))"
  if (( max_children < 10 )); then max_children=10; fi
  if (( max_children > 200 )); then max_children=200; fi

  # dynamic: start ~ 1x CPU, min/max spares scaled
  start_servers="$cpu"
  if (( start_servers < 2 )); then start_servers=2; fi
  if (( start_servers > 20 )); then start_servers=20; fi

  min_spare="$(( start_servers ))"
  max_spare="$(( start_servers * 2 ))"
  if (( max_spare > 40 )); then max_spare=40; fi

  # Max requests helps with slow memory creep
  max_requests=2000

  fpm_tuning="/etc/php/${php_ver}/fpm/pool.d/99-itflow-pool.conf"
  if write_if_changed "$fpm_tuning" <<FPM
; Managed by itflow-autotune.sh (do not edit directly)
[www]
pm = dynamic
pm.max_children = ${max_children}
pm.start_servers = ${start_servers}
pm.min_spare_servers = ${min_spare}
pm.max_spare_servers = ${max_spare}
pm.max_requests = ${max_requests}
request_terminate_timeout = 300s
FPM
  then
    phpfpm_changed=1
  fi
fi

# -------------------------
# systemd limits (nofile)
# -------------------------
systemd_changed=0
for svc in apache2 mariadb; do
  override="/etc/systemd/system/${svc}.service.d/override.conf"
  if write_if_changed "$override" <<OVR
# Managed by itflow-autotune.sh (do not edit directly)
[Service]
LimitNOFILE=65535
OVR
  then
    systemd_changed=1
  fi
done

# -------------------------
# sysctl tuning (light touch)
# -------------------------
sysctl_changed=0
sysctl_conf="/etc/sysctl.d/99-itflow-tuning.conf"
if write_if_changed "$sysctl_conf" <<SYS
# Managed by itflow-autotune.sh (do not edit directly)
vm.swappiness=10
net.core.somaxconn=1024
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_max_syn_backlog=4096
SYS
then
  sysctl_changed=1
fi

# -------------------------
# Apache MPM tuning (adaptive)
# -------------------------
apache_changed=0

if [[ "$PROFILE" == "balanced" ]]; then
  per_proc_mb=60
  target_mb="$(( (mem_mb * 60) / 100 ))"
  max_workers="$(( target_mb / per_proc_mb ))"
  if (( max_workers < 20 )); then max_workers=20; fi
  if (( max_workers > 400 )); then max_workers=400; fi

  prefork_snip="/etc/apache2/mods-available/99-itflow-mpm.conf"
  if write_if_changed "$prefork_snip" <<PREF
# Managed by itflow-autotune.sh (do not edit directly)
<IfModule mpm_prefork_module>
  StartServers             5
  MinSpareServers          5
  MaxSpareServers         10
  MaxRequestWorkers      ${max_workers}
  MaxConnectionsPerChild  2000
</IfModule>
PREF
  then
    apache_changed=1
  fi
  a2enconf 99-itflow-mpm >/dev/null 2>&1 || true
else
  threads=25
  max_workers="$(( cpu * 150 ))"
  if (( max_workers < 150 )); then max_workers=150; fi
  if (( max_workers > 2000 )); then max_workers=2000; fi

  server_limit="$(( (max_workers + threads - 1) / threads ))"
  if (( server_limit < 4 )); then server_limit=4; fi
  if (( server_limit > 64 )); then server_limit=64; fi

  event_snip="/etc/apache2/mods-available/99-itflow-mpm.conf"
  if write_if_changed "$event_snip" <<EVT
# Managed by itflow-autotune.sh (do not edit directly)
<IfModule mpm_event_module>
  ServerLimit              ${server_limit}
  StartServers             2
  MinSpareThreads          50
  MaxSpareThreads         200
  ThreadLimit              ${threads}
  ThreadsPerChild          ${threads}
  MaxRequestWorkers       $(( server_limit * threads ))
  MaxConnectionsPerChild  10000
</IfModule>
EVT
  then
    apache_changed=1
  fi
  a2enconf 99-itflow-mpm >/dev/null 2>&1 || true
fi

# Apply changes
if (( sysctl_changed == 1 )) || (( force_apply == 1 )); then sysctl --system >/dev/null 2>&1 || true; fi
if (( systemd_changed == 1 )) || (( force_apply == 1 )); then systemctl daemon-reload >/dev/null 2>&1 || true; fi
if (( mariadb_changed == 1 )) || (( force_apply == 1 )); then systemctl restart mariadb >/dev/null 2>&1 || true; fi

if (( php_changed == 1 )) || (( phpfpm_changed == 1 )) || (( force_apply == 1 )); then
  systemctl restart "$fpm_svc" >/dev/null 2>&1 || true
fi

if (( apache_changed == 1 )) || (( systemd_changed == 1 )) || (( php_changed == 1 )) || (( force_apply == 1 )); then
  systemctl restart apache2 >/dev/null 2>&1 || true
fi

# Create first-run marker after successful apply
if (( force_apply == 1 )); then
  date -Is > "$FIRST_RUN_MARK"
fi

# -------------------------
# Verification / status output
# -------------------------
mpm="$(apachectl -M 2>/dev/null | awk '/mpm_.*_module/ {print $1}' | head -n 1 || true)"
fpm_active="unknown"
if systemctl list-unit-files 2>/dev/null | grep -q "^${fpm_svc}"; then
  fpm_active="$(systemctl is-active "$fpm_svc" 2>/dev/null || true)"
fi

echo "[itflow-autotune] profile=${PROFILE} mem_mb=${mem_mb} cpu=${cpu} force_apply=${force_apply} mariadb_changed=${mariadb_changed} php_changed=${php_changed} phpfpm_changed=${phpfpm_changed} apache_changed=${apache_changed} systemd_changed=${systemd_changed} sysctl_changed=${sysctl_changed}"
echo "[itflow-autotune] apache_mpm=${mpm:-unknown} php_fpm_service=${fpm_svc}(${fpm_active})"
echo "[itflow-autotune] file_status:"
stat_line "$mariadb_conf"
stat_line "/etc/sysctl.d/99-itflow-tuning.conf"
stat_line "/etc/apache2/mods-available/99-itflow-mpm.conf"
stat_line "/etc/php/${php_ver}/apache2/conf.d/99-itflow-opcache.ini"
stat_line "/etc/php/${php_ver}/fpm/conf.d/99-itflow-opcache.ini"
stat_line "/etc/php/${php_ver}/cli/conf.d/99-itflow-opcache.ini"
stat_line "/etc/php/${php_ver}/fpm/pool.d/99-itflow-pool.conf"
EOF

chmod 755 "$AUTOTUNE_SCRIPT"

# Save performance profile for autotune
mkdir -p "$AUTOTUNE_STATE_DIR"
echo "$perf_profile" > "${AUTOTUNE_STATE_DIR}/profile"
chmod 644 "${AUTOTUNE_STATE_DIR}/profile"

# Stronger boot ordering (cloud-init + network-online + services)
cat > "$AUTOTUNE_UNIT" <<EOF
[Unit]
Description=ITFlow Autotune (MariaDB/PHP/Apache/system)
After=network-online.target cloud-init.service mariadb.service apache2.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${AUTOTUNE_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable itflow-autotune.service >/dev/null 2>&1 || true

# Run autotune now (first pass)
say "Running autotune now (first pass)..."
"$AUTOTUNE_SCRIPT" | tee -a "$LOG_FILE" || warn "Autotune encountered issues (non-fatal). Check log."

# -------------------------
# Cert renewal dry-run (non-fatal)
# -------------------------
if [[ "$ssl_type" == "letsencrypt" || "$ssl_type" == "letsencrypt-dns-cloudflare" ]]; then
  say "Testing certbot renewal (dry-run)..."
  certbot renew --dry-run || warn "certbot renew --dry-run failed (non-fatal)."
fi

# -------------------------
# Health summary
# -------------------------
say "Health check summary:"
{
  echo "apache2:  $(systemctl is-active apache2 || true)"
  echo "mariadb:  $(systemctl is-active mariadb || true)"
  if systemctl list-unit-files | grep -q "^php${PHP_VERSION}-fpm"; then
    echo "php-fpm:  $(systemctl is-active "php${PHP_VERSION}-fpm" || true)"
  fi
  echo "apache_mpm: $(apachectl -M 2>/dev/null | awk '/mpm_.*_module/ {print $1}' | head -n 1 || echo unknown)"
  echo "disk:     $(df -h / | tail -n 1)"
  echo "mem:      $(free -h | awk 'NR==2{print $0}')"
} | tee -a "$LOG_FILE"

# -------------------------
# Finish
# -------------------------
BASE_URL_OUT="https://${domain}"
[[ "$ssl_type" == "none" ]] && BASE_URL_OUT="http://${domain}"

say "Installation Complete!"
echo -e "URL:     ${GREEN}${BASE_URL_OUT}${NC}"
echo -e "DB User: ${GREEN}itflow${NC}"
echo -e "DB Pass: ${GREEN}${mariadbpwd}${NC}"
echo -e "Log:     ${GREEN}${LOG_FILE}${NC}"
echo -e "Autotune:${GREEN} sudo ${AUTOTUNE_SCRIPT}${NC}  (also runs automatically at every boot)"

# Cloudflare notes ONLY when access_mode is cloudflare-tunnel
if [[ "$access_mode" == "cloudflare-tunnel" ]]; then
  cat <<EOF

Cloudflare Tunnel notes:
- Public hostname: ${domain}
- Origin service (recommended): https://localhost:443

Cloudflare Tunnel origin settings (recommended to avoid cert/vhost weirdness):
- Turn ON:  Match SNI to Host
- Set:      Origin Server Name  = ${domain}
- Set:      HTTP Host Header    = ${domain}

Cloudflare SSL/TLS mode guidance (choose what fits your risk tolerance):
- "Full (strict)" is recommended if your origin has a valid cert (Let's Encrypt is ideal).
- "Full" can work if your origin cert isn't publicly trusted (e.g., self-signed), but it's less strict.
- If you use origin TLS mode "none" (HTTP to origin), Cloudflare can still serve HTTPS at the edge.

EOF
fi

# -------------------------
# Reboot recommendation/prompt (interactive only)
# - Enter defaults to YES
# - Only 'n'/'N' rejects
# - Anything else re-prompts
# - EXIT after reboot to avoid SSH prompt artifacts
# -------------------------
echo ""
echo -e "${YELLOW}Recommendation:${NC} Reboot this server to finalize dependency changes and ensure all services start clean."
if [[ "$unattended" == true ]]; then
  echo -e "${YELLOW}Unattended mode:${NC} Not rebooting automatically. Reboot when convenient:"
  echo -e "  ${GREEN}sudo reboot${NC}"
else
  while true; do
    read -r -p "Reboot now? [Y/n]: " rb
    rb="${rb:-Y}"
    case "$rb" in
      Y|y)
        say "Rebooting now..."
        reboot
        exit 0
        ;;
      N|n)
        warn "Reboot skipped. Please reboot later to finalize the install."
        echo -e "Run: ${GREEN}sudo reboot${NC}"
        break
        ;;
      *)
        echo "Please enter Y or n."
        ;;
    esac
  done
fi
