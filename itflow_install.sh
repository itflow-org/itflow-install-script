#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Log
LOG_FILE="/var/log/itflow_install.log"
rm -f "$LOG_FILE"

# Spinner
spin() {
    local pid=$!
    local delay=0.1
    local spinner='|/-\\'
    local message=$1
    while kill -0 $pid 2>/dev/null; do
        for i in $(seq 0 3); do
            printf "\r$message ${spinner:$i:1}"
            sleep $delay
        done
    done
    printf "\r$message... Done!        \n"
}

log() {
    echo "$(date): $1" >> "$LOG_FILE"
}

show_progress() {
    echo -e "${GREEN}$1${NC}"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root.${NC}"
    exit 1
fi

# CLI Args
unattended=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            domain="$2"
            shift 2
            ;;
        -t|--timezone)
            timezone="$2"
            shift 2
            ;;
        -b|--branch)
            branch="$2"
            shift 2
            ;;
        -s|--ssl)
            ssl_type="$2"
            shift 2
            ;;
        -u|--unattended)
            unattended=true
            shift
            ;;
        -h|--help)
            echo -e "\nUsage: $0 [options]"
            echo "  -d, --domain DOMAIN        Set the domain name (FQDN)"
            echo "  -t, --timezone ZONE        Set the system timezone"
            echo "  -b, --branch BRANCH        Git branch to use: master or develop"
            echo "  -s, --ssl TYPE             SSL type: letsencrypt, selfsigned, none"
            echo "  -u, --unattended           Run in fully automated mode"
            echo "  -h, --help                 Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option $1${NC}"
            exit 1
            ;;
    esac
done

# Timezone
if [ "$unattended" = true ]; then
    timezone=${timezone:-"America/New_York"}
else
    timezone=${timezone:-$(cat /etc/timezone 2>/dev/null || echo "UTC")}
    read -p "Timezone [${timezone}]: " input_tz
    timezone=${input_tz:-$timezone}
fi

if [ -f "/usr/share/zoneinfo/$timezone" ]; then
    timedatectl set-timezone "$timezone"
else
    echo -e "${RED}Invalid timezone.${NC}"
    exit 1
fi

# Domain
current_fqdn=$(hostname -f 2>/dev/null || echo "")
domain=${domain:-$current_fqdn}
if [ "$unattended" != true ]; then
    read -p "Domain [${domain}]: " input_domain
    domain=${input_domain:-$domain}
fi
if ! [[ $domain =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}Invalid domain.${NC}"
    exit 1
fi

# Branch
branch=${branch:-master}
if [ "$unattended" != true ]; then
    echo -e "Available branches: master, develop"
    read -p "Which branch to use [${branch}]: " input_branch
    branch=${input_branch:-$branch}
fi
if [[ "$branch" != "master" && "$branch" != "develop" ]]; then
    echo -e "${RED}Invalid branch.${NC}"
    exit 1
fi

# SSL
ssl_type=${ssl_type:-letsencrypt}
if [ "$unattended" != true ]; then
    echo -e "SSL options: letsencrypt, selfsigned, none"
    read -p "SSL type [${ssl_type}]: " input_ssl
    ssl_type=${input_ssl:-$ssl_type}
fi
if [[ "$ssl_type" != "letsencrypt" && "$ssl_type" != "selfsigned" && "$ssl_type" != "none" ]]; then
    echo -e "${RED}Invalid SSL option.${NC}"
    exit 1
fi

# HTTPS config flag
config_https_only="TRUE"
if [[ "$ssl_type" == "none" ]]; then
    config_https_only="FALSE"
fi

# Passwords
MARIADB_ROOT_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
mariadbpwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)

# Install packages
show_progress "Installing packages..."
{
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get -y upgrade
    apt-get install -y apache2 mariadb-server \
        php libapache2-mod-php php-intl php-mysqli php-gd \
        php-curl php-mbstring php-zip \
        certbot python3-certbot-apache git sudo whois cron dnsutils openssl
} & spin "Installing packages"

# PHP config
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
PHP_INI_PATH="/etc/php/${PHP_VERSION}/apache2/php.ini"
sed -i 's/^;\?upload_max_filesize =.*/upload_max_filesize = 500M/' "$PHP_INI_PATH"
sed -i 's/^;\?post_max_size =.*/post_max_size = 500M/' "$PHP_INI_PATH"
sed -i 's/^;\?max_execution_time =.*/max_execution_time = 300/' "$PHP_INI_PATH"

# Apache setup
show_progress "Configuring Apache..."
{
    a2enmod md ssl rewrite
    mkdir -p /var/www/${domain}

    cat <<EOF > /etc/apache2/sites-available/${domain}.conf
<VirtualHost *:80>
    ServerName ${domain}
    DocumentRoot /var/www/${domain}
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

    a2ensite ${domain}.conf
    a2dissite 000-default.conf
    systemctl reload apache2

    if [[ "$ssl_type" == "letsencrypt" ]]; then
        certbot --apache --non-interactive --agree-tos --register-unsafely-without-email --domains ${domain}
    elif [[ "$ssl_type" == "selfsigned" ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/${domain}.key \
            -out /etc/ssl/certs/${domain}.crt \
            -subj "/C=US/ST=State/L=City/O=Org/OU=IT/CN=${domain}"

        cat <<EOFSSL > /etc/apache2/sites-available/${domain}-ssl.conf
<VirtualHost *:443>
    ServerName ${domain}
    DocumentRoot /var/www/${domain}

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/${domain}.crt
    SSLCertificateKeyFile /etc/ssl/private/${domain}.key

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOFSSL
        a2ensite ${domain}-ssl.conf
        systemctl reload apache2
    else
        echo -e "${YELLOW}No SSL will be configured. HTTPS will not be available.${NC}"
    fi
} & spin "Apache setup and SSL"

# Git clone
show_progress "Cloning ITFlow..."
{
    git clone --branch ${branch} https://github.com/itflow-org/itflow.git /var/www/${domain}
    chown -R www-data:www-data /var/www/${domain}
} & spin "Cloning ITFlow"

# Cron jobs
PHP_BIN=$(command -v php)
cat <<EOF > /etc/cron.d/itflow
0 2 * * * www-data ${PHP_BIN} /var/www/${domain}/scripts/cron.php
* * * * * www-data ${PHP_BIN} /var/www/${domain}/cron/ticket_email_parser.php
* * * * * www-data ${PHP_BIN} /var/www/${domain}/cron/mail_queue.php
0 3 * * * www-data ${PHP_BIN} /var/www/${domain}/scripts/cron_domain_refresher.php
0 4 * * * www-data ${PHP_BIN} /var/www/${domain}/scripts/cron_certificate_refresher.php
EOF
chmod 644 /etc/cron.d/itflow
chown root:root /etc/cron.d/itflow

# MariaDB
show_progress "Configuring MariaDB..."
{
    until mysqladmin ping --silent; do sleep 1; done
    mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS itflow CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'itflow'@'localhost' IDENTIFIED BY '${mariadbpwd}';
GRANT ALL PRIVILEGES ON itflow.* TO 'itflow'@'localhost';
FLUSH PRIVILEGES;
SQL
} & spin "MariaDB setup"

# Import SQL
SQL_DUMP="/var/www/${domain}/db.sql"
if [ -f "$SQL_DUMP" ]; then
    show_progress "Importing database..."
    log "Importing database from $SQL_DUMP"
    mysql -u itflow -p"${mariadbpwd}" itflow < "$SQL_DUMP"
else
    echo -e "${YELLOW}Database dump not found at $SQL_DUMP${NC}"
    log "Database dump not found at $SQL_DUMP"
fi

# Config.php
INSTALL_ID=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${#mariadbpwd})
cat <<EOF > /var/www/${domain}/config.php
<?php
\$dbhost = 'localhost';
\$dbusername = 'itflow';
\$dbpassword = '${mariadbpwd}';
\$database = 'itflow';
\$mysqli = mysqli_connect(\$dbhost, \$dbusername, \$dbpassword, \$database) or die('Database Connection Failed');
\$config_app_name = 'ITFlow';
\$config_base_url = '${domain}';
\$config_https_only = ${config_https_only};
\$repo_branch = '${branch}';
\$installation_id = '${INSTALL_ID}';
EOF
chown www-data:www-data /var/www/${domain}/config.php
chmod 640 /var/www/${domain}/config.php

# Done
show_progress "Installation Complete!"
echo -e "Visit: ${GREEN}https://${domain}${NC}"
echo -e "Log: ${GREEN}${LOG_FILE}${NC}"

