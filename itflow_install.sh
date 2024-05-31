#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if the user is root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

# Check OS
check_os() {
    if ! grep -E "22.04|24.04|12" "/etc/"*"release" &>/dev/null; then
        echo -e "${RED}Error: This script only supports Ubuntu 22.04, Ubuntu 24.04 or Debian 12.${NC}"
        exit 1
    fi
}

# Set Correct Timezone
set_timezone() {
    dpkg-reconfigure tzdata
}

# Get domain name from user
get_domain() {
    while [[ $domain != *[.]*[.]* ]]; do
        echo -ne "Step 1: Please enter your Fully Qualified Domain (e.g., itflow.domain.com): "
        read domain
    done
    echo -e "${GREEN}Domain set to: $domain${NC}"
}

generate_passwords() {
    mariadbpwd=$(tr -dc 'A-Za-z0-9' < /dev/urandom | fold -w 20 | head -n 1)
    cronkey=$(tr -dc 'A-Za-z0-9' < /dev/urandom | fold -w 20 | head -n 1)
}

install_packages() {
    apt-get update && apt-get -y upgrade
    apt-get install -y apache2 mariadb-server \
    php libapache2-mod-php php-intl php-mysqli php-gd \
    php-curl php-imap php-mailparse libapache2-mod-md \
    certbot python3-certbot-apache git sudo ufw

    mariadb_secure_installation

    a2enmod md
    a2enmod ssl
}

modify_php_ini() {
    # Get the PHP version
    PHP_VERSION=$(php -v | head -n 1 | awk '{print $2}' | cut -d '.' -f 1,2)
    
    # Set the PHP_INI_PATH
    PHP_INI_PATH="/etc/php/${PHP_VERSION}/apache2/php.ini"

    sed -i 's/^;\?upload_max_filesize =.*/upload_max_filesize = 500M/' $PHP_INI_PATH
    sed -i 's/^;\?post_max_size =.*/post_max_size = 500M/' $PHP_INI_PATH
}

setup_ufw() {
    ufw allow https
    ufw allow http
    ufw allow ssh
    ufw enable
}

setup_webroot() {
    mkdir -p /var/www/${domain}
    chown -R www-data:www-data /var/www/
}

setup_apache() {
    apache2_conf="<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName ${domain}
    DocumentRoot /var/www/${domain}
    ErrorLog /\${APACHE_LOG_DIR}/error.log
    CustomLog /\${APACHE_LOG_DIR}/access.log combined
</VirtualHost>"

    echo "${apache2_conf}" > /etc/apache2/sites-available/${domain}.conf

    a2ensite ${domain}.conf
    a2dissite 000-default.conf
    systemctl restart apache2

    certbot --apache --non-interactive --agree-tos --register-unsafely-without-email --domains ${domain}
}

clone_itflow() {
    git clone https://github.com/itflow-org/itflow.git /var/www/${domain}
}

setup_cronjobs() {
    (crontab -l 2>/dev/null; echo "0 2 * * * sudo -u www-data php /var/www/${domain}/cron.php ${cronkey}") | crontab -
    (crontab -l 2>/dev/null; echo "* * * * * sudo -u www-data php /var/www/${domain}/cron_ticket_email_parser.php ${cronkey}") | crontab -
    (crontab -l 2>/dev/null; echo "* * * * * sudo -u www-data php /var/www/${domain}/cron_mail_queue.php ${cronkey}") | crontab -
}

generate_cronkey_file() {
    mkdir -p /var/www/${domain}/uploads/tmp
    echo "<?php" > /var/www/${domain}/uploads/tmp/cronkey.php
    echo "\$itflow_install_script_generated_cronkey = \"${cronkey}\";" >> /var/www/${domain}/uploads/tmp/cronkey.php
    echo "?>" >> /var/www/${domain}/uploads/tmp/cronkey.php
    chown -R www-data:www-data /var/www/
}

setup_mysql() {
    mysql -e "CREATE DATABASE itflow /*\!40100 DEFAULT CHARACTER SET utf8 */;"
    mysql -e "CREATE USER itflow@localhost IDENTIFIED BY '${mariadbpwd}';"
    mysql -e "GRANT ALL PRIVILEGES ON itflow.* TO 'itflow'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
}

print_final_instructions() {
    echo "Please go to https://${domain} to finish setting up ITFlow"
    echo ""
    echo "In database setup section enter the following:"
    echo "Database User: itflow"
    echo "Database Name: itflow"
    echo "Database Password: ${mariadbpwd}"
}

# Welcome Message
clear
echo "#############################################"
echo "# Welcome to the ITFlow Installation Script #"
echo "#############################################"
echo ""
echo "Please follow the prompts to complete the installation."
echo ""
echo "Please note, UFW will be setup during the installation, restricting access to HTTP, HTTPS, and SSH."
echo ""

# Execution begins here
check_root
check_os
set_timezone
get_domain
generate_passwords

echo -e "\n${GREEN}Step 2: Installing necessary packages...${NC}"
install_packages

echo -e "\n${GREEN}Step 3: Modifying PHP configurations...${NC}"
modify_php_ini

echo -e "\n${GREEN}Step 4. Setting up ufw"
setup_ufw

echo -e "\n${GREEN}Step 4: Setting up webroot...${NC}"
setup_webroot

echo -e "\n${GREEN}Step 5: Configuring Apache...${NC}"
setup_apache

echo -e "\n${GREEN}Step 6: Cloning ITFlow...${NC}"
clone_itflow

echo -e "\n${GREEN}Step 7: Setting up cron jobs...${NC}"
setup_cronjobs

echo -e "\n${GREEN}Step 8: Generating cron key file...${NC}"
generate_cronkey_file

echo -e "\n${GREEN}Step 9: Setting up MySQL...${NC}"
setup_mysql

# Final message with clear instructions
clear
echo "######################################################"
echo "# Installation Completed Successfully!               #"
echo "######################################################"
echo ""
echo -e "Visit: ${GREEN}https://${domain}${NC} to complete the ITFlow setup."
echo ""
echo "Database setup details:"
echo -e "Database User: ${GREEN}itflow${NC}"
echo -e "Database Name: ${GREEN}itflow${NC}"
echo -e "Database Password: ${GREEN}${mariadbpwd}${NC}"
echo ""
