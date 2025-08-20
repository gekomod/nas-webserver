#!/bin/bash

# Skrypt bezpiecznego wdrożenia z isolation

echo "🔒 Secure Deployment Script"

# Tworzenie użytkownika dedicated
if ! id "nasweb" &>/dev/null; then
    useradd -r -s /bin/false -d /var/empty nasweb
    echo "Created dedicated user: nasweb"
fi

# Tworzenie secure directory
mkdir -p /var/empty
chown root:root /var/empty
chmod 755 /var/empty

# Konfiguracja capabilities
setcap 'cap_net_bind_service=+ep' /usr/local/bin/nas-web-server

echo "✅ Security isolation configured"
