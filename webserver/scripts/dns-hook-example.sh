#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  dns-hook-example.sh — przykładowy hook dla ACME DNS-01 challenge
#  Użycie w konfiguracji: dns_exec /etc/nas-web/scripts/dns-hook.sh;
#
#  nas-web wywołuje: dns-hook.sh add|remove DOMAIN TXT_VALUE
# ─────────────────────────────────────────────────────────────────────────────
set -e
ACTION="$1"   # add | remove
DOMAIN="$2"   # np. nasserver.pl
VALUE="$3"    # base64url(sha256(key_auth))
RECORD="_acme-challenge.${DOMAIN}"

echo "[dns-hook] action=${ACTION} domain=${DOMAIN} record=${RECORD}"

case "${ACTION}" in
    add)
        # Przykład: nsupdate (BIND)
        # nsupdate -k /etc/named/tsig.key << EOF
        # server 127.0.0.1
        # zone ${DOMAIN}.
        # update add ${RECORD}. 60 TXT "${VALUE}"
        # send
        # EOF

        # Przykład: Cloudflare curl
        # curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE}/dns_records" \
        #   -H "Authorization: Bearer ${CF_TOKEN}" \
        #   -H "Content-Type: application/json" \
        #   --data "{\"type\":\"TXT\",\"name\":\"${RECORD}\",\"content\":\"${VALUE}\",\"ttl\":60}"

        echo "[dns-hook] ADD ${RECORD} TXT ${VALUE} — implement above!"
        ;;
    remove)
        echo "[dns-hook] REMOVE ${RECORD} — implement above!"
        ;;
    *)
        echo "[dns-hook] Unknown action: ${ACTION}" >&2
        exit 1
        ;;
esac
