# nas-web v2.2.80 — własny reverse proxy w C++ dla NAS/homelab

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue)](https://en.cppreference.com/w/cpp/20)
[![Debian 12](https://img.shields.io/badge/Debian-12-red)](https://www.debian.org/)
[![CodeQL Security Scan](https://github.com/gekomod/nas-webserver/actions/workflows/codeql.yml/badge.svg)](https://github.com/gekomod/nas-webserver/actions/workflows/codeql.yml)

Lekki, event-driven reverse proxy napisany w C++20 z myślą o NAS-ach i maszynach z ograniczonymi zasobami. Alternatywa dla nginx/Caddy gdy zależy Ci na pełnej kontroli i minimalnym footprintcie.

Projekt działa produkcyjnie na **Dell PowerEdge R620** z **Debianem 12**.

## Spis treści
- [Stack techniczny](#stack-techniczny)
- [Panel administracyjny](#panel-administracyjny)
- [Cechy](#cechy)
- [Konfiguracja (przykład)](#konfiguracja-przykład)
- [Instalacja (Debian/Ubuntu)](#instalacja-debianubuntu)
- [Status projektu](#status-projektu)
- [Licencja](#licencja)

---

## Stack techniczny

| Warstwa | Technologia |
|---|---|
| Core | C++20, [libuv](https://libuv.org/) (event loop) |
| TLS | OpenSSL 3 |
| HTTP/2 | [nghttp2](https://nghttp2.org/) |
| Kompresja | Brotli + Gzip |
| Skrypty | Lua 5.4 (middleware) |
| ACME | Let's Encrypt ACMEv2 (HTTP-01 + DNS-01) |
| WAF | [ModSecurity 3](https://github.com/SpiderLabs/ModSecurity) + OWASP CRS 3.3.7 |
| Cache | LRU in-memory |
| zstd | Kompresja |
| Janet WAF | Dodatek do waf |
| AutoBan | własna implementacja (blokada na poziomie TCP) |

## Panel administracyjny

Panel dostępny przez przeglądarkę — bez zewnętrznych zależności, cały wbudowany w binarkę.

| Widok główny — statystyki RPS, aktywne połączenia, upstream health check |
|:---:|

| WAF ModSecurity — 916 reguł OWASP CRS, tryb BLOCK |
|:---:|

| ACME / Let's Encrypt — automatyczne certyfikaty, obsługa wielu domen |
|:---:|

| AutoBan — blokowanie IP na poziomie TCP (przed TLS handshake) |
|:---:|

| Edytor konfiguracji — zmiany bez restartu serwera |
|:---:|

## Cechy

- **Single binary** — jeden plik wykonywalny, zero zależności runtime poza systemowymi
- **Event-driven** — libuv, nieblokujące I/O, brak wątków na połączenie
- **ACME multi-domain** — obsługuje wiele domen w jednym certyfikacie, pełny flow HTTP-01 per authz
- **AutoBan** — drop na poziomie TCP zaraz po `accept()`, zbanowane IP nie wykonują nawet TLS handshake
- **WAF** — ModSecurity z OWASP Core Rule Set + własny regex engine
- **Lua middleware** — skrypty per-lokacja, dostęp do request/response
- **HTTP/2** — pełna obsługa z nghttp2
- **LRU cache** — cache dla proxy i plików statycznych z `Cache-Control`
- **Hot reload** — przeładowanie konfiguracji bez downtime

## Konfiguracja (przykład)

```nginx
server {
    listen 443 ssl;
    ssl_cert /etc/nas-web/cert.pem;
    ssl_key  /etc/nas-web/key.pem;
    acme on;
    acme_domains ADRES.pl www.ADRES.pl;

    location / {
        proxy_pass http://127.0.0.1:3000;
        cache max_age=30;
    }

    location /static {
        root /var/www/html;
        gzip on;
        brotli on;
    }
}
```

## Instalacja (Debian/Ubuntu)

```bash
# Pobierz i zainstaluj gotowy pakiet
wget https://github.com/gekomod/nas-webserver/releases/download/v2.2.83/nas-web_2.2.83-1_amd64.deb
dpkg -i nas-web_2.2.80-1_amd64.deb

# Lub zbuduj ze źródeł
git clone https://github.com/gekomod/nas-webserver.git
cd nas-web
bash build-deb.sh --with-modsec
dpkg -i build/nas-web_*.deb

# Uruchom
systemctl enable --now nas-web
```

## Status projektu

✅ HTTP/1.1 + HTTP/2
✅ TLS 1.2/1.3 (OpenSSL 3)
✅ ACME (Let's Encrypt)
✅ WAF (ModSecurity + własny regex)
✅ AutoBan (blokowanie na TCP level)
✅ Lua 5.4 middleware
✅ LRU cache
✅ Janet WAF
✅ Page Optimizer
✅ zstd Kompresja
✅ Panel administracyjny
🔧 HTTP/3 (QUIC) — w planach
🔧 mTLS — w planach

## Licencja

Projekt dostępny na licencji MIT. Szczegóły w pliku LICENSE.
Projekt prywatny / homelab.
