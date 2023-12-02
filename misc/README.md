
### Prerequisites
* docker

### Installation
Clone repo into $YOURFOLDER/repo (e.g. /opt/sertifikatsok/repo) and run install.sh as root.

Folder /var/log/caddy must exist and the SERVICE_USER (caddy) must have access to it.

### Caddy config
Caffyfile example:

```
sertifikatsok.no, www.sertifikatsok.no, xn--sertifikatsk-5jb.no, www.xn--sertifikatsk-5jb.no {
    root "/var/www/sertifikatsok"
    log / /var/log/caddy/sertifikatsok.log "{combined}"
    gzip

    git github.com/magnuswatn/sertifikatsok {
        interval -1
        hook /deploy SuperHemmeligPassord
        path /opt/sertifikatsok/repo
        then /opt/sertifikatsok/repo/misc/deploy.sh
    }
    header / {
        Strict-Transport-Security "max-age=15768000; includeSubdomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy strict-origin-when-cross-origin
        Content-Security-Policy "default-src 'none'; script-src 'self'; font-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' data.brreg.no; frame-ancestors 'none'"
.brreg.no; frame-ancestors 'none'"
    }
    header /resources Cache-Control "max-age=31536000,public"
    header /api -Server
    proxy /api localhost:7001/
    tls {
        key_type p256
        ciphers ECDHE-RSA-WITH-CHACHA20-POLY1305 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-WITH-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256
    }
}
```
