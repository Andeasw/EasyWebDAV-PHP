# EasyWebDAV-PHP

Single-file PHP **WebDAV server + web file manager** with **HTTP Basic Auth**, **share links**, and optional **operation logs**.

---

## What it does (matches the script)

* **Basic Auth login**

  * First run: the first successful Basic Auth credentials are stored (hashed) in `/.htpasswd.php`.
  * Next runs: credentials are verified against `/.htpasswd.php`.
* **WebDAV endpoint**
  Supports: `OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE, LOCK, UNLOCK`
* **Web UI (directory view)**

  * Upload file, create folder
  * Rename / copy / move / delete
  * Download
  * Share manager (create/update/unshare)
  * CN/EN + dark mode
* **Share links**

  * Preferred: `/s/<token>/filename` (PATH_INFO style)
  * Also supported: `?s=<token>`
  * Share metadata stored in `/.shares.php` (expires/max_uses/uses)
* **Logs (optional)**

  * Daily logs in `./logs/YYYY-MM-DD.log`
  * UI actions: `?log_action=download` and `?log_action=clear`

---

## Requirements

* PHP **7.4+** (PHP 8.x recommended)
* Web server:

  * **Apache** (works out-of-the-box with generated `.htaccess`)
  * **Nginx + PHP-FPM** (manual config required)
  * **Caddy + PHP-FPM** (manual config required)
* The script directory must be writable by PHP (it creates `storage/`, `logs/`, and config files)

---

## Files created by the script

* `./storage/` — storage root for files and folders
* `./logs/` — logs (only if `LOG_ENABLED = true`)
* `./.htpasswd.php` — stored admin username + password hash
* `./.shares.php` — share tokens and settings

---

## Quick Start (any server)

1. Put `index.php` into your site root, e.g.:

   * `/var/www/easywebdav/index.php`
2. Open the site in a browser.
3. When prompted for **Basic Auth**, enter the username/password you want.

   * On first run, these are saved to `/.htpasswd.php`.
4. Upload/manage files in the UI. All files go to `./storage/`.

---

## Recommended security baseline

These are practical notes based on how the script works:

* **Use HTTPS** whenever possible (Basic Auth over HTTP is not encrypted).
* **Deny direct web access** to:

  * `/.htpasswd.php`
  * `/.shares.php`
  * `/logs/`
  * `/storage/` (recommended; the app serves files itself)
* After first setup, **tighten permissions**:

  * `chmod 600 .htpasswd.php`
  * (optional) `chmod 600 .shares.php`

> Why: even though the app itself “hides” these names in the UI, your web server might still allow direct URL access unless you block it.

---

## Apache (works with generated `.htaccess`)

The script auto-creates:

* `./storage/.htaccess` with `Deny from all`
* `./.htaccess` disabling indexes and helping auth header handling

### Optional: Apache hard rules (recommended)

Add to your site config (preferred) or `.htaccess`:

```apache
<FilesMatch "^\.((htpasswd)|(shares))\.php$">
  Require all denied
</FilesMatch>

<LocationMatch "^/logs(?:/|$)">
  Require all denied
</LocationMatch>

<LocationMatch "^/storage(?:/|$)">
  Require all denied
</LocationMatch>
```

---

## Nginx + PHP-FPM (example config)

> This config:
>
> * keeps share links working (`/s/<token>`) by passing PATH_INFO
> * blocks sensitive paths
> * supports WebDAV verbs and larger uploads

Create `/etc/nginx/sites-available/easywebdav.conf`:

```nginx
server {
    listen 80;
    server_name example.com;

    root /var/www/easywebdav;
    index index.php;

    # ---- SECURITY: block sensitive things ----
    location = /.htpasswd.php { deny all; }
    location = /.shares.php   { deny all; }
    location ^~ /logs/        { deny all; }
    location ^~ /storage/     { deny all; }
    location ~ /\.            { deny all; }  # optional: block all dotfiles

    # ---- ROUTING: send everything through index.php (PATH_INFO support) ----
    location / {
        try_files $uri $uri/ /index.php$uri?$args;
    }

    # ---- PHP-FPM ----
    location ~ \.php($|/) {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;  # change to your PHP-FPM socket/host

        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;

        # Upload size and timeouts (adjust as needed)
        client_max_body_size 2g;
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
    }
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/easywebdav.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Nginx HTTPS (basic idea)

If you use Let’s Encrypt, create a second `server { listen 443 ssl; ... }` block and reuse the same locations.
Always prefer HTTPS for Basic Auth.

---

## Caddy + PHP-FPM (example config)

Create `/etc/caddy/Caddyfile`:

```caddy
example.com {
    root * /var/www/easywebdav

    # ---- SECURITY: block sensitive things ----
    @secrets path /.htpasswd.php /.shares.php
    respond @secrets 403

    @logs path /logs/*
    respond @logs 403

    @storage path /storage/*
    respond @storage 403

    # Optional: block dotfiles
    @dotfiles path /.*
    respond @dotfiles 403

    # ---- ROUTING + PHP ----
    # Keep PATH_INFO working for /s/<token>
    try_files {path} {path}/ /index.php{path}?{query}

    php_fastcgi unix//run/php/php8.2-fpm.sock
    file_server
}
```

Reload:

```bash
sudo caddy reload --config /etc/caddy/Caddyfile
```

### Caddy on LAN/IP (no public cert)

Use internal TLS:

```caddy
https://192.168.1.10 {
    tls internal
    root * /var/www/easywebdav
    # (same blocks as above)
}
```

---

## WebDAV client usage

Use your WebDAV client with:

* `https://example.com/`
  (or whatever base URL you installed it at)

Authenticate using the same Basic Auth username/password.

---

## Share links

* PATH_INFO (recommended):
  `https://example.com/s/<token>/filename.ext`
* Query fallback:
  `https://example.com/?s=<token>`

Share settings live in `/.shares.php`, and “uses” increments automatically on each successful access.

---

## Common issues & fixes

### 1) Share links `/s/<token>` don’t work

Cause: PATH_INFO not forwarded.

Fix:

* **Nginx**: ensure `try_files ... /index.php$uri?...` and `fastcgi_split_path_info` + `PATH_INFO`
* **Caddy**: ensure `try_files ... /index.php{path}?...`

### 2) Upload fails / 413 Request Entity Too Large

Fix:

* **Nginx**: increase `client_max_body_size`
* Also check PHP: `upload_max_filesize` and `post_max_size`

### 3) Permissions errors

Ensure the PHP user can write:

* `./storage/`, `./logs/`, and create `/.htpasswd.php`, `/.shares.php`

---

## Configuration knobs (in code)

At the top of `index.php`:

* `LOG_ENABLED` (true/false)
* `LOG_PATH` (default `./logs`)

---

## Notes

* If `/.htpasswd.php` is deleted, the script enters “first login creates admin” mode again.
* For better protection, block sensitive paths at the web server level (examples above) and prefer HTTPS.
