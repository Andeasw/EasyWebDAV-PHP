# PHP WebDAV Server (Single File)

A **lightweight, single-file PHP WebDAV server** for quick self-hosted file sharing. Supports authentication, hidden system files, and browser-friendly file browsing.

## Features

* Single PHP file, no dependencies
* Auto-create storage folder and `.htaccess`
* Basic HTTP authentication
* Supports WebDAV methods: `GET`, `PUT`, `DELETE`, `PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`
* Hides system and hidden files (`.htaccess`, `.DS_Store`, etc.)
* Browser-friendly directory listing

## Usage

1. Upload `index.php` to your web server
2. Open in browser or WebDAV client
3. Login with default credentials:

```
Username: admin
Password: 123456
```

4. Browse, upload, or manage files

## Configuration

Edit the top of `index.php`:

```php
define('DAV_USER', 'admin');       // Username
define('DAV_PASS', '123456');      // Password
define('STORAGE_NAME', 'data');    // Storage folder
```

## Security Notes

* **Change default credentials immediately**
* Use **HTTPS** to protect authentication
* Adjust folder permissions if needed

---
