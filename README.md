# EasyWebDAV-PHP 🚀

[![PHP Version](https://img.shields.io/badge/php-5.6%20--%208.4-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**EasyWebDAV-PHP** is a lightweight, single-file WebDAV server and modern web-based file manager for PHP.
It supports **standard WebDAV mounts** (including Windows, macOS Finder, iOS/Android, and OpenList / WebDAV mount clients) *and* offers a full-featured **HTML web interface** with file operations, dark mode, and direct-link sharing.

Designed for shared hosting and low-permission environments, it requires **no database**, writes minimal files, and is ready to deploy immediately.

A signature feature is the **Hidden Path Security Mechanism**, which uses the script filename as an access gateway—preventing unauthorized directory browsing and automated scanner attacks.

---

## ✨ Key Features

### 🔐 Security & Access

* **Strict Hidden Path Security**
  The script can only be accessed via its exact filename. Direct folder access returns **403 Forbidden**.
* **Automatic Hardening**
  Auto-generated `.htaccess` blocks PHP execution in storage folders and prevents traversal or direct file access.
* **Works on shared hosting**
  Includes CGI/FastCGI authentication recovery to fix stripped Authorization headers.

---

## 📂 WebDAV Support

* **Fully compatible with standard WebDAV clients**, including:

  * Windows “Map Network Drive”
  * macOS Finder (CMD + K)
  * iOS Files App / Documents
  * Android WebDAV clients
  * **OpenList / WebDAV mount apps**
* Supports upload, download, folder creation, deletion, renaming, and streaming.
* No code-level upload limit (server limits apply).

---

## 🌐 Modern Web Interface

A built-in responsive HTML file manager featuring:

* Clean, single-page UI (desktop + mobile)
* **Dark Mode / Light Mode toggle**
* Drag-and-drop upload
* Create, rename, delete files & folders
* Inline previews for images, text files, audio/video
* **Direct-Link Sharing** (with auto-generated permanent URLs)
* Breadcrumb navigation
* File size and modification date display

Users can log in directly through the browser—no WebDAV client required.

---

## 🚀 Broad Compatibility

* **PHP 5.6 – 8.4**
* No external libraries required
* Works without database
* Works on shared hosting, VPS, cPanel, Plesk, and Apache environments

---

## 🛠️ Installation & Deployment

### 1. Download

Download the single file, e.g., `easywebdav.php`.

### 2. Rename (highly recommended)

Using a unique filename increases security:

| Bad               | Good            |
| ----------------- | --------------- |
| `webdav.php`      | `drive_92x.php` |
| `filemanager.php` | `x3portal.php`  |
| `dav.php`         | `mydisk_7a.php` |

### 3. Upload

Upload the file to your server, e.g., `/disk/`.

### 4. Visit the script

Navigate to the **full path**:

```
http://your-domain.com/disk/drive_92x.php
```

Accessing only `/disk/` returns **403 Forbidden** — intended behavior.

### 5. Create Login Credentials

On first access, set your Username & Password. The system will auto-generate:

* `/storage/` directory
* security `.htaccess`
* config file

---

## 📡 WebDAV Connection Guide

**Base URL (must include the .php filename):**

```
http://your-domain.com/disk/drive_92x.php
```

### Windows

1. Open “This PC” → “Map Network Drive”
2. Folder:

   ```
   http://your-domain.com/disk/drive_92x.php
   ```
3. Enter login credentials

### macOS Finder

1. Go → "Connect to Server…" (⌘ + K)
2. Enter:

   ```
   http://your-domain.com/disk/drive_92x.php
   ```

### iOS / Android / OpenList

Add a new WebDAV connection and use the same URL.

---

## 🎨 Built-in HTML File Manager

The HTML UI supports:

✔ Login form
✔ Drag & drop upload
✔ File/Folder CRUD operations
✔ Rename / Move / Copy
✔ Image & media previews
✔ Dark Mode
✔ **Direct-Link Sharing** for files (copy URL instantly)
✔ Multi-select actions
✔ Mobile-friendly layout

Perfect for users who prefer a browser-based interface.

---

## 🔒 Security Architecture

### 1. Hidden Path Protection

The script refuses access unless the full filename matches.
This blocks:

* directory traversal
* automated scanners
* direct folder probing
* common brute-force paths

### 2. Anti-Webshell Hardening

Automatically creates `.htaccess` that disables PHP execution inside storage folders.

### 3. CGI/FastCGI Authorization Fix

Ensures compatibility with shared hosting providers that strip `Authorization:` headers.

### 4. Internal File Protection

Blocks access to:

* `.htpasswd.php`
* `.htaccess`
* config files
* the script itself inside the file manager

---

## 📋 Requirements

* **Apache** (required for `.htaccess` rules)
* **PHP 5.6 – 8.4**
* Script directory must be writable (755/775/777 depending on host)

---

## ⚠️ Disclaimer

This software is provided “as is”, without warranty of any kind.
Always back up your data before use.

---

### © 2025 Prince — EasyWebDAV-PHP

MIT Licensed.

---
