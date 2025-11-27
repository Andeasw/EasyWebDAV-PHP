# EasyWebDAV-PHP 🚀

[![PHP Version](https://img.shields.io/badge/php-7.0%20--%208.4-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

***

A single-file, secure, and aesthetic WebDAV server & file manager written in PHP.

**EasyWebDAV-PHP** is designed to be the simplest way to deploy a private cloud storage. It serves as both a modern web-based file manager and a standard WebDAV server compatible with various clients.

## ✨ Features

*   **🚀 Zero Configuration:** Just upload one file (`index.php`) and go. No database required.
*   **🎨 Aesthetic UI:** "Spring Warmth" eye-care theme with a responsive design, smooth animations, and Dark Mode support.
*   **🔒 Secure:** Built-in Basic Authentication, CSRF protection, and Path Traversal prevention.
*   **📂 Full Management:** Upload, Create Folder, Rename, Copy, Move, and Delete files via the web interface.
*   **🔗 Smart Sharing:** Generate public direct download links with random or custom keys.
*   **☁️ WebDAV Support:** Fully compatible with **OpenList**, PotPlayer, Windows Explorer, Finder, and other WebDAV clients.

## 🚀 Quick Start

1.  **Upload:** Upload the script to your web server (e.g., name it `index.php`).
2.  **Initialize:** Open the URL in your browser.
3.  **Setup:** The first time you visit, you will be prompted to set your **Admin Username** and **Password**.
4.  **Enjoy:** Your private cloud is ready! Files are stored in the automatically created `storage/` directory.

## 📱 WebDAV Client Connection

You can mount your storage as a local drive or stream media directly using WebDAV clients.

| Setting | Value |
| :--- | :--- |
| **Server URL** | `http://your-domain.com/path/to/script.php` |
| **Username** | The username you set |
| **Password** | The password you set |

### ✅ Tested Clients
*   **OpenList** (Recommended for media streaming)
*   Windows File Explorer (Map Network Drive)
*   macOS Finder
*   PotPlayer / VLC
*   Raidrive

## 🛠 Requirements

*   PHP 7.0 or higher.
*   Write permissions on the server directory (to create `storage/` and config files).

## 📝 License

MIT License. Created by Prince.
