# Game Port Manager (GPM) 🎮

A modern, fancy web interface for managing `firewalld` port forwardings on Fedora/Linux systems, specifically optimized for routing game traffic to Tailscale nodes.

![GPM UI](https://img.shields.io/badge/UI-Modern%20Glassmorphism-blue)
![Backend](https://img.shields.io/badge/Backend-FastAPI-green)
![OS](https://img.shields.io/badge/OS-Fedora%2042-red)

## 🚀 Features

- **Modern Glassmorphism UI:** Built with Tailwind CSS for a sleek, responsive experience.
- **Direct Firewall Integration:** Controls the host's `firewalld` via D-Bus.
- **TCP/UDP Support:** Forward any protocol or both simultaneously.
- **Secure Authentication:** JWT-based login with persistent SQLite storage.
- **Dockerized:** Runs in a privileged container for isolation and easy deployment.

## 🛠 Architecture

- **Base Image:** `fedora:42`
- **Framework:** FastAPI (Python 3.13)
- **Database:** SQLite (for user management)
- **Networking:** Host mode with D-Bus mount for firewall control.
- **Proxy:** Designed to be used behind Nginx Proxy Manager or similar.

## 📦 Deployment

1. **Clone and Scaffold:**
   ```bash
   cd /opt/stacks/apps/game-port-manager
   ```

2. **Start with Docker Compose:**
   ```bash
   docker compose up -d --build
   ```

## 👤 User Management

Users are managed via the CLI for maximum security:

```bash
docker exec game-port-manager-app-1 python3 create_user.py <username> <password>
```

## 🔒 Security Note

This application runs in **privileged mode** to interact with the system's firewall daemon. It should always be served over HTTPS and protected with strong passwords.

## 📄 License

MIT
