# covertD

```
   ___   ___         __  __  _____  ___ 
  / __\ /___\/\   /\/__\/__\/__   \/   \
 / /   //  //\ \ / /_\ / \//  / /\/ /\ /
/ /___/ \_//  \ V //__/ _  \ / / / /_// 
\____/\___/    \_/\__/\/ \_/ \/ /___,'  
```

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-educational-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

# Stealth File Activity Monitor for Linux

A Red Team–oriented proof-of-concept for covert file monitoring and data exfiltration on Linux systems. Developed as a Bachelor's thesis project to explore stealth persistence, forensic evasion, and covert telemetry in secure environments.

## 🔍 Features

- Real-time file monitoring using `inotify`
- USB device detection via `libudev`
- AES-encrypted log exfiltration via TCP
- Screenshot capture on active window change (`libX11`)
- Optional ARP signaling for covert communication
- LD_PRELOAD-based stealth (hiding from `/proc`, readdir interception)
- Deployable via `systemd` service
- Keylogging module prototype (non-default)

## 🧪 Security & Compliance

- Static and dynamic code analysis performed (Clang Analyzer, Valgrind)
- Manually audited against CWE and logic bugs
- Complies with Class 3 FSTEC standards for absence of undocumented features

## 🧩 Why This Tool?

| System                      | USB Detection | Keystroke Logging | Data Exfiltration | Process Hiding  | Screenshots |
| --------------------------- | ------------- | ----------------- | ----------------- | --------------- | ----------- |
| **Auditd**                  | ✅            | ❌                | ❌                | ❌              | ❌          |
| **inotify-tools**           | ❌            | ❌                | ❌                | ❌              | ❌          |
| **Auditbeat**               | ✅            | ❌                | ✅                | ❌              | ❌          |
| **Sysdig**                  | ✅            | ❌                | ❌                | ❌              | ✅          |
| **SprutMonitor (Win only)** | ✅            | ✅                | ✅                | ✅              | ✅          |
| **covertd (this)**        | ✅            | ✅ (prototype)    | ✅ (AES over TCP) | ✅ (LD_PRELOAD) | ✅          |

## ⚙️ Dependencies

Install required libraries (Debian/Ubuntu/Kali):

```bash
sudo apt update
sudo apt install libssl-dev libudev-dev libpcap-dev libx11-dev libnet1-dev
```

## 🛠 Build

```bash
make all
```

This builds:
- `coretaskd` — file monitoring daemon
- `server` — log receiver and decryptor
- `screenshot-decryptor` — optional PoC for visual log parsing

## 🚀 Usage

### 1. Deploy systemd service

```bash
cp coretaskd /usr/local/bin/
cp coretaskd.service /etc/systemd/system/
systemctl daemon-reexec
systemctl enable coretaskd
systemctl start coretaskd
```

### 2. Start receiver

```bash
./server 9999
```

### 3. (Optional) Enable process hiding

```bash
cd processhider
make
echo /full/path/to/libprocesshider.so >> /etc/ld.so.preload
```

## 📁 Project Structure

- `main.c` – file and USB monitor
- `server.c` / `decrypt.c` – listener with AES decryption
- `coretask.sh` – deployment helper script
- `processhider/` – LD_PRELOAD stealth library
- `screenshot-decryptor.c` – GUI window watcher and screenshot handler

## ✅ Tested On

- Astra Linux SE
- Ubuntu 22.04

## 📈 Future Improvements

- Wayland screenshot capture
- Cross-platform builds (Windows, macOS)
- Kernel-level rootkit integration
- Real-time USB block & alerting

## ⚠ Disclaimer

**Educational use only.** Do not deploy without explicit authorization.

## 🧠 Thesis Origin

Originally developed as part of a Bachelor's thesis focused on secure file telemetry and stealth persistence mechanisms in hardened Linux environments. Designed for use in Red Team training, malware research, and threat simulation labs.
