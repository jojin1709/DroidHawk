# 🦅 DroidHawk — Android Bug Bounty Automation

**Made by Jojin John**

DroidHawk is a powerful Android security testing automation toolkit for bug bounty hunters and pentesters.

> ⚠️ For **authorized testing only** — only use on apps/devices you have permission to test.

---

## 🚀 Features

| Menu | Feature |
|------|---------|
| 1 | Create Virtual Device (guide) |
| 2 | Root Emulator — Magisk + rootAVD (one-click) |
| 3 | Install Tools — frida, objection, apkleaks, and more |
| 4 | Configure Emulator — Frida server, Burp cert, proxy |
| 5 | Run Frida Server |
| 6 | **Frida Tools** — SSL bypass, root bypass, objection, REPL, frida-trace |
| 7 | **APK Analysis** — decode, secrets scan, manifest audit, pull, repack+sign, grep |
| 8 | **Traffic & Proxy** — set/clear proxy, adb reverse, cleartext monitor |
| 9 | Device Info — root status, Frida status, ABI, disk |
| 10 | **Runtime Tampering** — debug attach, intent launch, content provider, SharedPrefs dump, SQLite dump |
| 11 | Session Log & Reports |

---

## ⚡ Quick Start

```bash
pip install -r requirements.txt
python DroidHawk.py
```

## 📋 Requirements

- Python 3.9+
- Android Studio + ADB in PATH
- frida-tools: `pip install frida-tools`
- requests: `pip install requests`

## 🛠 Optional Tools

```bash
pip install objection apkleaks androguard
```

- **apktool** — https://apktool.org/
- **jadx** — https://github.com/skylot/jadx/releases
