#!/usr/bin/env python3
"""
🦅 DroidHawk - Android Bug Bounty Automation Tool (v4.1)
Made by Jojin John
For authorized penetration testing only.

CHANGELOG (v4.1):
- BUG 1: Moved argparse import to top-level to prevent NameError.
- BUG 2: Wrapped Androguard xref_to calls with safety exception handlers for androguard 4.x compatibility.
- BUG 3: Rewrote deep link extractor aapt2 fallback conditional logic for clarity.
- BUG 4: Added screenrecord process polling to automatically detect completion.
- BUG 5: Added polling logic to MobSF scanner to wait for completion before pulling JSON reports.
- BUG 6: Relaxed package name validation in the bug bounty report generator to support custom/blank inputs.

CHANGELOG (v4.0):
- Added persistent configuration via config.json and settings menu.
- Added JADX decompiler integration with auto-grep (Feature 2).
- Added Androguard static analysis module (Feature 3).
- Added Deep Link Extractor & Intent Fuzzer (Feature 4).
- Added Screenshot & Screen Record evidence utilities (Feature 5).
- Added persistent background logcat capture (Feature 6).
- Added MobSF REST API dynamic scanning integration (Feature 7).
- Added TXT, Markdown, and HTML report formatting (Feature 8).
- Added SHA256 integrity checksum verification for downloads (Feature 10).
- Added Bug Bounty report template generator (Feature 11).
- Fixed Bug 1: Correct subprocess argument splitting for Frida server shell launch.
- Fixed Bug 2: Added connection validation and version mismatch warnings for Frida server.
- Fixed Bug 3: Corrected dynamic parameter ordering for aapt/aapt2 component extraction.
- Fixed Bug 4: Implemented Androguard fallback for manifest analysis if aapt is missing.
- Fixed Bug 5: Resolved empty dirname bug in strings grep for single-file targets.
- Fixed Bug 6: Avoided temp file collision in SQLite extraction via unique filenames.
- Fixed Bug 7: Reimplemented cleartext traffic monitor with non-blocking thread queue.
- Fixed Bug 8: Added recursive build-tools search for apksigner on host.
- Fixed Bug 9: Reloaded custom Frida scripts on top of the menu loop.
- Fixed Bug 10: Added timeout parameters to ADB shell command executions.
- Fixed Bug 11: Sanitized and validated all package name inputs to block shell injection.
- Production Hardening: Context managers everywhere, generic try-except wrappers, clean up on exit.
"""

import os
import sys
import time
import zipfile
import shutil
import json
import re
import datetime
import subprocess
import platform
import hashlib
import atexit
import threading
import queue
import argparse

# ── Optional deps (graceful fallback) ────────────────────────────────────────
try:
    import requests as _rq
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from OpenSSL import crypto as _ssl_crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

try:
    from termcolor import force_color as _fc
    _fc()
    _FORCE_COLOR = True
except Exception:
    _FORCE_COLOR = False

# ── Platform ──────────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

# ── Global configuration defaults ────────────────────────────────────────────
CONFIG_FILE = "config.json"
CONFIG = {
    "proxy_host": "127.0.0.1",
    "proxy_port": "8080",
    "reports_dir": "DroidHawk_Reports",
    "preferred_serial": "",
    "mobsf_api_key": "",
    "mobsf_url": "http://localhost:8000",
    "default_report_format": "txt",
    "last_record_path": "",
    "last_record_ts": ""
}

REPORTS_DIR = CONFIG["reports_dir"]
SESSION_LOG = []
custom_scripts = []

# Background process tracking
LOGCAT_PROC = None
LOGCAT_FILE = None
RECORD_PROC = None
ARGS = None

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[1;31m"   # red
G  = "\033[1;32m"   # green
Y  = "\033[1;33m"   # yellow
C  = "\033[1;36m"   # cyan
M  = "\033[1;35m"   # magenta
B  = "\033[1;34m"   # blue
W  = "\033[0m"      # reset

TOOL_NAME    = "DroidHawk"
TOOL_VERSION = "v4.0"
TOOL_AUTHOR  = "Jojin John"

def ok(msg):   print("{}[✓] {}{}".format(G, msg, W))
def err(msg):  print("{}[✗] {}{}".format(R, msg, W))
def info(msg): print("{}[*] {}{}".format(C, msg, W))
def warn(msg): print("{}[!] {}{}".format(Y, msg, W))

def log_session(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    SESSION_LOG.append("[{}] {}".format(ts, msg))

# ── Config Loader & Saver ─────────────────────────────────────────────────────
def load_config():
    global CONFIG, REPORTS_DIR
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                CONFIG.update(loaded)
        except Exception:
            pass
    REPORTS_DIR = CONFIG["reports_dir"]

def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, indent=4)
    except Exception as e:
        err(f"Failed to save config: {e}")

# ── Exit Cleanup ──────────────────────────────────────────────────────────────
def cleanup():
    global LOGCAT_PROC, LOGCAT_FILE, RECORD_PROC
    if LOGCAT_PROC:
        try:
            LOGCAT_PROC.terminate()
        except Exception:
            pass
    if LOGCAT_FILE:
        try:
            LOGCAT_FILE.close()
        except Exception:
            pass
    if RECORD_PROC:
        try:
            RECORD_PROC.terminate()
        except Exception:
            pass

atexit.register(cleanup)

# ── Multi-Format Report Saver ─────────────────────────────────────────────────
def save_report(name, content, fmt=None):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if not fmt:
        fmt = CONFIG.get("default_report_format", "txt")
        
    if fmt == "json":
        path = os.path.join(REPORTS_DIR, f"{name}_{ts}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path
        
    path = os.path.join(REPORTS_DIR, f"{name}_{ts}.{fmt}")
    
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("=" * 60 + "\n")
            fh.write(f"{TOOL_NAME} Report — {datetime.datetime.now()}\n")
            fh.write(f"Made by {TOOL_AUTHOR}\n")
            fh.write("=" * 60 + "\n\n")
            fh.write(content)
            
    elif fmt == "md":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# {TOOL_NAME} Security Report\n\n")
            fh.write(f"**Date:** {datetime.datetime.now()}  \n")
            fh.write(f"**Author:** {TOOL_AUTHOR}  \n\n")
            fh.write("---\n\n")
            fh.write(content)
            
    elif fmt == "html":
        html_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>DroidHawk Security Report</title>
    <style>
        body {{
            background-color: #121212;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
        }}
        h1 {{
            color: #ff3366;
            border-bottom: 2px solid #2d2d2d;
            padding-bottom: 15px;
        }}
        .meta {{
            color: #888;
            margin-bottom: 30px;
        }}
        .content {{
            background-color: #1e1e1e;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            white-space: pre-wrap;
            font-family: monospace;
            line-height: 1.5;
            font-size: 14px;
        }}
        footer {{
            margin-top: 50px;
            color: #555;
            font-size: 12px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <h1>🦅 DroidHawk Security Report</h1>
    <div class="meta">
        <strong>Generated on:</strong> {date}<br>
        <strong>Author:</strong> {author}
    </div>
    <div class="content">{content}</div>
    <footer>Made with 🦅 DroidHawk — Android Bug Bounty Automation Tool</footer>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_template.format(
                date=datetime.datetime.now(),
                author=TOOL_AUTHOR,
                content=content.replace("<", "&lt;").replace(">", "&gt;")
            ))
            
    ok(f"Report saved → {path}")
    return path

def ask_save_report(name, content):
    ch = input(f"\n{C}→ Save report? (y/n): {W}").strip().lower()
    if ch != "y":
        return
        
    print(f"\n{C}Choose format:{W}")
    print("  1. TXT (Plain Text)")
    print("  2. Markdown")
    print("  3. HTML (Dark Theme)")
    fmt_ch = input("→ Choose format [1]: ").strip()
    
    fmt = "txt"
    if fmt_ch == "2":
        fmt = "md"
    elif fmt_ch == "3":
        fmt = "html"
        
    save_report(name, content, fmt)

# ── Requests Loader ───────────────────────────────────────────────────────────
def _get_rq():
    if not HAS_REQUESTS:
        err("requests not installed. Run: pip install requests")
        return None
    import requests as rq
    return rq

# ── Integrity Check ───────────────────────────────────────────────────────────
def verify_sha256(filepath, expected_hash):
    if not expected_hash:
        return True
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        calc_hash = sha256.hexdigest()
        if calc_hash.lower() == expected_hash.lower():
            ok("SHA256 verified ✓")
            return True
        else:
            if os.path.exists(filepath):
                os.remove(filepath)
            err("Checksum mismatch — download may be corrupted or tampered")
            return False
    except Exception as e:
        err(f"Integrity check failed: {e}")
        return False

# ── Input Sanitization & Validation ──────────────────────────────────────────
def validate_package(name):
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$', name))

def ask_package():
    while True:
        name = input(f"{C}→ Package name (e.g. com.example.app): {W}").strip()
        if not name:
            return ""
        if validate_package(name):
            return name
        err("Invalid package format. Must follow standard Java package naming (e.g. com.company.app).")

# ── ASCII banner & animations ─────────────────────────────────────────────────
LOGO = r"""
  ____            _     _ _   _                 _
 |  _ \ _ __ ___ (_) __| | | | |__ __ ___      _| | __
 | | | | '__/ _ \| |/ _` | |_| '_ \ \ \ /\ / / | |/ /
 | |_| | | | (_) | | (_| |  _| | | |\ V  V /| |   <
 |____/|_|  \___/|_|\__,_|_| |_| |_| \_/\_/ |_|_|\_\
"""

def startup_animation():
    if ARGS and ARGS.no_banner:
        return
    os.system("cls" if IS_WINDOWS else "clear")
    colours = [R, C, G]
    msgs    = ["", "  Initializing ...", "  Systems Online  ✓"]
    for col, msg in zip(colours, msgs):
        os.system("cls" if IS_WINDOWS else "clear")
        print(col + LOGO + W)
        print("{}{}{}".format(Y, msg, W))
        time.sleep(0.7)
    time.sleep(0.3)

def display_banner():
    dev_count = len(get_connected_devices())
    dev_str   = "{}{}{}".format(
        G if dev_count else R,
        f"{dev_count} device(s) connected" if dev_count else "No device connected",
        W)
    
    logcat_status = f"{G}LOGCAT: ON{W}" if LOGCAT_PROC else f"{R}LOGCAT: OFF{W}"
    
    os.system("cls" if IS_WINDOWS else "clear")
    print(R + LOGO + W)
    print("  {}{}  {}  | Made by {}{}".format(M, TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, W))
    print("  {}Android Bug Bounty Automation — Authorized Testing Only{}".format(Y, W))
    print("  {}Platform: {} {}  |  {}  |  {}{}".format(B, platform.system(), platform.release(), dev_str, logcat_status, W))
    print()

# ── Environment checks ────────────────────────────────────────────────────────
def initial_environment_check():
    if ARGS and ARGS.skip_checks:
        return
    os.system("cls" if IS_WINDOWS else "clear")
    print(R + LOGO + W)
    print("{}→  Verifying {} Environment ...{}\n".format(C, TOOL_NAME, W))

    checks = [
        ("Python 3.9+",      _chk_python),
        ("Python PATH",      _chk_python_path),
        ("ADB",              _chk_adb),
        ("frida-tools",      _chk_frida),
        ("curl",             _chk_curl),
        ("requests",         _chk_requests),
        ("objection",        _chk_objection),
        ("apkleaks",         _chk_apkleaks),
        ("jadx",             _chk_jadx),
    ]
    results = []
    for name, fn in checks:
        print("{}[*] Checking {:<20}{}".format(C, name + "...", W), end="", flush=True)
        time.sleep(0.15)
        ok_flag, detail = fn()
        results.append((name, ok_flag, detail))
        sym = "{}[✓]{}".format(G, W) if ok_flag else "{}[!]{}".format(Y, W)
        print("\r{} {:<22} {}".format(sym, name, detail))

    passed = sum(1 for _, s, _ in results if s)
    print("\n{}→ {}/{} checks passed.{}".format(C, passed, len(results), W))
    if passed < len(results):
        warn("Some optional tools missing — affected features will warn you.")
        try:
            if input("{}→ Continue anyway? (y/n): {}".format(C, W)).strip().lower() != "y":
                sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)
    else:
        ok("Environment ready!")
    time.sleep(0.4)

def _chk_python():
    if IS_WINDOWS and "Microsoft\\WindowsApps" in sys.executable:
        return False, "Use python.org build, not Microsoft Store"
    if sys.version_info < (3, 9):
        return False, "Need 3.9+ (found {}.{})".format(*sys.version_info[:2])
    return True, "Python {}.{}".format(*sys.version_info[:2])

def _chk_python_path():
    for cmd in ("python3", "python"):
        if shutil.which(cmd):
            return True, "found as '{}'".format(cmd)
    return False, "not in PATH"

def _chk_adb():
    if not shutil.which("adb"):
        return False, "not in PATH — install Android SDK Platform-Tools"
    try:
        ver = subprocess.check_output(["adb","version"], text=True,
                                      stderr=subprocess.DEVNULL, timeout=10).splitlines()[0]
        return True, ver
    except Exception:
        return True, "found"

def _chk_frida():
    if not shutil.which("frida"):
        return False, "pip install frida-tools"
    try:
        ver = subprocess.check_output(["frida","--version"], text=True,
                                      stderr=subprocess.DEVNULL, timeout=10).strip()
        return True, "frida {}".format(ver)
    except Exception:
        return True, "found"

def _chk_curl():
    return (True, "available") if shutil.which("curl") else (False, "not found")

def _chk_requests():
    try:
        import requests as _r
        return True, "v{}".format(_r.__version__)
    except ImportError:
        return False, "pip install requests"

def _chk_objection():
    return (True, "found") if shutil.which("objection") else (False, "pip install objection (optional)")

def _chk_apkleaks():
    return (True, "found") if shutil.which("apkleaks") else (False, "pip install apkleaks (optional)")

def _chk_jadx():
    return (True, "found") if (shutil.which("jadx") or shutil.which("jadx.bat")) else (False, "jadx decompiler missing (optional)")

# ── ADB helpers ───────────────────────────────────────────────────────────────
ADB = "adb"

def get_connected_devices():
    try:
        out = subprocess.check_output([ADB,"devices"], text=True, stderr=subprocess.DEVNULL, timeout=10)
        devs = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line and "\tdevice" in line:
                devs.append(line.split("\t")[0])
        return devs
    except Exception:
        return []

def is_device_connected():
    return bool(get_connected_devices())

def select_device():
    if ARGS and ARGS.serial:
        return ARGS.serial
    if CONFIG.get("preferred_serial"):
        return CONFIG["preferred_serial"]
        
    devs = get_connected_devices()
    if not devs:
        return None
    if len(devs) == 1:
        return devs[0]
        
    print("{}Multiple devices:{}".format(C, W))
    for i, d in enumerate(devs, 1):
        print("  {}. {}".format(i, d))
    try:
        ch = input("{}→ Select device #: {}".format(C, W)).strip()
        selected = devs[int(ch) - 1]
        if input("Save this device serial as preferred? (y/n): ").strip().lower() == 'y':
            CONFIG["preferred_serial"] = selected
            save_config()
        return selected
    except (ValueError, IndexError):
        return devs[0]

def adb_cmd(args, serial=None, **kwargs):
    base = [ADB] + (["-s", serial] if serial else [])
    try:
        return subprocess.run(base + args, **kwargs)
    except subprocess.TimeoutExpired as te:
        err(f"ADB execution timed out: {te}")
        return subprocess.CompletedProcess(args=base+args, returncode=-1, stdout="", stderr="TimeoutExpired")
    except Exception as e:
        err(f"ADB command failed: {e}")
        return subprocess.CompletedProcess(args=base+args, returncode=-1, stdout="", stderr=str(e))

def adb_shell(cmd_list, serial=None, timeout=15):
    try:
        r = adb_cmd(["shell"] + cmd_list, serial=serial, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

# ── Tool installer helpers ────────────────────────────────────────────────────
def is_tool_installed(tool):
    if tool == "frida-tools":
        return bool(shutil.which("frida"))
    try:
        return subprocess.run([sys.executable, "-m", "pip", "show", tool],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15).returncode == 0
    except Exception:
        return False

def pip_install(tool):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool], timeout=300)
    except Exception as e:
        err(f"Pip installation failed for {tool}: {e}")

def load_custom_scripts():
    global custom_scripts
    custom_scripts = []
    default_set = {"SSL-BYE.js", "ROOTER.js", "PintooR.js"}
    if os.path.exists("./Fripts"):
        try:
            for fname in sorted(os.listdir("./Fripts")):
                if fname.endswith(".js") and fname not in default_set:
                    name = os.path.splitext(fname)[0]
                    custom_scripts.append((name, os.path.join("./Fripts", fname)))
        except Exception:
            pass

def _press_enter():
    try:
        input("\n{}→ Press Enter to continue ...{}".format(C, W))
    except KeyboardInterrupt:
        pass

def _require_device():
    """Print error and return False if no device connected."""
    if not is_device_connected():
        err("No emulator/device connected. Start one first.")
        _press_enter()
        return False
    return True

# ════════════════════════════════════════════════════════════════
#  MENU 1 — Create Virtual Device
# ════════════════════════════════════════════════════════════════
def menu_create_avd():
    display_banner()
    warn("THIS IS A MANUAL TASK — DroidHawk guides you step-by-step.\n")
    steps = [
        ("Open Android Studio",     "Launch → Device Manager → Virtual tab."),
        ("Create New Device",       "Click 'Create Virtual Device', choose Pixel model, click Next."),
        ("Select System Image",     "API 33 (Android 13) x86_64 or arm64 — download if missing."),
        ("Finish & Launch",         "Click Finish, then press the green Play button in AVD Manager."),
    ]
    for i, (title, body) in enumerate(steps, 1):
        print("  {}{}.{} {}{}".format(C, i, W, title, W))
        print("     {}\n".format(body))
    print("{}Tips:{}".format(Y, W))
    print("  • API missing? SDK Manager → Android 13 (API 33)")
    print("  • Emulator won't start? Enable VT-x / AMD-V in BIOS")
    print("  • Docs: https://developer.android.com/studio/run/managing-avds\n")
    _press_enter()

# ════════════════════════════════════════════════════════════════
#  MENU 2 — Root Emulator
# ════════════════════════════════════════════════════════════════
def menu_root_emulator():
    display_banner()
    print("{}[  Root Emulator — Magisk + rootAVD  ]{}\n".format(C, W))
    if not IS_WINDOWS:
        warn("Automated rootAVD patching uses Windows .bat files.\n"
             "  On Linux/macOS run rootAVD.sh manually after download.\n")
    if not _require_device():
        return
    serial = select_device()
    ok("Using device: {}".format(serial))
    rq = _get_rq()
    if not rq:
        return
    try:
        # --- Download Magisk ---
        info("Fetching latest Magisk release ...")
        magisk_ver = "v30.0"
        magisk_file = "Magisk-v30.0.apk"
        magisk_url = "https://github.com/topjohnwu/Magisk/releases/download/v30.0/Magisk-v30.0.apk"
        expected_magisk_sha = None
        
        try:
            resp = rq.get("https://api.github.com/repos/topjohnwu/Magisk/releases/latest", timeout=10)
            resp.raise_for_status()
            release_json = resp.json()
            magisk_ver  = release_json["tag_name"]
            magisk_file = "Magisk-{}.apk".format(magisk_ver)
            
            # Find matching binary asset
            for asset in release_json.get("assets", []):
                if asset["name"].endswith(".apk"):
                    magisk_file = asset["name"]
                    magisk_url = asset["browser_download_url"]
                    break
                    
            # Try to fetch sha256 checksum asset
            for asset in release_json.get("assets", []):
                if asset["name"].endswith(".sha256") or (magisk_file + ".sha256" in asset["name"]):
                    sha_resp = rq.get(asset["browser_download_url"], timeout=10)
                    if sha_resp.status_code == 200:
                        expected_magisk_sha = sha_resp.text.strip().split()[0]
                        break
        except Exception as e:
            warn(f"GitHub Magisk lookup failed ({e}), using defaults")
            
        if not os.path.exists(magisk_file):
            info("Downloading {} ...".format(magisk_file))
            data = rq.get(magisk_url, timeout=180)
            data.raise_for_status()
            with open(magisk_file, "wb") as f:
                f.write(data.content)
                
        # Verify Magisk SHA256 integrity
        if expected_magisk_sha:
            if not verify_sha256(magisk_file, expected_magisk_sha):
                _press_enter()
                return
        else:
            ok(f"Magisk {magisk_ver} download complete")
 
        # --- Install Magisk APK ---
        info("Installing Magisk APK ...")
        r = adb_cmd(["install", "-r", magisk_file], serial=serial,
                    capture_output=True, text=True)
        if r.returncode != 0:
            err("APK install failed: {}".format(r.stderr.strip()))
            _press_enter()
            return
        ok("Magisk installed on emulator")

        # --- Download rootAVD ---
        info("Downloading rootAVD ...")
        rAVD_zip = "rootAVD.zip"
        rAVD_dir = "rootAVD"
        if not os.path.exists(rAVD_zip):
            data = rq.get("https://gitlab.com/newbit/rootAVD/-/archive/master/rootAVD-master.zip",
                           timeout=180)
            data.raise_for_status()
            with open(rAVD_zip, "wb") as f:
                f.write(data.content)
                
        if not os.path.isdir(rAVD_dir):
            with zipfile.ZipFile(rAVD_zip) as z:
                z.extractall(rAVD_dir)
        ok("rootAVD ready")

        bat_dir = os.path.join(rAVD_dir, "rootAVD-master")

        if IS_WINDOWS:
            # List images
            info("Listing available system images ...")
            cwd = os.getcwd()
            os.chdir(bat_dir)
            try:
                res = subprocess.run('cmd /c "rootAVD.bat ListAllAVDs"',
                                     shell=True, capture_output=True, text=True, timeout=60)
            finally:
                os.chdir(cwd)
            imgs = sorted({l.split()[1] for l in res.stdout.splitlines()
                           if l.startswith("rootAVD.bat system-images") and "ramdisk.img" in l})
            if imgs:
                ok("Found images:")
                for p in imgs:
                    print("    {}{}{}".format(C, p, W))
            else:
                warn("No images auto-detected.")
            android_home = os.environ.get(
                "ANDROID_HOME",
                os.path.join(os.environ.get("LOCALAPPDATA",""), "Android","Sdk"))
            img_path = input("{}→ System image path (e.g. system-images\\android-33\\google_apis\\x86_64\\ramdisk.img): {}".format(C, W)).strip()
            full_path = os.path.normpath(os.path.join(android_home, img_path))
            if not os.path.exists(full_path):
                err("Path not found: {}".format(full_path))
                _press_enter(); return
            info("Patching system image ...")
            cwd = os.getcwd()
            os.chdir(bat_dir)
            try:
                res = subprocess.run('cmd /c ".\\rootAVD.bat {}"'.format(img_path),
                                     shell=True, capture_output=True, text=True, timeout=120)
            finally:
                os.chdir(cwd)
            if res.returncode != 0:
                err("Patching failed:\n{}".format(res.stderr))
                _press_enter(); return
            ok("System image patched!")
        else:
            sh = os.path.join(bat_dir, "rootAVD.sh")
            os.chmod(sh, 0o755)
            warn("Linux/macOS — run these commands manually:")
            print("    cd {}".format(os.path.abspath(bat_dir)))
            print("    ./rootAVD.sh ListAllAVDs")
            print("    ./rootAVD.sh <path/to/ramdisk.img>")
            input("{}→ Press Enter once done ...{}".format(C, W))

        warn("COLD BOOT required → Device Manager → your AVD → ⋮ → Cold Boot Now")
        print("{}Waiting 90 seconds for boot ...{}".format(Y, W))
        for i in range(90, 0, -1):
            print("\r{}  {}s remaining ...{}".format(C, i, W), end="", flush=True)
            time.sleep(1)
        print()

        # --- Verify root ---
        info("Verifying root ...")
        r = adb_cmd(["shell", "su", "-c", "echo ROOT_OK"],
                    serial=serial, capture_output=True, text=True, timeout=15)
        if "ROOT_OK" in r.stdout:
            ok("Root CONFIRMED! ✓")
            log_session("Rooted device: {}".format(serial))
        else:
            err("Root not confirmed — open Magisk app, tap OK and allow reboot.")
    except Exception as exc:
        err("Rooting failed: {}".format(exc))
    print("\n{}Tip: adb kill-server && adb start-server  — resets ADB if stuck{}".format(M, W))
    _press_enter()

# ════════════════════════════════════════════════════════════════
#  MENU 3 — Install Tools
# ════════════════════════════════════════════════════════════════
def menu_install_tools():
    TOOLS = [
        ("frida",        "Core Frida dynamic instrumentation library"),
        ("frida-tools",  "CLI tools: frida-ps, frida-trace, frida-ls-devices"),
        ("objection",    "Runtime mobile exploration & bypass toolkit"),
        ("reflutter",    "Flutter app reverse-engineering"),
        ("apkleaks",     "APK secrets scanner — API keys, tokens, URLs"),
        ("androguard",   "Android static analysis framework"),
        ("apkid",        "APK packer / protector identifier"),
        ("mobsf",        "Mobile Security Framework (pip install mobsf)"),
    ]
    while True:
        try:
            display_banner()
            print("{}[  Install Tools  ]{}\n".format(C, W))
            for i, (tool, desc) in enumerate(TOOLS, 1):
                st = "{}[Installed]  {}".format(G, W) if is_tool_installed(tool) \
                     else "{}[Missing]    {}".format(R, W)
                print("  {}. {:<20} {}".format(i, tool, st))
                print("     {}{}{}\n".format(M, desc, W))
            print("  {}. Install ALL missing".format(len(TOOLS)+1))
            print("  {}. Back\n".format(len(TOOLS)+2))
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if not ch.isdigit():
                continue
            c = int(ch)
            if 1 <= c <= len(TOOLS):
                t = TOOLS[c-1][0]
                info("Installing {} ...".format(t))
                try:
                    pip_install(t)
                    ok("{} installed.".format(t))
                except Exception as e:
                    err("Failed: {}".format(e))
                _press_enter()
            elif c == len(TOOLS)+1:
                missing = [t for t,_ in TOOLS if not is_tool_installed(t)]
                if not missing:
                    ok("All tools already installed!")
                else:
                    for t in missing:
                        info("Installing {} ...".format(t))
                        try:
                            pip_install(t)
                            ok(t)
                        except Exception as e:
                            err("{}: {}".format(t, e))
                _press_enter()
            elif c == len(TOOLS)+2:
                break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 4 — Configure Emulator
# ════════════════════════════════════════════════════════════════
def _install_frida_server():
    display_banner()
    print("{}[  Install Frida Server  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    rq = _get_rq()
    if not rq: return
    try:
        abi = adb_shell(["getprop", "ro.product.cpu.abi"], serial)
        ok("Device ABI: {}".format(abi))
        frida_ver = subprocess.check_output(
            ["frida","--version"], text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
        ok("Host frida-tools: {}".format(frida_ver))
        
        # Pull expected SHA256 checksums first
        expected_sha = None
        sha_url = f"https://github.com/frida/frida/releases/download/{frida_ver}/SHA256SUMS"
        try:
            sha_resp = rq.get(sha_url, timeout=15)
            if sha_resp.status_code == 200:
                filename = f"frida-server-{frida_ver}-android-{abi}.xz"
                for line in sha_resp.text.splitlines():
                    if filename in line:
                        expected_sha = line.split()[0]
                        break
        except Exception as e:
            warn(f"Unable to load Frida integrity hashes: {e}")
            
        url = ("https://github.com/frida/frida/releases/download/{v}/"
               "frida-server-{v}-android-{a}.xz").format(v=frida_ver, a=abi)
        info("Downloading frida-server ...")
        r = rq.get(url, timeout=300, stream=True)
        r.raise_for_status()
        xz  = "frida-server-{}-android-{}.xz".format(frida_ver, abi)
        out = xz[:-3]
        total = int(r.headers.get("content-length", 0))
        done  = 0
        with open(xz, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
                done += len(chunk)
                if total:
                    print("\r  {}Progress: {}%{}".format(
                        C, done*100//total, W), end="", flush=True)
        print()
        
        # Verify SHA256 of the archive
        if expected_sha:
            if not verify_sha256(xz, expected_sha):
                _press_enter()
                return
        
        import lzma
        info("Extracting ...")
        with lzma.open(xz) as fin, open(out, "wb") as fout:
            fout.write(fin.read())
        ok("Extracted: {}".format(out))
        info("Pushing to /data/local/tmp/frida-server ...")
        adb_cmd(["push", out, "/data/local/tmp/frida-server"], serial=serial, check=True, timeout=30)
        adb_cmd(["shell", "chmod", "+x", "/data/local/tmp/frida-server"], serial=serial, check=True, timeout=15)
        ok("Frida server installed! ✓")
        
        # Start server in background to test
        info("Testing frida-server launch...")
        base = [ADB] + (["-s", serial] if serial else [])
        subprocess.Popen(base + ["shell", "su", "-c", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"])
        time.sleep(2)
        
        # Connection check
        r_ver = subprocess.run(["frida-ps"] + (["-D", serial] if serial else ["-U"]), capture_output=True, text=True, timeout=10)
        if r_ver.returncode != 0:
            warn("Unable to connect to frida-server. There might be a version mismatch between host frida-tools and device frida-server, or permission issues.")
        else:
            ok("Frida server verified and responding! ✓")
            
        # Stop test server
        adb_cmd(["shell", "su", "-c", "pkill -f frida-server"], serial=serial, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        
        log_session("frida-server {} installed on {}".format(frida_ver, serial))
    except Exception as e:
        err("Failed: {}".format(e))
    _press_enter()

def _install_burp_cert():
    display_banner()
    print("{}[  Install Burp Suite Certificate  ]{}\n".format(C, W))
    print("{}Prerequisites:{}".format(Y, W))
    print("  1. Burp Suite running on 127.0.0.1:8080")
    print("  2. Emulator proxy set to 127.0.0.1:8080")
    print("  3. Rooted emulator (Magisk)\n")
    if not _require_device(): return
    serial = select_device()
    rq = _get_rq()
    if not rq: return
    try:
        info("Downloading Burp CA certificate ...")
        cert_bytes = None
        for url in ["http://127.0.0.1:8080/cert", "http://burp/cert"]:
            try:
                resp = rq.get(url, timeout=10)
                resp.raise_for_status()
                cert_bytes = resp.content
                break
            except Exception:
                pass
        if not cert_bytes:
            raise RuntimeError("Cannot reach Burp on 127.0.0.1:8080 — is it running?")
        with open("cacert.der", "wb") as f:
            f.write(cert_bytes)
        if HAS_OPENSSL:
            from OpenSSL import crypto as ssl_c
            cert = ssl_c.load_certificate(ssl_c.FILETYPE_ASN1, cert_bytes)
            pem  = ssl_c.dump_certificate(ssl_c.FILETYPE_PEM, cert)
            with open("portswigger.crt", "wb") as f:
                f.write(pem)
        else:
            shutil.copy("cacert.der", "portswigger.crt")
        ok("Certificate downloaded & converted")

        adb_cmd(["push", "portswigger.crt", "/sdcard/portswigger.crt"],
                serial=serial, check=True, timeout=30)
        ok("Pushed to /sdcard/portswigger.crt")

        # AlwaysTrustUserCerts Magisk module
        info("Fetching AlwaysTrustUserCerts module ...")
        try:
            resp = rq.get("https://api.github.com/repos/NVISOsecurity/"
                          "AlwaysTrustUserCerts/releases/latest", timeout=10)
            resp.raise_for_status()
            mod_ver = resp.json()["tag_name"]
        except Exception:
            mod_ver = "v1.3"
        mod_file = "AlwaysTrustUserCerts_{}.zip".format(mod_ver)
        mod_url  = ("https://github.com/NVISOsecurity/AlwaysTrustUserCerts"
                    "/releases/download/{}/{}".format(mod_ver, mod_file))
        if not os.path.exists(mod_file):
            data = rq.get(mod_url, timeout=120)
            data.raise_for_status()
            with open(mod_file, "wb") as f:
                f.write(data.content)
        ok("Module {} ready".format(mod_ver))

        adb_cmd(["push", mod_file, "/data/local/tmp/"+mod_file], serial=serial, check=True, timeout=30)
        adb_cmd(["shell","su","-c",
                 "magisk --install-module /data/local/tmp/{}".format(mod_file)],
                serial=serial, check=True, timeout=30)
        ok("Magisk module installed")

        warn("Now: Settings → Security → Install cert → CA → /sdcard/portswigger.crt")
        warn("Waiting 60 s for manual install ...")
        for i in range(60, 0, -1):
            print("\r{}  {}s ...{}".format(C, i, W), end="", flush=True)
            time.sleep(1)
        print()
        adb_cmd(["reboot"], serial=serial, timeout=15)
        ok("Emulator rebooting — setup complete! ✓")
        log_session("Burp cert installed on {}".format(serial))
    except Exception as e:
        err("Failed: {}".format(e))
    _press_enter()

def _one_click_proxy(port="8080"):
    display_banner()
    if not _require_device(): return
    serial = select_device()
    port   = input("{}→ Proxy port [8080]: {}".format(C, W)).strip() or "8080"
    adb_cmd(["shell","settings","put","global","http_proxy","127.0.0.1:{}".format(port)],
            serial=serial, timeout=15)
    adb_cmd(["reverse","tcp:{}".format(port),"tcp:{}".format(port)], serial=serial, timeout=15)
    ok("Proxy → 127.0.0.1:{} | adb reverse configured".format(port))
    _press_enter()

def menu_configure_emulator():
    while True:
        try:
            display_banner()
            print("{}[  Configure Emulator  ]{}\n".format(C, W))
            print("  1. Install Frida Server")
            print("  2. Install Burp Suite Certificate (Magisk)")
            print("  3. One-Click Burp Proxy Setup")
            print("  4. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if   ch == "1": _install_frida_server()
            elif ch == "2": _install_burp_cert()
            elif ch == "3": _one_click_proxy()
            elif ch == "4": break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 5 — Run Frida Server
# ════════════════════════════════════════════════════════════════
def menu_run_frida_server():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    info("Killing any old frida-server instance ...")
    adb_cmd(["shell","su","-c","pkill -f frida-server"], serial=serial,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    time.sleep(1)
    
    # Bug 1 Fix: Properly formatted Popen arguments list
    base = [ADB] + (["-s", serial] if serial else [])
    subprocess.Popen(base + ["shell", "su", "-c", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"])
    time.sleep(3)
    
    r = adb_cmd(["shell","su","-c","pgrep -f frida-server"],
                serial=serial, capture_output=True, text=True, timeout=15)
    if r.stdout.strip():
        ok("Frida server running — PID {}".format(r.stdout.strip()))
        
        # connection mismatch check (Bug 2)
        r_ver = subprocess.run(["frida-ps"] + (["-D", serial] if serial else ["-U"]), capture_output=True, text=True, timeout=10)
        if r_ver.returncode != 0:
            warn("Unable to connect to frida-server. There might be a version mismatch between host frida-tools and device frida-server.")
        
        log_session("frida-server started on {}".format(serial))
    else:
        err("Frida server did not start — check /data/local/tmp/frida-server exists.")
    _press_enter()

# ════════════════════════════════════════════════════════════════
#  MENU 6 — Frida Tools
# ════════════════════════════════════════════════════════════════
def _frida_run_script(package, script_path, script_name, serial=None, attach=False):
    info("Running '{}' on {} ...".format(script_name, package))
    print("{}→ Ctrl+C to stop.\n{}".format(M, W))
    s_args = ["-D", serial] if serial else ["-U"]
    cmd = (["frida"] + s_args + ["-n", package, "-l", script_path]
           if attach else
           ["frida"] + s_args + ["-f", package, "-l", script_path, "--no-pause"])
    try:
        subprocess.run(cmd)
        ok("{} finished".format(script_name))
    except KeyboardInterrupt:
        print("\n{}[!] Stopped.{}".format(Y, W))
    except Exception as e:
        err("frida error: {}".format(e))
        if not attach:
            warn("Retrying in attach mode (app must be running) ...")
            try:
                subprocess.run(["frida"]+s_args+["-n",package,"-l",script_path])
            except Exception as e2:
                err("Attach also failed: {}".format(e2))

def _add_custom_script():
    display_banner()
    print("{}[  Add Custom Frida Script  ]{}\n".format(C, W))
    print("  1. Paste code interactively")
    print("  2. Import from file path")
    print("  3. Cancel\n")
    mode = input("{}→ Choose: {}".format(C, W)).strip()
    code = name = ""
    if mode == "1":
        print("{}Paste code — press Enter twice when done:{}\n".format(C, W))
        lines = []
        while True:
            try:
                ln = input()
            except KeyboardInterrupt:
                break
            if ln == "" and lines and lines[-1] == "":
                break
            lines.append(ln)
        code = "\n".join(lines[:-1] if lines and lines[-1]=="" else lines)
        name = input("{}Script name (no spaces): {}".format(C, W)).strip()
    elif mode == "2":
        path = input("{}Full path to .js: {}".format(C, W)).strip().strip('"').strip("'")
        if not os.path.isfile(path):
            err("Not found: {}".format(path)); _press_enter(); return
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        name = os.path.splitext(os.path.basename(path))[0]
    else:
        return
    if not code.strip():
        err("Empty script."); _press_enter(); return
    name = re.sub(r"[^\w\-]", "_", name)
    if not name:
        err("Invalid name."); _press_enter(); return
    os.makedirs("./Fripts", exist_ok=True)
    spath = os.path.join("./Fripts", "{}.js".format(name))
    with open(spath, "w", encoding="utf-8") as f:
        f.write(code)
    custom_scripts.append((name, spath))
    ok("Script '{}' saved → {}".format(name, spath))
    _press_enter()

def _delete_custom_script():
    if not custom_scripts:
        warn("No custom scripts saved."); _press_enter(); return
    for i,(n,_) in enumerate(custom_scripts,1):
        print("  {}. {}".format(i,n))
    print("  {}. Cancel".format(len(custom_scripts)+1))
    ch = input("{}→ Choose: {}".format(C, W)).strip()
    if ch.isdigit():
        c = int(ch)
        if 1 <= c <= len(custom_scripts):
            n,p = custom_scripts.pop(c-1)
            try:
                os.remove(p)
                ok("Deleted '{}'".format(n))
            except Exception as e:
                err(str(e))
    _press_enter()

def _objection_launch():
    display_banner()
    if not shutil.which("objection"):
        err("objection not installed — run: pip install objection"); _press_enter(); return
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    info("Launching objection for {} ...".format(package))
    print("{}→ Type 'help' in the objection shell.\n{}".format(M, W))
    try:
        subprocess.run(["objection"] + (["-S",serial] if serial else []) + ["-g",package,"explore"])
    except KeyboardInterrupt:
        print("\n{}[!] Closed.{}".format(Y, W))
    except Exception as e:
        err("objection error: {}".format(e))
    _press_enter()

def _frida_repl():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    s_args = ["-D",serial] if serial else ["-U"]
    info("Opening Frida REPL for '{}' — Ctrl+C to exit.".format(package))
    try:
        subprocess.run(["frida"]+s_args+["-n",package])
    except KeyboardInterrupt:
        print("\n{}[!] REPL closed.{}".format(Y, W))
    except Exception as e:
        err("REPL error: {}".format(e))
    _press_enter()

def _frida_trace():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    pattern = input("{}→ Method pattern (e.g. *ssl* or recv*): {}".format(C, W)).strip()
    if not pattern:
        err("Cannot be empty."); _press_enter(); return
    s_args = ["-D",serial] if serial else ["-U"]
    info("Tracing '{}' on '{}' — Ctrl+C to stop.".format(pattern, package))
    try:
        subprocess.run(["frida-trace"]+s_args+["-f",package,"-i",pattern,"--no-pause"])
    except KeyboardInterrupt:
        print("\n{}[!] Trace stopped.{}".format(Y, W))
    except Exception as e:
        err("frida-trace error: {}".format(e))
    _press_enter()

def menu_frida_tools():
    PRED = {
        "2": ("Bypass SSL Pinning",         "./Fripts/SSL-BYE.js"),
        "3": ("Bypass Root Detection",       "./Fripts/ROOTER.js"),
        "4": ("Bypass SSL + Root (Combined)","./Fripts/PintooR.js"),
    }
    while True:
        try:
            # Bug 9 Fix: Reload custom scripts on redraw
            load_custom_scripts()
            
            display_banner()
            print("{}[  Frida Tools  ]{}\n".format(C, W))
            print("  1. List installed apps (frida-ps -ai)")
            print("  2. Bypass SSL Pinning             (SSL-BYE.js)")
            print("  3. Bypass Root Detection          (ROOTER.js)")
            print("  4. Bypass SSL + Root              (PintooR.js)")
            print("  5. Add custom Frida script")
            print("  6. Delete custom Frida script")
            print("  7. Launch Objection explorer")
            print("  8. Frida REPL (interactive shell)")
            print("  9. Trace method calls (frida-trace)")
            if custom_scripts:
                print("\n{}  Custom Scripts:{}".format(C, W))
                for i,(n,_) in enumerate(custom_scripts, 10):
                    print("    {}. {}".format(i, n))
            back_n = 10 + len(custom_scripts)
            print("  {}. Back\n".format(back_n))
            warn("Device must be running, rooted, Frida server active.")
            ch = input("{}→ Choose: {}".format(C, W)).strip()

            if ch == "1":
                if not _require_device(): continue
                serial = select_device()
                subprocess.run(["frida-ps"]+(["-D",serial] if serial else ["-U"])+["-ai"])
                _press_enter()

            elif ch in PRED:
                sc_name, sc_path = PRED[ch]
                if not _require_device(): continue
                if not os.path.exists(sc_path):
                    err("Script not found: {} — ensure Fripts/ folder is intact.".format(sc_path))
                    _press_enter(); continue
                serial  = select_device()
                package = ask_package()
                if not package: _press_enter(); continue
                attach  = input("{}→ Attach to running process? y/[n]: {}".format(C, W)).strip().lower()
                _frida_run_script(package, sc_path, sc_name, serial, attach=attach=="y")
                log_session("{} → {}".format(sc_name, package))
                _press_enter()

            elif ch == "5": _add_custom_script()
            elif ch == "6": _delete_custom_script()
            elif ch == "7": _objection_launch()
            elif ch == "8": _frida_repl()
            elif ch == "9": _frida_trace()

            elif ch.isdigit() and 10 <= int(ch) < back_n:
                idx = int(ch) - 10
                cn, cp = custom_scripts[idx]
                if not _require_device(): continue
                serial  = select_device()
                package = ask_package()
                if not package: _press_enter(); continue
                _frida_run_script(package, cp, cn, serial)
                _press_enter()

            elif ch == str(back_n): break
            else:
                err("Invalid choice."); time.sleep(0.4)
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 7 — APK Analysis
# ════════════════════════════════════════════════════════════════
def _ask_apk():
    p = input("{}→ APK path: {}".format(C, W)).strip().strip('"').strip("'")
    if not os.path.isfile(p):
        err("Not found: {}".format(p)); return None
    return p

def _apk_decode():
    display_banner()
    if not shutil.which("apktool"):
        warn("apktool not found → https://apktool.org/"); _press_enter(); return
    apk = _ask_apk()
    if not apk: _press_enter(); return
    out = os.path.splitext(apk)[0] + "_decoded"
    info("Decoding with apktool ...")
    try:
        subprocess.run(["apktool","d","-f","-o",out,apk], timeout=180)
        ok("Output → {}".format(out))
        log_session("Decoded: {}".format(apk))
    except Exception as e:
        err(f"Decompilation failed: {e}")
    _press_enter()

def _apk_secrets():
    display_banner()
    if not shutil.which("apkleaks"):
        warn("apkleaks not installed → pip install apkleaks"); _press_enter(); return
    apk = _ask_apk()
    if not apk: _press_enter(); return
    rpt = os.path.splitext(apk)[0] + "_secrets.json"
    info("Scanning for secrets ...")
    try:
        subprocess.run(["apkleaks","-f",apk,"-o",rpt], timeout=300)
        if os.path.isfile(rpt):
            ok("Report → {}".format(rpt))
            try:
                with open(rpt, "r", encoding="utf-8") as f:
                    data = json.load(f)
                hits = [(k,v) for k,v in data.items() if v]
                if hits:
                    print("\n{}Top findings:{}".format(Y, W))
                    for k,v in hits[:10]:
                        print("  {}{}{}: {}".format(C, k, W, v[:3] if isinstance(v,list) else v))
            except Exception: pass
        log_session("Secrets scan: {}".format(apk))
    except Exception as e:
        err(f"Apkleaks failed: {e}")
    _press_enter()

def _apk_components():
    display_banner()
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if not aapt:
        warn("aapt not found — install Android Build Tools"); _press_enter(); return
    apk = _ask_apk()
    if not apk: _press_enter(); return
    info("Listing exported components ...")
    try:
        # Bug 3 Fix: aapt vs aapt2 dynamic argument order
        if "aapt2" in os.path.basename(aapt).lower():
            cmd = [aapt, "dump", "xmltree", "--file", "AndroidManifest.xml", apk]
        else:
            cmd = [aapt, "dump", "xmltree", apk, "--file", "AndroidManifest.xml"]
            
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=30)
        exported_true = []
        for line in out.splitlines():
            if "exported" in line.lower() or "android:name" in line.lower():
                print(line)
            if "exported" in line and "true" in line:
                exported_true.append(line)
        if exported_true:
            print("\n{}Found {} exported component(s) — investigate!{}".format(
                Y, len(exported_true), W))
    except Exception as e: err(str(e))
    _press_enter()

def _apk_netsec():
    display_banner()
    apk = _ask_apk()
    if not apk: _press_enter(); return
    info("Checking network_security_config ...")
    try:
        with zipfile.ZipFile(apk) as z:
            netsec = [n for n in z.namelist() if "network_security_config" in n]
            if not netsec:
                warn("No network_security_config found — app may trust ALL CAs.")
                ok("SSL interception should work without extra config.")
            else:
                for n in netsec:
                    ok("Found: {}".format(n))
                    data = z.read(n).decode("utf-8", errors="replace")
                    for line in data.splitlines():
                        colour = Y if any(k in line for k in
                            ("certificates","trust-anchors","cleartextTrafficPermitted","domain")) else ""
                        print("  {}{}{}".format(colour, line, W if colour else ""))
    except Exception as e: err(str(e))
    _press_enter()

def _manifest_deep():
    display_banner()
    print("{}[  Manifest Deep Analysis  ]{}\n".format(C, W))
    apk = _ask_apk()
    if not apk: _press_enter(); return
    info("Parsing AndroidManifest.xml ...")
    findings = []
    try:
        aapt = shutil.which("aapt") or shutil.which("aapt2")
        lines = []
        if aapt:
            if "aapt2" in os.path.basename(aapt).lower():
                cmd = [aapt, "dump", "xmltree", "--file", "AndroidManifest.xml", apk]
            else:
                cmd = [aapt, "dump", "xmltree", apk, "--file", "AndroidManifest.xml"]
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=30)
            lines = raw.splitlines()
        else:
            # Bug 4 Fix: Androguard manifest reading fallback
            try:
                from androguard.core.bytecodes import apk as aapk
                import xml.etree.ElementTree as ET
                andro_apk = aapk.APK(apk)
                manifest_xml = andro_apk.get_android_manifest_xml()
                xml_str = ET.tostring(manifest_xml, encoding='utf-8').decode('utf-8')
                lines = xml_str.splitlines()
            except ImportError:
                err("aapt/aapt2 and Androguard are not available. Manifest analysis cannot continue.")
                _press_enter()
                return

        if any("debuggable" in l.lower() and "true" in l.lower() for l in lines):
            warn("DEBUGGABLE — attacker can attach debugger / run arbitrary code!")
            findings.append("CRITICAL: android:debuggable=true")

        if any("allowbackup" in l.lower() and "true" in l.lower() for l in lines):
            warn("allowBackup=true — data extractable via adb backup!")
            findings.append("HIGH: android:allowBackup=true")

        if any("usescleartexttraffic" in l.lower() and "true" in l.lower() for l in lines):
            warn("usesCleartextTraffic=true — plain HTTP allowed!")
            findings.append("MEDIUM: usesCleartextTraffic=true")

        exp_cnt = sum(1 for l in lines if "exported" in l.lower() and "true" in l.lower())
        if exp_cnt:
            warn("{} exported component(s) — check for intent injection!".format(exp_cnt))
            findings.append("MEDIUM: {} exported components".format(exp_cnt))

        dl_cnt = sum(1 for l in lines if "android.intent.action.VIEW" in l or "scheme" in l.lower())
        if dl_cnt:
            info("{} deep-link / intent-filter reference(s).".format(dl_cnt))
            findings.append("INFO: {} deep link references".format(dl_cnt))

        DK = ("CAMERA","RECORD_AUDIO","READ_CONTACTS","ACCESS_FINE_LOCATION",
              "READ_SMS","PROCESS_OUTGOING_CALLS","READ_CALL_LOG")
        danger = [l.strip() for l in lines if "uses-permission" in l.lower() and any(k in l for k in DK)]
        if danger:
            warn("{} dangerous permission(s):".format(len(danger)))
            for d in danger: print("  {}{}{}".format(R, d, W))
            findings.append("INFO: {} dangerous permissions".format(len(danger)))

        print("\n{}=== Summary ==={}".format(C, W))
        if findings:
            for f in findings:
                col = R if "CRITICAL" in f else Y if "HIGH" in f or "MEDIUM" in f else C
                print("  {}{}{}".format(col, f, W))
        else:
            ok("No obvious misconfigurations in manifest.")

        ask_save_report("manifest_{}".format(os.path.basename(apk)), "\n".join(findings) or "No issues found.")
        log_session("Manifest analysis: {}".format(apk))
    except Exception as e: err(str(e))
    _press_enter()

def _pull_apk():
    display_banner()
    print("{}[  Pull APK from Device  ]{}\n".format(C, W))
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    info("Finding APK path on device ...")
    r = adb_cmd(["shell","pm","path",package], serial=serial, capture_output=True, text=True, timeout=15)
    if "package:" not in r.stdout:
        err("Package not found: {}".format(package)); _press_enter(); return
    apk_on_device = r.stdout.strip().replace("package:","")
    ok("APK on device: {}".format(apk_on_device))
    out = "{}.apk".format(package)
    adb_cmd(["pull", apk_on_device, out], serial=serial, timeout=120)
    if os.path.isfile(out):
        ok("Pulled → {} ({:.1f} MB)".format(out, os.path.getsize(out)/1024/1024))
        log_session("Pulled APK: {}".format(package))
    else:
        err("Pull failed.")
    _press_enter()

# Bug 8 Fix: Recursive apksigner tool finder
def find_apksigner():
    apksigner = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if apksigner:
        return apksigner
        
    sdk_paths = []
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        sdk_paths.append(android_home)
    if IS_WINDOWS:
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            sdk_paths.append(os.path.join(localappdata, "Android", "Sdk"))
    else:
        home = os.path.expanduser("~")
        sdk_paths.append(os.path.join(home, "Android", "Sdk"))
        sdk_paths.append(os.path.join(home, "Library", "Android", "sdk"))
        
    for sdk in sdk_paths:
        bt_dir = os.path.join(sdk, "build-tools")
        if os.path.isdir(bt_dir):
            try:
                versions = [d for d in os.listdir(bt_dir) if os.path.isdir(os.path.join(bt_dir, d))]
                if versions:
                    # Sort version strings correctly
                    versions.sort(key=lambda s: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', s)], reverse=True)
                    for v in versions:
                        exe = "apksigner.bat" if IS_WINDOWS else "apksigner"
                        path = os.path.join(bt_dir, v, exe)
                        if os.path.isfile(path):
                            return path
            except Exception:
                pass
    return None

def _repack_sign():
    display_banner()
    print("{}[  Repack & Sign APK  ]{}\n".format(C, W))
    if not shutil.which("apktool"):
        warn("apktool not found → https://apktool.org/"); _press_enter(); return
    d = input("{}→ Decoded APK directory: {}".format(C, W)).strip().strip('"')
    if not os.path.isdir(d): err("Directory not found."); _press_enter(); return
    out = d.rstrip("/\\") + "_repacked.apk"
    info("Building with apktool ...")
    r = subprocess.run(["apktool","b","-o",out,d], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        err("Build failed:\n{}".format(r.stderr)); _press_enter(); return
    ok("Repacked → {}".format(out))
    ks = "debug.keystore"
    if shutil.which("keytool") and not os.path.isfile(ks):
        info("Generating debug keystore ...")
        subprocess.run([
            "keytool","-genkey","-v","-keystore",ks,
            "-alias","androiddebugkey","-keyalg","RSA","-keysize","2048",
            "-validity","10000","-storepass","android","-keypass","android",
            "-dname","CN=Android Debug,O=Android,C=US"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            
    apksigner = find_apksigner()
    if apksigner and os.path.isfile(ks):
        signed = out.replace(".apk","_signed.apk")
        subprocess.run([apksigner,"sign","--ks",ks,
                        "--ks-pass","pass:android","--key-pass","pass:android",
                        "--out",signed, out], timeout=60)
        if os.path.isfile(signed):
            ok("Signed APK → {}".format(signed))
            log_session("Repack+sign: {}".format(signed))
        else:
            warn("Signing failed — install manually: adb install -r {}".format(out))
    else:
        warn("apksigner not found — sign manually with apksigner.")
    _press_enter()

def _strings_grep(target_dir=None):
    display_banner()
    print("{}[  Sensitive Data Grep  ]{}\n".format(C, W))
    if target_dir:
        target = target_dir
    else:
        target = input("{}→ Decoded APK dir (or single file): {}".format(C, W)).strip().strip('"')
    if not os.path.exists(target): err("Not found."); _press_enter(); return
    PATS = {
        "API Keys / Tokens": r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[\w\-]{16,}",
        "Passwords":         r"(?i)(password|passwd|secret|pwd)\s*[:=]\s*['\"]?\S{4,}",
        "Private Keys":      r"-----BEGIN (RSA|EC|PRIVATE) KEY-----",
        "AWS Keys":          r"AKIA[0-9A-Z]{16}",
        "Cleartext URLs":    r"http://[^\s'\"]+",
        "JWT Tokens":        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "Firebase URLs":     r"https://[a-z0-9-]+\.firebaseio\.com",
        "Google API Keys":   r"AIza[0-9A-Za-z_-]{35}",
        "IP Addresses":      r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    }
    results  = {}
    scanned  = 0
    EXTS     = (".xml",".java",".kt",".smali",".json",".txt",".properties",".gradle",".yaml")
    
    # Bug 5 Fix: Target directory default parsing
    walk_it  = os.walk(target) if os.path.isdir(target) else [((os.path.dirname(target) or "."), [], [os.path.basename(target)])]
    
    for root, _, files in walk_it:
        for fname in files:
            if not any(fname.endswith(e) for e in EXTS): continue
            fp = os.path.join(root, fname)
            scanned += 1
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for label, pat in PATS.items():
                    matches = re.findall(pat, content)
                    if matches:
                        results.setdefault(label,[]).extend((fp,m) for m in matches[:3])
            except Exception: pass
    print("\n{}=== Results — {} files scanned ==={}".format(C, scanned, W))
    if results:
        for label, hits in results.items():
            print("\n{}{}{}".format(Y, label, W))
            for fp, match in hits[:5]:
                rel = os.path.relpath(fp, target) if os.path.isdir(target) else fp
                print("  {} → {}{}{}".format(rel, G, str(match)[:80], W))
    else:
        ok("No sensitive patterns found.")
        
    if results:
        txt = ""
        for label, hits in results.items():
            txt += "\n[{}]\n".format(label)
            for fp, match in hits:
                txt += "  {} → {}\n".format(fp, match)
        ask_save_report("strings_grep", txt or "No findings.")
    log_session("Strings grep on: {}".format(target))
    _press_enter()

def _permissions_audit():
    display_banner()
    print("{}[  App Permissions Audit  ]{}\n".format(C, W))
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    info("Fetching permission grants for {} ...".format(package))
    r = adb_cmd(["shell","dumpsys","package",package], serial=serial, capture_output=True, text=True, timeout=15)
    lines   = r.stdout.splitlines()
    granted = [l.strip() for l in lines if "granted=true"  in l]
    denied  = [l.strip() for l in lines if "granted=false" in l]
    DK = ("CAMERA","RECORD_AUDIO","READ_CONTACTS","ACCESS_FINE_LOCATION",
          "READ_SMS","PROCESS_OUTGOING_CALLS","READ_CALL_LOG","READ_EXTERNAL")
    danger = [p for p in granted if any(k in p for k in DK)]
    print("\n  {}Granted: {}{}   {}Denied: {}{}".format(
        G,len(granted),W, Y,len(denied),W))
    if danger:
        print("\n{}Dangerous permissions granted:{}".format(R, W))
        for p in danger: print("  {}{}{}".format(R,p,W))
    else:
        ok("No dangerous permissions granted.")
        
    ask_save_report("permissions_{}".format(package),
                    "Package: {}\nGranted:{}\nDenied:{}\n\nDangerous:\n{}".format(
                        package,len(granted),len(denied),"\n".join(danger)))
    log_session("Permissions audit: {}".format(package))
    _press_enter()

# ── Feature 2: JADX Decompiler Integration ────────────────────────────────────
def _apk_decompile_jadx():
    display_banner()
    print("{}[  JADX Decompiler Integration  ]{}\n".format(C, W))
    jadx = shutil.which("jadx") or shutil.which("jadx.bat")
    if not jadx:
        warn("JADX not found in PATH.")
        info("Please download JADX from: https://github.com/skylot/jadx/releases")
        _press_enter()
        return
    apk = _ask_apk()
    if not apk:
        _press_enter()
        return
    out_dir = os.path.splitext(apk)[0] + "_jadx"
    info(f"Decompiling {apk} to {out_dir} using JADX...")
    try:
        res = subprocess.run([jadx, "-d", out_dir, apk], capture_output=True, text=True, timeout=360)
        if res.returncode == 0:
            ok(f"Decompilation complete! Output directory: {out_dir}")
            log_session(f"Decompiled APK with JADX: {apk}")
            
            if input("\n→ Do you want to run Sensitive Data Grep on decompiled sources? (y/n): ").strip().lower() == "y":
                _strings_grep(out_dir)
        else:
            err(f"JADX failed with return code {res.returncode}")
            print(res.stderr)
    except Exception as e:
        err(f"Error running JADX: {e}")
    _press_enter()

# ── Feature 3: Androguard Static Analysis ─────────────────────────────────────
def _androguard_analysis():
    display_banner()
    print("{}[  Androguard Static Analysis  ]{}\n".format(C, W))
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        err("androguard not installed. Run: pip install androguard")
        _press_enter()
        return
    apk = _ask_apk()
    if not apk:
        _press_enter()
        return
    info("Performing Androguard analysis (this may take a minute) ...")
    try:
        a, d, dx = AnalyzeAPK(apk)
        
        # Package Info
        pkg = a.get_package()
        ver = a.get_androidversion_name()
        min_sdk = a.get_min_sdk_version()
        tgt_sdk = a.get_target_sdk_version()
        
        print("\n{}=== Package Info ==={}".format(C, W))
        print(f"  Package: {pkg}")
        print(f"  Version: {ver}")
        print(f"  Min SDK: {min_sdk}")
        print(f"  Target SDK: {tgt_sdk}")
        
        # Permissions
        print("\n{}=== Permissions ==={}".format(C, W))
        perms = a.get_permissions()
        DK = ("CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
              "READ_SMS", "PROCESS_OUTGOING_CALLS", "READ_CALL_LOG", "WRITE_EXTERNAL_STORAGE")
        for perm in perms:
            short_p = perm.split(".")[-1]
            if any(k in short_p for k in DK):
                print(f"  {R}[DANGEROUS] {perm}{W}")
            else:
                print(f"  {G}{perm}{W}")
                
        # Exported Components
        print("\n{}=== Exported Components ==={}".format(C, W))
        manifest = a.get_android_manifest_xml()
        exported_components = []
        for c_type in ['activity', 'service', 'receiver', 'provider']:
            for el in manifest.findall(f'.//{c_type}'):
                name = el.get('{http://schemas.android.com/apk/res/android}name')
                exp = el.get('{http://schemas.android.com/apk/res/android}exported')
                has_filter = el.find('intent-filter') is not None
                is_exp = (exp == 'true') or (exp is None and has_filter)
                if is_exp:
                    exported_components.append((c_type.upper(), name))
                    print(f"  {Y}[{c_type.upper()}] {name} (exported=true){W}")
                    
        # Native libs
        print("\n{}=== Native Libraries ==={}".format(C, W))
        so_files = [f for f in a.get_files() if f.endswith(".so")]
        if so_files:
            for so in so_files:
                print(f"  {C}{so}{W}")
        else:
            print("  No native libraries (.so) found.")
            
        # Code Analysis (Crypto, Reflection, DCL, Network)
        print("\n{}=== Code API Usage ==={}".format(C, W))
        crypto_calls = set()
        reflection_calls = set()
        dynamic_loading = set()
        network_calls = set()
        
        for method in dx.get_methods():
            try:
                for _, call, _ in method.get_xref_to():
                    try:
                        c_name = str(getattr(call, 'class_name', '') or '')
                        m_name = str(getattr(call, 'name', '') or '')
                        if not c_name:
                            continue
                        full_call = f"{c_name}->{m_name}"
                        
                        if "javax/crypto/" in c_name or "java/security/" in c_name:
                            crypto_calls.add(full_call)
                        if "java/lang/Class" in c_name and m_name in ("forName", "getMethod", "getDeclaredMethod"):
                            reflection_calls.add(full_call)
                        if "java/lang/reflect/Method" in c_name and m_name == "invoke":
                            reflection_calls.add(full_call)
                        if "DexClassLoader" in c_name or "PathClassLoader" in c_name:
                            dynamic_loading.add(full_call)
                        if "HttpURLConnection" in c_name or "okhttp3" in c_name or "retrofit" in c_name:
                            network_calls.add(full_call)
                    except Exception:
                        continue
            except Exception:
                continue
                    
        # Print summaries
        severity_findings = []
        if crypto_calls:
            print(f"  {G}[INFO] Crypto APIs Used: {len(crypto_calls)} unique calls{W}")
            severity_findings.append(("INFO", f"Crypto APIs used: {len(crypto_calls)} calls"))
        if reflection_calls:
            print(f"  {Y}[MEDIUM] Reflection Used: {len(reflection_calls)} unique calls (Class.forName/invoke){W}")
            severity_findings.append(("MEDIUM", f"Reflection used: {len(reflection_calls)} calls"))
        if dynamic_loading:
            print(f"  {R}[HIGH] Dynamic Code Loading (DCL): {len(dynamic_loading)} calls (DexClassLoader){W}")
            severity_findings.append(("HIGH", f"Dynamic Code Loading: {len(dynamic_loading)} calls"))
        if network_calls:
            print(f"  {C}[INFO] Network Libraries Used: {len(network_calls)} calls{W}")
            severity_findings.append(("INFO", f"Network APIs used: {len(network_calls)} calls"))
            
        report_data = {
            "package": pkg,
            "version": ver,
            "min_sdk": min_sdk,
            "target_sdk": tgt_sdk,
            "permissions": list(perms),
            "exported_components": exported_components,
            "native_libs": so_files,
            "findings": severity_findings
        }
        
        if input("\n→ Save JSON report? (y/n): ").strip().lower() == "y":
            path = save_report(f"androguard_{pkg}", json.dumps(report_data, indent=4), fmt="json")
            ok(f"Report saved to {path}")
            
    except Exception as e:
        err(f"Androguard analysis failed: {e}")
    _press_enter()

# ── Feature 7: MobSF Integration ──────────────────────────────────────────────
def _mobsf_scan():
    display_banner()
    print("{}[  MobSF Security Analysis  ]{}\n".format(C, W))
    rq = _get_rq()
    if not rq:
        return
    
    url = CONFIG.get("mobsf_url", "http://localhost:8000")
    api_key = CONFIG.get("mobsf_api_key", "")
    
    # 1. Check if running
    info(f"Checking if MobSF is running at {url}...")
    try:
        rq.get(url, timeout=5)
    except Exception:
        err("MobSF is not running.")
        print("\nHow to start MobSF:")
        print("  - Local: running command 'mobsf'")
        print("  - Docker: docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf")
        _press_enter()
        return
        
    if not api_key:
        err("MobSF API Key is missing in configuration.")
        api_key = input("Enter MobSF API Key: ").strip()
        if not api_key:
            err("API Key required.")
            _press_enter()
            return
        CONFIG["mobsf_api_key"] = api_key
        save_config()
        
    apk = _ask_apk()
    if not apk:
        _press_enter()
        return
        
    headers = {"Authorization": api_key}
    
    # 2. Upload APK
    info("Uploading APK to MobSF...")
    try:
        with open(apk, "rb") as f:
            files = {"file": f}
            r_up = rq.post(f"{url}/api/v1/upload", files=files, headers=headers, timeout=300)
            
        if r_up.status_code != 200:
            err(f"Upload failed (Status {r_up.status_code}): {r_up.text}")
            _press_enter()
            return
            
        up_data = r_up.json()
        apk_hash = up_data.get("hash")
        if not apk_hash:
            err(f"Invalid upload response: {up_data}")
            _press_enter()
            return
        ok(f"Uploaded successfully! Hash: {apk_hash}")
        
        # 3. Trigger Scan
        info("Starting MobSF scan...")
        scan_data = {"hash": apk_hash, "scan_type": "apk"}
        r_scan = rq.post(f"{url}/api/v1/scan", data=scan_data, headers=headers, timeout=300)
        if r_scan.status_code != 200:
            err(f"Scan trigger failed: {r_scan.text}")
            _press_enter()
            return
            
        # 4. Poll and Fetch JSON Report
        info("Waiting for MobSF scan to complete...")
        max_wait = 300  # seconds
        poll_interval = 10
        elapsed = 0
        scan_complete = False
        report = None
        while elapsed < max_wait:
            try:
                r_status = rq.post(f"{url}/api/v1/report_json", data={"hash": apk_hash}, headers=headers, timeout=30)
                if r_status.status_code == 200:
                    status_data = r_status.json()
                    if status_data.get("title") or status_data.get("package_name") or status_data.get("security_score") is not None:
                        scan_complete = True
                        report = status_data
                        break
            except Exception:
                pass
            print(f"\r  {C}Polling... {elapsed}s elapsed{W}", end="", flush=True)
            time.sleep(poll_interval)
            elapsed += poll_interval
        print()
        if not scan_complete:
            err("MobSF scan timed out after 300s. Try fetching report manually.")
            _press_enter()
            return
        ok("Scan complete!")
        
        print("\n=== Scan Summary ===")
        print(f"  App Name: {report.get('app_name', 'N/A')}")
        print(f"  Security Score: {report.get('security_score', 'N/A')}/100")
        print(f"  Package Name: {report.get('package_name', 'N/A')}")
        
        trackers = report.get("trackers", {})
        tracker_count = trackers.get("detected_trackers", 0) if isinstance(trackers, dict) else len(trackers)
        print(f"  Trackers Detected: {tracker_count}")
        
        local_report_path = save_report(f"mobsf_{apk_hash}", json.dumps(report, indent=4), fmt="json")
        ok(f"Full JSON report saved to: {local_report_path}")
        log_session(f"MobSF scan: {apk_hash}")
        
    except Exception as e:
        err(f"MobSF integration error: {e}")
        
    _press_enter()

def menu_apk_analysis():
    while True:
        try:
            display_banner()
            print("{}[  APK Analysis  ]{}\n".format(C, W))
            print("  1.  Decode APK (apktool)")
            print("  2.  Scan secrets / API keys (apkleaks)")
            print("  3.  List exported components (aapt)")
            print("  4.  Check network security config")
            print("  5.  Manifest deep analysis & auto-findings")
            print("  6.  Pull APK from device")
            print("  7.  Repack & sign APK (debug key)")
            print("  8.  Sensitive data grep (decoded dir)")
            print("  9.  App permissions audit (live device)")
            print("  10. Decompile with JADX")
            print("  11. Androguard Static Analysis")
            print("  12. MobSF scanning")
            print("  13. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if   ch == "1":  _apk_decode()
            elif ch == "2":  _apk_secrets()
            elif ch == "3":  _apk_components()
            elif ch == "4":  _apk_netsec()
            elif ch == "5":  _manifest_deep()
            elif ch == "6":  _pull_apk()
            elif ch == "7":  _repack_sign()
            elif ch == "8":  _strings_grep()
            elif ch == "9":  _permissions_audit()
            elif ch == "10": _apk_decompile_jadx()
            elif ch == "11": _androguard_analysis()
            elif ch == "12": _mobsf_scan()
            elif ch == "13": break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 8 — Traffic & Proxy
# ════════════════════════════════════════════════════════════════
def _set_proxy():
    if not _require_device(): return
    serial = select_device()
    host   = input("{}→ Proxy host [127.0.0.1]: {}".format(C, W)).strip() or "127.0.0.1"
    port   = input("{}→ Proxy port [8080]: {}".format(C, W)).strip() or "8080"
    adb_cmd(["shell","settings","put","global","http_proxy","{}:{}".format(host,port)],
            serial=serial, timeout=15)
    ok("Proxy set → {}:{}".format(host, port))
    _press_enter()

def _clear_proxy():
    if not _require_device(): return
    serial = select_device()
    adb_cmd(["shell","settings","put","global","http_proxy",":0"], serial=serial, timeout=15)
    adb_cmd(["shell","settings","delete","global","http_proxy"], serial=serial, timeout=15)
    ok("Proxy cleared.")
    _press_enter()

def _check_proxy():
    if not _require_device(): return
    serial = select_device()
    r = adb_cmd(["shell","settings","get","global","http_proxy"],
                serial=serial, capture_output=True, text=True, timeout=15)
    val = r.stdout.strip()
    print("{}Current proxy: {}{}".format(C, val or "(not set)", W))
    _press_enter()

def _adb_reverse():
    if not _require_device(): return
    serial = select_device()
    port   = input("{}→ Port [8080]: {}".format(C, W)).strip() or "8080"
    adb_cmd(["reverse","tcp:{}".format(port),"tcp:{}".format(port)], serial=serial, timeout=15)
    ok("adb reverse: device:{} → host:{}".format(port, port))
    _press_enter()

# Bug 7 Fix: Non-blocking reader cleartext traffic monitor
def _cleartext_monitor():
    display_banner()
    print("{}[  Cleartext HTTP Monitor  ]{}\n".format(C, W))
    if not _require_device(): return
    serial  = select_device()
    pkg_flt = input("{}→ Filter by package (blank = all traffic): {}".format(C, W)).strip()
    duration = int(input("{}→ Monitor duration seconds [60]: {}".format(C, W)).strip() or "60")
    info("Monitoring logcat for http:// traffic — use the app now ...")
    warn("Ctrl+C to stop early.\n")
    base  = [ADB]+(["-s",serial] if serial else [])
    hits  = []
    
    # Thread Safe Non-Blocking Read
    try:
        proc = subprocess.Popen(base+["logcat","-v","brief"],
                                 stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL, errors="replace")
        
        q = queue.Queue()
        def enqueue_output(out, q):
            try:
                for line in iter(out.readline, ''):
                    q.put(line)
            except Exception:
                pass
            finally:
                out.close()
                
        t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
        t.daemon = True
        t.start()
        
        start = time.time()
        while time.time() - start < duration:
            processed_any = False
            while True:
                try:
                    line = q.get_nowait()
                    processed_any = True
                    if "http://" in line and (not pkg_flt or pkg_flt in line):
                        hits.append(line.strip())
                        print("  {}{}{}".format(Y, line.strip()[:120], W))
                except queue.Empty:
                    break
            if not processed_any:
                time.sleep(0.1)
                
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            pass
    except KeyboardInterrupt:
        pass
        
    if hits:
        warn("{} cleartext HTTP request(s) found!".format(len(hits)))
        ask_save_report("cleartext_http", "\n".join(hits))
    else:
        ok("No cleartext HTTP detected during monitoring.")
    _press_enter()

def _net_info():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    info("Open connections (netstat / ss):")
    r = adb_cmd(["shell","su","-c","netstat -tuln 2>/dev/null || ss -tuln"],
                serial=serial, capture_output=True, text=True, timeout=15)
    print(r.stdout or "  (no output — root required)")
    info("Network interfaces (ip addr):")
    r2 = adb_cmd(["shell","ip","addr"], serial=serial, capture_output=True, text=True, timeout=15)
    print(r2.stdout)
    _press_enter()

# ── Feature 6: Logcat Capture ─────────────────────────────────────────────────
def _start_logcat_capture():
    global LOGCAT_PROC, LOGCAT_FILE
    display_banner()
    print("{}[  Start Persistent Logcat Capture  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    
    if LOGCAT_PROC:
        warn("Logcat capture is already running.")
        _press_enter()
        return
        
    pkg = input("Enter package filter (optional): ").strip()
    if pkg and not validate_package(pkg):
        err("Invalid package name.")
        _press_enter()
        return
        
    level = input("Enter log level (V/D/I/W/E) [V]: ").strip().upper() or "V"
    if level not in ("V", "D", "I", "W", "E"):
        err("Invalid log level.")
        _press_enter()
        return
        
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"logcat_{ts}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    info(f"Starting persistent logcat capture to {filepath}...")
    
    try:
        LOGCAT_FILE = open(filepath, "w", encoding="utf-8")
        LOGCAT_PROC = subprocess.Popen([ADB] + (["-s", serial] if serial else []) + ["logcat", f"*:{level}"],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        
        def filter_logcat_thread(proc, file_handle, pkg_filter):
            for line in iter(proc.stdout.readline, ''):
                if not pkg_filter or pkg_filter in line:
                    file_handle.write(line)
                    file_handle.flush()
            file_handle.close()
            
        t = threading.Thread(target=filter_logcat_thread, args=(LOGCAT_PROC, LOGCAT_FILE, pkg))
        t.daemon = True
        t.start()
        
        ok("Logcat capture started successfully in background!")
        log_session(f"Started persistent logcat for package: {pkg or 'All'}")
    except Exception as e:
        err(f"Failed to start logcat: {e}")
        if LOGCAT_FILE:
            LOGCAT_FILE.close()
            LOGCAT_FILE = None
            
    _press_enter()

def _stop_logcat_capture():
    global LOGCAT_PROC, LOGCAT_FILE
    display_banner()
    print("{}[  Stop Persistent Logcat Capture  ]{}\n".format(C, W))
    if not LOGCAT_PROC:
        warn("No logcat capture is currently running.")
        _press_enter()
        return
        
    info("Stopping logcat process...")
    try:
        LOGCAT_PROC.terminate()
        LOGCAT_PROC.wait(timeout=3)
    except Exception:
        try:
            LOGCAT_PROC.kill()
        except Exception:
            pass
            
    LOGCAT_PROC = None
    ok("Logcat capture stopped.")
    
    filepath = None
    if LOGCAT_FILE:
        filepath = LOGCAT_FILE.name
        try:
            LOGCAT_FILE.close()
        except Exception:
            pass
        LOGCAT_FILE = None
        
    if filepath and os.path.exists(filepath):
        print(f"\nSaved file: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                print("\n=== Last 20 lines preview ===")
                for line in lines[-20:]:
                    print("  " + line.strip())
        except Exception as e:
            err(f"Failed to read logcat preview: {e}")
    else:
        warn("Logcat file not found.")
        
    _press_enter()

def menu_traffic_proxy():
    while True:
        try:
            display_banner()
            print("{}[  Traffic & Proxy Tools  ]{}\n".format(C, W))
            print("  1. Set emulator proxy")
            print("  2. Clear emulator proxy")
            print("  3. Check proxy settings")
            print("  4. adb reverse (port-forward to host)")
            print("  5. Monitor cleartext HTTP traffic (logcat)")
            print("  6. Network info (connections & interfaces)")
            print("  7. Start persistent logcat capture")
            print("  8. Stop persistent logcat capture")
            print("  9. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if   ch == "1": _set_proxy()
            elif ch == "2": _clear_proxy()
            elif ch == "3": _check_proxy()
            elif ch == "4": _adb_reverse()
            elif ch == "5": _cleartext_monitor()
            elif ch == "6": _net_info()
            elif ch == "7": _start_logcat_capture()
            elif ch == "8": _stop_logcat_capture()
            elif ch == "9": break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 9 — Device Info
# ════════════════════════════════════════════════════════════════
def menu_device_info():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    PROPS  = [
        ("ro.product.model",         "Model"),
        ("ro.product.brand",         "Brand"),
        ("ro.build.version.release", "Android Version"),
        ("ro.build.version.sdk",     "API Level"),
        ("ro.product.cpu.abi",       "ABI"),
        ("ro.build.type",            "Build Type"),
        ("ro.debuggable",            "Debuggable"),
        ("ro.secure",                "Secure Flag"),
        ("ro.build.fingerprint",     "Build Fingerprint"),
    ]
    print("\n{}[  Device Information — {} ]{}\n".format(C, serial, W))
    for prop, label in PROPS:
        val   = adb_shell(["getprop", prop], serial) or "(unknown)"
        col   = R if (label in ("Debuggable","Secure Flag") and val == "1") else ""
        print("  {}{:<25}{} {}{}{}".format(C, label, W, col, val, W if col else ""))

    # Root check
    r_root = adb_cmd(["shell","su","-c","echo ROOTED"],
                     serial=serial, capture_output=True, text=True, timeout=5)
    rooted = "{}YES ✓{}".format(G,W) if "ROOTED" in r_root.stdout else "{}NO{}".format(R,W)
    print("  {}{:<25}{} {}".format(C,"Root Status",W, rooted))

    # Frida server
    r_fs = adb_cmd(["shell","pgrep","-f","frida-server"],
                   serial=serial, capture_output=True, text=True, timeout=15)
    fs_st = "{}RUNNING (PID {}){}".format(G,r_fs.stdout.strip(),W) if r_fs.stdout.strip() \
            else "{}STOPPED{}".format(R,W)
    print("  {}{:<25}{} {}".format(C,"Frida Server",W, fs_st))

    # Disk space
    r_disk = adb_cmd(["shell","df","/data"], serial=serial, capture_output=True, text=True, timeout=15)
    disk   = r_disk.stdout.splitlines()[-1] if r_disk.stdout.strip() else "(unknown)"
    print("  {}{:<25}{} {}".format(C,"Data Partition",W, disk))
    print()
    _press_enter()

# ════════════════════════════════════════════════════════════════
#  MENU 10 — Runtime App Tampering
# ════════════════════════════════════════════════════════════════
def _debug_launch():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    r = adb_cmd(["shell","cmd","package","resolve-activity","--brief",
                 "-a","android.intent.action.MAIN",
                 "-c","android.intent.category.LAUNCHER", package],
                serial=serial, capture_output=True, text=True, timeout=15)
    activity = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "{}/MainActivity".format(package)
    info("Launching {} in debug mode (-D) ...".format(activity))
    adb_cmd(["shell","am","start","-D","-n",activity], serial=serial, timeout=15)
    ok("Launched — waiting for debugger attach.")
    print("{}  Attach: adb forward tcp:8700 jdwp:<pid> && jdb -attach localhost:8700{}".format(M,W))
    _press_enter()

def _list_running():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    r = adb_cmd(["shell","ps","-A"], serial=serial, capture_output=True, text=True, timeout=15)
    print("\n{}  PID        PACKAGE / PROCESS{}".format(C,W))
    print("  " + "─"*46)
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9:
            pid, name = parts[1], parts[-1]
            if "." in name and not name.startswith("["):
                print("  {:<12} {}".format(pid, name))
    _press_enter()

def _force_stop():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    adb_cmd(["shell","am","force-stop",package], serial=serial, timeout=15)
    ok("Force-stopped {}".format(package))
    _press_enter()

def _grant_permissions():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    PERMS = [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CALL_PHONE",
    ]
    info("Granting all dangerous permissions to {} ...".format(package))
    granted = 0
    for p in PERMS:
        r = adb_cmd(["shell","pm","grant",package,p],
                    serial=serial, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            granted += 1
            print("  {}✓  {}{}".format(G, p.split(".")[-1], W))
    ok("Granted {}/{} permissions.".format(granted, len(PERMS)))
    _press_enter()

def _clear_data():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    if input("{}→ Clear ALL data for {}? (y/n): {}".format(Y,package,W)).strip().lower() == "y":
        adb_cmd(["shell","pm","clear",package], serial=serial, timeout=15)
        ok("Data cleared for {}.".format(package))
        log_session("Cleared data: {}".format(package))
    _press_enter()

def _monkey_test():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    events  = input("{}→ Event count [500]: {}".format(C, W)).strip() or "500"
    info("Monkey testing '{}' with {} events — Ctrl+C to stop.".format(package, events))
    try:
        adb_cmd(["shell","monkey","-p",package,"-v","--throttle","100",events],
                serial=serial, timeout=300)
    except KeyboardInterrupt:
        print("\n{}[!] Stopped.{}".format(Y,W))
    _press_enter()

def _launch_activity():
    display_banner()
    if not _require_device(): return
    serial   = select_device()
    activity = input("{}→ Activity (e.g. com.example/.AdminActivity): {}".format(C, W)).strip()
    if not activity: err("Cannot be empty."); _press_enter(); return
    extra    = input("{}→ Extra args (e.g. --es key val) or blank: {}".format(C, W)).strip()
    cmd      = ["shell","am","start","-n",activity]
    if extra: cmd += extra.split()
    r = adb_cmd(cmd, serial=serial, capture_output=True, text=True, timeout=15)
    if "Error" in r.stdout or r.returncode != 0:
        err("Launch failed: {}".format((r.stdout+r.stderr).strip()))
    else:
        ok("Launched: {}".format(activity))
        print(r.stdout)
    _press_enter()

def _send_broadcast():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    action = input("{}→ Broadcast action: {}".format(C, W)).strip()
    if not action: err("Cannot be empty."); _press_enter(); return
    extra  = input("{}→ Extra args or blank: {}".format(C, W)).strip()
    cmd    = ["shell","am","broadcast","-a",action]
    if extra: cmd += extra.split()
    r = adb_cmd(cmd, serial=serial, capture_output=True, text=True, timeout=15)
    print(r.stdout)
    _press_enter()

def _content_provider_query():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    uri    = input("{}→ Content URI (e.g. content://com.example/data): {}".format(C, W)).strip()
    if not uri: err("Cannot be empty."); _press_enter(); return
    info("Querying {} ...".format(uri))
    r = adb_cmd(["shell","content","query","--uri",uri],
                serial=serial, capture_output=True, text=True, timeout=15)
    if r.stdout.strip():
        ok("Results:")
        print(r.stdout[:4000])
    else:
        warn("No results — access denied or empty table.")
        if r.stderr: print(r.stderr[:300])
    _press_enter()

def _dump_shared_prefs():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    info("Reading shared_prefs for {} (requires root) ...".format(package))
    prefs_dir = "/data/data/{}/shared_prefs".format(package)
    r = adb_cmd(["shell","su","-c","ls {}".format(prefs_dir)],
                serial=serial, capture_output=True, text=True, timeout=15)
    if not r.stdout.strip():
        warn("No shared_prefs found or root denied.")
        _press_enter(); return
    files = r.stdout.strip().splitlines()
    ok("Found {} shared_prefs file(s):".format(len(files)))
    for fname in files:
        print("\n  {}{}{}".format(Y, fname, W))
        r2 = adb_cmd(["shell","su","-c",
                      "cat {}/{}".format(prefs_dir, fname.strip())],
                     serial=serial, capture_output=True, text=True, timeout=15)
        print(r2.stdout[:2000])
        
    content = ""
    for fname in files:
        r3 = adb_cmd(["shell","su","-c",
                      "cat {}/{}".format(prefs_dir, fname.strip())],
                     serial=serial, capture_output=True, text=True, timeout=15)
        content += "\n### {} ###\n{}".format(fname, r3.stdout)
    ask_save_report("shared_prefs_{}".format(package), content)
    log_session("Shared prefs dump: {}".format(package))
    _press_enter()

def _dump_sqlite_db():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = ask_package()
    if not package: _press_enter(); return
    db_dir = "/data/data/{}/databases".format(package)
    r = adb_cmd(["shell","su","-c","ls {}".format(db_dir)],
                serial=serial, capture_output=True, text=True, timeout=15)
    if not r.stdout.strip():
        warn("No databases found or root denied.")
        _press_enter(); return
    dbs = [f.strip() for f in r.stdout.strip().splitlines() if f.strip().endswith(".db")]
    ok("Found {} database(s):".format(len(dbs)))
    for db in dbs:
        print("  • {}{}{}".format(C, db, W))
    db_choice = input("{}→ Pull which DB (name or blank for all): {}".format(C, W)).strip()
    to_pull   = [db_choice] if db_choice else dbs
    for db in to_pull:
        src  = "{}/{}".format(db_dir, db)
        
        # Bug 6 Fix: Unique SQLite dump tmp filename
        tmp_name = "dh_tmp_{}.db".format(db.replace(".db","").replace("/","_").replace("\\","_"))
        tmp_path = f"/data/local/tmp/{tmp_name}"
        dest = "{}_{}.db".format(package, db.replace(".db",""))
        
        adb_cmd(["shell","su","-c",
                 "cp {} {} && chmod 777 {}".format(src, tmp_path, tmp_path)],
                serial=serial, timeout=15)
        adb_cmd(["pull", tmp_path, dest], serial=serial, timeout=30)
        adb_cmd(["shell","su","-c", "rm {}".format(tmp_path)], serial=serial, timeout=15)
        
        if os.path.isfile(dest):
            ok("Pulled → {} — open with DB Browser for SQLite".format(dest))
            log_session("SQLite dump: {}".format(dest))
        else:
            err("Pull failed for {}".format(db))
    _press_enter()

# ── Feature 4: Deep Link Extractor & Intent Fuzzer ────────────────────────────
def extract_deep_links(apk_path):
    links = []
    try:
        from androguard.core.bytecodes import apk as aapk
        a = aapk.APK(apk_path)
        manifest = a.get_android_manifest_xml()
        for intent in manifest.findall('.//intent-filter'):
            actions = [act.get('{http://schemas.android.com/apk/res/android}name') for act in intent.findall('action')]
            if 'android.intent.action.VIEW' in actions:
                data_elements = intent.findall('data')
                schemes = [d.get('{http://schemas.android.com/apk/res/android}scheme') for d in data_elements if d.get('{http://schemas.android.com/apk/res/android}scheme')]
                hosts = [d.get('{http://schemas.android.com/apk/res/android}host') for d in data_elements if d.get('{http://schemas.android.com/apk/res/android}host')]
                paths = [d.get('{http://schemas.android.com/apk/res/android}path') for d in data_elements if d.get('{http://schemas.android.com/apk/res/android}path')]
                path_prefixes = [d.get('{http://schemas.android.com/apk/res/android}pathPrefix') for d in data_elements if d.get('{http://schemas.android.com/apk/res/android}pathPrefix')]
                
                for scheme in schemes:
                    base = f"{scheme}://"
                    if hosts:
                        for host in hosts:
                            url = base + host
                            if paths:
                                for path in paths:
                                    links.append(url + path)
                            elif path_prefixes:
                                for pref in path_prefixes:
                                    links.append(url + pref)
                            else:
                                links.append(url)
                    else:
                        links.append(base)
    except Exception:
        aapt_bin = shutil.which("aapt") or shutil.which("aapt2")
        if aapt_bin:
            try:
                if "aapt2" in os.path.basename(aapt_bin).lower():
                    cmd = [aapt_bin, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path]
                else:
                    cmd = [aapt_bin, "dump", "xmltree", apk_path, "--file", "AndroidManifest.xml"]
                raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=30)
                schemes = re.findall(r'scheme="([^"]+)"', raw)
                hosts = re.findall(r'host="([^"]+)"', raw)
                for s in schemes:
                    if hosts:
                        for h in hosts:
                            links.append(f"{s}://{h}")
                    else:
                        links.append(f"{s}://")
            except Exception:
                pass
    return list(set(links))

def _deeplink_fuzzer():
    display_banner()
    print("{}[  Deep Link Extractor & Intent Fuzzer  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    package = ask_package()
    if not package: _press_enter(); return
        
    apk = input("{}→ Local APK path (to extract deep links) or blank: {}".format(C, W)).strip().strip('"').strip("'")
    links = []
    if apk and os.path.isfile(apk):
        info("Extracting deep links from APK manifest...")
        links = extract_deep_links(apk)
    else:
        info("No local APK provided. You can enter deep links manually.")
        while True:
            link = input("Enter a deep link (or blank to finish): ").strip()
            if not link:
                break
            links.append(link)
            
    if not links:
        warn("No deep links found or entered.")
        _press_enter()
        return
        
    print("\n{}Found/Entered Deep Links:{}".format(Y, W))
    for i, l in enumerate(links, 1):
        print("  {}. {}".format(i, l))
        
    ch = input("\n→ Enter index to fuzz (or 'all'): ").strip()
    target_links = []
    if ch.lower() == "all":
        target_links = links
    elif ch.isdigit() and 1 <= int(ch) <= len(links):
        target_links = [links[int(ch)-1]]
    else:
        err("Invalid choice.")
        _press_enter()
        return
        
    fuzzed_urls = []
    for l in target_links:
        base_url = l
        if "?" in l:
            base_url = l.split("?")[0]
        
        # Payloads
        fuzzed_urls.append(f"{base_url}?q=")
        fuzzed_urls.append(f"{base_url}?url=../../../../etc/passwd&file=../../../../etc/passwd")
        fuzzed_urls.append(f"{base_url}?q=%3Cscript%3Ealert(1)%3C/script%3E")
        fuzzed_urls.append(f"{base_url}?id=1%27%20OR%201=1")
        fuzzed_urls.append(f"{base_url}?id=0")
        fuzzed_urls.append(f"{base_url}?id=99999")
        
    info(f"Fuzzing target apps with {len(fuzzed_urls)} test intents...")
    tested_urls = []
    for i, url in enumerate(fuzzed_urls, 1):
        print(f"\n[{i}/{len(fuzzed_urls)}] Fuzzing URL: {url}")
        cmd = ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url, "-p", package]
        r = adb_cmd(cmd, serial=serial, capture_output=True, text=True, timeout=10)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tested_urls.append(f"[{ts}] URL: {url} | Result: {r.stdout.strip() or r.stderr.strip()}")
        print(f"  Result: {r.stdout.strip() or 'Launched (No output)'}")
        try:
            input("  Observe app behavior and press Enter for next test case...")
        except KeyboardInterrupt:
            break
        
    ask_save_report(f"deeplink_fuzz_{package}", "\n".join(tested_urls))
    log_session(f"Deep link fuzzed package {package}")
    _press_enter()

# ── Feature 5: Screenshot & Screen Record ─────────────────────────────────────
def _take_screenshot():
    display_banner()
    print("{}[  Take Screenshot  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    device_path = f"/sdcard/dh_screenshot_{ts}.png"
    local_filename = f"dh_screenshot_{ts}.png"
    local_path = os.path.join(REPORTS_DIR, local_filename)
    
    info("Capturing screenshot on device...")
    r1 = adb_cmd(["shell", "screencap", "-p", device_path], serial=serial, capture_output=True, text=True, timeout=15)
    if r1.returncode != 0:
        err(f"Screencap failed: {r1.stderr.strip()}")
        _press_enter()
        return
        
    info("Pulling screenshot to host...")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    r2 = adb_cmd(["pull", device_path, local_path], serial=serial, capture_output=True, text=True, timeout=15)
    
    adb_cmd(["shell", "rm", device_path], serial=serial, capture_output=True, text=True, timeout=15)
    
    if os.path.isfile(local_path):
        ok(f"Screenshot saved to: {local_path}")
        log_session(f"Captured screenshot: {local_filename}")
    else:
        err(f"Failed to pull screenshot. {r2.stderr.strip()}")
    _press_enter()

def _start_screenrecord():
    global RECORD_PROC
    display_banner()
    print("{}[  Screen Record Evidence  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    
    if RECORD_PROC:
        warn("A screen recording is already running in background.")
        _press_enter()
        return
        
    duration = input("Enter duration in seconds (1-180) [30]: ").strip() or "30"
    if not duration.isdigit() or not (1 <= int(duration) <= 180):
        err("Duration must be a number between 1 and 180.")
        _press_enter()
        return
        
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    device_path = f"/sdcard/dh_record_{ts}.mp4"
    
    info(f"Starting screen recording for {duration} seconds...")
    warn("Screenrecord might not be supported on all emulator builds.")
    
    cmd = [ADB] + (["-s", serial] if serial else []) + ["shell", "screenrecord", "--time-limit", duration, device_path]
    try:
        RECORD_PROC = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info(f"Recording running in background (PID {RECORD_PROC.pid})...")
        CONFIG["last_record_path"] = device_path
        CONFIG["last_record_ts"] = ts
        save_config()
    except Exception as e:
        err(f"Failed to start screenrecord: {e}")
    _press_enter()

def _stop_screenrecord():
    global RECORD_PROC
    display_banner()
    print("{}[  Stop Screen Recording  ]{}\n".format(C, W))
    if not _require_device(): return
    serial = select_device()
    
    if RECORD_PROC:
        info("Terminating recording process...")
        try:
            RECORD_PROC.terminate()
            RECORD_PROC.wait(timeout=5)
        except Exception:
            try:
                RECORD_PROC.kill()
            except Exception:
                pass
        RECORD_PROC = None
        ok("Recording stopped.")
        
    device_path = CONFIG.get("last_record_path")
    ts = CONFIG.get("last_record_ts")
    if not device_path or not ts:
        warn("No active or recent screen record path found.")
        _press_enter()
        return
        
    local_filename = f"dh_record_{ts}.mp4"
    local_path = os.path.join(REPORTS_DIR, local_filename)
    
    info("Retrieving recording from device...")
    time.sleep(2)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    r = adb_cmd(["pull", device_path, local_path], serial=serial, capture_output=True, text=True, timeout=60)
    
    adb_cmd(["shell", "rm", device_path], serial=serial, capture_output=True, text=True, timeout=15)
    
    if os.path.isfile(local_path):
        ok(f"Screen recording saved to: {local_path}")
        log_session(f"Captured screen recording: {local_filename}")
        CONFIG["last_record_path"] = ""
        CONFIG["last_record_ts"] = ""
        save_config()
    else:
        err(f"Failed to pull screen recording. {r.stderr.strip()}")
    _press_enter()

def menu_runtime_tampering():
    global RECORD_PROC
    while True:
        try:
            display_banner()
            print("{}[  Runtime App Tampering  ]{}\n".format(C, W))
            print("  1.  Start app with debugger (JDWP)")
            print("  2.  List running apps (PID + package)")
            print("  3.  Force-stop an app")
            print("  4.  Grant all dangerous permissions")
            print("  5.  Clear app data (reset state)")
            print("  6.  Monkey stress test (random UI events)")
            print("  7.  Launch exported activity directly")
            print("  8.  Send broadcast intent")
            print("  9.  Content provider query")
            print("  10. Dump shared preferences (root)")
            print("  11. Dump SQLite databases (root)")
            print("  12. Deep link extractor + fuzzer")
            print("  13. Take screenshot (evidence)")
            
            if RECORD_PROC and RECORD_PROC.poll() is not None:
                RECORD_PROC = None
            record_lbl = "Stop & Pull screen record" if (RECORD_PROC or CONFIG.get("last_record_path")) else "Start screen record"
            print("  14. {}".format(record_lbl))
            print("  15. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if   ch == "1":  _debug_launch()
            elif ch == "2":  _list_running()
            elif ch == "3":  _force_stop()
            elif ch == "4":  _grant_permissions()
            elif ch == "5":  _clear_data()
            elif ch == "6":  _monkey_test()
            elif ch == "7":  _launch_activity()
            elif ch == "8":  _send_broadcast()
            elif ch == "9":  _content_provider_query()
            elif ch == "10": _dump_shared_prefs()
            elif ch == "11": _dump_sqlite_db()
            elif ch == "12": _deeplink_fuzzer()
            elif ch == "13": _take_screenshot()
            elif ch == "14":
                if RECORD_PROC or CONFIG.get("last_record_path"):
                    _stop_screenrecord()
                else:
                    _start_screenrecord()
            elif ch == "15": break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 11 — Session Log & Reports
# ════════════════════════════════════════════════════════════════
def menu_generate_report():
    display_banner()
    print("{}[  Bug Bounty Report Template Generator  ]{}\n".format(C, W))
    
    app_name = input("App Name: ").strip()
    package = input(f"{C}→ Package name (e.g. com.example.app or leave blank if unknown): {W}").strip()
    if package and not validate_package(package):
        warn("Package name format looks unusual but continuing anyway.")
        
    version = input("App Version: ").strip()
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    title = input("Vulnerability Title: ").strip()
    severity = input("Severity (Critical/High/Medium/Low/Info) [Medium]: ").strip() or "Medium"
    cwe = input("CWE Number (e.g. CWE-94): ").strip()
    summary = input("Summary of findings: ").strip()
    steps = []
    print("\nEnter Steps to Reproduce (press Enter on empty line to finish):")
    idx = 1
    while True:
        try:
            step = input(f"Step {idx}: ").strip()
            if not step:
                break
            steps.append(f"{idx}. {step}")
            idx += 1
        except KeyboardInterrupt:
            break
        
    impact = input("Business/Security Impact: ").strip()
    remediation = input("Remediation / How to Fix: ").strip()
    
    steps_str = "\n".join(steps)
    md_content = f"""## {title}

**Severity:** {severity}  
**CWE:** {cwe}  
**Package:** {package}  
**Tested On:** {date_str}

### Summary
{summary}

### Steps to Reproduce
{steps_str}

### Impact
{impact}

### Remediation
{remediation}
"""
    
    path_md = save_report(f"bugbounty_{app_name.replace(' ', '_')}", md_content, fmt="md")
    path_txt = save_report(f"bugbounty_{app_name.replace(' ', '_')}", md_content, fmt="txt")
    
    ok("Bug bounty templates generated successfully!")
    print(f"  Markdown template: {path_md}")
    print(f"  Plain-text template: {path_txt}")
    print("\nReady to copy & paste into HackerOne / Bugcrowd!")
    _press_enter()

def menu_session_log():
    while True:
        try:
            display_banner()
            print("{}[  Session Log & Reports  ]{}\n".format(C, W))
            print("  1. View session log")
            print("  2. Save session log to file")
            print("  3. List saved reports")
            print("  4. Generate Bug Bounty Report Template")
            print("  5. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if ch == "1":
                display_banner()
                if SESSION_LOG:
                    for entry in SESSION_LOG:
                        print("  {}".format(entry))
                else:
                    warn("Nothing logged yet this session.")
                _press_enter()
            elif ch == "2":
                if SESSION_LOG:
                    ask_save_report("session_log", "\n".join(SESSION_LOG))
                else:
                    warn("Nothing to save.")
                _press_enter()
            elif ch == "3":
                display_banner()
                if os.path.isdir(REPORTS_DIR):
                    files = sorted(os.listdir(REPORTS_DIR))
                    if files:
                        print("{}Reports in {}/{}".format(C, REPORTS_DIR, W))
                        for f in files:
                            sz = os.path.getsize(os.path.join(REPORTS_DIR, f))
                            print("  {} ({} bytes)".format(f, sz))
                    else:
                        warn("No reports saved yet.")
                else:
                    warn("Reports directory does not exist yet.")
                _press_enter()
            elif ch == "4":
                menu_generate_report()
            elif ch == "5":
                break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MENU 12 — Settings
# ════════════════════════════════════════════════════════════════
def menu_settings():
    while True:
        try:
            display_banner()
            print("{}[  Settings & Configuration  ]{}\n".format(C, W))
            print("  1. View Current Configuration")
            print("  2. Edit Proxy Settings (Host & Port)")
            print("  3. Edit MobSF Settings (URL & API Key)")
            print("  4. Change Default Report Format (txt/md/html)")
            print("  5. Change Reports Directory")
            print("  6. Clear Saved Device Serial")
            print("  7. Back\n")
            ch = input("{}→ Choose: {}".format(C, W)).strip()
            if ch == "1":
                display_banner()
                print("{}[ Current Config ]{}\n".format(C, W))
                for k, v in CONFIG.items():
                    print("  {:<25}: {}".format(k, v))
                _press_enter()
            elif ch == "2":
                host = input(f"Enter Proxy Host [{CONFIG['proxy_host']}]: ").strip() or CONFIG["proxy_host"]
                port = input(f"Enter Proxy Port [{CONFIG['proxy_port']}]: ").strip() or CONFIG["proxy_port"]
                CONFIG["proxy_host"] = host
                CONFIG["proxy_port"] = port
                save_config()
                ok("Proxy settings updated.")
                _press_enter()
            elif ch == "3":
                url = input(f"Enter MobSF URL [{CONFIG['mobsf_url']}]: ").strip() or CONFIG["mobsf_url"]
                key = input(f"Enter MobSF API Key [{CONFIG['mobsf_api_key']}]: ").strip() or CONFIG["mobsf_api_key"]
                CONFIG["mobsf_url"] = url
                CONFIG["mobsf_api_key"] = key
                save_config()
                ok("MobSF settings updated.")
                _press_enter()
            elif ch == "4":
                fmt = input(f"Enter Default Report Format (txt/md/html) [{CONFIG['default_report_format']}]: ").strip().lower()
                if fmt in ("txt", "md", "html"):
                    CONFIG["default_report_format"] = fmt
                    save_config()
                    ok("Default report format updated.")
                else:
                    err("Invalid format. Choose txt, md, or html.")
                _press_enter()
            elif ch == "5":
                rdir = input(f"Enter Reports Directory [{CONFIG['reports_dir']}]: ").strip() or CONFIG["reports_dir"]
                CONFIG["reports_dir"] = rdir
                global REPORTS_DIR
                REPORTS_DIR = rdir
                save_config()
                ok("Reports directory updated.")
                _press_enter()
            elif ch == "6":
                CONFIG["preferred_serial"] = ""
                save_config()
                ok("Saved device serial cleared.")
                _press_enter()
            elif ch == "7":
                break
        except KeyboardInterrupt:
            print("\n  Returning to Main Menu...")
            time.sleep(0.5)
            break

# ════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════
def display_main_menu():
    MENU = [
        ("1",  "Create Virtual Device",                                  ""),
        ("2",  "Root Emulator  (Magisk + rootAVD)",                      ""),
        ("3",  "Install Tools",                                           ""),
        ("4",  "Configure Emulator  (Frida server, Burp cert, proxy)",   ""),
        ("5",  "Run Frida Server",                                        ""),
        ("6",  "Frida Tools  (SSL/root bypass · objection · REPL · trace)",""),
        ("7",  "APK Analysis  (decode · secrets · manifest · pull · sign)",""),
        ("8",  "Traffic & Proxy Tools",                                   ""),
        ("9",  "Device Info",                                             ""),
        ("10", "Runtime App Tampering  (sharedPrefs · SQLite · intents)",""),
        ("11", "Session Log & Reports",                                   ""),
        ("12", "Settings & Configuration",                                "[NEW]"),
        ("13", "Exit",                                                    ""),
    ]
    while True:
        try:
            display_banner()
            print("{}  Main Menu:{}\n".format(C, W))
            for num, label, tag in MENU:
                tag_str = "  {}{}{}".format(G, tag, W) if tag else ""
                print("  {}{:>3}.{}  {}{}".format(C, num, W, label, tag_str))
            print()
            ch = input("{}→ Choose: {}".format(G, W)).strip()
            if   ch == "1":  menu_create_avd()
            elif ch == "2":  menu_root_emulator()
            elif ch == "3":  menu_install_tools()
            elif ch == "4":  menu_configure_emulator()
            elif ch == "5":  menu_run_frida_server()
            elif ch == "6":  menu_frida_tools()
            elif ch == "7":  menu_apk_analysis()
            elif ch == "8":  menu_traffic_proxy()
            elif ch == "9":  menu_device_info()
            elif ch == "10": menu_runtime_tampering()
            elif ch == "11": menu_session_log()
            elif ch == "12": menu_settings()
            elif ch == "13":
                display_banner()
                if SESSION_LOG:
                    try:
                        if input("{}→ Save session log before exit? (y/n): {}".format(Y, W)).strip().lower() == "y":
                            save_report("session_final", "\n".join(SESSION_LOG))
                    except KeyboardInterrupt:
                        pass
                print("{}  DroidHawk — by {}  |  Stay sharp! ✓{}".format(G, TOOL_AUTHOR, W))
                break
            else:
                err("Invalid choice — enter a number from the menu.")
                time.sleep(0.4)
        except KeyboardInterrupt:
            print("\n")
            try:
                if input("{}→ Exit DroidHawk? (y/n): {}".format(Y, W)).strip().lower() == "y":
                    if SESSION_LOG:
                        if input("{}→ Save session log before exit? (y/n): {}".format(Y, W)).strip().lower() == "y":
                            save_report("session_final", "\n".join(SESSION_LOG))
                    print("{}  DroidHawk — by {}  |  Stay sharp! ✓{}".format(G, TOOL_AUTHOR, W))
                    break
            except KeyboardInterrupt:
                print("\n  Exiting immediately.")
                break

# ── Entry Point ───────────────────────────────────────────────────────────────
def parse_args():
    global ARGS
    parser = argparse.ArgumentParser(description="DroidHawk — Android Bug Bounty Automation")
    parser.add_argument("--skip-checks", action="store_true", help="Skip environment check on startup")
    parser.add_argument("--no-banner", action="store_true", help="Skip startup animation")
    parser.add_argument("--serial", help="Pre-select ADB device serial (skip device selector)")
    parser.add_argument("--report-dir", help="Override default DroidHawk_Reports directory")
    ARGS = parser.parse_args()

if __name__ == "__main__":
    load_config()
    parse_args()
    
    if ARGS and ARGS.report_dir:
        REPORTS_DIR = ARGS.report_dir
        CONFIG["reports_dir"] = ARGS.report_dir
        
    startup_animation()
    initial_environment_check()
    display_main_menu()
