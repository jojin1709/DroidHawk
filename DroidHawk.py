#!/usr/bin/env python3
"""
DroidHawk - Android Bug Bounty Automation Tool
Made by Jojin John
For authorized penetration testing only.
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

# ── Globals ───────────────────────────────────────────────────────────────────
TOOL_NAME    = "DroidHawk"
TOOL_VERSION = "v3.0"
TOOL_AUTHOR  = "Jojin John"
REPORTS_DIR  = "DroidHawk_Reports"
SESSION_LOG  = []
custom_scripts = []

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[1;31m"   # red
G  = "\033[1;32m"   # green
Y  = "\033[1;33m"   # yellow
C  = "\033[1;36m"   # cyan
M  = "\033[1;35m"   # magenta
B  = "\033[1;34m"   # blue
W  = "\033[0m"      # reset

def ok(msg):   print("{}[✓] {}{}".format(G, msg, W))
def err(msg):  print("{}[✗] {}{}".format(R, msg, W))
def info(msg): print("{}[*] {}{}".format(C, msg, W))
def warn(msg): print("{}[!] {}{}".format(Y, msg, W))

def log_session(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    SESSION_LOG.append("[{}] {}".format(ts, msg))

def save_report(name, content):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, "{}_{}.txt".format(name, ts))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=" * 60 + "\n")
        fh.write("{} Report — {}\n".format(TOOL_NAME, datetime.datetime.now()))
        fh.write("Made by {}\n".format(TOOL_AUTHOR))
        fh.write("=" * 60 + "\n\n")
        fh.write(content)
    ok("Report saved → {}".format(path))
    return path

def _get_rq():
    if not HAS_REQUESTS:
        err("requests not installed. Run: pip install requests")
        return None
    import requests as rq
    return rq

# ── ASCII banner & animations ─────────────────────────────────────────────────
LOGO = r"""
  ____            _     _ _   _                 _
 |  _ \ _ __ ___ (_) __| | | | |__ __ ___      _| | __
 | | | | '__/ _ \| |/ _` | |_| '_ \ \ \ /\ / / | |/ /
 | |_| | | | (_) | | (_| |  _| | | |\ V  V /| |   <
 |____/|_|  \___/|_|\__,_|_| |_| |_| \_/\_/ |_|_|\_\
"""

def startup_animation():
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
        "{} device(s) connected".format(dev_count) if dev_count else "No device connected",
        W)
    os.system("cls" if IS_WINDOWS else "clear")
    print(R + LOGO + W)
    print("  {}{}  {}  | Made by {}{}".format(M, TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, W))
    print("  {}Android Bug Bounty Automation — Authorized Testing Only{}".format(Y, W))
    print("  {}Platform: {} {}  |  {}{}".format(B, platform.system(), platform.release(), dev_str, W))
    print()

# ── Environment checks ────────────────────────────────────────────────────────
def initial_environment_check():
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
        if input("{}→ Continue anyway? (y/n): {}".format(C, W)).strip().lower() != "y":
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
                                      stderr=subprocess.DEVNULL).splitlines()[0]
        return True, ver
    except Exception:
        return True, "found"

def _chk_frida():
    if not shutil.which("frida"):
        return False, "pip install frida-tools"
    try:
        ver = subprocess.check_output(["frida","--version"], text=True,
                                      stderr=subprocess.DEVNULL).strip()
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

# ── ADB helpers ───────────────────────────────────────────────────────────────
ADB = "adb"

def get_connected_devices():
    try:
        out = subprocess.check_output([ADB,"devices"], text=True, stderr=subprocess.DEVNULL)
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
    devs = get_connected_devices()
    if not devs:
        return None
    if len(devs) == 1:
        return devs[0]
    print("{}Multiple devices:{}".format(C, W))
    for i, d in enumerate(devs, 1):
        print("  {}. {}".format(i, d))
    try:
        return devs[int(input("{}→ Select device #: {}".format(C, W)).strip()) - 1]
    except (ValueError, IndexError):
        return devs[0]

def adb_cmd(args, serial=None, **kwargs):
    base = [ADB] + (["-s", serial] if serial else [])
    return subprocess.run(base + args, **kwargs)

def adb_shell(cmd_list, serial=None):
    r = adb_cmd(["shell"] + cmd_list, serial=serial, capture_output=True, text=True)
    return r.stdout.strip()

# ── Tool installer helpers ────────────────────────────────────────────────────
def is_tool_installed(tool):
    if tool == "frida-tools":
        return bool(shutil.which("frida"))
    try:
        return subprocess.run([sys.executable, "-m", "pip", "show", tool],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False

def pip_install(tool):
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool])

def load_custom_scripts():
    global custom_scripts
    custom_scripts = []
    default_set = {"SSL-BYE.js", "ROOTER.js", "PintooR.js"}
    if os.path.exists("./Fripts"):
        for fname in sorted(os.listdir("./Fripts")):
            if fname.endswith(".js") and fname not in default_set:
                name = os.path.splitext(fname)[0]
                custom_scripts.append((name, os.path.join("./Fripts", fname)))

def _press_enter():
    input("\n{}→ Press Enter to continue ...{}".format(C, W))

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
        try:
            resp = rq.get("https://api.github.com/repos/topjohnwu/Magisk/releases/latest",
                          timeout=10)
            resp.raise_for_status()
            magisk_ver  = resp.json()["tag_name"]
            magisk_file = "Magisk-{}.apk".format(magisk_ver)
            magisk_url  = ("https://github.com/topjohnwu/Magisk/releases/download/"
                           "{}/{}".format(magisk_ver, magisk_file))
        except Exception as e:
            warn("GitHub lookup failed ({}), falling back to v30.0".format(e))
            magisk_ver  = "v30.0"
            magisk_file = "Magisk-v30.0.apk"
            magisk_url  = ("https://github.com/topjohnwu/Magisk/releases/download/"
                           "{}/{}".format(magisk_ver, magisk_file))
        if not os.path.exists(magisk_file):
            info("Downloading {} ...".format(magisk_file))
            data = rq.get(magisk_url, timeout=180)
            data.raise_for_status()
            open(magisk_file, "wb").write(data.content)
        ok("Magisk {} ready".format(magisk_ver))

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
            open(rAVD_zip, "wb").write(data.content)
        if not os.path.isdir(rAVD_dir):
            with zipfile.ZipFile(rAVD_zip) as z:
                z.extractall(rAVD_dir)
        ok("rootAVD ready")

        bat_dir = os.path.join(rAVD_dir, "rootAVD-master")

        if IS_WINDOWS:
            # List images
            info("Listing available system images ...")
            cwd = os.getcwd(); os.chdir(bat_dir)
            res = subprocess.run('cmd /c "rootAVD.bat ListAllAVDs"',
                                 shell=True, capture_output=True, text=True)
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
            cwd = os.getcwd(); os.chdir(bat_dir)
            res = subprocess.run('cmd /c ".\\rootAVD.bat {}"'.format(img_path),
                                 shell=True, capture_output=True, text=True)
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
                pip_install(t); ok("{} installed.".format(t))
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
                        pip_install(t); ok(t)
                    except Exception as e:
                        err("{}: {}".format(t, e))
            _press_enter()
        elif c == len(TOOLS)+2:
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
            ["frida","--version"], text=True, stderr=subprocess.DEVNULL).strip()
        ok("Host frida-tools: {}".format(frida_ver))
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
        import lzma
        info("Extracting ...")
        with lzma.open(xz) as fin, open(out, "wb") as fout:
            fout.write(fin.read())
        ok("Extracted: {}".format(out))
        info("Pushing to /data/local/tmp/frida-server ...")
        adb_cmd(["push", out, "/data/local/tmp/frida-server"], serial=serial, check=True)
        adb_cmd(["shell", "chmod", "+x", "/data/local/tmp/frida-server"], serial=serial, check=True)
        ok("Frida server installed! ✓")
        print("{}  Start it: adb shell su -c '/data/local/tmp/frida-server &'{}".format(M, W))
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
        open("cacert.der", "wb").write(cert_bytes)
        if HAS_OPENSSL:
            from OpenSSL import crypto as ssl_c
            cert = ssl_c.load_certificate(ssl_c.FILETYPE_ASN1, cert_bytes)
            pem  = ssl_c.dump_certificate(ssl_c.FILETYPE_PEM, cert)
            open("portswigger.crt", "wb").write(pem)
        else:
            shutil.copy("cacert.der", "portswigger.crt")
        ok("Certificate downloaded & converted")

        adb_cmd(["push", "portswigger.crt", "/sdcard/portswigger.crt"],
                serial=serial, check=True)
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
            open(mod_file, "wb").write(data.content)
        ok("Module {} ready".format(mod_ver))

        adb_cmd(["push", mod_file, "/data/local/tmp/"+mod_file], serial=serial, check=True)
        adb_cmd(["shell","su","-c",
                 "magisk --install-module /data/local/tmp/{}".format(mod_file)],
                serial=serial, check=True)
        ok("Magisk module installed")

        warn("Now: Settings → Security → Install cert → CA → /sdcard/portswigger.crt")
        warn("Waiting 60 s for manual install ...")
        for i in range(60, 0, -1):
            print("\r{}  {}s ...{}".format(C, i, W), end="", flush=True)
            time.sleep(1)
        print()
        adb_cmd(["reboot"], serial=serial)
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
            serial=serial)
    adb_cmd(["reverse","tcp:{}".format(port),"tcp:{}".format(port)], serial=serial)
    ok("Proxy → 127.0.0.1:{} | adb reverse configured".format(port))
    _press_enter()

def menu_configure_emulator():
    while True:
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

# ════════════════════════════════════════════════════════════════
#  MENU 5 — Run Frida Server
# ════════════════════════════════════════════════════════════════
def menu_run_frida_server():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    info("Killing any old frida-server instance ...")
    adb_cmd(["shell","su","-c","pkill -f frida-server"], serial=serial,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    base = [ADB]+(["-s",serial] if serial else [])
    subprocess.Popen(base+["shell",'su -c "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"'])
    time.sleep(3)
    r = adb_cmd(["shell","su","-c","pgrep -f frida-server"],
                serial=serial, capture_output=True, text=True)
    if r.stdout.strip():
        ok("Frida server running — PID {}".format(r.stdout.strip()))
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
            ln = input()
            if ln == "" and lines and lines[-1] == "":
                break
            lines.append(ln)
        code = "\n".join(lines[:-1] if lines and lines[-1]=="" else lines)
        name = input("{}Script name (no spaces): {}".format(C, W)).strip()
    elif mode == "2":
        path = input("{}Full path to .js: {}".format(C, W)).strip().strip('"').strip("'")
        if not os.path.isfile(path):
            err("Not found: {}".format(path)); _press_enter(); return
        code = open(path,"r",encoding="utf-8").read()
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
    open(spath,"w",encoding="utf-8").write(code)
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
            try: os.remove(p); ok("Deleted '{}'".format(n))
            except Exception as e: err(str(e))
    _press_enter()

def _objection_launch():
    display_banner()
    if not shutil.which("objection"):
        err("objection not installed — run: pip install objection"); _press_enter(); return
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
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
    package = input("{}→ Package name or PID: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
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
    package = input("{}→ Package name: {}".format(C, W)).strip()
    pattern = input("{}→ Method pattern (e.g. *ssl* or recv*): {}".format(C, W)).strip()
    if not package or not pattern:
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
            package = input("{}→ Package name (e.g. com.example.app): {}".format(C, W)).strip()
            if not package: err("Cannot be empty."); _press_enter(); continue
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
            package = input("{}→ Package name: {}".format(C, W)).strip()
            if not package: err("Cannot be empty."); _press_enter(); continue
            _frida_run_script(package, cp, cn, serial)
            _press_enter()

        elif ch == str(back_n): break
        else:
            err("Invalid choice."); time.sleep(0.4)

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
    subprocess.run(["apktool","d","-f","-o",out,apk])
    ok("Output → {}".format(out))
    log_session("Decoded: {}".format(apk))
    _press_enter()

def _apk_secrets():
    display_banner()
    if not shutil.which("apkleaks"):
        warn("apkleaks not installed → pip install apkleaks"); _press_enter(); return
    apk = _ask_apk()
    if not apk: _press_enter(); return
    rpt = os.path.splitext(apk)[0] + "_secrets.json"
    info("Scanning for secrets ...")
    subprocess.run(["apkleaks","-f",apk,"-o",rpt])
    if os.path.isfile(rpt):
        ok("Report → {}".format(rpt))
        try:
            data = json.load(open(rpt))
            hits = [(k,v) for k,v in data.items() if v]
            if hits:
                print("\n{}Top findings:{}".format(Y, W))
                for k,v in hits[:10]:
                    print("  {}{}{}: {}".format(C, k, W, v[:3] if isinstance(v,list) else v))
        except Exception: pass
    log_session("Secrets scan: {}".format(apk))
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
        out = subprocess.check_output([aapt,"dump","xmltree",apk,"--file","AndroidManifest.xml"],
                                      text=True, stderr=subprocess.DEVNULL)
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
        if aapt:
            raw = subprocess.check_output(
                [aapt,"dump","xmltree",apk,"--file","AndroidManifest.xml"],
                text=True, stderr=subprocess.DEVNULL)
        else:
            with zipfile.ZipFile(apk) as z:
                raw = z.read("AndroidManifest.xml").decode("utf-8", errors="replace")
        lines = raw.splitlines()

        if any("debuggable" in l.lower() and "true" in l.lower() for l in lines):
            warn("DEBUGGABLE — attacker can attach debugger / run arbitrary code!")
            findings.append("CRITICAL: android:debuggable=true")

        if any("allowBackup" in l and "true" in l.lower() for l in lines):
            warn("allowBackup=true — data extractable via adb backup!")
            findings.append("HIGH: android:allowBackup=true")

        if any("usesCleartextTraffic" in l and "true" in l.lower() for l in lines):
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

        if input("\n{}→ Save report? (y/n): {}".format(C, W)).strip().lower() == "y":
            save_report("manifest_{}".format(os.path.basename(apk)),
                        "\n".join(findings) or "No issues found.")
        log_session("Manifest analysis: {}".format(apk))
    except Exception as e: err(str(e))
    _press_enter()

def _pull_apk():
    display_banner()
    print("{}[  Pull APK from Device  ]{}\n".format(C, W))
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name (e.g. com.example.app): {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    info("Finding APK path on device ...")
    r = adb_cmd(["shell","pm","path",package], serial=serial, capture_output=True, text=True)
    if "package:" not in r.stdout:
        err("Package not found: {}".format(package)); _press_enter(); return
    apk_on_device = r.stdout.strip().replace("package:","")
    ok("APK on device: {}".format(apk_on_device))
    out = "{}.apk".format(package)
    adb_cmd(["pull", apk_on_device, out], serial=serial)
    if os.path.isfile(out):
        ok("Pulled → {} ({:.1f} MB)".format(out, os.path.getsize(out)/1024/1024))
        log_session("Pulled APK: {}".format(package))
    else:
        err("Pull failed.")
    _press_enter()

def _repack_sign():
    display_banner()
    print("{}[  Repack & Sign APK  ]{}\n".format(C, W))
    if not shutil.which("apktool"):
        warn("apktool not found → https://apktool.org/"); _press_enter(); return
    d = input("{}→ Decoded APK directory: {}".format(C, W)).strip().strip('"')
    if not os.path.isdir(d): err("Directory not found."); _press_enter(); return
    out = d.rstrip("/\\") + "_repacked.apk"
    info("Building with apktool ...")
    r = subprocess.run(["apktool","b","-o",out,d], capture_output=True, text=True)
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
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if shutil.which("apksigner") and os.path.isfile(ks):
        signed = out.replace(".apk","_signed.apk")
        subprocess.run(["apksigner","sign","--ks",ks,
                        "--ks-pass","pass:android","--key-pass","pass:android",
                        "--out",signed, out])
        if os.path.isfile(signed):
            ok("Signed APK → {}".format(signed))
            log_session("Repack+sign: {}".format(signed))
        else:
            warn("Signing failed — install manually: adb install -r {}".format(out))
    else:
        warn("apksigner not found — sign manually with apksigner.")
    _press_enter()

def _strings_grep():
    display_banner()
    print("{}[  Sensitive Data Grep  ]{}\n".format(C, W))
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
    walk_it  = os.walk(target) if os.path.isdir(target) else [(os.path.dirname(target),[],[os.path.basename(target)])]
    for root, _, files in walk_it:
        for fname in files:
            if not any(fname.endswith(e) for e in EXTS): continue
            fp = os.path.join(root, fname)
            scanned += 1
            try:
                content = open(fp,"r",encoding="utf-8",errors="replace").read()
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
    if input("\n{}→ Save report? (y/n): {}".format(C, W)).strip().lower() == "y":
        txt = ""
        for label, hits in results.items():
            txt += "\n[{}]\n".format(label)
            for fp, match in hits:
                txt += "  {} → {}\n".format(fp, match)
        save_report("strings_grep", txt or "No findings.")
    log_session("Strings grep on: {}".format(target))
    _press_enter()

def _permissions_audit():
    display_banner()
    print("{}[  App Permissions Audit  ]{}\n".format(C, W))
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    info("Fetching permission grants for {} ...".format(package))
    r = adb_cmd(["shell","dumpsys","package",package], serial=serial, capture_output=True, text=True)
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
    if input("\n{}→ Save? (y/n): {}".format(C, W)).strip().lower() == "y":
        save_report("permissions_{}".format(package),
                    "Package: {}\nGranted:{}\nDenied:{}\n\nDangerous:\n{}".format(
                        package,len(granted),len(denied),"\n".join(danger)))
    log_session("Permissions audit: {}".format(package))
    _press_enter()

def menu_apk_analysis():
    while True:
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
        print("  10. Back\n")
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
        elif ch == "10": break

# ════════════════════════════════════════════════════════════════
#  MENU 8 — Traffic & Proxy
# ════════════════════════════════════════════════════════════════
def _set_proxy():
    if not _require_device(): return
    serial = select_device()
    host   = input("{}→ Proxy host [127.0.0.1]: {}".format(C, W)).strip() or "127.0.0.1"
    port   = input("{}→ Proxy port [8080]: {}".format(C, W)).strip() or "8080"
    adb_cmd(["shell","settings","put","global","http_proxy","{}:{}".format(host,port)],
            serial=serial)
    ok("Proxy set → {}:{}".format(host, port))
    _press_enter()

def _clear_proxy():
    if not _require_device(): return
    serial = select_device()
    adb_cmd(["shell","settings","put","global","http_proxy",":0"], serial=serial)
    adb_cmd(["shell","settings","delete","global","http_proxy"], serial=serial)
    ok("Proxy cleared.")
    _press_enter()

def _check_proxy():
    if not _require_device(): return
    serial = select_device()
    r = adb_cmd(["shell","settings","get","global","http_proxy"],
                serial=serial, capture_output=True, text=True)
    val = r.stdout.strip()
    print("{}Current proxy: {}{}".format(C, val or "(not set)", W))
    _press_enter()

def _adb_reverse():
    if not _require_device(): return
    serial = select_device()
    port   = input("{}→ Port [8080]: {}".format(C, W)).strip() or "8080"
    adb_cmd(["reverse","tcp:{}".format(port),"tcp:{}".format(port)], serial=serial)
    ok("adb reverse: device:{} → host:{}".format(port, port))
    _press_enter()

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
    try:
        proc  = subprocess.Popen(base+["logcat","-v","brief"],
                                 stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)
        start = time.time()
        while time.time()-start < duration:
            line = proc.stdout.readline()
            if not line: break
            if "http://" in line and (not pkg_flt or pkg_flt in line):
                hits.append(line.strip())
                print("  {}{}{}".format(Y, line.strip()[:120], W))
        proc.terminate()
    except KeyboardInterrupt: pass
    if hits:
        warn("{} cleartext HTTP request(s) found!".format(len(hits)))
        if input("{}→ Save? (y/n): {}".format(C, W)).strip().lower() == "y":
            save_report("cleartext_http", "\n".join(hits))
    else:
        ok("No cleartext HTTP detected during monitoring.")
    _press_enter()

def _net_info():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    info("Open connections (netstat / ss):")
    r = adb_cmd(["shell","su","-c","netstat -tuln 2>/dev/null || ss -tuln"],
                serial=serial, capture_output=True, text=True)
    print(r.stdout or "  (no output — root required)")
    info("Network interfaces (ip addr):")
    r2 = adb_cmd(["shell","ip","addr"], serial=serial, capture_output=True, text=True)
    print(r2.stdout)
    _press_enter()

def menu_traffic_proxy():
    while True:
        display_banner()
        print("{}[  Traffic & Proxy Tools  ]{}\n".format(C, W))
        print("  1. Set emulator proxy")
        print("  2. Clear emulator proxy")
        print("  3. Check proxy settings")
        print("  4. adb reverse (port-forward to host)")
        print("  5. Monitor cleartext HTTP traffic (logcat)")
        print("  6. Network info (connections & interfaces)")
        print("  7. Back\n")
        ch = input("{}→ Choose: {}".format(C, W)).strip()
        if   ch == "1": _set_proxy()
        elif ch == "2": _clear_proxy()
        elif ch == "3": _check_proxy()
        elif ch == "4": _adb_reverse()
        elif ch == "5": _cleartext_monitor()
        elif ch == "6": _net_info()
        elif ch == "7": break

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
                   serial=serial, capture_output=True, text=True)
    fs_st = "{}RUNNING (PID {}){}".format(G,r_fs.stdout.strip(),W) if r_fs.stdout.strip() \
            else "{}STOPPED{}".format(R,W)
    print("  {}{:<25}{} {}".format(C,"Frida Server",W, fs_st))

    # Disk space
    r_disk = adb_cmd(["shell","df","/data"], serial=serial, capture_output=True, text=True)
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
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    r = adb_cmd(["shell","cmd","package","resolve-activity","--brief",
                 "-a","android.intent.action.MAIN",
                 "-c","android.intent.category.LAUNCHER", package],
                serial=serial, capture_output=True, text=True)
    activity = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "{}/MainActivity".format(package)
    info("Launching {} in debug mode (-D) ...".format(activity))
    adb_cmd(["shell","am","start","-D","-n",activity], serial=serial)
    ok("Launched — waiting for debugger attach.")
    print("{}  Attach: adb forward tcp:8700 jdwp:<pid> && jdb -attach localhost:8700{}".format(M,W))
    _press_enter()

def _list_running():
    display_banner()
    if not _require_device(): return
    serial = select_device()
    r = adb_cmd(["shell","ps","-A"], serial=serial, capture_output=True, text=True)
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
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    adb_cmd(["shell","am","force-stop",package], serial=serial)
    ok("Force-stopped {}".format(package))
    _press_enter()

def _grant_permissions():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
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
                    serial=serial, capture_output=True, text=True)
        if r.returncode == 0:
            granted += 1
            print("  {}✓  {}{}".format(G, p.split(".")[-1], W))
    ok("Granted {}/{} permissions.".format(granted, len(PERMS)))
    _press_enter()

def _clear_data():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    if input("{}→ Clear ALL data for {}? (y/n): {}".format(Y,package,W)).strip().lower() == "y":
        adb_cmd(["shell","pm","clear",package], serial=serial)
        ok("Data cleared for {}.".format(package))
        log_session("Cleared data: {}".format(package))
    _press_enter()

def _monkey_test():
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    events  = input("{}→ Event count [500]: {}".format(C, W)).strip() or "500"
    if not package: err("Cannot be empty."); _press_enter(); return
    info("Monkey testing '{}' with {} events — Ctrl+C to stop.".format(package, events))
    try:
        adb_cmd(["shell","monkey","-p",package,"-v","--throttle","100",events],
                serial=serial)
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
    r = adb_cmd(cmd, serial=serial, capture_output=True, text=True)
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
    r = adb_cmd(cmd, serial=serial, capture_output=True, text=True)
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
                serial=serial, capture_output=True, text=True)
    if r.stdout.strip():
        ok("Results:")
        print(r.stdout[:4000])
    else:
        warn("No results — access denied or empty table.")
        if r.stderr: print(r.stderr[:300])
    _press_enter()

def _dump_shared_prefs():
    """Dump shared preferences files of an app (requires root)."""
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    info("Reading shared_prefs for {} (requires root) ...".format(package))
    prefs_dir = "/data/data/{}/shared_prefs".format(package)
    r = adb_cmd(["shell","su","-c","ls {}".format(prefs_dir)],
                serial=serial, capture_output=True, text=True)
    if not r.stdout.strip():
        warn("No shared_prefs found or root denied.")
        _press_enter(); return
    files = r.stdout.strip().splitlines()
    ok("Found {} shared_prefs file(s):".format(len(files)))
    for fname in files:
        print("\n  {}{}{}".format(Y, fname, W))
        r2 = adb_cmd(["shell","su","-c",
                      "cat {}/{}".format(prefs_dir, fname.strip())],
                     serial=serial, capture_output=True, text=True)
        print(r2.stdout[:2000])
    if input("\n{}→ Save? (y/n): {}".format(C, W)).strip().lower() == "y":
        content = ""
        for fname in files:
            r3 = adb_cmd(["shell","su","-c",
                          "cat {}/{}".format(prefs_dir, fname.strip())],
                         serial=serial, capture_output=True, text=True)
            content += "\n### {} ###\n{}".format(fname, r3.stdout)
        save_report("shared_prefs_{}".format(package), content)
    log_session("Shared prefs dump: {}".format(package))
    _press_enter()

def _dump_sqlite_db():
    """Dump SQLite databases of an app (requires root)."""
    display_banner()
    if not _require_device(): return
    serial  = select_device()
    package = input("{}→ Package name: {}".format(C, W)).strip()
    if not package: err("Cannot be empty."); _press_enter(); return
    db_dir = "/data/data/{}/databases".format(package)
    r = adb_cmd(["shell","su","-c","ls {}".format(db_dir)],
                serial=serial, capture_output=True, text=True)
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
        dest = "{}_{}.db".format(package, db.replace(".db",""))
        # copy out of restricted dir first
        adb_cmd(["shell","su","-c",
                 "cp {} /data/local/tmp/dh_tmp.db && chmod 777 /data/local/tmp/dh_tmp.db".format(src)],
                serial=serial)
        adb_cmd(["pull","/data/local/tmp/dh_tmp.db", dest], serial=serial)
        if os.path.isfile(dest):
            ok("Pulled → {} — open with DB Browser for SQLite".format(dest))
            log_session("SQLite dump: {}".format(dest))
        else:
            err("Pull failed for {}".format(db))
    _press_enter()

def menu_runtime_tampering():
    while True:
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
        print("  12. Back\n")
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
        elif ch == "12": break

# ════════════════════════════════════════════════════════════════
#  MENU 11 — Session Log & Reports
# ════════════════════════════════════════════════════════════════
def menu_session_log():
    while True:
        display_banner()
        print("{}[  Session Log & Reports  ]{}\n".format(C, W))
        print("  1. View session log")
        print("  2. Save session log to file")
        print("  3. List saved reports")
        print("  4. Back\n")
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
                save_report("session_log", "\n".join(SESSION_LOG))
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
        ("10", "Runtime App Tampering  (sharedPrefs · SQLite · intents)","[NEW]"),
        ("11", "Session Log & Reports",                                   "[NEW]"),
        ("12", "Exit",                                                    ""),
    ]
    while True:
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
        elif ch == "12":
            display_banner()
            if SESSION_LOG:
                if input("{}→ Save session log before exit? (y/n): {}".format(Y, W)).strip().lower() == "y":
                    save_report("session_final", "\n".join(SESSION_LOG))
            print("{}  DroidHawk — by {}  |  Stay sharp! ✓{}".format(G, TOOL_AUTHOR, W))
            break
        else:
            err("Invalid choice — enter a number from the menu.")
            time.sleep(0.4)

# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    load_custom_scripts()
    startup_animation()
    initial_environment_check()
    display_main_menu()
