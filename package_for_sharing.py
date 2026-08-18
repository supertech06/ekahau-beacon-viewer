#!/usr/bin/env python3
"""
Package the beacon viewer into single files you can send over Teams.

A .app is a folder, not a file, so chat clients unpack it into loose pieces.
Zipping with ditto keeps the bundle intact. Windows cannot run a .app at all,
so it gets the plain scripts plus a launcher instead — the tool itself is pure
standard library and runs anywhere Python 3 does.

Produces, in ./Share:
    Ekahau Beacon Viewer (macOS).zip     - the app bundle, ready to drag to /Applications
    Ekahau Beacon Viewer (Windows).zip   - scripts plus a double-click .cmd launcher

Usage
    python3 build_macos_app.py      # refresh the bundle first
    python3 package_for_sharing.py
"""
import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
APP = "Ekahau Beacon Viewer.app"
SCRIPTS = ["esx_beacon_web.py", "esx_beacon_ies.py"]
OUT_DIR = os.path.join(HERE, "Share")

WINDOWS_LAUNCHER = """@echo off
title Ekahau Beacon Viewer
cd /d "%~dp0"

set "PYEXE="
where py >nul 2>nul && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>nul && set "PYEXE=python"
)
if not defined PYEXE (
  echo.
  echo   Python 3 is required and was not found on this PC.
  echo.
  echo   Install it from https://www.python.org/downloads/ or the Microsoft
  echo   Store, tick "Add python.exe to PATH" during setup, then run this
  echo   file again.
  echo.
  pause
  exit /b 1
)

echo Starting the viewer - your browser will open in a moment.
echo Close this window to stop it.
echo.
%PYEXE% "%~dp0esx_beacon_web.py" %*
if errorlevel 1 pause
"""

MAC_README = """Ekahau Beacon Viewer - macOS
============================

Decodes the raw 802.11 beacon information elements that Ekahau records in a
.esx survey but never shows you: transmit power, channel utilisation, country
and regulatory limits, 802.11k/v/r support, vendor elements, and the complete
element list for any access point.


Install
-------
Drag "Ekahau Beacon Viewer.app" to your Applications folder, then open it.
It starts a small local server and opens your browser.


First launch: macOS will probably block it
------------------------------------------
This app is not code-signed, so macOS quarantines anything downloaded from
Teams, email or a browser. You will see a message like "Apple could not verify
that this app is free of malware."

To allow it:

  1. Try to open the app once and dismiss the warning.
  2. Open System Settings > Privacy & Security.
  3. Scroll to the Security section. There will be a line about the app
     being blocked, with an "Open Anyway" button. Click it.
  4. Open the app again and confirm.

You only do this once.

If you prefer the command line, this does the same thing in one step:

    xattr -dr com.apple.quarantine "/Applications/Ekahau Beacon Viewer.app"


Requirements
------------
Python 3, which macOS provides. If you have never installed Xcode Command
Line Tools, the first launch may prompt you to - accept, or run:

    xcode-select --install


If the app will not start at all
--------------------------------
The bundle carries the plain scripts inside it, and running them directly
bypasses Gatekeeper entirely:

    python3 "/Applications/Ekahau Beacon Viewer.app/Contents/Resources/esx_beacon_web.py"


Privacy
-------
Nothing is uploaded. The server binds to 127.0.0.1 only and reads the .esx from
your disk. Each launch picks a random port and a URL token so another browser
tab cannot guess the address. The token is printed in the terminal; it is not a
barrier against other processes running as you.
"""

WIN_README = """Ekahau Beacon Viewer - Windows
==============================

Decodes the raw 802.11 beacon information elements that Ekahau records in a
.esx survey but never shows you: transmit power, channel utilisation, country
and regulatory limits, 802.11k/v/r support, vendor elements, and the complete
element list for any access point.


Install
-------
1. Unzip this folder somewhere permanent, keeping all three files together.
2. Double-click "Ekahau Beacon Viewer.cmd".

A console window opens and your browser follows a second later. Closing the
console window stops the tool, as does the Quit button in the page.


Requirements
------------
Python 3. Windows does not include it. If the launcher tells you it is
missing, install from https://www.python.org/downloads/ or the Microsoft
Store, and tick "Add python.exe to PATH" during setup.

No other packages are needed - this uses only the Python standard library.


SmartScreen
-----------
Windows may warn about a downloaded .cmd file. Choose "More info" then
"Run anyway". You can read the file in Notepad first if you would rather
check it — it locates Python 3 and starts the viewer.


Privacy
-------
Nothing is uploaded. The server binds to 127.0.0.1 only and reads the .esx from
your disk. Each launch picks a random port and a URL token so another browser
tab cannot guess the address. The token is printed in the terminal; it is not a
barrier against other processes running as you.
"""


def human(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return "%.0f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def load_builder():
    path = os.path.join(HERE, "build_macos_app.py")
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location("build_macos_app", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_mac(out_dir):
    if sys.platform != "darwin" or not shutil.which("ditto"):
        print("  skipped macOS: the bundle can only be built on a Mac")
        return None
    builder = load_builder()
    if builder is None:
        print("  skipped macOS: build_macos_app.py not found next to this script")
        return None

    # Always build a fresh bundle into a scratch folder rather than copying
    # whatever .app happens to be lying around — that one may be stale, and
    # macOS will not let us refresh it in place once it exists.
    scratch = tempfile.mkdtemp(prefix="ekahau-share-")
    # --keepParent names the zip's top folder after this directory, so it has
    # to be the name we want recipients to see, not the temp directory's.
    staging = os.path.join(scratch, "Ekahau Beacon Viewer")
    os.makedirs(staging)
    try:
        builder.build(staging, quiet=True)
    except Exception as exc:                              # noqa: BLE001
        shutil.rmtree(scratch, ignore_errors=True)
        print("  skipped macOS: %s" % exc)
        return None
    with open(os.path.join(staging, "READ ME.txt"), "w") as fh:
        fh.write(MAC_README)

    dest = os.path.join(out_dir, "Ekahau Beacon Viewer (macOS).zip")
    if os.path.exists(dest):
        os.remove(dest)
    # ditto preserves the bundle layout and the executable bit; plain zip may not
    r = subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                        staging, dest], capture_output=True, text=True)
    shutil.rmtree(scratch, ignore_errors=True)
    if r.returncode != 0:
        print("  macOS zip failed: %s" % r.stderr.strip())
        return None
    return dest


def build_windows(out_dir):
    missing = [s for s in SCRIPTS if not os.path.exists(os.path.join(HERE, s))]
    if missing:
        print("  skipped Windows: missing %s" % ", ".join(missing))
        return None

    dest = os.path.join(out_dir, "Ekahau Beacon Viewer (Windows).zip")
    if os.path.exists(dest):
        os.remove(dest)
    root = "Ekahau Beacon Viewer"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        # CRLF so the .cmd behaves in every Windows shell
        z.writestr(root + "/Ekahau Beacon Viewer.cmd",
                   WINDOWS_LAUNCHER.replace("\n", "\r\n"))
        z.writestr(root + "/READ ME.txt", WIN_README.replace("\n", "\r\n"))
        for name in SCRIPTS:
            z.write(os.path.join(HERE, name), root + "/" + name)
    return dest


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", default=OUT_DIR, help="output folder (default: ./Share)")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.dest)
    os.makedirs(out_dir, exist_ok=True)
    print("Packaging into %s\n" % out_dir)

    made = []
    for builder in (build_mac, build_windows):
        path = builder(out_dir)
        if path:
            made.append(path)
            print("  %-42s %s" % (os.path.basename(path), human(os.path.getsize(path))))

    if not made:
        print("\nNothing was produced.")
        return 1
    print("\nSend these as-is. Recipients unzip and follow the READ ME inside.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
