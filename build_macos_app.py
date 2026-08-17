#!/usr/bin/env python3
"""
Assemble "Ekahau Beacon Viewer.app" from the scripts in this folder.

Produces a normal double-clickable macOS application bundle that starts the
local viewer and opens your browser. The bundle is self-contained — it carries
its own copies of the Python files — so you can drag it to /Applications or
the Dock. Re-run this after editing either script to refresh those copies.

Usage
    python3 build_macos_app.py [--dest /Applications]

Standard library only. The icon is drawn here in pure Python and converted
with iconutil, which ships with macOS.
"""
import argparse
import math
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "Ekahau Beacon Viewer"
# Reverse-DNS identifier. Unsigned builds do not care what this is, but if you
# publish the repo, point it at a namespace you own —
# io.github.<your-username>.ekahau-beacon-viewer is the usual convention.
BUNDLE_ID = "io.github.supertech06.ekahau-beacon-viewer"
VERSION = "1.0"
PAYLOAD = ["esx_beacon_web.py", "esx_beacon_ies.py"]

LAUNCHER = """#!/bin/sh
# Resolve the Resources folder next to this script, then hand off to Python.
RES="$(cd "$(dirname "$0")/../Resources" && pwd)"
# Deliberately not cd'ing into Resources: when the bundle lives in OneDrive,
# macOS blocks Python from scanning that directory for imports if it is also
# the working directory.
cd / || exit 1
exec /usr/bin/python3 "$RES/esx_beacon_web.py" "$@"
"""

# icon palette - matches the AP markers used on the coverage maps
INK = (18, 38, 74)
GLYPH = (247, 249, 252)


def write_png(path, size, pixels):
    raw = b"".join(b"\x00" + pixels[y * size * 4:(y + 1) * size * 4] for y in range(size))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)))
        fh.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        fh.write(chunk(b"IEND", b""))


def draw_icon(size):
    """A flat rounded square with a signal glyph. Analytic antialiasing."""
    s = float(size)
    aa = s / 400.0                      # edge softness in pixels
    cx = s / 2.0
    origin_y = s * 0.735                # apex the arcs radiate from
    radii = [s * 0.150, s * 0.268, s * 0.386]
    half_t = s * 0.030
    dot_r = s * 0.055
    corner = s * 0.225
    inset = s * 0.055
    half = s / 2.0 - inset
    spread = math.tan(math.radians(52.0))

    def smooth(edge):
        """1 inside, 0 outside, soft across ~aa pixels."""
        return min(1.0, max(0.0, 0.5 - edge / aa))

    out = bytearray(size * size * 4)
    for py in range(size):
        y = py + 0.5
        row = py * size * 4
        for px in range(size):
            x = px + 0.5
            dx = abs(x - cx) - (half - corner)
            dy = abs(y - cx) - (half - corner)
            dx = dx if dx > 0 else 0.0
            dy = dy if dy > 0 else 0.0
            bg = smooth(math.hypot(dx, dy) - corner)
            if bg <= 0.0:
                continue

            ddx = x - cx
            ddy = y - origin_y
            dist = math.hypot(ddx, ddy)

            arcs = 0.0
            if ddy < 0 and abs(ddx) <= (-ddy) * spread:
                for r in radii:
                    a = smooth(abs(dist - r) - half_t)
                    if a > arcs:
                        arcs = a
                # soften where an arc is clipped by the wedge edge
                edge = ((-ddy) * spread - abs(ddx))
                arcs *= min(1.0, max(0.0, edge / (aa * 2.0)))

            # the dot is composited after the wedge fade so it stays solid
            g = max(arcs, smooth(dist - dot_r))

            i = row + px * 4
            r = INK[0] + (GLYPH[0] - INK[0]) * g
            gg = INK[1] + (GLYPH[1] - INK[1]) * g
            b = INK[2] + (GLYPH[2] - INK[2]) * g
            out[i] = int(r)
            out[i + 1] = int(gg)
            out[i + 2] = int(b)
            out[i + 3] = int(255 * bg)
    return bytes(out)


def build_icns(dest_icns, quiet=False):
    """Draw once at 512 and let sips produce the rest of the iconset."""
    if not shutil.which("iconutil") or not shutil.which("sips"):
        print("  iconutil/sips unavailable — skipping icon")
        return False
    tmp = tempfile.mkdtemp()
    iconset = os.path.join(tmp, "AppIcon.iconset")
    os.makedirs(iconset)
    base = os.path.join(tmp, "base.png")
    if not quiet:
        print("  drawing icon…")
    write_png(base, 512, draw_icon(512))
    wanted = [(16, "16x16"), (32, "16x16@2x"), (32, "32x32"), (64, "32x32@2x"),
              (128, "128x128"), (256, "128x128@2x"), (256, "256x256"),
              (512, "256x256@2x"), (512, "512x512"), (1024, "512x512@2x")]
    for px, label in wanted:
        target = os.path.join(iconset, "icon_%s.png" % label)
        subprocess.run(["sips", "-z", str(px), str(px), base, "--out", target],
                       capture_output=True, check=False)
    r = subprocess.run(["iconutil", "-c", "icns", iconset, "-o", dest_icns],
                       capture_output=True, text=True)
    shutil.rmtree(tmp, ignore_errors=True)
    if r.returncode != 0:
        print("  iconutil failed: %s" % r.stderr.strip())
        return False
    return True


class BuildError(Exception):
    pass


def build(dest_dir, quiet=False):
    """Assemble the bundle in dest_dir. Returns the path to the .app."""
    def say(msg):
        if not quiet:
            print(msg)

    for name in PAYLOAD:
        if not os.path.exists(os.path.join(HERE, name)):
            raise BuildError("missing %s — it must sit next to this builder" % name)

    app = os.path.join(os.path.abspath(dest_dir), APP_NAME + ".app")
    contents = os.path.join(app, "Contents")
    macos = os.path.join(contents, "MacOS")
    resources = os.path.join(contents, "Resources")

    say("Building %s" % app)
    # Refresh in place rather than deleting first: synced folders often refuse
    # deletes mid-sync, and a half-removed bundle is worse than an overwritten
    # one. macOS still guards existing bundles behind App Management, so a
    # refusal here is reported with the one instruction that resolves it.
    try:
        for folder in (macos, resources):
            os.makedirs(folder, exist_ok=True)

        for name in PAYLOAD:
            shutil.copy2(os.path.join(HERE, name), os.path.join(resources, name))
            say("  bundled %s" % name)

        launcher = os.path.join(macos, "launcher")
        with open(launcher, "w") as fh:
            fh.write(LAUNCHER)
        os.chmod(launcher, 0o755)
    except PermissionError:
        raise BuildError(
            "macOS refused to modify the existing bundle at\n  %s\n"
            "Since macOS 14, changing an app you did not launch requires the App\n"
            "Management permission. Drag the old bundle to the Trash in Finder and\n"
            "run this again, or build somewhere else with --dest." % app)

    info = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": VERSION,
        "CFBundleShortVersionString": VERSION,
        "CFBundlePackageType": "APPL",
        "CFBundleExecutable": "launcher",
        "CFBundleInfoDictionaryVersion": "6.0",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
    }
    if build_icns(os.path.join(resources, "AppIcon.icns"), quiet=quiet):
        info["CFBundleIconFile"] = "AppIcon"
        say("  icon written")

    with open(os.path.join(contents, "Info.plist"), "wb") as fh:
        plistlib.dump(info, fh)

    # a locally built bundle is not quarantined, but strip the flag if present
    subprocess.run(["xattr", "-cr", app], capture_output=True, check=False)
    subprocess.run(["touch", app], capture_output=True, check=False)
    return app


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", default=HERE,
                    help="where to write the .app (default: this folder)")
    args = ap.parse_args()

    if sys.platform != "darwin":
        print("This builds a macOS .app bundle; run it on a Mac.")
        return 1
    try:
        app = build(args.dest)
    except BuildError as exc:
        print("\n%s" % exc)
        return 1
    print("\nDone. Double-click it, or drag it to /Applications.")
    print("  %s" % app)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
