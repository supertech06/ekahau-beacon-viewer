# Ekahau beacon element viewer

Decodes the raw 802.11 beacon information elements that Ekahau records inside a
`.esx` survey but never shows you.

Ekahau stores the complete beacon body for every access point it hears,
base64-encoded, in `accessPointMeasurements.json`. Its own UI parses five fields
out of that blob — BSSID, SSID, channel, security, 802.11 standards — and leaves
everything else untouched. This reads the rest:

- **Transmit power** from the TPC Report element, where the AP advertises one
- **Regulatory limits** from the Country element and VHT Transmit Power Envelope
- **Channel load** — associated client count and channel utilisation from BSS Load
- **Roaming support** — 802.11k, 802.11v and 802.11r
- **Vendor elements** and their OUIs
- The **complete element list** for any single AP, plus the raw bytes

## A caution about transmit power

The Country element and the VHT Transmit Power Envelope both advertise a maximum
power — commonly 36 dBm in the US. That is the **regulatory ceiling every AP in
the country advertises**, not what the radio is configured to. Only the TPC
Report element (ID 35) states real transmit power, and many enterprise vendors
do not send it. Some consumer gear fills it with `63` (`0x3f`) as a "not
specified" placeholder; the tool separates those out rather than reporting them
as readings.

If no AP in your survey reports a usable TPC Report, actual transmit power is
not recoverable from a passive capture and you need it from the WLAN controller.
An active survey will not reveal it either.

## Usage

### Graphical

```sh
python3 esx_beacon_web.py [optional/path/to/survey.esx]
python3 esx_beacon_web.py --tab      # force a normal browser tab
```

Opens in a standalone window with no tabs or address bar, so it behaves like an
ordinary desktop app. That relies on a Chromium-family browser — Chrome, Edge,
Brave or Vivaldi — being installed; without one it falls back to a normal
browser tab, which works identically.

Filter by SSID, BSSID prefix or band; tick column groups on and off; click any
column to sort; click an access point for its full element list.

Nothing is uploaded. The server binds to `127.0.0.1` only, reads the `.esx`
straight off disk, and each launch mints a random URL token so nothing else on
the machine can reach it. **Browse…** calls the native file dialog — AppleScript
on macOS, PowerShell on Windows, zenity or kdialog on Linux.

### Command line

```sh
python3 esx_beacon_ies.py survey.esx                # which elements appear, and how often
python3 esx_beacon_ies.py survey.esx --txpower      # every AP reporting real transmit power
python3 esx_beacon_ies.py survey.esx --ssid Corp    # full dump for matching SSIDs
python3 esx_beacon_ies.py survey.esx --bssid f8:e7  # match a BSSID or OUI prefix
python3 esx_beacon_ies.py survey.esx --ie 35        # only APs advertising a given element
```

## Packaging

```sh
python3 build_macos_app.py                  # build Ekahau Beacon Viewer.app
python3 build_macos_app.py --dest /Applications
python3 package_for_sharing.py              # zips for macOS and Windows, into ./Share
```

`package_for_sharing.py` builds a fresh bundle into scratch space, so its output
is always current regardless of any `.app` lying around. It produces:

| File | Contents |
| --- | --- |
| `Ekahau Beacon Viewer (macOS).zip` | the app bundle plus a README |
| `Ekahau Beacon Viewer (Windows).zip` | the scripts, a `.cmd` launcher and a README |

macOS bundles have to be zipped with `ditto` to survive email and chat clients —
a `.app` is a directory, so anything that treats it as a file will flatten it.

### Code signing

Neither artifact is signed. macOS quarantines the downloaded app and shows
"Apple could not verify…"; the recipient allows it once via System Settings ›
Privacy & Security › Open Anyway. Windows SmartScreen behaves similarly. Only an
Apple Developer ID plus notarization, and an Authenticode certificate on the
Windows side, remove those prompts.

### Windows and Python

The zip produced locally by `package_for_sharing.py` ships the scripts and needs
Python 3 installed, since Windows does not provide it. The zip attached to a
**release** is different: CI freezes it with PyInstaller into a standalone
`.exe` with Python bundled, so there is nothing to install. Both are named
`Ekahau Beacon Viewer (Windows).zip`; the release build is the one to hand to
people. A Windows executable cannot be cross-compiled from macOS, which is why
it only exists via CI.

## Cutting a release

`.github/workflows/release.yml` builds both platforms and publishes them to the
repository's Releases page:

```sh
git tag v1.0.0
git push origin v1.0.0
```

That builds the macOS bundle on a `macos-latest` runner and the Windows
executable on `windows-latest`, smoke-tests each by starting the server and
fetching a page, then attaches both zips to a release named after the tag.

Running the workflow by hand from the **Actions** tab builds and smoke-tests
both without publishing anything, which is the way to check a change before
tagging it.

The workflow uses only first-party actions plus the `gh` CLI that ships on the
runners, so there are no third-party dependencies to allow-list.

## Requirements

Python 3.9 or newer. Standard library only, no third-party packages. Verified
against Apple's `/usr/bin/python3` on macOS 26.

An earlier build used tkinter, which was abandoned: Apple's bundled Python ships
Tcl/Tk 8.5, and that renders blank windows on current macOS.

## Repository contents

| File | Purpose |
| --- | --- |
| `esx_beacon_ies.py` | the decoder, and a CLI over it — all parsing lives here |
| `esx_beacon_web.py` | browser front end |
| `build_macos_app.py` | assembles the `.app`, including a dependency-free icon |
| `package_for_sharing.py` | produces the distributable zips |

## Client data

Ekahau surveys contain floor plans, site addresses and customer names. Nothing
from a real survey belongs in this repository. `.gitignore` excludes `.esx`
files and exported imagery; keep it that way.
