#!/usr/bin/env python3
"""
Decode raw 802.11 beacon information elements out of an Ekahau .esx survey.

Ekahau stores the full beacon body for every AP it heard, base64-encoded, in
accessPointMeasurements.json. The app surfaces a handful of parsed fields from
it (SSID, BSSID, channel, security, 802.11 standards) but never shows the raw
element list. This prints it.

Usage
    python3 esx_beacon_ies.py survey.esx                      # summary of which IEs appear
    python3 esx_beacon_ies.py survey.esx --ssid <SSID>        # full dump for one SSID
    python3 esx_beacon_ies.py survey.esx --bssid f8:e7:1e     # match a BSSID or OUI prefix
    python3 esx_beacon_ies.py survey.esx --ie 35              # only APs advertising a given IE
    python3 esx_beacon_ies.py survey.esx --txpower            # every AP that reports TX power

No third-party dependencies.
"""
import argparse
import base64
import collections
import json
import os
import sys
import zipfile

IE_NAMES = {
    0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM", 7: "Country",
    11: "BSS Load", 32: "Power Constraint", 33: "Power Capability", 35: "TPC Report",
    36: "Supported Channels", 37: "Channel Switch Ann.", 42: "ERP",
    45: "HT Capabilities", 48: "RSN (WPA2/3)", 50: "Extended Rates",
    54: "Mobility Domain (11r)", 59: "Supported Oper Classes", 61: "HT Operation",
    70: "RM Enabled Caps (11k)", 74: "Overlapping BSS Scan", 107: "Interworking",
    108: "Advertisement Protocol", 127: "Extended Capabilities",
    191: "VHT Capabilities", 192: "VHT Operation", 195: "VHT Tx Power Envelope",
    221: "Vendor Specific", 255: "Element ID Extension",
}

KNOWN_OUI = {
    "00:50:f2": "Microsoft / WPA", "00:0f:ac": "IEEE 802.11",
    "50:6f:9a": "Wi-Fi Alliance", "00:13:92": "Ruckus", "00:1f:41": "Ruckus",
    "00:40:96": "Cisco / Aironet", "00:0b:86": "HPE Aruba", "8c:fd:f0": "Qualcomm",
    "00:10:18": "Broadcom", "00:90:4c": "Epigram / Broadcom", "00:03:7f": "Atheros",
    "00:17:f2": "Apple", "00:14:6c": "Netgear",
}


TPE_UNSPECIFIED = 127
COUNTRY_POWER_UNSPECIFIED = 255
OPERATING_TRIPLET_MIN = 201
HE_OPERATION_EXT = 36
TPE_INTERP = {
    0: "local EIRP",
    1: "local EIRP PSD",
    2: "regulatory client EIRP",
    3: "regulatory client EIRP PSD",
}


def signed(byte: int) -> int:
    return byte - 256 if byte > 127 else byte


def matches_bssid(mac, prefix) -> bool:
    return (mac or "").lower().startswith((prefix or "").lower())


def resolve_esx_path(path: str, start_dir=None) -> str:
    path = os.path.expanduser((path or "").strip())
    if not path:
        return path
    if not os.path.isabs(path):
        root = start_dir or os.environ.get("EKAHAU_START_DIR") or os.getcwd()
        path = os.path.join(root, path)
    return os.path.abspath(path)


def parse_ies(body: bytes):
    """Split a beacon body into (element_id, payload) pairs."""
    out, i = [], 0
    while i + 2 <= len(body):
        eid, length = body[i], body[i + 1]
        if i + 2 + length > len(body):
            break
        out.append((eid, body[i + 2:i + 2 + length]))
        i += 2 + length
    return out


def _country_fields(v: bytes):
    if not v or len(v) < 3:
        return None, [], []
    country = v[:2].decode("ascii", "replace").strip()
    operating, subbands = [], []
    for i in range(3, len(v) - 2, 3):
        first, count, third = v[i], v[i + 1], v[i + 2]
        if first >= OPERATING_TRIPLET_MIN:
            operating.append((first, count, third))
        else:
            power = None if third == COUNTRY_POWER_UNSPECIFIED else third
            subbands.append((first, count, power))
    return country, operating, subbands


def _country_max_for_channel(v: bytes, channel):
    _country, _operating, subbands = _country_fields(v)
    if channel is None:
        return None
    matched = [
        power for first, n, power in subbands
        if power is not None and first <= channel <= first + n - 1
    ]
    return max(matched) if matched else None


def _tpe_parse(v: bytes):
    if not v:
        return None
    info = v[0]
    count = info & 0x07
    interp = (info >> 3) & 0x07
    raw = list(v[1:1 + count + 1])
    widths = ["20 MHz", "40 MHz", "80 MHz", "160 MHz", "80+80/320 MHz"]
    values = []
    for i, octet in enumerate(raw):
        if octet == TPE_UNSPECIFIED:
            continue
        label = widths[i] if i < len(widths) else "field %d" % i
        values.append((label, signed(octet) / 2))
    return {
        "interp": interp,
        "is_psd": interp in (1, 3),
        "label": TPE_INTERP.get(interp, "interpretation %d" % interp),
        "values": values,
    }


def _tpe_eirp_max(payloads):
    best = None
    for v in payloads:
        parsed = _tpe_parse(v)
        if not parsed or parsed["is_psd"] or not parsed["values"]:
            continue
        n = max(x[1] for x in parsed["values"])
        if best is None or n > best:
            best = n
    return best


def _he_6ghz_primary(payloads):
    for v in payloads:
        if not v or v[0] != HE_OPERATION_EXT or len(v) < 8:
            continue
        params = v[1:4]
        if not ((params[2] >> 1) & 1):
            continue
        i = 7
        if params[0] & 0x80:
            i += 3
        if params[1] & 0x01:
            i += 1
        if i < len(v):
            return v[i]
    return None


def describe(eid: int, v: bytes) -> str:
    if eid == 0:
        ssid = v.decode("utf-8", "replace")
        return repr(ssid) if ssid else "<hidden>"
    if eid == 3 and v:
        return f"channel {v[0]}"
    if eid == 7 and len(v) >= 3:
        country, operating, subbands = _country_fields(v)
        parts = [
            f"operating class {oclass} coverage {coverage}"
            for _ext, oclass, coverage in operating
        ]
        for first, n, power in subbands:
            last = first + n - 1
            if power is None:
                parts.append(f"ch {first}-{last} max unspecified")
            else:
                parts.append(f"ch {first}-{last} max {power} dBm")
        return f"{country} | " + "; ".join(parts) if parts else country
    if eid == 32 and v:
        return f"{v[0]} dB local power constraint"
    if eid == 35 and len(v) >= 2:
        return f"TRANSMIT POWER = {signed(v[0])} dBm, link margin {v[1]} dB"
    if eid == 11 and len(v) >= 5:
        stations = int.from_bytes(v[0:2], "little")
        return f"{stations} associated stations, {round(v[2] / 255 * 100)}% channel utilisation"
    if eid == 195:
        parsed = _tpe_parse(v)
        if parsed:
            unit = "dBm/MHz" if parsed["is_psd"] else "dBm"
            kind = "PSD" if parsed["is_psd"] else "EIRP"
            if not parsed["values"]:
                return f"{parsed['label']}: unspecified"
            body = ", ".join(
                f"{label} max {kind} {val:g} {unit}" for label, val in parsed["values"]
            )
            return f"{parsed['label']}: {body}"
    if eid == 221 and len(v) >= 3:
        oui = v[:3].hex(":")
        return f"OUI {oui} ({KNOWN_OUI.get(oui, 'unknown vendor')})"
    if eid == 61 and v:
        return f"primary channel {v[0]}"
    if len(v) <= 16:
        return v.hex(" ")
    return v[:16].hex(" ") + f" … ({len(v)} bytes total)"


def band_of(freq):
    if not freq:
        return ""
    if freq < 2500:
        return "2.4 GHz"
    return "5 GHz" if freq < 5925 else "6 GHz"


def channel_of(freq):
    """Centre frequency in MHz to channel number."""
    if not freq:
        return None
    if freq == 2484:
        return 14
    if freq < 2500:
        return (freq - 2407) // 5
    if freq < 5925:
        return (freq - 5000) // 5
    if freq == 5935:
        return 2
    return (freq - 5950) // 5


def summarise(m, ies):
    """Reduce one beacon capture to the fields worth putting in a table.

    Returns plain values (or None when the AP does not advertise the element)
    so callers can format them however they like.
    """
    by = {}
    for eid, payload in ies:
        by.setdefault(eid, []).append(payload)

    def first(eid):
        vals = by.get(eid)
        return vals[0] if vals else None

    freqs = m.get("channelByCenterFrequencyDefinedNarrowChannels") or []
    freq = freqs[0] if freqs else None

    ds = first(3)
    ht = first(61)
    he_primary = _he_6ghz_primary(by.get(255, []))
    if ds:
        channel = ds[0]
    elif ht:
        channel = ht[0]
    elif he_primary is not None:
        channel = he_primary
    else:
        channel = channel_of(freq)

    tpc = None
    v = first(35)
    if v:
        reported = signed(v[0])
        # 0x3f is widely used as a "not specified" placeholder by consumer gear
        tpc = None if reported == 63 else reported

    country = country_max = None
    v = first(7)
    if v and len(v) >= 3:
        country, _operating, _subbands = _country_fields(v)
        country_max = _country_max_for_channel(v, channel)

    vht_max = _tpe_eirp_max(by.get(195, []))

    stations = utilisation = None
    v = first(11)
    if v and len(v) >= 5:
        stations = int.from_bytes(v[0:2], "little")
        utilisation = round(v[2] / 255 * 100)

    ext = first(127)
    return {
        "ssid": m.get("ssid", ""),
        "bssid": m.get("mac", ""),
        "freq": freq,
        "band": band_of(freq),
        "channel": channel,
        "security": m.get("security") or "",
        "technologies": "/".join(m.get("technologies") or []),
        "tpc": tpc,
        "country": country,
        "country_max": country_max,
        "vht_max": vht_max,
        "stations": stations,
        "utilisation": utilisation,
        "dot11k": 70 in by,
        "dot11r": 54 in by,
        "dot11v": bool(ext and len(ext) >= 3 and ext[2] & 0x08),
        "vendors": sorted({p[:3].hex(":") for p in by.get(221, []) if len(p) >= 3}),
        "ie_count": len(ies),
        "ie_ids": sorted(by),
    }


def load(path: str):
    path = resolve_esx_path(path)
    with zipfile.ZipFile(path) as z:
        data = json.loads(z.read("accessPointMeasurements.json"))
    return data["accessPointMeasurements"]


def dump_one(m, body, ies):
    chans = m.get("channelByCenterFrequencyDefinedNarrowChannels")
    print(f"\n{m['ssid']!r}   {m['mac']}   channel {chans}   {m.get('security')}")
    print(f"  {len(body)} bytes of beacon body, {len(ies)} information elements")
    print("  " + "-" * 88)
    for eid, v in ies:
        name = IE_NAMES.get(eid, "(unrecognised)")
        print(f"  IE {eid:>3}  {name:<26} len {len(v):>3}   {describe(eid, v)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("esx", help="path to the .esx survey file")
    ap.add_argument("--ssid", help="only APs whose SSID contains this string")
    ap.add_argument("--bssid", help="only APs whose BSSID starts with this (OUI prefix works)")
    ap.add_argument("--ie", type=int, help="only APs advertising this element ID")
    ap.add_argument("--txpower", action="store_true",
                    help="list every AP advertising a TPC Report (IE 35)")
    ap.add_argument("--limit", type=int, default=10, help="max APs to dump in full (default 10)")
    args = ap.parse_args()

    try:
        measurements = load(args.esx)
    except (OSError, zipfile.BadZipFile, KeyError, ValueError, TypeError) as exc:
        print(f"could not read {args.esx}: {exc}", file=sys.stderr)
        return 1

    decoded = []
    for m in measurements:
        blob = m.get("informationElements")
        if not blob:
            continue
        try:
            body = base64.b64decode(blob)
        except (ValueError, TypeError):
            continue
        decoded.append((m, body, parse_ies(body)))

    if args.txpower:
        found = [(m, [v for e, v in ies if e == 35][0])
                 for m, _, ies in decoded if any(e == 35 for e, _ in ies)]
        print(f"{len(found)} of {len(decoded)} beacon captures advertise a TPC Report\n")
        real, placeholder = {}, {}
        for m, v in found:
            if not v:
                continue
            p = signed(v[0])
            # 0x3f is widely used by consumer gear to mean "not specified"
            (placeholder if p == 63 else real).setdefault(m["mac"], (m["ssid"], p))
        if real:
            print(f"  usable readings ({len(real)} radios):")
            for mac, (ssid, p) in sorted(real.items(), key=lambda kv: -kv[1][1]):
                print(f"    {p:>4} dBm   {mac}   {ssid!r}")
        else:
            print("  no usable readings — no radio here reports a real transmit power")
        placeholder = {mac: v for mac, v in placeholder.items() if mac not in real}
        if placeholder:
            print(f"\n  ignored, reporting the 63 dBm 'not specified' placeholder "
                  f"({len(placeholder)} radios):")
            for mac, (ssid, _) in sorted(placeholder.items()):
                print(f"           {mac}   {ssid!r}")
        return 0

    selected = decoded
    if args.ssid:
        selected = [d for d in selected if args.ssid.lower() in d[0]["ssid"].lower()]
    if args.bssid:
        selected = [d for d in selected if matches_bssid(d[0].get("mac", ""), args.bssid)]
    if args.ie is not None:
        selected = [d for d in selected if any(e == args.ie for e, _ in d[2])]

    if not (args.ssid or args.bssid or args.ie):
        counts = collections.Counter()
        for _, _, ies in decoded:
            counts.update({e for e, _ in ies})
        print(f"{len(decoded)} beacon captures in {args.esx}\n")
        print(f"{'ID':>4}  {'element':<28}{'seen in':>9}")
        for eid, n in counts.most_common():
            print(f"{eid:>4}  {IE_NAMES.get(eid, '(unrecognised)'):<28}{n:>9}")
        print("\nre-run with --ssid / --bssid / --ie / --txpower to dump individual APs")
        return 0

    print(f"{len(selected)} matching beacon captures; showing up to {args.limit}")
    for m, body, ies in selected[:args.limit]:
        dump_one(m, body, ies)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
