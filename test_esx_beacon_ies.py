#!/usr/bin/env python3
"""Decoder tests. Standard library only — run with python3 -m unittest."""
import base64
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import esx_beacon_ies as d


def measurement(freq, mac="aa:bb:cc:dd:ee:ff", ssid="lab", **extra):
    m = {
        "mac": mac,
        "ssid": ssid,
        "security": "WPA2",
        "technologies": ["802.11ac"],
        "channelByCenterFrequencyDefinedNarrowChannels": [freq] if freq else [],
    }
    m.update(extra)
    return m


def summarise(ies, freq=5180, **kwargs):
    return d.summarise(measurement(freq, **kwargs), ies)


class CountryElementTests(unittest.TestCase):
    def test_operating_triplet_is_not_a_channel_range_or_zero_dBm(self):
        v = bytes([ord("U"), ord("S"), 0x04, 201, 131, 0])
        s = summarise([(7, v)], freq=5955)
        self.assertIsNone(s["country_max"])
        self.assertEqual(s["country"], "US")
        text = d.describe(7, v)
        self.assertNotIn("ch 201", text)
        self.assertIn("operating class 131", text)

    def test_regulatory_max_is_the_subband_that_covers_this_channel(self):
        v = bytes([ord("U"), ord("S"), 0x04, 36, 4, 23, 149, 5, 30])
        s = summarise([(7, v)], freq=5180)  # channel 36
        self.assertEqual(s["country_max"], 23)

    def test_unspecified_country_power_255_is_not_255_dBm(self):
        v = bytes([ord("U"), ord("S"), 0x04, 36, 8, 255])
        s = summarise([(7, v)], freq=5180)
        self.assertIsNone(s["country_max"])


class TransmitPowerEnvelopeTests(unittest.TestCase):
    def test_unspecified_127_slots_do_not_become_63_5_dBm(self):
        # count=3 → four octets: 36 dBm (72 half-dB) then three 127 sentinels
        v = bytes([0x03, 72, 127, 127, 127])
        s = summarise([(195, v)])
        self.assertEqual(s["vht_max"], 36)
        self.assertNotIn("63.5", d.describe(195, v))

    def test_info_byte_count_limits_how_many_power_octets_are_read(self):
        # count=0 → only the 20 MHz field; leftover 127 must not be max()'d
        v = bytes([0x00, 72, 127, 127, 127])
        s = summarise([(195, v)])
        self.assertEqual(s["vht_max"], 36)

    def test_psd_interpretation_is_not_reported_as_eirp(self):
        # interpretation = 1 (Local EIRP PSD), count = 0, one PSD octet
        v = bytes([0x08, 10])
        s = summarise([(195, v)], freq=5955)
        self.assertIsNone(s["vht_max"])
        self.assertIn("PSD", d.describe(195, v))


class ChannelTests(unittest.TestCase):
    def test_6ghz_5935_mhz_is_channel_2(self):
        self.assertEqual(d.channel_of(5935), 2)
        self.assertEqual(d.band_of(5935), "6 GHz")

    def test_channel_prefers_ds_parameter_set_over_first_narrow_centre(self):
        freqs = [5180, 5200, 5220, 5240]  # 36/40/44/48 — primary is 52
        s = d.summarise(
            measurement(None, **{"channelByCenterFrequencyDefinedNarrowChannels": freqs}),
            [(3, bytes([52]))],
        )
        self.assertEqual(s["channel"], 52)

    def test_channel_prefers_ht_operation_primary(self):
        freqs = [5180, 5200, 5220, 5240]
        ht = bytes([44] + [0] * 20)
        s = d.summarise(
            measurement(None, **{"channelByCenterFrequencyDefinedNarrowChannels": freqs}),
            [(61, ht)],
        )
        self.assertEqual(s["channel"], 44)

    def test_6ghz_primary_from_he_operation(self):
        # Ext ID 36, 6 GHz Operation Info present (bit 17), primary channel 5
        he = bytes([
            36,
            0, 0, 0x02,
            0,
            0, 0,
            5, 0, 0, 0, 0,
        ])
        s = summarise([(255, he)], freq=5955)  # would be channel 1 without HE primary
        self.assertEqual(s["channel"], 5)


class DescribeAndParseTests(unittest.TestCase):
    def test_empty_ssid_is_hidden(self):
        self.assertEqual(d.describe(0, b""), "<hidden>")

    def test_truncated_length_keeps_earlier_elements(self):
        body = bytes([0, 4, 1, 2, 3, 4, 35, 20])  # IE 35 claims 20 bytes, 0 remain
        ies = d.parse_ies(body)
        ids = [eid for eid, _ in ies]
        self.assertIn(0, ids)
        self.assertEqual(ids[0], 0)

    def test_truncated_last_header_is_not_dropped_from_prior_ies(self):
        body = bytes([7, 6, ord("U"), ord("S"), 4, 36, 8, 23, 35])  # lone 35 id, no len
        ies = d.parse_ies(body)
        self.assertEqual(ies[0][0], 7)


class PathAndFilterTests(unittest.TestCase):
    def test_bssid_prefix_match_is_case_insensitive(self):
        self.assertTrue(d.matches_bssid("F8:E7:1E:00:00:01", "f8:e7"))
        self.assertFalse(d.matches_bssid("aa:bb:cc:dd:ee:ff", "f8:e7"))

    def test_resolve_esx_path_expands_user_home(self):
        home = os.path.expanduser("~")
        resolved = d.resolve_esx_path("~/survey.esx")
        self.assertTrue(resolved.startswith(home))
        self.assertTrue(os.path.isabs(resolved))

    def test_resolve_esx_path_joins_relative_to_start_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            resolved = d.resolve_esx_path("survey.esx", start_dir=tmp)
            self.assertEqual(resolved, os.path.join(tmp, "survey.esx"))


class LoadErrorTests(unittest.TestCase):
    def test_invalid_json_inside_esx_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.esx")
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("accessPointMeasurements.json", "{not json")
            err = io.StringIO()
            with mock.patch.object(sys, "argv", ["esx_beacon_ies.py", path]):
                with mock.patch.object(sys, "stderr", err):
                    code = d.main()
            self.assertEqual(code, 1)
            self.assertIn("could not read", err.getvalue())


def write_esx(path, measurements):
    payload = {"accessPointMeasurements": measurements}
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("accessPointMeasurements.json", json.dumps(payload))


def tpc_blob(dbm):
    # IE 35, length 2: transmit power, link margin 0
    raw = bytes([35, 2, dbm & 0xFF, 0])
    return base64.b64encode(raw).decode("ascii")


class CliTxpowerTests(unittest.TestCase):
    def test_txpower_does_not_list_the_same_radio_as_real_and_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.esx")
            write_esx(path, [
                {**measurement(5180), "informationElements": tpc_blob(63)},
                {**measurement(5180), "informationElements": tpc_blob(20)},
            ])
            out = io.StringIO()
            with mock.patch.object(sys, "argv", ["esx_beacon_ies.py", path, "--txpower"]):
                with mock.patch.object(sys, "stdout", out):
                    code = d.main()
            self.assertEqual(code, 0)
            text = out.getvalue()
            self.assertIn("20 dBm", text)
            self.assertNotIn("placeholder", text.lower())


if __name__ == "__main__":
    unittest.main()
