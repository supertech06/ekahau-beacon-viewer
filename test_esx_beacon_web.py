#!/usr/bin/env python3
"""Viewer tests. Standard library only — run with python3 -m unittest."""
import base64
import json
import os
import tempfile
import unittest
import zipfile

import esx_beacon_web as web


def tpc_blob(dbm):
    raw = bytes([35, 2, dbm & 0xFF, 0])
    return base64.b64encode(raw).decode("ascii")


def write_esx(path, measurements):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(
            "accessPointMeasurements.json",
            json.dumps({"accessPointMeasurements": measurements}),
        )


def ap(freq=5180, mac="aa:bb:cc:dd:ee:ff", ssid="lab", dbm=20):
    return {
        "mac": mac,
        "ssid": ssid,
        "security": "WPA2",
        "technologies": ["802.11ac"],
        "channelByCenterFrequencyDefinedNarrowChannels": [freq],
        "informationElements": tpc_blob(dbm),
    }


class DecodeSurveyTests(unittest.TestCase):
    def test_usable_tpc_and_placeholder_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.esx")
            write_esx(path, [ap(dbm=63), ap(dbm=20)])
            payload, raw = web.decode_survey(path)
        bssids_real = {t["bssid"] for t in payload["txpower"]}
        bssids_ph = {p["bssid"] for p in payload["placeholders"]}
        self.assertIn("aa:bb:cc:dd:ee:ff", bssids_real)
        self.assertEqual(bssids_real & bssids_ph, set())
        self.assertEqual(payload["txpower"][0]["power"], 20)

    def test_raw_view_keeps_the_capture_with_usable_tpc(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.esx")
            write_esx(path, [ap(dbm=63), ap(dbm=20)])
            payload, raw = web.decode_survey(path)
        row = payload["rows"][0]
        _m, _body, ies = raw[row["id"]]
        tpc = [v for e, v in ies if e == 35][0]
        self.assertEqual(web.DEC.signed(tpc[0]), 20)


class PageTests(unittest.TestCase):
    def test_status_does_not_assign_innerHTML_from_filename(self):
        self.assertNotIn("$('status').innerHTML", web.PAGE)

    def test_bssid_filter_lowercases_the_stored_address(self):
        self.assertIn("(r.bssid||'').toLowerCase().startsWith(bs)", web.PAGE)

    def test_row_id_is_not_interpolated_raw_into_attributes(self):
        self.assertNotIn("data-id=\"'+r.id+'\"", web.PAGE)


class PathTests(unittest.TestCase):
    def test_analyse_resolves_home_relative_paths(self):
        home = os.path.expanduser("~")
        self.assertTrue(web.survey_path("~/survey.esx").startswith(home))
