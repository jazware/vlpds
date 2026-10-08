"""hactl.py's segment parser against the golden log objects in testdata/formats/L*/segment,
which tests/all/formats.rs proves this build's writer emits byte for byte (rewrite them with
`VLPDS_BLESS=1 cargo test --test all formats::`; see that file for the test level's).

    python3 -m unittest bench/ha/test_hactl.py      # from packages/vlpds, or `just ha-parser-test`
"""

import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hactl  # noqa: E402

LOG = "node-a.1790000000000000"
LEVELS = sorted(glob.glob(os.path.join(hactl.PKG, "testdata", "formats", "L*", "segment")))


def read(level_dir, name):
    with open(os.path.join(level_dir, name), "rb") as f:
        return f.read()


class ParseLogObject(unittest.TestCase):
    def test_fixture_levels_present(self):
        self.assertIn("L1", [os.path.basename(os.path.dirname(d)) for d in LEVELS])

    def test_segments(self):
        want = {
            # derived muts (repo generation 2), plain muts, a private-state entry with no frame
            "plain.seg": (5, 4, 1000 << 8, 1002 << 8, [1000 << 8, 1001 << 8]),
            "zstd.seg": (5, 4, 1000 << 8, 1002 << 8, [1000 << 8, 1001 << 8]),
            "like.seg": (6, 6, 1010 << 8, 1010 << 8, [1010 << 8]),
        }
        for d in LEVELS:
            for name, (ordinal, prefix_end, first, last, seqs) in want.items():
                with self.subTest(level=d, name=name):
                    got = hactl.parse_log_object(read(d, name))
                    self.assertEqual(got, {"kind": "segment", "log_id": LOG, "ordinal": ordinal,
                                           "prefix_end": prefix_end, "first_seq": first, "last_seq": last,
                                           "seqs": seqs})

    def test_fence_and_missing(self):
        for d in LEVELS:
            self.assertEqual(hactl.parse_log_object(read(d, "fence.bin")), {"kind": "fence", "by": "node-b"})
        self.assertEqual(hactl.parse_log_object(b""), {"kind": "missing"})

    def test_unknown_formats_fail_clearly(self):
        plain = read(LEVELS[0], "plain.seg")
        with self.assertRaisesRegex(hactl.SegmentFormatError, "unknown log object magic"):
            hactl.parse_log_object(b"VLSEG07\n" + plain[8:])
        with self.assertRaisesRegex(hactl.SegmentFormatError, "truncated|bytes"):
            hactl.parse_log_object(plain[:-3])


if __name__ == "__main__":
    unittest.main()
