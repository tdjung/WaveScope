"""TRN/SHM dispatch: extension detection, .shm directory resolution,
and helpful errors when simvisdbutil is absent."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wavescope import trn
from wavescope.waveform import WaveConfig, _is_trn, prepare_for_scan


class TestTrnDispatch(unittest.TestCase):
    def test_extension_detection(self):
        self.assertTrue(_is_trn("waves.shm/waves.trn"))
        self.assertTrue(_is_trn("dump.TRN"))
        self.assertTrue(_is_trn("waves.shm"))
        self.assertFalse(_is_trn("sim.vcd"))
        self.assertFalse(_is_trn("sim.fsdb"))

    def test_shm_dir_detection_and_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            shm = os.path.join(d, "mywaves")     # no .shm suffix
            os.mkdir(shm)
            trn_file = os.path.join(shm, "waves.trn")
            open(trn_file, "wb").write(b"\x00")
            self.assertTrue(_is_trn(shm))
            self.assertEqual(trn.resolve_db_path(shm), trn_file)

    def test_resolve_missing_trn_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(trn.TrnError):
                trn.resolve_db_path(d)

    def test_missing_tool_error_is_helpful(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "waves.trn")
            open(f, "wb").write(b"\x00")
            old_path = os.environ.get("PATH", "")
            envs = {k: os.environ.pop(k, None)
                    for k in ("XCELIUM_HOME", "CDS_ROOT", "CDS_INST_DIR")}
            os.environ["PATH"] = d                # simvisdbutil 없음
            try:
                with self.assertRaises(trn.TrnError) as cm:
                    prepare_for_scan(f, WaveConfig())
                msg = str(cm.exception)
                self.assertIn("simvisdbutil", msg)
                self.assertIn("--cadence-bin", msg)
            finally:
                os.environ["PATH"] = old_path
                for k, v in envs.items():
                    if v is not None:
                        os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
