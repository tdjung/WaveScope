"""Cadence SHM/TRN waveform support via simvisdbutil.

TRN is the transition database inside a SimVision SHM directory
(typically waves.shm/waves.trn), a proprietary Cadence format with no
open-source reader. Xcelium / SimVision installations ship
`simvisdbutil`, which converts SHM databases to VCD.

Tool discovery order: --cadence-bin, $XCELIUM_HOME/tools/bin,
$CDS_ROOT/tools/bin, $CDS_INST_DIR/tools/bin, then $PATH.

NOTE: simvisdbutil flags can differ across Xcelium releases. The
default invocation below follows the common form; override with
--simvisdbutil-args (":" separated) if your version differs.
"""

import os
import shutil
import subprocess
import tempfile
from typing import List, Optional


class TrnError(Exception):
    pass


_ENV_HOMES = ("XCELIUM_HOME", "CDS_ROOT", "CDS_INST_DIR")


def find_simvisdbutil(cadence_bin=None, simvisdbutil_bin=None):
    # type: (Optional[str], Optional[str]) -> Optional[str]
    if simvisdbutil_bin:
        return simvisdbutil_bin      # explicit path (site wrapper) wins
    dirs = []  # type: List[str]
    if cadence_bin:
        dirs.append(cadence_bin)
    for env in _ENV_HOMES:
        home = os.environ.get(env)
        if home:
            dirs += [os.path.join(home, "tools", "bin"),
                     os.path.join(home, "tools.lnx86", "bin"),
                     os.path.join(home, "bin")]
    for d in dirs:
        p = os.path.join(d, "simvisdbutil")
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("simvisdbutil")


def resolve_db_path(path):
    # type: (str) -> str
    """Accept either the .trn file or the .shm directory."""
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.endswith(".trn"):
                return os.path.join(path, name)
        raise TrnError("no .trn file found inside '%s'" % path)
    return path


def convert_to_vcd(path, tool, scope=None, extra_args=None,
                   reconvert=False):
    # type: (str, str, Optional[str], Optional[List[str]], bool) -> str
    from .fsdb import _cache_path, cache_fresh
    trn = resolve_db_path(path)
    out = _cache_path(trn, scope, "trn")
    if not reconvert and cache_fresh(trn, out):
        import sys
        print("[wavescope] reusing cached conversion %s "
              "(--reconvert to force)" % out, file=sys.stderr)
        return out
    cmd = [tool, trn, "-vcd", "-output", out, "-overwrite"]
    if scope:
        cmd += ["-scope", scope, "-recursive"]
    cmd += (extra_args or [])
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    if r.returncode != 0 or not os.path.exists(out) \
            or os.path.getsize(out) == 0:
        raise TrnError(
            "simvisdbutil failed:\n%s\ncmd: %s\n"
            "(flags vary by Xcelium release; override with "
            "--simvisdbutil-args)" % (r.stderr.strip(), " ".join(cmd)))
    return out


def no_tool_msg():
    # type: () -> str
    return ("TRN/SHM input requires Cadence 'simvisdbutil' (ships with "
            "Xcelium/SimVision), but it was not found.\n"
            "  - pass --cadence-bin /path/to/tools/bin, or\n"
            "  - set $XCELIUM_HOME / $CDS_ROOT, or\n"
            "  - add it to PATH, or\n"
            "  - convert manually: simvisdbutil waves.shm/waves.trn "
            "-vcd -output out.vcd [-scope top.core -recursive] "
            "and pass the VCD.")
