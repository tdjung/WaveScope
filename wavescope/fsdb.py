"""FSDB support via Synopsys Verdi utilities.

FSDB is a proprietary format with no open-source reader, so WaveScope
relies on tools shipped with Verdi, tried in this order:

1. fsdbreport  -- dumps value changes of *specific signals* as text.
                  Fastest path: only clk/pc/valid are extracted, no VCD
                  conversion.  Preferred when available.
2. fsdb2vcd    -- converts to VCD (optionally restricted to a scope via
                  --fsdb-scope) which is then parsed by the normal VCD
                  reader.

Tool discovery: --verdi-home, $VERDI_HOME, then $PATH.

NOTE: fsdbreport/fsdb2vcd flags differ slightly across Verdi releases.
The invocations below follow the common form; if your version differs,
override with --fsdbreport-args / --fsdb2vcd-args (":" separated).
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import Iterator, List, Optional, Tuple


class FsdbError(Exception):
    pass


class VerdiTools(object):
    __slots__ = ("fsdbreport", "fsdb2vcd")

    def __init__(self, fsdbreport, fsdb2vcd):
        self.fsdbreport = fsdbreport
        self.fsdb2vcd = fsdb2vcd


def find_tools(verdi_home: Optional[str] = None,
               fsdbreport_bin: Optional[str] = None,
               fsdb2vcd_bin: Optional[str] = None) -> VerdiTools:
    """Explicit --*-bin paths win unconditionally: license-queued sites
    often front vendor tools with wrapper scripts, and tool-home
    discovery must not bypass them."""
    dirs: List[str] = []
    home = verdi_home or os.environ.get("VERDI_HOME")
    if home:
        dirs += [os.path.join(home, "bin"), home]

    def find(name: str, explicit: Optional[str]) -> Optional[str]:
        if explicit:
            return explicit
        for d in dirs:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return shutil.which(name)

    return VerdiTools(fsdbreport=find("fsdbreport", fsdbreport_bin),
                      fsdb2vcd=find("fsdb2vcd", fsdb2vcd_bin))


def to_fsdb_path(name: str) -> str:
    """Convert dotted hierarchical name to FSDB '/' path."""
    if name.startswith("/"):
        return name
    return "/" + name.replace(".", "/")


# ----------------------------------------------------------------------
# Path 1: fsdbreport (per-signal text dump, no conversion)
# ----------------------------------------------------------------------
_VC_RE = re.compile(r"^\s*(\d+)\s+([0-9a-fA-FxXzZ'hbd_]+)\s*$")


def _dump_signal(tool: str, fsdb: str, signal: str,
                 extra_args: List[str]) -> List[Tuple[int, Optional[int]]]:
    """Run fsdbreport for one signal; return [(time, value|None), ...]."""
    with tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False) as tf:
        out_path = tf.name
    try:
        cmd = [tool, fsdb, "-s", signal, "-of", "h", "-o", out_path] + extra_args
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if r.returncode != 0:
            raise FsdbError(
                f"fsdbreport failed for '{signal}':\n{r.stderr.strip()}\n"
                f"cmd: {' '.join(cmd)}\n"
                f"(flags vary by Verdi version; override with --fsdbreport-args)")
        changes: List[Tuple[int, Optional[int]]] = []
        with open(out_path) as f:
            for line in f:
                m = _VC_RE.match(line)
                if not m:
                    continue
                t = int(m.group(1))
                v = _parse_value(m.group(2))
                changes.append((t, v))
        if not changes:
            raise FsdbError(
                f"fsdbreport produced no value changes for '{signal}'. "
                f"Check the signal path (FSDB uses '/' hierarchy: "
                f"{to_fsdb_path(signal)}) or override --fsdbreport-args.")
        return changes
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _parse_value(tok: str) -> Optional[int]:
    t = tok.lower().replace("_", "")
    if "x" in t or "z" in t:
        return None
    if "'" in t:                       # verilog literal e.g. 32'h1a2b
        _, _, rest = t.partition("'")
        base = {"h": 16, "d": 10, "b": 2, "o": 8}.get(rest[0], 16)
        try:
            return int(rest[1:], base)
        except ValueError:
            return None
    try:
        return int(t, 16)
    except ValueError:
        return None


def iter_pc_samples_fsdbreport(fsdb: str, tool: str,
                               clock: str, pc: str,
                               valid: Optional[str] = None,
                               sample_edge: str = "rising",
                               extra_args: Optional[List[str]] = None,
                               ) -> Iterator[Tuple[int, int]]:
    """Yield (tick, pc_value) by merging per-signal fsdbreport dumps."""
    args = extra_args or []
    clk_vc = _dump_signal(tool, fsdb, to_fsdb_path(clock), args)
    pc_vc = _dump_signal(tool, fsdb, to_fsdb_path(pc), args)
    val_vc = _dump_signal(tool, fsdb, to_fsdb_path(valid), args) if valid else None

    want = 1 if sample_edge == "rising" else 0
    tick = 0
    pi = vi = 0
    cur_pc: Optional[int] = None
    cur_valid: Optional[int] = None
    prev_clk: Optional[int] = None

    for t, cv in clk_vc:
        while pi < len(pc_vc) and pc_vc[pi][0] <= t:
            cur_pc = pc_vc[pi][1]
            pi += 1
        if val_vc:
            while vi < len(val_vc) and val_vc[vi][0] <= t:
                cur_valid = val_vc[vi][1]
                vi += 1
        if cv is None:
            prev_clk = None
            continue
        if prev_clk is not None and prev_clk != cv and cv == want:
            if (val_vc is None or cur_valid == 1) and cur_pc is not None:
                yield tick, cur_pc
            tick += 1
        prev_clk = cv


# ----------------------------------------------------------------------
# Path 2: fsdb2vcd conversion (scope-restricted)
# ----------------------------------------------------------------------
def _cache_path(src: str, scope: Optional[str], kind: str) -> str:
    tag = "" if not scope else "." + "".join(
        c if c.isalnum() else "_" for c in scope)
    return os.path.join(tempfile.gettempdir(),
                        os.path.basename(src) + tag
                        + ".wavescope." + kind + ".vcd")


def cache_fresh(src: str, out: str) -> bool:
    """Reuse a previous conversion if it is newer than the source --
    every skipped conversion is a license checkout (and possibly a
    queue wait) saved on license-managed sites."""
    try:
        return (os.path.exists(out) and os.path.getsize(out) > 0
                and os.path.getmtime(out) >= os.path.getmtime(src))
    except OSError:
        return False


def convert_to_vcd(fsdb: str, tool: str, scope: Optional[str] = None,
                   extra_args: Optional[List[str]] = None,
                   keep: bool = False, reconvert: bool = False) -> str:
    out = _cache_path(fsdb, scope, "fsdb")
    if not reconvert and cache_fresh(fsdb, out):
        import sys
        print("[wavescope] reusing cached conversion %s "
              "(--reconvert to force)" % out, file=sys.stderr)
        return out
    cmd = [tool, fsdb, "-o", out]
    if scope:
        cmd += ["-s", scope if scope.startswith("/") else to_fsdb_path(scope)]
    cmd += (extra_args or [])
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode != 0 or not os.path.exists(out):
        raise FsdbError(
            f"fsdb2vcd failed:\n{r.stderr.strip()}\ncmd: {' '.join(cmd)}\n"
            f"(flags vary by Verdi version; override with --fsdb2vcd-args)")
    return out


def iter_pc_changes_fsdbreport(fsdb: str, tool: str, pc: str,
                               valid: Optional[str] = None,
                               extra_args: Optional[List[str]] = None,
                               ) -> Iterator[Tuple[int, int]]:
    """(time, pc) changes without a clock signal, valid-gated if given."""
    args = extra_args or []
    pc_vc = _dump_signal(tool, fsdb, to_fsdb_path(pc), args)
    if not valid:
        for t, v in pc_vc:
            if v is not None:
                yield t, v
        return
    val_vc = _dump_signal(tool, fsdb, to_fsdb_path(valid), args)
    vi = 0
    cur_valid: Optional[int] = None
    cur_pc: Optional[int] = None
    for t, v in pc_vc:
        while vi < len(val_vc) and val_vc[vi][0] <= t:
            nv = val_vc[vi][1]
            if nv == 1 and cur_valid != 1 and cur_pc is not None:
                yield val_vc[vi][0], cur_pc
            cur_valid = nv
            vi += 1
        if v is not None:
            cur_pc = v
            if cur_valid == 1 or cur_valid is None:
                yield t, v
