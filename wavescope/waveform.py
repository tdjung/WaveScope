"""Waveform input dispatch: one entry point for VCD / FSDB (and future FST).

    open_pc_stream(...)  -> iterator of (clock_tick, pc_value)
    prepare_for_scan(...) -> a VCD path usable by scan (converting if needed)
"""

import sys
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from . import fsdb as fsdb_mod
from .vcd_reader import (changes_to_ticks, get_timescale, iter_pc_changes,
                         iter_pc_samples, parse_period)


@dataclass
class WaveConfig:
    verdi_home: Optional[str] = None
    fsdb_scope: Optional[str] = None
    fsdbreport_args: List[str] = field(default_factory=list)
    fsdb2vcd_args: List[str] = field(default_factory=list)


def _is_fsdb(path: str) -> bool:
    return path.lower().endswith(".fsdb")


def _no_tools_msg(tools: "fsdb_mod.VerdiTools") -> str:
    return ("FSDB input requires Synopsys Verdi utilities, but neither "
            "'fsdbreport' nor 'fsdb2vcd' was found.\n"
            "  - pass --verdi-home /path/to/verdi (or set $VERDI_HOME), or\n"
            "  - add the Verdi bin directory to PATH, or\n"
            "  - convert manually: fsdb2vcd input.fsdb -o out.vcd "
            "[-s /top/scope] and pass the VCD.")


def open_pc_stream(path: str, clock: Optional[str], pc: str,
                   valid: Optional[str] = None,
                   sample_edge: str = "rising",
                   clock_period: Optional[str] = None,
                   cfg: Optional[WaveConfig] = None,
                   ) -> Iterator[Tuple[int, int]]:
    cfg = cfg or WaveConfig()
    if not _is_fsdb(path):
        if clock:
            return iter_pc_samples(path, clock, pc,
                                   sample_edge=sample_edge, valid_name=valid)
        # clockless: derive cycle grid from PC change times
        period = None
        if clock_period:
            period = parse_period(clock_period, get_timescale(path))
        changes = iter_pc_changes(path, pc, valid_name=valid)
        period, samples = changes_to_ticks(changes, period=period)
        print(f"[wavescope] no clock signal: using "
              f"{'given' if clock_period else 'auto-detected'} period of "
              f"{period} dump time units as 1 cycle", file=sys.stderr)
        return samples

    tools = fsdb_mod.find_tools(cfg.verdi_home)
    if tools.fsdbreport:
        print(f"[wavescope] FSDB: extracting signals via fsdbreport "
              f"({tools.fsdbreport})", file=sys.stderr)
        if clock:
            return fsdb_mod.iter_pc_samples_fsdbreport(
                path, tools.fsdbreport, clock, pc, valid=valid,
                sample_edge=sample_edge, extra_args=cfg.fsdbreport_args)
        changes = fsdb_mod.iter_pc_changes_fsdbreport(
            path, tools.fsdbreport, pc, valid=valid,
            extra_args=cfg.fsdbreport_args)
        period = int(clock_period) if clock_period else None
        period, samples = changes_to_ticks(changes, period=period)
        print(f"[wavescope] no clock signal: period={period} "
              f"fsdb time units = 1 cycle", file=sys.stderr)
        return samples
    if tools.fsdb2vcd:
        print(f"[wavescope] FSDB: converting via fsdb2vcd "
              f"({tools.fsdb2vcd})"
              + (f", scope={cfg.fsdb_scope}" if cfg.fsdb_scope else
                 " -- consider --fsdb-scope to speed this up"),
              file=sys.stderr)
        vcd = fsdb_mod.convert_to_vcd(path, tools.fsdb2vcd,
                                      scope=cfg.fsdb_scope,
                                      extra_args=cfg.fsdb2vcd_args)
        return iter_pc_samples(vcd, clock, pc,
                               sample_edge=sample_edge, valid_name=valid)
    raise fsdb_mod.FsdbError(_no_tools_msg(tools))


def prepare_for_scan(path: str, cfg: Optional[WaveConfig] = None) -> str:
    """Return a VCD path for the scanner, converting FSDB if necessary."""
    cfg = cfg or WaveConfig()
    if not _is_fsdb(path):
        return path
    tools = fsdb_mod.find_tools(cfg.verdi_home)
    if not tools.fsdb2vcd:
        raise fsdb_mod.FsdbError(
            "Scanning an FSDB requires fsdb2vcd (fsdbreport needs known "
            "signal names, but scan's job is to discover them).\n"
            + _no_tools_msg(tools)
            + "\nTip: restrict with --fsdb-scope to keep the VCD small.")
    print("[wavescope] FSDB: converting for scan via fsdb2vcd"
          + (f", scope={cfg.fsdb_scope}" if cfg.fsdb_scope else
             " -- STRONGLY consider --fsdb-scope for large dumps"),
          file=sys.stderr)
    return fsdb_mod.convert_to_vcd(path, tools.fsdb2vcd,
                                   scope=cfg.fsdb_scope,
                                   extra_args=cfg.fsdb2vcd_args)
