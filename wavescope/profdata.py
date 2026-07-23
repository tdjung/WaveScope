"""Shared profile data model.

Both engines produce this structure: `default` (wavescope.simcore, the
literal transcription of the simulator reference, plus marked ADAPTER
deviations) and the FROZEN `legacy` engine (wavescope.profiler, kept
for reference/comparison but no longer maintained).  Keeping the model
here lets the default engine stand alone without importing the legacy
engine module.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

from .disasm import BinaryInfo

# Order matches the user's simulator output for line-level diffing.
EVENTS = ["Ir", "Dr", "Dw", "Bc", "Bi", "Bim", "Cy"]
E_IR, E_DR, E_DW, E_BC, E_BI, E_BIM, E_CY = range(len(EVENTS))
N_EVENTS = len(EVENTS)


class CallSite(object):
    """Aggregated call info for callgrind `calls=` lines."""
    __slots__ = ("count", "inclusive")

    def __init__(self):
        self.count = 0
        self.inclusive = [0] * N_EVENTS


class Profile:
    def __init__(self, binary: BinaryInfo):
        self.binary = binary
        self.self_cost: Dict[int, List[int]] = defaultdict(lambda: [0] * N_EVENTS)
        # (call_pc, callee_start) -> CallSite   [simulator-style pure-PC key]
        self.calls: Dict[Tuple[int, int], CallSite] = defaultdict(CallSite)
        self.total: List[int] = [0] * N_EVENTS
        # intra-function control flow for callgrind jcnd=/jump= lines
        self.cond_jumps: Dict[Tuple[int, int], int] = defaultdict(int)    # (src,dst) -> landings (incl. fall-through)
        self.uncond_jumps: Dict[Tuple[int, int], int] = defaultdict(int)  # (src,dst) -> count
        self.debug = None            # optional DebugTrace
        self.root_log = None         # --debug-roots: bottom-frame events
        self.cur_tick = None
        self.unknown_pcs = 0
        self.exceptions = 0
        self.healed_returns = 0
        self.unmatched_returns = 0
        self.drained_frames = 0
        self.drained_top: List[Tuple[int, int, int]] = []  # (call_pc, callee, acc_ir)
        # --- epc-mode diagnostics ---
        self.epc_mode = False        # any signal-driven ISR mode
        self.isr_kind = None         # 'epc' | 'level' when signal-driven        # an epc value was actually seen
        self.spurious_epc = 0        # same-function mepc changes suppressed
        self.flow_anomalies = 0      # unexplained discontinuities (epc mode)
        self.orphan_xrets = 0        # xret committed with no ISR context
        self.exit_rejects = 0        # v0.20.5: pc==resume arrivals rejected
                                     # as exits because the handler's own
                                     # flow (shared millicode/subroutines)
                                     # explains them architecturally
        self.guarded_unwinds = 0     # unwinds stopped by the landing floor
                                     # (v0.20.3: pops that would have closed
                                     # a frame the landing pc is still inside)
        self.discontinuity_returns = 0  # v0.20.4: frames closed because a
                                     # flow discontinuity with NO committed
                                     # return/jump landed exactly on an open
                                     # frame's return address (macro-fused
                                     # auipc+jr / movw+bx style pairs where
                                     # only the first pc is sampled, veneers
                                     # and far-stubs running through
                                     # untracked code, dropped jump commits)
        self.isr_open = 0            # ISR contexts alive at end of trace

    def _update(self, pc: int, ev: int, n: int, stack: list) -> None:
        self.self_cost[pc][ev] += n
        self.total[ev] += n
        for fr in stack:
            fr.acc[ev] += n
