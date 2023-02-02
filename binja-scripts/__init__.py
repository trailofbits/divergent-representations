"""
__init__.py

    Plugin module if commercial is not available.
"""
import binaryninja.log as log
from binaryninja.plugin import PluginCommand

from .fdr import find_divergent_representations


def run_all(bv):
    total = 0
    for function in bv.functions:
        total += find_divergent_representations(function, disass=True)

    log.log_info(f"Potential divergent representation instances for binary: {total}")


def run_for_function(_, func):
    log.log_info(
        f"Potential divergent representation instances for {func.name}: {find_divergent_representations(func, disass=True)}"
    )


PluginCommand.register(
    "Binja Div Reps\\Find in all functions",
    "Identify divergent representations across every function",
    run_all,
)

PluginCommand.register_for_function(
    "Binja Div Reps\\Find in highlighted function",
    "Identify divergent representations in a single function",
    run_for_function,
)
