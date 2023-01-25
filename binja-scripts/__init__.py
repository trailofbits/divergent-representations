"""
__init__.py

    Plugin module if commercial is not available.
"""
from binaryninja.plugin import PluginCommand

from .fdr import find_divergent_representations


def run_all(bv):
    for function in bv.functions:
        find_divergent_representations(function, disass=True)


def run_for_function(_, func):
    find_divergent_representations(func, disass=True)


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
