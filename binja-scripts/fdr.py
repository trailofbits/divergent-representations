"""
fdr.py

Find Divergent Representations

Usage: import in Binary Ninja scripting console

>>> import fdr
>>> for function in bv.functions:
    fdr.find_divergent_representations(function)
"""
from queue import Queue

import binaryninja as bn
import binaryninja.log as log

MLIL_EXTEND_INSTRUCTIONS = [
    bn.MediumLevelILOperation.MLIL_SX,
    bn.MediumLevelILOperation.MLIL_ZX,
]

LLIL_EXTEND_INSTRUCTIONS = [
    bn.LowLevelILOperation.LLIL_ZX,
    bn.LowLevelILOperation.LLIL_SX,
]

MLIL_ARITHMETIC_INSTRUCTIONS = [
    bn.MediumLevelILOperation.MLIL_ADD,
    bn.MediumLevelILOperation.MLIL_SUB,
]


def find_divergent_representations(f, disass=False):
    """Given a function, print the MLIL SSA instruction and assembly
    instruction address of any divergent representation candidates found in the
    function.
    """
    instances = 0
    try:
        if not f.mlil:
            return instances

    # If binja has failed to analyze the function, the mlil attribute will be
    # inaccessible.
    except AttributeError as err:
        print(f"ERROR analyzing function: {f.name} - {err}")
        return instances

    if not f.mlil.ssa_form:
        return instances

    for insn in f.mlil.ssa_form.instructions:
        if (
            is_phi_consuming_own_def(f, insn)
            and get_downcast_uses(f, insn)
            and are_vars_consumed_different_sizes(f, insn)
            and is_used_in_64bit_operation(f, insn)
        ):

            result = f"{f.name}@{hex(insn.address)}: {insn}"
            if disass:
                log.log_info(result)
            else:
                print(result)

            instances += 1

    return instances


def is_phi_consuming_own_def(f, phi_node):
    """Given a function and a MLIL SSA instruction of a Phi node operation,
    return True if the Phi node consumes a variable that is set by the Phi
    node, indicating that the Phi node affects a loop control variable.
    """
    if phi_node.operation != bn.MediumLevelILOperation.MLIL_VAR_PHI:
        return False

    # Iterate through all uses of the variable defined by the phi node.
    for dest in phi_node.vars_written:
        uses = get_mlil_ssa_var_uses(f, dest)
        for use in uses:
            # Check whether any uses define one of the variables consumed by
            # the phi node.

            # Check that the operation to set this use is 64-bit.
            if (
                use.operation == bn.MediumLevelILOperation.MLIL_SET_VAR_SSA
                and use.src.operation in MLIL_ARITHMETIC_INSTRUCTIONS
            ):
                for written in use.vars_written:
                    if written in phi_node.vars_read:
                        return True
    return False


def get_downcast_uses(f, phi_node):
    """Given a function and a MLIL SSA instruction of a Phi node operation,
    return True if the Phi node sets a variable that is downcast to a smaller
    variable, indicating that the 64-bit value is being treated elsewhere as a
    smaller value.
    """
    if phi_node.operation != bn.MediumLevelILOperation.MLIL_VAR_PHI:
        return False

    downcast_uses = []
    for var_written in phi_node.vars_written:
        uses = get_mlil_ssa_var_uses(f, var_written)
        for use in uses:
            if use.operation == bn.MediumLevelILOperation.MLIL_SET_VAR_SSA:
                llil_use = use.llil.src
                if llil_use.operation in LLIL_EXTEND_INSTRUCTIONS:
                    downcast_uses.append(use)

    return downcast_uses


def is_used_in_64bit_operation(f, phi_node):
    """Given a function and a MLIL SSA instruction of a Phi node operation,
    return True if the Phi node defines a variable that gets used in a 64-bit
    arithmetic operation. Otherwise return False.
    """

    if phi_node.operation != bn.MediumLevelILOperation.MLIL_VAR_PHI:
        return False

    for var_def in phi_node.vars_written:
        for use in get_mlil_ssa_var_uses(f, var_def):
            if (
                use.operation == bn.MediumLevelILOperation.MLIL_SET_VAR_SSA
                and use.src.operation in MLIL_ARITHMETIC_INSTRUCTIONS
            ):
                return True
    return False


def are_vars_consumed_different_sizes(f, phi_node):
    """Given a function and a MLIL SSA instruction of a Phi node operation,
    return True if the variables consumed by the Phi node are defined by
    different sizes (e.g. is one variable defined from 64-bit arithmetic, while
    the other was sign extended from a 32-bit value).
    """

    if phi_node.operation != bn.MediumLevelILOperation.MLIL_VAR_PHI:
        return False

    def_extend_from_smaller = False
    def_operation_on_64 = False
    for var_read in phi_node.vars_read:
        var_def = get_mlil_ssa_var_def(f, var_read)
        if var_def is None:
            continue
        if var_def.operation == bn.MediumLevelILOperation.MLIL_SET_VAR_SSA:
            if var_def.src.operation in MLIL_EXTEND_INSTRUCTIONS:
                def_extend_from_smaller = True
            elif var_def.src.size == 8:
                def_operation_on_64 = True

    return def_extend_from_smaller and def_operation_on_64


def get_mlil_ssa_at(f, address):
    """Given a function and the address of an instruction inside the function,
    return the instruction at the address in MLIL SSA form.
    """
    return f.get_low_level_il_at(address).medium_level_il.ssa_form


def get_mlil_ssa_var_def(f, ssa_var):
    """Given a function and an MLIL SSA variable, return the def site of the
    SSA variable within the function.
    """
    return f.mlil.ssa_form.get_ssa_var_definition(ssa_var)


def get_mlil_ssa_var_uses(f, ssa_var):
    """Given a function and an MLIL SSA variable, return all uses of the SSA
    variable within the function.
    """
    return f.mlil.ssa_form.get_ssa_var_uses(ssa_var)
