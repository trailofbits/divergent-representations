/**
 * @name Divergent Representations in While Loops
 * @problem.severity warning
 * @description Finds candidate code patterns in while loops that might be
 *  compiled as divergent representations when optimized.
 */

import cpp

predicate isInStmt(Stmt needle, Stmt haystack) {
    haystack.getAChild*() = needle or isInStmt(needle, haystack.getAChild*())
}

predicate isInExpr(Expr needle, Expr haystack) {
    haystack.getAChild*() = needle or isInExpr(needle, haystack.getAChild*())
}

predicate varCrementedInLoop(VariableAccess access, CrementOperation op, WhileStmt loop) {
    isInStmt(access.getBasicBlock(), loop.getStmt()) and
    op.getAnOperand() = access
}

predicate varDeclaredOutsideLoop(Variable v, WhileStmt loop) {
    not (loop.getStmt().getAChild*() = v.getADeclarationEntry().getDeclaration())
}

predicate varAccessesArrayInLoop(VariableAccess access, ArrayExpr expr, WhileStmt loop) {
    expr.getArrayOffset() = access and
    (
        isInStmt(access.getBasicBlock(), loop.getStmt()) or
        isInExpr(access, loop.getCondition())
    )
}

predicate varAccessArrayInCondition(VariableAccess access, ArrayExpr expr, WhileStmt loop) {
    expr.getArrayOffset() = access and
    isInExpr(access, loop.getCondition())
}

predicate varAccessAfterLoop(VariableAccess access, WhileStmt loop) {
    access.getLocation().getStartLine() > loop.getLocation().getEndLine()
}

from
    LocalVariable v,
    IntType int_type,
    VariableAccess v_access_crement,
    VariableAccess v_access_array,
    ArrayExpr array_expr,
    WhileStmt while_loop,
    CrementOperation crement_op
where
    // Variable is a signed integer.
    v.getType() = int_type and
    int_type.isSigned() and

    // Variable is incremented inside loop.
    v_access_crement.getTarget() = v and
    varCrementedInLoop(v_access_crement, crement_op, while_loop) and

    // Variable is declared outside the loop.
    varDeclaredOutsideLoop(v, while_loop) and

    // Variable accesses array inside loop.
    v_access_array.getTarget() = v and
    // varAccessesArrayInLoop(v_access_array, array_expr, while_loop) and
    varAccessArrayInCondition(v_access_array, array_expr, while_loop) and

    // Variable is used outside of (after) the loop.
    exists (VariableAccess access_after_loop |
            access_after_loop.getTarget() = v |
            varAccessAfterLoop(access_after_loop, while_loop))

select v,
       "increment in loop:", v_access_crement,
       "mem access in loop:", v_access_array
