/**
 * @name Divergent Representations in For Loops
 * @problem.severity warning
 * @description Finds candidate code patterns in for loops that might be 
 *  compiled as divergent representations when optimized. 
 */

import cpp

predicate isInStmt(Stmt needle, Stmt haystack) {
    haystack.getAChild*() = needle or isInStmt(needle, haystack.getAChild*())
}

predicate isInExpr(Expr needle, Expr haystack) {
    haystack.getAChild*() = needle or isInExpr(needle, haystack.getAChild*())
}

predicate varCrementedInLoop(VariableAccess access, CrementOperation op, ForStmt loop) {
    (
        isInStmt(access.getBasicBlock(), loop.getStmt()) or
        isInExpr(access, loop.getUpdate())
    ) and 
    op.getAnOperand() = access
}

predicate varDeclaredOutsideLoop(Variable v, ForStmt loop) {
    not (
        loop.getStmt().getAChild*() = v.getADeclarationEntry().getDeclaration() or
        loop.getInitialization().getAChild*() = v.getADeclarationEntry().getDeclaration()
    ) 
}

predicate varAccessesArrayInLoop(VariableAccess access, ArrayExpr expr, ForStmt loop) {
    expr.getArrayOffset() = access and
    (
        isInStmt(access.getBasicBlock(), loop.getStmt()) or
        isInExpr(access, loop.getCondition())
    )
}

predicate varAccessArrayInCondition(VariableAccess access, ArrayExpr expr, ForStmt loop) {
    expr.getArrayOffset() = access and 
    isInExpr(access, loop.getCondition())
}

predicate varAccessAfterLoop(VariableAccess access, ForStmt loop) {
    access.getLocation().getStartLine() > loop.getLocation().getEndLine()
}

from 
    //Function f, 
    LocalVariable v, 
    IntType int_type,
    VariableAccess v_access_crement,
    VariableAccess v_access_array, 
    ArrayExpr array_expr,
    ForStmt for_loop,
    CrementOperation crement_op
where 
    // Debug in sqlite3_str_vappendf.
    // v.getName() = "i" and 
    // f.getName() = "xmlBuildURI" and 
    // v.getFunction() = f and 

    // Variable is an integer.
    v.getType() = int_type and 
    
    // Variable is incremented inside loop.
    v_access_crement.getTarget() = v and 
    varCrementedInLoop(v_access_crement, crement_op, for_loop) and

    // Variable is declared outside the loop.
    varDeclaredOutsideLoop(v, for_loop) and

    // Variable accesses array inside loop.
    v_access_array.getTarget() = v and
    // varAccessesArrayInLoop(v_access_array, array_expr, for_loop) and
    varAccessArrayInCondition(v_access_array, array_expr, for_loop) and

    // Variable is used outside of (after) the loop.
    exists (VariableAccess access_after_loop | 
            access_after_loop.getTarget() = v | 
            varAccessAfterLoop(access_after_loop, for_loop))

select v, 
       "increment in loop:", v_access_crement,
       "mem access in loop:", v_access_array