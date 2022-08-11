# Queries for Divergent Representations

Sometimes, while applying optimizations to a program, a C compiler will
produce code that represents a single source code variable with different
representations that produce divergent program semantics when inputs cause
undefined behavior.

These are queries for identifying undefined behavior when it occurs.

Perform a 'bottom-up' search using `binja-scripts` over compiled binaries with
Binary Ninja.

Perform a 'top-down' search using `codeql-queries` over source code with
CodeQL.
