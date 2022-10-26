# Part-3: Guarding GOT segment against AW attempt (40 pt)

## Problem Statement

We consider (assume) legitimate updates can only be made by _dl_runtime_resolve*() function. Therefore any overwrite attempts outside the _dl_runtime_resolve*() function context we consider to be a suspicious event to raise the alarm and stop the execution of the process. To implement the solution, you must instrument memory write instructions and check their destinations at runtime. In case the memory address falls inside the range of GOT section, you need to trace back function call history and confirm the instruction is called from a legitimate function.

