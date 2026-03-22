# ttd-ldb
Run SBCL's low-level debugger against a dead process.

![demo](demo.gif)

## Background
[SBCL](https://sbcl.org) is a native-code Common Lisp compiler. I used to use it at work, deploying code primarily to Windows. While we found SBCL to be stable, we encountered one fatal, non-deterministic bug that showed up only on Windows. We used [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-overview), specifically its [Time Travel Debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview) feature, to root-cause and fix the bug.

The bug turned out to be a Windows-only error in the conservative stack scanning logic in the garbage collector. Finding this bug involved stepping through compiled Lisp machine code, checking page tables, and tracking memory across garbage collections. The SBCL runtime and garbage collector are written in C, so we had some limited support in WinDbg. But any time we were inside compiled Lisp code, the support dropped to zero. For instance, we did not have Lisp backtraces because SBCL uses a different stack format than C.

I developed `ttd-ldb` to solve this problem.