# ttd-ldb
Run SBCL's low-level debugger (LDB) against a dead process.

![demo](demo.gif)

## Background
[SBCL](https://sbcl.org) is a native-code Common Lisp compiler. I used to use it at work, deploying code primarily to Windows. While we found SBCL to be stable, we encountered one fatal, non-deterministic bug that showed up only on Windows. We used [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-overview), specifically its [Time Travel Debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview) feature, to root-cause and fix the bug.

The bug turned out to be a Windows-only error in the conservative stack scanning logic in the garbage collector. Finding this bug involved stepping through compiled Lisp machine code, checking page tables, and tracking memory across garbage collections. The SBCL runtime and garbage collector are written in C, so we had some limited support in WinDbg. But any time we were inside compiled Lisp code, the support dropped to zero. For instance, we did not have Lisp backtraces because SBCL uses a different stack format than C. You can see this in the WinDbg window in the demo GIF—the stack is a mess of hex values.

I developed `ttd-ldb` to solve this problem.

## How it works
`ttd-ldb` connects as a client to WinDbg's debug server, communicating with it using the `DbgEng` API. It starts as an empty process. The final thing it does is to query the remote process for the address of `ldb_monitor`, the entry point to SBCL's low-level debugger, and call into it. This immediately triggers an access violation because the code is not present in the process.

The setup process ensures that this access violation recovers into smooth execution of LDB instead of a crash. The first step is to set an access violation handler that copies the memory page containing the faulting address from the remote process into the local one and then restarts execution from the faulting instruction.

The second step is to create a local thread with the same stack and stack pointer as the remote thread. The local thread runs a function that will eventually call into LDB. It begins by loading all the DLLs that are loaded in the remote process into the local one by name. ASLR removes any guarantee that the local DLLs will load into the same addresses as in the remote process. This is a problem because all the code paged in from the remote process calls into external DLLs through the remote import address table (IAT), which contains call addresses that don't work in the local address space because of ASLR.

Each IAT entry consists of a function identifier, usually a name, and a function address. Patching the IAT by looking up each identifier in the appropriate local DLL and writing back the local function address fixes the ASLR issue.

Next, the thread copies its stack extents from the remote thread so that stack bounds checks line up with the remote stack that the parent thread set. The thread also copies a TLS value from the remote thread so that `get_sb_vm_thread()` returns the correct thread.

Finally, the thread prepares to call into LDB. It stores the remote thread's context in the local thread's interrupt context array. LDB consults the interrupt context array to determine where the Lisp code stopped, so this ensures that LDB thinks it is wherever the remote thread was executing at the current point in the TTD trace.

Once this is set, the thread calls `ldb_monitor`, and the debugger starts as if it were running in the original process.