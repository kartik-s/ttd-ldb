#include <cstdio>

#include <dbgeng.h>
#include <errhandlingapi.h>
#include <excpt.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <minwinbase.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <sysinfoapi.h>
#include <vcruntime.h>
#include <winbase.h>
#include <winerror.h>
#include <winnt.h>

thread_local IDebugAdvanced *dbg_adv = nullptr;
thread_local IDebugControl *dbg_ctrl = nullptr;
thread_local IDebugDataSpaces4 *dbg_mem = nullptr;
thread_local IDebugSymbols  *dbg_syms = nullptr;

static const char *remote_options = nullptr;
static DWORD page_size;

LONG access_violation_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    int rw_flag = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    ULONG64 fault_addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    ULONG64 page_addr = fault_addr - (fault_addr % page_size);
    void *page;
    MEMORY_BASIC_INFORMATION mem_info;

    if (fault_addr == 0xFFFFFFFFFFFFFFFF) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    printf("access violation at %p (rw=%d, rip=%p, rsp=%p, rax=%p)\n", (void *) fault_addr, rw_flag, ExceptionInfo->ExceptionRecord->ExceptionAddress, (void *) ExceptionInfo->ContextRecord->Rsp, (void *) ExceptionInfo->ContextRecord->Rax);
    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "access violation at %p (rw=%d)\n", (void *) fault_addr, rw_flag);

    VirtualQuery((void *) page_addr, &mem_info, sizeof(mem_info));

    if (mem_info.State == MEM_FREE) {
        ULONG num_bytes_read;
        dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "loading page at %p\n", (void *) page_addr);
        page = VirtualAlloc((void *) page_addr, page_size, MEM_COMMIT | MEM_RESERVE, (rw_flag == 8) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
        dbg_mem->ReadVirtualUncached(page_addr, (void *) page_addr, page_size, &num_bytes_read);
    }

    DWORD old_prot;

    VirtualProtect((void *) page_addr, page_size, (rw_flag == 8) ? PAGE_EXECUTE_READ : PAGE_READWRITE, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), page, page_size);

    return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI ldb_monitor_trampoline(LPVOID arg) {
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugDataSpaces4), (void **) &dbg_mem);
    DebugConnect(remote_options, __uuidof(IDebugSymbols), (void **) &dbg_syms);
    
    ULONG64 jump_addr;

    dbg_syms->GetOffsetByName("sbcl!ldb_monitor",  &jump_addr);
    AddVectoredExceptionHandler(TRUE, access_violation_handler);
    ((void (*)()) jump_addr)();

    return 0;
}

int main(int argc, char **argv) {
    remote_options = argv[1];
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugSymbols), (void **) &dbg_syms);

    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "debug clients connected, hello!\n");

    static SYSTEM_INFO sys_info;

    GetSystemInfo(&sys_info);
    page_size = sys_info.dwAllocationGranularity;

    CONTEXT orig_context;
    CONTEXT thread_context;
    DWORD orig_context_len = sizeof(orig_context);
    DWORD thread_context_len = sizeof(thread_context);
    HANDLE ldb_thread = CreateThread(nullptr, 0, ldb_monitor_trampoline, nullptr, CREATE_SUSPENDED, nullptr);

    InitializeContext(&orig_context, CONTEXT_ALL, nullptr, &orig_context_len);
    InitializeContext(&thread_context, CONTEXT_ALL, nullptr, &thread_context_len);

    dbg_adv->GetThreadContext(&orig_context, orig_context_len);
    // GetThreadContext(ldb_thread, &thread_context);
    
    // thread_context.SegFs = orig_context.SegFs;
    // SetThreadContext(ldb_thread, &thread_context);

    ResumeThread(ldb_thread);
    WaitForSingleObject(ldb_thread, INFINITE);
    CloseHandle(ldb_thread);

    return 0;
}