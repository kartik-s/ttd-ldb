#include <cstdio>

#include <dbgeng.h>
#include <errhandlingapi.h>
#include <excpt.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <process.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <synchapi.h>
#include <sysinfoapi.h>
#include <vcruntime.h>
#include <winbase.h>
#include <winerror.h>
#include <winnt.h>
#include <winternl.h>

thread_local IDebugAdvanced *dbg_adv = nullptr;
thread_local IDebugControl *dbg_ctrl = nullptr;
thread_local IDebugDataSpaces4 *dbg_mem = nullptr;
thread_local IDebugSymbols  *dbg_syms = nullptr;
thread_local IDebugSystemObjects  *dbg_sysobjs = nullptr;

static const char *remote_options = nullptr;
static DWORD alloc_gran;
static DWORD page_size;

void load_remote_pages(ULONG64 addr, ULONG num_bytes) {
    ULONG64 page_addr = addr - (addr % page_size);

    while (page_addr < addr + num_bytes) {
        MEMORY_BASIC_INFORMATION mem_info;
        ULONG64 valid_base;
        ULONG valid_size;

        VirtualQuery((void *) page_addr, &mem_info, sizeof(mem_info));

        if (mem_info.State == MEM_FREE) {
            ULONG64 base_addr = page_addr - (page_addr % alloc_gran);

            VirtualAlloc((void *) base_addr, alloc_gran, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            dbg_mem->GetValidRegionVirtual(base_addr, alloc_gran, &valid_base, &valid_size);
            page_addr = base_addr + alloc_gran;
        } else {
            DWORD old_prot;

            VirtualProtect((void *) page_addr, mem_info.RegionSize, PAGE_EXECUTE_READWRITE, &old_prot);
            dbg_mem->GetValidRegionVirtual(page_addr, mem_info.RegionSize, &valid_base, &valid_size);
            page_addr += mem_info.RegionSize;
        }

        dbg_mem->ReadVirtualUncached(valid_base, (void *) valid_base, valid_size, nullptr);
    }
}

LONG access_violation_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    int rw_flag = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    ULONG64 fault_addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    ULONG64 base_addr = fault_addr - (fault_addr % alloc_gran);

    // printf("access violation at %p (rw=%d, rip=%p, rsp=%p, rax=%p)\n", (void *) fault_addr, rw_flag, ExceptionInfo->ExceptionRecord->ExceptionAddress, (void *) ExceptionInfo->ContextRecord->Rsp, (void *) ExceptionInfo->ContextRecord->Rax);
    load_remote_pages(base_addr, alloc_gran);

    if (rw_flag == 8) {
        FlushInstructionCache(GetCurrentProcess(), (void *) base_addr, alloc_gran);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

unsigned WINAPI ldb_monitor_trampoline(void *arg) {
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugDataSpaces4), (void **) &dbg_mem);
    DebugConnect(remote_options, __uuidof(IDebugSymbols), (void **) &dbg_syms);
    DebugConnect(remote_options, __uuidof(IDebugSystemObjects), (void **) &dbg_sysobjs);

    AddVectoredExceptionHandler(TRUE, access_violation_handler);

    ULONG num_loaded;
    ULONG num_unloaded;
    ULONG sbcl_index;

    dbg_syms->GetNumberModules(&num_loaded, &num_unloaded);
    dbg_syms->GetModuleByModuleName("sbcl", 0, &sbcl_index, nullptr);

    for (int i = 0; i < num_loaded; i += 1) {
        if (i == sbcl_index) {
            continue;
        }

        DEBUG_MODULE_PARAMETERS mod_info;
        HMODULE mod;

        dbg_syms->GetModuleParameters(1, NULL, i, &mod_info);
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR) mod_info.Base, &mod);

        if (mod) {
            continue;
        }

        load_remote_pages(mod_info.Base, mod_info.Size);
    }

    ULONG64 offset;
    ULONG type_id;
    DWORD sbcl_thread_tls_index;
    ULONG64 sbcl_base;

    dbg_syms->GetOffsetByName("sbcl!sbcl_thread_tls_index", &offset);
    dbg_syms->GetOffsetTypeId(offset, &type_id, &sbcl_base);
    dbg_syms->ReadTypedDataVirtual(offset, sbcl_base, type_id, &sbcl_thread_tls_index, sizeof(sbcl_thread_tls_index), nullptr);

    ULONG64 teb;

    dbg_sysobjs->GetCurrentThreadTeb(&teb);
    load_remote_pages(teb, sizeof(TEB));
    TlsSetValue(sbcl_thread_tls_index, ((TEB *) teb)->TlsSlots[sbcl_thread_tls_index]);

    ULONG64 jump_addr;

    dbg_syms->GetOffsetByName("sbcl!ldb_monitor",  &jump_addr);
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
    alloc_gran = sys_info.dwAllocationGranularity;
    page_size = sys_info.dwPageSize;    

    HANDLE ldb_thread = (HANDLE) _beginthreadex(nullptr, 0, ldb_monitor_trampoline, nullptr, CREATE_SUSPENDED, nullptr);
    printf("%p\n", ldb_thread);

    DWORD orig_context_len;
    CONTEXT *orig_context;

    DWORD thread_context_len;
    CONTEXT *thread_context;

    if (!InitializeContext(nullptr, CONTEXT_ALL, nullptr, &orig_context_len)) {
        printf("orig len %lx\n", GetLastError());
    }
    char orig_context_buf[orig_context_len];
    if (!InitializeContext(orig_context_buf, CONTEXT_ALL, &orig_context, &orig_context_len)) {
        printf("orig ctx %lx\n", GetLastError());
    }

    if (!InitializeContext(nullptr, CONTEXT_ALL, nullptr, &thread_context_len)) {
        printf("thread len%lx\n", GetLastError());
    }
    char thread_context_buf[thread_context_len];
    if (!InitializeContext(thread_context_buf, CONTEXT_ALL, &thread_context, &thread_context_len)) {
        printf("thread ctx: %lx\n", GetLastError());
    }

    HRESULT res = dbg_adv->GetThreadContext(orig_context, orig_context_len);
    printf("get remote context: %lx\n", res);
    BOOL res2 = GetThreadContext(ldb_thread, thread_context);
    printf("get local context: %d\n", res2);

    // thread_context->SegFs = orig_context->SegFs;
    // thread_context->SegGs = orig_context->SegGs;
    thread_context->Rbp = orig_context->Rbp;
    // thread_context->Rsp = orig_context->Rsp;

    res2 = SetThreadContext(ldb_thread, thread_context);
    if (!res2) {
        printf("%lx\n", GetLastError());
    }
    ResumeThread(ldb_thread);
    WaitForSingleObject(ldb_thread, INFINITE);
    CloseHandle(ldb_thread);

    return 0;
}