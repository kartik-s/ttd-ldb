#include <cstdio>
#include <cstdlib>

#include <dbgeng.h>
#include <DbgHelp.h>
#include <errhandlingapi.h>
#include <excpt.h>
#include <fileapi.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <mmeapi.h>
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
thread_local IDebugSymbols3  *dbg_syms = nullptr;
thread_local IDebugSystemObjects  *dbg_sysobjs = nullptr;

static const char *remote_options = nullptr;
static DWORD alloc_gran;
static DWORD page_size;

void load_remote_pages(ULONG64 addr, ULONG num_bytes, BOOL is_stack) {
    ULONG64 page_addr = addr - (addr % page_size);
    BOOL first = TRUE;

    while (page_addr < addr + num_bytes) {
        MEMORY_BASIC_INFORMATION mem_info;
        ULONG64 valid_base;
        ULONG valid_size;

        VirtualQuery((void *) page_addr, &mem_info, sizeof(mem_info));

        if (mem_info.State == MEM_FREE) {
            ULONG64 base_addr = page_addr - (page_addr % alloc_gran);

            VirtualAlloc((void *) base_addr, alloc_gran, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            dbg_mem->GetValidRegionVirtual(first ? addr : base_addr, alloc_gran, &valid_base, &valid_size);
            page_addr = base_addr + alloc_gran;
        } else {
            DWORD old_prot;

            VirtualProtect((void *) page_addr, mem_info.RegionSize, PAGE_EXECUTE_READWRITE, &old_prot);
            dbg_mem->GetValidRegionVirtual(first ? addr : page_addr, mem_info.RegionSize, &valid_base, &valid_size);
            page_addr += mem_info.RegionSize;
        }

        dbg_mem->ReadVirtualUncached(valid_base, (void *) valid_base, valid_size, nullptr);
        first = FALSE;
    }
}

LONG access_violation_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    int rw_flag = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    ULONG64 fault_addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    ULONG64 base_addr = fault_addr - (fault_addr % alloc_gran);

    if (fault_addr == 0x0 || fault_addr == 0x20) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    BOOL is_stack = llabs((LONG64) fault_addr - (LONG64) ExceptionInfo->ContextRecord->Rsp) <= page_size;
    // printf("access violation at %p (rw=%d, rip=%p, rsp=%p, rax=%p)\n", (void *) fault_addr, rw_flag, ExceptionInfo->ExceptionRecord->ExceptionAddress, (void *) ExceptionInfo->ContextRecord->Rsp, (void *) ExceptionInfo->ContextRecord->Rax);
    load_remote_pages(is_stack ? fault_addr : base_addr, alloc_gran, is_stack);

    if (rw_flag == 8) {
        FlushInstructionCache(GetCurrentProcess(), (void *) base_addr, alloc_gran);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

unsigned WINAPI ldb_monitor_trampoline(void *arg) {
    // load remote modules
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
        MODULEINFO local_info;
        HMODULE mod;
        char buf[1024];

        ZeroMemory(&local_info, sizeof(local_info));

        dbg_syms->GetModuleParameters(1, NULL, i, &mod_info);
        dbg_syms->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, 0, buf, 1024, NULL);
        mod = LoadLibraryEx(buf, NULL, 0);
        GetModuleInformation(GetCurrentProcess(), mod, &local_info, sizeof(local_info));
        dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "%s: %p (bases match? %d)\n", buf, mod, mod_info.Base == (ULONG64) local_info.lpBaseOfDll);
#if 0
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR) mod_info.Base, &mod);

        if (mod) {
            continue;
        }

        load_remote_pages(mod_info.Base, mod_info.Size, FALSE);
#endif
    }

    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "loaded libraries\n");

    // fix up IAT
    DEBUG_MODULE_PARAMETERS sbcl_info;
    PIMAGE_SECTION_HEADER header;
    ULONG size;

    dbg_syms->GetModuleParameters(1, NULL, sbcl_index, &sbcl_info);

    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx((void *) sbcl_info.Base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &header);

    for (; import_desc->Name; import_desc++) {
        LPCSTR import_name = (LPCSTR) (sbcl_info.Base + import_desc->Name);

        dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "IAT: %s\n", import_name);
        HMODULE import_mod = GetModuleHandleA(import_name);

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) (sbcl_info.Base + import_desc->FirstThunk);
        PIMAGE_THUNK_DATA name = (PIMAGE_THUNK_DATA) (sbcl_info.Base + import_desc->Characteristics);

        for (; thunk->u1.Function; thunk++, name++) {
            LPCSTR proc_name = (LPCSTR) (sbcl_info.Base + ((PIMAGE_IMPORT_BY_NAME) (name->u1.AddressOfData))->Name);

            dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "%s @ %p\n", proc_name, thunk->u1.Function);
            thunk->u1.Function = (ULONGLONG) GetProcAddress(import_mod, proc_name);
        }
    }

    // set stack limits before anything else
    TEB *current_teb = NtCurrentTeb();
    TEB *remote_teb;
    DWORD old_prot;

    dbg_sysobjs->GetCurrentThreadTeb((PULONG64) &remote_teb);
    VirtualProtect(current_teb, sizeof(TEB), PAGE_READWRITE, &old_prot);
    current_teb->Reserved1[1] = remote_teb->Reserved1[1];
    current_teb->Reserved1[2] = remote_teb->Reserved1[2];

    // connect to debugger
#if 0
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugDataSpaces4), (void **) &dbg_mem);
    DebugConnect(remote_options, __uuidof(IDebugSymbols3), (void **) &dbg_syms);
    DebugConnect(remote_options, __uuidof(IDebugSystemObjects), (void **) &dbg_sysobjs);
#endif

    // set sb_vm_thread
    ULONG64 offset;
    ULONG type_id;
    DWORD sbcl_thread_tls_index;
    ULONG64 sbcl_base;

    dbg_syms->GetOffsetByName("sbcl!sbcl_thread_tls_index", &offset);
    dbg_syms->GetOffsetTypeId(offset, &type_id, &sbcl_base);
    dbg_syms->ReadTypedDataVirtual(offset, sbcl_base, type_id, &sbcl_thread_tls_index, sizeof(sbcl_thread_tls_index), nullptr);

    TlsSetValue(sbcl_thread_tls_index, remote_teb->TlsSlots[sbcl_thread_tls_index]);

    // run ldb
    DWORD remote_context_len;
    CONTEXT *remote_context;

    InitializeContext(nullptr, CONTEXT_INTEGER, nullptr, &remote_context_len);
    char remote_context_buf[remote_context_len];
    InitializeContext(remote_context_buf, CONTEXT_INTEGER, &remote_context, &remote_context_len);
    dbg_adv->GetThreadContext(remote_context, remote_context_len);

    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "about to set interrupt context\n");

    ULONG64 fake_foreign_function_call_noassert;
    dbg_syms->GetOffsetByName("sbcl!fake_foreign_function_call_noassert",  &fake_foreign_function_call_noassert);
    ((void (*)(CONTEXT **)) (fake_foreign_function_call_noassert))(&remote_context);

    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "finished setting interrupt context\n");

    ULONG64 ldb_monitor;
    dbg_syms->GetOffsetByName("sbcl!ldb_monitor",  &ldb_monitor);
    ((void (*)()) ldb_monitor)();

    return 0;
}

LONG breakpoint_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD remote_context_len;
    CONTEXT *remote_context;

    InitializeContext(nullptr, CONTEXT_ALL, nullptr, &remote_context_len);
    char remote_context_buf[remote_context_len];
    InitializeContext(remote_context_buf, CONTEXT_ALL, &remote_context, &remote_context_len);
    dbg_adv->GetThreadContext(remote_context, remote_context_len);

    ExceptionInfo->ContextRecord->Rip = (DWORD64) ldb_monitor_trampoline;
    ExceptionInfo->ContextRecord->Rsp = remote_context->Rsp;

    load_remote_pages(remote_context->Rsp, page_size, TRUE);

    return EXCEPTION_CONTINUE_EXECUTION;
}

unsigned thread_start_trampoline(void *arg) {
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugDataSpaces4), (void **) &dbg_mem);
    DebugConnect(remote_options, __uuidof(IDebugSymbols3), (void **) &dbg_syms);
    DebugConnect(remote_options, __uuidof(IDebugSystemObjects), (void **) &dbg_sysobjs);
    DebugBreak();

    return 0;
}

int main(int argc, char **argv) {
    remote_options = argv[1];
    DebugConnect(remote_options, __uuidof(IDebugAdvanced), (void **) &dbg_adv);
    DebugConnect(remote_options, __uuidof(IDebugControl), (void **) &dbg_ctrl);
    DebugConnect(remote_options, __uuidof(IDebugDataSpaces4), (void **) &dbg_mem);
    DebugConnect(remote_options, __uuidof(IDebugSymbols3), (void **) &dbg_syms);
    DebugConnect(remote_options, __uuidof(IDebugSystemObjects), (void **) &dbg_sysobjs);

    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "debug clients connected, hello!\n");

    static SYSTEM_INFO sys_info;

    GetSystemInfo(&sys_info);
    alloc_gran = sys_info.dwAllocationGranularity;
    page_size = sys_info.dwPageSize;

    HANDLE ldb_thread = (HANDLE) _beginthreadex(nullptr, 0, thread_start_trampoline, nullptr, CREATE_SUSPENDED, nullptr);

    DWORD remote_context_len;
    CONTEXT *remote_context;

    InitializeContext(nullptr, CONTEXT_CONTROL, nullptr, &remote_context_len);
    char remote_context_buf[remote_context_len];
    InitializeContext(remote_context_buf, CONTEXT_CONTROL, &remote_context, &remote_context_len);
    dbg_adv->GetThreadContext(remote_context, remote_context_len);

    DWORD thread_context_len;
    CONTEXT *thread_context;

    InitializeContext(nullptr, CONTEXT_CONTROL | CONTEXT_SEGMENTS, nullptr, &thread_context_len);
    char thread_context_buf[thread_context_len];
    InitializeContext(thread_context_buf, CONTEXT_CONTROL | CONTEXT_SEGMENTS, &thread_context, &thread_context_len);
    GetThreadContext(ldb_thread, thread_context);

    // thread_context->Rip = (DWORD64) ldb_monitor_trampoline;
    // thread_context->Rsp = remote_context->Rsp;

    // SetThreadContext(ldb_thread, thread_context);
    AddVectoredExceptionHandler(TRUE, access_violation_handler);
    AddVectoredExceptionHandler(TRUE, breakpoint_handler);
    ResumeThread(ldb_thread);
    WaitForSingleObject(ldb_thread, INFINITE);
    CloseHandle(ldb_thread);

    return 0;
}