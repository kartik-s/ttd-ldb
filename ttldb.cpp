#include <dbgeng.h>
#include <Windows.h>

extern "C" {

__declspec(dllexport) 
HRESULT DebugExtensionInitialize(PULONG Version, PULONG Flags) {
    return S_OK;
}

__declspec(dllexport)
HRESULT ldb(PDEBUG_CLIENT Client, PCSTR Args) {
    IDebugControl *dbg_ctrl;

    Client->QueryInterface(__uuidof(IDebugControl), (void **) &dbg_ctrl);
    dbg_ctrl->Output(DEBUG_OUTPUT_NORMAL, "hello from ttldb\n");

    return S_OK;
}

}