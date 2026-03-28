#include <stdio.h>

#include <windows.h>
#include <detours.h>

static BOOL (WINAPI *RealReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) = ReadFile;

BOOL TouchReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
)
{
    BOOL ret = RealReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    
    if (!ret) return ret;

    for (DWORD i = 0; i < *lpNumberOfBytesRead; i++) asm volatile ("" : : "r" (*((char *) lpBuffer + i)));

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;

    if (DetourIsHelperProcess()) return TRUE;

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID &) RealReadFile, TouchReadFile);
    
        error = DetourTransactionCommit();

        if (error != NO_ERROR) {
            printf("touch_read.dll: Error detouring ReadFile(): %ld", error);
        }
    } else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID &) RealReadFile, TouchReadFile);

        error = DetourTransactionCommit();

        if (error != NO_ERROR) {
            printf("touch_read.dll: Error detaching ReadFile(): %ld", error);
        }
    }

    return TRUE;
}