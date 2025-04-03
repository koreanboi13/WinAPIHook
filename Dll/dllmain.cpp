#include "pch.h"
#include <iostream>
#include <windows.h>
#include "Hook.h"
#include <ctime>
Hook h;
extern "C" void Save();
extern "C" void hookFunc() {
    h.unhook(0);

    time_t now = time(nullptr);
    tm local_time_struct; 
    localtime_s(&local_time_struct, &now);

    char time_buf[20]; 
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &local_time_struct);
    std::string time_str = time_buf;

    std::string message = "Function: " + std::string(h.getFuncName()) + " called at: " + time_str + "\n";
    h.writeToPipe(message);
    h.setHook(h.getFuncName(), (FARPROC)Save,0);
}
bool IsTargetFile(LPCWSTR fileName, const char* targetName) {
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, targetName, -1, NULL, 0);
    if (wideLen == 0) return false;

    wchar_t* wideTarget = new wchar_t[wideLen];
    MultiByteToWideChar(CP_UTF8, 0, targetName, -1, wideTarget, wideLen);

    bool match = (wcsstr(fileName, wideTarget) != nullptr);

    delete[] wideTarget;
    return match;
}

HANDLE WINAPI myFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) { 
    h.unhook(1);
    HANDLE hFind = FindFirstFileW(lpFileName, lpFindFileData);

    if (IsTargetFile(lpFileName, h.getFileName())) {
        h.writeToPipe("Target file found - hiding it");
        CloseHandle(hFind);  
        h.setHook("FindFirstFileW", (FARPROC)myFindFirstFileW,1);
        return INVALID_HANDLE_VALUE;
    }
    h.setHook("FindFirstFileW", (FARPROC)myFindFirstFileW,1);
    return hFind;

}

BOOL WINAPI myFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    h.unhook(2);
    bool res = FindNextFileW(hFindFile, lpFindFileData);
    while (res && IsTargetFile(lpFindFileData->cFileName, h.getFileName())) {
        res = FindNextFileW(hFindFile, lpFindFileData);
    }
    h.setHook("FindNextFileW", (FARPROC)myFindNextFileW,2);
    return res;
    
}

HANDLE WINAPI myCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    h.unhook(3);
    if (IsTargetFile(lpFileName, h.getFileName())) {
        h.setHook("CreateFileW", (FARPROC)myCreateFileW,3);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE res = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return res;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (h.connectToPipe()) {
            h.readFromPipe();
            if (strcmp(h.getMode(),"0") == 0) {
                h.setHook(h.getFuncName(), (FARPROC)Save,0);

            }
            else {
                //FindFirstFileW
                h.setHook("FindFirstFileW", (FARPROC)myFindFirstFileW,1);
                
                //FindNextFileW
                h.setHook("FindNextFileW", (FARPROC)myFindNextFileW,2);

                //CreateFileW
                h.setHook("CreateFileW", (FARPROC)myCreateFileW, 3);
            }
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

