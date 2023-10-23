#ifndef _SETENV_REMOTE_THREAD_H
#define _SETENV_REMOTE_THREAD_H

#include <Windows.h>

typedef HMODULE(WINAPI *PFN_LoadLibraryW)(LPCWSTR lpLibFileName);
typedef FARPROC(WINAPI *PFN_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef DWORD(WINAPI *PFN_GetLastError)(VOID);
typedef BOOL(WINAPI *PFN_FreeLibrary)(HMODULE hLibModule);

typedef DWORD (*PFN_seInjectedProc)(void *parameter);

typedef struct SeProcessInjectionData
{
    LPCWSTR lib_file_name;
    LPCSTR proc_name;
    PFN_LoadLibraryW FN_LoadLibraryW;
    PFN_GetProcAddress FN_GetProcAddress;
    PFN_FreeLibrary FN_FreeLibrary;
    PFN_GetLastError FN_GetLastError;
    LPVOID proc_parameter;
} SeProcessInjectionData;

#endif
