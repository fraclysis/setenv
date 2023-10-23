#include "setenv_remote_thread.h"

DWORD WINAPI seProcessInjectionThread(LPVOID lpThreadParameter)
{
    struct SeProcessInjectionData *restrict data = lpThreadParameter;

    HMODULE library = data->FN_LoadLibraryW(data->lib_file_name);
    if (library == NULL)
    {
        DWORD error = data->FN_GetLastError();
        return error;
    }

    PFN_seInjectedProc proc = (PFN_seInjectedProc)data->FN_GetProcAddress(library, data->proc_name);
    if (proc == NULL)
    {
        DWORD error = data->FN_GetLastError();
        data->FN_FreeLibrary(library);
        return error;
    }

    return proc(data->proc_parameter);
}
