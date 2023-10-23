#ifndef _SETENV_H
#define _SETENV_H

#include <Windows.h>

#define SE_DLL_EXPORT __declspec(dllexport)
#define SE_DLL_IMPORT __declspec(dllimport)

#ifdef SE_BUILD_DLL
#define SE_API SE_DLL_EXPORT
#else
#define SE_API SE_DLL_IMPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define seIsError(r) ((r).se_error || (r).os_error)

typedef struct SeResult {
    DWORD os_error;
    const char *se_error;
} SeResult;

typedef SeResult (*PFN_seSetProcessEnvironmentVariable)(LPCWSTR name, DWORD name_size, LPCWSTR value, DWORD value_size);

typedef void (*PFN_seWarningCallback)(SeResult);

SE_API SeResult seGetParentProcessId(DWORD *ppid);

SE_API SeResult seGetParentOfProcessId(DWORD pid, DWORD *ppid);

SE_API SeResult seSetParentProcessEnvironmentVariable(LPCWSTR name, DWORD name_size, LPCWSTR value, DWORD value_size);

SE_API SeResult seSetProcessEnvironmentVariable(DWORD ppid, LPCWSTR name, DWORD name_size, LPCWSTR value,
                                                DWORD value_size);

SE_API PFN_seWarningCallback seSetWarningCallback(PFN_seWarningCallback);

#ifdef __cplusplus
}
#endif

#endif
