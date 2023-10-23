#define SE_BUILD_DLL
#include "setenv.h"
#include "setenv_remote_thread.h"
#include "setenv_remote_thread_opcodes.c"
#include <stdalign.h>
#include <string.h>
#include <tlhelp32.h>

#define SE_EVENT_FORMAT L"Global\\SetEnvEvent%lu"
#define SE_PIPE_FORMAT L"\\\\.\\pipe\\SetEnv%lu"

#define SE_READ_FISHED_EVENT_FORMAT L"Global\\SetEnvReadFished%lu"

typedef struct SeMessageHeader
{
    DWORD name_size;
    DWORD value_size;
} SeMessageHeader;

SE_API void seCallWarning(LPCSTR message);

DWORD WINAPI sePipeHandler(LPVOID lpParameter);

SE_API SeResult seLastOsError(const char *message);

SE_API SeResult seGetRequiredPfn(SeProcessInjectionData *restrict data);

SE_API SeResult seWriteToPipe(HANDLE pipe, DWORD ppid, LPCWSTR name, DWORD name_size, LPCWSTR value, DWORD value_size);

SE_API SeResult seGetProcessPipe(DWORD ppid, HANDLE *pipe);

SE_API SeResult seSetParentProcessEnvironmentVariable(LPCWSTR name, DWORD name_size, LPCWSTR value, DWORD value_size)
{
    SeResult result = {0};

    DWORD ppid = 0;
    result = seGetParentProcessId(&ppid);
    if (seIsError(result))
    {
        return result;
    }

    result = seSetProcessEnvironmentVariable(ppid, name, name_size, value, value_size);

    return result;
}

SE_API SeResult seSetProcessEnvironmentVariable(DWORD ppid, LPCWSTR name, DWORD name_size, LPCWSTR value,
                                                DWORD value_size)
{
    SeResult result = {0};

    HANDLE pipe = NULL;
    result = seGetProcessPipe(ppid, &pipe);
    if (seIsError(result))
    {
        return result;
    }

    result = seWriteToPipe(pipe, ppid, name, name_size, value, value_size);
    if (seIsError(result))
    {
        return result;
    }

close_pipe:
    CloseHandle(pipe);

    return result;
}

SE_API SeResult seGetLongFilePath(HANDLE heap, WCHAR *path, WCHAR **long_path, BOOL *allocated, SIZE_T *size)
{
    SeResult result = {0};

    DWORD size0 = GetFullPathNameW(path, MAX_PATH, *long_path, NULL);
    if (size0 == 0)
    {
        return seLastOsError("Failed to get module file name.");
    }
    else if (MAX_PATH > size0)
    {
        *size = size0;
    }
    else
    {
        *long_path = HeapAlloc(heap, 0, sizeof(WCHAR) * size0);
        if (*long_path == NULL)
        {
            return seLastOsError("Failed to allocate.");
        }

        DWORD size1 = GetFullPathNameW(path, size0, *long_path, NULL);
        if (size1 == 0)
        {

            if (!HeapFree(heap, 0, *long_path))
            {
                seCallWarning("Failed to free heap.");
            }

            return seLastOsError("Failed to get module file name.");
        }
        else if (size0 > size1)
        {
            *allocated = TRUE;
            *size = size1;
        }
        else
        {
            if (!HeapFree(heap, 0, *long_path))
            {
                seCallWarning("Failed to free heap.");
            }

            result.os_error = ERROR_UNHANDLED_ERROR;
            result.se_error = "TODO";
        }
    }

    return result;
}

SE_API SeResult seGetModulePath(HMODULE module, HANDLE heap, WCHAR **file_name, BOOL *allocated, SIZE_T *size)
{
    SeResult result = {0};

    DWORD size0 = GetModuleFileNameW(module, *file_name, MAX_PATH);
    if (size0 == 0)
    {
        return seLastOsError("Failed to get module file name.");
    }
    else if (MAX_PATH > size0)
    {
        *size = size0;
    }
    else
    {
        *file_name = HeapAlloc(heap, 0, sizeof(WCHAR) * size0);
        if (*file_name == NULL)
        {
            return seLastOsError("Failed to allocate.");
        }

        DWORD size1 = GetModuleFileNameW(module, *file_name, size0);
        if (size1 == 0)
        {

            if (!HeapFree(heap, 0, *file_name))
            {
                seCallWarning("Failed to free heap.");
            }

            return seLastOsError("Failed to get module file name.");
        }
        else if (size0 > size1)
        {
            *allocated = TRUE;
            *size = size1;
        }
        else
        {
            if (!HeapFree(heap, 0, *file_name))
            {
                seCallWarning("Failed to free heap.");
            }

            result.os_error = ERROR_UNHANDLED_ERROR;
            result.se_error = "TODO";
        }
    }

    return result;
}

SE_API SeResult seGetDllFullPath(HANDLE heap, WCHAR *name, WCHAR **full_path, BOOL *allocated, SIZE_T *size)
{
    SeResult result = {0};

    HMODULE dll = GetModuleHandleW(name);
    if (dll == NULL)
    {
        return seLastOsError("Failed to get module handle.");
    }

    WCHAR buffer[MAX_PATH];

    BOOL module_path_allocated = FALSE;
    WCHAR *module_path = buffer;

    SIZE_T unused;
    result = seGetModulePath(dll, heap, &module_path, &module_path_allocated, &unused);
    if (seIsError(result))
    {
        return result;
    }

    result = seGetLongFilePath(heap, module_path, full_path, allocated, size);

free_module_path:
    if (module_path_allocated)
    {
        if (!HeapFree(heap, 0, module_path))
        {
            seCallWarning("Failed to clean heap");
        }
    }
    return result;
}

SE_API SeResult seCreateRemotePipe(DWORD ppid)
{
    typedef struct SeProcName
    {
        CHAR name[20];
    } SeProcName;

    typedef struct SeWriteData
    {
        alignas(64) unsigned char remote_thread_opcodes[sizeof(seProcessInjectionThread_opcodes)];
        struct SeProcName proc;
        SeProcessInjectionData data;
    } SeWriteData;

    SeResult result = {0};

    HANDLE heap = GetProcessHeap();
    if (heap == NULL)
    {
        return seLastOsError("Failed to get process heap.");
    }

    HANDLE pph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_READ | PROCESS_VM_WRITE,
                             FALSE, ppid);
    if (pph == NULL)
    {
        return seLastOsError("Failed to OpenProcess for parent process.");
    }

    struct
    {
        WCHAR setenv[MAX_PATH];
    } buffers;

    WCHAR *setenv_path = buffers.setenv;
    BOOL setenv_allocated = FALSE;
    SIZE_T setenv_path_size = 0;
    result = seGetDllFullPath(heap, L"setenv.dll", &setenv_path, &setenv_allocated, &setenv_path_size);
    if (seIsError(result))
    {
        setenv_path = L"setenv.dll";
        setenv_path_size = ARRAYSIZE(L"setenv.dll") - 1;
    }

    void *remote_memory = VirtualAllocEx(pph, NULL, sizeof(SeWriteData) + (sizeof(WCHAR) * setenv_path_size + 1),
                                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (remote_memory == NULL)
    {
        result.os_error = GetLastError();
        result.se_error = "Failed to allocate memory for parent process.";
        goto free_setenv_path;
    }

    SeWriteData *remote_data = remote_memory;

    SeWriteData data;
    data.proc = (SeProcName){"seRemoteMain"};
    data.data.proc_name = remote_data->proc.name;
    data.data.lib_file_name = (WCHAR *)(remote_data + 1);
    memcpy(data.remote_thread_opcodes, seProcessInjectionThread_opcodes, sizeof(seProcessInjectionThread_opcodes));

    result = seGetRequiredPfn(&data.data);
    if (seIsError(result))
    {
        goto free_remote_memory;
    }

    if (!WriteProcessMemory(pph, remote_data, &data, sizeof(SeWriteData), NULL))
    {
        result = seLastOsError("Failed to write to process memory.");
        goto free_remote_memory;
    }

    if (!WriteProcessMemory(pph, remote_data + 1, setenv_path, (sizeof(WCHAR) * setenv_path_size + 1), NULL))
    {
        result = seLastOsError("Failed to write to process memory.");
        goto free_remote_memory;
    }

    unsigned char *start_routine = remote_data->remote_thread_opcodes;
    SeProcessInjectionData *parameter = &remote_data->data;

    HANDLE remote_thread = CreateRemoteThread(pph, NULL, 0, (LPTHREAD_START_ROUTINE)start_routine, parameter, 0, NULL);
    if (remote_thread == NULL)
    {
        result = seLastOsError("Failed to create remote thread on parent process.");
        goto free_remote_memory;
    }

    DWORD wait = WaitForSingleObject(remote_thread, INFINITE);
    if (wait == WAIT_FAILED)
    {
        seLastOsError("Wait for remote thread failed.");
        goto close_remote_thread;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeThread(remote_thread, &exit_code))
    {
        seCallWarning("Failed to get exit code.");
    }

    if (exit_code != 0)
    {
        result.os_error = exit_code;
        result.se_error = "Thread did not exit successfully.";
        goto close_remote_thread;
    }

close_remote_thread:
    if (!CloseHandle(remote_thread))
    {
        seCallWarning("Failed to close remote thread.");
    }
free_remote_memory:
    if (!VirtualFree(remote_memory, 0, MEM_FREE))
    {
        seCallWarning("Failed to free remote memory.");
    }
free_setenv_path:
    if (setenv_allocated)
    {
        if (!HeapFree(heap, 0, setenv_path))
        {
            seCallWarning("Failed to clean allocated memory.");
        }
    }
close_pph:
    if (!CloseHandle(pph))
    {
        seCallWarning("Failed to close parent process handle.");
    }

    return result;
}

SE_API SeResult seGetProcessPipe(DWORD ppid, HANDLE *restrict pipe)
{
    SeResult result = {0};

    WCHAR pipe_name[MAX_PATH];
    wsprintfW(pipe_name, SE_PIPE_FORMAT, ppid);

    // FIX:(fraclysis) Loops and creates threads
try_create_file:
    *pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*pipe == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_PIPE_BUSY)
        {
            WaitNamedPipeW(pipe_name, 100);
        }
        else
        {
            result = seCreateRemotePipe(ppid);
            if (seIsError(result))
            {
                return result;
            }
        }
        goto try_create_file;
    }

    return result;
}
SE_API SeResult seGetParentOfProcessId(DWORD pid, DWORD *ppid)
{
    SeResult result = {0};

    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE)
    {
        result.se_error = "CreateToolhelp32Snapshot failed.";
        result.os_error = GetLastError();
        goto ret;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(h, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                *ppid = pe.th32ParentProcessID;
                goto close;
            }
        } while (Process32Next(h, &pe));
    }

    result.os_error = ERROR_UNHANDLED_ERROR;
    result.se_error = "Could not found process id.";

close:
    if (!CloseHandle(h))
    {
        seCallWarning("Failed to close snapshot handle.");
    }
ret:
    return result;
}

SE_API SeResult seGetParentProcessId(DWORD *restrict ppid)
{
    SeResult result = {0};

    result = seGetParentOfProcessId(GetCurrentProcessId(), ppid);

    return result;
}

SE_API SeResult seWriteToPipe(HANDLE pipe, DWORD ppid, LPCWSTR name, DWORD name_size, LPCWSTR value, DWORD value_size)
{
    SeResult result = {0};

    WCHAR event_name[MAX_PATH];
    wsprintfW(event_name, SE_READ_FISHED_EVENT_FORMAT, ppid);
    HANDLE read_fished = OpenEventW(EVENT_ALL_ACCESS, FALSE, event_name);
    if (read_fished == NULL)
    {
        return seLastOsError("Failed to open read finished event.");
    }

    HANDLE heap = GetProcessHeap();
    if (heap == NULL)
    {
        result = seLastOsError("Failed at GetProcessHeap.");
        goto close_read_fished;
    }

    DWORD required_bytes = (sizeof(WCHAR) * (name_size + value_size)) + sizeof(SeMessageHeader);

    void *message = HeapAlloc(heap, 0, required_bytes);
    if (message == NULL)
    {
        result = seLastOsError("Failed to allocate memory.");
        goto close_read_fished;
    }

    SeMessageHeader *header = message;
    header->name_size = name_size;
    header->value_size = value_size;

    WCHAR *message_data = (WCHAR *)(header + 1);
    memcpy(message_data, name, name_size * sizeof(WCHAR));
    memcpy(message_data + name_size, value, value_size * sizeof(WCHAR));

    BOOL ok = WriteFile(pipe, message, required_bytes, NULL, NULL);
    if (!ok)
    {
        result = seLastOsError("Failed to write pipe.");
        goto free_message;
    }

    DWORD pipe_ret;
    ok = ReadFile(pipe, &pipe_ret, sizeof(DWORD), NULL, NULL);

    if (!SetEvent(read_fished))
    {
        MessageBoxW(0, L"Failed to set event.", NULL, 0);
    }

    if (!ok)
    {
        result = seLastOsError("Failed to read pipe return value.");
        goto free_message;
    }

    if (pipe_ret)
    {
        result.se_error = "Pipe return value";
        result.os_error = pipe_ret;
    }

free_message:
    HeapFree(heap, 0, message);
close_read_fished:
    CloseHandle(read_fished);

    return result;
}

SE_API SeResult seLastOsError(const char *message)
{
    SeResult result = {GetLastError(), message};
    return result;
}

SE_API SeResult seGetRequiredPfn(SeProcessInjectionData *restrict data)
{
    SeResult result = {0};

    HMODULE kernel = GetModuleHandleW(L"Kernel32.dll");
    if (kernel == NULL)
    {
        return seLastOsError("Failed to get Kernel32.dll module handle.");
    }

#pragma warning(suppress : 4191)
    data->FN_LoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(kernel, "LoadLibraryW");
    data->FN_FreeLibrary = (PFN_FreeLibrary)GetProcAddress(kernel, "FreeLibrary");
    data->FN_GetProcAddress = (PFN_GetProcAddress)GetProcAddress(kernel, "GetProcAddress");
    data->FN_GetLastError = (PFN_GetLastError)GetProcAddress(kernel, "GetLastError");
    if (!(data->FN_LoadLibraryW && data->FN_GetProcAddress && data->FN_FreeLibrary && data->FN_GetLastError))
    {
        return seLastOsError("Failed to get proc address for required procs.");
    }

    return result;
}

DWORD WINAPI sePipeHandler(LPVOID lpParameter);

SE_API DWORD seRemoteMain(void *parameter)
{
    DWORD result = 0;

    HANDLE pipe_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (pipe_ready == NULL)
    {
        result = GetLastError();
        goto return_result;
    }

    HANDLE pipe_handler_thread = CreateThread(NULL, 0, sePipeHandler, pipe_ready, 0, NULL);
    if (pipe_handler_thread == NULL)
    {
        result = GetLastError();
        goto close_pipe_ready;
    }

    HANDLE wait_list[2] = {pipe_ready, pipe_handler_thread};

    DWORD wait = WaitForMultipleObjects(2, wait_list, FALSE, INFINITE);
    switch (wait)
    {
    case WAIT_OBJECT_0 + 0:
        // Pipe ready event signaled
        break;
    case WAIT_OBJECT_0 + 1: {
        // Pipe handler failed to initialize
        DWORD exit_code = 0;
        if (!GetExitCodeThread(pipe_handler_thread, &exit_code))
        {
            result = GetLastError();
        }
    }
    break;
    case WAIT_FAILED:
        result = GetLastError();
        goto close_pipe_handler_thread;
        break;
    default:
        // Getting ERROR_UNHANDLED_ERROR message is bug
        result = ERROR_UNHANDLED_ERROR;
        break;
    }

close_pipe_handler_thread:
    CloseHandle(pipe_handler_thread);
close_pipe_ready:
    CloseHandle(pipe_ready);
return_result:
    return result;
}

DWORD seInner(HANDLE pipe, HANDLE heap, SeMessageHeader header)
{
    DWORD bytes_read;
    DWORD result;

    SIZE_T required_bytes = sizeof(WCHAR) * (header.name_size + header.value_size + 2);
    WCHAR *message_data = HeapAlloc(heap, 0, required_bytes);
    if (message_data == NULL)
    {
        result = GetLastError();
        goto Return;
    }

    BOOL ok = ReadFile(pipe, message_data, sizeof(WCHAR) * header.name_size, &bytes_read, NULL);
    if (!ok)
    {
        result = GetLastError();
        if (result != ERROR_MORE_DATA)
        {
            goto free_message_data;
        }
    }
    if (bytes_read != header.name_size * sizeof(WCHAR))
    {
        result = ERROR_INCORRECT_SIZE;
        goto free_message_data;
    }
    message_data[header.name_size] = 0;

    WCHAR *value_ptr = NULL;
    if (header.value_size)
    {
        value_ptr = message_data + (header.name_size + 1);

        ok = ReadFile(pipe, value_ptr, sizeof(WCHAR) * header.value_size, &bytes_read, NULL);
        if (!ok)
        {
            result = GetLastError();
            goto free_message_data;
        }
        if (bytes_read != header.value_size * sizeof(WCHAR))
        {
            result = ERROR_INCORRECT_SIZE;
            goto free_message_data;
        }
        value_ptr[header.value_size] = 0;
    }

    ok = SetEnvironmentVariableW(message_data, value_ptr);
    if (!ok)
    {
        result = GetLastError();
    }
    else
    {
        result = 0;
    }

free_message_data:
    if (message_data)
    {
        HeapFree(heap, 0, message_data);
    }
Return:
    return result;
}

DWORD sePipeLoop(HANDLE pipe, HANDLE read_finished)
{
    BOOL ok;
    DWORD result;

    HANDLE heap = GetProcessHeap();
    if (heap == NULL)
    {
        return GetLastError();
    }

    for (;;)
    {

        ok = ConnectNamedPipe(pipe, NULL);
        if (!ok)
        {
            result = GetLastError();
            if (result != ERROR_PIPE_CONNECTED)
            {
                return result;
            }
        }

        DWORD bytes_read;
        SeMessageHeader header;
        ok = ReadFile(pipe, &header, sizeof(SeMessageHeader), &bytes_read, NULL);
        if (!ok)
        {
            DWORD error = GetLastError();
            if (error != ERROR_MORE_DATA)
            {
                goto disconnect;
            }
        }
        if (bytes_read != sizeof(SeMessageHeader))
        {
            result = ERROR_INCORRECT_SIZE;
            goto write_result;
        }

        result = seInner(pipe, heap, header);

    write_result:
        // TODO
        ok = WriteFile(pipe, &result, sizeof(DWORD), NULL, NULL);
        if (ok)
        {
            WaitForSingleObject(read_finished, INFINITE);
        }
    disconnect:
        DisconnectNamedPipe(pipe);
    }

    return 0;
}

DWORD WINAPI sePipeHandler(LPVOID lpParameter)
{
    DWORD result = 0;
    HANDLE pipe_ready = lpParameter;

    DWORD pid = GetCurrentProcessId();

    WCHAR name_buffer[MAX_PATH];

    wsprintfW(name_buffer, SE_READ_FISHED_EVENT_FORMAT, pid);
    HANDLE read_finished = CreateEventW(NULL, FALSE, FALSE, name_buffer);
    if (read_finished == NULL)
    {
        result = GetLastError();
        goto return_result;
    }
    else if (read_finished == INVALID_HANDLE_VALUE)
    {
        // IDK ??
        read_finished = OpenEventW(EVENT_ALL_ACCESS, FALSE, name_buffer);
        if (read_finished == NULL || read_finished == INVALID_HANDLE_VALUE)
        {
            result = GetLastError();
            goto return_result;
        }
    }

    wsprintfW(name_buffer, SE_PIPE_FORMAT, pid);
    HANDLE pipe =
        CreateNamedPipeW(name_buffer, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 512,
                         512 * sizeof(WCHAR), NMPWAIT_WAIT_FOREVER, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        result = GetLastError();
        goto close_event;
    }

    if (!SetEvent(pipe_ready))
    {
        result = GetLastError();
        goto close_pipe;
    }

    result = sePipeLoop(pipe, read_finished);

close_pipe:
    CloseHandle(pipe);
close_event:
    CloseHandle(read_finished);
return_result:
    return result;
}

static PFN_seWarningCallback internal_warning_callback = NULL;

SE_API PFN_seWarningCallback seSetWarningCallback(PFN_seWarningCallback callback)
{
    PFN_seWarningCallback old_callback = internal_warning_callback;
    internal_warning_callback = callback;
    return old_callback;
}

SE_API void seCallWarning(LPCSTR message)
{
    SeResult result = {
        .os_error = GetLastError(),
        .se_error = message,
    };

    if (internal_warning_callback)
    {
        internal_warning_callback(result);
    }
}

#ifndef SE_CRT
BOOL WINAPI seDllMainCRTStartup(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        __security_init_cookie();
    }

    return TRUE;
}
#endif

BOOL WINAPI _DllMainCRTStartup(HINSTANCE const instance, DWORD const reason, LPVOID const reserved);
