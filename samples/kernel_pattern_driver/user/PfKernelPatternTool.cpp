#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "../shared/PfKernelPatternIoctl.h"

#define PFKP_SERVICE_NAME L"PfKernelPattern"
#define PFKP_DRIVER_FILE_NAME L"PfKernelPattern.sys"
#define PFKP_DWORD_SIZEOF(value) ((DWORD)sizeof(value))

static HANDLE g_DeviceHandle = INVALID_HANDLE_VALUE;
static SC_HANDLE g_ServiceHandle = NULL;
static SC_HANDLE g_ManagerHandle = NULL;
static volatile LONG g_StopRequested = 0;

static BOOL WINAPI PfkpConsoleHandler(DWORD ControlType);
static bool PfkpIsElevated();
static void PfkpPrintLastError(const wchar_t *Operation, DWORD Error);
static bool PfkpResolveDriverPath(wchar_t *Path, DWORD CharacterCount);
static bool PfkpOpenScm();
static bool PfkpStopAndDeleteExistingService();
static bool PfkpCreateAndStartService(const wchar_t *DriverPath);
static bool PfkpWaitForDevice();
static bool PfkpDeviceIoControl(DWORD Ioctl, void *InOutBuffer, DWORD InOutLength, DWORD *BytesReturned);
static bool PfkpQueryStatus();
static bool PfkpExerciseDriver(bool EnableCallbacks);
static void PfkpCleanup(bool LeaveLoaded);

int
wmain(
    int argc,
    wchar_t **argv
    )
{
    int result;
    bool leaveLoaded;
    bool enableCallbacks;
    wchar_t driverPath[MAX_PATH];

    result = 1;
    leaveLoaded = false;
    enableCallbacks = false;
    ZeroMemory(driverPath, sizeof(driverPath));

    for (int index = 1; index < argc; ++index)
    {
        if (_wcsicmp(argv[index], L"--leave-loaded") == 0)
        {
            leaveLoaded = true;
        }
        else if (_wcsicmp(argv[index], L"--callbacks") == 0)
        {
            enableCallbacks = true;
        }
        else
        {
            wprintf(L"Unknown option: %ls\n", argv[index]);
            goto Exit;
        }
    }

    if (!SetConsoleCtrlHandler(PfkpConsoleHandler, TRUE))
    {
        PfkpPrintLastError(L"SetConsoleCtrlHandler", GetLastError());
        goto Exit;
    }

    if (!PfkpIsElevated())
    {
        wprintf(L"This tool must run elevated.\n");
        goto Exit;
    }

    if (!PfkpResolveDriverPath(driverPath, ARRAYSIZE(driverPath)))
    {
        goto Exit;
    }

    wprintf(L"Driver path: %ls\n", driverPath);

    if (!PfkpOpenScm())
    {
        goto Exit;
    }

    if (!PfkpStopAndDeleteExistingService())
    {
        goto Exit;
    }

    if (!PfkpCreateAndStartService(driverPath))
    {
        goto Exit;
    }

    if (!PfkpWaitForDevice())
    {
        goto Exit;
    }

    if (!PfkpExerciseDriver(enableCallbacks))
    {
        goto Exit;
    }

    result = 0;

Exit:
    PfkpCleanup(leaveLoaded && result == 0);
    return result;
}

static
BOOL WINAPI
PfkpConsoleHandler(
    DWORD ControlType
    )
{
    switch (ControlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        InterlockedExchange(&g_StopRequested, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

static
bool
PfkpIsElevated()
{
    bool elevated;
    HANDLE token;
    TOKEN_ELEVATION elevation;
    DWORD returned;

    elevated = false;
    token = NULL;
    ZeroMemory(&elevation, sizeof(elevation));
    returned = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        PfkpPrintLastError(L"OpenProcessToken", GetLastError());
        goto Exit;
    }

    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned))
    {
        PfkpPrintLastError(L"GetTokenInformation", GetLastError());
        goto Exit;
    }

    elevated = elevation.TokenIsElevated != 0;

Exit:
    if (token != NULL)
    {
        CloseHandle(token);
    }

    return elevated;
}

static
void
PfkpPrintLastError(
    const wchar_t *Operation,
    DWORD Error
    )
{
    wchar_t *message;

    message = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        Error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&message,
        0,
        NULL);

    if (message != NULL)
    {
        wprintf(L"%ls failed: %lu: %ls", Operation, Error, message);
        LocalFree(message);
    }
    else
    {
        wprintf(L"%ls failed: %lu\n", Operation, Error);
    }
}

static
bool
PfkpResolveDriverPath(
    wchar_t *Path,
    DWORD CharacterCount
    )
{
    DWORD length;
    wchar_t *slash;

    length = GetModuleFileNameW(NULL, Path, CharacterCount);
    if (length == 0 || length >= CharacterCount)
    {
        PfkpPrintLastError(L"GetModuleFileNameW", GetLastError());
        return false;
    }

    slash = wcsrchr(Path, L'\\');
    if (slash == NULL)
    {
        wprintf(L"Could not resolve executable directory.\n");
        return false;
    }

    slash[1] = L'\0';
    if (wcscat_s(Path, CharacterCount, PFKP_DRIVER_FILE_NAME) != 0)
    {
        wprintf(L"Driver path buffer is too small.\n");
        return false;
    }

    if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
    {
        PfkpPrintLastError(L"GetFileAttributesW(driver)", GetLastError());
        return false;
    }

    return true;
}

static
bool
PfkpOpenScm()
{
    g_ManagerHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (g_ManagerHandle == NULL)
    {
        PfkpPrintLastError(L"OpenSCManagerW", GetLastError());
        return false;
    }

    return true;
}

static
bool
PfkpStopAndDeleteExistingService()
{
    SC_HANDLE service;
    SERVICE_STATUS status;
    DWORD error;

    service = OpenServiceW(g_ManagerHandle, PFKP_SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (service == NULL)
    {
        error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            return true;
        }

        PfkpPrintLastError(L"OpenServiceW(existing)", error);
        return false;
    }

    ZeroMemory(&status, sizeof(status));
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
        error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE)
        {
            PfkpPrintLastError(L"ControlService(stop)", error);
        }
    }

    if (!DeleteService(service))
    {
        error = GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            CloseServiceHandle(service);
            PfkpPrintLastError(L"DeleteService", error);
            return false;
        }
    }

    CloseServiceHandle(service);
    Sleep(500);
    return true;
}

static
bool
PfkpCreateAndStartService(
    const wchar_t *DriverPath
    )
{
    DWORD error;

    g_ServiceHandle = CreateServiceW(
        g_ManagerHandle,
        PFKP_SERVICE_NAME,
        PFKP_SERVICE_NAME,
        SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        DriverPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (g_ServiceHandle == NULL)
    {
        PfkpPrintLastError(L"CreateServiceW", GetLastError());
        return false;
    }

    if (!StartServiceW(g_ServiceHandle, 0, NULL))
    {
        error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING)
        {
            PfkpPrintLastError(L"StartServiceW", error);
            return false;
        }
    }

    return true;
}

static
bool
PfkpWaitForDevice()
{
    DWORD attempt;

    for (attempt = 0; attempt < 40; ++attempt)
    {
        g_DeviceHandle = CreateFileW(
            PFKP_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (g_DeviceHandle != INVALID_HANDLE_VALUE)
        {
            return true;
        }

        Sleep(100);
    }

    PfkpPrintLastError(L"CreateFileW(device)", GetLastError());
    return false;
}

static
bool
PfkpDeviceIoControl(
    DWORD Ioctl,
    void *InOutBuffer,
    DWORD InOutLength,
    DWORD *BytesReturned
    )
{
    DWORD bytesReturned;

    bytesReturned = 0;
    if (!DeviceIoControl(
        g_DeviceHandle,
        Ioctl,
        InOutBuffer,
        InOutLength,
        InOutBuffer,
        InOutLength,
        &bytesReturned,
        NULL))
    {
        PfkpPrintLastError(L"DeviceIoControl", GetLastError());
        return false;
    }

    if (BytesReturned != NULL)
    {
        *BytesReturned = bytesReturned;
    }

    return true;
}

static
bool
PfkpQueryStatus()
{
    PFKP_STATUS_REPLY status;
    DWORD returned;

    ZeroMemory(&status, sizeof(status));
    if (!PfkpDeviceIoControl(PFKP_IOCTL_GET_STATUS, &status, PFKP_DWORD_SIZEOF(status), &returned))
    {
        return false;
    }

    wprintf(
        L"status: flags=0x%08x events=%u ioctls=%u allocs=%u proc=%u image=%u thread=%u ob=%u white=%u black=%u timer=%u work=%u last=0x%08x\n",
        status.Flags,
        status.EventCount,
        status.IoctlCount,
        status.AllocationCount,
        status.ProcessCallbackCount,
        status.ImageCallbackCount,
        status.ThreadCallbackCount,
        status.ObCallbackCount,
        status.WhitelistHitCount,
        status.BlacklistHitCount,
        status.TimerFireCount,
        status.WorkItemCount,
        status.LastErrorStatus);

    return true;
}

static
bool
PfkpExerciseDriver(
    bool EnableCallbacks
    )
{
    bool ok;
    DWORD returned;
    unsigned char allocateBuffer[sizeof(PFKP_ALLOCATE_REPLY)];
    PFKP_ALLOCATE_REQUEST *allocateRequest;
    PFKP_ALLOCATE_REPLY *allocateReply;
    unsigned char processBuffer[sizeof(PFKP_PROCESS_QUERY_REPLY)];
    PFKP_PROCESS_QUERY_REQUEST *processRequest;
    PFKP_PROCESS_QUERY_REPLY *processReply;
    PFKP_TIMER_REQUEST timerRequest;
    unsigned char callbackBuffer[sizeof(PFKP_CALLBACK_REPLY)];
    PFKP_CALLBACK_REQUEST *callbackRequest;
    PFKP_CALLBACK_REPLY *callbackReply;
    unsigned char eventBuffer[sizeof(PFKP_EVENT_LIST) + sizeof(PFKP_EVENT_RECORD) * 32];
    PFKP_EVENT_LIST *eventList;

    ok = false;
    returned = 0;

    if (!PfkpQueryStatus())
    {
        goto Exit;
    }

    ZeroMemory(allocateBuffer, sizeof(allocateBuffer));
    allocateRequest = (PFKP_ALLOCATE_REQUEST *)allocateBuffer;
    allocateRequest->Header.Size = sizeof(*allocateRequest);
    allocateRequest->Header.Version = 1;
    allocateRequest->AllocationSize = 512;
    allocateRequest->Pattern = 0x5a;

    if (!PfkpDeviceIoControl(PFKP_IOCTL_ALLOCATE_PATTERN, allocateBuffer, PFKP_DWORD_SIZEOF(allocateBuffer), &returned))
    {
        goto Exit;
    }

    allocateReply = (PFKP_ALLOCATE_REPLY *)allocateBuffer;
    wprintf(
        L"allocate: size=%u checksum=0x%08x status=0x%08x\n",
        allocateReply->AllocationSize,
        allocateReply->Checksum,
        allocateReply->Status);

    ZeroMemory(processBuffer, sizeof(processBuffer));
    processRequest = (PFKP_PROCESS_QUERY_REQUEST *)processBuffer;
    processRequest->Header.Size = sizeof(*processRequest);
    processRequest->Header.Version = 1;
    processRequest->ProcessId = GetCurrentProcessId();

    if (!PfkpDeviceIoControl(PFKP_IOCTL_QUERY_PROCESS, processBuffer, PFKP_DWORD_SIZEOF(processBuffer), &returned))
    {
        goto Exit;
    }

    processReply = (PFKP_PROCESS_QUERY_REPLY *)processBuffer;
    wprintf(
        L"process: pid=%llu object=0x%llx status=0x%08x\n",
        processReply->ProcessId,
        processReply->ProcessObject,
        processReply->Status);

    if (!PfkpDeviceIoControl(PFKP_IOCTL_QUEUE_WORK, NULL, 0, &returned))
    {
        goto Exit;
    }

    ZeroMemory(&timerRequest, sizeof(timerRequest));
    timerRequest.Header.Size = sizeof(timerRequest);
    timerRequest.Header.Version = 1;
    timerRequest.DueTimeMs = 50;
    timerRequest.PeriodMs = 0;

    if (!PfkpDeviceIoControl(PFKP_IOCTL_ARM_TIMER, &timerRequest, PFKP_DWORD_SIZEOF(timerRequest), &returned))
    {
        goto Exit;
    }

    if (EnableCallbacks)
    {
        ZeroMemory(callbackBuffer, sizeof(callbackBuffer));
        callbackRequest = (PFKP_CALLBACK_REQUEST *)callbackBuffer;
        callbackRequest->Header.Size = sizeof(*callbackRequest);
        callbackRequest->Header.Version = 1;
        callbackRequest->Enable = 1;

        if (!PfkpDeviceIoControl(PFKP_IOCTL_ENABLE_CALLBACKS, callbackBuffer, PFKP_DWORD_SIZEOF(callbackBuffer), &returned))
        {
            goto Exit;
        }

        callbackReply = (PFKP_CALLBACK_REPLY *)callbackBuffer;
        wprintf(L"callbacks: enabled=%u status=0x%08x\n", callbackReply->Enabled, callbackReply->Status);
    }

    Sleep(200);

    if (!PfkpQueryStatus())
    {
        goto Exit;
    }

    ZeroMemory(eventBuffer, sizeof(eventBuffer));
    if (!PfkpDeviceIoControl(PFKP_IOCTL_LIST_EVENTS, eventBuffer, PFKP_DWORD_SIZEOF(eventBuffer), &returned))
    {
        goto Exit;
    }

    eventList = (PFKP_EVENT_LIST *)eventBuffer;
    wprintf(
        L"events: count=%u required=%u truncated=%u bytes=%u\n",
        eventList->RecordCount,
        eventList->RequiredRecordCount,
        eventList->Truncated,
        returned);

    for (unsigned int index = 0; index < eventList->RecordCount; ++index)
    {
        const PFKP_EVENT_RECORD *record;

        record = &eventList->Records[index];
        wprintf(
            L"  event[%u]: type=%u pid=%u tid=%u value=0x%08x status=0x%08x seq=%llu\n",
            index,
            record->EventType,
            record->ProcessId,
            record->ThreadId,
            record->Value,
            record->Status,
            record->Sequence);
    }

    ok = true;

Exit:
    return ok;
}

static
void
PfkpCleanup(
    bool LeaveLoaded
    )
{
    SERVICE_STATUS status;

    if (g_DeviceHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_DeviceHandle);
        g_DeviceHandle = INVALID_HANDLE_VALUE;
    }

    if (!LeaveLoaded && g_ServiceHandle != NULL)
    {
        ZeroMemory(&status, sizeof(status));
        if (!ControlService(g_ServiceHandle, SERVICE_CONTROL_STOP, &status))
        {
            DWORD error;

            error = GetLastError();
            if (error != ERROR_SERVICE_NOT_ACTIVE)
            {
                PfkpPrintLastError(L"ControlService(cleanup)", error);
            }
        }

        if (!DeleteService(g_ServiceHandle))
        {
            DWORD error;

            error = GetLastError();
            if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                PfkpPrintLastError(L"DeleteService(cleanup)", error);
            }
        }
    }

    if (g_ServiceHandle != NULL)
    {
        CloseServiceHandle(g_ServiceHandle);
        g_ServiceHandle = NULL;
    }

    if (g_ManagerHandle != NULL)
    {
        CloseServiceHandle(g_ManagerHandle);
        g_ManagerHandle = NULL;
    }
}
