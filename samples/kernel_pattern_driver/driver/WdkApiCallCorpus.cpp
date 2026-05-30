#include <ntifs.h>

#include "../shared/PfKernelPatternIoctl.h"

extern "C" volatile LONG g_PfkpWdkApiCallCorpusEnabled = 0;

static volatile ULONG_PTR g_PfkpWdkApiCallCorpusSink;
static volatile LONG g_PfkpWdkApiCallCorpusStatusSink;

static
VOID
PfkpConsumePointer(
    _In_opt_ PVOID Value
    )
{
    g_PfkpWdkApiCallCorpusSink = (ULONG_PTR)Value;
}

static
VOID
PfkpConsumeUlongPtr(
    _In_ ULONG_PTR Value
    )
{
    g_PfkpWdkApiCallCorpusSink = Value;
}

static
VOID
PfkpConsumeStatus(
    _In_ NTSTATUS Status
    )
{
    g_PfkpWdkApiCallCorpusStatusSink = Status;
}

static
KDEFERRED_ROUTINE PfkpApiCorpusDpcRoutine;

static
VOID
PfkpApiCorpusDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

static
NTSTATUS
PfkpApiCorpusRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    return STATUS_SUCCESS;
}

extern "C"
__declspec(noinline)
VOID
ExFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    FAST_MUTEX fastMutex;
    ERESOURCE resource;
    EX_RUNDOWN_REF rundown;
    NPAGED_LOOKASIDE_LIST lookaside;
    PVOID pool;
    PVOID lookasideEntry;
    LARGE_INTEGER systemTime;
    LARGE_INTEGER localTime;
    UUID uuid;
    BOOLEAN acquired;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    pool = NULL;
    lookasideEntry = NULL;
    acquired = FALSE;

    ExInitializeFastMutex(&fastMutex);
    ExAcquireFastMutex(&fastMutex);
    ExReleaseFastMutex(&fastMutex);
    acquired = ExTryToAcquireFastMutex(&fastMutex);
    if (acquired != FALSE)
    {
        ExReleaseFastMutex(&fastMutex);
    }

    status = ExInitializeResourceLite(&resource);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ExAcquireResourceExclusiveLite(&resource, TRUE);
        ExReleaseResourceLite(&resource);
        ExAcquireResourceSharedLite(&resource, TRUE);
        ExReleaseResourceLite(&resource);
        ExDeleteResourceLite(&resource);
    }

    ExInitializeRundownProtection(&rundown);
    acquired = ExAcquireRundownProtection(&rundown);
    if (acquired != FALSE)
    {
        ExReleaseRundownProtection(&rundown);
    }

    ExWaitForRundownProtectionRelease(&rundown);
    ExRundownCompleted(&rundown);
    ExReInitializeRundownProtection(&rundown);

    pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x40, PFKP_TEMP_POOL_TAG);
    PfkpConsumePointer(pool);
    if (pool != NULL)
    {
        RtlFillMemory(pool, 0x40, 0x41);
        ExFreePoolWithTag(pool, PFKP_TEMP_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable: 4996)
    pool = ExAllocatePoolWithTag(NonPagedPoolNx, 0x20, PFKP_TEMP_POOL_TAG);
#pragma warning(pop)
    PfkpConsumePointer(pool);
    if (pool != NULL)
    {
        ExFreePoolWithTag(pool, PFKP_TEMP_POOL_TAG);
    }

    ExInitializeNPagedLookasideList(
        &lookaside,
        NULL,
        NULL,
        0,
        0x40,
        PFKP_TEMP_POOL_TAG,
        0);
    lookasideEntry = ExAllocateFromNPagedLookasideList(&lookaside);
    PfkpConsumePointer(lookasideEntry);
    if (lookasideEntry != NULL)
    {
        ExFreeToNPagedLookasideList(&lookaside, lookasideEntry);
    }

    ExDeleteNPagedLookasideList(&lookaside);

    KeQuerySystemTimePrecise(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    ExLocalTimeToSystemTime(&localTime, &systemTime);
    status = ExUuidCreate(&uuid);
    PfkpConsumeStatus(status);
    PfkpConsumeUlongPtr((ULONG_PTR)ExGetPreviousMode());
}

extern "C"
__declspec(noinline)
VOID
PsFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    PEPROCESS process;
    PETHREAD thread;
    HANDLE processId;
    HANDLE threadId;
    HANDLE processHandle;
    NTSTATUS status;
    BOOLEAN value;

    UNREFERENCED_PARAMETER(DeviceObject);

    process = PsGetCurrentProcess();
    thread = PsGetCurrentThread();
    processId = PsGetCurrentProcessId();
    threadId = PsGetCurrentThreadId();
    processHandle = PsGetCurrentProcessId();

    PfkpConsumePointer(process);
    PfkpConsumePointer(thread);
    PfkpConsumeUlongPtr((ULONG_PTR)processId);
    PfkpConsumeUlongPtr((ULONG_PTR)threadId);
    PfkpConsumeUlongPtr((ULONG_PTR)PsGetThreadProcessId(thread));
    PfkpConsumeUlongPtr((ULONG_PTR)PsGetThreadId(thread));
    PfkpConsumeUlongPtr((ULONG_PTR)PsGetProcessId(process));
    PfkpConsumeUlongPtr((ULONG_PTR)PsGetProcessCreateTimeQuadPart(process));
    PfkpConsumeStatus(PsGetProcessExitStatus(process));

    value = PsIsSystemThread(thread);
    PfkpConsumeUlongPtr((ULONG_PTR)value);

    status = PsLookupProcessByProcessId(processHandle, &process);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
    }

    status = PsLookupThreadByThreadId(threadId, &thread);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(thread);
    }
}

extern "C"
__declspec(noinline)
VOID
ObFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    PVOID object;
    HANDLE handle;
    ULONG length;
    PSECURITY_DESCRIPTOR securityDescriptor;
    BOOLEAN memoryAllocated;

    if (DeviceObject == NULL)
    {
        return;
    }

    object = NULL;
    handle = NULL;
    length = 0;
    securityDescriptor = NULL;
    memoryAllocated = FALSE;

    ObReferenceObject(DeviceObject);
    ObDereferenceObject(DeviceObject);

    if (ObReferenceObjectSafe(DeviceObject) != FALSE)
    {
        ObDereferenceObject(DeviceObject);
    }

    status = ObReferenceObjectByPointer(
        DeviceObject,
        0,
        NULL,
        KernelMode);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(DeviceObject);
    }

    status = ObOpenObjectByPointer(
        DeviceObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        0,
        NULL,
        KernelMode,
        &handle);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ZwClose(handle);
    }

    status = ObReferenceObjectByHandle(
        NtCurrentProcess(),
        0,
        NULL,
        KernelMode,
        &object,
        NULL);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(object);
    }

    status = ObGetObjectSecurity(DeviceObject, &securityDescriptor, &memoryAllocated);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ObReleaseObjectSecurity(securityDescriptor, memoryAllocated);
    }

    status = ObQueryNameString(DeviceObject, NULL, 0, &length);
    PfkpConsumeStatus(status);
    PfkpConsumeUlongPtr(length);
    PfkpConsumeUlongPtr(ObGetFilterVersion());
    PfkpConsumeUlongPtr((ULONG_PTR)ObIsKernelHandle(NtCurrentProcess()));
}

extern "C"
__declspec(noinline)
VOID
KeFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    KEVENT event;
    KTIMER timer;
    KDPC dpc;
    KSPIN_LOCK spinLock;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;
    LARGE_INTEGER systemTime;
    LARGE_INTEGER tickCount;
    LARGE_INTEGER performanceCounter;
    NTSTATUS status;
    ULONG processor;

    UNREFERENCED_PARAMETER(DeviceObject);

    timeout.QuadPart = 0;
    oldIrql = PASSIVE_LEVEL;

    KeInitializeEvent(&event, NotificationEvent, TRUE);
    KeClearEvent(&event);
    KeSetEvent(&event, IO_NO_INCREMENT, FALSE);
    KeResetEvent(&event);
    KeReadStateEvent(&event);
    status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
    PfkpConsumeStatus(status);

    KeInitializeTimer(&timer);
    KeInitializeTimerEx(&timer, NotificationTimer);
    KeSetTimer(&timer, timeout, NULL);
    KeCancelTimer(&timer);
    KeReadStateTimer(&timer);

    KeInitializeDpc(&dpc, PfkpApiCorpusDpcRoutine, DeviceObject);
    KeSetImportanceDpc(&dpc, LowImportance);
    KeSetTargetProcessorDpc(&dpc, 0);
    KeInsertQueueDpc(&dpc, NULL, NULL);
    KeRemoveQueueDpc(&dpc);
    KeFlushQueuedDpcs();

    KeInitializeSpinLock(&spinLock);
    KeAcquireSpinLock(&spinLock, &oldIrql);
    KeReleaseSpinLock(&spinLock, oldIrql);
    oldIrql = KeAcquireSpinLockRaiseToDpc(&spinLock);
    KeReleaseSpinLockFromDpcLevel(&spinLock);
    KeAcquireSpinLockAtDpcLevel(&spinLock);
    KeReleaseSpinLockFromDpcLevel(&spinLock);
    KeLowerIrql(oldIrql);

    KeEnterCriticalRegion();
    KeLeaveCriticalRegion();
    KeMemoryBarrier();

    KeQueryTickCount(&tickCount);
    KeQuerySystemTimePrecise(&systemTime);
    performanceCounter = KeQueryPerformanceCounter(NULL);
    PfkpConsumeUlongPtr((ULONG_PTR)systemTime.QuadPart);
    PfkpConsumeUlongPtr((ULONG_PTR)KeQueryInterruptTimePrecise(NULL));
    PfkpConsumeUlongPtr((ULONG_PTR)KeGetCurrentIrql());
    processor = KeGetCurrentProcessorNumber();
    PfkpConsumeUlongPtr(processor);
    PfkpConsumeUlongPtr((ULONG_PTR)tickCount.QuadPart);
    PfkpConsumeUlongPtr((ULONG_PTR)performanceCounter.QuadPart);

    status = KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    PfkpConsumeStatus(status);
}

extern "C"
__declspec(noinline)
VOID
IoFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    PIO_WORKITEM workItem;
    PIRP irp;
    PMDL mdl;
    IO_REMOVE_LOCK removeLock;
    KEVENT event;
    PDEVICE_OBJECT attachedDevice;
    PDEVICE_OBJECT baseDevice;
    ULONG length;
    NTSTATUS status;
    UCHAR buffer[0x40];
    UNICODE_STRING eventName;
    HANDLE eventHandle;
    PKEVENT namedEvent;

    if (DeviceObject == NULL)
    {
        return;
    }

    workItem = NULL;
    irp = NULL;
    mdl = NULL;
    attachedDevice = NULL;
    baseDevice = NULL;
    length = 0;
    eventHandle = NULL;
    namedEvent = NULL;
    RtlZeroMemory(buffer, sizeof(buffer));

    workItem = IoAllocateWorkItem(DeviceObject);
    PfkpConsumePointer(workItem);
    if (workItem != NULL)
    {
        IoFreeWorkItem(workItem);
    }

    irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    PfkpConsumePointer(irp);
    if (irp != NULL)
    {
        IoReuseIrp(irp, STATUS_CANCELLED);
        IoFreeIrp(irp);
    }

    mdl = IoAllocateMdl(buffer, sizeof(buffer), FALSE, FALSE, NULL);
    PfkpConsumePointer(mdl);
    if (mdl != NULL)
    {
        IoFreeMdl(mdl);
    }

    IoInitializeRemoveLock(&removeLock, PFKP_TEMP_POOL_TAG, 0, 0);
    status = IoAcquireRemoveLock(&removeLock, DeviceObject);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        IoReleaseRemoveLock(&removeLock, DeviceObject);
    }

    IoInitializeRemoveLock(&removeLock, PFKP_TEMP_POOL_TAG, 0, 0);
    status = IoAcquireRemoveLock(&removeLock, DeviceObject);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        IoReleaseRemoveLockAndWait(&removeLock, DeviceObject);
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlInitUnicodeString(&eventName, L"\\KernelObjects\\PfkpApiCorpusEvent");
    namedEvent = IoCreateNotificationEvent(&eventName, &eventHandle);
    PfkpConsumePointer(namedEvent);
    if (eventHandle != NULL)
    {
        ZwClose(eventHandle);
    }

    namedEvent = IoCreateSynchronizationEvent(&eventName, &eventHandle);
    PfkpConsumePointer(namedEvent);
    if (eventHandle != NULL)
    {
        ZwClose(eventHandle);
    }

    status = IoGetDeviceProperty(
        DeviceObject,
        DevicePropertyDeviceDescription,
        0,
        NULL,
        &length);
    PfkpConsumeStatus(status);
    PfkpConsumeUlongPtr(length);

    attachedDevice = IoGetAttachedDeviceReference(DeviceObject);
    PfkpConsumePointer(attachedDevice);
    if (attachedDevice != NULL)
    {
        ObDereferenceObject(attachedDevice);
    }

    baseDevice = IoGetDeviceAttachmentBaseRef(DeviceObject);
    PfkpConsumePointer(baseDevice);
    if (baseDevice != NULL)
    {
        ObDereferenceObject(baseDevice);
    }

    PfkpConsumePointer(IoGetCurrentProcess());
    PfkpConsumeUlongPtr((ULONG_PTR)IoIsWdmVersionAvailable(1, 0));
    status = IoRegisterShutdownNotification(DeviceObject);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        IoUnregisterShutdownNotification(DeviceObject);
    }

    status = IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_REGISTER);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        (VOID)IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_DEREGISTER);
    }
}

extern "C"
__declspec(noinline)
VOID
CmFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    ULONG major;
    ULONG minor;
    LARGE_INTEGER cookie;
    UNICODE_STRING altitude;
    NTSTATUS status;

    CmGetCallbackVersion(&major, &minor);
    PfkpConsumeUlongPtr(major);
    PfkpConsumeUlongPtr(minor);

    if (DeviceObject == NULL)
    {
        return;
    }

    cookie.QuadPart = 0;
    RtlInitUnicodeString(&altitude, L"385123.9000");
    status = CmRegisterCallbackEx(
        PfkpApiCorpusRegistryCallback,
        &altitude,
        DeviceObject->DriverObject,
        DeviceObject,
        &cookie,
        NULL);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        CmUnRegisterCallback(cookie);
    }

    status = CmRegisterCallback(PfkpApiCorpusRegistryCallback, DeviceObject, &cookie);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        CmUnRegisterCallback(cookie);
    }
}

extern "C"
__declspec(noinline)
VOID
MmFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    PVOID pool;
    PVOID nonCached;
    PMDL mdl;
    PHYSICAL_ADDRESS physicalAddress;
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied;
    UCHAR source[0x40];
    UCHAR destination[0x40];
    UNICODE_STRING routineName;
    PVOID routine;
    PHYSICAL_ADDRESS lowest;
    PHYSICAL_ADDRESS highest;
    PHYSICAL_ADDRESS boundary;

    UNREFERENCED_PARAMETER(DeviceObject);

    pool = NULL;
    nonCached = NULL;
    mdl = NULL;
    copied = 0;
    RtlZeroMemory(source, sizeof(source));
    RtlZeroMemory(destination, sizeof(destination));

    RtlInitUnicodeString(&routineName, L"ZwClose");
    routine = MmGetSystemRoutineAddress(&routineName);
    PfkpConsumePointer(routine);

    pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(source), PFKP_TEMP_POOL_TAG);
    PfkpConsumePointer(pool);
    if (pool != NULL)
    {
        RtlCopyMemory(pool, source, sizeof(source));
        PfkpConsumeUlongPtr((ULONG_PTR)MmIsAddressValid(pool));
        physicalAddress = MmGetPhysicalAddress(pool);
        PfkpConsumeUlongPtr((ULONG_PTR)physicalAddress.QuadPart);

        copyAddress.VirtualAddress = pool;
        (VOID)MmCopyMemory(
            destination,
            copyAddress,
            sizeof(destination),
            MM_COPY_MEMORY_VIRTUAL,
            &copied);
        PfkpConsumeUlongPtr(copied);

        mdl = IoAllocateMdl(pool, sizeof(source), FALSE, FALSE, NULL);
        PfkpConsumePointer(mdl);
        if (mdl != NULL)
        {
            MmBuildMdlForNonPagedPool(mdl);
            PfkpConsumePointer(MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority));
            PfkpConsumeUlongPtr(MmGetMdlByteCount(mdl));
            PfkpConsumeUlongPtr(MmGetMdlByteOffset(mdl));
            PfkpConsumePointer(MmGetMdlVirtualAddress(mdl));
            IoFreeMdl(mdl);
        }

        ExFreePoolWithTag(pool, PFKP_TEMP_POOL_TAG);
    }

    nonCached = MmAllocateNonCachedMemory(sizeof(source));
    PfkpConsumePointer(nonCached);
    if (nonCached != NULL)
    {
        MmFreeNonCachedMemory(nonCached, sizeof(source));
    }

    lowest.QuadPart = 0;
    highest.QuadPart = MAXLONGLONG;
    boundary.QuadPart = 0;
    pool = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE,
        lowest,
        highest,
        boundary,
        MmCached);
    PfkpConsumePointer(pool);
    if (pool != NULL)
    {
        MmFreeContiguousMemory(pool);
    }
}

extern "C"
__declspec(noinline)
VOID
NtFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    ULONG returnedLength;
    UCHAR information[0x100];
    IO_STATUS_BLOCK ioStatus;
    HANDLE tokenHandle;

    UNREFERENCED_PARAMETER(DeviceObject);

    returnedLength = 0;
    tokenHandle = NULL;
    RtlZeroMemory(information, sizeof(information));
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));

    status = NtClose(NULL);
    PfkpConsumeStatus(status);
    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        (VOID)NtQueryInformationToken(
            tokenHandle,
            TokenUser,
            information,
            sizeof(information),
            &returnedLength);
        NtClose(tokenHandle);
    }

    status = NtQuerySecurityObject(
        NULL,
        OWNER_SECURITY_INFORMATION,
        (PSECURITY_DESCRIPTOR)information,
        sizeof(information),
        &returnedLength);
    PfkpConsumeStatus(status);
    status = NtQueryInformationFile(
        NULL,
        &ioStatus,
        information,
        sizeof(information),
        FileBasicInformation);
    PfkpConsumeStatus(status);
}

extern "C"
__declspec(noinline)
VOID
ZwFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING name;
    UNICODE_STRING valueName;
    HANDLE handle;
    HANDLE tokenHandle;
    LARGE_INTEGER timeout;
    NTSTATUS status;
    ULONG returnedLength;
    UCHAR information[0x100];

    UNREFERENCED_PARAMETER(DeviceObject);

    handle = NULL;
    tokenHandle = NULL;
    returnedLength = 0;
    timeout.QuadPart = 0;
    RtlZeroMemory(information, sizeof(information));
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));

    status = ZwClose(NULL);
    PfkpConsumeStatus(status);
    status = ZwWaitForSingleObject(NULL, FALSE, &timeout);
    PfkpConsumeStatus(status);

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateEvent(
        &handle,
        EVENT_ALL_ACCESS,
        &objectAttributes,
        NotificationEvent,
        FALSE);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        (VOID)ZwSetEvent(handle, NULL);
        (VOID)ZwWaitForSingleObject(handle, FALSE, &timeout);
        ZwClose(handle);
        handle = NULL;
    }

    RtlInitUnicodeString(&name, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
    InitializeObjectAttributes(&objectAttributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&handle, KEY_READ, &objectAttributes);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(&valueName, L"SystemStartOptions");
        (VOID)ZwQueryValueKey(
            handle,
            &valueName,
            KeyValuePartialInformation,
            information,
            sizeof(information),
            &returnedLength);
        (VOID)ZwQueryKey(
            handle,
            KeyBasicInformation,
            information,
            sizeof(information),
            &returnedLength);
        ZwClose(handle);
        handle = NULL;
    }

    status = ZwOpenProcessTokenEx(
        NtCurrentProcess(),
        TOKEN_QUERY,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        (VOID)ZwQueryInformationToken(
            tokenHandle,
            TokenUser,
            information,
            sizeof(information),
            &returnedLength);
        ZwClose(tokenHandle);
    }

    status = ZwOpenThreadTokenEx(
        NtCurrentThread(),
        TOKEN_QUERY,
        TRUE,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ZwClose(tokenHandle);
    }

    status = ZwQueryObject(
        NULL,
        ObjectBasicInformation,
        information,
        sizeof(information),
        &returnedLength);
    PfkpConsumeStatus(status);

    RtlInitUnicodeString(&name, L"\\SystemRoot\\Temp\\PfkpApiCorpus.tmp");
    InitializeObjectAttributes(&objectAttributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(
        &handle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        (VOID)ZwQueryInformationFile(
            handle,
            &ioStatus,
            information,
            sizeof(information),
            FileBasicInformation);
        ZwClose(handle);
    }
}

extern "C"
__declspec(noinline)
VOID
RtlFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    WCHAR unicodeBuffer[64];
    CHAR ansiBuffer[64];
    UNICODE_STRING unicodeString;
    UNICODE_STRING unicodeString2;
    UNICODE_STRING allocatedUnicode;
    ANSI_STRING ansiString;
    ANSI_STRING allocatedAnsi;
    ULONG value;
    ULONG hash;
    ULONG seed;
    ULONG bits[2];
    RTL_BITMAP bitmap;
    TIME_FIELDS timeFields;
    LARGE_INTEGER timeValue;
    GUID guid;
    UNICODE_STRING guidString;
    SECURITY_DESCRIPTOR securityDescriptor;
    SID_IDENTIFIER_AUTHORITY authority;
    UCHAR sidBuffer[SECURITY_MAX_SID_SIZE];
    PSID sid;
    ULONG sidLength;
    RTL_OSVERSIONINFOW versionInfo;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    RtlZeroMemory(unicodeBuffer, sizeof(unicodeBuffer));
    RtlZeroMemory(ansiBuffer, sizeof(ansiBuffer));
    RtlZeroMemory(&allocatedUnicode, sizeof(allocatedUnicode));
    RtlZeroMemory(&allocatedAnsi, sizeof(allocatedAnsi));
    RtlZeroMemory(&guidString, sizeof(guidString));
    RtlZeroMemory(&versionInfo, sizeof(versionInfo));
    value = 0;
    hash = 0;
    seed = 0x1234u;

    RtlInitEmptyUnicodeString(&unicodeString, unicodeBuffer, sizeof(unicodeBuffer));
    RtlInitUnicodeString(&unicodeString2, L"PfKernelPattern");
    status = RtlAppendUnicodeStringToString(&unicodeString, &unicodeString2);
    PfkpConsumeStatus(status);
    status = RtlAppendUnicodeToString(&unicodeString, L"Api");
    PfkpConsumeStatus(status);
    RtlCopyUnicodeString(&unicodeString, &unicodeString2);
    PfkpConsumeUlongPtr((ULONG_PTR)RtlEqualUnicodeString(&unicodeString, &unicodeString2, TRUE));
    PfkpConsumeStatus(RtlCompareUnicodeString(&unicodeString, &unicodeString2, TRUE));
    PfkpConsumeUlongPtr((ULONG_PTR)RtlPrefixUnicodeString(&unicodeString2, &unicodeString, TRUE));
    PfkpConsumeUlongPtr((ULONG_PTR)RtlSuffixUnicodeString(&unicodeString2, &unicodeString, TRUE));
    status = RtlHashUnicodeString(&unicodeString, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &hash);
    PfkpConsumeStatus(status);
    PfkpConsumeUlongPtr(hash);

    RtlInitString(&ansiString, "1234");
    status = RtlAnsiStringToUnicodeString(&allocatedUnicode, &ansiString, TRUE);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        RtlFreeUnicodeString(&allocatedUnicode);
    }

    status = RtlUnicodeStringToAnsiString(&allocatedAnsi, &unicodeString2, TRUE);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        RtlFreeAnsiString(&allocatedAnsi);
    }

    status = RtlUnicodeStringToInteger(&unicodeString2, 10, &value);
    PfkpConsumeStatus(status);
    status = RtlIntegerToUnicodeString(0x1234u, 16, &unicodeString);
    PfkpConsumeStatus(status);

    RtlFillMemory(ansiBuffer, sizeof(ansiBuffer), 0x41);
    RtlCopyMemory(ansiBuffer, "PFKP", sizeof("PFKP"));
    RtlMoveMemory(ansiBuffer + 1, ansiBuffer, 4);
    PfkpConsumeUlongPtr(RtlCompareMemory(ansiBuffer, "PPFK", 4));
    RtlZeroMemory(ansiBuffer, sizeof(ansiBuffer));

    RtlInitializeBitMap(&bitmap, bits, RTL_NUMBER_OF(bits) * sizeof(ULONG) * 8);
    RtlClearAllBits(&bitmap);
    RtlSetBits(&bitmap, 1, 3);
    PfkpConsumeUlongPtr((ULONG_PTR)RtlAreBitsSet(&bitmap, 1, 3));
    PfkpConsumeUlongPtr((ULONG_PTR)RtlAreBitsClear(&bitmap, 8, 2));
    PfkpConsumeUlongPtr(RtlFindClearBitsAndSet(&bitmap, 2, 8));
    RtlClearBits(&bitmap, 1, 3);

    RtlSecondsSince1970ToTime(1, &timeValue);
    RtlTimeToTimeFields(&timeValue, &timeFields);
    RtlTimeFieldsToTime(&timeFields, &timeValue);
    (VOID)RtlTimeToSecondsSince1970(&timeValue, &value);
    PfkpConsumeUlongPtr(value);

    RtlInitUnicodeString(&unicodeString2, L"{00000000-0000-0000-0000-000000000000}");
    status = RtlGUIDFromString(&unicodeString2, &guid);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        status = RtlStringFromGUID(guid, &guidString);
        PfkpConsumeStatus(status);
        if (NT_SUCCESS(status))
        {
            RtlFreeUnicodeString(&guidString);
        }
    }

    authority.Value[0] = 0;
    authority.Value[1] = 0;
    authority.Value[2] = 0;
    authority.Value[3] = 0;
    authority.Value[4] = 0;
    authority.Value[5] = 5;
    sid = (PSID)sidBuffer;
    sidLength = sizeof(sidBuffer);
    RtlZeroMemory(sidBuffer, sizeof(sidBuffer));
    status = RtlInitializeSid(sid, &authority, 1);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        *RtlSubAuthoritySid(sid, 0) = SECURITY_LOCAL_SYSTEM_RID;
        PfkpConsumeUlongPtr(RtlLengthSid(sid));
        PfkpConsumeUlongPtr((ULONG_PTR)RtlValidSid(sid));
        PfkpConsumeUlongPtr((ULONG_PTR)RtlEqualSid(sid, sid));
        sidLength = RtlLengthRequiredSid(1);
        PfkpConsumeUlongPtr(sidLength);
    }

    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        PfkpConsumeUlongPtr((ULONG_PTR)RtlValidSecurityDescriptor(&securityDescriptor));
        PfkpConsumeUlongPtr(RtlLengthSecurityDescriptor(&securityDescriptor));
    }

    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    status = RtlGetVersion(&versionInfo);
    PfkpConsumeStatus(status);
    PfkpConsumeUlongPtr(versionInfo.dwBuildNumber);
    PfkpConsumeUlongPtr(RtlRandomEx(&seed));
}

extern "C"
__declspec(noinline)
VOID
SeFunctionCallTest(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    SECURITY_SUBJECT_CONTEXT subjectContext;
    SECURITY_DESCRIPTOR securityDescriptor;
    GENERIC_MAPPING genericMapping;
    PRIVILEGE_SET privileges;
    PPRIVILEGE_SET privilegesPointer;
    ACCESS_MASK grantedAccess;
    NTSTATUS accessStatus;
    NTSTATUS status;
    LUID privilege;
    PACCESS_TOKEN token;
    PVOID tokenInformation;
    PUNICODE_STRING imageName;
    BOOLEAN granted;

    UNREFERENCED_PARAMETER(DeviceObject);

    token = NULL;
    tokenInformation = NULL;
    imageName = NULL;
    grantedAccess = 0;
    accessStatus = STATUS_SUCCESS;
    privilegesPointer = &privileges;
    RtlZeroMemory(&subjectContext, sizeof(subjectContext));
    RtlZeroMemory(&securityDescriptor, sizeof(securityDescriptor));
    RtlZeroMemory(&genericMapping, sizeof(genericMapping));
    RtlZeroMemory(&privileges, sizeof(privileges));

    SeCaptureSubjectContext(&subjectContext);
    SeLockSubjectContext(&subjectContext);
    SeUnlockSubjectContext(&subjectContext);

    privilege.LowPart = SE_DEBUG_PRIVILEGE;
    privilege.HighPart = 0;
    granted = SeSinglePrivilegeCheck(privilege, KernelMode);
    PfkpConsumeUlongPtr((ULONG_PTR)granted);

    privileges.PrivilegeCount = 1;
    privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privileges.Privilege[0].Luid = privilege;
    privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    granted = SePrivilegeCheck(&privileges, &subjectContext, KernelMode);
    PfkpConsumeUlongPtr((ULONG_PTR)granted);

    status = RtlCreateSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        genericMapping.GenericRead = READ_CONTROL;
        genericMapping.GenericWrite = WRITE_DAC;
        genericMapping.GenericExecute = SYNCHRONIZE;
        genericMapping.GenericAll = STANDARD_RIGHTS_ALL;
        granted = SeAccessCheck(
            &securityDescriptor,
            &subjectContext,
            FALSE,
            READ_CONTROL,
            0,
            &privilegesPointer,
            &genericMapping,
            KernelMode,
            &grantedAccess,
            &accessStatus);
        PfkpConsumeUlongPtr((ULONG_PTR)granted);
        PfkpConsumeUlongPtr(grantedAccess);
        PfkpConsumeStatus(accessStatus);
    }

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token != NULL)
    {
        PfkpConsumeUlongPtr((ULONG_PTR)SeTokenIsAdmin(token));
        status = SeQueryInformationToken(token, TokenUser, &tokenInformation);
        PfkpConsumeStatus(status);
        if (NT_SUCCESS(status))
        {
            ExFreePool(tokenInformation);
        }

        PsDereferencePrimaryToken(token);
    }

    status = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
    PfkpConsumeStatus(status);
    if (NT_SUCCESS(status))
    {
        ExFreePool(imageName);
    }

    SeReleaseSubjectContext(&subjectContext);
}

extern "C"
__declspec(noinline)
VOID
PfkpWdkApiCallCorpusEntry(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    if (InterlockedCompareExchange(
            const_cast<volatile LONG *>(&g_PfkpWdkApiCallCorpusEnabled),
            0,
            0) != 0)
    {
        ExFunctionCallTest(DeviceObject);
        PsFunctionCallTest(DeviceObject);
        ObFunctionCallTest(DeviceObject);
        KeFunctionCallTest(DeviceObject);
        IoFunctionCallTest(DeviceObject);
        CmFunctionCallTest(DeviceObject);
        MmFunctionCallTest(DeviceObject);
        NtFunctionCallTest(DeviceObject);
        ZwFunctionCallTest(DeviceObject);
        RtlFunctionCallTest(DeviceObject);
        SeFunctionCallTest(DeviceObject);
    }
}
