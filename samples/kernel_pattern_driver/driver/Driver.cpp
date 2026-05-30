#include <ntifs.h>

#define INITGUID
#include "../shared/PfKernelPatternIoctl.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001u
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002u
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008u
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010u
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020u
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040u
#endif

typedef struct _PFKP_RECORD_ENTRY
{
    LIST_ENTRY Link;
    PFKP_EVENT_RECORD Record;
} PFKP_RECORD_ENTRY, *PPFKP_RECORD_ENTRY;

typedef struct _PFKP_PROCESS_RULE_ENTRY
{
    LIST_ENTRY Link;
    HANDLE ProcessId;
    ULONG AccessCount;
    BOOLEAN AutoAdded;
    LARGE_INTEGER LastAccessTime;
} PFKP_PROCESS_RULE_ENTRY, *PPFKP_PROCESS_RULE_ENTRY;

typedef struct _PFKP_DEVICE_EXTENSION
{
    ULONG Signature;
    PDEVICE_OBJECT DeviceObject;
    FAST_MUTEX StateLock;
    FAST_MUTEX AccessListLock;
    KSPIN_LOCK EventLock;
    LIST_ENTRY EventList;
    LIST_ENTRY ProcessWhitelist;
    LIST_ENTRY ProcessBlacklist;
    NPAGED_LOOKASIDE_LIST RecordLookaside;
    NPAGED_LOOKASIDE_LIST ProcessRuleLookaside;
    KTIMER Timer;
    KDPC TimerDpc;
    PIO_WORKITEM WorkItem;
    KEVENT WorkItemIdleEvent;
    EX_RUNDOWN_REF Rundown;
    ERESOURCE Resource;
    UNICODE_STRING RegistryPath;
    ULONG MaxRecords;
    ULONG EventCount;
    ULONG IoctlCount;
    ULONG AllocationCount;
    ULONG ProcessCallbackCount;
    ULONG ImageCallbackCount;
    ULONG ThreadCallbackCount;
    ULONG ObCallbackCount;
    ULONG WhitelistHitCount;
    ULONG BlacklistHitCount;
    ULONG TimerFireCount;
    ULONG WorkItemCount;
    ULONG LastErrorStatus;
    PVOID ObRegistrationHandle;
    volatile LONG WorkItemQueued;
    volatile LONG CallbacksRegistered;
    volatile LONG TimerArmed;
    volatile LONG Unloading;
} PFKP_DEVICE_EXTENSION, *PPFKP_DEVICE_EXTENSION;

static PDEVICE_OBJECT g_DeviceObject;
static UNICODE_STRING g_DosDeviceName;

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" VOID PfkpWdkApiCallCorpusEntry(_In_opt_ PDEVICE_OBJECT DeviceObject);
static DRIVER_UNLOAD PfkpUnload;
static DRIVER_DISPATCH PfkpCreateClose;
static DRIVER_DISPATCH PfkpDeviceControl;
static DRIVER_DISPATCH PfkpUnsupported;

static IO_WORKITEM_ROUTINE PfkpWorkItemRoutine;
static KDEFERRED_ROUTINE PfkpTimerDpcRoutine;
static VOID PfkpProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
static VOID PfkpLoadImageNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
static VOID PfkpThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
static OB_PREOP_CALLBACK_STATUS PfkpObjectPreOperation(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

static NTSTATUS PfkpReadConfiguration(_Inout_ PPFKP_DEVICE_EXTENSION Extension);
static NTSTATUS PfkpCopyRegistryPath(_Inout_ PUNICODE_STRING Destination, _In_ PUNICODE_STRING Source);
static VOID PfkpDeleteEvents(_Inout_ PPFKP_DEVICE_EXTENSION Extension);
static VOID PfkpDeleteProcessRules(_Inout_ PPFKP_DEVICE_EXTENSION Extension);
static VOID PfkpRecordEvent(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _In_ ULONG EventType, _In_ ULONG Value, _In_ NTSTATUS Status);
static NTSTATUS PfkpSeedProcessRules(_Inout_ PPFKP_DEVICE_EXTENSION Extension);
static NTSTATUS PfkpAddProcessRuleLocked(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_ PLIST_ENTRY ListHead, _In_ HANDLE ProcessId, _In_ BOOLEAN AutoAdded);
static BOOLEAN PfkpFindProcessRuleLocked(_In_ PLIST_ENTRY ListHead, _In_ HANDLE ProcessId, _Outptr_result_maybenull_ PPFKP_PROCESS_RULE_ENTRY *MatchedEntry);
static NTSTATUS PfkpSetCallbacks(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _In_ BOOLEAN Enable);
static NTSTATUS PfkpHandleAllocate(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(OutputLength) PVOID Buffer, _In_ ULONG InputLength, _In_ ULONG OutputLength, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleQueryProcess(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(OutputLength) PVOID Buffer, _In_ ULONG InputLength, _In_ ULONG OutputLength, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleGetStatus(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleQueueWork(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleArmTimer(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleEnableCallbacks(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(OutputLength) PVOID Buffer, _In_ ULONG InputLength, _In_ ULONG OutputLength, _Out_ PULONG_PTR Information);
static NTSTATUS PfkpHandleListEvents(_Inout_ PPFKP_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);

extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT deviceObject;
    PPFKP_DEVICE_EXTENSION extension;
    ULONG index;

    status = STATUS_SUCCESS;
    deviceObject = NULL;
    extension = NULL;

    RtlInitUnicodeString(&deviceName, PFKP_NT_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosDeviceName, PFKP_DOS_DEVICE_NAME);

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index)
    {
        DriverObject->MajorFunction[index] = PfkpUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PfkpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PfkpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PfkpDeviceControl;
    DriverObject->DriverUnload = PfkpUnload;

    status = IoCreateDevice(
        DriverObject,
        sizeof(PFKP_DEVICE_EXTENSION),
        &deviceName,
        PFKP_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    extension = (PPFKP_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));

    extension->Signature = PFKP_POOL_TAG;
    extension->DeviceObject = deviceObject;
    extension->MaxRecords = 64;
    g_DeviceObject = deviceObject;

    ExInitializeFastMutex(&extension->StateLock);
    ExInitializeFastMutex(&extension->AccessListLock);
    KeInitializeSpinLock(&extension->EventLock);
    InitializeListHead(&extension->EventList);
    InitializeListHead(&extension->ProcessWhitelist);
    InitializeListHead(&extension->ProcessBlacklist);
    ExInitializeNPagedLookasideList(
        &extension->RecordLookaside,
        NULL,
        NULL,
        0,
        sizeof(PFKP_RECORD_ENTRY),
        PFKP_RECORD_POOL_TAG,
        0);
    ExInitializeNPagedLookasideList(
        &extension->ProcessRuleLookaside,
        NULL,
        NULL,
        0,
        sizeof(PFKP_PROCESS_RULE_ENTRY),
        PFKP_RULE_POOL_TAG,
        0);
    KeInitializeTimerEx(&extension->Timer, NotificationTimer);
    KeInitializeDpc(&extension->TimerDpc, PfkpTimerDpcRoutine, extension);
    KeInitializeEvent(&extension->WorkItemIdleEvent, NotificationEvent, TRUE);
    ExInitializeRundownProtection(&extension->Rundown);
    ExInitializeResourceLite(&extension->Resource);

    status = PfkpSeedProcessRules(extension);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = PfkpCopyRegistryPath(&extension->RegistryPath, RegistryPath);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    (VOID)PfkpReadConfiguration(extension);

    extension->WorkItem = IoAllocateWorkItem(deviceObject);
    if (extension->WorkItem == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    status = IoCreateSymbolicLink(&g_DosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    PfkpWdkApiCallCorpusEntry(deviceObject);

Exit:
    if (!NT_SUCCESS(status))
    {
        if (extension != NULL)
        {
            if (extension->WorkItem != NULL)
            {
                IoFreeWorkItem(extension->WorkItem);
                extension->WorkItem = NULL;
            }

            if (extension->RegistryPath.Buffer != NULL)
            {
                ExFreePoolWithTag(extension->RegistryPath.Buffer, PFKP_POOL_TAG);
                RtlZeroMemory(&extension->RegistryPath, sizeof(extension->RegistryPath));
            }

            ExDeleteResourceLite(&extension->Resource);
            PfkpDeleteProcessRules(extension);
            ExDeleteNPagedLookasideList(&extension->ProcessRuleLookaside);
            ExDeleteNPagedLookasideList(&extension->RecordLookaside);
        }

        if (deviceObject != NULL)
        {
            IoDeleteDevice(deviceObject);
            g_DeviceObject = NULL;
        }
    }

    return status;
}

static
VOID
PfkpUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT deviceObject;
    PPFKP_DEVICE_EXTENSION extension;

    deviceObject = DriverObject->DeviceObject;
    if (deviceObject == NULL)
    {
        return;
    }

    extension = (PPFKP_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    InterlockedExchange(&extension->Unloading, 1);

    (VOID)PfkpSetCallbacks(extension, FALSE);
    KeCancelTimer(&extension->Timer);
    KeFlushQueuedDpcs();

    if (InterlockedCompareExchange(&extension->WorkItemQueued, 0, 0) != 0)
    {
        KeWaitForSingleObject(&extension->WorkItemIdleEvent, Executive, KernelMode, FALSE, NULL);
    }

    ExWaitForRundownProtectionRelease(&extension->Rundown);

    PfkpDeleteEvents(extension);
    PfkpDeleteProcessRules(extension);

    if (extension->WorkItem != NULL)
    {
        IoFreeWorkItem(extension->WorkItem);
        extension->WorkItem = NULL;
    }

    if (extension->RegistryPath.Buffer != NULL)
    {
        ExFreePoolWithTag(extension->RegistryPath.Buffer, PFKP_POOL_TAG);
        RtlZeroMemory(&extension->RegistryPath, sizeof(extension->RegistryPath));
    }

    ExDeleteResourceLite(&extension->Resource);
    ExDeleteNPagedLookasideList(&extension->ProcessRuleLookaside);
    ExDeleteNPagedLookasideList(&extension->RecordLookaside);

    IoDeleteSymbolicLink(&g_DosDeviceName);
    IoDeleteDevice(deviceObject);
    g_DeviceObject = NULL;
}

static
NTSTATUS
PfkpUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

static
NTSTATUS
PfkpCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PPFKP_DEVICE_EXTENSION extension;

    extension = (PPFKP_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PfkpRecordEvent(extension, PFKP_EVENT_IOCTL, 0, STATUS_SUCCESS);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PPFKP_DEVICE_EXTENSION extension;
    PIO_STACK_LOCATION stack;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG controlCode;
    NTSTATUS status;
    ULONG_PTR information;

    extension = (PPFKP_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    status = STATUS_INVALID_DEVICE_REQUEST;
    information = 0;

    InterlockedIncrement((volatile LONG *)&extension->IoctlCount);

    if (buffer == NULL && (inputLength != 0 || outputLength != 0))
    {
        status = STATUS_INVALID_USER_BUFFER;
        goto Complete;
    }

    if (InterlockedCompareExchange(&extension->Unloading, 0, 0) != 0)
    {
        status = STATUS_DELETE_PENDING;
        goto Complete;
    }

    switch (controlCode)
    {
    case PFKP_IOCTL_GET_STATUS:
        status = PfkpHandleGetStatus(extension, buffer, outputLength, &information);
        break;
    case PFKP_IOCTL_RESET_COUNTERS:
        ExAcquireFastMutex(&extension->StateLock);
        extension->IoctlCount = 0;
        extension->AllocationCount = 0;
        extension->ProcessCallbackCount = 0;
        extension->ImageCallbackCount = 0;
        extension->ThreadCallbackCount = 0;
        extension->ObCallbackCount = 0;
        extension->WhitelistHitCount = 0;
        extension->BlacklistHitCount = 0;
        extension->TimerFireCount = 0;
        extension->WorkItemCount = 0;
        extension->LastErrorStatus = STATUS_SUCCESS;
        ExReleaseFastMutex(&extension->StateLock);
        status = STATUS_SUCCESS;
        break;
    case PFKP_IOCTL_ALLOCATE_PATTERN:
        status = PfkpHandleAllocate(extension, buffer, inputLength, outputLength, &information);
        break;
    case PFKP_IOCTL_QUERY_PROCESS:
        status = PfkpHandleQueryProcess(extension, buffer, inputLength, outputLength, &information);
        break;
    case PFKP_IOCTL_QUEUE_WORK:
        status = PfkpHandleQueueWork(extension, &information);
        break;
    case PFKP_IOCTL_ARM_TIMER:
        status = PfkpHandleArmTimer(extension, buffer, inputLength, &information);
        break;
    case PFKP_IOCTL_ENABLE_CALLBACKS:
        status = PfkpHandleEnableCallbacks(extension, buffer, inputLength, outputLength, &information);
        break;
    case PFKP_IOCTL_LIST_EVENTS:
        status = PfkpHandleListEvents(extension, buffer, outputLength, &information);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    if (!NT_SUCCESS(status))
    {
        extension->LastErrorStatus = (ULONG)status;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static
NTSTATUS
PfkpCopyRegistryPath(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PUNICODE_STRING Source
    )
{
    USHORT bytes;
    PWSTR buffer;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Source->Length > (USHORT)(MAXUSHORT - sizeof(WCHAR)))
    {
        return STATUS_NAME_TOO_LONG;
    }

    bytes = (USHORT)(Source->Length + sizeof(WCHAR));
    buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, bytes, PFKP_POOL_TAG);
    if (buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bytes);
    RtlCopyMemory(buffer, Source->Buffer, Source->Length);

    Destination->Buffer = buffer;
    Destination->Length = Source->Length;
    Destination->MaximumLength = bytes;
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpReadConfiguration(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension
    )
{
    NTSTATUS status;
    RTL_QUERY_REGISTRY_TABLE queryTable[3];
    ULONG maxRecords;
    ULONG timerPeriodMs;

    maxRecords = Extension->MaxRecords;
    timerPeriodMs = 0;
    RtlZeroMemory(queryTable, sizeof(queryTable));

    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    queryTable[0].Name = (PWSTR)L"MaxRecords";
    queryTable[0].EntryContext = &maxRecords;
    queryTable[0].DefaultType = REG_DWORD;
    queryTable[0].DefaultData = &maxRecords;
    queryTable[0].DefaultLength = sizeof(maxRecords);

    queryTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
    queryTable[1].Name = (PWSTR)L"TimerPeriodMs";
    queryTable[1].EntryContext = &timerPeriodMs;
    queryTable[1].DefaultType = REG_DWORD;
    queryTable[1].DefaultData = &timerPeriodMs;
    queryTable[1].DefaultLength = sizeof(timerPeriodMs);

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        Extension->RegistryPath.Buffer,
        queryTable,
        NULL,
        NULL);

    if (NT_SUCCESS(status))
    {
        if (maxRecords >= 8 && maxRecords <= 1024)
        {
            Extension->MaxRecords = maxRecords;
        }

        if (timerPeriodMs != 0)
        {
            LARGE_INTEGER dueTime;

            dueTime.QuadPart = -((LONGLONG)timerPeriodMs * 10000LL);
            KeSetTimerEx(&Extension->Timer, dueTime, (LONG)timerPeriodMs, &Extension->TimerDpc);
            InterlockedExchange(&Extension->TimerArmed, 1);
        }
    }

    return status;
}

static
VOID
PfkpDeleteEvents(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension
    )
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    InitializeListHead(&localList);

    KeAcquireSpinLock(&Extension->EventLock, &oldIrql);
    while (!IsListEmpty(&Extension->EventList))
    {
        PLIST_ENTRY entry;

        entry = RemoveHeadList(&Extension->EventList);
        InsertTailList(&localList, entry);
    }
    Extension->EventCount = 0;
    KeReleaseSpinLock(&Extension->EventLock, oldIrql);

    while (!IsListEmpty(&localList))
    {
        PLIST_ENTRY entry;
        PPFKP_RECORD_ENTRY record;

        entry = RemoveHeadList(&localList);
        record = CONTAINING_RECORD(entry, PFKP_RECORD_ENTRY, Link);
        ExFreeToNPagedLookasideList(&Extension->RecordLookaside, record);
    }
}

static
NTSTATUS
PfkpSeedProcessRules(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension
    )
{
    NTSTATUS status;

    ExAcquireFastMutex(&Extension->AccessListLock);

    status = PfkpAddProcessRuleLocked(
        Extension,
        &Extension->ProcessBlacklist,
        ULongToHandle(4),
        FALSE);
    if (NT_SUCCESS(status))
    {
        status = PfkpAddProcessRuleLocked(
            Extension,
            &Extension->ProcessWhitelist,
            PsGetCurrentProcessId(),
            FALSE);
    }

    ExReleaseFastMutex(&Extension->AccessListLock);
    return status;
}

static
VOID
PfkpDeleteProcessRules(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension
    )
{
    PLIST_ENTRY entry;

    ExAcquireFastMutex(&Extension->AccessListLock);

    while (!IsListEmpty(&Extension->ProcessWhitelist))
    {
        PPFKP_PROCESS_RULE_ENTRY rule;

        entry = RemoveHeadList(&Extension->ProcessWhitelist);
        rule = CONTAINING_RECORD(entry, PFKP_PROCESS_RULE_ENTRY, Link);
        ExFreeToNPagedLookasideList(&Extension->ProcessRuleLookaside, rule);
    }

    while (!IsListEmpty(&Extension->ProcessBlacklist))
    {
        PPFKP_PROCESS_RULE_ENTRY rule;

        entry = RemoveHeadList(&Extension->ProcessBlacklist);
        rule = CONTAINING_RECORD(entry, PFKP_PROCESS_RULE_ENTRY, Link);
        ExFreeToNPagedLookasideList(&Extension->ProcessRuleLookaside, rule);
    }

    ExReleaseFastMutex(&Extension->AccessListLock);
}

static
NTSTATUS
PfkpAddProcessRuleLocked(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_ PLIST_ENTRY ListHead,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN AutoAdded
    )
{
    PPFKP_PROCESS_RULE_ENTRY existingRule;
    PPFKP_PROCESS_RULE_ENTRY newRule;

    existingRule = NULL;
    if (PfkpFindProcessRuleLocked(ListHead, ProcessId, &existingRule))
    {
        return STATUS_SUCCESS;
    }

    newRule = (PPFKP_PROCESS_RULE_ENTRY)ExAllocateFromNPagedLookasideList(&Extension->ProcessRuleLookaside);
    if (newRule == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newRule, sizeof(*newRule));
    newRule->ProcessId = ProcessId;
    newRule->AccessCount = 1;
    newRule->AutoAdded = AutoAdded;
    KeQuerySystemTimePrecise(&newRule->LastAccessTime);
    InsertTailList(ListHead, &newRule->Link);
    return STATUS_SUCCESS;
}

static
BOOLEAN
PfkpFindProcessRuleLocked(
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE ProcessId,
    _Outptr_result_maybenull_ PPFKP_PROCESS_RULE_ENTRY *MatchedEntry
    )
{
    PLIST_ENTRY entry;
    BOOLEAN found;

    found = FALSE;
    *MatchedEntry = NULL;

    entry = ListHead->Flink;
    while (entry != ListHead)
    {
        PPFKP_PROCESS_RULE_ENTRY rule;

        rule = CONTAINING_RECORD(entry, PFKP_PROCESS_RULE_ENTRY, Link);
        if (rule->ProcessId == ProcessId)
        {
            rule->AccessCount++;
            KeQuerySystemTimePrecise(&rule->LastAccessTime);
            *MatchedEntry = rule;
            found = TRUE;
            break;
        }

        entry = entry->Flink;
    }

    return found;
}

static
VOID
PfkpRecordEvent(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _In_ ULONG EventType,
    _In_ ULONG Value,
    _In_ NTSTATUS Status
    )
{
    PPFKP_RECORD_ENTRY record;
    LARGE_INTEGER time;
    KIRQL oldIrql;

    if (InterlockedCompareExchange(&Extension->Unloading, 0, 0) != 0)
    {
        return;
    }

    record = (PPFKP_RECORD_ENTRY)ExAllocateFromNPagedLookasideList(&Extension->RecordLookaside);
    if (record == NULL)
    {
        Extension->LastErrorStatus = (ULONG)STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    RtlZeroMemory(record, sizeof(*record));
    KeQuerySystemTimePrecise(&time);
    record->Record.RecordSize = sizeof(record->Record);
    record->Record.EventType = EventType;
    record->Record.ProcessId = HandleToULong(PsGetCurrentProcessId());
    record->Record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    record->Record.Value = Value;
    record->Record.Status = (ULONG)Status;
    record->Record.Sequence = (ULONGLONG)InterlockedIncrement((volatile LONG *)&Extension->EventCount);
    record->Record.Time100ns = time.QuadPart;

    KeAcquireSpinLock(&Extension->EventLock, &oldIrql);
    InsertTailList(&Extension->EventList, &record->Link);

    while (Extension->EventCount > Extension->MaxRecords && !IsListEmpty(&Extension->EventList))
    {
        PLIST_ENTRY oldEntry;
        PPFKP_RECORD_ENTRY oldRecord;

        oldEntry = RemoveHeadList(&Extension->EventList);
        oldRecord = CONTAINING_RECORD(oldEntry, PFKP_RECORD_ENTRY, Link);
        --Extension->EventCount;
        ExFreeToNPagedLookasideList(&Extension->RecordLookaside, oldRecord);
    }

    KeReleaseSpinLock(&Extension->EventLock, oldIrql);
}

static
NTSTATUS
PfkpSetCallbacks(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _In_ BOOLEAN Enable
    )
{
    NTSTATUS status;
    NTSTATUS imageStatus;
    NTSTATUS threadStatus;
    NTSTATUS objectStatus;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration;
    UNICODE_STRING altitude;

    status = STATUS_SUCCESS;
    imageStatus = STATUS_SUCCESS;
    threadStatus = STATUS_SUCCESS;
    objectStatus = STATUS_SUCCESS;
    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    RtlZeroMemory(&operationRegistration, sizeof(operationRegistration));
    RtlInitUnicodeString(&altitude, L"370030");

    ExAcquireFastMutex(&Extension->StateLock);

    if (Enable)
    {
        if (InterlockedCompareExchange(&Extension->CallbacksRegistered, 1, 0) == 0)
        {
            operationRegistration.ObjectType = PsProcessType;
            operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
            operationRegistration.PreOperation = PfkpObjectPreOperation;
            operationRegistration.PostOperation = NULL;

            callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
            callbackRegistration.OperationRegistrationCount = 1;
            callbackRegistration.Altitude = altitude;
            callbackRegistration.RegistrationContext = Extension;
            callbackRegistration.OperationRegistration = &operationRegistration;

            status = PsSetCreateProcessNotifyRoutineEx(PfkpProcessNotify, FALSE);
            imageStatus = PsSetLoadImageNotifyRoutine(PfkpLoadImageNotify);
            threadStatus = PsSetCreateThreadNotifyRoutine(PfkpThreadNotify);
            objectStatus = ObRegisterCallbacks(&callbackRegistration, &Extension->ObRegistrationHandle);

            if (!NT_SUCCESS(status) || !NT_SUCCESS(imageStatus) || !NT_SUCCESS(threadStatus) || !NT_SUCCESS(objectStatus))
            {
                if (NT_SUCCESS(objectStatus) && Extension->ObRegistrationHandle != NULL)
                {
                    ObUnRegisterCallbacks(Extension->ObRegistrationHandle);
                    Extension->ObRegistrationHandle = NULL;
                }

                if (NT_SUCCESS(status))
                {
                    (VOID)PsSetCreateProcessNotifyRoutineEx(PfkpProcessNotify, TRUE);
                }

                if (NT_SUCCESS(imageStatus))
                {
                    (VOID)PsRemoveLoadImageNotifyRoutine(PfkpLoadImageNotify);
                }

                if (NT_SUCCESS(threadStatus))
                {
                    (VOID)PsRemoveCreateThreadNotifyRoutine(PfkpThreadNotify);
                }

                InterlockedExchange(&Extension->CallbacksRegistered, 0);
                if (NT_SUCCESS(status))
                {
                    if (!NT_SUCCESS(imageStatus))
                    {
                        status = imageStatus;
                    }
                    else
                    {
                        status = !NT_SUCCESS(threadStatus) ? threadStatus : objectStatus;
                    }
                }
            }
        }
    }
    else
    {
        if (InterlockedCompareExchange(&Extension->CallbacksRegistered, 0, 1) == 1)
        {
            if (Extension->ObRegistrationHandle != NULL)
            {
                ObUnRegisterCallbacks(Extension->ObRegistrationHandle);
                Extension->ObRegistrationHandle = NULL;
            }

            (VOID)PsSetCreateProcessNotifyRoutineEx(PfkpProcessNotify, TRUE);
            (VOID)PsRemoveLoadImageNotifyRoutine(PfkpLoadImageNotify);
            (VOID)PsRemoveCreateThreadNotifyRoutine(PfkpThreadNotify);
        }
    }

    ExReleaseFastMutex(&Extension->StateLock);
    return status;
}

static
NTSTATUS
PfkpHandleGetStatus(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    PFKP_STATUS_REPLY reply;

    if (Length < sizeof(reply))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Header.Size = sizeof(reply);
    reply.Header.Version = 1;
    reply.Flags = (InterlockedCompareExchange(&Extension->CallbacksRegistered, 0, 0) != 0) ? 1u : 0u;
    reply.Flags |= (InterlockedCompareExchange(&Extension->TimerArmed, 0, 0) != 0) ? 2u : 0u;
    reply.MaxRecords = Extension->MaxRecords;
    reply.EventCount = Extension->EventCount;
    reply.IoctlCount = Extension->IoctlCount;
    reply.AllocationCount = Extension->AllocationCount;
    reply.ProcessCallbackCount = Extension->ProcessCallbackCount;
    reply.ImageCallbackCount = Extension->ImageCallbackCount;
    reply.ThreadCallbackCount = Extension->ThreadCallbackCount;
    reply.ObCallbackCount = Extension->ObCallbackCount;
    reply.WhitelistHitCount = Extension->WhitelistHitCount;
    reply.BlacklistHitCount = Extension->BlacklistHitCount;
    reply.TimerFireCount = Extension->TimerFireCount;
    reply.WorkItemCount = Extension->WorkItemCount;
    reply.LastErrorStatus = Extension->LastErrorStatus;

    RtlCopyMemory(Buffer, &reply, sizeof(reply));
    *Information = sizeof(reply);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpHandleAllocate(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(OutputLength) PVOID Buffer,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PFKP_ALLOCATE_REQUEST request;
    PFKP_ALLOCATE_REPLY reply;
    PUCHAR allocation;
    ULONG index;
    ULONG checksum;
    ULONG allocationSize;
    NTSTATUS status;

    if (InputLength < sizeof(request))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (OutputLength < sizeof(reply))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&request, Buffer, sizeof(request));
    if (request.Header.Size < sizeof(request))
    {
        return STATUS_INVALID_PARAMETER;
    }

    allocationSize = request.AllocationSize;
    if (allocationSize == 0 || allocationSize > 4096)
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    allocation = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationSize, PFKP_TEMP_POOL_TAG);
    if (allocation == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlFillMemory(allocation, allocationSize, (UCHAR)request.Pattern);
    checksum = 0;

    for (index = 0; index < allocationSize; ++index)
    {
        checksum = _rotl(checksum, 3) ^ allocation[index];
    }

    ExFreePoolWithTag(allocation, PFKP_TEMP_POOL_TAG);

    status = STATUS_SUCCESS;
    InterlockedIncrement((volatile LONG *)&Extension->AllocationCount);
    PfkpRecordEvent(Extension, PFKP_EVENT_IOCTL, allocationSize, status);

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Header.Size = sizeof(reply);
    reply.Header.Version = 1;
    reply.AllocationSize = allocationSize;
    reply.Checksum = checksum;
    reply.Status = (ULONG)status;

    RtlCopyMemory(Buffer, &reply, sizeof(reply));
    *Information = sizeof(reply);
    return status;
}

static
NTSTATUS
PfkpHandleQueryProcess(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(OutputLength) PVOID Buffer,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PFKP_PROCESS_QUERY_REQUEST request;
    PFKP_PROCESS_QUERY_REPLY reply;
    PEPROCESS process;
    NTSTATUS status;

    if (InputLength < sizeof(request))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (OutputLength < sizeof(reply))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&request, Buffer, sizeof(request));
    if (request.Header.Size < sizeof(request))
    {
        return STATUS_INVALID_PARAMETER;
    }

    process = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request.ProcessId, &process);

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Header.Size = sizeof(reply);
    reply.Header.Version = 1;
    reply.ProcessId = request.ProcessId;
    reply.ProcessObject = (ULONGLONG)(ULONG_PTR)process;
    reply.Status = (ULONG)status;

    if (process != NULL)
    {
        ObDereferenceObject(process);
    }

    PfkpRecordEvent(Extension, PFKP_EVENT_IOCTL, (ULONG)request.ProcessId, status);

    RtlCopyMemory(Buffer, &reply, sizeof(reply));
    *Information = sizeof(reply);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpHandleQueueWork(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Out_ PULONG_PTR Information
    )
{
    if (Extension->WorkItem == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (InterlockedCompareExchange(&Extension->WorkItemQueued, 1, 0) != 0)
    {
        return STATUS_DEVICE_BUSY;
    }

    KeClearEvent(&Extension->WorkItemIdleEvent);
    IoQueueWorkItem(Extension->WorkItem, PfkpWorkItemRoutine, DelayedWorkQueue, Extension);
    *Information = 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpHandleArmTimer(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    PFKP_TIMER_REQUEST request;
    LARGE_INTEGER dueTime;

    if (Length < sizeof(request))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    RtlCopyMemory(&request, Buffer, sizeof(request));
    if (request.Header.Size < sizeof(request))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request.DueTimeMs == 0 || request.DueTimeMs > 60000)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request.PeriodMs > 60000)
    {
        return STATUS_INVALID_PARAMETER;
    }

    dueTime.QuadPart = -((LONGLONG)request.DueTimeMs * 10000LL);
    KeSetTimerEx(&Extension->Timer, dueTime, (LONG)request.PeriodMs, &Extension->TimerDpc);
    InterlockedExchange(&Extension->TimerArmed, 1);
    *Information = 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpHandleEnableCallbacks(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(OutputLength) PVOID Buffer,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PFKP_CALLBACK_REQUEST request;
    PFKP_CALLBACK_REPLY reply;
    NTSTATUS status;

    if (InputLength < sizeof(request))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (OutputLength < sizeof(reply))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&request, Buffer, sizeof(request));
    if (request.Header.Size < sizeof(request))
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = PfkpSetCallbacks(Extension, request.Enable ? TRUE : FALSE);

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Header.Size = sizeof(reply);
    reply.Header.Version = 1;
    reply.Enabled = (InterlockedCompareExchange(&Extension->CallbacksRegistered, 0, 0) != 0) ? 1u : 0u;
    reply.Status = (ULONG)status;

    RtlCopyMemory(Buffer, &reply, sizeof(reply));
    *Information = sizeof(reply);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfkpHandleListEvents(
    _Inout_ PPFKP_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    ULONG headerSize;
    ULONG capacity;
    ULONG copied;
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PFKP_EVENT_LIST *list;

    headerSize = FIELD_OFFSET(PFKP_EVENT_LIST, Records);
    if (Length < headerSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    list = (PFKP_EVENT_LIST *)Buffer;
    capacity = (Length - headerSize) / sizeof(PFKP_EVENT_RECORD);
    copied = 0;

    RtlZeroMemory(Buffer, Length);
    list->Header.Size = headerSize;
    list->Header.Version = 1;
    list->RecordSize = sizeof(PFKP_EVENT_RECORD);

    KeAcquireSpinLock(&Extension->EventLock, &oldIrql);
    list->RequiredRecordCount = Extension->EventCount;

    entry = Extension->EventList.Flink;
    while (entry != &Extension->EventList)
    {
        PPFKP_RECORD_ENTRY record;

        record = CONTAINING_RECORD(entry, PFKP_RECORD_ENTRY, Link);
        if (copied < capacity)
        {
            RtlCopyMemory(&list->Records[copied], &record->Record, sizeof(record->Record));
            ++copied;
        }

        entry = entry->Flink;
    }

    KeReleaseSpinLock(&Extension->EventLock, oldIrql);

    list->RecordCount = copied;
    list->Truncated = (list->RequiredRecordCount > copied) ? 1u : 0u;
    *Information = headerSize + ((ULONG_PTR)copied * sizeof(PFKP_EVENT_RECORD));
    return STATUS_SUCCESS;
}

static
VOID
PfkpWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PPFKP_DEVICE_EXTENSION extension;

    UNREFERENCED_PARAMETER(DeviceObject);

    extension = (PPFKP_DEVICE_EXTENSION)Context;
    if (extension != NULL)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&extension->Resource, TRUE);
        InterlockedIncrement((volatile LONG *)&extension->WorkItemCount);
        PfkpRecordEvent(extension, PFKP_EVENT_WORK_ITEM, extension->WorkItemCount, STATUS_SUCCESS);
        ExReleaseResourceLite(&extension->Resource);
        KeLeaveCriticalRegion();

        InterlockedExchange(&extension->WorkItemQueued, 0);
        KeSetEvent(&extension->WorkItemIdleEvent, IO_NO_INCREMENT, FALSE);
    }
}

static
VOID
PfkpTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PPFKP_DEVICE_EXTENSION extension;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    extension = (PPFKP_DEVICE_EXTENSION)DeferredContext;
    if (extension != NULL)
    {
        InterlockedIncrement((volatile LONG *)&extension->TimerFireCount);
        PfkpRecordEvent(extension, PFKP_EVENT_TIMER, extension->TimerFireCount, STATUS_SUCCESS);
    }
}

static
VOID
PfkpProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    PPFKP_DEVICE_EXTENSION extension;
    PDEVICE_OBJECT deviceObject;

    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(CreateInfo);

    deviceObject = g_DeviceObject;
    if (deviceObject == NULL)
    {
        return;
    }

    extension = (PPFKP_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    if (ExAcquireRundownProtection(&extension->Rundown))
    {
        InterlockedIncrement((volatile LONG *)&extension->ProcessCallbackCount);
        PfkpRecordEvent(extension, PFKP_EVENT_PROCESS, HandleToULong(ProcessId), STATUS_SUCCESS);
        ExReleaseRundownProtection(&extension->Rundown);
    }
}

static
VOID
PfkpLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    PPFKP_DEVICE_EXTENSION extension;
    PDEVICE_OBJECT deviceObject;
    ULONG imageFlags;

    UNREFERENCED_PARAMETER(FullImageName);

    imageFlags = ImageInfo != NULL ? ImageInfo->ImageSignatureLevel : 0;
    deviceObject = g_DeviceObject;
    if (deviceObject == NULL)
    {
        return;
    }

    extension = (PPFKP_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    if (ExAcquireRundownProtection(&extension->Rundown))
    {
        InterlockedIncrement((volatile LONG *)&extension->ImageCallbackCount);
        PfkpRecordEvent(extension, PFKP_EVENT_IMAGE, HandleToULong(ProcessId) ^ imageFlags, STATUS_SUCCESS);
        ExReleaseRundownProtection(&extension->Rundown);
    }
}

static
VOID
PfkpThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    PPFKP_DEVICE_EXTENSION extension;
    PDEVICE_OBJECT deviceObject;
    ULONG value;

    value = HandleToULong(ProcessId) ^ HandleToULong(ThreadId) ^ (Create ? 0x80000000u : 0u);
    deviceObject = g_DeviceObject;
    if (deviceObject == NULL)
    {
        return;
    }

    extension = (PPFKP_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    if (ExAcquireRundownProtection(&extension->Rundown))
    {
        InterlockedIncrement((volatile LONG *)&extension->ThreadCallbackCount);
        PfkpRecordEvent(extension, PFKP_EVENT_THREAD, value, STATUS_SUCCESS);
        ExReleaseRundownProtection(&extension->Rundown);
    }
}

static
OB_PREOP_CALLBACK_STATUS
PfkpObjectPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PPFKP_DEVICE_EXTENSION extension;
    PEPROCESS targetProcess;
    HANDLE targetProcessId;
    HANDLE requesterProcessId;
    ACCESS_MASK desiredAccess;
    ACCESS_MASK monitoredAccess;
    PLIST_ENTRY entry;
    PPFKP_PROCESS_RULE_ENTRY whiteRule;
    PPFKP_PROCESS_RULE_ENTRY blackRule;
    PPFKP_PROCESS_RULE_ENTRY newRule;
    PPFKP_RECORD_ENTRY record;
    LARGE_INTEGER time;
    KIRQL oldIrql;
    BOOLEAN whitelisted;
    BOOLEAN blacklisted;
    BOOLEAN whitelistAdded;
    BOOLEAN accessTouchesProcess;
    NTSTATUS status;

    extension = (PPFKP_DEVICE_EXTENSION)RegistrationContext;
    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetProcessId = PsGetProcessId(targetProcess);
    requesterProcessId = PsGetCurrentProcessId();
    desiredAccess = 0;
    monitoredAccess =
        PROCESS_TERMINATE |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_CREATE_THREAD;
    whiteRule = NULL;
    blackRule = NULL;
    newRule = NULL;
    record = NULL;
    whitelisted = FALSE;
    blacklisted = FALSE;
    whitelistAdded = FALSE;
    accessTouchesProcess = FALSE;
    status = STATUS_SUCCESS;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }
    else
    {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        }
    }

    accessTouchesProcess = (desiredAccess & monitoredAccess) != 0;

    ExAcquireFastMutex(&extension->AccessListLock);

    entry = extension->ProcessWhitelist.Flink;
    while (entry != &extension->ProcessWhitelist)
    {
        whiteRule = CONTAINING_RECORD(entry, PFKP_PROCESS_RULE_ENTRY, Link);
        if (whiteRule->ProcessId == requesterProcessId)
        {
            ++whiteRule->AccessCount;
            KeQuerySystemTimePrecise(&whiteRule->LastAccessTime);
            whitelisted = TRUE;
            break;
        }

        entry = entry->Flink;
    }

    entry = extension->ProcessBlacklist.Flink;
    while (entry != &extension->ProcessBlacklist)
    {
        blackRule = CONTAINING_RECORD(entry, PFKP_PROCESS_RULE_ENTRY, Link);
        if (blackRule->ProcessId == targetProcessId)
        {
            ++blackRule->AccessCount;
            KeQuerySystemTimePrecise(&blackRule->LastAccessTime);
            blacklisted = TRUE;
            break;
        }

        entry = entry->Flink;
    }

    if (whitelisted)
    {
        InterlockedIncrement((volatile LONG *)&extension->WhitelistHitCount);
    }

    if (blacklisted)
    {
        InterlockedIncrement((volatile LONG *)&extension->BlacklistHitCount);
        if (!whitelisted && !OperationInformation->KernelHandle && accessTouchesProcess)
        {
            newRule = (PPFKP_PROCESS_RULE_ENTRY)ExAllocateFromNPagedLookasideList(&extension->ProcessRuleLookaside);
            if (newRule == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                extension->LastErrorStatus = (ULONG)status;
            }
            else
            {
                RtlZeroMemory(newRule, sizeof(*newRule));
                newRule->ProcessId = requesterProcessId;
                newRule->AccessCount = 1;
                newRule->AutoAdded = TRUE;
                KeQuerySystemTimePrecise(&newRule->LastAccessTime);
                InsertTailList(&extension->ProcessWhitelist, &newRule->Link);
                whitelistAdded = TRUE;
            }
        }
    }

    ExReleaseFastMutex(&extension->AccessListLock);

    InterlockedIncrement((volatile LONG *)&extension->ObCallbackCount);

    if (InterlockedCompareExchange(&extension->Unloading, 0, 0) == 0)
    {
        record = (PPFKP_RECORD_ENTRY)ExAllocateFromNPagedLookasideList(&extension->RecordLookaside);
        if (record == NULL)
        {
            extension->LastErrorStatus = (ULONG)STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            RtlZeroMemory(record, sizeof(*record));
            KeQuerySystemTimePrecise(&time);
            record->Record.RecordSize = sizeof(record->Record);
            record->Record.EventType = PFKP_EVENT_OB_CALLBACK;
            record->Record.ProcessId = HandleToULong(PsGetCurrentProcessId());
            record->Record.ThreadId = HandleToULong(PsGetCurrentThreadId());
            record->Record.Value = HandleToULong(whitelistAdded ? requesterProcessId : targetProcessId);
            record->Record.Status = (ULONG)status;
            record->Record.Sequence = (ULONGLONG)InterlockedIncrement((volatile LONG *)&extension->EventCount);
            record->Record.Time100ns = time.QuadPart;

            KeAcquireSpinLock(&extension->EventLock, &oldIrql);
            InsertTailList(&extension->EventList, &record->Link);

            while (extension->EventCount > extension->MaxRecords && !IsListEmpty(&extension->EventList))
            {
                PLIST_ENTRY oldEntry;
                PPFKP_RECORD_ENTRY oldRecord;

                oldEntry = RemoveHeadList(&extension->EventList);
                oldRecord = CONTAINING_RECORD(oldEntry, PFKP_RECORD_ENTRY, Link);
                --extension->EventCount;
                ExFreeToNPagedLookasideList(&extension->RecordLookaside, oldRecord);
            }

            KeReleaseSpinLock(&extension->EventLock, oldIrql);
        }
    }

    return OB_PREOP_SUCCESS;
}
