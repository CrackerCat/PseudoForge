#pragma once

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define PFKP_DEVICE_TYPE 0x8337u

#define PFKP_NT_DEVICE_NAME L"\\Device\\PfKernelPattern"
#define PFKP_DOS_DEVICE_NAME L"\\DosDevices\\PfKernelPattern"
#define PFKP_WIN32_DEVICE_NAME L"\\\\.\\PfKernelPattern"

#define PFKP_MAKE_POOL_TAG(a, b, c, d) ((unsigned long)(a) | ((unsigned long)(b) << 8) | ((unsigned long)(c) << 16) | ((unsigned long)(d) << 24))
#define PFKP_POOL_TAG PFKP_MAKE_POOL_TAG('P', 'F', 'K', 'p')
#define PFKP_RECORD_POOL_TAG PFKP_MAKE_POOL_TAG('P', 'F', 'K', 'r')
#define PFKP_RULE_POOL_TAG PFKP_MAKE_POOL_TAG('P', 'F', 'K', 'l')
#define PFKP_TEMP_POOL_TAG PFKP_MAKE_POOL_TAG('P', 'F', 'K', 't')

#define PFKP_IOCTL_GET_STATUS CTL_CODE(PFKP_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_READ_DATA)
#define PFKP_IOCTL_RESET_COUNTERS CTL_CODE(PFKP_DEVICE_TYPE, 0x802u, METHOD_BUFFERED, FILE_WRITE_DATA)
#define PFKP_IOCTL_ALLOCATE_PATTERN CTL_CODE(PFKP_DEVICE_TYPE, 0x803u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PFKP_IOCTL_QUERY_PROCESS CTL_CODE(PFKP_DEVICE_TYPE, 0x804u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PFKP_IOCTL_QUEUE_WORK CTL_CODE(PFKP_DEVICE_TYPE, 0x805u, METHOD_BUFFERED, FILE_READ_DATA)
#define PFKP_IOCTL_ARM_TIMER CTL_CODE(PFKP_DEVICE_TYPE, 0x806u, METHOD_BUFFERED, FILE_WRITE_DATA)
#define PFKP_IOCTL_ENABLE_CALLBACKS CTL_CODE(PFKP_DEVICE_TYPE, 0x807u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PFKP_IOCTL_LIST_EVENTS CTL_CODE(PFKP_DEVICE_TYPE, 0x808u, METHOD_BUFFERED, FILE_READ_DATA)

#define PFKP_EVENT_PROCESS 1
#define PFKP_EVENT_IMAGE 2
#define PFKP_EVENT_THREAD 3
#define PFKP_EVENT_WORK_ITEM 4
#define PFKP_EVENT_TIMER 5
#define PFKP_EVENT_IOCTL 6
#define PFKP_EVENT_OB_CALLBACK 7

#pragma pack(push, 8)

typedef struct _PFKP_HEADER
{
    unsigned int Size;
    unsigned int Version;
} PFKP_HEADER;

typedef struct _PFKP_STATUS_REPLY
{
    PFKP_HEADER Header;
    unsigned int Flags;
    unsigned int MaxRecords;
    unsigned int EventCount;
    unsigned int IoctlCount;
    unsigned int AllocationCount;
    unsigned int ProcessCallbackCount;
    unsigned int ImageCallbackCount;
    unsigned int ThreadCallbackCount;
    unsigned int ObCallbackCount;
    unsigned int WhitelistHitCount;
    unsigned int BlacklistHitCount;
    unsigned int TimerFireCount;
    unsigned int WorkItemCount;
    unsigned int LastErrorStatus;
} PFKP_STATUS_REPLY;

typedef struct _PFKP_ALLOCATE_REQUEST
{
    PFKP_HEADER Header;
    unsigned int AllocationSize;
    unsigned int Pattern;
} PFKP_ALLOCATE_REQUEST;

typedef struct _PFKP_ALLOCATE_REPLY
{
    PFKP_HEADER Header;
    unsigned int AllocationSize;
    unsigned int Checksum;
    unsigned int Status;
} PFKP_ALLOCATE_REPLY;

typedef struct _PFKP_PROCESS_QUERY_REQUEST
{
    PFKP_HEADER Header;
    unsigned __int64 ProcessId;
} PFKP_PROCESS_QUERY_REQUEST;

typedef struct _PFKP_PROCESS_QUERY_REPLY
{
    PFKP_HEADER Header;
    unsigned __int64 ProcessId;
    unsigned __int64 ProcessObject;
    unsigned int Status;
} PFKP_PROCESS_QUERY_REPLY;

typedef struct _PFKP_TIMER_REQUEST
{
    PFKP_HEADER Header;
    unsigned int DueTimeMs;
    unsigned int PeriodMs;
} PFKP_TIMER_REQUEST;

typedef struct _PFKP_CALLBACK_REQUEST
{
    PFKP_HEADER Header;
    unsigned int Enable;
} PFKP_CALLBACK_REQUEST;

typedef struct _PFKP_CALLBACK_REPLY
{
    PFKP_HEADER Header;
    unsigned int Enabled;
    unsigned int Status;
} PFKP_CALLBACK_REPLY;

typedef struct _PFKP_EVENT_RECORD
{
    unsigned int RecordSize;
    unsigned int EventType;
    unsigned int ProcessId;
    unsigned int ThreadId;
    unsigned int Value;
    unsigned int Status;
    unsigned __int64 Sequence;
    __int64 Time100ns;
} PFKP_EVENT_RECORD;

typedef struct _PFKP_EVENT_LIST
{
    PFKP_HEADER Header;
    unsigned int RecordSize;
    unsigned int RecordCount;
    unsigned int RequiredRecordCount;
    unsigned int Truncated;
    PFKP_EVENT_RECORD Records[1];
} PFKP_EVENT_LIST;

#pragma pack(pop)
