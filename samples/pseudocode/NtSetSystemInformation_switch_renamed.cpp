/*
    Readable reverse-engineered pseudocode for NtSetSystemInformation.

    This is not intended to compile as-is.  It preserves private helper names,
    global names, and numeric SYSTEM_INFORMATION_CLASS values from the IDA dump
    while renaming parameters and short-lived temporaries for review.
*/

NTSTATUS NTAPI NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS systemInformationClass,
    PVOID systemInformation,
    ULONG systemInformationLength)
{
    ULONG infoClass = (ULONG)(ULONG_PTR)systemInformationClass;
    __m128i *systemInfo128 = (__m128i *)systemInformation;
    SIZE_T inputLength = systemInformationLength;
    KPROCESSOR_MODE previousMode = KeGetCurrentThread()->PreviousMode;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID userProbeEnd = NULL;

    __m128i capturedLoadImage = {};
    __m128i capturedBlock0 = {};
    __m128i capturedBlock1 = {};
    __m128i capturedBlock2 = {};
    void *capturedUnicodeStorage[2] = {};
    __int64 capturedI64A = 0;
    __int64 capturedI64B = 0;
    __int64 capturedI64C = 0;
    PVOID referencedObject = NULL;
    unsigned __int64 outValue64 = 0;
    ULONG outputValue32 = 0;
    ULONG defaultSoftRebootFlags = 1;
    BOOLEAN byteFlag = FALSE;
    KPROCESSOR_MODE savedPreviousMode = previousMode;
    _BYTE cpuSetBuffer0[256] = {};
    _BYTE cpuSetBuffer1[256] = {};
    _BYTE cpuSetBuffer2[256] = {};

    if (previousMode != KernelMode)
    {
        ULONG_PTR alignmentMask = 3;

        if (infoClass == 89)
        {
            alignmentMask = 1;
        }
        else
        {
            if (infoClass == 151 && systemInformationLength == 1)
            {
                alignmentMask = 0;
            }
        }

        if (systemInformationLength != 0)
        {
            if ((((ULONG_PTR)systemInformation) & alignmentMask) != 0)
            {
                ExRaiseDatatypeMisalignment();
            }

            userProbeEnd = (PUCHAR)systemInformation + systemInformationLength;
        }
    }

    switch (infoClass)
    {
    case 9:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        NtGlobalFlag =
            (NtGlobalFlag & 0x6DCE640F) |
            (systemInfo128->m128i_i32[0] & 0x92319BF0);
        systemInfo128->m128i_i32[0] = NtGlobalFlag;
        return STATUS_SUCCESS;
    }

    case 21:
    case 81:
    {
        char workingSetChangeState[30] = {};
        ULONG workingSetFlags = 0;

        if (systemInformationLength < 0x40)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (infoClass == 21)
        {
            workingSetFlags = 0;
        }
        else
        {
            workingSetFlags = systemInfo128[3].m128i_i32[3];
            if ((workingSetFlags & 0xFFFFFFF0) != 0 ||
                (workingSetFlags & 0xC) == 0xC ||
                (workingSetFlags & 3) == 3)
            {
                return (NTSTATUS)0xC0000110;
            }
        }

        if (!SeSinglePrivilegeCheck(SeIncreaseQuotaPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        return MmAdjustWorkingSetSizeEx(
            systemInfo128[1].m128i_i64[1],
            systemInfo128[2].m128i_i64[0],
            1,
            TRUE,
            workingSetFlags,
            (__int64)workingSetChangeState);
    }

    case 24:
    {
        ULONG activeProcessorCount = 0;
        __int64 *processorBlock = NULL;

        if (systemInformationLength != 20)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeLoadDriverPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        capturedBlock0 = *systemInfo128;
        capturedBlock1.m128i_i32[0] = systemInfo128[1].m128i_i32[0];

        KiMinimumDpcRate = capturedBlock0.m128i_i32[2];
        KiMaximumDpcQueueDepth = capturedBlock0.m128i_i32[1];
        KiAdjustDpcThreshold = capturedBlock0.m128i_i32[3];
        KiIdealDpcRate = capturedBlock1.m128i_i32[0];

        KeSynchronizeWithDynamicProcessors(
            capturedBlock1.m128i_u32[0],
            systemInformation,
            systemInformationLength,
            1);

        activeProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
        if (activeProcessorCount != 0)
        {
            processorBlock = &KiProcessorBlock;
            do
            {
                __int64 processorControlBlock = *processorBlock;

                *(_DWORD *)(processorControlBlock + 14504) = KiMaximumDpcQueueDepth;
                *(_DWORD *)(processorControlBlock + 14512) = KiMinimumDpcRate;

                ++processorBlock;
                --activeProcessorCount;
            }
            while (activeProcessorCount != 0);
        }

        return STATUS_SUCCESS;
    }

    case 26:
    case 54:
    {
        BOOLEAN wantsExtendedImageInfo = FALSE;

        if (systemInformationLength == 48)
        {
            wantsExtendedImageInfo = FALSE;
        }
        else
        {
            if (systemInformationLength != 56)
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            wantsExtendedImageInfo = TRUE;
        }

        if (previousMode != KernelMode)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        *(__m128i *)capturedUnicodeStorage = *systemInfo128;
        status = MmLoadSystemImage(
            (unsigned int)capturedUnicodeStorage,
            0,
            0,
            infoClass == 54 ? 0 : 1,
            (__int64)&capturedI64C,
            (__int64)&capturedI64A);

        if (status < 0)
        {
            if (status == (NTSTATUS)0xC00001AD)
            {
                return (NTSTATUS)0xC000011E;
            }

            return status;
        }

        {
            __int64 imageBase = capturedI64A;
            __int64 directoryData = 0;
            __int64 ntHeaders = 0;
            __int64 entryPoint = 0;
            PVOID directorySize = NULL;

            if (wantsExtendedImageInfo)
            {
                directoryData = RtlImageDirectoryEntryToData(
                    imageBase,
                    TRUE,
                    0,
                    &directorySize);
            }

            ntHeaders = RtlImageNtHeader(imageBase);
            entryPoint = imageBase + *(unsigned int *)(ntHeaders + 40);

            systemInfo128[1].m128i_i64[0] = imageBase;
            systemInfo128[1].m128i_i64[1] = capturedI64C;
            systemInfo128[2].m128i_i64[0] = entryPoint;

            if (wantsExtendedImageInfo)
            {
                systemInfo128[2].m128i_i64[1] = directoryData;
                systemInfo128[3].m128i_i32[0] = *(_DWORD *)(ntHeaders + 80);
            }
            else
            {
                systemInfo128[2].m128i_i32[2] = *(_DWORD *)(ntHeaders + 80);
            }
        }

        return status;
    }

    case 27:
    {
        if (systemInformationLength != sizeof(PVOID))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        MmUnloadSystemImage(systemInfo128->m128i_i64[0]);
        return STATUS_SUCCESS;
    }

    case 28:
    {
        unsigned __int64 timerValue = 0;
        unsigned __int64 timerRemainder = 0;
        BOOLEAN useCurrentInterruptTime = FALSE;

        if (((systemInformationLength - 8) & 0xFFFFFFF7) != 0)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeSystemtimePrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (PsIsCurrentThreadInServerSilo(systemInformationClass, systemInformation, systemInformationLength, 1))
        {
            return STATUS_ACCESS_DENIED;
        }

        if (inputLength == 16)
        {
            useCurrentInterruptTime = systemInfo128->m128i_i8[8];
            timerValue = systemInfo128->m128i_i64[0];
        }
        else
        {
            unsigned __int64 requestedPeriod = systemInfo128->m128i_u32[0];

            useCurrentInterruptTime = systemInfo128->m128i_i8[4];
            timerValue = requestedPeriod;

            if (requestedPeriod != 0)
            {
                timerRemainder =
                    MEMORY[0xFFFFF78000000300] *
                    (unsigned __int64)(unsigned int)KeMaximumIncrement %
                    requestedPeriod;
                timerValue =
                    MEMORY[0xFFFFF78000000300] *
                    (unsigned __int64)(unsigned int)KeMaximumIncrement /
                    requestedPeriod;
            }
        }

        if (useCurrentInterruptTime)
        {
            timerValue = MEMORY[0xFFFFF78000000300];
        }

        ExAcquireTimeRefreshLockExclusive(
            useCurrentInterruptTime,
            timerRemainder,
            0xFFFFF78000000300uLL);
        status = ExpUpdateTimerConfiguration(0, &timerValue, &useCurrentInterruptTime);
        ExReleaseTimeRefreshLockExclusive();
        return status;
    }

    case 30:
    {
        return (NTSTATUS)MmCreateMirror();
    }

    case 31:
    {
        return EtwSetPerformanceTraceInformation(
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 34:
    {
        ULONG crashDumpCommand = 0;

        if ((previousMode != KernelMode &&
             !SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode)) ||
            PsIsCurrentThreadInServerSilo(systemInformationClass, systemInformation, systemInformationLength, 1))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (inputLength != sizeof(ULONG))
        {
            return IoConfigureCrashDump(1, 0);
        }

        if (previousMode != KernelMode)
        {
            if (((ULONG_PTR)systemInfo128 & 3) != 0)
            {
                ExRaiseDatatypeMisalignment();
            }
        }

        crashDumpCommand = systemInfo128->m128i_i32[0];
        if (crashDumpCommand == 0)
        {
            return IoConfigureCrashDump(0, 0);
        }

        if (crashDumpCommand == 1)
        {
            return IoConfigureCrashDump(1, 0);
        }

        if (crashDumpCommand == 2)
        {
            return WheaCrashDumpInitializationComplete();
        }

        return STATUS_INVALID_PARAMETER;
    }

    case 37:
    {
        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeIncreaseQuotaPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return CmSetRegistryQuotaInformation(systemInfo128, systemInformation, systemInformationLength, 1);
    }

    case 38:
    {
        const WCHAR win32kPath[] = L"\\SystemRoot\\System32\\win32k.sys";

        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode == KernelMode)
        {
            *(__m128i *)capturedUnicodeStorage = *systemInfo128;

            if (memcmp((const void *)systemInfo128->m128i_i64[1], win32kPath, 0x3EuLL) != 0)
            {
                return (NTSTATUS)0xC00000DB;
            }

            {
                __int64 win32kImageBase = *(_QWORD *)(PsWin32kDataTableEntry + 48);
                __int64 ntHeaders = RtlImageNtHeader(win32kImageBase);

                if (ntHeaders == 0)
                {
                    MmUnloadSystemImage(PsWin32kDataTableEntry);
                    return (NTSTATUS)0xC000003B;
                }

                status = ExpInitializeSessionDriver(
                    win32kImageBase + *(unsigned int *)(ntHeaders + 40),
                    win32kImageBase);

                if (status < 0 &&
                    PsGetSessionIdEx(KeGetCurrentThread()->ApcState.Process, 0, 0, 0) == 0)
                {
                    MmUnloadSystemImage(PsWin32kDataTableEntry);
                }

                return status;
            }
        }

        if ((HIDWORD(KeGetCurrentThread()->ApcState.Process[4].IdealProcessorAssignmentBlock) & 8) == 0 ||
            !SeSinglePrivilegeCheck(SeLoadDriverPrivilege, UserMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        {
            ULONG_PTR readableUserPointer = 0x7FFFFFFF0000LL;

            if ((ULONG_PTR)systemInfo128 < 0x7FFFFFFF0000LL)
            {
                readableUserPointer = (ULONG_PTR)systemInfo128;
            }

            LODWORD(capturedUnicodeStorage[0]) = *(_DWORD *)readableUserPointer;
            capturedUnicodeStorage[1] = *(void **)(readableUserPointer + 8);
        }

        if (LOWORD(capturedUnicodeStorage[0]) != 62)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (memcmp(capturedUnicodeStorage[1], win32kPath, 0x3EuLL) != 0)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        capturedUnicodeStorage[1] = (void *)win32kPath;
        WORD1(capturedUnicodeStorage[0]) = 62;
        return ZwSetSystemInformation(38, capturedUnicodeStorage);
    }

    case 39:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        PsChangeQuantumTable(TRUE);
        return STATUS_SUCCESS;
    }

    case 40:
    case 41:
    {
        PCUNICODE_STRING verifierEntryName = (PCUNICODE_STRING)systemInfo128;

        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode)
        {
            if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            status = VfProbeAndCaptureUnicodeString(capturedUnicodeStorage, systemInfo128, TRUE);
            if (status < 0)
            {
                return status;
            }

            verifierEntryName = (PCUNICODE_STRING)capturedUnicodeStorage;
            if (LOWORD(capturedUnicodeStorage[0]) == 0)
            {
                return (NTSTATUS)0xC000010F;
            }
        }

        if (infoClass == 40)
        {
            status = VfAddVerifierEntry(verifierEntryName);
        }
        else
        {
            status = VfRemoveVerifierEntry(
                (__m128i *)verifierEntryName,
                systemInformation,
                systemInformationLength,
                1);
        }

        if (previousMode != KernelMode)
        {
            VfFreeCapturedUnicodeString(verifierEntryName);
        }

        return status;
    }

    case 46:
    {
        HANDLE timeSlipEventHandle = NULL;

        if (systemInformationLength != sizeof(HANDLE))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeSystemtimePrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (PsIsCurrentThreadInServerSilo(0, systemInformation, systemInformationLength, 1))
        {
            return STATUS_ACCESS_DENIED;
        }

        timeSlipEventHandle = (HANDLE)systemInfo128->m128i_i64[0];
        if (timeSlipEventHandle != NULL)
        {
            status = ObReferenceObjectByHandle(
                timeSlipEventHandle,
                2,
                (POBJECT_TYPE)ExEventObjectType,
                previousMode,
                &referencedObject,
                NULL);

            if (status < 0)
            {
                return status;
            }
        }

        KdUpdateTimeSlipEvent(referencedObject);
        return status;
    }

    case 47:
    case 48:
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    case 51:
    {
        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        return VfSetVerifierInformation(systemInfo128, systemInformationLength, 0);
    }

    case 56:
    {
        return PfSnSetPrefetcherInformation(
            systemInformationClass,
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 59:
    {
        ULONG comPlusPackage = 0;

        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        comPlusPackage = systemInfo128->m128i_i32[0];
        status = ExpUpdateComPlusPackage(systemInfo128->m128i_u32[0], systemInformation, systemInformationLength, 1);
        if (status >= 0)
        {
            *(_DWORD *)(MmWriteableSharedUserData + 736) = comPlusPackage;
        }

        return status;
    }

    case 69:
    {
        return STATUS_NOT_SUPPORTED;
    }

    case 71:
    {
        return (NTSTATUS)0xC00000DB;
    }

    case 72:
    {
        ULONG kdCommand = 0;

        if (previousMode != KernelMode || systemInformation == NULL || systemInformationLength != 8)
        {
            return STATUS_INVALID_PARAMETER;
        }

        kdCommand = systemInfo128->m128i_i32[0];
        switch (kdCommand)
        {
        case 0:
        {
            return STATUS_NOT_SUPPORTED;
        }

        case 1:
        case 2:
        case 3:
        {
            guard_dispatch_icall_no_overrides(kdCommand - 1, systemInformation, systemInformationLength, 1);
            return STATUS_SUCCESS;
        }

        case 4:
        {
            return STATUS_NOT_SUPPORTED;
        }

        case 6:
        {
            return guard_dispatch_icall_no_overrides(1, systemInformation, systemInformationLength, 1);
        }

        case 7:
        {
            if (off_140E00B18[0] == xKdEnumerateDebuggingDevices)
            {
                return STATUS_NOT_IMPLEMENTED;
            }

            return STATUS_SUCCESS;
        }

        default:
        {
            return STATUS_INVALID_PARAMETER;
        }
        }
    }

    case 74:
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    case 75:
    {
        return ExpRegisterFirmwareTableInformationHandler(
            systemInformation,
            systemInformationLength,
            previousMode,
            1);
    }

    case 79:
    {
        return PfSetSuperfetchInformation(
            79,
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 80:
    {
        if (systemInformationLength < sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return MmIssueMemoryListCommand(
            systemInfo128->m128i_u32[0],
            previousMode,
            -1,
            1);
    }

    case 82:
    {
        __m128i clientId = {};
        PVOID threadObject = NULL;

        if (systemInformationLength < 0x18)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeIncreaseBasePriorityPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (previousMode != KernelMode)
        {
            capturedBlock0 = *systemInfo128;
            capturedBlock1.m128i_i64[0] = systemInfo128[1].m128i_i64[0];
            systemInfo128 = &capturedBlock0;
        }

        if ((unsigned int)(systemInfo128[1].m128i_i32[0] - 1) > 0x1E)
        {
            return STATUS_INVALID_PARAMETER;
        }

        clientId = *systemInfo128;
        status = PsLookupProcessThreadByCid(&clientId, NULL, &threadObject);
        if (status < 0)
        {
            return status;
        }

        if (*((_BYTE *)threadObject + 4) != 0)
        {
            status = (NTSTATUS)0xC000004B;
        }
        else
        {
            KeSetActualBasePriorityThread((ULONG_PTR)threadObject);
            status = STATUS_PENDING;
        }

        ObfDereferenceObject(threadObject);
        return status;
    }

    case 86:
    {
        return ObSetRefTraceInformation(systemInformation, systemInformationLength, systemInformationLength, 1);
    }

    case 87:
    {
        __int64 specialPoolTagAndFlags = 0;

        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        if (inputLength != sizeof(ULONGLONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        specialPoolTagAndFlags = systemInfo128->m128i_i64[0];
        MmSpecialPoolTag = specialPoolTagAndFlags;
        MmSpecialPoolCatchOverruns = BYTE4(specialPoolTagAndFlags) & 1;
        return STATUS_SUCCESS;
    }

    case 89:
    {
        if (previousMode != UserMode)
        {
            return STATUS_NOT_SUPPORTED;
        }

        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, UserMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        {
            _KPROCESS *currentProcess = KeGetCurrentThread()->ApcState.Process;
            BOOLEAN allowErrorPort = TRUE;

            if (!currentProcess[1].ReadyTime)
            {
                return DbgkRegisterErrorPort(systemInfo128, systemInformationLength);
            }

            {
                USHORT subsystemVersion = WORD2(currentProcess[3].PerProcessorCycleTimes);

                if (subsystemVersion != 332 && subsystemVersion != 452)
                {
                    allowErrorPort = FALSE;
                }
            }

            if (allowErrorPort)
            {
                return STATUS_NOT_SUPPORTED;
            }

            return DbgkRegisterErrorPort(systemInfo128, systemInformationLength);
        }
    }

    case 91:
    {
        if (previousMode != KernelMode)
        {
            return STATUS_ACCESS_DENIED;
        }

        if (systemInformationLength != 0)
        {
            return (NTSTATUS)0xC0000100;
        }

        if (HvlHypervisorConnected == 0)
        {
            return (NTSTATUS)0xC0351000;
        }

        return STATUS_SUCCESS;
    }

    case 92:
    {
        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        if (inputLength != 40)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return VfSetVerifierInformationEx(systemInfo128);
    }

    case 93:
    case 102:
    {
        ULONG timeZoneInfoLength = infoClass == 93 ? 172 : 432;

        if (systemInformationLength != timeZoneInfoLength)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeTimeZonePrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return ExpSetTimeZoneInformation(
            systemInfo128,
            timeZoneInfoLength,
            systemInformationLength,
            1);
    }

    case 94:
    {
        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        if (inputLength != sizeof(ULONGLONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        capturedBlock0.m128i_i64[0] = systemInfo128->m128i_i64[0];
        _InterlockedOr(
            (volatile signed __int32 *)(MmWriteableSharedUserData + 928),
            capturedBlock0.m128i_u32[0]);
        _InterlockedAnd(
            (volatile signed __int32 *)(MmWriteableSharedUserData + 928),
            ~capturedBlock0.m128i_i32[1]);
        return STATUS_SUCCESS;
    }

    case 95:
    {
        return (NTSTATUS)0xC00000DB;
    }

    case 97:
    {
        if (systemInformationLength != 40)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode)
        {
            if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            capturedBlock0 = *systemInfo128;
            capturedBlock1 = systemInfo128[1];
            capturedBlock2.m128i_i64[0] = systemInfo128[2].m128i_i64[0];

            status = VfProbeAndCaptureUnicodeStringBuffer(&capturedBlock0.m128i_u64[1], TRUE, 0, 0);
            if (status < 0)
            {
                return status;
            }

            status = VfProbeAndCaptureUnicodeStringBuffer(&capturedBlock1.m128i_u64[1], TRUE, 0, 0);
            if (status < 0)
            {
                VfFreeCapturedUnicodeString(&capturedBlock0.m128i_u64[1]);
                return status;
            }

            systemInfo128 = &capturedBlock0;
        }

        status = VfFaultsSetParameters(systemInfo128, systemInformation, systemInformationLength, 1);

        if (previousMode != KernelMode)
        {
            VfFreeCapturedUnicodeString(&systemInfo128->m128i_u64[1]);
            VfFreeCapturedUnicodeString((PUCHAR)systemInfo128 + 24);
        }

        return status;
    }

    case 104:
    {
        return ExpSetProcessorMicrocodeUpdateInformation(
            systemInformation,
            systemInformationLength,
            previousMode,
            1);
    }

    case 106:
    {
        return STATUS_INVALID_INFO_CLASS;
    }

    case 109:
    {
        return SmSetStoreInformation(
            systemInformationClass,
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 110:
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    case 111:
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    case 112:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeProfileSingleProcessPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        *(_DWORD *)(MmWriteableSharedUserData + 584) = systemInfo128->m128i_i32[0];
        return STATUS_SUCCESS;
    }

    case 113:
    {
        return PsSetCpuQuotaInformation(
            systemInformation,
            inputLength,
            previousMode,
            1);
    }

    case 126:
    {
        if (previousMode != KernelMode)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (systemInformationLength != 32)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return BgkSetBootGraphicsInformation(
            systemInformationClass,
            systemInformation,
            systemInformationLength,
            1);
    }

    case 127:
    {
        HANDLE scrubHandle = NULL;

        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeProfileSingleProcessPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        scrubHandle = (HANDLE)systemInfo128->m128i_i64[0];
        status = MmScrubMemory(0, scrubHandle, &capturedI64C);
        systemInfo128->m128i_i64[1] = capturedI64C;
        return status;
    }

    case 129:
    {
        return KeProcessorProfileControlArea(
            systemInformation,
            inputLength,
            previousMode,
            1);
    }

    case 130:
    {
        __int64 combinePartition = 0;
        __int64 combineExtraAddress = 0;

        if (((systemInformationLength - 16) & 0xFFFFFFE7) != 0 ||
            systemInformationLength == 40)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeProfileSingleProcessPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        memmove(&capturedBlock0, systemInfo128, inputLength);
        if (inputLength == 32)
        {
            combineExtraAddress = capturedBlock1.m128i_i64[1];
        }

        combinePartition = MiGetThreadPartition(KeGetCurrentThread());
        status = MiCombineIdenticalPages(
            combinePartition,
            capturedBlock0.m128i_i64[0],
            capturedBlock1.m128i_u32[0],
            combineExtraAddress,
            KeGetCurrentThread()->PreviousMode,
            &capturedI64B,
            outputValue32);

        systemInfo128->m128i_i64[1] = capturedI64B;
        return status;
    }

    case 131:
    {
        if (previousMode != KernelMode)
        {
            return STATUS_ACCESS_DENIED;
        }

        if (systemInformationLength != 24)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return KeInitializeEntropySystem(
            systemInfo128->m128i_i64[0],
            systemInfo128->m128i_i64[1],
            systemInfo128[1].m128i_i64[0],
            1);
    }

    case 132:
    {
        UNICODE_STRING driverServiceName = {};

        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        driverServiceName.Length = 0x76;
        driverServiceName.MaximumLength = 0x76;
        driverServiceName.Buffer =
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\condrv";

        if ((systemInfo128->m128i_i8[0] & 1) != 0)
        {
            __int64 pushLockState = 0;
            KTHREAD *currentThread = KeGetCurrentThread();

            --currentThread->KernelApcDisable;
            pushLockState = KeAbPreAcquire(&ExpConDrvLoadLock, 0, 0, 1);

            if (_interlockedbittestandset64((volatile signed __int32 *)&ExpConDrvLoadLock, 0))
            {
                ExfAcquirePushLockExclusiveEx(&ExpConDrvLoadLock, pushLockState, &ExpConDrvLoadLock);
            }

            if (pushLockState != 0)
            {
                *(_BYTE *)(pushLockState + 10) = 1;
            }

            status = ZwLoadDriver(&driverServiceName);

            if ((_InterlockedExchangeAdd64(
                    (volatile signed __int64 *)&ExpConDrvLoadLock,
                    0xFFFFFFFFFFFFFFFFuLL) & 6) == 2)
            {
                ExfTryToWakePushLock(&ExpConDrvLoadLock);
            }

            KeAbPostRelease((ULONG_PTR)&ExpConDrvLoadLock);
            KeLeaveCriticalRegion();
            return status;
        }

        if (!SeSinglePrivilegeCheck(SeLoadDriverPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return ZwUnloadDriver(&driverServiceName);
    }

    case 134:
    {
        if (systemInformationLength != 32)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return sub_1409FC794(systemInformationClass, systemInformation, systemInformationLength, 1);
    }

    case 142:
    {
        __int64 siloGlobalBlock = 0;
        LUID shutdownPrivilegeValue = {};
        void *capturedStringSource[2] = {};

        siloGlobalBlock = PsGetCurrentServerSiloGlobals(systemInformationClass, systemInformation, systemInformationLength, 1) + 1368;
        shutdownPrivilegeValue = (LUID)siloGlobalBlock;

        if (inputLength != 48)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeShutdownPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        capturedBlock0 = *systemInfo128;
        capturedBlock1 = systemInfo128[1];
        capturedBlock2 = systemInfo128[2];

        if (_InterlockedCompareExchange(
                (volatile signed __int32 *)siloGlobalBlock,
                _mm_cvtsi128_si32(capturedBlock0),
                0) != 0)
        {
            return STATUS_SUCCESS;
        }

        *(__m128i *)capturedStringSource = capturedBlock1;
        capturedBlock1 = {};

        {
            USHORT stringByteLength = _mm_cvtsi128_si32(*(__m128i *)capturedStringSource);

            if (stringByteLength != 0 && (stringByteLength & 1) == 0)
            {
                const void *sourceBuffer = capturedStringSource[1];
                PVOID poolCopy = NULL;

                if (((ULONG_PTR)capturedStringSource[1] & 1) != 0)
                {
                    ExRaiseDatatypeMisalignment();
                }

                if ((ULONG_PTR)((PUCHAR)capturedStringSource[1] + stringByteLength) > 0x7FFFFFFF0000LL ||
                    (PUCHAR)capturedStringSource[1] + stringByteLength < capturedStringSource[1])
                {
                    sourceBuffer = capturedStringSource[1];
                    stringByteLength = (USHORT)capturedStringSource[0];
                }

                poolCopy = ExAllocatePool2(0x101uLL, stringByteLength, 0x50535845u);
                if (poolCopy != NULL)
                {
                    memmove(poolCopy, sourceBuffer, stringByteLength);
                    capturedBlock1.m128i_i64[1] = (__int64)poolCopy;
                    capturedBlock1.m128i_i16[0] = stringByteLength;
                    capturedBlock1.m128i_i16[1] = stringByteLength;
                }
            }
        }

        *(__m128i *)siloGlobalBlock = capturedBlock0;
        *(__m128i *)(siloGlobalBlock + 16) = capturedBlock1;
        *(__m128i *)(siloGlobalBlock + 32) = capturedBlock2;
        return STATUS_SUCCESS;
    }

    case 150:
    {
        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return ExpSetBootLoaderMetadata(systemInfo128, inputLength);
    }

    case 151:
    {
        LUID softRebootPrivilege = {};

        softRebootPrivilege = (LUID)19LL;
        if (!SeSinglePrivilegeCheck(softRebootPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (inputLength == 1)
        {
            BOOLEAN requestedValue = systemInfo128->m128i_i8[0];

            if (requestedValue != FALSE &&
                !SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            if (requestedValue == FALSE)
            {
                defaultSoftRebootFlags = 5;
            }
        }
        else
        {
            if (inputLength != 4)
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            defaultSoftRebootFlags = systemInfo128->m128i_i32[0];
        }

        return ExpSetSoftRebootFlags(defaultSoftRebootFlags);
    }

    case 152:
    {
        if (systemInformationLength != sizeof(ULONGLONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode == KernelMode)
        {
            return STATUS_INVALID_PARAMETER;
        }

        return ExpQueryElamCertInfo(systemInfo128->m128i_i64[0], systemInformation, systemInformationLength, 1);
    }

    case 155:
    {
        return CmReconcileAndValidateAllHives(
            systemInformationClass,
            systemInformation,
            systemInformationLength,
            1);
    }

    case 159:
    {
        return STATUS_NOT_SUPPORTED;
    }

    case 161:
    {
        if (previousMode != KernelMode)
        {
            return STATUS_ACCESS_DENIED;
        }

        if (systemInformationLength != sizeof(ULONGLONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        return KdInitialize(3, systemInformation, &KdpContext, 1);
    }

    case 168:
    {
        if ((systemInformationLength & 7) != 0 || systemInformationLength > 0x100)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        memmove(cpuSetBuffer0, systemInformation, systemInformationLength);

        status = ExCpuSetResourceManagerAccessCheck(previousMode);
        if (status < 0)
        {
            return status;
        }

        return KeModifySystemAllowedCpuSets(
            inputLength >> 3,
            (_DWORD)cpuSetBuffer0,
            0,
            0);
    }

    case 170:
    {
        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeIncreaseBasePriorityPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return KeIntSteerAssignCpuSetForGsiv(
            systemInfo128->m128i_i64[0],
            HIDWORD(systemInfo128->m128i_i64[0]),
            systemInfo128->m128i_i64[1]);
    }

    case 176:
    {
        ULONG payloadLength = 0;
        __int64 tagValue = 0;

        if (systemInformationLength < 8)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        payloadLength = systemInformationLength - 8;
        if (((payloadLength) & 7) != 0 || payloadLength > 0x100)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        tagValue = systemInfo128->m128i_i64[0];
        memmove(cpuSetBuffer1, &systemInfo128->m128i_u64[1], payloadLength);

        status = ExCpuSetResourceManagerAccessCheck(previousMode);
        if (status < 0)
        {
            return status;
        }

        return KeSetTagCpuSets(payloadLength >> 3, cpuSetBuffer1, tagValue);
    }

    case 177:
    {
        __int128 win32CalloutContext = {};
        _KPROCESS *targetProcess = NULL;
        int sessionId = 0;

        if (systemInformationLength == 0)
        {
            targetProcess = KeGetCurrentThread()->ApcState.Process;
            sessionId = PsGetSessionIdEx(targetProcess, systemInformation, systemInformationLength, 1);

            if (sessionId == -1)
            {
                return STATUS_SUCCESS;
            }

            return PsInvokeWin32Callout(32, &win32CalloutContext, 1, &sessionId);
        }

        if (systemInformationLength != sizeof(HANDLE))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        status = ObReferenceObjectByHandle(
            (HANDLE)systemInfo128->m128i_i64[0],
            0x1000,
            (POBJECT_TYPE)PsProcessType,
            previousMode,
            &referencedObject,
            NULL);

        if (status < 0)
        {
            return status;
        }

        targetProcess = (_KPROCESS *)referencedObject;
        sessionId = PsGetSessionIdEx(referencedObject, 0, 0, 0);
        if (sessionId != -1)
        {
            status = PsInvokeWin32Callout(32, &win32CalloutContext, 1, &sessionId);
        }

        ObfDereferenceObject(targetProcess);
        return status;
    }

    case 187:
    {
        if (systemInformationLength != 24)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        capturedBlock0 = *systemInfo128;
        capturedBlock1.m128i_i64[0] = systemInfo128[1].m128i_i64[0];

        status = VfProbeAndCaptureUnicodeStringBuffer(&capturedBlock0, TRUE, systemInformationLength, TRUE);
        if (status < 0)
        {
            return status;
        }

        status = PsSetExeModerationState(
            &capturedBlock0,
            capturedBlock1.m128i_u32[0],
            capturedBlock1.m128i_u32[1]);

        VfFreeCapturedUnicodeString(&capturedBlock0);
        return status;
    }

    case 191:
    {
        if (systemInformationLength != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return VslRelaxQuotas(1, systemInformation, systemInformationLength, 1);
    }

    case 194:
    {
        if (systemInformationLength != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (!SeSinglePrivilegeCheck(SeTcbPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        status = VslProvisionDumpEncryption();
        if (status < 0)
        {
            return status;
        }

        return IoProvisionCrashDumpKey();
    }

    case 204:
    {
        ULONG payloadLength = 0;
        unsigned __int64 modeSelector = 0;

        if (systemInformationLength < 8)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        payloadLength = systemInformationLength - 8;
        if (((payloadLength) & 7) != 0 || payloadLength > 0x100)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        modeSelector = systemInfo128->m128i_i64[0];
        memmove(cpuSetBuffer2, &systemInfo128->m128i_u64[1], payloadLength);

        if (modeSelector >= 2)
        {
            return STATUS_INVALID_PARAMETER;
        }

        status = ExCpuSetResourceManagerAccessCheck(previousMode);
        if (status < 0)
        {
            return status;
        }

        return KeModifySystemAllowedCpuSets(
            payloadLength >> 3,
            (_DWORD)cpuSetBuffer2,
            0,
            (int)modeSelector);
    }

    case 206:
    {
        if (systemInformationLength != sizeof(ULONGLONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode &&
            !SeSinglePrivilegeCheck(SeSystemtimePrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        if (PsIsCurrentThreadInServerSilo(0, systemInformation, systemInformationLength, 1))
        {
            return STATUS_ACCESS_DENIED;
        }

        byteFlag = systemInfo128->m128i_i64[0] != 0;
        status = ExSetLeapSecondEnabled();
        if (status < 0)
        {
            return status;
        }

        *(_BYTE *)ExLeapSecondData = byteFlag;
        return status;
    }

    case 207:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        if ((systemInfo128->m128i_i32[0] & 0x2018) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        NtGlobalFlag2 =
            (NtGlobalFlag2 & 0x2018) |
            systemInfo128->m128i_i32[0];
        systemInfo128->m128i_i32[0] = NtGlobalFlag2;
        return STATUS_SUCCESS;
    }

    case 210:
    {
        return CmUpdateFeatureConfiguration(
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 212:
    {
        return CmUpdateFeatureUsageSubscription(
            systemInformation,
            systemInformationLength,
            previousMode);
    }

    case 217:
    {
        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        return VfVolatileSetDifRuleClass(systemInfo128, inputLength);
    }

    case 218:
    {
        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_ACCESS_DENIED;
        }

        return VfVolatileClearDifRuleClass();
    }

    case 219:
    case 220:
    {
        PCUNICODE_STRING difTargetName = (PCUNICODE_STRING)systemInfo128;

        if (systemInformationLength != 16)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (previousMode != KernelMode)
        {
            if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            status = VfProbeAndCaptureUnicodeString(capturedUnicodeStorage, systemInfo128, TRUE);
            if (status < 0)
            {
                return status;
            }

            difTargetName = (PCUNICODE_STRING)capturedUnicodeStorage;
            if (LOWORD(capturedUnicodeStorage[0]) == 0)
            {
                return (NTSTATUS)0xC000010F;
            }
        }

        if (infoClass == 219)
        {
            status = VfVolatileApplyDifVerification(
                (__m128i *)difTargetName,
                systemInformation,
                systemInformationLength,
                1);
        }
        else
        {
            status = VfVolatileRemoveDifVerification(
                (__m128i *)difTargetName,
                systemInformation,
                systemInformationLength,
                1);
        }

        if (previousMode != KernelMode)
        {
            VfFreeCapturedUnicodeString(difTargetName);
        }

        return status;
    }

    case 223:
    {
        return ExPoolSetLimit(systemInformation, systemInformationLength, previousMode);
    }

    case 226:
    {
        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return VfPtGenerateTraceInformation(inputLength == 0);
    }

    case 228:
    case 229:
    {
        BOOLEAN isAdmin = FALSE;

        if (RtlCheckTokenMembership(NULL, SeAliasAdminsSid, &isAdmin, 1) < 0 || !isAdmin)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        return KeUpdateDpcWatchdogConfiguration(systemInfo128, inputLength);
    }

    case 233:
    {
        return PnpIommuBlockUnblockDevice(
            systemInformation,
            systemInformationLength,
            systemInformationLength,
            1);
    }

    case 235:
    {
        return HvlQuerySetBootPagesInfo(systemInformation, 0);
    }

    case 243:
    {
        return STATUS_NOT_SUPPORTED;
    }

    case 245:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        ExResourceTimeoutCount = (systemInfo128->m128i_i32[0] + 3999) / 0xFA0u;
        return STATUS_SUCCESS;
    }

    case 246:
    {
        if (systemInformationLength != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SeSinglePrivilegeCheck(SeDebugPrivilege, previousMode))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        PspBreakOnContextUnwindFailure = systemInfo128->m128i_i32[0];
        return STATUS_SUCCESS;
    }

    case 164:
    case 190:
    case 199:
    case 224:
    case 225:
    {
        if (qword_140F04A80 != 0)
        {
            return guard_dispatch_icall_no_overrides(
                infoClass,
                systemInformation,
                systemInformationLength,
                1);
        }

        return STATUS_NOT_SUPPORTED;
    }

    default:
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    }
}
