# PfKernelPattern

`PfKernelPattern` is a small WDM driver and console harness used as a static-analysis corpus for PseudoForge. It intentionally combines common kernel-driver call patterns without performing risky memory writes or process modification.

## Included Patterns

- WDM `DriverEntry`, `DriverUnload`, `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL`
- `IoCreateDevice`, `IoCreateSymbolicLink`, `DO_BUFFERED_IO`, and `METHOD_BUFFERED` IOCTL validation
- `ExAllocatePool2`, `ExFreePoolWithTag`, and `NPAGED_LOOKASIDE_LIST`
- `LIST_ENTRY` insert, remove, bounded telemetry retention, and variable-size output using `FIELD_OFFSET`
- `FAST_MUTEX`, `ERESOURCE`, `KeEnterCriticalRegion`, and `KeLeaveCriticalRegion`
- `PsLookupProcessByProcessId` with `ObDereferenceObject`
- `KTIMER`, `KDPC`, `IoAllocateWorkItem`, and `IoQueueWorkItem`
- Optional process, image-load, and thread callbacks through `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, and `PsSetCreateThreadNotifyRoutine`
- Optional process object handle callback registration through `ObRegisterCallbacks`
- Object pre-operation callback logic concentrated inside `PfkpObjectPreOperation`, including LIST_ENTRY-backed process whitelist/blacklist walks with `CONTAINING_RECORD`, requested-access checks, and requester auto-add
- `RtlQueryRegistryValues` for simple service-registry configuration
- Static-analysis-only WDK API call corpus in `WdkApiCallCorpus.cpp`, grouped into `ExFunctionCallTest`, `PsFunctionCallTest`, `ObFunctionCallTest`, `KeFunctionCallTest`, `IoFunctionCallTest`, `CmFunctionCallTest`, `MmFunctionCallTest`, `NtFunctionCallTest`, `ZwFunctionCallTest`, `RtlFunctionCallTest`, and `SeFunctionCallTest`

The callback path is opt-in through the user tool's `--callbacks` switch. The default run exercises IOCTL, allocation, process lookup, timer, work-item, and event-list paths only. `ObRegisterCallbacks` can fail with code-integrity or altitude conflicts on machines that are not configured for object callbacks; the sample reports that status instead of treating it as a default-path failure.

The WDK API call corpus is referenced from `DriverEntry` through a volatile disabled gate and is not executed during the normal sample run. It exists to give IDA and PseudoForge richer call-pattern coverage across common kernel prefixes without changing the default runtime behavior.

## Build

Requirements:

- Visual Studio 2022
- Windows Driver Kit with Windows 10 SDK/WDK `10.0.26100.0`

Build Release x64:

```powershell
.\tools\build.ps1 -Configuration Release
```

Or call MSBuild directly:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" .\PfKernelPattern.sln /m /p:Configuration=Release /p:Platform=x64 /v:minimal
```

Expected outputs:

```text
x64\Release\PfKernelPattern.sys
x64\Release\PfKernelPatternTool.exe
x64\Release\PfKernelPattern.pdb
```

## Run

Live loading modifies SCM and kernel state. Run only in a VM or disposable test machine with test-signing configured.

```powershell
.\x64\Release\PfKernelPatternTool.exe
```

Optional callback registration:

```powershell
.\x64\Release\PfKernelPatternTool.exe --callbacks
```

Keep the driver loaded after the probe run:

```powershell
.\x64\Release\PfKernelPatternTool.exe --leave-loaded
```

The tool installs the kernel service, starts the driver, opens `\\.\PfKernelPattern`, exercises the IOCTL surface, prints raw counters/events, then stops and deletes the service unless `--leave-loaded` is used.

## Analysis Use

For PseudoForge and IDA tests, analyze the built `.sys`:

```powershell
.\tools\run_pseudoforge_ida_batch.ps1 `
  -IdaPath "C:\Program Files\IDA Professional 9.0\ida.exe" `
  -IdbPath "<path-to-PfKernelPattern.sys.i64>" `
  -TargetPath ".\x64\Release\PfKernelPattern.sys" `
  -OutputDir "$env:TEMP\pseudoforge_pfkp" `
  -MaxFunctions 200 `
  -LlmRenames `
  -LlmProvider codex_cli `
  -LlmModel gpt-5.5
```

This corpus should produce decompiler patterns around cleanup tails, dispatch switches, pool tags, object references, callback registration, object pre-operation callbacks, whitelist/blacklist list walks, work item cleanup, timer/DPC paths, and list management.
