DRIVER_ENTRY_SAMPLE = r"""
__int64 __fastcall sub_140003530(struct _DRIVER_OBJECT *a1, __int64 a2)
{
  NTSTATUS v3; // [rsp+40h] [rbp-38h]
  unsigned int i; // [rsp+44h] [rbp-34h]
  _DWORD *DeferredContext; // [rsp+48h] [rbp-30h]
  PDEVICE_OBJECT DeviceObject; // [rsp+50h] [rbp-28h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+58h] [rbp-20h] BYREF

  DeviceObject = 0LL;
  DeferredContext = 0LL;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\PfKernelPattern");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\PfKernelPattern");
  for ( i = 0; i <= 0x1B; ++i )
    a1->MajorFunction[i] = (PDRIVER_DISPATCH)sub_140003430;
  a1->MajorFunction[0] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[2] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[14] = (PDRIVER_DISPATCH)sub_1400013F0;
  a1->DriverUnload = (PDRIVER_UNLOAD)sub_140003270;
  v3 = IoCreateDevice(a1, 0x340u, &DestinationString, 0x8337u, 0x100u, 0, &DeviceObject);
  if ( v3 >= 0 )
  {
    DeviceObject->Flags |= 4u;
    DeferredContext = DeviceObject->DeviceExtension;
    memset(DeferredContext, 0, 0x340uLL);
    *DeferredContext = 1883981392;
    *((_QWORD *)DeferredContext + 1) = DeviceObject;
    DeferredContext[184] = 64;
    qword_140005010 = (__int64)DeviceObject;
    sub_1400039D0(DeferredContext + 4);
    sub_1400039D0(DeferredContext + 18);
    KeInitializeSpinLock((PKSPIN_LOCK)DeferredContext + 16);
    sub_140003A70(DeferredContext + 34);
    sub_140003A70(DeferredContext + 38);
    sub_140003A70(DeferredContext + 42);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48),
      0LL,
      0LL,
      0,
      0x38uLL,
      0x724B4650u,
      0);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80),
      0LL,
      0LL,
      0,
      0x28uLL,
      0x6C4B4650u,
      0);
    KeInitializeTimerEx((PKTIMER)DeferredContext + 7, NotificationTimer);
    KeInitializeDpc((PRKDPC)DeferredContext + 8, DeferredRoutine, DeferredContext);
    KeInitializeEvent((PRKEVENT)(DeferredContext + 146), NotificationEvent, 1u);
    ExInitializeRundownProtection((PEX_RUNDOWN_REF)DeferredContext + 76);
    ExInitializeResourceLite((PERESOURCE)(DeferredContext + 154));
    v3 = sub_140002D60(DeferredContext);
    if ( v3 >= 0 )
    {
      v3 = sub_1400010D0(DeferredContext + 180, a2);
      if ( v3 >= 0 )
      {
        sub_140002950(DeferredContext);
        *((_QWORD *)DeferredContext + 72) = IoAllocateWorkItem(DeviceObject);
        if ( *((_QWORD *)DeferredContext + 72) )
        {
          v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
          if ( v3 >= 0 )
            DeviceObject->Flags &= ~0x80u;
        }
        else
        {
          v3 = -1073741670;
        }
      }
    }
  }
  if ( v3 < 0 )
  {
    if ( DeferredContext )
    {
      if ( *((_QWORD *)DeferredContext + 72) )
      {
        IoFreeWorkItem(*((PIO_WORKITEM *)DeferredContext + 72));
        *((_QWORD *)DeferredContext + 72) = 0LL;
      }
      if ( *((_QWORD *)DeferredContext + 91) )
      {
        ExFreePoolWithTag(*((PVOID *)DeferredContext + 91), 0x704B4650u);
        memset(DeferredContext + 180, 0, 0x10uLL);
      }
      ExDeleteResourceLite((PERESOURCE)(DeferredContext + 154));
      sub_140001310(DeferredContext);
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80));
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48));
    }
    if ( DeviceObject )
    {
      IoDeleteDevice(DeviceObject);
      qword_140005010 = 0LL;
    }
  }
  return (unsigned int)v3;
}
"""


IOCTL_DISPATCH_SAMPLE = r"""
__int64 __fastcall sub_1400013F0(__int64 a1, IRP *a2)
{
  int status; // [rsp+30h] [rbp-58h]
  __int64 v4; // [rsp+38h] [rbp-50h]
  unsigned int v5; // [rsp+44h] [rbp-44h]
  unsigned int v6; // [rsp+48h] [rbp-40h]
  struct _IRP *MasterIrp; // [rsp+58h] [rbp-30h]
  unsigned int v9; // [rsp+60h] [rbp-28h]
  _DWORD *v10; // [rsp+68h] [rbp-20h]

  v4 = *(_QWORD *)(a1 + 64);
  v10 = (_DWORD *)sub_140003B30(a2);
  MasterIrp = a2->AssociatedIrp.MasterIrp;
  v6 = v10[4];
  v5 = v10[2];
  v9 = v10[6];
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      break;
    case 0x8337A008:
      status = 0;
      break;
    case 0x8337E00C:
      status = 0;
      break;
    case 0x8337E010:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  switch ( status )
  {
    case 0x83376004:
      status = 1;
      break;
  }
  a2->IoStatus.Status = status;
  IofCompleteRequest(a2, 0);
  return (unsigned int)status;
}
"""


SINGLE_LINE_IF_SAMPLE = r"""
__int64 __fastcall SingleLineIfSample(int a1)
{
  int v1;

  v1 = 0;
  if ( a1 )
    *(_BYTE *)(v1 + 10) = 1;
  v1 = ZwLoadDriver(&DriverServiceName);
  return v1;
}
"""
