NTSET_SYSTEM_INFORMATION_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  size_t v3;
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  PVOID Object;

  v3 = (unsigned int)a3;
  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  if ( v5 > 113 )
  {
    if ( v5 == 194 )
      return IoProvisionCrashDumpKey();
    v115 = v5 - 235;
    if ( !v115 )
      return HvlQuerySetBootPagesInfo(a2, 0LL);
    v116 = v115 - 8;
    if ( !v116 )
      return (ULONG)-1073741637;
  }
  if ( v5 == 9 )
    return 3221225476LL;
LABEL_214:
  ObfDereferenceObject(Object);
  return updated;
LABEL_421:
  VfFreeCapturedUnicodeString(v4);
  return updated;
  return (ULONG)-1073741821;
}
"""
