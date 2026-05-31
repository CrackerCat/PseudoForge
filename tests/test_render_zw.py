from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import (
    display_warning_count,
    render_cleaned_pseudocode,
)
from ida_pseudoforge.core.render_zw import normalize_zw_api_probe_body


ZW_API_PROBE_SAMPLE = r"""
void sub_1400059F0()
{
  NTSTATUS v0; // eax
  NTSTATUS v1; // eax
  NTSTATUS v2; // eax
  NTSTATUS v3; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v4; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v5; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v6; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v7; // [rsp+60h] [rbp-1A8h]
  void *EventHandle; // [rsp+68h] [rbp-1A0h] BYREF
  ULONG ReturnLength; // [rsp+70h] [rbp-198h] BYREF
  void *TokenHandle; // [rsp+78h] [rbp-190h] BYREF
  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF
  union _LARGE_INTEGER Timeout; // [rsp+B0h] [rbp-158h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+B8h] [rbp-150h] BYREF
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+C8h] [rbp-140h] BYREF
  struct _UNICODE_STRING ValueName; // [rsp+D8h] [rbp-130h] BYREF
  _BYTE KeyValueInformation[256]; // [rsp+F0h] [rbp-118h] BYREF

  EventHandle = 0LL;
  TokenHandle = 0LL;
  ReturnLength = 0;
  Timeout.QuadPart = 0LL;
  memset(KeyValueInformation, 0, sizeof(KeyValueInformation));
  memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));
  v0 = ZwClose(0LL);
  DbgSetWaitTimeout(v0);
  v1 = ZwWaitForSingleObject(0LL, 0, &Timeout);
  DbgSetWaitTimeout(v1);
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.ObjectName = 0LL;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v3 = ZwCreateEvent(&EventHandle, 0x1F0003u, &ObjectAttributes, NotificationEvent, 0);
  DbgSetWaitTimeout(v3);
  if ( v3 >= 0 )
  {
    ZwSetEvent(EventHandle, 0LL);
    ZwWaitForSingleObject(EventHandle, 0, &Timeout);
    ZwClose(EventHandle);
    EventHandle = 0LL;
  }
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v4 = ZwOpenKey(&EventHandle, 0x20019u, &ObjectAttributes);
  DbgSetWaitTimeout(v4);
  if ( v4 >= 0 )
  {
    RtlInitUnicodeString(&ValueName, L"SystemStartOptions");
    ZwQueryValueKey(EventHandle, &ValueName, KeyValuePartialInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwQueryKey(EventHandle, KeyBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(EventHandle);
    EventHandle = 0LL;
  }
  v5 = ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &TokenHandle);
  DbgSetWaitTimeout(v5);
  if ( v5 >= 0 )
  {
    ZwQueryInformationToken(TokenHandle, TokenUser, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(TokenHandle);
  }
  v6 = ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &TokenHandle);
  DbgSetWaitTimeout(v6);
  if ( v6 >= 0 )
  {
    ZwClose(TokenHandle);
  }
  v2 = ZwQueryObject(0LL, ObjectBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
  DbgSetWaitTimeout(v2);
  RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\Temp\\PfkpApiCorpus.tmp");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v7 = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);
  DbgSetWaitTimeout(v7);
  if ( v7 >= 0 )
  {
    ZwQueryInformationFile(EventHandle, &IoStatusBlock, KeyValueInformation, 0x100u, FileBasicInformation);
    ZwClose(EventHandle);
  }
}
"""


ZW_REUSED_STATUS_SLOT_SAMPLE = r"""
int ZwProbeNoPdbSample()
{
  NTSTATUS v0; // eax
  int result; // eax
  void *EventHandle; // [rsp+60h] [rbp-A0h] BYREF
  ULONG ReturnLength; // [rsp+68h] [rbp-98h] BYREF
  void *TokenHandle; // [rsp+70h] [rbp-90h] BYREF
  union _LARGE_INTEGER Timeout; // [rsp+78h] [rbp-88h] BYREF
  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-80h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+B0h] [rbp-50h] BYREF
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+C0h] [rbp-40h] BYREF
  struct _UNICODE_STRING ValueName; // [rsp+D0h] [rbp-30h] BYREF
  _BYTE KeyValueInformation[256]; // [rsp+E0h] [rbp-20h] BYREF

  EventHandle = 0LL;
  TokenHandle = 0LL;
  ReturnLength = 0;
  Timeout.QuadPart = 0LL;
  memset(KeyValueInformation, 0, sizeof(KeyValueInformation));
  IoStatusBlock = 0LL;
  g_ReusedZwStatus = ZwClose(0LL);
  v0 = ZwWaitForSingleObject(0LL, 0, &Timeout);
  ObjectAttributes.Length = 48;
  g_ReusedZwStatus = v0;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.ObjectName = 0LL;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  g_ReusedZwStatus = ZwCreateEvent(&EventHandle, 0x1F0003u, &ObjectAttributes, NotificationEvent, 0);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwSetEvent(EventHandle, 0LL);
    ZwWaitForSingleObject(EventHandle, 0, &Timeout);
    ZwClose(EventHandle);
  }
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  g_ReusedZwStatus = ZwOpenKey(&EventHandle, 0x20019u, &ObjectAttributes);
  if ( g_ReusedZwStatus >= 0 )
  {
    RtlInitUnicodeString(&ValueName, L"SystemStartOptions");
    ZwQueryValueKey(EventHandle, &ValueName, KeyValuePartialInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwQueryKey(EventHandle, KeyBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(EventHandle);
  }
  g_ReusedZwStatus = ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &TokenHandle);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwQueryInformationToken(TokenHandle, TokenUser, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(TokenHandle);
  }
  g_ReusedZwStatus = ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &TokenHandle);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwClose(TokenHandle);
  }
  g_ReusedZwStatus = ZwQueryObject(0LL, ObjectBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
  RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\Temp\\Any.tmp");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  result = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);
  g_ReusedZwStatus = result;
  if ( result >= 0 )
  {
    ZwQueryInformationFile(EventHandle, &IoStatusBlock, KeyValueInformation, 0x100u, FileBasicInformation);
    return ZwClose(EventHandle);
  }
  return result;
}
"""


class RenderZwTests(unittest.TestCase):
    def test_normalize_zw_api_probe_body_rewrites_object_attributes_and_handles(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Length = 48;",
                "objectAttributes.Attributes = 576;",
                "createEventStatus = ZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, 0);",
                "if ( createEventStatus >= 0 )",
                "  ZwSetEvent(eventHandle, 0LL);",
                "ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &tokenHandle);",
                "ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &tokenHandle);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("if ( NT_SUCCESS(createEventStatus) )", rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwOpenThreadTokenEx(NtCurrentThread(), 8u, 1u, 0x200u, &tokenHandle);", rendered)

    def test_normalize_zw_api_probe_body_rewrites_only_used_object_attributes(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Length = 0x30u;",
                "objectAttributes.Attributes = 0x200u;",
                "otherHeader.Length = 48;",
                "ZwOpenKey(&eventHandle, 0x20019u, &objectAttributes);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("otherHeader.Length = 48;", rendered)

    def test_normalize_zw_api_probe_body_preserves_unknown_object_attribute_bits(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Attributes = 0x2402u;",
                "ZwCreateKey(&eventHandle, 0xF003Fu, &objectAttributes, 0, 0LL, 0, 0LL);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn(
            "objectAttributes.Attributes = OBJ_INHERIT | OBJ_FORCE_ACCESS_CHECK | 0x2000;",
            rendered,
        )

    def test_zw_api_probe_gets_deterministic_names_and_status_checks(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "DestinationString", "new": "objectPath", "confidence": 0.70},
                            {"old": "EventHandle", "new": "genericHandle", "confidence": 0.80},
                            {"old": "KeyValueInformation", "new": "infoBuffer", "confidence": 0.85},
                            {"old": "v0", "new": "closeStatus", "confidence": 0.85},
                            {"old": "v1", "new": "waitStatus", "confidence": 0.85},
                            {"old": "v2", "new": "queryObjectStatus", "confidence": 0.85},
                            {"old": "v3", "new": "createEventStatus", "confidence": 0.95},
                            {"old": "v4", "new": "openKeyStatus", "confidence": 0.95},
                            {"old": "v5", "new": "openProcessTokenStatus", "confidence": 0.95},
                            {"old": "v6", "new": "openThreadTokenStatus", "confidence": 0.95},
                            {"old": "v7", "new": "createFileStatus", "confidence": 0.95},
                        ],
                        "warnings": [
                            (
                                "Function exercises many Zw* APIs and writes results to PfkpApiCorpus.tmp; "
                                "likely an API-probing/corpus routine."
                            ),
                            (
                                "infoBuffer is reused across heterogeneous query types "
                                "(KeyValuePartialInformation, TokenUser, ObjectBasicInformation, "
                                "FileBasicInformation); name is intentionally generic."
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(ZW_API_PROBE_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v0"], "closeStatus")
        self.assertEqual(rename_map["v1"], "waitStatus")
        self.assertEqual(rename_map["v2"], "queryObjectStatus")
        self.assertEqual(rename_map["v3"], "createEventStatus")
        self.assertEqual(rename_map["v4"], "openKeyStatus")
        self.assertEqual(rename_map["v5"], "openProcessTokenStatus")
        self.assertEqual(rename_map["v6"], "openThreadTokenStatus")
        self.assertEqual(rename_map["v7"], "createFileStatus")
        self.assertEqual(rename_map["EventHandle"], "genericHandle")
        self.assertEqual(rename_map["TokenHandle"], "tokenHandle")
        self.assertEqual(rename_map["DestinationString"], "objectPath")
        self.assertEqual(rename_map["KeyValueInformation"], "infoBuffer")
        self.assertEqual(rename_map["ReturnLength"], "returnLength")
        self.assertEqual(rename_map["ObjectAttributes"], "objectAttributes")
        self.assertEqual(rename_map["Timeout"], "timeout")
        self.assertEqual(rename_map["IoStatusBlock"], "ioStatusBlock")
        self.assertEqual(rename_map["ValueName"], "valueName")
        self.assertIn("zw_api_probe", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("createEventStatus = ZwCreateEvent(&genericHandle", rendered)
        self.assertIn("ZwWaitForSingleObject(0LL, FALSE, &timeout);", rendered)
        self.assertIn("ZwWaitForSingleObject(genericHandle, FALSE, &timeout);", rendered)
        self.assertIn("if ( NT_SUCCESS(createEventStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openKeyStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openProcessTokenStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openThreadTokenStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(createFileStatus) )", rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwOpenThreadTokenEx(NtCurrentThread(), 8u, TRUE, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwQueryValueKey(genericHandle, &valueName, KeyValuePartialInformation, infoBuffer", rendered)
        self.assertIn("ZwQueryInformationToken(tokenHandle, TokenUser, infoBuffer", rendered)
        self.assertIn("ZwQueryObject(0LL, ObjectBasicInformation, infoBuffer", rendered)
        self.assertIn("ZwQueryInformationFile(genericHandle, &ioStatusBlock, infoBuffer", rendered)
        self.assertNotIn("ObjectAttributes.Length = 48", rendered)
        self.assertNotIn("(HANDLE)0xFFFFFFFFFFFFFFFF", rendered)
        self.assertNotIn("KeyValueInformation", rendered.rsplit("*/", 1)[-1])

        partial_sample = ZW_API_PROBE_SAMPLE.replace(
            "  v7 = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);\n",
            "",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(any(comment.get("kind") == "zw_api_probe" for comment in partial_plan.comments))

        generic_sample = (
            ZW_API_PROBE_SAMPLE.replace("ObjectAttributes", "vAttr")
            .replace("ReturnLength", "vReturnLength")
            .replace("Timeout", "vTimeout")
            .replace("IoStatusBlock", "vIoStatus")
            .replace("ValueName", "vValueName")
            .replace("KeyValueInformation", "vInfoBuffer")
            .replace("0x100u", "0x40u")
            .replace("vAttr.Length = 48;", "vAttr.Length = 0x30u;")
            .replace("vAttr.Attributes = 512;", "vAttr.Attributes = 0x200u;")
            .replace("vAttr.Attributes = 576;", "vAttr.Attributes = 0x240u;")
            .replace("(HANDLE)0xFFFFFFFFFFFFFFFFLL", "(HANDLE)0xFFFFFFFFFFFFFFFFui64")
            .replace(
                'L"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Control"',
                'L"\\\\BaseNamedObjects\\\\PfkpObject"',
            )
        )
        generic_capture = capture_from_pseudocode(generic_sample)
        generic_plan = build_clean_plan(generic_capture)
        generic_map = {item.old: item.new for item in generic_plan.renames if item.apply}
        generic_rendered = render_cleaned_pseudocode(generic_capture, generic_plan)
        self.assertEqual(generic_map["vAttr"], "objectAttributes")
        self.assertEqual(generic_map["vReturnLength"], "returnLength")
        self.assertEqual(generic_map["vTimeout"], "timeout")
        self.assertEqual(generic_map["vIoStatus"], "ioStatusBlock")
        self.assertEqual(generic_map["vValueName"], "valueName")
        self.assertEqual(generic_map["vInfoBuffer"], "infoBuffer")
        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", generic_rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", generic_rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", generic_rendered)
        self.assertIn("ZwQueryValueKey(genericHandle, &valueName, KeyValuePartialInformation, infoBuffer, 0x40u", generic_rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", generic_rendered)
        self.assertIn("RtlInitUnicodeString(&objectPath, L\"\\\\BaseNamedObjects\\\\PfkpObject\");", generic_rendered)

        guard_sample = ZW_API_PROBE_SAMPLE.replace(
            "  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF\n",
            (
                "  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF\n"
                "  _SOME_HEADER OtherHeader; // [rsp+88h] [rbp-180h]\n"
            ),
            1,
        ).replace(
            "  ObjectAttributes.Length = 48;\n",
            "  ObjectAttributes.Length = 48;\n  OtherHeader.Length = 48;\n",
            1,
        )
        guard_capture = capture_from_pseudocode(guard_sample)
        guard_rendered = render_cleaned_pseudocode(guard_capture, build_clean_plan(guard_capture))
        self.assertIn("OtherHeader.Length = 48;", guard_rendered)

    def test_zw_reused_status_slot_is_not_given_routine_specific_name(self):
        capture = capture_from_pseudocode(ZW_REUSED_STATUS_SLOT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("g_ReusedZwStatus", rename_map)
        self.assertEqual(rename_map["v0"], "waitStatus")
        self.assertEqual(rename_map["result"], "createFileStatus")
        self.assertIn("g_ReusedZwStatus = ZwCreateEvent", rendered)
        self.assertIn("g_ReusedZwStatus = ZwOpenKey", rendered)
        self.assertIn("g_ReusedZwStatus = ZwOpenProcessTokenEx", rendered)
        self.assertNotIn("closeStatus = ZwCreateEvent", rendered)
        self.assertNotIn("closeStatus = ZwOpenKey", rendered)
        self.assertNotIn("closeStatus = ZwOpenProcessTokenEx", rendered)

    def test_mm_get_system_routine_address_indirect_call_uses_profile_metadata(self):
        sample = r"""
__int64 __fastcall sub_140004000()
{
  NTSTATUS status; // [rsp+30h] [rbp-48h]
  UNICODE_STRING routineName; // [rsp+38h] [rbp-40h] BYREF
  PVOID pZwCreateEvent; // [rsp+48h] [rbp-30h]
  HANDLE eventHandle; // [rsp+50h] [rbp-28h] BYREF
  OBJECT_ATTRIBUTES objectAttributes; // [rsp+58h] [rbp-20h] BYREF

  pZwCreateEvent = 0LL;
  RtlInitUnicodeString(&routineName, L"ZwCreateEvent");
  pZwCreateEvent = (PVOID)MmGetSystemRoutineAddress((PUNICODE_STRING)&routineName);
  status = pZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, 1u);
  return (unsigned int)status;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "PseudoForge: resolved indirect call pZwCreateEvent as ZwCreateEvent via MmGetSystemRoutineAddress "
            'confidence=0.95; routine string L"ZwCreateEvent"',
            rendered,
        )
        self.assertIn(
            "status = pZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, TRUE);",
            rendered,
        )
        self.assertNotIn("status = ZwCreateEvent(", rendered)

    def test_mm_get_system_routine_address_indirect_call_can_use_variable_name_hint(self):
        sample = r"""
void __fastcall sub_140004100()
{
  UNICODE_STRING routineName; // [rsp+30h] [rbp-58h] BYREF
  PVOID pExInitializeNPagedLookasideList; // [rsp+40h] [rbp-48h]
  NPAGED_LOOKASIDE_LIST lookaside; // [rsp+48h] [rbp-40h] BYREF

  pExInitializeNPagedLookasideList = MmGetSystemRoutineAddress(&routineName);
  pExInitializeNPagedLookasideList(&lookaside, 0LL, 0LL, 0, 0x38uLL, 0x724B4650u, 0);
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "PseudoForge: resolved indirect call pExInitializeNPagedLookasideList as "
            "ExInitializeNPagedLookasideList via MmGetSystemRoutineAddress confidence=0.70; "
            "inferred from function pointer variable name",
            rendered,
        )
        self.assertIn(
            "pExInitializeNPagedLookasideList(&lookaside, 0LL, 0LL, 0, 0x38uLL, "
            "POOL_TAG('P', 'F', 'K', 'r'), 0);",
            rendered,
        )

    def test_mm_get_system_routine_address_indirect_call_requires_matching_arity(self):
        sample = r"""
__int64 __fastcall sub_140004200()
{
  NTSTATUS status; // [rsp+30h] [rbp-48h]
  UNICODE_STRING routineName; // [rsp+38h] [rbp-40h] BYREF
  PVOID pZwCreateEvent; // [rsp+48h] [rbp-30h]
  HANDLE eventHandle; // [rsp+50h] [rbp-28h] BYREF

  RtlInitUnicodeString(&routineName, L"ZwCreateEvent");
  pZwCreateEvent = MmGetSystemRoutineAddress(&routineName);
  status = pZwCreateEvent(&eventHandle, 1u);
  return (unsigned int)status;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("PseudoForge: resolved indirect call", rendered)
        self.assertIn("status = pZwCreateEvent(&eventHandle, 1u);", rendered)
        self.assertNotIn("TRUE", rendered)


if __name__ == "__main__":
    unittest.main()
