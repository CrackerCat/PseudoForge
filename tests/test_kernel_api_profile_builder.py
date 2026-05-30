import unittest
from pathlib import Path

from tools.build_kernel_api_profile import (
    _eval_int_expression,
    _extract_function_declarations,
    _merge_function_semantics,
)


class KernelApiProfileBuilderTests(unittest.TestCase):
    def test_parser_rejects_iprtrmib_comment_prose_as_function(self):
        header = r"""
/*
Abstract:
    This file contains definitions used by the IP Router Manager
    (as mentioned in ipinfoid.h).
*/
#define NUMBER_OF_EXPORTED_VARIABLES 1
typedef struct _MIB_OPAQUE_QUERY {
    DWORD dwVarId;
    DWORD dwVarIndex[1];
} MIB_OPAQUE_QUERY, *PMIB_OPAQUE_QUERY;

NTKERNELAPI
NTSTATUS
NTAPI
RealKernelFunction(
    _In_ HANDLE Handle
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertNotIn("Manager", declarations)
        self.assertNotIn("MIB_OPAQUE_QUERY", declarations)
        self.assertIn("RealKernelFunction", declarations)
        self.assertEqual(declarations["RealKernelFunction"]["return_type"], "NTSTATUS")

    def test_parser_keeps_markerless_plain_prototypes(self):
        header = r"""
PIMAGE_EXPORT_DIRECTORY
AuxKlibGetImageExportDirectory(
    _In_ PVOID ImageBase
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertIn("AuxKlibGetImageExportDirectory", declarations)
        self.assertEqual(
            declarations["AuxKlibGetImageExportDirectory"]["return_type"],
            "PIMAGE_EXPORT_DIRECTORY",
        )

    def test_parser_keeps_marker_split_by_comment_line(self):
        header = r"""
NTKERNELAPI
/* _Check_return_ */
NTSTATUS
PsGetSiloContext(
    _In_ PESILO Silo
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertIn("PsGetSiloContext", declarations)
        self.assertEqual(declarations["PsGetSiloContext"]["return_type"], "NTSTATUS")

    def test_parser_does_not_cross_previous_declaration_after_spaced_blank(self):
        header = (
            "NTAPI\n"
            "PreviousFunction(\n"
            "    VOID\n"
            "    );\n"
            "    \n"
            "KSDDKAPI\n"
            "NTSTATUS\n"
            "NTAPI\n"
            "KsGetBusEnumIdentifier(\n"
            "    _Inout_ PIRP Irp\n"
            "    );\n"
        )

        declarations = _extract_function_declarations(header)

        self.assertIn("KsGetBusEnumIdentifier", declarations)
        self.assertNotIn("PreviousFunction", declarations)
        self.assertEqual(
            declarations["KsGetBusEnumIdentifier"]["return_type"],
            "KSDDKAPI NTSTATUS",
        )

    def test_ast_integer_expression_evaluator_accepts_needed_macro_math(self):
        symbols = {
            "POOL_FLAG_USE_QUOTA": 1,
            "POOL_FLAG_PAGED": 0x100,
        }

        self.assertEqual(
            _eval_int_expression("POOL_FLAG_USE_QUOTA | POOL_FLAG_PAGED", symbols),
            0x101,
        )
        self.assertEqual(_eval_int_expression("(ULONG)(1 << 8)", {}), 0x100)
        self.assertEqual(_eval_int_expression("5 / 2", {}), 2)
        self.assertEqual(_eval_int_expression("~0", {}), -1)

    def test_ast_integer_expression_evaluator_rejects_unsupported_nodes(self):
        self.assertIsNone(_eval_int_expression("__import__('os').system('whoami')", {}))
        self.assertIsNone(_eval_int_expression("1 if 1 else 0", {}))
        self.assertIsNone(_eval_int_expression("1 << -1", {}))
        self.assertIsNone(_eval_int_expression("1 / 0", {}))

    def test_merge_function_semantics_remains_compatible(self):
        declaration = {
            "return_type": "NTSTATUS",
            "raw_signature": "NTSTATUS ExAllocatePool2(...);",
            "params": [
                {"name": "Flags", "type": "POOL_FLAGS"},
                {"name": "NumberOfBytes", "type": "SIZE_T"},
                {"name": "Tag", "type": "ULONG"},
            ],
        }

        metadata = _merge_function_semantics("ExAllocatePool2", declaration, Path("wdm.h"))

        self.assertEqual(metadata["params"][0]["kind"], "flags")
        self.assertEqual(metadata["params"][2]["kind"], "pool_tag")


if __name__ == "__main__":
    unittest.main()
