// rea decompile_all
// name: FUN_140011410
// address: 0x140011410
// body: available
// range: 0x140011410-0x140011456 inclusive
// range: 0x140011460-0x14001147f inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


/* WARNING: Enum "SectionFlags": Some values do not have unique names */

IMAGE_SECTION_HEADER * FUN_140011410(longlong param_1)

{
  IMAGE_SECTION_HEADER *pIVar1;
  int iVar2;
  
  iVar2 = 7;
  pIVar1 = &IMAGE_SECTION_HEADER_140000180;
  while ((param_1 - 0x140000000U < (ulonglong)(uint)pIVar1->VirtualAddress ||
         ((ulonglong)(pIVar1->VirtualAddress + (pIVar1->Misc).PhysicalAddress) <=
          param_1 - 0x140000000U))) {
    pIVar1 = pIVar1 + 1;
    iVar2 = iVar2 + -1;
    if (iVar2 == 0) {
      return (IMAGE_SECTION_HEADER *)0x0;
    }
  }
  return pIVar1;
}

