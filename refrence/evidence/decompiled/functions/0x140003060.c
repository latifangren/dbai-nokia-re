// rea decompile_all
// name: FUN_140003060
// address: 0x140003060
// body: available
// range: 0x140003060-0x1400030e0 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x1400030dc to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140003060(short *param_1,short *param_2,longlong param_3)

{
  short sVar1;
  size_t sVar2;
  longlong lVar3;
  longlong lVar4;
  
  if (param_2 != (short *)0x0) {
    if (*param_1 != 0) {
      sVar2 = wcslen(param_1 + 1);
      param_1 = param_1 + sVar2 + 1;
      param_3 = param_3 + ~sVar2;
    }
    sVar1 = *param_2;
    if (sVar1 != 0) {
      lVar3 = 0;
      lVar4 = 0;
      do {
        if (param_3 == lVar4) goto LAB_1400030dc;
        param_1[lVar4] = sVar1;
        sVar1 = param_2[lVar4 + 1];
        lVar4 = lVar4 + 1;
        lVar3 = lVar3 + -2;
      } while (sVar1 != 0);
      param_1 = (short *)((longlong)param_1 - lVar3);
    }
    *param_1 = 0;
    return;
  }
LAB_1400030dc:
                    /* WARNING: Subroutine does not return */
  abort();
}

