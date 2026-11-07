// rea decompile_all
// name: FUN_140001a00
// address: 0x140001a00
// body: available
// range: 0x140001a00-0x140001abe inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140001aba to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined2 * FUN_140001a00(short *param_1)

{
  longlong lVar1;
  short *psVar2;
  short *psVar3;
  short *psVar4;
  undefined2 *puVar5;
  longlong lVar6;
  short sVar7;
  
  sVar7 = *param_1;
  psVar2 = &DAT_142c30040;
  puVar5 = &DAT_142c30040;
  if (sVar7 != 0) {
    lVar1 = 0;
    do {
      lVar6 = lVar1;
      *(short *)((longlong)&DAT_142c30040 + lVar6) = sVar7;
      sVar7 = *(short *)((longlong)param_1 + lVar6 + 2);
      if (sVar7 == 0) {
        puVar5 = (undefined2 *)((longlong)&DAT_142c30042 + lVar6);
        goto LAB_140001a87;
      }
      *(short *)((longlong)&DAT_142c30042 + lVar6) = sVar7;
      sVar7 = *(short *)((longlong)param_1 + lVar6 + 4);
      if (sVar7 == 0) {
        puVar5 = (undefined2 *)((longlong)&DAT_142c30044 + lVar6);
        goto LAB_140001a87;
      }
      if (lVar6 == 0x1ffe) {
                    /* WARNING: Subroutine does not return */
        abort();
      }
      *(short *)((longlong)&DAT_142c30044 + lVar6) = sVar7;
      sVar7 = *(short *)((longlong)param_1 + lVar6 + 6);
      lVar1 = lVar6 + 6;
    } while (sVar7 != 0);
    puVar5 = (undefined2 *)((longlong)&DAT_142c30046 + lVar6);
  }
LAB_140001a87:
  *puVar5 = 0;
  psVar4 = (short *)0x0;
  for (; (psVar3 = psVar2, *psVar2 == 0x5c || (psVar3 = psVar4, *psVar2 != 0)); psVar2 = psVar2 + 1)
  {
    psVar4 = psVar3;
  }
  if (psVar4 != (short *)0x0) {
    *psVar4 = 0;
  }
  return &DAT_142c30040;
}

