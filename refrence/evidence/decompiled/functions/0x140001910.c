// rea decompile_all
// name: FUN_140001910
// address: 0x140001910
// body: available
// range: 0x140001910-0x140001992 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000198e to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140001910(LPCWSTR param_1,ulonglong param_2)

{
  WCHAR WVar1;
  DWORD DVar2;
  longlong lVar3;
  longlong lVar4;
  ulonglong uVar5;
  WCHAR aWStackX_8 [16];
  undefined8 uStack_20;
  
  uStack_20 = 0x14000191d;
  lVar3 = FUN_140005b80();
  lVar3 = -lVar3;
  *(undefined8 *)((longlong)&uStack_20 + lVar3) = 0x14000193b;
  DVar2 = GetFullPathNameW(param_1,(DWORD)param_2,(LPWSTR)((longlong)aWStackX_8 + lVar3),
                           (LPWSTR *)0x0);
  if ((DVar2 != 0) && (DVar2 < param_2)) {
    WVar1 = *(WCHAR *)((longlong)aWStackX_8 + lVar3);
    if (WVar1 != L'\0') {
      lVar4 = 0;
      uVar5 = 0;
      do {
        if (param_2 == uVar5) goto LAB_14000198e;
        param_1[uVar5] = WVar1;
        WVar1 = *(WCHAR *)((longlong)aWStackX_8 + uVar5 * 2 + lVar3 + 2);
        uVar5 = uVar5 + 1;
        lVar4 = lVar4 + -2;
      } while (WVar1 != L'\0');
      param_1 = (LPCWSTR)((longlong)param_1 - lVar4);
    }
    *param_1 = L'\0';
    return;
  }
LAB_14000198e:
                    /* WARNING: Subroutine does not return */
  *(undefined **)((longlong)&uStack_20 + lVar3) = &UNK_140001993;
  abort();
}

