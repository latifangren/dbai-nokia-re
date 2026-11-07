// rea decompile_all
// name: FUN_140001e00
// address: 0x140001e00
// body: available
// range: 0x140001e00-0x140001ef6 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140001ef2 to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


LPWSTR FUN_140001e00(undefined4 param_1)

{
  short *psVar1;
  longlong lVar2;
  LPWSTR pWVar3;
  LPWSTR lpFilename;
  short sVar4;
  
  psVar1 = DAT_142c30030;
  lpFilename = &DAT_142c36060;
  if ((char)param_1 != '\0') {
    lpFilename = &DAT_142c34050;
  }
  if (*lpFilename == L'\0') {
    if (DAT_142c30030 == (short *)0x0) {
      GetModuleFileNameW((HMODULE)0x0,lpFilename,0x1001);
    }
    else {
      sVar4 = *DAT_142c30030;
      pWVar3 = lpFilename;
      if (sVar4 != 0) {
        lVar2 = 0;
        do {
          *(short *)((longlong)lpFilename + lVar2) = sVar4;
          sVar4 = *(short *)((longlong)psVar1 + lVar2 + 2);
          if (sVar4 == 0) {
            pWVar3 = (LPWSTR)((longlong)lpFilename + lVar2 + 2);
            goto LAB_140001ebb;
          }
          *(short *)((longlong)lpFilename + lVar2 + 2) = sVar4;
          sVar4 = *(short *)((longlong)psVar1 + lVar2 + 4);
          if (sVar4 == 0) {
            pWVar3 = (LPWSTR)((longlong)lpFilename + lVar2 + 4);
            goto LAB_140001ebb;
          }
          if (lVar2 == 0x1ffe) {
                    /* WARNING: Subroutine does not return */
            abort();
          }
          *(short *)((longlong)lpFilename + lVar2 + 4) = sVar4;
          sVar4 = *(short *)((longlong)psVar1 + lVar2 + 6);
          lVar2 = lVar2 + 6;
        } while (sVar4 != 0);
        pWVar3 = (LPWSTR)(lVar2 + (longlong)lpFilename);
      }
LAB_140001ebb:
      *pWVar3 = L'\0';
    }
    FUN_140001f00(lpFilename,lpFilename,0x1001,param_1);
    FUN_140002140(&DAT_142c34050,0x1001);
  }
  return lpFilename;
}

