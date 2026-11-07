// rea decompile_all
// name: FUN_1400022d0
// address: 0x1400022d0
// body: available
// range: 0x1400022d0-0x140002430 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000242c to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


LPSTR FUN_1400022d0(undefined4 param_1)

{
  short *psVar1;
  uint cbMultiByte;
  uint uVar2;
  longlong lVar3;
  LPWSTR pWVar4;
  LPSTR lpMultiByteStr;
  LPWSTR lpFilename;
  short sVar5;
  
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
      sVar5 = *DAT_142c30030;
      pWVar4 = lpFilename;
      if (sVar5 != 0) {
        lVar3 = 0;
        do {
          *(short *)((longlong)lpFilename + lVar3) = sVar5;
          sVar5 = *(short *)((longlong)psVar1 + lVar3 + 2);
          if (sVar5 == 0) {
            pWVar4 = (LPWSTR)((longlong)lpFilename + lVar3 + 2);
            goto LAB_14000238f;
          }
          *(short *)((longlong)lpFilename + lVar3 + 2) = sVar5;
          sVar5 = *(short *)((longlong)psVar1 + lVar3 + 4);
          if (sVar5 == 0) {
            pWVar4 = (LPWSTR)((longlong)lpFilename + lVar3 + 4);
            goto LAB_14000238f;
          }
          if (lVar3 == 0x1ffe) goto LAB_14000242c;
          *(short *)((longlong)lpFilename + lVar3 + 4) = sVar5;
          sVar5 = *(short *)((longlong)psVar1 + lVar3 + 6);
          lVar3 = lVar3 + 6;
        } while (sVar5 != 0);
        pWVar4 = (LPWSTR)(lVar3 + (longlong)lpFilename);
      }
LAB_14000238f:
      *pWVar4 = L'\0';
    }
    FUN_140001f00(lpFilename,lpFilename,0x1001,param_1);
    FUN_140002140(&DAT_142c34050,0x1001);
  }
  cbMultiByte = WideCharToMultiByte(0,0,lpFilename,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
  lpMultiByteStr = malloc((ulonglong)(cbMultiByte + 1));
  uVar2 = WideCharToMultiByte(0,0,lpFilename,-1,lpMultiByteStr,cbMultiByte,(LPCSTR)0x0,(LPBOOL)0x0);
  if (uVar2 <= cbMultiByte) {
    return lpMultiByteStr;
  }
LAB_14000242c:
                    /* WARNING: Subroutine does not return */
  abort();
}

