// rea decompile_all
// name: FUN_140001f00
// address: 0x140001f00
// body: available
// range: 0x140001f00-0x140002135 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140001fda to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140001f00(wchar_t *param_1,LPCWSTR param_2,uint param_3,char param_4)

{
  wchar_t wVar1;
  int iVar2;
  HANDLE hObject;
  longlong lVar3;
  wchar_t *pwVar4;
  HMODULE hModule;
  FARPROC pFVar5;
  INT_PTR IVar6;
  WCHAR WVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  bool bVar10;
  
  if (param_4 == '\0') {
    WVar7 = *param_2;
    if (WVar7 != L'\0') {
      lVar3 = 0;
      do {
        if ((ulonglong)param_3 * 2 == lVar3) goto LAB_140001fda;
        *(WCHAR *)((longlong)param_1 + lVar3) = WVar7;
        WVar7 = *(WCHAR *)((longlong)param_2 + lVar3 + 2);
        lVar3 = lVar3 + 2;
      } while (WVar7 != L'\0');
      param_1 = (wchar_t *)((longlong)param_1 + lVar3);
    }
    *param_1 = L'\0';
    return;
  }
  hObject = CreateFileW(param_2,0,7,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  uVar9 = (ulonglong)param_3;
  WVar7 = *param_2;
  pwVar4 = param_1;
  if (WVar7 != L'\0') {
    lVar3 = 0;
    do {
      if (uVar9 * 2 == lVar3) goto LAB_140001fda;
      *(WCHAR *)((longlong)param_1 + lVar3) = WVar7;
      WVar7 = *(WCHAR *)((longlong)param_2 + lVar3 + 2);
      lVar3 = lVar3 + 2;
    } while (WVar7 != L'\0');
    pwVar4 = (wchar_t *)(lVar3 + (longlong)param_1);
  }
  *pwVar4 = L'\0';
  if (hObject == (HANDLE)0xffffffffffffffff) {
    return;
  }
  hModule = GetModuleHandleA("Kernel32.dll");
  pFVar5 = GetProcAddress(hModule,"GetFinalPathNameByHandleW");
  if (pFVar5 == (FARPROC)0x0) {
    CloseHandle(hObject);
  }
  else {
    IVar6 = (*pFVar5)(hObject,param_1,(ulonglong)param_3,0);
    CloseHandle(hObject);
    if (param_3 <= (uint)IVar6) {
LAB_140001fda:
                    /* WARNING: Subroutine does not return */
      abort();
    }
  }
  iVar2 = wcsncmp(param_1,L"\\\\?\\",4);
  if (iVar2 == 0) {
    iVar2 = wcscmp(param_1 + 4,param_2);
    pwVar4 = param_1;
    if (iVar2 == 0) {
      WVar7 = *param_2;
      if (WVar7 != L'\0') {
        lVar3 = 0;
        do {
          if (uVar9 * 2 == lVar3) goto LAB_140001fda;
          *(WCHAR *)((longlong)param_1 + lVar3) = WVar7;
          WVar7 = *(WCHAR *)((longlong)param_2 + lVar3 + 2);
          lVar3 = lVar3 + 2;
        } while (WVar7 != L'\0');
        pwVar4 = (wchar_t *)(lVar3 + (longlong)param_1);
      }
    }
    else {
      if (param_1[5] != L':') goto LAB_1400020d3;
      wVar1 = param_1[4];
      uVar8 = uVar9;
      while (wVar1 != L'\0') {
        bVar10 = uVar8 == 0;
        uVar8 = uVar8 - 1;
        if (bVar10) goto LAB_140001fda;
        *pwVar4 = wVar1;
        wVar1 = pwVar4[5];
        pwVar4 = pwVar4 + 1;
      }
    }
    *pwVar4 = L'\0';
  }
LAB_1400020d3:
  iVar2 = wcsncmp(param_1,L"\\\\?\\UNC\\",8);
  if (iVar2 == 0) {
    wVar1 = param_1[6];
    pwVar4 = param_1;
    while (wVar1 != L'\0') {
      bVar10 = uVar9 == 0;
      uVar9 = uVar9 - 1;
      if (bVar10) goto LAB_140001fda;
      *pwVar4 = wVar1;
      wVar1 = pwVar4[7];
      pwVar4 = pwVar4 + 1;
    }
    *pwVar4 = L'\0';
    *param_1 = L'\\';
  }
  return;
}

