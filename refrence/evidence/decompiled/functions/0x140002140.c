// rea decompile_all
// name: FUN_140002140
// address: 0x140002140
// body: available
// range: 0x140002140-0x14000215d inclusive
// range: 0x140002160-0x1400022c9 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x1400022b2 to 0x140011560 API-MS-WIN-CRT-HEAP-L1-1-0.DLL::free (external=false, thunk=true, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation.; Ghidra Listing reports a terminal call at 0x1400022c5 to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140002140(LPCWSTR param_1,longlong param_2)

{
  wchar_t wVar1;
  DWORD cchBuffer;
  DWORD DVar2;
  wchar_t *_Memory;
  LPWSTR lpszShortPath;
  longlong lVar3;
  LPCWSTR pWVar4;
  size_t sVar5;
  WCHAR WVar6;
  LPCWSTR pWVar7;
  LPCWSTR pWVar8;
  longlong lVar9;
  
  pWVar8 = (LPCWSTR)0x0;
  for (pWVar4 = param_1; (pWVar7 = pWVar4, *pWVar4 == L'\\' || (pWVar7 = pWVar8, *pWVar4 != L'\0'));
      pWVar4 = pWVar4 + 1) {
    pWVar8 = pWVar7;
  }
  if (pWVar8 == (LPCWSTR)0x0) {
    _Memory = (wchar_t *)0x0;
  }
  else {
    *pWVar8 = L'\0';
    _Memory = _wcsdup(pWVar8 + 1);
  }
  cchBuffer = GetShortPathNameW(param_1,(LPWSTR)0x0,0);
  if (cchBuffer != 0) {
    lpszShortPath = malloc((ulonglong)(cchBuffer + 1) * 2);
    DVar2 = GetShortPathNameW(param_1,lpszShortPath,cchBuffer);
    if ((cchBuffer < DVar2) || (*param_1 = L'\0', lpszShortPath == (LPWSTR)0x0)) goto LAB_1400022c5;
    WVar6 = *lpszShortPath;
    pWVar4 = param_1;
    if (WVar6 != L'\0') {
      lVar3 = 0;
      do {
        if (param_2 * 2 == lVar3) goto LAB_1400022c5;
        *(WCHAR *)((longlong)param_1 + lVar3) = WVar6;
        WVar6 = *(WCHAR *)((longlong)lpszShortPath + lVar3 + 2);
        lVar3 = lVar3 + 2;
      } while (WVar6 != L'\0');
      pWVar4 = (LPCWSTR)(lVar3 + (longlong)param_1);
    }
    *pWVar4 = L'\0';
    free(lpszShortPath);
  }
  if (_Memory == (wchar_t *)0x0) {
    return;
  }
  pWVar4 = param_1;
  if (*param_1 != L'\0') {
    sVar5 = wcslen(param_1 + 1);
    if (param_2 == sVar5 + 1) {
LAB_1400022c5:
                    /* WARNING: Subroutine does not return */
      abort();
    }
    pWVar4 = param_1 + sVar5 + 1;
  }
  pWVar4[0] = L'\\';
  pWVar4[1] = L'\0';
  if (*param_1 != L'\0') {
    sVar5 = wcslen(param_1 + 1);
    param_1 = param_1 + sVar5 + 1;
    param_2 = param_2 + ~sVar5;
  }
  wVar1 = *_Memory;
  if (wVar1 != L'\0') {
    lVar3 = 0;
    lVar9 = 0;
    do {
      if (param_2 == lVar9) goto LAB_1400022c5;
      param_1[lVar9] = wVar1;
      wVar1 = _Memory[lVar9 + 1];
      lVar9 = lVar9 + 1;
      lVar3 = lVar3 + -2;
    } while (wVar1 != L'\0');
    param_1 = (LPCWSTR)((longlong)param_1 - lVar3);
  }
  *param_1 = L'\0';
  free(_Memory);
  return;
}

