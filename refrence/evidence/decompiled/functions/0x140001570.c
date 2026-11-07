// rea decompile_all
// name: FUN_140001570
// address: 0x140001570
// body: available
// range: 0x140001570-0x1400015be inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


wchar_t * FUN_140001570(LPCWSTR param_1)

{
  DWORD DVar1;
  longlong lVar2;
  wchar_t *pwVar3;
  WCHAR aWStackX_18 [8];
  undefined8 uStack_10;
  
  uStack_10 = 0x14000157b;
  lVar2 = FUN_140005b80();
  lVar2 = -lVar2;
  *(undefined2 *)((longlong)aWStackX_18 + lVar2) = 0;
  *(undefined8 *)((longlong)&uStack_10 + lVar2) = 0x14000159c;
  DVar1 = GetEnvironmentVariableW(param_1,(LPWSTR)((longlong)aWStackX_18 + lVar2),0x10000);
  if (DVar1 - 0x10001 < 0xffff0000) {
    pwVar3 = (wchar_t *)0x0;
  }
  else {
    *(undefined8 *)((longlong)&uStack_10 + lVar2) = 0x1400015b5;
    pwVar3 = _wcsdup((wchar_t *)((longlong)aWStackX_18 + lVar2));
  }
  return pwVar3;
}

