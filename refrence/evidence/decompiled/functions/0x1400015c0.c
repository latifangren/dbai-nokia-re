// rea decompile_all
// name: FUN_1400015c0
// address: 0x1400015c0
// body: available
// range: 0x1400015c0-0x140001634 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


wchar_t * FUN_1400015c0(undefined8 param_1)

{
  DWORD DVar1;
  longlong lVar2;
  wchar_t *pwVar3;
  WCHAR aWStackX_10 [12];
  undefined8 uStack_18;
  
  uStack_18 = 0x1400015cc;
  lVar2 = FUN_140005b80();
  lVar2 = -lVar2;
  *(undefined2 *)(&stack0x00010010 + lVar2) = 0;
  *(undefined8 *)((longlong)&uStack_18 + lVar2) = 0x1400015f8;
  FUN_140001640(&stack0x00010010 + lVar2,param_1,0x28);
  *(undefined2 *)((longlong)aWStackX_10 + lVar2) = 0;
  *(undefined8 *)((longlong)&uStack_18 + lVar2) = 0x140001611;
  DVar1 = GetEnvironmentVariableW
                    ((LPCWSTR)(&stack0x00010010 + lVar2),(LPWSTR)((longlong)aWStackX_10 + lVar2),
                     0x10000);
  if (DVar1 - 0x10001 < 0xffff0000) {
    pwVar3 = (wchar_t *)0x0;
  }
  else {
    *(undefined8 *)((longlong)&uStack_18 + lVar2) = 0x14000162a;
    pwVar3 = _wcsdup((wchar_t *)((longlong)aWStackX_10 + lVar2));
  }
  return pwVar3;
}

