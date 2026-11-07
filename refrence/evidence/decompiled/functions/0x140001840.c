// rea decompile_all
// name: FUN_140001840
// address: 0x140001840
// body: available
// range: 0x140001840-0x1400018aa inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 FUN_140001840(wchar_t *param_1,long *param_2)

{
  long lVar1;
  int *piVar2;
  undefined8 uVar3;
  wchar_t *local_30;
  
  piVar2 = _errno();
  *piVar2 = 0;
  local_30 = (wchar_t *)0x0;
  lVar1 = wcstol(param_1,&local_30,10);
  piVar2 = _errno();
  if (((*piVar2 == 0x22) || (local_30 == param_1)) || (*local_30 != L'\0')) {
    uVar3 = 0;
  }
  else {
    *param_2 = lVar1;
    uVar3 = 1;
  }
  return uVar3;
}

