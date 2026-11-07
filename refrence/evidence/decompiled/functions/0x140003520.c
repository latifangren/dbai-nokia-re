// rea decompile_all
// name: FUN_140003520
// address: 0x140003520
// body: available
// range: 0x140003520-0x140003568 inclusive
// range: 0x140003570-0x1400035bf inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140003520(undefined8 param_1,DWORD param_2)

{
  char cVar1;
  DWORD DVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  longlong local_20;
  
  DVar2 = FormatMessageA(0x1300,(LPCVOID)0x0,param_2,0x409,(LPSTR)&local_20,0,(va_list *)0x0);
  if (DVar2 != 0) {
    uVar3 = (ulonglong)DVar2;
    do {
      cVar1 = *(char *)(local_20 + -1 + uVar3);
      if ((cVar1 != '\r') && (cVar1 != '\n')) break;
      *(undefined1 *)(local_20 + -1 + uVar3) = 0;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  uVar4 = __acrt_iob_func(2);
  FUN_1400057e0(uVar4,"%s ([Error %ld] %s)\n",param_1,param_2,local_20);
  return;
}

