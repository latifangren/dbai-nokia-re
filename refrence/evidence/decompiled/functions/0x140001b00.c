// rea decompile_all
// name: FUN_140001b00
// address: 0x140001b00
// body: available
// range: 0x140001b00-0x140001b37 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


bool FUN_140001b00(HANDLE param_1,LPVOID param_2,ulonglong param_3)

{
  BOOL BVar1;
  uint local_14;
  
  BVar1 = ReadFile(param_1,param_2,(DWORD)param_3,&local_14,(LPOVERLAPPED)0x0);
  return param_3 == local_14 && BVar1 != 0;
}

