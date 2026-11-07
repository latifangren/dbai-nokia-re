// rea decompile_all
// name: API-MS-WIN-CRT-CONVERT-L1-1-0.DLL::wcstol
// address: 0x140011550
// body: available
// range: 0x140011550-0x140011555 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


long __cdecl wcstol(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  long lVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140011550. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  lVar1 = wcstol(_Str,_EndPtr,_Radix);
  return lVar1;
}

