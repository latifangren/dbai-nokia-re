// rea decompile_all
// name: FUN_1400030f0
// address: 0x1400030f0
// body: available
// range: 0x1400030f0-0x140003142 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000313e to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400030f0(wint_t *param_1)

{
  wint_t _C;
  int iVar1;
  
  if ((param_1 != (wint_t *)0x0) && (_C = *param_1, _C != 0)) {
    while( true ) {
      param_1 = param_1 + 1;
      iVar1 = iswctype(_C,4);
      if (iVar1 == 0) break;
      _C = *param_1;
      if (_C == 0) {
        return;
      }
    }
  }
                    /* WARNING: Subroutine does not return */
  abort();
}

