// rea decompile_all
// name: FUN_1400033a0
// address: 0x1400033a0
// body: available
// range: 0x1400033a0-0x1400033f0 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x1400033ec to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400033a0(char *param_1,char param_2,ulonglong param_3)

{
  longlong lVar1;
  longlong lVar2;
  char local_22 [2];
  
  local_22[1] = 0;
  local_22[0] = param_2;
  lVar1 = FUN_140005900(local_22);
  lVar2 = FUN_140005900(param_1);
  if ((ulonglong)(lVar2 + lVar1) < param_3) {
    strcat(param_1,local_22);
    return;
  }
                    /* WARNING: Subroutine does not return */
  abort();
}

