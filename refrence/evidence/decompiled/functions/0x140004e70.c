// rea decompile_all
// name: tls_callback_0
// address: 0x140004e70
// body: available
// range: 0x140004e70-0x140004eb2 inclusive
// range: 0x140004ec0-0x140004ee5 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004ee1 to 0x140011260 FUN_140011260 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


/* WARNING: Removing unreachable block (ram,0x000140004ec9) */
/* WARNING: Removing unreachable block (ram,0x000140004ed1) */
/* WARNING: Removing unreachable block (ram,0x000140004ec0) */

void tls_callback_0(undefined8 param_1,int param_2)

{
  if (DAT_142c30010 != 2) {
    DAT_142c30010 = 2;
  }
  if (param_2 == 1) {
    FUN_140011260(param_1,1);
    return;
  }
  return;
}

