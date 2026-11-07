// rea decompile_all
// name: FUN_1400052c0
// address: 0x1400052c0
// body: available
// range: 0x1400052c0-0x140005402 inclusive
// range: 0x140005410-0x14000549e inclusive
// range: 0x1400054a0-0x1400055b3 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000558f to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x14000559f to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x1400055af to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


/* WARNING: Removing unreachable block (ram,0x00014000533f) */
/* WARNING: Removing unreachable block (ram,0x000140005352) */
/* WARNING: Removing unreachable block (ram,0x00014000535e) */
/* WARNING: Removing unreachable block (ram,0x00014000536b) */
/* WARNING: Removing unreachable block (ram,0x00014000537a) */
/* WARNING: Removing unreachable block (ram,0x00014000537e) */
/* WARNING: Removing unreachable block (ram,0x000140005383) */
/* WARNING: Removing unreachable block (ram,0x000140005460) */
/* WARNING: Removing unreachable block (ram,0x0001400055a4) */
/* WARNING: Removing unreachable block (ram,0x00014000546c) */
/* WARNING: Removing unreachable block (ram,0x00014000547d) */
/* WARNING: Removing unreachable block (ram,0x0001400054ad) */
/* WARNING: Removing unreachable block (ram,0x0001400054c3) */
/* WARNING: Removing unreachable block (ram,0x0001400054ff) */
/* WARNING: Removing unreachable block (ram,0x0001400054ea) */
/* WARNING: Removing unreachable block (ram,0x000140005594) */
/* WARNING: Removing unreachable block (ram,0x000140005504) */
/* WARNING: Removing unreachable block (ram,0x0001400054da) */
/* WARNING: Removing unreachable block (ram,0x000140005513) */
/* WARNING: Removing unreachable block (ram,0x000140005517) */
/* WARNING: Removing unreachable block (ram,0x000140005529) */
/* WARNING: Removing unreachable block (ram,0x000140005536) */
/* WARNING: Removing unreachable block (ram,0x00014000557c) */
/* WARNING: Removing unreachable block (ram,0x000140005544) */
/* WARNING: Removing unreachable block (ram,0x00014000555d) */
/* WARNING: Removing unreachable block (ram,0x0001400054a0) */
/* WARNING: Removing unreachable block (ram,0x00014000538d) */
/* WARNING: Removing unreachable block (ram,0x000140005396) */
/* WARNING: Removing unreachable block (ram,0x0001400053b0) */
/* WARNING: Removing unreachable block (ram,0x0001400053de) */
/* WARNING: Removing unreachable block (ram,0x0001400053e8) */
/* WARNING: Removing unreachable block (ram,0x00014000541f) */
/* WARNING: Removing unreachable block (ram,0x000140005429) */
/* WARNING: Removing unreachable block (ram,0x000140005410) */
/* WARNING: Recovered jumptable eliminated as dead code */

void FUN_1400052c0(void)

{
  longlong lVar1;
  undefined1 auStack_58 [24];
  
  if (DAT_142c5c92c == '\0') {
    DAT_142c5c92c = '\x01';
    FUN_140011480();
    lVar1 = FUN_140005b80();
    DAT_142c5c978 = auStack_58 + -lVar1;
    DAT_142c5c968 = 0;
  }
  return;
}

