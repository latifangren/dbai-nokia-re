// rea decompile_all
// name: FUN_140004f60
// address: 0x140004f60
// body: available
// range: 0x140004f60-0x140004fe1 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004fdd to 0x140004e50 FUN_140004e50 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140004f60(void)

{
  uint uVar1;
  uint uVar2;
  ulonglong uVar3;
  
  if (DAT_142c5c94c == '\0') {
    DAT_142c5c94c = 1;
    uVar2 = 0xffffffff;
    do {
      uVar1 = uVar2 + 2;
      uVar2 = uVar2 + 1;
    } while ((&DAT_142c2dc68)[uVar1] != 0);
    if (uVar2 != 0) {
      uVar3 = (ulonglong)uVar2;
      do {
        uVar3 = uVar3 - 1;
        (*(code *)(&DAT_142c2dc70)[uVar3])();
      } while ((int)uVar3 != 0);
    }
    FUN_140004e50(FUN_140004f10);
    return;
  }
  return;
}

