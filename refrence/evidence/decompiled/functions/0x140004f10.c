// rea decompile_all
// name: FUN_140004f10
// address: 0x140004f10
// body: available
// range: 0x140004f10-0x140004f52 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140004f10(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)*DAT_142c30008;
  while (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    pcVar1 = (code *)DAT_142c30008[1];
    DAT_142c30008 = DAT_142c30008 + 1;
  }
  return;
}

