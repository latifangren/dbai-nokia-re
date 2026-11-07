// rea decompile_all
// name: FUN_140004b70
// address: 0x140004b70
// body: available
// range: 0x140004b70-0x140004bc7 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004bc7 with no resolved callee; its no-return basis is unknown.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140004b70(void)

{
  code *pcVar1;
  int iVar2;
  undefined4 local_c;
  
  local_c = DAT_142c5c928;
  iVar2 = FUN_140005180(&DAT_142c5c934,&DAT_142c5c938,&DAT_142c5c940,DAT_142c5c920,&local_c);
  if (-1 < iVar2) {
    return;
  }
  FUN_1400051f0(8);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

