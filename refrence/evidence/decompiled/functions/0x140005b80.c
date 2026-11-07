// rea decompile_all
// name: FUN_140005b80
// address: 0x140005b80
// body: available
// range: 0x140005b80-0x140005baf inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


ulonglong FUN_140005b80(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  
  uVar1 = in_RAX;
  if (0xfff < in_RAX) {
    do {
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  return in_RAX;
}

