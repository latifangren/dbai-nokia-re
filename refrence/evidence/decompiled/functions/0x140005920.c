// rea decompile_all
// name: FUN_140005920
// address: 0x140005920
// body: available
// range: 0x140005920-0x140005991 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140005920(longlong param_1,undefined1 param_2,ulonglong param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  if (param_3 != 0) {
    uVar2 = param_3;
    if ((param_3 & 7) != 0) {
      uVar1 = 0;
      do {
        *(undefined1 *)(param_1 + uVar1) = param_2;
        uVar1 = uVar1 + 1;
      } while ((param_3 & 7) != uVar1);
      uVar2 = param_3 - uVar1;
      param_1 = uVar1 + param_1;
    }
    if (7 < param_3) {
      uVar1 = 0;
      do {
        *(undefined1 *)(param_1 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 1 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 2 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 3 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 4 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 5 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 6 + uVar1) = param_2;
        *(undefined1 *)(param_1 + 7 + uVar1) = param_2;
        uVar1 = uVar1 + 8;
      } while (uVar2 != uVar1);
    }
  }
  return;
}

