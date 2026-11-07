// rea decompile_all
// name: FUN_1400018c0
// address: 0x1400018c0
// body: available
// range: 0x1400018c0-0x1400018c5 inclusive
// range: 0x1400018d0-0x1400018e1 inclusive
// range: 0x1400018f0-0x14000190d inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400018c0(short *param_1)

{
  short *psVar1;
  short *psVar2;
  
  do {
    if (*param_1 == 0x5c) {
      while (psVar2 = param_1, param_1[1] == 0x5c) {
        do {
          psVar1 = psVar2 + 1;
          *psVar2 = *psVar1;
          psVar2 = psVar2 + 1;
        } while (*psVar1 != 0);
      }
    }
    else if (*param_1 == 0) {
      return;
    }
    param_1 = param_1 + 1;
  } while( true );
}

