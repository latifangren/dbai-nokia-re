// rea decompile_all
// name: FUN_140005240
// address: 0x140005240
// body: available
// range: 0x140005240-0x1400052b0 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 FUN_140005240(int *param_1)

{
  undefined8 uVar1;
  char *pcVar2;
  
  if (*param_1 - 1U < 6) {
    pcVar2 = &DAT_142c2aa7c + *(int *)(&DAT_142c2aa7c + (ulonglong)(*param_1 - 1U) * 4);
  }
  else {
    pcVar2 = "Unknown error";
  }
  uVar1 = __acrt_iob_func(2);
  FUN_1400057e0(uVar1,"_matherr(): %s in %s(%g, %g)  (retval=%g)\n",pcVar2,
                *(undefined8 *)(param_1 + 2),*(undefined8 *)(param_1 + 4),
                *(undefined8 *)(param_1 + 6),*(undefined8 *)(param_1 + 8));
  return 0;
}

