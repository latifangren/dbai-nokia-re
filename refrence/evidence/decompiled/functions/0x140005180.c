// rea decompile_all
// name: FUN_140005180
// address: 0x140005180
// body: available
// range: 0x140005180-0x1400051ec inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8
FUN_140005180(undefined4 *param_1,undefined8 *param_2,undefined8 *param_3,int param_4,
             undefined4 *param_5)

{
  undefined4 *puVar1;
  undefined8 *puVar2;
  
  _initialize_wide_environment();
  _configure_wide_argv(2 - (uint)(param_4 == 0));
  puVar1 = (undefined4 *)__p___argc();
  *param_1 = *puVar1;
  puVar2 = (undefined8 *)__p___wargv();
  *param_2 = *puVar2;
  puVar2 = (undefined8 *)__p__wenviron();
  *param_3 = *puVar2;
  _set_new_mode(*param_5);
  return 0;
}

