// rea decompile_all
// name: FUN_1400017b0
// address: 0x1400017b0
// body: available
// range: 0x1400017b0-0x140001835 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400017b0(undefined8 param_1,undefined4 param_2)

{
  undefined1 local_1f8 [128];
  WCHAR local_178 [128];
  WCHAR local_78 [44];
  
  FUN_140005830(local_1f8,0x80,&DAT_142c29440,param_2);
  local_178[0] = L'\0';
  FUN_140001640(local_178,local_1f8,0x80);
  local_78[0] = L'\0';
  FUN_140001640(local_78,param_1,0x28);
  SetEnvironmentVariableW(local_78,local_178);
  return;
}

