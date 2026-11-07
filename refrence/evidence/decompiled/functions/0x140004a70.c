// rea decompile_all
// name: FUN_140004a70
// address: 0x140004a70
// body: available
// range: 0x140004a70-0x140004b6f inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004b6f with no resolved callee; its no-return basis is unknown.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


/* WARNING: Removing unreachable block (ram,0x000140004b63) */
/* WARNING: Removing unreachable block (ram,0x000140004ad2) */
/* WARNING: Removing unreachable block (ram,0x000140004ada) */

undefined8 FUN_140004a70(void)

{
  code *pcVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  
  DAT_142c5c8c8 = 1;
  DAT_142c5c8cc = 1;
  DAT_142c5c8d0 = 1;
  DAT_142c5c964 = 0;
  _set_app_type(2 - (uint)(DAT_142c5c8c4 == 0));
  uVar2 = DAT_142c5c924;
  puVar4 = (undefined4 *)__p__fmode();
  *puVar4 = uVar2;
  uVar2 = DAT_142c5c91c;
  puVar4 = (undefined4 *)__p__commode();
  *puVar4 = uVar2;
  iVar3 = FUN_1400057d0();
  if (-1 < iVar3) {
    if (DAT_142c30000 == 1) {
      FUN_140005150(FUN_140005240);
    }
    return 0;
  }
  FUN_1400051f0(8);
  pcVar1 = (code *)swi(3);
  uVar5 = (*pcVar1)();
  return uVar5;
}

