// rea decompile_all
// name: FUN_140004ff0
// address: 0x140004ff0
// body: available
// range: 0x140004ff0-0x140005146 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 FUN_140004ff0(undefined8 *param_1)

{
  uint uVar1;
  bool bVar2;
  code *extraout_RAX;
  code *extraout_RAX_00;
  code *extraout_RAX_01;
  code *pcVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  
  uVar1 = *(uint *)*param_1;
  if (((uVar1 & 0x20ffffff) == 0x20474343) && ((((uint *)*param_1)[1] & 1) == 0)) {
    return 0xffffffff;
  }
  uVar5 = 0xffffffff;
  if ((int)uVar1 < -0x3fffffe3) {
    if (uVar1 == 0x80000002) {
      return 0xffffffff;
    }
    if (uVar1 != 0xc0000005) {
      if (uVar1 == 0xc0000008) {
        return 0xffffffff;
      }
      goto LAB_140005109;
    }
    signal(0xb);
    if (extraout_RAX_01 == (code *)0x0) goto LAB_140005109;
    if (extraout_RAX_01 == (code *)0x1) {
      signal(0xb);
      return 0xffffffff;
    }
    uVar4 = 0xb;
    pcVar3 = extraout_RAX_01;
    goto LAB_14000513a;
  }
  switch(uVar1) {
  case 0xc000008c:
  case 0xc0000092:
  case 0xc0000095:
    goto switchD_140005049_caseD_c000008c;
  case 0xc000008d:
  case 0xc000008e:
  case 0xc000008f:
  case 0xc0000090:
  case 0xc0000091:
  case 0xc0000093:
    bVar2 = false;
    break;
  case 0xc0000094:
    bVar2 = true;
    break;
  case 0xc0000096:
    goto switchD_140005049_caseD_c0000096;
  default:
    if (uVar1 != 0xc000001d) goto LAB_140005109;
switchD_140005049_caseD_c0000096:
    signal(4);
    if (extraout_RAX_00 == (code *)0x0) goto LAB_140005109;
    if (extraout_RAX_00 == (code *)0x1) {
      signal(4);
      return 0xffffffff;
    }
    uVar4 = 4;
    pcVar3 = extraout_RAX_00;
    goto LAB_14000513a;
  }
  signal(8);
  if (extraout_RAX == (code *)0x0) {
LAB_140005109:
    if (DAT_142c5c8d8 != (code *)0x0) {
                    /* WARNING: Could not recover jumptable at 0x000140005120. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar5 = (*DAT_142c5c8d8)(param_1);
      return uVar5;
    }
    uVar5 = 0;
  }
  else if (extraout_RAX == (code *)0x1) {
    signal(8);
    if (!bVar2) {
      FUN_140005230();
    }
  }
  else {
    uVar4 = 8;
    pcVar3 = extraout_RAX;
LAB_14000513a:
    (*pcVar3)(uVar4);
  }
switchD_140005049_caseD_c000008c:
  return uVar5;
}

