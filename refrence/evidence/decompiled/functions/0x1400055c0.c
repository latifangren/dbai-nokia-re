// rea decompile_all
// name: FUN_1400055c0
// address: 0x1400055c0
// body: available
// range: 0x1400055c0-0x1400055fe inclusive
// range: 0x140005600-0x140005753 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000571b to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x14000573b to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x14000574f to 0x140005760 FUN_140005760 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400055c0(ulonglong param_1,undefined8 param_2,undefined8 param_3)

{
  PDWORD lpflOldProtect;
  ulonglong uVar1;
  longlong lVar2;
  BOOL BVar3;
  DWORD DVar4;
  longlong lVar5;
  SIZE_T SVar6;
  LPCVOID lpAddress;
  longlong lVar7;
  longlong lVar8;
  _MEMORY_BASIC_INFORMATION local_68;
  
  lVar8 = (longlong)DAT_142c5c968;
  if (lVar8 < 1) {
    lVar8 = 0;
  }
  else {
    lVar7 = 0;
    do {
      uVar1 = *(ulonglong *)(DAT_142c5c978 + 0x18 + lVar7);
      if ((uVar1 <= param_1) &&
         (param_1 < uVar1 + *(uint *)(*(longlong *)(DAT_142c5c978 + 0x20 + lVar7) + 8)))
      goto LAB_1400056f3;
      lVar7 = lVar7 + 0x28;
    } while (lVar8 * 0x28 != lVar7);
  }
  lVar5 = FUN_140011410(param_1);
  lVar7 = DAT_142c5c978;
  if (lVar5 == 0) {
                    /* WARNING: Subroutine does not return */
    FUN_140005760("Address %p has no image-section",param_1);
  }
  lVar2 = lVar8 * 0x28;
  *(longlong *)(DAT_142c5c978 + 0x20 + lVar2) = lVar5;
  *(undefined4 *)(lVar7 + lVar2) = 0;
  lVar7 = FUN_1400114c0();
  lpAddress = (LPCVOID)((ulonglong)*(uint *)(lVar5 + 0xc) + lVar7);
  *(LPCVOID *)(DAT_142c5c978 + 0x18 + lVar2) = lpAddress;
  SVar6 = VirtualQuery(lpAddress,&local_68,0x30);
  lVar7 = DAT_142c5c978;
  if (SVar6 == 0) {
                    /* WARNING: Subroutine does not return */
    FUN_140005760("  VirtualQuery failed for %d bytes at address %p",*(undefined4 *)(lVar5 + 8),
                  *(undefined8 *)(DAT_142c5c978 + 0x18 + lVar8 * 0x28));
  }
  if ((int)local_68.Protect < 8) {
    DVar4 = 4;
    if (local_68.Protect != 2) {
      if (local_68.Protect == 4) goto LAB_1400056ed;
      goto LAB_1400056bc;
    }
  }
  else {
    if (((local_68.Protect == 8) || (local_68.Protect == 0x40)) || (local_68.Protect == 0x80))
    goto LAB_1400056ed;
LAB_1400056bc:
    DVar4 = 0x40;
  }
  lpflOldProtect = (PDWORD)(DAT_142c5c978 + lVar8 * 0x28);
  *(PVOID *)(DAT_142c5c978 + 8 + lVar8 * 0x28) = local_68.BaseAddress;
  *(SIZE_T *)(lVar7 + 0x10 + lVar8 * 0x28) = local_68.RegionSize;
  BVar3 = VirtualProtect(local_68.BaseAddress,local_68.RegionSize,DVar4,lpflOldProtect);
  if (BVar3 == 0) {
    DVar4 = GetLastError();
                    /* WARNING: Subroutine does not return */
    FUN_140005760("  VirtualProtect failed with code 0x%x",DVar4);
  }
LAB_1400056ed:
  DAT_142c5c968 = DAT_142c5c968 + 1;
LAB_1400056f3:
  FUN_1400059a0(param_1,param_2,param_3);
  return;
}

