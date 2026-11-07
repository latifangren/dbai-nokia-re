// rea decompile_all
// name: FUN_1400059a0
// address: 0x1400059a0
// body: available
// range: 0x1400059a0-0x140005b78 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400059a0(undefined8 *param_1,undefined8 *param_2,ulonglong param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  longlong lVar6;
  longlong lVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  
  if (0xf < param_3) {
    if (param_3 < 0x40) {
      uVar10 = (ulonglong)((uint)param_3 >> 1 & 0x10);
      lVar7 = (param_3 - 0x10) - uVar10;
      uVar3 = param_2[1];
      *param_1 = *param_2;
      param_1[1] = uVar3;
      uVar3 = ((undefined8 *)((longlong)param_2 + uVar10))[1];
      *(undefined8 *)((longlong)param_1 + uVar10) = *(undefined8 *)((longlong)param_2 + uVar10);
      ((undefined8 *)((longlong)param_1 + uVar10))[1] = uVar3;
      puVar1 = (undefined8 *)((longlong)param_2 + lVar7);
      uVar3 = puVar1[1];
      puVar2 = (undefined8 *)((longlong)param_1 + lVar7);
      *puVar2 = *puVar1;
      puVar2[1] = uVar3;
      param_2 = (undefined8 *)((longlong)param_2 + (param_3 - 0x10));
      uVar3 = param_2[1];
      param_1 = (undefined8 *)((longlong)param_1 + (param_3 - 0x10));
      *param_1 = *param_2;
      param_1[1] = uVar3;
      return;
    }
    uVar3 = param_2[1];
    uVar4 = param_2[2];
    uVar5 = param_2[3];
    *param_1 = *param_2;
    param_1[1] = uVar3;
    param_1[2] = uVar4;
    param_1[3] = uVar5;
    uVar10 = (ulonglong)((uint)param_2 & 0x1f);
    uVar8 = (uVar10 + param_3) - 0x20 >> 5;
    if (uVar8 - 1 < 7) {
      uVar9 = 0;
    }
    else {
      uVar9 = 0;
      lVar7 = -uVar10;
      do {
        lVar6 = lVar7 + 0x100;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0x20);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0x20);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0x40);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0x40);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0x60);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0x60);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0x80);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0x80);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0xa0);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0xa0);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0xc0);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0xc0);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar7 + 0xe0);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar7 + 0xe0);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        puVar1 = (undefined8 *)((longlong)param_2 + lVar6);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + lVar6);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        uVar9 = uVar9 + 8;
        lVar7 = lVar6;
      } while ((uVar8 & 0xfffffffffffffff8) != uVar9);
    }
    if ((uVar8 & 7) != 0) {
      lVar7 = uVar9 * 0x20 - uVar10;
      uVar10 = 0;
      do {
        puVar1 = (undefined8 *)((longlong)param_2 + uVar10 + lVar7 + 0x20);
        uVar3 = puVar1[1];
        uVar4 = puVar1[2];
        uVar5 = puVar1[3];
        puVar2 = (undefined8 *)((longlong)param_1 + uVar10 + lVar7 + 0x20);
        *puVar2 = *puVar1;
        puVar2[1] = uVar3;
        puVar2[2] = uVar4;
        puVar2[3] = uVar5;
        uVar10 = uVar10 + 0x20;
      } while (((uint)uVar8 & 7) << 5 != uVar10);
    }
    param_2 = (undefined8 *)((longlong)param_2 + (param_3 - 0x20));
    uVar3 = param_2[1];
    uVar4 = param_2[2];
    uVar5 = param_2[3];
    param_1 = (undefined8 *)((longlong)param_1 + (param_3 - 0x20));
    *param_1 = *param_2;
    param_1[1] = uVar3;
    param_1[2] = uVar4;
    param_1[3] = uVar5;
    return;
  }
  if (param_3 < 4) {
    if (param_3 != 0) {
      *(undefined1 *)param_1 = *(undefined1 *)param_2;
      *(undefined1 *)((longlong)param_1 + (param_3 >> 1)) =
           *(undefined1 *)((longlong)param_2 + (param_3 >> 1));
      *(undefined1 *)((longlong)param_1 + (param_3 - 1)) =
           *(undefined1 *)((longlong)param_2 + (param_3 - 1));
    }
    return;
  }
  uVar10 = (ulonglong)((uint)param_3 >> 1 & 4);
  lVar7 = (param_3 - 4) - uVar10;
  *(undefined4 *)param_1 = *(undefined4 *)param_2;
  *(undefined4 *)((longlong)param_1 + uVar10) = *(undefined4 *)((longlong)param_2 + uVar10);
  *(undefined4 *)((longlong)param_1 + lVar7) = *(undefined4 *)((longlong)param_2 + lVar7);
  *(undefined4 *)((longlong)param_1 + (param_3 - 4)) =
       *(undefined4 *)((longlong)param_2 + (param_3 - 4));
  return;
}

