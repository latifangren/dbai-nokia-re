// rea decompile_all
// name: FUN_140001020
// address: 0x140001020
// body: available
// range: 0x140001020-0x140001562 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


uint FUN_140001020(uint *param_1,uint param_2)

{
  byte *pbVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  uint *puVar7;
  longlong lVar8;
  uint *puVar9;
  uint uVar10;
  ulonglong uVar11;
  
  if (param_1 == (uint *)0x0) {
    uVar6 = 0;
  }
  else {
    uVar11 = (ulonglong)param_2;
    uVar6 = 0xffffffff;
    if (0x16 < param_2) {
      if (((ulonglong)param_1 & 3) == 0) {
        uVar6 = 0xffffffff;
        puVar7 = param_1;
        uVar5 = uVar11;
      }
      else {
        uVar6 = *(uint *)(&DAT_142c29040 + (ulonglong)((byte)*param_1 ^ 0xff) * 4) ^ 0xffffff;
        puVar7 = (uint *)((longlong)param_1 + 1);
        uVar5 = uVar11 - 1;
        if (((ulonglong)puVar7 & 3) != 0 && uVar5 != 0) {
          uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 +
                           (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 1)) * 4);
          puVar7 = (uint *)((longlong)param_1 + 2);
          uVar5 = uVar11 - 2;
          if (((ulonglong)puVar7 & 3) != 0 && uVar5 != 0) {
            uVar6 = uVar6 >> 8 ^
                    *(uint *)(&DAT_142c29040 +
                             (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 2)) * 4);
            puVar7 = (uint *)((longlong)param_1 + 3);
            uVar5 = uVar11 - 3;
            if (((ulonglong)puVar7 & 3) != 0 && uVar5 != 0) {
              uVar6 = uVar6 >> 8 ^
                      *(uint *)(&DAT_142c29040 +
                               (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 3)) * 4
                               );
              puVar7 = param_1 + 1;
              uVar5 = uVar11 - 4;
            }
          }
        }
      }
      lVar8 = uVar5 / 0x14 - 1;
      if (lVar8 == 0) {
        uVar4 = 0;
        uVar2 = 0;
        uVar3 = 0;
        uVar10 = 0;
      }
      else {
        uVar10 = 0;
        uVar3 = 0;
        uVar2 = 0;
        uVar4 = 0;
        puVar9 = puVar7;
        do {
          uVar6 = uVar6 ^ *puVar9;
          uVar2 = uVar2 ^ puVar9[1];
          uVar4 = uVar4 ^ puVar9[2];
          uVar3 = uVar3 ^ puVar9[3];
          uVar10 = uVar10 ^ puVar9[4];
          uVar6 = *(uint *)(&DAT_142c29a50 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29650 + (ulonglong)(uVar6 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29e50 + (uVar6 >> 0xe & 0x3fc)) ^
                  *(uint *)(&DAT_142c2a250 + (ulonglong)(uVar6 >> 0x18) * 4);
          uVar2 = *(uint *)(&DAT_142c29a50 + (ulonglong)(uVar2 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29650 + (ulonglong)(uVar2 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29e50 + (uVar2 >> 0xe & 0x3fc)) ^
                  *(uint *)(&DAT_142c2a250 + (ulonglong)(uVar2 >> 0x18) * 4);
          uVar4 = *(uint *)(&DAT_142c29a50 + (ulonglong)(uVar4 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29650 + (ulonglong)(uVar4 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29e50 + (uVar4 >> 0xe & 0x3fc)) ^
                  *(uint *)(&DAT_142c2a250 + (ulonglong)(uVar4 >> 0x18) * 4);
          uVar3 = *(uint *)(&DAT_142c29a50 + (ulonglong)(uVar3 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29650 + (ulonglong)(uVar3 & 0xff) * 4) ^
                  *(uint *)(&DAT_142c29e50 + (uVar3 >> 0xe & 0x3fc)) ^
                  *(uint *)(&DAT_142c2a250 + (ulonglong)(uVar3 >> 0x18) * 4);
          uVar10 = *(uint *)(&DAT_142c29a50 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_142c29650 + (ulonglong)(uVar10 & 0xff) * 4) ^
                   *(uint *)(&DAT_142c29e50 + (uVar10 >> 0xe & 0x3fc)) ^
                   *(uint *)(&DAT_142c2a250 + (ulonglong)(uVar10 >> 0x18) * 4);
          puVar9 = puVar9 + 5;
          lVar8 = lVar8 + -1;
        } while (lVar8 != 0);
        puVar7 = puVar7 + (uVar5 / 0x14) * 5 + -5;
      }
      uVar6 = (uVar6 ^ *puVar7) >> 8 ^
              *(uint *)(&DAT_142c29040 + (ulonglong)((uVar6 ^ *puVar7) & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar2 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4) ^ puVar7[1] ^
              uVar6 >> 8;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar4 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4) ^ puVar7[2] ^
              uVar6 >> 8;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar3 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4) ^ puVar7[3] ^
              uVar6 >> 8;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar10 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4) ^ puVar7[4] ^
              uVar6 >> 8;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar11 = uVar5 % 0x14;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(uVar6 & 0xff) * 4);
      param_1 = puVar7 + 5;
    }
    for (; 7 < uVar11; uVar11 = uVar11 - 8) {
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 + (ulonglong)(byte)((byte)uVar6 ^ (byte)*param_1) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 1)) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 2)) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 3)) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 + (ulonglong)(byte)((byte)uVar6 ^ (byte)param_1[1]) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 5)) * 4);
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 6)) * 4);
      pbVar1 = (byte *)((longlong)param_1 + 7);
      param_1 = param_1 + 2;
      uVar6 = uVar6 >> 8 ^ *(uint *)(&DAT_142c29040 + (ulonglong)(byte)((byte)uVar6 ^ *pbVar1) * 4);
    }
    if ((((uVar11 != 0) &&
         (uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 + (ulonglong)(byte)((byte)uVar6 ^ (byte)*param_1) * 4),
         uVar11 != 1)) &&
        (uVar6 = uVar6 >> 8 ^
                 *(uint *)(&DAT_142c29040 +
                          (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 1)) * 4),
        uVar11 != 2)) &&
       (((uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 +
                           (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 2)) * 4),
         uVar11 != 3 &&
         (uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 +
                           (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 3)) * 4),
         uVar11 != 4)) &&
        ((uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 + (ulonglong)(byte)((byte)uVar6 ^ (byte)param_1[1]) * 4),
         uVar11 != 5 &&
         (uVar6 = uVar6 >> 8 ^
                  *(uint *)(&DAT_142c29040 +
                           (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 5)) * 4),
         uVar11 != 6)))))) {
      uVar6 = uVar6 >> 8 ^
              *(uint *)(&DAT_142c29040 +
                       (ulonglong)(byte)((byte)uVar6 ^ *(byte *)((longlong)param_1 + 6)) * 4);
    }
    uVar6 = ~uVar6;
  }
  return uVar6;
}

