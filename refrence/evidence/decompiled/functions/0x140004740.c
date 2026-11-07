// rea decompile_all
// name: FUN_140004740
// address: 0x140004740
// body: available
// range: 0x140004740-0x140004877 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004873 to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140004740(short *param_1)

{
  char cVar1;
  longlong lVar2;
  longlong lVar3;
  size_t sVar4;
  wchar_t *pwVar5;
  short sVar6;
  undefined2 *puVar7;
  wchar_t wStackX_8;
  short asStackX_a [15];
  undefined8 uStack_20;
  
  uStack_20 = 0x14000474d;
  lVar2 = FUN_140005b80();
  lVar2 = -lVar2;
  puVar7 = (undefined2 *)((longlong)&wStackX_8 + lVar2);
  *(undefined8 *)((longlong)&uStack_20 + lVar2) = 0x14000476f;
  FUN_140005920(puVar7,0,0x2000);
  if (param_1 != (short *)0x0) {
    sVar6 = *param_1;
    if (sVar6 != 0) {
      lVar3 = 0;
      do {
        if (lVar3 == 0x2000) goto LAB_140004873;
        *(short *)((longlong)&wStackX_8 + lVar3 + lVar2) = sVar6;
        sVar6 = *(short *)((longlong)param_1 + lVar3 + 2);
        if (sVar6 == 0) {
          puVar7 = (undefined2 *)((longlong)asStackX_a + lVar3 + lVar2);
          goto LAB_140004802;
        }
        *(short *)((longlong)asStackX_a + lVar3 + lVar2) = sVar6;
        sVar6 = *(short *)((longlong)param_1 + lVar3 + 4);
        if (sVar6 == 0) {
          puVar7 = (undefined2 *)((longlong)asStackX_a + lVar3 + lVar2 + 2);
          goto LAB_140004802;
        }
        *(short *)((longlong)asStackX_a + lVar3 + lVar2 + 2) = sVar6;
        sVar6 = *(short *)((longlong)param_1 + lVar3 + 6);
        if (sVar6 == 0) {
          puVar7 = (undefined2 *)((longlong)asStackX_a + lVar3 + lVar2 + 4);
          goto LAB_140004802;
        }
        *(short *)((longlong)asStackX_a + lVar3 + lVar2 + 4) = sVar6;
        sVar6 = *(short *)((longlong)param_1 + lVar3 + 8);
        lVar3 = lVar3 + 8;
      } while (sVar6 != 0);
      puVar7 = (undefined2 *)((longlong)asStackX_a + lVar3 + lVar2 + -2);
    }
LAB_140004802:
    *puVar7 = 0;
    *(undefined8 *)((longlong)&uStack_20 + lVar2) = 0x140004813;
    sVar4 = wcslen((wchar_t *)((longlong)&wStackX_8 + lVar2));
    if (sVar4 != 0) {
      pwVar5 = (wchar_t *)((longlong)&wStackX_8 + sVar4 * 2 + lVar2);
      do {
        if (*pwVar5 == L'\\') {
          *pwVar5 = L'\0';
          *(undefined8 *)((longlong)&uStack_20 + lVar2) = 0x14000484f;
          cVar1 = FUN_1400048f0((longlong)&wStackX_8 + lVar2);
          if (cVar1 != '\0') {
            return;
          }
          *(undefined8 *)((longlong)&uStack_20 + lVar2) = 0x14000485f;
          FUN_140004740((longlong)&wStackX_8 + lVar2);
          *(undefined8 *)((longlong)&uStack_20 + lVar2) = 0x140004867;
          FUN_1400048f0((longlong)&wStackX_8 + lVar2);
          return;
        }
        pwVar5 = pwVar5 + -1;
      } while ((wchar_t *)((longlong)&wStackX_8 + lVar2) < pwVar5);
    }
    return;
  }
LAB_140004873:
                    /* WARNING: Subroutine does not return */
  *(undefined **)((longlong)&uStack_20 + lVar2) = &UNK_140004878;
  abort();
}

