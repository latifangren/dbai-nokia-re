// rea decompile_all
// name: FUN_1400048f0
// address: 0x1400048f0
// body: available
// range: 0x1400048f0-0x140004a1f inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004a1b to 0x140004700 FUN_140004700 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


bool FUN_1400048f0(wchar_t *param_1)

{
  char cVar1;
  int iVar2;
  BOOL BVar3;
  DWORD DVar4;
  longlong lVar5;
  size_t sVar6;
  wchar_t *pwVar7;
  longlong lVar8;
  ulonglong uVar9;
  bool bVar10;
  undefined8 uStack_30;
  
  uStack_30 = 0x140004900;
  lVar5 = FUN_140005b80();
  lVar5 = -lVar5;
  if (DAT_142c3a080 == 0) {
    *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x140004934;
    cVar1 = FUN_140002440(&stack0xfffffffffffffff8 + lVar5,L"{HOME}",0x1000);
    if (cVar1 == '\0') {
                    /* WARNING: Subroutine does not return */
      *(undefined **)((longlong)&uStack_30 + lVar5) = &UNK_140004a20;
      FUN_140004700(L"{HOME}");
    }
    *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x140004945;
    pwVar7 = _wcsdup((wchar_t *)(&stack0xfffffffffffffff8 + lVar5));
    (&DAT_142c428c0)[(int)DAT_142c3a080] = pwVar7;
    DAT_142c3a080 = DAT_142c3a080 + 1;
  }
  if (0 < (int)DAT_142c3a080) {
    uVar9 = (ulonglong)DAT_142c3a080;
    lVar8 = 0;
    do {
      pwVar7 = *(wchar_t **)((longlong)&DAT_142c428c0 + lVar8);
      *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x14000498c;
      iVar2 = wcscmp(param_1,pwVar7);
      if (iVar2 == 0) goto LAB_140004a04;
      lVar8 = lVar8 + 8;
    } while (uVar9 << 3 != lVar8);
  }
  *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x1400049a1;
  sVar6 = wcslen(param_1);
  if ((sVar6 != 2) || (bVar10 = true, param_1[1] != L':')) {
    *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x1400049bb;
    BVar3 = CreateDirectoryW(param_1,(LPSECURITY_ATTRIBUTES)0x0);
    bVar10 = true;
    if (BVar3 == 0) {
      *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x1400049c9;
      DVar4 = GetLastError();
      bVar10 = DVar4 == 0xb7;
    }
    if ((bVar10 != false) && ((int)DAT_142c3a080 < 0x400)) {
      *(undefined8 *)((longlong)&uStack_30 + lVar5) = 0x1400049e9;
      pwVar7 = _wcsdup(param_1);
      (&DAT_142c428c0)[(int)DAT_142c3a080] = pwVar7;
      DAT_142c3a080 = DAT_142c3a080 + 1;
LAB_140004a04:
      bVar10 = true;
    }
  }
  return bVar10;
}

