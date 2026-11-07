// rea decompile_all
// name: FUN_140004c00
// address: 0x140004c00
// body: available
// range: 0x140004c00-0x140004e12 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140004e0e to 0x140011610 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::exit (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


ulonglong FUN_140004c00(void)

{
  wchar_t *_Str;
  void *pvVar1;
  undefined8 uVar2;
  longlong lVar3;
  int iVar4;
  void *pvVar5;
  size_t sVar6;
  void *pvVar7;
  undefined8 *puVar8;
  ulonglong uVar9;
  longlong lVar10;
  longlong lVar11;
  longlong unaff_GS_OFFSET;
  bool bVar12;
  
  lVar11 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  lVar10 = 0;
  LOCK();
  bVar12 = DAT_142c5c910 == 0;
  lVar3 = lVar11;
  if (!bVar12) {
    lVar10 = DAT_142c5c910;
    lVar3 = DAT_142c5c910;
  }
  DAT_142c5c910 = lVar3;
  UNLOCK();
  if (lVar11 != lVar10 && !bVar12) {
    do {
      Sleep(1000);
      lVar10 = 0;
      LOCK();
      bVar12 = DAT_142c5c910 == 0;
      lVar3 = lVar11;
      if (!bVar12) {
        lVar10 = DAT_142c5c910;
        lVar3 = DAT_142c5c910;
      }
      DAT_142c5c910 = lVar3;
      UNLOCK();
    } while ((!bVar12) && (lVar11 != lVar10));
  }
  if (DAT_142c5c918 == 1) {
    uVar9 = FUN_1400051f0(0x1f);
  }
  else {
    if (DAT_142c5c918 == 0) {
      DAT_142c5c918 = 1;
      iVar4 = _initterm_e(&DAT_142c2dc30,&DAT_142c2dc40);
      if (iVar4 != 0) {
        return 0xff;
      }
    }
    else {
      DAT_142c5c948 = '\x01';
    }
    if (DAT_142c5c918 == 1) {
      _initterm(&DAT_142c2dc08,&DAT_142c2dc18);
      DAT_142c5c918 = 2;
    }
    if (bVar12) {
      LOCK();
      DAT_142c5c910 = 0;
      UNLOCK();
    }
    tls_callback_0(0,2,0);
    FUN_1400052c0();
    DAT_142c5c8d8 = SetUnhandledExceptionFilter(FUN_140004ff0);
    _set_invalid_parameter_handler(FUN_140004e60);
    FUN_140005230();
    lVar11 = (longlong)DAT_142c5c934;
    pvVar5 = malloc(lVar11 * 8 + 8);
    pvVar1 = DAT_142c5c938;
    if (lVar11 < 1) {
      lVar11 = 0;
    }
    else {
      lVar10 = 0;
      do {
        _Str = *(wchar_t **)((longlong)pvVar1 + lVar10 * 8);
        sVar6 = wcslen(_Str);
        sVar6 = sVar6 * 2 + 2;
        pvVar7 = malloc(sVar6);
        *(void **)((longlong)pvVar5 + lVar10 * 8) = pvVar7;
        FUN_1400059a0(pvVar7,_Str,sVar6);
        lVar10 = lVar10 + 1;
      } while (lVar11 != lVar10);
    }
    *(undefined8 *)((longlong)pvVar5 + lVar11 * 8) = 0;
    DAT_142c5c938 = pvVar5;
    FUN_140004f60();
    uVar2 = DAT_142c5c940;
    puVar8 = (undefined8 *)FUN_140005170();
    *puVar8 = uVar2;
    uVar9 = FUN_140003720(DAT_142c5c934,DAT_142c5c938,DAT_142c5c940);
    DAT_142c5c960 = (uint)uVar9;
    if (DAT_142c5c964 != 0) {
      if (DAT_142c5c948 == '\0') {
        _cexit();
        uVar9 = (ulonglong)DAT_142c5c960;
      }
      return uVar9;
    }
  }
                    /* WARNING: Subroutine does not return */
  exit((int)uVar9);
}

