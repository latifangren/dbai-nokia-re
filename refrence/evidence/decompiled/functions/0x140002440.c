// rea decompile_all
// name: FUN_140002440
// address: 0x140002440
// body: available
// range: 0x140002440-0x1400024da inclusive
// range: 0x1400024e0-0x140002659 inclusive
// range: 0x140002660-0x14000283b inclusive
// range: 0x140002840-0x14000305c inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x140003058 to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 FUN_140002440(wchar_t *param_1,ushort *param_2,longlong param_3)

{
  wchar_t *_Str1;
  undefined1 *puVar1;
  wint_t _C;
  undefined8 uVar2;
  bool bVar3;
  char cVar4;
  wchar_t wVar5;
  int iVar6;
  DWORD DVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  longlong lVar12;
  ulonglong uVar13;
  longlong lVar14;
  wchar_t *pwVar15;
  size_t sVar16;
  undefined8 *puVar17;
  wchar_t *pwVar18;
  wint_t *pwVar19;
  uint uVar20;
  wchar_t *pwVar21;
  longlong lVar22;
  uint uVar23;
  longlong lVar24;
  undefined8 uStack_48;
  
  uStack_48 = 0x140002456;
  lVar12 = FUN_140005b80();
  lVar12 = -lVar12;
  *param_1 = L'\0';
  uVar13 = (ulonglong)*param_2;
  if (*param_2 != 0) {
    _Str1 = (wchar_t *)(&stack0xfffffffffffffff0 + lVar12);
LAB_140002498:
    pwVar21 = (wchar_t *)0x0;
    while( true ) {
      param_2 = param_2 + 1;
      wVar5 = (wchar_t)uVar13;
      if (wVar5 != L'{') break;
      *(undefined2 *)(&stack0xfffffffffffffff0 + lVar12) = 0;
      pwVar21 = _Str1;
LAB_1400024a9:
      uVar13 = (ulonglong)*param_2;
      if (*param_2 == 0) goto LAB_140003039;
    }
    if ((int)uVar13 == 0x7d) {
      *(ushort **)(&stack0x00001058 + lVar12) = param_2;
      *pwVar21 = L'\0';
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400024f7;
      iVar6 = _wcsicmp(_Str1,(wchar_t *)"T");
      if (iVar6 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002690;
        GetTempPathW((DWORD)param_3,param_1);
        bVar3 = true;
        goto LAB_14000271c;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000250a;
      iVar6 = _wcsicmp(_Str1,L"PROGRAM");
      pwVar21 = param_1;
      if (iVar6 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400026a4;
        puVar17 = (undefined8 *)__p___wargv();
        pwVar15 = *(wchar_t **)*puVar17;
        if (pwVar15 == (wchar_t *)0x0) goto LAB_140003058;
        lVar14 = param_3;
        if (*param_1 != L'\0') {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400026ca;
          sVar16 = wcslen(param_1 + 1);
          pwVar21 = param_1 + sVar16 + 1;
          lVar14 = ~sVar16 + param_3;
        }
        wVar5 = *pwVar15;
        if (wVar5 == L'\0') goto LAB_140002714;
        lVar22 = 0;
        lVar24 = 0;
        goto LAB_1400026f0;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000251d;
      iVar6 = _wcsicmp(_Str1,L"PROGRAM_BASE");
      if (iVar6 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400027ad;
        sVar16 = wcslen(param_1);
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400027c2;
        cVar4 = FUN_140002440(param_1,L"{PROGRAM}",param_3 - sVar16);
        if (cVar4 == '\0') {
          return 0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400027d8;
        sVar16 = wcslen(param_1);
        if (3 < sVar16) {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400027fc;
          iVar6 = _wcsicmp(param_1 + (sVar16 - 4),L".exe");
          if (iVar6 == 0) {
            param_1[sVar16 - 4] = L'\0';
          }
        }
        goto LAB_140002719;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002534;
      iVar6 = _wcsicmp(_Str1,L"PROGRAM_DIR");
      if (iVar6 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002818;
        sVar16 = wcslen(param_1);
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000282d;
        cVar4 = FUN_140002440(param_1,L"{PROGRAM}",param_3 - sVar16);
        if (cVar4 == '\0') {
          return 0;
        }
        pwVar21 = (wchar_t *)0x0;
        for (pwVar15 = param_1;
            (pwVar18 = pwVar15, *pwVar15 == L'\\' || (pwVar18 = pwVar21, *pwVar15 != L'\0'));
            pwVar15 = pwVar15 + 1) {
          pwVar21 = pwVar18;
        }
        if (pwVar21 != (wchar_t *)0x0) {
          *pwVar21 = L'\0';
        }
        goto LAB_140002719;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000254b;
      iVar6 = _wcsicmp(_Str1,L"PID");
      if (iVar6 == 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000287e;
        pwVar19 = (wint_t *)FUN_1400015c0("NUITKA_ONEFILE_PARENT");
        if (pwVar19 == (wint_t *)0x0) {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002a6b;
          GetCurrentProcessId();
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002a89;
          FUN_140005830(&stack0x000007f0 + lVar12,0x80,&DAT_142c29440);
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002a97;
          FUN_140001640(param_1,&stack0x000007f0 + lVar12,param_3);
          goto LAB_140002719;
        }
        _C = *pwVar19;
        if (_C == 0) goto LAB_140003058;
        goto LAB_1400028a0;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002562;
      iVar6 = _wcsicmp(_Str1,L"HOME");
      if (iVar6 == 0) {
        *(undefined1 **)(&stack0xffffffffffffffe0 + lVar12) = &stack0x000007f0 + lVar12;
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002965;
        iVar6 = SHGetFolderPathW(0,0x28);
        if (iVar6 != 0) {
          return 0;
        }
        lVar14 = param_3;
        if (*param_1 != L'\0') {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002984;
          sVar16 = wcslen(param_1 + 1);
          pwVar21 = param_1 + sVar16 + 1;
          lVar14 = ~sVar16 + param_3;
        }
        wVar5 = *(wchar_t *)(&stack0x000007f0 + lVar12);
        if (wVar5 != L'\0') {
          lVar22 = 0;
          goto LAB_1400029b0;
        }
      }
      else {
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002579;
        iVar6 = _wcsicmp(_Str1,L"CACHE_DIR");
        if (iVar6 != 0) {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002590;
          iVar6 = _wcsicmp(_Str1,L"RANDOM");
          if (iVar6 == 0) {
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002ac4;
            lVar14 = FUN_1400015c0("NUITKA_ONEFILE_RANDOM");
            if (lVar14 == 0) {
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002c41;
              QueryPerformanceCounter((LARGE_INTEGER *)(&stack0x000007f0 + lVar12));
              uVar2 = *(undefined8 *)(&stack0x000007f0 + lVar12);
              *(ulonglong *)(&stack0x00001060 + lVar12) =
                   (ulonglong)((uint)uVar2 ^ (uint)(&stack0x000007f0 + lVar12));
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002c68;
              DVar7 = GetCurrentProcessId();
              uVar8 = DVar7 ^ *(uint *)(&stack0x00001060 + lVar12) ^
                      (uint)((ulonglong)uVar2 >> 0x20) ^
                      (uint)((ulonglong)(&stack0x000007f0 + lVar12) >> 0x20);
              uVar8 = uVar8 + (uVar8 == 0);
              uVar8 = uVar8 * 0x2000 ^ uVar8;
              uVar8 = uVar8 >> 0x11 ^ uVar8;
              uVar8 = uVar8 << 5 ^ uVar8;
              uVar9 = uVar8 << 0xd ^ uVar8;
              uVar9 = uVar9 >> 0x11 ^ uVar9;
              uVar9 = uVar9 << 5 ^ uVar9;
              uVar10 = uVar9 << 0xd ^ uVar9;
              uVar10 = uVar10 >> 0x11 ^ uVar10;
              uVar10 = uVar10 << 5 ^ uVar10;
              uVar11 = uVar10 << 0xd ^ uVar10;
              uVar11 = uVar11 >> 0x11 ^ uVar11;
              uVar11 = uVar11 << 5 ^ uVar11;
              uVar20 = uVar11 << 0xd ^ uVar11;
              uVar20 = uVar20 >> 0x11 ^ uVar20;
              uVar20 = uVar20 << 5 ^ uVar20;
              *(ulonglong *)(&stack0x00001060 + lVar12) = (ulonglong)uVar20;
              uVar20 = uVar20 << 0xd ^ uVar20;
              uVar20 = uVar20 >> 0x11 ^ uVar20;
              uVar20 = uVar20 << 5 ^ uVar20;
              *(ulonglong *)(&stack0x00000ff8 + lVar12) = (ulonglong)uVar20;
              uVar20 = uVar20 << 0xd ^ uVar20;
              uVar20 = uVar20 >> 0x11 ^ uVar20;
              uVar20 = uVar20 << 5 ^ uVar20;
              uVar23 = uVar20 << 0xd ^ uVar20;
              uVar23 = uVar23 >> 0x11 ^ uVar23;
              uVar23 = uVar23 << 5 ^ uVar23;
              *(wchar_t *)(&stack0x00001000 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)((byte)uVar8 >> 2)];
              *(wchar_t *)(&stack0x00001002 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)(((byte)uVar8 & 3) << 4 | (byte)uVar9 >> 4)];
              *(wchar_t *)(&stack0x00001004 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)((byte)uVar9 * '\x04' & 0x3f | (byte)uVar10 >> 6)];
              *(wchar_t *)(&stack0x00001006 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [uVar10 & 0x3f];
              *(wchar_t *)(&stack0x00001008 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)((byte)uVar11 >> 2)];
              *(wchar_t *)(&stack0x0000100a + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)(((byte)uVar11 & 3) << 4 |
                          (byte)(*(ulonglong *)(&stack0x00001060 + lVar12) >> 4) & 0xf)];
              *(wchar_t *)(&stack0x0000100c + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(char)*(ulonglong *)(&stack0x00001060 + lVar12) * '\x04' & 0x3fU |
                    (byte)((*(ulonglong *)(&stack0x00000ff8 + lVar12) & 0xffffffff) >> 6) & 3];
              *(wchar_t *)(&stack0x0000100e + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(uint)*(ulonglong *)(&stack0x00000ff8 + lVar12) & 0x3f];
              *(wchar_t *)(&stack0x00001010 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)((byte)uVar20 >> 2)];
              *(wchar_t *)(&stack0x00001012 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(byte)(((byte)uVar20 & 3) << 4 | (byte)(uVar23 >> 4) & 0xf)];
              *(wchar_t *)(&stack0x00001014 + lVar12) =
                   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   [(ulonglong)(byte)((char)uVar23 << 2) & 0x3c];
              *(undefined2 *)(&stack0x00001016 + lVar12) = 0;
              *(undefined2 *)(&stack0x000007f0 + lVar12) = 0;
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002ea5;
              FUN_140001640(&stack0x000007f0 + lVar12,"NUITKA_ONEFILE_RANDOM");
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002eb5;
              SetEnvironmentVariableW
                        ((LPCWSTR)(&stack0x000007f0 + lVar12),(LPCWSTR)(&stack0x00001000 + lVar12));
              lVar14 = param_3;
              if (*param_1 != L'\0') {
                *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002ecc;
                sVar16 = wcslen(param_1 + 1);
                pwVar21 = param_1 + sVar16 + 1;
                lVar14 = ~sVar16 + param_3;
              }
              wVar5 = *(wchar_t *)(&stack0x00001000 + lVar12);
              if (wVar5 == L'\0') goto LAB_140002714;
              lVar22 = 0;
              lVar24 = 0;
              goto LAB_140002ef3;
            }
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002ad5;
            pwVar15 = (wchar_t *)FUN_1400015c0("NUITKA_ONEFILE_RANDOM");
            if (pwVar15 == (wchar_t *)0x0) goto LAB_140003058;
            lVar14 = param_3;
            if (*param_1 != L'\0') {
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002af8;
              sVar16 = wcslen(param_1 + 1);
              pwVar21 = param_1 + sVar16 + 1;
              lVar14 = ~sVar16 + param_3;
            }
            wVar5 = *pwVar15;
            if (wVar5 == L'\0') goto LAB_140002714;
            lVar22 = 0;
            lVar24 = 0;
            goto LAB_140002b1d;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400025a7;
          iVar6 = _wcsicmp(_Str1,L"TIME_US");
          if (iVar6 == 0) {
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002b4f;
            lVar14 = FUN_1400015c0("NUITKA_ONEFILE_TIME_US");
            if (lVar14 == 0) {
              *(undefined8 *)(&stack0x00001050 + lVar12) = 0;
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002f34;
              GetSystemTimeAsFileTime((LPFILETIME)(&stack0x00001050 + lVar12));
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002f91;
              FUN_140005890(&stack0x000007f0 + lVar12,0x100,L"%06ld");
              *(undefined2 *)(&stack0x00001000 + lVar12) = 0;
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002fb6;
              FUN_140001640(&stack0x00001000 + lVar12,"NUITKA_ONEFILE_TIME_US");
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002fc6;
              SetEnvironmentVariableW
                        ((LPCWSTR)(&stack0x00001000 + lVar12),(LPCWSTR)(&stack0x000007f0 + lVar12));
              lVar14 = param_3;
              if (*param_1 != L'\0') {
                *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002fdd;
                sVar16 = wcslen(param_1 + 1);
                pwVar21 = param_1 + sVar16 + 1;
                lVar14 = ~sVar16 + param_3;
              }
              wVar5 = *(wchar_t *)(&stack0x000007f0 + lVar12);
              if (wVar5 == L'\0') goto LAB_140002714;
              lVar22 = 0;
              lVar24 = 0;
              goto LAB_140003000;
            }
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002b6a;
            pwVar15 = (wchar_t *)FUN_1400015c0("NUITKA_ONEFILE_TIME_US");
            if (pwVar15 == (wchar_t *)0x0) goto LAB_140003058;
            lVar14 = param_3;
            if (*param_1 != L'\0') {
              *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002b8d;
              sVar16 = wcslen(param_1 + 1);
              pwVar21 = param_1 + sVar16 + 1;
              lVar14 = ~sVar16 + param_3;
            }
            wVar5 = *pwVar15;
            if (wVar5 == L'\0') goto LAB_140002714;
            lVar22 = 0;
            lVar24 = 0;
            goto LAB_140002bb2;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400025be;
          iVar6 = _wcsicmp(_Str1,L"TIME");
          if (iVar6 != 0) {
            return 0;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400025db;
          lVar14 = FUN_1400015c0("NUITKA_ONEFILE_START");
          if (lVar14 == 0) {
            *(undefined8 *)(&stack0x00001000 + lVar12) = 0;
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002bf0;
            GetSystemTimeAsFileTime((LPFILETIME)(&stack0x00001000 + lVar12));
            puVar1 = &stack0x000007f0 + lVar12;
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002c12;
            FUN_140005890(puVar1,0x800,L"%lld");
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002c21;
            FUN_140001730("NUITKA_ONEFILE_START",puVar1);
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002c2f;
            FUN_140003060(param_1,puVar1,param_3);
            goto LAB_140002719;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400025ec;
          pwVar15 = (wchar_t *)FUN_1400015c0("NUITKA_ONEFILE_START");
          if (pwVar15 == (wchar_t *)0x0) goto LAB_140003058;
          lVar14 = param_3;
          if (*param_1 != L'\0') {
            *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000260f;
            sVar16 = wcslen(param_1 + 1);
            pwVar21 = param_1 + sVar16 + 1;
            lVar14 = ~sVar16 + param_3;
          }
          wVar5 = *pwVar15;
          if (wVar5 == L'\0') goto LAB_140002714;
          lVar22 = 0;
          lVar24 = 0;
          goto LAB_140002634;
        }
        *(undefined1 **)(&stack0xffffffffffffffe0 + lVar12) = &stack0x000007f0 + lVar12;
        *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400029f1;
        iVar6 = SHGetFolderPathW(0,0x1c);
        if (iVar6 != 0) {
          return 0;
        }
        lVar14 = param_3;
        if (*param_1 != L'\0') {
          *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x140002a10;
          sVar16 = wcslen(param_1 + 1);
          pwVar21 = param_1 + sVar16 + 1;
          lVar14 = ~sVar16 + param_3;
        }
        wVar5 = *(wchar_t *)(&stack0x000007f0 + lVar12);
        if (wVar5 != L'\0') {
          lVar22 = 0;
          goto LAB_140002a30;
        }
      }
      *pwVar21 = L'\0';
      bVar3 = true;
      goto LAB_14000271c;
    }
    if (pwVar21 != (wchar_t *)0x0) {
      *pwVar21 = wVar5;
      pwVar21 = pwVar21 + 1;
      goto LAB_1400024a9;
    }
    if (param_3 == 0) {
      return 0;
    }
    pwVar21 = param_1 + 1;
    *param_1 = wVar5;
    param_1[1] = L'\0';
    param_3 = param_3 + -1;
    goto LAB_140002791;
  }
LAB_140003039:
  *param_1 = L'\0';
  return CONCAT71((int7)(uVar13 >> 8),1);
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = pwVar15[lVar24 + 1];
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_1400026f0:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
  goto LAB_140002711;
  while (_C = *pwVar19, _C != 0) {
LAB_1400028a0:
    pwVar19 = pwVar19 + 1;
    *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400028aa;
    iVar6 = iswctype(_C,4);
    if (iVar6 == 0) goto LAB_140003058;
  }
  *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400028cc;
  pwVar15 = (wchar_t *)FUN_1400015c0("NUITKA_ONEFILE_PARENT");
  if (pwVar15 == (wchar_t *)0x0) {
LAB_140003058:
                    /* WARNING: Subroutine does not return */
    *(undefined **)((longlong)&uStack_48 + lVar12) = &UNK_14000305d;
    abort();
  }
  lVar14 = param_3;
  if (*param_1 != L'\0') {
    *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x1400028ef;
    sVar16 = wcslen(param_1 + 1);
    pwVar21 = param_1 + sVar16 + 1;
    lVar14 = ~sVar16 + param_3;
  }
  wVar5 = *pwVar15;
  if (wVar5 != L'\0') {
    lVar22 = 0;
    lVar24 = 0;
    do {
      if (lVar14 == lVar24) goto LAB_140003058;
      pwVar21[lVar24] = wVar5;
      wVar5 = pwVar15[lVar24 + 1];
      lVar24 = lVar24 + 1;
      lVar22 = lVar22 + -2;
    } while (wVar5 != L'\0');
    goto LAB_140002711;
  }
  goto LAB_140002714;
  while( true ) {
    pwVar21[lVar22] = wVar5;
    wVar5 = *(wchar_t *)(&stack0x000007f2 + lVar22 * 2 + lVar12);
    lVar22 = lVar22 + 1;
    if (wVar5 == L'\0') break;
LAB_1400029b0:
    if (lVar14 == lVar22) goto LAB_140003058;
  }
  goto LAB_140002a50;
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = *(wchar_t *)(&stack0x00001002 + lVar24 * 2 + lVar12);
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_140002ef3:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
  goto LAB_140002711;
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = pwVar15[lVar24 + 1];
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_140002b1d:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
  goto LAB_140002711;
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = *(wchar_t *)(&stack0x000007f2 + lVar24 * 2 + lVar12);
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_140003000:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
  goto LAB_140002711;
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = pwVar15[lVar24 + 1];
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_140002bb2:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
  goto LAB_140002711;
  while( true ) {
    pwVar21[lVar24] = wVar5;
    wVar5 = pwVar15[lVar24 + 1];
    lVar24 = lVar24 + 1;
    lVar22 = lVar22 + -2;
    if (wVar5 == L'\0') break;
LAB_140002634:
    if (lVar14 == lVar24) goto LAB_140003058;
  }
LAB_140002711:
  pwVar21 = (wchar_t *)((longlong)pwVar21 - lVar22);
LAB_140002714:
  *pwVar21 = L'\0';
LAB_140002719:
  bVar3 = false;
LAB_14000271c:
  pwVar21 = param_1;
  if (*param_1 != L'\0') {
    *(undefined8 *)((longlong)&uStack_48 + lVar12) = 0x14000272d;
    sVar16 = wcslen(param_1 + 1);
    pwVar21 = param_1 + sVar16 + 1;
    param_3 = param_3 + ~sVar16;
  }
  param_2 = *(ushort **)(&stack0x00001058 + lVar12);
  if (bVar3) {
    wVar5 = pwVar21[-1];
    while (wVar5 == L'\\') {
      pwVar21[-1] = L'\0';
      param_3 = param_3 + 1;
      wVar5 = pwVar21[-2];
      pwVar21 = pwVar21 + -1;
    }
  }
LAB_140002791:
  uVar13 = (ulonglong)*param_2;
  param_1 = pwVar21;
  if (*param_2 == 0) goto code_r0x0001400027a0;
  goto LAB_140002498;
  while( true ) {
    pwVar21[lVar22] = wVar5;
    wVar5 = *(wchar_t *)(&stack0x000007f2 + lVar22 * 2 + lVar12);
    lVar22 = lVar22 + 1;
    if (wVar5 == L'\0') break;
LAB_140002a30:
    if (lVar14 == lVar22) goto LAB_140003058;
  }
LAB_140002a50:
  pwVar21[lVar22] = L'\0';
  bVar3 = true;
  goto LAB_14000271c;
code_r0x0001400027a0:
  uVar13 = 0;
  goto LAB_140003039;
}

