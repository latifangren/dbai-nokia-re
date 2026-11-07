// rea decompile_all
// name: FUN_140003720
// address: 0x140003720
// body: available
// range: 0x140003720-0x140003a57 inclusive
// range: 0x140003a60-0x140003f93 inclusive
// range: 0x140003fa0-0x1400041e8 inclusive
// range: 0x1400041f0-0x14000422c inclusive
// range: 0x140004230-0x140004240 inclusive
// range: 0x140004250-0x140004289 inclusive
// range: 0x140004290-0x1400042a6 inclusive
// range: 0x1400042b0-0x1400042e6 inclusive
// range: 0x1400042f0-0x14000431d inclusive
// range: 0x140004320-0x140004371 inclusive
// range: 0x140004380-0x1400046ef inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x1400045db to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x14000468c to 0x140004700 FUN_140004700 (external=false, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x1400046d5 to 0x140011610 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::exit (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Ghidra Listing reports a terminal call at 0x1400046eb to 0x140011610 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::exit (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


ulonglong FUN_140003720(undefined4 param_1,undefined8 param_2)

{
  LPCWSTR pWVar1;
  undefined8 *puVar2;
  LPCWSTR lpValue;
  char cVar3;
  wchar_t wVar4;
  DWORD DVar5;
  BOOL BVar6;
  longlong lVar7;
  wchar_t *pwVar8;
  int *piVar9;
  size_t sVar10;
  longlong lVar11;
  HANDLE pvVar12;
  HMODULE hModule;
  FARPROC pFVar13;
  undefined2 *puVar14;
  short *psVar15;
  LPWSTR lpCmdLine;
  LPWSTR *ppWVar16;
  wchar_t *pwVar17;
  short sVar18;
  short *psVar19;
  char *pcVar20;
  longlong lVar21;
  int iVar22;
  short *psVar23;
  uint uVar24;
  short sVar25;
  ulonglong uVar26;
  longlong lVar27;
  longlong lVar28;
  int iVar29;
  ulonglong uVar30;
  longlong lStackX_8;
  undefined8 uStackX_10;
  short asStackX_18 [4];
  undefined8 uStackX_20;
  undefined8 uStack_48;
  
  uStack_48 = 0x140003736;
  lVar7 = FUN_140005b80();
  lVar7 = -lVar7;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003754;
  SetDllDirectoryW(L"");
  *(undefined2 *)(&stack0x00010010 + lVar7) = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003779;
  FUN_140001640(&stack0x00010010 + lVar7,"NUITKA_ONEFILE_PARENT",0x28);
  *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003792;
  DVar5 = GetEnvironmentVariableW
                    ((LPCWSTR)(&stack0x00010010 + lVar7),(LPWSTR)((longlong)&uStackX_10 + lVar7),
                     0x10000);
  if (DVar5 - 0x10001 < 0xffff0000) {
LAB_1400037fa:
    *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
    pWVar1 = (LPCWSTR)((longlong)&uStackX_10 + lVar7);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003819;
    FUN_140001640(pWVar1,"NUITKA_ONEFILE_START",0x28);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003827;
    SetEnvironmentVariableW(pWVar1,(LPCWSTR)0x0);
    *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003842;
    FUN_140001640(pWVar1,"NUITKA_ONEFILE_TIME_US",0x28);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003849;
    SetEnvironmentVariableW(pWVar1,(LPCWSTR)0x0);
    *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003864;
    FUN_140001640(pWVar1,"NUITKA_ONEFILE_RANDOM",0x28);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000386b;
    SetEnvironmentVariableW(pWVar1,(LPCWSTR)0x0);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003871;
    GetCurrentProcessId();
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000388f;
    FUN_140005830(&stack0x00010010 + lVar7,0x80,&DAT_142c29440);
    *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400038aa;
    FUN_140001640((LPCWSTR)((longlong)&uStackX_10 + lVar7),&stack0x00010010 + lVar7,0x80);
    *(undefined2 *)(&stack0x00010090 + lVar7) = 0;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400038cf;
    FUN_140001640(&stack0x00010090 + lVar7,"NUITKA_ONEFILE_PARENT",0x28);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400038d7;
    BVar6 = SetEnvironmentVariableW
                      ((LPCWSTR)(&stack0x00010090 + lVar7),(LPCWSTR)((longlong)&uStackX_10 + lVar7))
    ;
    *(int *)(&stack0x000100f0 + lVar7) = (int)CONCAT71((uint7)(uint3)((uint)BVar6 >> 8),1);
  }
  else {
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400037a7;
    pwVar8 = _wcsdup((wchar_t *)((longlong)&uStackX_10 + lVar7));
    if ((pwVar8 == (wchar_t *)0x0) || (*pwVar8 == L'\0')) goto LAB_1400037fa;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400037be;
    piVar9 = _errno();
    *piVar9 = 0;
    *(undefined8 *)((longlong)&uStackX_10 + lVar7) = 0;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400037de;
    DVar5 = wcstol(pwVar8,(wchar_t **)((longlong)&uStackX_10 + lVar7),10);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400037e2;
    piVar9 = _errno();
    if ((*piVar9 == 0x22) ||
       ((*(wchar_t **)((longlong)&uStackX_10 + lVar7) == pwVar8 ||
        (**(wchar_t **)((longlong)&uStackX_10 + lVar7) != L'\0')))) goto LAB_1400037fa;
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000451b;
    pvVar12 = OpenProcess(0x410,0,DVar5);
    if (pvVar12 == (HANDLE)0x0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400045e8;
      CloseHandle((HANDLE)0x0);
      goto LAB_1400037fa;
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000453b;
    iVar29 = K32GetModuleFileNameExW(pvVar12,0,(longlong)&uStackX_10 + lVar7);
    if (iVar29 != 0) {
      lVar21 = (longlong)&uStackX_10 + lVar7;
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000455a;
      FUN_140001f00(lVar21,lVar21,0x800);
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004567;
      FUN_140002140(lVar21);
    }
    psVar23 = DAT_142c30030;
    if (DAT_142c34050 == 0) {
      if (DAT_142c30030 == (short *)0x0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004602;
        GetModuleFileNameW((HMODULE)0x0,&DAT_142c34050,0x1001);
      }
      else {
        sVar18 = *DAT_142c30030;
        if (sVar18 == 0) {
          psVar23 = &DAT_142c34050;
        }
        else {
          lVar21 = 0;
          do {
            lVar11 = lVar21;
            *(short *)((longlong)&DAT_142c34050 + lVar11) = sVar18;
            sVar18 = *(short *)((longlong)psVar23 + lVar11 + 2);
            if (sVar18 == 0) {
              psVar23 = (short *)((longlong)&DAT_142c34052 + lVar11);
              goto LAB_14000461d;
            }
            *(short *)((longlong)&DAT_142c34052 + lVar11) = sVar18;
            sVar18 = *(short *)((longlong)psVar23 + lVar11 + 4);
            if (sVar18 == 0) {
              psVar23 = (short *)((longlong)&DAT_142c34054 + lVar11);
              goto LAB_14000461d;
            }
            if (lVar11 == 0x1ffe) goto LAB_1400045db;
            *(short *)((longlong)&DAT_142c34054 + lVar11) = sVar18;
            sVar18 = *(short *)((longlong)psVar23 + lVar11 + 6);
            lVar21 = lVar11 + 6;
          } while (sVar18 != 0);
          psVar23 = (short *)((longlong)&DAT_142c34056 + lVar11);
        }
LAB_14000461d:
        *psVar23 = 0;
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000463d;
      FUN_140001f00(&DAT_142c34050,&DAT_142c34050,0x1001);
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000464a;
      FUN_140002140(&DAT_142c34050,0x1001);
    }
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000465a;
    iVar22 = wcscmp((wchar_t *)((longlong)&uStackX_10 + lVar7),&DAT_142c34050);
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004665;
    CloseHandle(pvVar12);
    if ((iVar29 == 0) || (iVar22 != 0)) goto LAB_1400037fa;
    *(undefined4 *)(&stack0x000100f0 + lVar7) = 0;
  }
  psVar23 = &DAT_142c3a090;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400038fb;
  cVar3 = FUN_140002440(&DAT_142c3a090,L"{TEMP}\\onefile_{PID}_{TIME_US}_{RANDOM}",0x1000);
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003913;
  DVar5 = GetFullPathNameW(&DAT_142c3a090,0x1000,(LPWSTR)((longlong)&uStackX_10 + lVar7),
                           (LPWSTR *)0x0);
  if (0xffe < DVar5 - 1) {
LAB_1400045db:
                    /* WARNING: Subroutine does not return */
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400045e0;
    abort();
  }
  sVar18 = *(short *)((longlong)&uStackX_10 + lVar7);
  if (sVar18 != 0) {
    lVar21 = 0;
    do {
      lVar11 = lVar21;
      if (lVar11 == 0x2000) goto LAB_1400045db;
      *(short *)((longlong)&DAT_142c3a090 + lVar11) = sVar18;
      sVar18 = *(short *)((longlong)&uStackX_10 + lVar11 + lVar7 + 2);
      if (sVar18 == 0) {
        psVar23 = (short *)((longlong)&DAT_142c3a092 + lVar11);
        goto LAB_1400039a9;
      }
      *(short *)((longlong)&DAT_142c3a092 + lVar11) = sVar18;
      sVar18 = *(short *)((longlong)&uStackX_10 + lVar11 + lVar7 + 4);
      if (sVar18 == 0) {
        psVar23 = (short *)((longlong)&DAT_142c3a094 + lVar11);
        goto LAB_1400039a9;
      }
      *(short *)((longlong)&DAT_142c3a094 + lVar11) = sVar18;
      sVar18 = *(short *)((longlong)&uStackX_10 + lVar11 + lVar7 + 6);
      if (sVar18 == 0) {
        psVar23 = (short *)((longlong)&DAT_142c3a096 + lVar11);
        goto LAB_1400039a9;
      }
      *(short *)((longlong)&DAT_142c3a096 + lVar11) = sVar18;
      sVar18 = *(short *)((longlong)asStackX_18 + lVar11 + lVar7);
      lVar21 = lVar11 + 8;
    } while (sVar18 != 0);
    psVar23 = (short *)((longlong)&DAT_142c3a098 + lVar11);
  }
LAB_1400039a9:
  *psVar23 = 0;
  DAT_142c420b0 = (short *)&DAT_140012000;
  if (cVar3 == '\0') {
                    /* WARNING: Subroutine does not return */
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004691;
    FUN_140004700(L"{TEMP}\\onefile_{PID}_{TIME_US}_{RANDOM}");
  }
  psVar23 = (short *)&DAT_140012000;
  if ((&stack0x000100f0)[lVar7] != '\0') {
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400039e0;
    BVar6 = SetConsoleCtrlHandler(FUN_1400035c0,1);
    psVar23 = DAT_142c420b0;
    if (BVar6 == 0) {
      pcVar20 = "Error, failed to register signal handler.";
      goto LAB_1400046e1;
    }
  }
  sVar18 = psVar23[1];
  DAT_142c420b0 = (short *)((longlong)psVar23 + 3);
  if (((char)*psVar23 == 'K') && (*(char *)((longlong)psVar23 + 1) == 'A')) {
    *(undefined4 *)(&stack0x000100e4 + lVar7) = param_1;
    *(undefined8 *)(&stack0x000100e8 + lVar7) = param_2;
    if ((char)sVar18 == 'X') {
      DAT_142c3e090 = 1;
      psVar23 = &DAT_142c420c0;
      do {
        do {
          psVar15 = DAT_142c420b0;
          sVar18 = *psVar15;
          DAT_142c420b0 = psVar15 + 1;
          *psVar23 = sVar18;
          sVar25 = DAT_142c420c0;
          psVar19 = DAT_142c30030;
          psVar23 = psVar23 + 1;
        } while (sVar18 != 0);
        if (DAT_142c420c0 == 0) {
          puVar2 = *(undefined8 **)(&stack0x000100e8 + lVar7);
          if (DAT_142c36060 != 0) goto LAB_140003f0d;
          if (DAT_142c30030 == (short *)0x0) {
            *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003e5a;
            GetModuleFileNameW((HMODULE)0x0,&DAT_142c36060,0x1001);
            goto LAB_140003e7a;
          }
          sVar18 = *DAT_142c30030;
          if (sVar18 != 0) {
            lVar21 = 0;
            goto LAB_140003d90;
          }
          psVar23 = &DAT_142c36060;
          goto LAB_140003e75;
        }
        DAT_142c3e0a0 = 0;
        psVar23 = &DAT_142c3e0a0;
        if (DAT_142c3a090 != 0) {
          lVar21 = 0;
          sVar18 = DAT_142c3a090;
          do {
            lVar11 = lVar21;
            if (lVar11 == 0x2000) goto LAB_1400045db;
            *(short *)((longlong)&DAT_142c3e0a0 + lVar11) = sVar18;
            if (*(short *)((longlong)&DAT_142c3a092 + lVar11) == 0) {
              psVar23 = (short *)(&DAT_142c3e0a2 + lVar11);
              goto LAB_140003b40;
            }
            *(short *)(&DAT_142c3e0a2 + lVar11) = *(short *)((longlong)&DAT_142c3a092 + lVar11);
            if (*(short *)((longlong)&DAT_142c3a094 + lVar11) == 0) {
              psVar23 = (short *)((longlong)&DAT_142c3e0a4 + lVar11);
              goto LAB_140003b40;
            }
            *(short *)((longlong)&DAT_142c3e0a4 + lVar11) =
                 *(short *)((longlong)&DAT_142c3a094 + lVar11);
            if (*(short *)((longlong)&DAT_142c3a096 + lVar11) == 0) {
              psVar23 = (short *)((longlong)&DAT_142c3e0a6 + lVar11);
              goto LAB_140003b40;
            }
            *(short *)((longlong)&DAT_142c3e0a6 + lVar11) =
                 *(short *)((longlong)&DAT_142c3a096 + lVar11);
            sVar18 = *(short *)((longlong)&DAT_142c3a098 + lVar11);
            lVar21 = lVar11 + 8;
          } while (sVar18 != 0);
          psVar23 = (short *)((longlong)&DAT_142c3e0a8 + lVar11);
        }
LAB_140003b40:
        *psVar23 = 0;
        psVar23 = &DAT_142c3e0a0;
        if (DAT_142c3e0a0 != 0) {
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003b5e;
          sVar10 = wcslen((wchar_t *)&DAT_142c3e0a2);
          if (sVar10 == 0xfff) goto LAB_1400045db;
          psVar23 = (short *)(&DAT_142c3e0a2 + sVar10 * 2);
        }
        psVar23[0] = 0x5c;
        psVar23[1] = 0;
        if (DAT_142c3e0a0 == 0) {
          lVar21 = 0x1000;
          psVar23 = &DAT_142c3e0a0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003b8e;
          sVar10 = wcslen((wchar_t *)&DAT_142c3e0a2);
          psVar23 = (short *)(&DAT_142c3e0a2 + sVar10 * 2);
          lVar21 = 0xfff - sVar10;
        }
        lVar11 = 0;
        do {
          if (lVar21 == lVar11) goto LAB_1400045db;
          psVar23[lVar11] = sVar25;
          sVar25 = (&DAT_142c420c2)[lVar11];
          lVar11 = lVar11 + 1;
        } while (sVar25 != 0);
        psVar23[lVar11] = 0;
        if (DAT_142c3c090 == 0) {
          psVar23 = &DAT_142c3c090;
          if (DAT_142c3e0a0 != 0) {
            lVar21 = 0;
            sVar18 = DAT_142c3e0a0;
            do {
              lVar11 = lVar21;
              if (lVar11 == 0x2000) goto LAB_1400045db;
              *(short *)((longlong)&DAT_142c3c090 + lVar11) = sVar18;
              if (*(short *)(&DAT_142c3e0a2 + lVar11) == 0) {
                psVar23 = (short *)((longlong)&DAT_142c3c092 + lVar11);
                goto LAB_140003c69;
              }
              *(short *)((longlong)&DAT_142c3c092 + lVar11) = *(short *)(&DAT_142c3e0a2 + lVar11);
              if (*(short *)((longlong)&DAT_142c3e0a4 + lVar11) == 0) {
                psVar23 = (short *)((longlong)&DAT_142c3c094 + lVar11);
                goto LAB_140003c69;
              }
              *(short *)((longlong)&DAT_142c3c094 + lVar11) =
                   *(short *)((longlong)&DAT_142c3e0a4 + lVar11);
              if (*(short *)((longlong)&DAT_142c3e0a6 + lVar11) == 0) {
                psVar23 = (short *)((longlong)&DAT_142c3c096 + lVar11);
                goto LAB_140003c69;
              }
              *(short *)((longlong)&DAT_142c3c096 + lVar11) =
                   *(short *)((longlong)&DAT_142c3e0a6 + lVar11);
              sVar18 = *(short *)((longlong)&DAT_142c3e0a8 + lVar11);
              lVar21 = lVar11 + 8;
            } while (sVar18 != 0);
            psVar23 = (short *)((longlong)&DAT_142c3c098 + lVar11);
          }
LAB_140003c69:
          *psVar23 = 0;
          if ((&stack0x000100f0)[lVar7] == '\0') {
            *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003df3;
            AddDllDirectory(&DAT_142c3a090);
            *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003e08;
            hModule = LoadLibraryExW(&DAT_142c3c090,(HANDLE)0x0,0xd00);
            if (hModule == (HMODULE)0x0) {
              *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400046c2;
              DVar5 = GetLastError();
              pcVar20 = "Error, load DLL.";
              goto LAB_1400046c9;
            }
            *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003e21;
            pFVar13 = GetProcAddress(hModule,"run_code");
            if (pFVar13 != (FARPROC)0x0) {
              *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003e40;
              uVar30 = (*pFVar13)((ulonglong)*(uint *)(&stack0x000100e4 + lVar7),
                                  *(undefined8 *)(&stack0x000100e8 + lVar7),&DAT_142c3c090);
              return uVar30;
            }
            pcVar20 = "Error, DLL entry point not found.";
            goto LAB_1400046e1;
          }
        }
        uVar30 = *(ulonglong *)(psVar15 + 1);
        DAT_142c420b0 = psVar15 + 5;
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003c92;
        FUN_140004740(&DAT_142c3e0a0);
        *(undefined8 *)(&stack0xfffffffffffffff0 + lVar7) = 0;
        *(undefined4 *)(&stack0xffffffffffffffe8 + lVar7) = 0;
        *(undefined4 *)(&stack0xffffffffffffffe0 + lVar7) = 2;
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003cc2;
        pvVar12 = CreateFileW(&DAT_142c3e0a0,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,
                              *(DWORD *)(&stack0xffffffffffffffe0 + lVar7),
                              *(DWORD *)(&stack0xffffffffffffffe8 + lVar7),
                              *(HANDLE *)(&stack0xfffffffffffffff0 + lVar7));
        psVar23 = DAT_142c420b0;
        if (pvVar12 == (HANDLE)0xffffffffffffffff) goto LAB_140004696;
        for (; DAT_142c420b0 = psVar23, uVar30 != 0; uVar30 = uVar30 - uVar26) {
          uVar26 = 0x8000;
          if (uVar30 < 0x8000) {
            uVar26 = uVar30;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003d05;
          FUN_1400059a0(&DAT_142c448c0,psVar23,uVar26);
          DAT_142c420b0 = (short *)((longlong)psVar23 + uVar26);
          *(undefined4 *)((longlong)&uStackX_10 + lVar7) = 0;
          *(undefined8 *)(&stack0xffffffffffffffe0 + lVar7) = 0;
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003d32;
          BVar6 = WriteFile(pvVar12,&DAT_142c448c0,(DWORD)uVar26,
                            (LPDWORD)((longlong)&uStackX_10 + lVar7),
                            *(LPOVERLAPPED *)(&stack0xffffffffffffffe0 + lVar7));
          if (BVar6 == 0) {
            *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004696;
            FUN_140004880();
            goto LAB_140004696;
          }
          psVar23 = DAT_142c420b0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003a69;
        CloseHandle(pvVar12);
        psVar23 = &DAT_142c420c0;
      } while( true );
    }
  }
  goto LAB_14000469b;
  while( true ) {
    if (lVar11 == 0x1ffe) goto LAB_1400045db;
    *(short *)((longlong)&DAT_142c36064 + lVar11) = sVar18;
    sVar18 = *(short *)((longlong)psVar19 + lVar11 + 6);
    lVar21 = lVar11 + 6;
    if (sVar18 == 0) break;
LAB_140003d90:
    lVar11 = lVar21;
    *(short *)((longlong)&DAT_142c36060 + lVar11) = sVar18;
    sVar18 = *(short *)((longlong)psVar19 + lVar11 + 2);
    if (sVar18 == 0) {
      psVar23 = (short *)((longlong)&DAT_142c36062 + lVar11);
      goto LAB_140003e75;
    }
    *(short *)((longlong)&DAT_142c36062 + lVar11) = sVar18;
    sVar18 = *(short *)((longlong)psVar19 + lVar11 + 4);
    if (sVar18 == 0) {
      psVar23 = (short *)((longlong)&DAT_142c36064 + lVar11);
      goto LAB_140003e75;
    }
  }
  psVar23 = (short *)((longlong)&DAT_142c36066 + lVar11);
LAB_140003e75:
  *psVar23 = 0;
LAB_140003e7a:
  if (DAT_142c36060 == 0) {
    psVar23 = &DAT_142c36060;
  }
  else {
    lVar21 = -0xfff;
    psVar19 = &DAT_142c36064;
    sVar18 = DAT_142c36060;
    do {
      psVar23 = psVar19;
      psVar23[-2] = sVar18;
      if (psVar23[-1] == 0) {
        psVar23 = psVar23 + -1;
        goto LAB_140003ee9;
      }
      psVar23[-1] = psVar23[-1];
      if (*psVar23 == 0) goto LAB_140003ee9;
      if (lVar21 == 0) goto LAB_1400045db;
      *psVar23 = *psVar23;
      sVar18 = psVar23[1];
      lVar21 = lVar21 + 3;
      psVar19 = psVar23 + 3;
    } while (sVar18 != 0);
    psVar23 = psVar23 + 1;
  }
LAB_140003ee9:
  *psVar23 = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003eff;
  FUN_140002140(&DAT_142c34050,0x1001);
  if (DAT_142c36060 == 0) {
    puVar14 = &DAT_142c30040;
  }
  else {
LAB_140003f0d:
    lVar21 = 0;
    sVar18 = DAT_142c36060;
    do {
      lVar11 = lVar21;
      *(short *)((longlong)&DAT_142c30040 + lVar11) = sVar18;
      if (*(short *)((longlong)&DAT_142c36062 + lVar11) == 0) {
        puVar14 = (undefined2 *)((longlong)&DAT_142c30042 + lVar11);
        goto LAB_140003f84;
      }
      *(short *)((longlong)&DAT_142c30042 + lVar11) = *(short *)((longlong)&DAT_142c36062 + lVar11);
      if (*(short *)((longlong)&DAT_142c36064 + lVar11) == 0) {
        puVar14 = (undefined2 *)((longlong)&DAT_142c30044 + lVar11);
        goto LAB_140003f84;
      }
      if (lVar11 == 0x1ffe) goto LAB_1400045db;
      *(short *)((longlong)&DAT_142c30044 + lVar11) = *(short *)((longlong)&DAT_142c36064 + lVar11);
      sVar18 = *(short *)((longlong)&DAT_142c36066 + lVar11);
      lVar21 = lVar11 + 6;
    } while (sVar18 != 0);
    puVar14 = (undefined2 *)((longlong)&DAT_142c30046 + lVar11);
  }
LAB_140003f84:
  *puVar14 = 0;
  psVar23 = (short *)0x0;
  for (psVar19 = &DAT_142c30040;
      (psVar15 = psVar19, *psVar19 == 0x5c || (psVar15 = psVar23, *psVar19 != 0));
      psVar19 = psVar19 + 1) {
    psVar23 = psVar15;
  }
  if (psVar23 != (short *)0x0) {
    *psVar23 = 0;
  }
  *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
  pWVar1 = (LPCWSTR)((longlong)&uStackX_10 + lVar7);
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003fdc;
  FUN_140001640(pWVar1,"NUITKA_ONEFILE_DIRECTORY",0x28);
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140003fef;
  SetEnvironmentVariableW(pWVar1,&DAT_142c30040);
  lpValue = (LPCWSTR)*puVar2;
  *(undefined2 *)((longlong)&uStackX_10 + lVar7) = 0;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000400d;
  FUN_140001640(pWVar1,"NUITKA_ORIGINAL_ARGV0");
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004015;
  SetEnvironmentVariableW(pWVar1,lpValue);
  if (DAT_142c32050 == 0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004034;
    DVar5 = GetModuleFileNameW((HMODULE)0x0,&DAT_142c32050,0x1000);
    if (DVar5 == 0) goto LAB_1400045db;
  }
  *(undefined8 *)(&stack0x00000040 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000048 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000050 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000058 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000030 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000038 + lVar7) = 0;
  *(undefined8 *)((longlong)&uStackX_20 + lVar7) = 0;
  *(undefined8 *)(&stack0x00000028 + lVar7) = 0;
  *(undefined8 *)((longlong)&uStackX_10 + lVar7) = 0;
  *(undefined8 *)((longlong)asStackX_18 + lVar7) = 0;
  *(undefined4 *)(&stack0x0000004c + lVar7) = 0x100;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004068;
  pvVar12 = GetStdHandle(0xfffffff6);
  *(HANDLE *)(&stack0x00000060 + lVar7) = pvVar12;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004073;
  pvVar12 = GetStdHandle(0xfffffff5);
  *(HANDLE *)(&stack0x00000068 + lVar7) = pvVar12;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000407e;
  pvVar12 = GetStdHandle(0xfffffff4);
  *(HANDLE *)(&stack0x00000070 + lVar7) = pvVar12;
  *(undefined4 *)((longlong)&uStackX_10 + lVar7) = 0x68;
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000408f;
  lpCmdLine = GetCommandLineW();
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000409f;
  ppWVar16 = CommandLineToArgvW(lpCmdLine,(int *)(&stack0x00010010 + lVar7));
  DAT_142c4c8c0 = 0;
  if (DAT_142c32050 != 0) {
LAB_1400040d2:
    *ppWVar16 = &DAT_142c32050;
    *(longlong *)(&stack0x000100f0 + lVar7) = (longlong)*(int *)(&stack0x00010010 + lVar7);
    if ((longlong)*(int *)(&stack0x00010010 + lVar7) < 1) {
LAB_14000442e:
      *(undefined1 **)((longlong)&lStackX_8 + lVar7) = &stack0x00010010 + lVar7;
      *(longlong *)(&stack0x00000000 + lVar7) = (longlong)&uStackX_10 + lVar7;
      *(undefined8 *)(&stack0xfffffffffffffff0 + lVar7) = 0;
      *(undefined8 *)(&stack0xfffffffffffffff8 + lVar7) = 0;
      *(undefined4 *)(&stack0xffffffffffffffe8 + lVar7) = 0x20;
      *(undefined4 *)(&stack0xffffffffffffffe0 + lVar7) = 1;
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004475;
      BVar6 = CreateProcessW(&DAT_142c32050,&DAT_142c4c8c0,(LPSECURITY_ATTRIBUTES)0x0,
                             (LPSECURITY_ATTRIBUTES)0x0,*(BOOL *)(&stack0xffffffffffffffe0 + lVar7),
                             *(DWORD *)(&stack0xffffffffffffffe8 + lVar7),
                             *(LPVOID *)(&stack0xfffffffffffffff0 + lVar7),
                             *(LPCWSTR *)(&stack0xfffffffffffffff8 + lVar7),
                             *(LPSTARTUPINFOW *)(&stack0x00000000 + lVar7),
                             *(LPPROCESS_INFORMATION *)((longlong)&lStackX_8 + lVar7));
      if (BVar6 != 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000448a;
        CloseHandle(*(HANDLE *)(&stack0x00010018 + lVar7));
        DAT_142c3a078 = *(HANDLE *)(&stack0x00010010 + lVar7);
        *(undefined4 *)(&stack0x00010090 + lVar7) = 0;
        if (DAT_142c3a078 != (HANDLE)0x0) {
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400044b2;
          WaitForSingleObject(DAT_142c3a078,0xffffffff);
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400044c6;
          BVar6 = GetExitCodeProcess(DAT_142c3a078,(LPDWORD)(&stack0x00010090 + lVar7));
          if (BVar6 == 0) {
            *(undefined4 *)(&stack0x00010090 + lVar7) = 1;
          }
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400044e1;
          CloseHandle(DAT_142c3a078);
          DAT_142c3a078 = (HANDLE)0x0;
        }
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400044f1;
        FUN_1400035f0();
        return (ulonglong)*(uint *)(&stack0x00010090 + lVar7);
      }
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400046aa;
      DVar5 = GetLastError();
      pcVar20 = "Error, couldn\'t launch child";
LAB_1400046c9:
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400046d0;
      FUN_140003520(pcVar20,DVar5);
                    /* WARNING: Subroutine does not return */
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400046da;
      exit(2);
    }
    lVar21 = 0;
    *(LPWSTR **)(&stack0x000100e8 + lVar7) = ppWVar16;
LAB_140004110:
    if (lVar21 != 0) {
      psVar23 = &DAT_142c4c8c0;
      if (DAT_142c4c8c0 != 0) {
        *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000412a;
        sVar10 = wcslen(&DAT_142c4c8c2);
        if (sVar10 == 0x7fff) goto LAB_1400045db;
        psVar23 = &DAT_142c4c8c2 + sVar10;
      }
      psVar23[0] = 0x20;
      psVar23[1] = 0;
    }
    pwVar8 = ppWVar16[lVar21];
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004154;
    pwVar17 = wcschr(pwVar8,L' ');
    if (pwVar17 == (wchar_t *)0x0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004165;
      pwVar17 = wcschr(pwVar8,L'\t');
      if (pwVar17 != (wchar_t *)0x0) goto LAB_1400041b0;
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004176;
      pwVar17 = wcschr(pwVar8,L'\n');
      if (pwVar17 != (wchar_t *)0x0) goto LAB_1400041b0;
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004187;
      pwVar17 = wcschr(pwVar8,L'\v');
      if (pwVar17 != (wchar_t *)0x0) goto LAB_1400041b0;
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004198;
      pwVar17 = wcschr(pwVar8,L'\"');
      if (pwVar17 != (wchar_t *)0x0) goto LAB_1400041b0;
      if (pwVar8 != (wchar_t *)0x0) {
        if (DAT_142c4c8c0 == 0) {
          lVar11 = 0x8000;
          psVar23 = &DAT_142c4c8c0;
        }
        else {
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400043d0;
          sVar10 = wcslen(&DAT_142c4c8c2);
          psVar23 = &DAT_142c4c8c2 + sVar10;
          lVar11 = 0x7fff - sVar10;
        }
        wVar4 = *pwVar8;
        if (wVar4 != L'\0') {
          lVar27 = 0;
          lVar28 = 0;
          do {
            if (lVar11 == lVar28) goto LAB_1400045db;
            psVar23[lVar28] = wVar4;
            wVar4 = pwVar8[lVar28 + 1];
            lVar28 = lVar28 + 1;
            lVar27 = lVar27 + -2;
          } while (wVar4 != L'\0');
          psVar23 = (short *)((longlong)psVar23 - lVar27);
        }
        *psVar23 = 0;
        goto LAB_14000435c;
      }
      goto LAB_1400045db;
    }
LAB_1400041b0:
    psVar23 = &DAT_142c4c8c0;
    if (DAT_142c4c8c0 != 0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400041c5;
      sVar10 = wcslen(&DAT_142c4c8c2);
      if (sVar10 == 0x7fff) goto LAB_1400045db;
      psVar23 = &DAT_142c4c8c2 + sVar10;
    }
    psVar23[0] = 0x22;
    psVar23[1] = 0;
LAB_14000420d:
    iVar22 = 0;
    iVar29 = 1;
    uVar24 = 0;
    for (; wVar4 = *pwVar8, wVar4 != L'\"'; pwVar8 = pwVar8 + 1) {
      if (wVar4 != L'\\') {
        if (wVar4 == L'\0') {
          if ((int)(uVar24 * 2) < 1) goto LAB_140004326;
          goto LAB_140004393;
        }
        if (0 < (int)uVar24) goto LAB_14000425f;
        goto LAB_1400042f0;
      }
      uVar24 = uVar24 + 1;
      iVar29 = iVar29 + 2;
      iVar22 = iVar22 + 2;
    }
    if ((uVar24 & 0x40000000) == 0) {
      if (iVar29 < 2) {
        iVar29 = 1;
      }
      do {
        psVar23 = &DAT_142c4c8c0;
        if (DAT_142c4c8c0 != 0) {
          *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400042d1;
          sVar10 = wcslen(&DAT_142c4c8c2);
          if (sVar10 == 0x7fff) goto LAB_1400045db;
          psVar23 = &DAT_142c4c8c2 + sVar10;
        }
        psVar23[0] = 0x5c;
        psVar23[1] = 0;
        iVar29 = iVar29 + -1;
      } while (iVar29 != 0);
    }
    goto LAB_1400042f0;
  }
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400040ca;
  DVar5 = GetModuleFileNameW((HMODULE)0x0,&DAT_142c32050,0x1000);
  if (DVar5 != 0) goto LAB_1400040d2;
  goto LAB_1400045db;
LAB_14000425f:
  do {
    psVar23 = &DAT_142c4c8c0;
    if (DAT_142c4c8c0 != 0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004274;
      sVar10 = wcslen(&DAT_142c4c8c2);
      if (sVar10 == 0x7fff) goto LAB_1400045db;
      psVar23 = &DAT_142c4c8c2 + sVar10;
    }
    psVar23[0] = 0x5c;
    psVar23[1] = 0;
    uVar24 = uVar24 - 1;
  } while (uVar24 != 0);
LAB_1400042f0:
  wVar4 = *pwVar8;
  pwVar17 = &DAT_142c4c8c0;
  if (DAT_142c4c8c0 != 0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000430d;
    sVar10 = wcslen(&DAT_142c4c8c2);
    if (sVar10 == 0x7fff) goto LAB_1400045db;
    pwVar17 = &DAT_142c4c8c2 + sVar10;
  }
  *pwVar17 = wVar4;
  pwVar17[1] = L'\0';
  pwVar8 = pwVar8 + 1;
  goto LAB_14000420d;
LAB_140004393:
  do {
    psVar23 = &DAT_142c4c8c0;
    if (DAT_142c4c8c0 != 0) {
      *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400043a8;
      sVar10 = wcslen(&DAT_142c4c8c2);
      if (sVar10 == 0x7fff) goto LAB_1400045db;
      psVar23 = &DAT_142c4c8c2 + sVar10;
    }
    psVar23[0] = 0x5c;
    psVar23[1] = 0;
    iVar22 = iVar22 + -1;
  } while (iVar22 != 0);
LAB_140004326:
  psVar23 = &DAT_142c4c8c0;
  ppWVar16 = *(LPWSTR **)(&stack0x000100e8 + lVar7);
  if (DAT_142c4c8c0 != 0) {
    *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x140004342;
    sVar10 = wcslen(&DAT_142c4c8c2);
    if (sVar10 == 0x7fff) goto LAB_1400045db;
    psVar23 = &DAT_142c4c8c2 + sVar10;
  }
  psVar23[0] = 0x22;
  psVar23[1] = 0;
LAB_14000435c:
  lVar21 = lVar21 + 1;
  if (lVar21 == *(longlong *)(&stack0x000100f0 + lVar7)) goto LAB_14000442e;
  goto LAB_140004110;
LAB_140004696:
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x14000469b;
  FUN_140004a30();
LAB_14000469b:
  pcVar20 = "Error, couldn\'t find attached data header.";
LAB_1400046e1:
  *(undefined8 *)((longlong)&uStack_48 + lVar7) = 0x1400046e6;
  puts(pcVar20);
                    /* WARNING: Subroutine does not return */
  *(undefined **)((longlong)&uStack_48 + lVar7) = &UNK_1400046f0;
  exit(2);
}

