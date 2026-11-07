// rea decompile_all
// name: FUN_140003150
// address: 0x140003150
// body: available
// range: 0x140003150-0x140003229 inclusive
// range: 0x140003230-0x1400032b3 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x1400032af to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined2 * FUN_140003150(void)

{
  longlong lVar1;
  undefined2 *puVar2;
  short *psVar3;
  longlong lVar4;
  short *psVar5;
  short sVar6;
  short *psVar7;
  
  if (DAT_142c38070 != 0) goto LAB_14000324d;
  psVar7 = DAT_142c30030;
  if (DAT_142c30030 == (short *)0x0) {
    if (DAT_142c400a0 == 0) {
      if (DAT_142c420a8 == (HMODULE)0x0) {
        GetModuleHandleExA(6,(LPCSTR)FUN_1400048b0,&DAT_142c420a8);
      }
      psVar7 = &DAT_142c400a0;
      GetModuleFileNameW(DAT_142c420a8,&DAT_142c400a0,0x1000);
      FUN_140002140(&DAT_142c400a0,0x1001);
      goto LAB_140003175;
    }
    psVar7 = &DAT_142c400a0;
    sVar6 = DAT_142c400a0;
LAB_1400031a0:
    lVar1 = 0;
    do {
      lVar4 = lVar1;
      if (lVar4 == 0x2000) {
                    /* WARNING: Subroutine does not return */
        abort();
      }
      *(short *)((longlong)&DAT_142c38070 + lVar4) = sVar6;
      sVar6 = *(short *)((longlong)psVar7 + lVar4 + 2);
      if (sVar6 == 0) {
        puVar2 = (undefined2 *)((longlong)&DAT_142c38072 + lVar4);
        goto LAB_14000321a;
      }
      *(short *)((longlong)&DAT_142c38072 + lVar4) = sVar6;
      sVar6 = *(short *)((longlong)psVar7 + lVar4 + 4);
      if (sVar6 == 0) {
        puVar2 = (undefined2 *)((longlong)&DAT_142c38074 + lVar4);
        goto LAB_14000321a;
      }
      *(short *)((longlong)&DAT_142c38074 + lVar4) = sVar6;
      sVar6 = *(short *)((longlong)psVar7 + lVar4 + 6);
      if (sVar6 == 0) {
        puVar2 = (undefined2 *)((longlong)&DAT_142c38076 + lVar4);
        goto LAB_14000321a;
      }
      *(short *)((longlong)&DAT_142c38076 + lVar4) = sVar6;
      sVar6 = *(short *)((longlong)psVar7 + lVar4 + 8);
      lVar1 = lVar4 + 8;
    } while (sVar6 != 0);
    puVar2 = (undefined2 *)((longlong)&DAT_142c38078 + lVar4);
  }
  else {
LAB_140003175:
    sVar6 = *psVar7;
    if (*psVar7 != 0) goto LAB_1400031a0;
    puVar2 = &DAT_142c38070;
  }
LAB_14000321a:
  *puVar2 = 0;
  psVar7 = (short *)0x0;
  for (psVar5 = &DAT_142c38070;
      (psVar3 = psVar5, *psVar5 == 0x5c || (psVar3 = psVar7, *psVar5 != 0)); psVar5 = psVar5 + 1) {
    psVar7 = psVar3;
  }
  if (psVar7 != (short *)0x0) {
    *psVar7 = 0;
  }
LAB_14000324d:
  return &DAT_142c38070;
}

