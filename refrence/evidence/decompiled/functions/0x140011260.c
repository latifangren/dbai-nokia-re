// rea decompile_all
// name: FUN_140011260
// address: 0x140011260
// body: available
// range: 0x140011260-0x1400112c3 inclusive
// range: 0x1400112d0-0x14001133a inclusive
// range: 0x140011340-0x140011402 inclusive
// non_contiguous: true
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 FUN_140011260(undefined8 param_1,undefined4 param_2)

{
  DWORD *pDVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  LPVOID pvVar4;
  
  switch(param_2) {
  case 0:
    if (DAT_142c5c908 != 0) {
      EnterCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
      for (pDVar1 = DAT_142c5c950; pDVar1 != (DWORD *)0x0; pDVar1 = *(DWORD **)(pDVar1 + 4)) {
        pvVar4 = TlsGetValue(*pDVar1);
        DVar3 = GetLastError();
        if ((DVar3 == 0) && (pvVar4 != (LPVOID)0x0)) {
          (**(code **)(pDVar1 + 2))(pvVar4);
        }
      }
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
    }
    if (DAT_142c5c908 == 1) {
      DAT_142c5c908 = 1;
      pDVar1 = DAT_142c5c950;
      while (pDVar1 != (DWORD *)0x0) {
        pDVar2 = *(DWORD **)(pDVar1 + 4);
        free(pDVar1);
        pDVar1 = pDVar2;
      }
      DAT_142c5c950 = (DWORD *)0x0;
      DAT_142c5c908 = 0;
      DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
    }
    break;
  case 1:
    if (DAT_142c5c908 == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
    }
    DAT_142c5c908 = 1;
    break;
  case 2:
    FUN_140005230();
    break;
  case 3:
    if (DAT_142c5c908 != 0) {
      EnterCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
      for (pDVar1 = DAT_142c5c950; pDVar1 != (DWORD *)0x0; pDVar1 = *(DWORD **)(pDVar1 + 4)) {
        pvVar4 = TlsGetValue(*pDVar1);
        DVar3 = GetLastError();
        if ((DVar3 == 0) && (pvVar4 != (LPVOID)0x0)) {
          (**(code **)(pDVar1 + 2))(pvVar4);
        }
      }
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_142c5c8e0);
    }
  }
  return 1;
}

