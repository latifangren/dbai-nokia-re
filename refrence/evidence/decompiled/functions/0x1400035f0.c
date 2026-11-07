// rea decompile_all
// name: FUN_1400035f0
// address: 0x1400035f0
// body: available
// range: 0x1400035f0-0x140003715 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_1400035f0(void)

{
  DWORD DVar1;
  int iVar2;
  _SHFILEOPSTRUCTW local_b8 [2];
  
  if (DAT_142c3a078 != (HANDLE)0x0) {
    DVar1 = WaitForSingleObject(DAT_142c3a078,5000);
    if (DVar1 != 0) {
      TerminateProcess(DAT_142c3a078,0);
    }
    CloseHandle(DAT_142c3a078);
  }
  if (DAT_142c3e090 == '\x01') {
    local_b8[0].lpszProgressTitle = L"";
    local_b8[0].fFlags = 0x414;
    local_b8[0]._34_2_ = 0;
    local_b8[0].fAnyOperationsAborted = 0;
    local_b8[0].hNameMappings = (LPVOID)0x0;
    local_b8[0].pFrom = &DAT_142c3a090;
    local_b8[0].pTo = L"";
    local_b8[0].hwnd = (HWND)0x0;
    local_b8[0].wFunc = 3;
    local_b8[0]._12_4_ = 0;
    SHFileOperationW(local_b8);
    iVar2 = 0x14;
    do {
      DVar1 = GetFileAttributesW(&DAT_142c3a090);
      if (DVar1 == 0xffffffff) {
        return;
      }
      if ((DVar1 & 0x10) == 0) {
        return;
      }
      Sleep(100);
      local_b8[0].lpszProgressTitle = L"";
      local_b8[0].fFlags = 0x414;
      local_b8[0]._34_2_ = 0;
      local_b8[0].fAnyOperationsAborted = 0;
      local_b8[0].hNameMappings = (LPVOID)0x0;
      local_b8[0].pFrom = &DAT_142c3a090;
      local_b8[0].pTo = L"";
      local_b8[0].hwnd = (HWND)0x0;
      local_b8[0].wFunc = 3;
      local_b8[0]._12_4_ = 0;
      SHFileOperationW(local_b8);
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return;
}

