// rea decompile_all
// name: FUN_140001ce0
// address: 0x140001ce0
// body: available
// range: 0x140001ce0-0x140001dff inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


int FUN_140001ce0(LPCWSTR param_1)

{
  DWORD DVar1;
  int iVar2;
  HANDLE hFile;
  HANDLE hFileMappingObject;
  LPVOID lpBaseAddress;
  
  hFile = CreateFileW(param_1,0x80000000,7,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    GetLastError();
  }
  else {
    DVar1 = GetFileSize(hFile,(LPDWORD)0x0);
    if ((DVar1 == 0xffffffff) ||
       (hFileMappingObject = CreateFileMappingW(hFile,(LPSECURITY_ATTRIBUTES)0x0,2,0,0,(LPCWSTR)0x0)
       , hFileMappingObject == (HANDLE)0x0)) {
      GetLastError();
      CloseHandle(hFile);
    }
    else {
      lpBaseAddress = MapViewOfFile(hFileMappingObject,4,0,0,0);
      if (lpBaseAddress != (LPVOID)0x0) {
        iVar2 = FUN_140001020(lpBaseAddress,DVar1);
        UnmapViewOfFile(lpBaseAddress);
        CloseHandle(hFileMappingObject);
        CloseHandle(hFile);
        return iVar2 + (uint)(iVar2 == 0);
      }
      GetLastError();
      CloseHandle(hFileMappingObject);
      CloseHandle(hFile);
    }
  }
  return 0;
}

