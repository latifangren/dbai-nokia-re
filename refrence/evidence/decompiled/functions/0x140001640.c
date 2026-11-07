// rea decompile_all
// name: FUN_140001640
// address: 0x140001640
// body: available
// range: 0x140001640-0x140001723 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 1894bf6845e04e761d2362126ba24f9db4c4a1c4e9fe4a3bde506a90bf5eac94
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; Ghidra Listing reports a terminal call at 0x14000171f to 0x140011600 API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::abort (external=false, thunk=true, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


void FUN_140001640(wchar_t *param_1,char *param_2,longlong param_3)

{
  wchar_t *pwVar1;
  wchar_t wVar2;
  size_t sVar3;
  wchar_t *pwVar4;
  longlong lVar5;
  longlong lVar6;
  wchar_t *_Str;
  wchar_t local_46 [2];
  char local_42 [2];
  
  if (*param_1 != L'\0') {
    sVar3 = wcslen(param_1 + 1);
    param_1 = param_1 + sVar3 + 1;
    param_3 = param_3 + ~sVar3;
  }
  local_42[0] = *param_2;
  if (local_42[0] != '\0') {
    lVar6 = param_3;
    pwVar1 = param_1;
    do {
      _Str = pwVar1 + 1;
      lVar6 = lVar6 + -1;
      param_2 = param_2 + 1;
      local_42[1] = 0;
      sVar3 = mbstowcs(local_46,local_42,2);
      wVar2 = local_46[0];
      if (sVar3 != 1) {
LAB_14000171f:
                    /* WARNING: Subroutine does not return */
        abort();
      }
      pwVar4 = param_1;
      lVar5 = param_3;
      if (*pwVar1 != L'\0') {
        sVar3 = wcslen(_Str);
        pwVar4 = _Str + sVar3;
        lVar5 = lVar6 - sVar3;
      }
      if (lVar5 == 0) goto LAB_14000171f;
      *pwVar4 = wVar2;
      pwVar4[1] = L'\0';
      param_1 = param_1 + 1;
      param_3 = param_3 + -1;
      local_42[0] = *param_2;
      pwVar1 = _Str;
    } while (local_42[0] != '\0');
  }
  return;
}

