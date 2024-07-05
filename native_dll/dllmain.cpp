#include <windows.h>
#include <winternl.h>

extern "C" NTSTATUS NTAPI NtRaiseHardError(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters, 
    ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
    ULONG ValidResponseOptions, PULONG Response);

ULONG KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type)
{
    UNICODE_STRING uTitle = {  };
    UNICODE_STRING uText = {  };

    RtlInitUnicodeString(&uTitle, title);
    RtlInitUnicodeString(&uText, text);

    ULONG_PTR args[] = { (ULONG_PTR)&uText, (ULONG_PTR)&uTitle, type };
    ULONG response = 0;

    NtRaiseHardError(0x50000018, 3, 3, args, 2, &response);
    return response;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        KeMessageBox(L"x64 dll process attach", L"Hello world!", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

