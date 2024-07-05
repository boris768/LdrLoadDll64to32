#include <iostream>
#include <fstream>
#include <Windows.h>
#include <winternl.h>

using LdrLoadDll_t = NTSTATUS(NTAPI *)(PWSTR SearchPath, PULONG LoadFlags, PUNICODE_STRING Name, PVOID *BaseAddress);
using RtlInitUnicodeString_t = void(NTAPI *)(PUNICODE_STRING UnicodeString, PCWSTR SourceString);

struct shellcode_context
{
	LdrLoadDll_t LdrLoadDll;
	RtlInitUnicodeString_t RtlInitUnicodeString;
	UNICODE_STRING dll_path;
	wchar_t path_buffer[MAX_PATH];
};

HANDLE WINAPI shellcode(shellcode_context* data);
DWORD WINAPI shellcode_end();

inline bool is_file_exists (const wchar_t * name)
{
	std::ifstream stream(name);
    return stream.good();
}

int wmain(int argument_count, wchar_t** arguments)
{
	if(argument_count != 3)
	{
		std::wcout << L"[?] Usage: " << arguments[0] << L" <target process id> <absolute path to dll library for inject>\n";
		return 0;
	}

	if(!is_file_exists(arguments[2]))
	{
		std::wcout << L"[-] File of dll library" << arguments[2] << L" is not exist. Exit.\n";
		return 0;
	}

	//Open process to be sure that process exists
	auto target_pid = _wtoi(arguments[1]);
	HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
	if(!target_process)
	{
		std::wcout << L"[-] Cant open process with pid" << target_pid << L". LastError code:" << GetLastError() << L". Exit.\n";
		return 1;
	}
	std::wcout << L"[+] injecton : process " << arguments[1] << " | dll: " << arguments[2] << L'\n';
	std::wcout << L"[+] target process handle: 0x" << target_process << L'\n';

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	LdrLoadDll_t LdrLoadDll = reinterpret_cast<LdrLoadDll_t>(GetProcAddress(ntdll, "LdrLoadDll"));
	RtlInitUnicodeString_t RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(GetProcAddress(ntdll, "RtlInitUnicodeString"));

	if(!LdrLoadDll)
	{
		std::wcout << L"[-] Cant find LdrLoadDll. LastError code:" << GetLastError() << L". Exit.\n";
		CloseHandle(target_process);
		return 2;
	}
	if(!RtlInitUnicodeString)
	{
		std::wcout << L"[-] Cant find RtlInitUnicodeString. LastError code:" << GetLastError() << L". Exit.\n";
		CloseHandle(target_process);
		return 2;
	}

	std::wcout << L"[+] ntdll ptr: 0x" << std::hex << ntdll << L'\n';
	std::wcout << L"[+] LdrLoadDll ptr: 0x" << std::hex << LdrLoadDll << L'\n';
	std::wcout << L"[+] RtlInitUnicodeString ptr: 0x" << std::hex << RtlInitUnicodeString << L'\n';

	//Allocate memory for remote context
	shellcode_context* remote_context = static_cast<shellcode_context*>(VirtualAllocEx(target_process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE));

	if(!remote_context)
	{
		std::wcout << L"[-] Cant allocate memory in target process. LastError code:" << GetLastError() << L". Exit.\n";
		CloseHandle(target_process);
		return 3;
	}
	std::wcout << L"[+] memory for remote context: 0x" << std::hex << remote_context << L'\n';

	//prepare context data
	shellcode_context local_context {LdrLoadDll, RtlInitUnicodeString, {}, {} };
	auto path_length = wcslen(arguments[2]);
	memcpy(local_context.path_buffer, arguments[2], path_length * sizeof(wchar_t));

	//write context to target process
	size_t written_bytes = 0;
	if(WriteProcessMemory(target_process, remote_context, &local_context, sizeof(shellcode_context), &written_bytes) == FALSE ||
		written_bytes != sizeof(shellcode_context))
	{
		std::wcout << L"[-] Cant write context data to memory in target process. LastError code:" << GetLastError() << L". Exit.\n";
		VirtualFreeEx(target_process, remote_context, 0, MEM_RELEASE);
		CloseHandle(target_process);
		return 4;
	}
	
	std::wcout << L"[+] remote context writted: 0x" << std::hex << written_bytes << L'\n';
		
	//in this time I will skip search algoritm, just hardcoded value for win10_1809
	uint8_t* shellcode_place_ptr = reinterpret_cast<uint8_t*>(ntdll) + 0x117200 /*.text first zero bytes*/ + 0x1000 /*nt header size*/;
	
	std::wcout << L"[+] memory for shell code inside ntdll: 0x" << std::hex << shellcode_place_ptr << L'\n';

	//hackway to get actual size of function code
	size_t code_size = reinterpret_cast<uintptr_t>(shellcode_end) - reinterpret_cast<uintptr_t>(shellcode);

	//write shellcode to target process
	written_bytes = 0;
	if(WriteProcessMemory(target_process, shellcode_place_ptr, shellcode, code_size, &written_bytes) &&
		written_bytes != code_size)
	{
		std::wcout << L"[-] Cant write shellcode to memory in target process. LastError code:" << GetLastError() << L". Exit.\n";
		VirtualFreeEx(target_process, remote_context, 0, MEM_RELEASE);
		CloseHandle(target_process);
		return 5;
	}

	std::wcout << L"[+] shellcode writted: 0x" << std::hex << written_bytes << L'\n';

	//start new thread in target process
	HANDLE thread = CreateRemoteThread(target_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_place_ptr), remote_context, 0, nullptr);
	if(!thread)
	{
		std::wcout << L"[-] Cant create thread in target process. LastError code:" << GetLastError() << L". Exit.\n";
		VirtualFreeEx(target_process, remote_context, 0, MEM_RELEASE);
		CloseHandle(target_process);
		return 6;
	}
	
	std::wcout << L"[+] remote thread started, handle: 0x" << std::hex << thread << L'\n';

	WaitForSingleObject(thread, INFINITE);
	
	std::wcout << L"[+] remote thread exited, job done\n";
	CloseHandle(thread);
	VirtualFreeEx(target_process, remote_context, 0, MEM_RELEASE);
	CloseHandle(target_process);
	return 0;

}

HANDLE WINAPI shellcode(shellcode_context* data)
{
	HANDLE out_module;
	data->RtlInitUnicodeString(&data->dll_path, data->path_buffer);
	data->LdrLoadDll(nullptr, nullptr, &data->dll_path, &out_module);
	return nullptr;
}

DWORD WINAPI shellcode_end()
{
	return 0;
}