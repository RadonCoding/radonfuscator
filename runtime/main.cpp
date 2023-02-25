#include "main.hpp"
#include <string>
#include <iostream>
#include <iomanip>
#include <thread>

std::uintptr_t getImageBase(const HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION processBasicInfo { 0 };

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll) {
		return false;
	}

	xNtQueryInformationProcess NtQueryInformationProcess = reinterpret_cast<xNtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processBasicInfo, sizeof(processBasicInfo), nullptr);

	if (status != ERROR_SUCCESS) {
		return 0;
	}

	if (!processBasicInfo.PebBaseAddress) {
		return 0;
	}

	PEB peb { 0 };

	if (!ReadProcessMemory(hProcess, processBasicInfo.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
		return 0;
	}
	return reinterpret_cast<std::uintptr_t>(peb.ImageBaseAddress);
}

bool execute(const char* executablePath, const char* commandLine, PROCESS_INFORMATION* pProcessInfo) {
	// Decrypt the payload
	payload.decrypt();

	std::vector<std::byte> payloadBytes = payload.getBytes();

	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(&payloadBytes[0]);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(&payloadBytes[0] + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	STARTUPINFOA startupInfo { 0 };

	if (!CreateProcessA(executablePath, const_cast<char*>(commandLine), nullptr, nullptr, false, CREATE_SUSPENDED | DEBUG_PROCESS, nullptr, nullptr, &startupInfo, pProcessInfo)) {
		return false;
	}

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll) {
		return false;
	}

	const xNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast<xNtUnmapViewOfSection>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
	NtUnmapViewOfSection(pProcessInfo->hProcess, nullptr);

	CONTEXT context { 0 };
	context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(pProcessInfo->hThread, &context)) {
		return false;
	}

	// Allocate space in the process for the PE
	std::byte* pImageBase = reinterpret_cast<std::byte*>(VirtualAllocEx(pProcessInfo->hProcess, reinterpret_cast<void*>(ntHeader->OptionalHeader.ImageBase),
		ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pImageBase) {
		return false;
	}

	// Write the payload to the newly allocated image base
	if (!WriteProcessMemory(pProcessInfo->hProcess, pImageBase, &payloadBytes[0], ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
		return false;
	}

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (!WriteProcessMemory(pProcessInfo->hProcess, pImageBase + section->VirtualAddress, &payloadBytes[section->PointerToRawData], section->SizeOfRawData, nullptr)) {
			return false;
		}
		section++;
	}

	// Re-encrypt the payload
	payload.encrypt();

	// Write the new image base to Rdx + 16
	WriteProcessMemory(pProcessInfo->hProcess, reinterpret_cast<void*>(context.Rdx + 16), &pImageBase, sizeof(pImageBase), nullptr);

	context.Rcx = reinterpret_cast<std::uintptr_t>(pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
	SetThreadContext(pProcessInfo->hThread, &context);
	ResumeThread(pProcessInfo->hThread);

	return true;
}

bool handleDebugEvent(const DEBUG_EVENT debugEvent, const HANDLE hProcess) {
	const HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);

	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		return false;
	}

	SuspendThread(hThread);

	CONTEXT context { 0 };
	context.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(hThread, &context)) {
		ResumeThread(hThread);
		CloseHandle(hThread);
		return false;
	}

	const std::uintptr_t imageBase = getImageBase(hProcess);
	const std::uintptr_t oldRVA = runtime.getOldRVA();

	if (oldRVA != 0) {
		if (runtime.hasInstruction(oldRVA)) {
			std::uintptr_t oldVA = oldRVA - imageBase;

			std::byte breakpoint = static_cast<std::byte>(0xCC);

			RuntimeInstruction oldRuntimeInstr = runtime.getInstruction(oldRVA);
			const std::vector<std::byte> oldInstrBytes = oldRuntimeInstr.getBytes();

			for (size_t i = 0; i < oldInstrBytes.size(); i++) {
				WriteProcessMemory(hProcess, reinterpret_cast<void*>(oldVA + i), &breakpoint, sizeof(breakpoint), nullptr);
			}
		}
	}

	std::uintptr_t va = context.Rip - 1;
	std::uintptr_t rva = va - imageBase;

	if (!runtime.hasInstruction(rva)) {
		context.Rip += 1;
		SetThreadContext(hThread, &context);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return false;
	}

	RuntimeInstruction runtimeInstr = runtime.getInstruction(rva);

	// Decrypt the instruction
	runtimeInstr.crypt();

	const std::vector<std::byte> instrBytes = runtimeInstr.getBytes();

	context.Rip -= 1;

	if (!WriteProcessMemory(hProcess, reinterpret_cast<void*>(va), &instrBytes[0], instrBytes.size(), nullptr)) {
		// Re-encrypt the instruction
		runtimeInstr.crypt();

		SetThreadContext(hThread, &context);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return false;
	}

	// Re-encrypt the instruction
	runtimeInstr.crypt();

	runtime.setOldRVA(rva);

	SetThreadContext(hThread, &context);
	ResumeThread(hThread);
	CloseHandle(hThread);

	return true;
}

void handler(const HANDLE hProcess, const HANDLE hThread) {
	DEBUG_EVENT debugEvent { 0 };

	bool running = true;

	while (running) {
		WaitForDebugEvent(&debugEvent, INFINITE);

		switch (debugEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			handleDebugEvent(debugEvent, hProcess);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			running = false;
			break;
		}
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}

	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	WaitForSingleObject(hProcess, INFINITE);
}

int main(int argc, char* argv[]) {
	std::byte* hModule = reinterpret_cast<std::byte*>(GetModuleHandleA(nullptr));
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return EXIT_FAILURE;
	}

	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(hModule + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return EXIT_FAILURE;
	}

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);

	for (uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// .radon0 is the section containing the original instructions
		// .radon1 is the section containing the payload

		std::byte* pointerToRawDataVA = hModule + section->VirtualAddress;

		if (strcmp((char*)section->Name, ".radon0") == 0) {
			radon0.insert(radon0.begin(), pointerToRawDataVA, pointerToRawDataVA + section->Misc.VirtualSize);
		}
		else if (strcmp((char*)section->Name, ".radon1") == 0) {
			radon1.insert(radon1.begin(), pointerToRawDataVA, pointerToRawDataVA + section->Misc.VirtualSize);
		}
		section++;
	}

	if (radon0.size() == 0 || radon1.size() == 0) {
		return EXIT_FAILURE;
	}

	runtime.deserialize(radon0);
	payload.deserialize(radon1);

	PROCESS_INFORMATION processInfo { 0 };

	std::string commandLine;

	for (int i = 0; i < argc; i++) {
		commandLine.append(argv[i]);
	}

	if (!execute(argv[0], const_cast<char*>(commandLine.c_str()), &processInfo)) {
		return EXIT_FAILURE;
	}

	handler(processInfo.hProcess, processInfo.hThread);

	if (processInfo.hProcess && processInfo.hProcess != INVALID_HANDLE_VALUE) {
		CloseHandle(processInfo.hProcess);
	}

	if (processInfo.hThread && processInfo.hThread != INVALID_HANDLE_VALUE) {
		CloseHandle(processInfo.hThread);
	}
	return EXIT_SUCCESS;
}