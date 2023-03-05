#include "main.hpp"
#include <string>
#include <iostream>
#include <iomanip>
#include <thread>

// Gets the image base for the specified process
uintptr_t getImageBase(const HANDLE hProcess) {
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
	return reinterpret_cast<uintptr_t>(peb.ImageBaseAddress);
}

// Relocating the image to avoid process dumping note this does break layering the obfuscation
void relocate(std::byte* pImageBase) {
	IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pImageBase);
	IMAGE_NT_HEADERS* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pImageBase + pDosHeader->e_lfanew);

	uint32_t imageSize = pNtHeader->OptionalHeader.SizeOfImage;

	// Allocate a new block of memory
	std::byte* pNewImageBase = reinterpret_cast<std::byte*>(VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pNewImageBase) {
		return;
	}

	// Initialize the radon0 and radon1
	IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (uint16_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		// .radon0 is the section containing the original instructions
		// .radon1 is the section containing the payload

		std::byte* pSectionAddr = pImageBase + pSection->VirtualAddress;

		if (strcmp((char*)pSection->Name, ".radon0") == 0) {
			radon0.insert(radon0.begin(), pSectionAddr, pSectionAddr + pSection->Misc.VirtualSize);
		}
		else if (strcmp((char*)pSection->Name, ".radon1") == 0) {
			radon1.insert(radon1.begin(), pSectionAddr, pSectionAddr + pSection->Misc.VirtualSize);
		}
		pSection++;
	}

	memcpy(pNewImageBase, pImageBase, imageSize);

	VirtualFree(pImageBase, 0, MEM_RELEASE);

	void* oep = pNewImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

	// Call the entry point of the new block of memory
	((void(*)())oep)();
}

// Doing some process hollowing using own image
bool execute(const char* currentPath, const char* commandLine, PROCESS_INFORMATION* pProcessInfo) {
	// Decrypt the payload
	payload.crypt();

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

	if (!CreateProcessA(currentPath, const_cast<char*>(commandLine), nullptr, nullptr, false, CREATE_SUSPENDED | DEBUG_PROCESS, nullptr, nullptr, &startupInfo, pProcessInfo)) {
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
	payload.crypt();

	// Write the new image base to Rdx + 16
	WriteProcessMemory(pProcessInfo->hProcess, reinterpret_cast<void*>(context.Rdx + 16), &pImageBase, sizeof(pImageBase), nullptr);

	context.Rcx = reinterpret_cast<uintptr_t>(pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
	SetThreadContext(pProcessInfo->hThread, &context);
	ResumeThread(pProcessInfo->hThread);

	return true;
}

// The main handler that replaces the int 3h instructions with the real ones
void handleDebugEvent(const DEBUG_EVENT debugEvent, const HANDLE hProcess) {
	const HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);

	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		return;
	}

	SuspendThread(hThread);

	CONTEXT ctx { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(hThread, &ctx)) {
		ResumeThread(hThread);
		CloseHandle(hThread);
		return;
	}

	const uintptr_t imageBase = getImageBase(hProcess);
	const uintptr_t oldRVA = runtime.getOldRVA();

	if (oldRVA != 0) {
		if (runtime.hasInstruction(oldRVA)) {
			uintptr_t oldVA = oldRVA - imageBase;

			std::byte breakpoint = static_cast<std::byte>(0xCC);

			RuntimeInstruction oldRuntimeInstr = runtime.getInstruction(oldRVA);
			const std::vector<std::byte> oldInstrBytes = oldRuntimeInstr.getBytes();

			for (size_t i = 0; i < oldInstrBytes.size(); i++) {
				WriteProcessMemory(hProcess, reinterpret_cast<void*>(oldVA + i), &breakpoint, sizeof(breakpoint), nullptr);
			}
		}
	}

	uintptr_t va = ctx.Rip - 1;
	uintptr_t rva = va - imageBase;

	if (!runtime.hasInstruction(rva)) {
		ctx.Rip += 1;
		SetThreadContext(hThread, &ctx);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return;
	}

	RuntimeInstruction runtimeInstr = runtime.getInstruction(rva);

	// Decrypt the instruction
	runtimeInstr.crypt();

	const std::vector<std::byte> instrBytes = runtimeInstr.getBytes();

	ctx.Rip -= 1;

	if (!WriteProcessMemory(hProcess, reinterpret_cast<void*>(va), &instrBytes[0], instrBytes.size(), nullptr)) {
		// Re-encrypt the instruction
		runtimeInstr.crypt();

		SetThreadContext(hThread, &ctx);
		ResumeThread(hThread);
		CloseHandle(hThread);
		return;
	}

	// Re-encrypt the instruction
	runtimeInstr.crypt();

	runtime.setOldRVA(rva);

	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);
	CloseHandle(hThread);
}

// Catches the debug events
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
	std::byte* pImageBase = reinterpret_cast<std::byte*>(GetModuleHandleA(nullptr));

	if (!relocated) {
		relocated = true;
		relocate(pImageBase);
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

	if (!execute(argv[0], commandLine.c_str(), &processInfo)) {
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