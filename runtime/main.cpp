#include "main.hpp"
#include <string>
#include <iostream>
#include <iomanip>
#include <thread>

// Gets the image base for the specified process
uintptr_t getImageBase(const HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION pbi;
	memset(&pbi, 0, sizeof(pbi));

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll) {
		return false;
	}

	xNtQueryInformationProcess NtQueryInformationProcess = reinterpret_cast<xNtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

	if (status != ERROR_SUCCESS) return 0;

	PEB peb;
	memset(&peb, 0, sizeof(peb));

	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
		return 0;
	}
	return reinterpret_cast<uintptr_t>(peb.ImageBaseAddress);
}

// Relocating the image to avoid process dumping note this does break layering the obfuscation
void relocate(std::byte* imageBase) {
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(imageBase + dosHeader->e_lfanew);

	uint32_t imageSize = ntHeader->OptionalHeader.SizeOfImage;

	// Allocate a new block of memory
	std::byte* newImageBase = reinterpret_cast<std::byte*>(VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!newImageBase) {
		return;
	}

	// Initialize the radon0 and radon1
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);

	for (uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// .radon0 is the section containing the original instructions
		// .radon1 is the section containing the payload

		std::byte* sectionAddr = imageBase + section->VirtualAddress;

		if (strcmp((char*)section->Name, ".radon0") == 0) {
			radon0.insert(radon0.begin(), sectionAddr, sectionAddr + section->Misc.VirtualSize);
		}
		else if (strcmp((char*)section->Name, ".radon1") == 0) {
			radon1.insert(radon1.begin(), sectionAddr, sectionAddr + section->Misc.VirtualSize);
		}
		section++;
	}

	memcpy(newImageBase, imageBase, imageSize);

	VirtualFree(imageBase, 0, MEM_RELEASE);

	void* oep = newImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;

	// Call the entry point of the new block of memory
	((void(*)())oep)();
}

// Doing some process hollowing using own image
bool execute(const char* currentPath, const char* commandLine, PROCESS_INFORMATION* pi) {
	// Decrypt the payload
	_payload.crypt();

	std::vector<std::byte> bytes = _payload.getBytes();

	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(&bytes[0]);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(&bytes[0] + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	STARTUPINFOA si;
	memset(&si, 0, sizeof(si));

	if (!CreateProcessA(currentPath, const_cast<char*>(commandLine), nullptr, nullptr, false, CREATE_SUSPENDED | DEBUG_PROCESS, nullptr, nullptr, &si, pi)) {
		return false;
	}

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll) {
		return false;
	}

	const xNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast<xNtUnmapViewOfSection>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
	NtUnmapViewOfSection(pi->hProcess, nullptr);

	CONTEXT context;
	memset(&context, 0, sizeof(context));
	context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(pi->hThread, &context)) {
		return false;
	}

	// Allocate space in the process for the PE
	std::byte* imageBase = reinterpret_cast<std::byte*>(VirtualAllocEx(pi->hProcess, reinterpret_cast<void*>(ntHeader->OptionalHeader.ImageBase),
		ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!imageBase) {
		return false;
	}

	// Write the payload to the newly allocated image base
	if (!WriteProcessMemory(pi->hProcess, imageBase, &bytes[0], ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
		return false;
	}

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (!WriteProcessMemory(pi->hProcess, imageBase + section->VirtualAddress, &bytes[section->PointerToRawData], section->SizeOfRawData, nullptr)) {
			return false;
		}
		section++;
	}

	// Re-encrypt the payload
	_payload.crypt();

	// Write the new image base to Rdx + 16
	WriteProcessMemory(pi->hProcess, reinterpret_cast<void*>(context.Rdx + 16), &imageBase, sizeof(imageBase), nullptr);

	context.Rcx = reinterpret_cast<uintptr_t>(imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
	SetThreadContext(pi->hThread, &context);
	ResumeThread(pi->hThread);

	return true;
}

// The main handler that replaces the int 3h instructions with the real ones
void handleDebugEvent(DEBUG_EVENT event, HANDLE process) {
	HANDLE thread = OpenThread(THREAD_ALL_ACCESS, false, event.dwThreadId);

	if (!thread || thread == INVALID_HANDLE_VALUE) {
		return;
	}

	SuspendThread(thread);

	CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(thread, &ctx)) {
		ResumeThread(thread);
		CloseHandle(thread);
		return;
	}

	uintptr_t imageBase = getImageBase(process);
	uintptr_t oldRVA = runtime.getOldRVA();

	if (oldRVA != 0) {
		if (runtime.hasInstruction(oldRVA)) {
			uintptr_t oldVA = oldRVA - imageBase;

			std::byte breakpoint = static_cast<std::byte>(0xCC);

			RuntimeInstruction instr = runtime.getInstruction(oldRVA);
			const std::vector<std::byte> oldInstrBytes = instr.getBytes();

			for (size_t i = 0; i < oldInstrBytes.size(); i++) {
				WriteProcessMemory(process, reinterpret_cast<void*>(oldVA + i), &breakpoint, sizeof(breakpoint), nullptr);
			}
		}
	}

	uintptr_t va = ctx.Rip - 1;
	uintptr_t rva = va - imageBase;

	if (!runtime.hasInstruction(rva)) {
		ctx.Rip += 1;
		SetThreadContext(thread, &ctx);
		ResumeThread(thread);
		CloseHandle(thread);
		return;
	}

	RuntimeInstruction instr = runtime.getInstruction(rva);

	// Decrypt the instruction
	instr.crypt();

	const std::vector<std::byte> bytes = instr.getBytes();

	ctx.Rip -= 1;

	if (!WriteProcessMemory(process, reinterpret_cast<void*>(va), &bytes[0], bytes.size(), nullptr)) {
		// Re-encrypt the instruction
		instr.crypt();

		SetThreadContext(thread, &ctx);
		ResumeThread(thread);
		CloseHandle(thread);
		return;
	}

	// Re-encrypt the instruction
	instr.crypt();

	runtime.setOldRVA(rva);

	SetThreadContext(thread, &ctx);
	ResumeThread(thread);
	CloseHandle(thread);
}

// Catches the debug events
void handler(HANDLE process, HANDLE thread) {
	DEBUG_EVENT event;
	memset(&event, 0, sizeof(event));

	bool running = true;

	while (running) {
		WaitForDebugEvent(&event, INFINITE);

		switch (event.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			handleDebugEvent(event, process);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			running = false;
			break;
		}
		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
	}

	ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
	WaitForSingleObject(process, INFINITE);
}

int main(int argc, char* argv[]) {
	std::byte* imageBase = reinterpret_cast<std::byte*>(GetModuleHandleA(nullptr));

	if (!relocated) {
		relocated = true;
		relocate(imageBase);
	}

	if (radon0.size() == 0 || radon1.size() == 0) {
		return EXIT_FAILURE;
	}

	runtime.deserialize(radon0);
	_payload.deserialize(radon1);

	PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

	std::string cmd;

	for (int i = 0; i < argc; i++) {
		cmd.append(argv[i]);
	}

	if (!execute(argv[0], cmd.c_str(), &pi)) {
		return EXIT_FAILURE;
	}

	handler(pi.hProcess, pi.hThread);

	if (pi.hProcess && pi.hProcess != INVALID_HANDLE_VALUE) {
		CloseHandle(pi.hProcess);
	}

	if (pi.hThread && pi.hThread != INVALID_HANDLE_VALUE) {
		CloseHandle(pi.hThread);
	}
	return EXIT_SUCCESS;
}