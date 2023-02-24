#include <iostream>
#include <Windows.h>
#include <fstream>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>
#include <iomanip>
#include <process.h>
#include <filesystem>
#include "pe-parser.hpp"
#include "../runtime/runtime.hpp"
#include <unordered_map>

namespace fs = std::filesystem;

// Improvements: encrypt .rdata section and when a value is accessed decrypt

std::string findString(PEParser& parser, const std::uintptr_t rva) {
	const auto sections = parser.getSections(IMAGE_SCN_CNT_INITIALIZED_DATA);

	std::string str;

	for (const auto section : sections) {
		std::vector<std::byte> contents = parser.getSectionContent(section);

		if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
			const char* start = reinterpret_cast<const char*>(&contents[rva - section->VirtualAddress]);
			const char* end = start + (section->Misc.VirtualSize - (rva - section->VirtualAddress));
			const char* found = std::find(start, end, '\0');

			if (found != end) {
				str = std::string(start, found - start);
				break;
			}
		}
	}
	return str;
}

bool infect(PEParser& parser, Runtime& runtime) {
	IMAGE_SECTION_HEADER* codeSection = parser.getSection(IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA);

	if (!codeSection) {
		return false;
	}

	std::uintptr_t ip = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr)) + codeSection->VirtualAddress;

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	std::vector<std::byte> code = parser.getSectionContent(codeSection);

	size_t offset = 0;
	size_t remaining = code.size();

	std::random_device rd;
	std::mt19937 gen(rd());

	std::vector<std::byte> newInstrs;

	ZydisDecodedInstruction instr;

	const std::byte breakpoint = static_cast<std::byte>(0xCC);

	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, &code[offset], remaining, &instr))) {
		if (offset + instr.length >= code.size()) {
			break;
		}

		if (instr.mnemonic != ZYDIS_MNEMONIC_INT3) {
			newInstrs.push_back(breakpoint);

			for (int i = 0; i < instr.length - 1; i++) {
				newInstrs.push_back(static_cast<std::byte>(gen()));
			}

			std::vector<std::byte> instrBytes(&code[offset], &code[offset + instr.length]);
			const RuntimeInstruction runtimeInstr(instrBytes);

			runtime.addInstruction(codeSection->VirtualAddress + offset, runtimeInstr);
		}
		else {
			std::vector<std::byte> rawInstr(&code[offset], &code[offset + instr.length]);
			newInstrs.insert(newInstrs.end(), rawInstr.begin(), rawInstr.end());
		}
		offset += instr.length;
		remaining -= instr.length;
		ip += instr.length;
	}

	if (!parser.replaceSection(codeSection, newInstrs)) {
		std::cout << "Failed to replace code section!" << std::endl;
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	/*std::cout << "Enter file: ";

	fs::path inputPath;
	std::cin >> inputPath;*/

	fs::path inputPath = "C:\\Users\\Radon\\Desktop\\crack-me.exe";

	const fs::path tempPath = fs::temp_directory_path() / inputPath.filename();
	fs::copy(inputPath, tempPath, fs::copy_options::overwrite_existing);

	PEParser parser;

	if (!parser.parse(tempPath.string())) {
		std::cout << "Failed to parse PE!" << std::endl;
		return EXIT_FAILURE;
	}

	Runtime runtime;
	infect(parser, runtime);

	const std::vector<std::byte> radon0 = runtime.serialize();

	Payload payload(parser.getImage());

	std::vector<std::byte> radon1 = payload.serialize();
	uint32_t extraSize = parser.alignToSection((uint32_t)radon0.size() + (uint32_t)radon1.size());

	parser.~PEParser();

	// We now have the runtimeInstructions so we can start messing with the runtime

	fs::remove(tempPath);

	const fs::path outputDir = inputPath.parent_path() / "Protected";

	if (fs::exists(outputDir)) {
		fs::remove_all(outputDir);
	}
	fs::create_directory(outputDir);

	const fs::path outputPath = outputDir / inputPath.filename();

	const fs::path executablePath = argv[0];
	const fs::path currentDir = executablePath.parent_path();

	fs::copy_file(currentDir / "runtime.exe", outputPath);

	parser.parse(outputPath.string(), extraSize);

	// .radon0 is the section containing the original instructions
	// .radon1 is the section containing the payload
	parser.createSection(".radon0", radon0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
	parser.createSection(".radon1", radon1, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);

	parser.save();

	return EXIT_SUCCESS;
}