#include <iostream>
#include <Windows.h>
#include <fstream>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>
#include <iomanip>
#include <filesystem>
#include "pe-parser.hpp"
#include "../runtime/runtime.hpp"

namespace fs = std::filesystem;

void infect(PEParser& parser, Runtime& runtime) {
	IMAGE_SECTION_HEADER* codeSection = parser.getSection(IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA);

	if (!codeSection) {
		return;
	}

	uintptr_t ip = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)) + codeSection->VirtualAddress;

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	std::vector<std::byte> code = parser.getSectionContent(codeSection);

	size_t offset = 0;
	size_t remaining = code.size();

	ZydisDecodedInstruction instr;

	const std::byte breakpoint = std::byte(0xCC);

	while (offset < code.size()) {
		ZyanStatus status = ZydisDecoderDecodeBuffer(&decoder, &code[offset], remaining, &instr);

		if (!ZYAN_SUCCESS(status)) {
			offset++;
			remaining--;
			ip++;
			continue;
		}
		
		if (instr.mnemonic != ZYDIS_MNEMONIC_INT3) {
			std::vector<std::byte> instrBytes(&code[offset], &code[offset + instr.length]);
			const RuntimeInstruction runtimeInstr(instrBytes);
			runtime.addInstruction(codeSection->VirtualAddress + offset, runtimeInstr);

			std::fill(&code[offset], &code[offset + instr.length], breakpoint);
		}
		offset += instr.length;
		remaining -= instr.length;
		ip += instr.length;
	}
	parser.replaceSection(codeSection, code);
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
	uint32_t extraSize = parser.alignToSection(static_cast<uint32_t>(radon0.size())) + parser.alignToSection(static_cast<uint32_t>(radon1.size()));

	parser.~PEParser();

	fs::remove(tempPath);

	// We now have the runtimeInstructions so we can start messing with the runtime

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

	return EXIT_SUCCESS;
}