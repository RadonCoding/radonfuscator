#include "pe-parser.hpp"
#include <iostream>

bool PEParser::parse(std::string filename, uint32_t extra) {
	this->_file = CreateFileA(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (this->_file == INVALID_HANDLE_VALUE) {
		return false;
	}

	uint32_t fileSize = GetFileSize(this->_file, nullptr);

	if (fileSize == INVALID_FILE_SIZE) {
		return false;
	}

	fileSize += extra;

	this->_imageSize = fileSize;

	this->_mapping = CreateFileMappingA(this->_file, nullptr, PAGE_READWRITE, 0, this->_imageSize, nullptr);

	if (!this->_mapping) {
		CloseHandle(this->_file);
		return false;
	}

	this->_image = reinterpret_cast<std::byte*>(MapViewOfFile(this->_mapping, FILE_MAP_WRITE, 0, 0, this->_imageSize));

	if (!this->_image) {
		CloseHandle(this->_mapping);
		CloseHandle(this->_file);
		return false;
	}

	this->_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(this->_image);

	if (_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		UnmapViewOfFile(this->_image);
		CloseHandle(this->_mapping);
		CloseHandle(this->_file);
		return false;
	}

	this->_ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(this->_image + this->_dosHeader->e_lfanew);

	if (_ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		UnmapViewOfFile(this->_image);
		CloseHandle(this->_mapping);
		CloseHandle(this->_file);
		return false;
	}
	return true;
}

IMAGE_SECTION_HEADER* PEParser::getSection(uint32_t required, uint32_t excluded) const {
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(this->_ntHeader);

	for (uint16_t i = 0; i < this->_ntHeader->FileHeader.NumberOfSections; i++) {
		if (section->Characteristics & required && (section->Characteristics & excluded) == 0) {
			return section;
		}
		section++;
	}
	return nullptr;
}

const std::vector<IMAGE_SECTION_HEADER*> PEParser::getSections(uint32_t required, uint32_t excluded) const {
	std::vector<IMAGE_SECTION_HEADER*> sections;

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(this->_ntHeader);

	for (uint16_t i = 0; i < this->_ntHeader->FileHeader.NumberOfSections; i++) {
		if (section->Characteristics & required && (section->Characteristics & excluded) == 0) {
			sections.push_back(section);
		}
		section++;
	}
	return sections;
}

const std::vector<std::byte> PEParser::getSectionContent(IMAGE_SECTION_HEADER* section) const {
	std::byte* offset = this->_image + section->PointerToRawData;
	std::vector<std::byte> contents(offset, offset + section->SizeOfRawData);
	return contents;
}

IMAGE_SECTION_HEADER* PEParser::createSection(const char* name, std::vector<std::byte> contents, uint32_t characteristics) {
	IMAGE_SECTION_HEADER* lastSection = IMAGE_FIRST_SECTION(this->_ntHeader) + (this->_ntHeader->FileHeader.NumberOfSections - 1);

	IMAGE_SECTION_HEADER* newSection = IMAGE_FIRST_SECTION(this->_ntHeader) + this->_ntHeader->FileHeader.NumberOfSections;
	ZeroMemory(newSection, sizeof(newSection));

	std::memcpy(newSection->Name, name, sizeof(newSection->Name));

	newSection->Characteristics = characteristics;

	newSection->Misc.VirtualSize = alignToSection(static_cast<uint32_t>(contents.size()));
	newSection->VirtualAddress = alignToSection(lastSection->Misc.VirtualSize, lastSection->VirtualAddress);
	newSection->SizeOfRawData = alignToFile(static_cast<uint32_t>(contents.size()));
	newSection->PointerToRawData = alignToFile(lastSection->SizeOfRawData, lastSection->PointerToRawData);

	this->_ntHeader->OptionalHeader.SizeOfImage = newSection->VirtualAddress + newSection->Misc.VirtualSize;
	this->_ntHeader->FileHeader.NumberOfSections++;

	std::memcpy(this->_image + newSection->PointerToRawData, &contents[0], contents.size());

	return newSection;
}

const inline uint32_t align(uint32_t size, uint32_t address, uint32_t alignment) {
	if (!(size % alignment)) {
		return address + size;
	}
	return address + (size / alignment + 1) * alignment;
}

const inline uint32_t PEParser::alignToFile(uint32_t size, uint32_t address) const {
	uint32_t alignment = this->_ntHeader->OptionalHeader.FileAlignment;
	return align(size, address, alignment);
}

const inline uint32_t PEParser::alignToSection(uint32_t size, uint32_t address) const {
	uint32_t alignment = this->_ntHeader->OptionalHeader.SectionAlignment;
	return align(size, address, alignment);
}

const std::vector<std::byte> PEParser::getImage() {
	return std::vector<std::byte>(this->_image, this->_image + this->_imageSize);
}

void PEParser::replaceSection(IMAGE_SECTION_HEADER* section, std::vector<std::byte> newContents) const {
	std::memcpy(this->_image + section->PointerToRawData, &newContents[0], section->SizeOfRawData);
}

PEParser::~PEParser() {
	if (this->_image) {
		UnmapViewOfFile(this->_image);
	}

	if (this->_file && this->_file != INVALID_HANDLE_VALUE) {
		CloseHandle(this->_file);
	}

	if (this->_mapping && this->_mapping != INVALID_HANDLE_VALUE) {
		CloseHandle(this->_mapping);
	}
}