#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

class PEParser {
public:
	bool parse(std::string filename, uint32_t extra = 0);
	IMAGE_SECTION_HEADER* getSection(uint32_t required, uint32_t excluded = 0);
	const std::vector<IMAGE_SECTION_HEADER*> getSections(uint32_t required, uint32_t excluded = 0);
	const std::vector<std::byte> getSectionContent(IMAGE_SECTION_HEADER* section);
	IMAGE_SECTION_HEADER* createSection(const char* name, std::vector<std::byte> contents, uint32_t characteristics);
	const inline uint32_t alignToFile(uint32_t size, uint32_t address = 0);
	const inline uint32_t alignToSection(uint32_t size, uint32_t address = 0);
	const std::vector<std::byte> getImage();
	bool replaceSection(IMAGE_SECTION_HEADER* section, std::vector<std::byte> newContents);

	void save();
	~PEParser();	

	std::byte* pImage = nullptr;
	uint32_t imageSize = 0;
private:
	IMAGE_DOS_HEADER* dosHeader = nullptr;
	IMAGE_NT_HEADERS* ntHeader = nullptr;

	HANDLE hFile = nullptr;
	HANDLE hMapping = nullptr;
};