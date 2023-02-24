#include "pe-parser.hpp"
#include <iostream>

bool PEParser::parse(std::string filename, uint32_t extra) {
    this->hFile = CreateFileA(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (this->hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    uint32_t fileSize = GetFileSize(this->hFile, nullptr);

    if (fileSize == INVALID_FILE_SIZE) {
        return false;
    }

    fileSize += extra;

    this->imageSize = fileSize;
    
    this->hMapping = CreateFileMappingA(this->hFile, nullptr, PAGE_READWRITE, 0, this->imageSize, nullptr);

    if (!this->hMapping) {
        CloseHandle(this->hFile);
        return false;
    }

    this->pImage = reinterpret_cast<std::byte*>(MapViewOfFile(this->hMapping, FILE_MAP_WRITE, 0, 0, this->imageSize));

    if (!this->pImage) {
        CloseHandle(this->hMapping);
        CloseHandle(this->hFile);
        return false;
    }

    this->dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(this->pImage);
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(this->pImage);
        CloseHandle(this->hMapping);
        CloseHandle(this->hFile);
        return false;
    }
    
    this->ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(this->pImage + this->dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(this->pImage);
        CloseHandle(this->hMapping);
        CloseHandle(this->hFile);
        return false;
    }
    return true;
}

IMAGE_SECTION_HEADER* PEParser::getSection(uint32_t required, uint32_t excluded) {
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(this->ntHeader);

    for (uint16_t i = 0; i < this->ntHeader->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & required && (section->Characteristics & excluded) == 0) {
            return section;
        }
        section++;
    }
    return nullptr;
}

std::vector<IMAGE_SECTION_HEADER*> PEParser::getSections(uint32_t required, uint32_t excluded) {
    std::vector<IMAGE_SECTION_HEADER*> sections;

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(this->ntHeader);

    for (uint16_t i = 0; i < this->ntHeader->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & required && (section->Characteristics & excluded) == 0) {
            sections.push_back(section);
        }
        section++;
    }
    return sections;
}

std::vector<std::byte> PEParser::getSectionContent(IMAGE_SECTION_HEADER* section) {
    std::byte* offset = this->pImage + section->PointerToRawData;
    std::vector<std::byte> contents(offset, offset + section->SizeOfRawData);
    return contents;
}

IMAGE_SECTION_HEADER* PEParser::createSection(const char* name, std::vector<std::byte> contents, uint32_t characteristics) {
    IMAGE_SECTION_HEADER* lastSection = IMAGE_FIRST_SECTION(this->ntHeader) + (this->ntHeader->FileHeader.NumberOfSections - 1);

    IMAGE_SECTION_HEADER* newSection = IMAGE_FIRST_SECTION(this->ntHeader) + this->ntHeader->FileHeader.NumberOfSections;
    ZeroMemory(newSection, sizeof(newSection));
    
    std::memcpy(newSection->Name, name, sizeof(newSection->Name));

    newSection->Characteristics = characteristics;

    newSection->Misc.VirtualSize = alignToSection((uint32_t)contents.size());
    newSection->VirtualAddress = alignToSection(lastSection->Misc.VirtualSize, lastSection->VirtualAddress);
    newSection->SizeOfRawData = alignToFile((uint32_t)contents.size());
    newSection->PointerToRawData = alignToFile(lastSection->SizeOfRawData, lastSection->PointerToRawData);

    this->ntHeader->OptionalHeader.SizeOfImage = newSection->VirtualAddress + newSection->Misc.VirtualSize;
    this->ntHeader->FileHeader.NumberOfSections++;

    std::memcpy(this->pImage + newSection->PointerToRawData, &contents[0], contents.size());

    return newSection;
}

uint32_t PEParser::alignToFile(uint32_t size, uint32_t address) {
    uint32_t align = this->ntHeader->OptionalHeader.FileAlignment;

    if (!(size % align)) {
        return address + size;
    }
    return address + (size / align + 1) * align;
}

uint32_t PEParser::alignToSection(uint32_t size, uint32_t address) {
    uint32_t align = this->ntHeader->OptionalHeader.SectionAlignment;

    if (!(size % align)) {
        return address + size;
    }
    return address + (size / align + 1) * align;
}

std::vector<std::byte> PEParser::getImage() {
    std::vector<std::byte> image(this->pImage, this->pImage + this->imageSize);
    return image;
}

bool PEParser::replaceSection(IMAGE_SECTION_HEADER* section, std::vector<std::byte> newContents) {
    std::memcpy(this->pImage + section->PointerToRawData, &newContents[0], section->SizeOfRawData);
    return true;
}

void PEParser::save() {
    FlushViewOfFile(this->pImage, 0);
}

PEParser::~PEParser() {
    if (this->pImage) {
        UnmapViewOfFile(this->pImage);
    }

    if (this->hFile && this->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(this->hFile);
    }

    if (this->hMapping && this->hMapping != INVALID_HANDLE_VALUE) {
        CloseHandle(this->hMapping);
    }
}