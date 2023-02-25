#include <cstdint>
#include <vector>
#include <random>
#include <map>
#include <iostream>
#include <Windows.h>

using namespace std;

constexpr std::size_t KEY_SIZE = 32;

struct RuntimeInstruction {
public:
	// Decrypt the instruction
	inline void crypt() {
		for (std::size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	// Get the encrypted instruction bytes
	inline const std::vector<std::byte>& getBytes() const {
		return this->bytes;
	}

	// Get the key used for encryption
	inline const std::vector<std::byte>& getKey() const {
		return this->key;
	}

	// Serialize the instruction to a byte vector
	const std::vector<std::byte> serialize() const {
		std::vector<std::byte> result;
		result.reserve(this->bytes.size() + KEY_SIZE);
		result.insert(result.end(), this->bytes.begin(), this->bytes.end());
		result.insert(result.end(), this->key.begin(), this->key.end());
		return result;
	}

	// Deserialize a byte vector into a RuntimeInstruction object
	static RuntimeInstruction deserialize(const std::vector<std::byte> serialized) {
		std::vector<std::byte> instructionBytes(serialized.begin(), serialized.begin() + serialized.size() - KEY_SIZE);
		std::vector<std::byte> key(serialized.end() - KEY_SIZE, serialized.end());
		return RuntimeInstruction(instructionBytes, key);
	}

	// Create a new RuntimeInstruction with a random key
	RuntimeInstruction(std::vector<std::byte> bytes) {
		this->bytes = bytes;

		// Use a more secure random number generator
		std::random_device rd;
		std::mt19937_64 gen(rd());
		std::uniform_int_distribution<uint64_t> dist(0, 255);

		for (std::size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<std::byte>(dist(gen)));
		}
		this->crypt();
	}

	// Create a new RuntimeInstruction with a given key
	RuntimeInstruction(std::vector<std::byte> bytes, std::vector<std::byte> key) {
		this->bytes = bytes;
		this->key = key;
	}

	RuntimeInstruction() {}
private:
	std::vector<std::byte> bytes;
	std::vector<std::byte> key;
};

struct Runtime {
public:
	std::vector<std::byte> serialize() const {
		std::vector<std::byte> serialized;

		const std::size_t instrsCount = this->runtimeInstrs.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&instrsCount), reinterpret_cast<const std::byte*>(&instrsCount) + sizeof(instrsCount));

		for (const auto& [rva, instr] : this->runtimeInstrs) {
			const uint32_t rvaSize = sizeof(rva);
			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&rva), reinterpret_cast<const std::byte*>(&rva) + rvaSize);

			const std::vector<std::byte> instrBytes = instr.getBytes();
			const std::size_t instrSize = instrBytes.size();
			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&instrSize), reinterpret_cast<const std::byte*>(&instrSize) + sizeof(instrSize));
			serialized.insert(serialized.end(), instrBytes.begin(), instrBytes.end());

			const std::vector<std::byte> keyBytes = instr.getKey();
			const std::size_t keySize = keyBytes.size();

			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&keySize), reinterpret_cast<const std::byte*>(&keySize) + sizeof(keySize));
			serialized.insert(serialized.end(), keyBytes.begin(), keyBytes.end());
		}

		const uint32_t oldRVASize = sizeof(this->oldRVA);
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&oldRVASize), reinterpret_cast<const std::byte*>(&oldRVASize) + sizeof(oldRVASize));
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&this->oldRVA), reinterpret_cast<const std::byte*>(&this->oldRVA) + oldRVASize);

		return serialized;
	}

	void deserialize(const std::vector<std::byte> serialized) {
		std::size_t offset = 0;

		std::size_t instrsCount;
		std::memcpy(&instrsCount, &serialized[offset], sizeof(instrsCount));
		offset += sizeof(instrsCount);

		for (uint32_t i = 0; i < instrsCount; i++) {
			std::uintptr_t rva;
			std::memcpy(&rva, &serialized[offset], sizeof(rva));
			offset += sizeof(rva);

			std::size_t instrSize;
			std::memcpy(&instrSize, &serialized[offset], sizeof(instrSize));
			offset += sizeof(instrSize);
			std::vector<std::byte> instrBytes(&serialized[offset], &serialized[offset] + instrSize);
			offset += instrSize;

			std::size_t keySize;
			std::memcpy(&keySize, &serialized[offset], sizeof(keySize));
			offset += sizeof(keySize);

			std::vector<std::byte> keyBytes(&serialized[offset], &serialized[offset] + keySize);
			offset += keySize;

			RuntimeInstruction runtimeInstr(instrBytes, keyBytes);
			this->runtimeInstrs.emplace(rva, runtimeInstr);
		}

		uint32_t oldRVASize;
		std::memcpy(&oldRVASize, &serialized[offset], sizeof(oldRVASize));
		offset += sizeof(oldRVASize);
		std::memcpy(&this->oldRVA, &serialized[offset], oldRVASize);
		offset += oldRVASize;
	}

	inline void addInstruction(std::uintptr_t rva, RuntimeInstruction runtimeInstr) {
		this->runtimeInstrs.emplace(rva, runtimeInstr);
	}

	inline bool hasInstruction(std::uintptr_t rva) {
		return this->runtimeInstrs.contains(rva);
	}

	inline RuntimeInstruction& getInstruction(std::uintptr_t rva) {
		return this->runtimeInstrs[rva];
	}

	std::uintptr_t getOldRVA() {
		if (this->oldRVA != 0) {
			const std::uintptr_t oldRVA = this->oldRVA;
			this->oldRVA = 0;
			return oldRVA;
		}
		return 0;
	}

	inline void setOldRVA(std::uintptr_t rva) {
		this->oldRVA = rva;
	}

	Runtime() {}
private:
	std::map<std::uintptr_t, RuntimeInstruction> runtimeInstrs;
	std::uintptr_t oldRVA = 0;
};

struct Payload {
	inline void encrypt() {
		for (std::size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	inline void decrypt() {
		for (std::size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	inline const std::vector<std::byte> getBytes() const {
		return this->bytes;
	}

	inline const std::vector<std::byte> getKey() const {
		return this->key;
	}

	const std::vector<std::byte> serialize() const {
		std::vector<std::byte> serialized;

		const std::size_t bytesSize = this->bytes.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&bytesSize), reinterpret_cast<const std::byte*>(&bytesSize) + sizeof(bytesSize));
		serialized.insert(serialized.end(), this->bytes.begin(), this->bytes.end());

		const std::size_t keySize = this->key.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&keySize), reinterpret_cast<const std::byte*>(&keySize) + sizeof(keySize));
		serialized.insert(serialized.end(), this->key.begin(), this->key.end());

		return serialized;
	}

	void deserialize(const std::vector<std::byte> serialized) {
		std::size_t offset = 0;

		std::size_t bytesSize;
		std::memcpy(&bytesSize, &serialized[0], sizeof(bytesSize));
		offset += sizeof(bytesSize);
		this->bytes.insert(this->bytes.begin(), &serialized[offset], &serialized[offset] + bytesSize);
		offset += bytesSize;

		std::size_t keySize;
		std::memcpy(&keySize, &serialized[offset], sizeof(keySize));
		offset += sizeof(keySize);
		this->key.insert(this->key.begin(), &serialized[offset], &serialized[offset] + keySize);
	}

	template<typename T>
	T* relativeToAbsolute(const std::uintptr_t rva) {
		std::byte* pImage = &this->bytes[0];
		IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pImage);
		IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pImage + dosHeader->e_lfanew);
		const auto sections = IMAGE_FIRST_SECTION(ntHeader);

		for (std::size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
			const auto& section = sections[i];

			if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData) {
				return (T*)(pImage + (rva - section.VirtualAddress + section.PointerToRawData));
			}
		}
		return (T*)(pImage + rva);
	}

	Payload(const std::vector<std::byte> bytes) {
		this->bytes = bytes;

		std::random_device rd;
		std::mt19937 gen(rd());

		for (std::size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<std::byte>(gen()));
		}
		this->encrypt();
	}

	Payload() {}
private:
	std::vector<std::byte> bytes;
	std::vector<std::byte> key;
};