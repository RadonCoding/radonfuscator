#include <cstdint>
#include <vector>
#include <random>
#include <map>
#include <iostream>
#include <Windows.h>

using namespace std;

constexpr size_t KEY_SIZE = 32;

class RuntimeInstruction {
public:
	inline void crypt() {
		for (size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	inline const std::vector<std::byte>& getBytes() const {
		return this->bytes;
	}

	inline const std::vector<std::byte>& getKey() const {
		return this->key;
	}

	RuntimeInstruction(std::vector<std::byte> bytes) {
		this->bytes = bytes;

		std::random_device rd;
		std::mt19937_64 gen(rd());
		std::uniform_int_distribution<uint64_t> dist(0, 255);

		for (size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<std::byte>(dist(gen)));
		}
		this->crypt();
	}

	RuntimeInstruction(std::vector<std::byte> bytes, std::vector<std::byte> key) {
		this->bytes = bytes;
		this->key = key;
	}

	RuntimeInstruction() {}
private:
	std::vector<std::byte> bytes;
	std::vector<std::byte> key;
};

class Runtime {
public:
	std::vector<std::byte> serialize() const {
		std::vector<std::byte> serialized;

		const size_t instrCount = this->runtimeInstrs.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&instrCount), reinterpret_cast<const std::byte*>(&instrCount) + sizeof(instrCount));

		for (const auto& [rva, instr] : this->runtimeInstrs) {
			const uint32_t rvaSize = sizeof(rva);
			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&rva), reinterpret_cast<const std::byte*>(&rva) + rvaSize);

			const std::vector<std::byte>& instrBytes = instr.getBytes();
			const size_t instrSize = instrBytes.size();
			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&instrSize), reinterpret_cast<const std::byte*>(&instrSize) + sizeof(instrSize));
			serialized.insert(serialized.end(), instrBytes.data(), instrBytes.data() + instrBytes.size());

			const std::vector<std::byte>& keyBytes = instr.getKey();
			const size_t keySize = keyBytes.size();
			serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&keySize), reinterpret_cast<const std::byte*>(&keySize) + sizeof(keySize));
			serialized.insert(serialized.end(), keyBytes.data(), keyBytes.data() + keyBytes.size());
		}
		const uint32_t oldRVASize = sizeof(this->oldRVA);
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&oldRVASize), reinterpret_cast<const std::byte*>(&oldRVASize) + sizeof(oldRVASize));
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&this->oldRVA), reinterpret_cast<const std::byte*>(&this->oldRVA) + oldRVASize);

		return serialized;
	}

	void deserialize(const std::vector<std::byte>& serialized) {
		size_t offset = 0;

		size_t instrCount;
		std::memcpy(&instrCount, &serialized[offset], sizeof(instrCount));
		offset += sizeof(instrCount);

		for (uint32_t i = 0; i < instrCount; i++) {
			uintptr_t rva;
			std::memcpy(&rva, &serialized[offset], sizeof(rva));
			offset += sizeof(rva);

			size_t instrSize;
			std::memcpy(&instrSize, &serialized[offset], sizeof(instrSize));
			offset += sizeof(instrSize);
			std::vector<std::byte> instrBytes(&serialized[offset], &serialized[offset] + instrSize);
			offset += instrSize;

			size_t keySize;
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

	inline void addInstruction(uintptr_t rva, RuntimeInstruction runtimeInstr) {
		this->runtimeInstrs.emplace(rva, runtimeInstr);
	}

	inline bool hasInstruction(uintptr_t rva) {
		return this->runtimeInstrs.contains(rva);
	}

	inline RuntimeInstruction& getInstruction(uintptr_t rva) {
		return this->runtimeInstrs[rva];
	}

	uintptr_t getOldRVA() {
		if (this->oldRVA != 0) {
			const uintptr_t oldRVA = this->oldRVA;
			this->oldRVA = 0;
			return oldRVA;
		}
		return 0;
	}

	inline void setOldRVA(uintptr_t rva) {
		this->oldRVA = rva;
	}

	Runtime() {}
private:
	std::map<uintptr_t, RuntimeInstruction> runtimeInstrs;
	uintptr_t oldRVA = 0;
};

class Payload {
public:
	inline void crypt() {
		for (size_t i = 0; i < this->bytes.size(); i++) {
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

		const size_t bytesSize = this->bytes.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&bytesSize), reinterpret_cast<const std::byte*>(&bytesSize) + sizeof(bytesSize));
		serialized.insert(serialized.end(), this->bytes.begin(), this->bytes.end());

		const size_t keySize = this->key.size();
		serialized.insert(serialized.end(), reinterpret_cast<const std::byte*>(&keySize), reinterpret_cast<const std::byte*>(&keySize) + sizeof(keySize));
		serialized.insert(serialized.end(), this->key.begin(), this->key.end());

		return serialized;
	}

	void deserialize(const std::vector<std::byte> serialized) {
		size_t offset = 0;

		size_t bytesSize;
		std::memcpy(&bytesSize, &serialized[0], sizeof(bytesSize));
		offset += sizeof(bytesSize);
		this->bytes.insert(this->bytes.begin(), &serialized[offset], &serialized[offset] + bytesSize);
		offset += bytesSize;

		size_t keySize;
		std::memcpy(&keySize, &serialized[offset], sizeof(keySize));
		offset += sizeof(keySize);
		this->key.insert(this->key.begin(), &serialized[offset], &serialized[offset] + keySize);
	}

	Payload(const std::vector<std::byte> bytes) {
		this->bytes = bytes;

		std::random_device rd;
		std::mt19937 gen(rd());

		for (size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<std::byte>(gen()));
		}
		this->crypt();
	}

	Payload() {}
private:
	std::vector<std::byte> bytes;
	std::vector<std::byte> key;
};