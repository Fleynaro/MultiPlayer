#pragma once
#include <main.h>

class ObjectHash
{
public:
	using Hash = int64_t;

	ObjectHash(Hash hash = 0L, std::string hashContent = "")
		: m_hash(hash), m_hashContent(hashContent)
	{}

	void addValue(std::string value) {
		m_hashContent += "{" + value + "}";
	}

	void addValue(int value) {
		addValue((int64_t)value);
	}

	void addValue(int64_t value) {
		addValue(std::to_string(value));
	}

	Hash getHash() {
		return m_hash * 31 + hash(m_hashContent);
	}

	void join(ObjectHash& hash) {
		m_hash = m_hash * 31 + hash.getHash();
	}

	void add(ObjectHash& hash) {
		m_hash = m_hash + hash.getHash();
	}

	static Hash hash(std::string string) {
		Hash h = 1125899906842597L;
		for (int i = 0; i < string.length(); i++) {
			h = 31 * h + string.at(i);
		}
		return h;
	}
private:
	std::string m_hashContent;
	Hash m_hash;
};