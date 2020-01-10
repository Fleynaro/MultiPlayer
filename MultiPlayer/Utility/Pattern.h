#pragma once




#include "main.h"
#include "Generic.h"
#include "MemoryHandle.h"
#include <future>


namespace Memory
{
	class Pattern
	{
	public:
		//typedef std::byte Byte;
		typedef unsigned short Byte;
		enum ByteName : Byte {
			MASK_BYTE = 0x100
		};

		Pattern() { ; }

		Pattern(std::string pattern)
		{
			this->m_pattern = pattern;
			transformToNormal();
		}

		Byte getByte(std::size_t index)
		{
			if (m_pattern.at(getPosByIndex(index)) == '?')
				return MASK_BYTE;

			return (Byte)(
				hexToInt(m_pattern.at(getPosByIndex(index))) * 16LL + hexToInt(m_pattern.at(getPosByIndex(index) + 1LL))
			);
		}

		std::size_t getByteCount()
		{
			return m_pattern.length() / 3 + 1U;
		}

		std::size_t getBegin() const
		{
			return m_begin;
		}

		std::string getStr() const
		{
			return m_pattern;
		}

		void reverse()
		{
			std::reverse(m_pattern.begin(), m_pattern.end());
		}

		void transformToNormal()
		{
			Generic::String::Replace(m_pattern, " ? ", " ?? ");
			Generic::String::Replace(m_pattern, " ? ", " ?? ");
			Generic::String::Replace(m_pattern, " *? ", " *?? ");

			auto beginPos = m_pattern.find_first_of('*');
			if (beginPos != std::string::npos) {
				m_begin = beginPos / 3;
				Generic::String::Replace(m_pattern, "*", "");
			}
		}
	private:
		std::string m_pattern;
		std::size_t m_begin = 0;

		std::size_t getPosByIndex(std::size_t index)
		{
			return index * 3LL;
		}

		static int hexToInt(char symbol)
		{
			if ('0' <= symbol && symbol <= '9')
				return symbol - '0';
			if ('A' <= symbol && symbol <= 'F')
				return symbol - 'A' + 0xA;
			if ('a' <= symbol && symbol <= 'f')
				return symbol - 'a' + 0xA;

			return 0;
		}
	};


	class FoundPattern
	{
		friend class FoundPatternList;
	public:
		using Handler = std::function <void(FoundPattern&)>;
		using ByteArr = std::unique_ptr<Pattern::Byte[]>;

		FoundPattern(Pattern pattern) : m_pattern(pattern)
		{
			m_size = pattern.getByteCount();
			
			transformToBytes();
		}

		FoundPattern(Pattern pattern, Handler handler, bool reverseSearching = false) : FoundPattern(pattern)
		{
			setHandler(handler);
			if (reverseSearching) {
				reverseSearchingEnable();
			}
		}

		FoundPattern(Pattern pattern, Handler handler, FoundPattern *next) : FoundPattern(pattern, handler)
		{
			setNext(next);
		}

		~FoundPattern()
		{
			delete[] m_bytes;
		}

		void setHandler(Handler handler)
		{
			m_handler = handler;
		}

		void setNext(FoundPattern* next)
		{
			m_next = next;
		}

		void reverseSearchingEnable()
		{
			m_reverseSearching = true;
		}

		Pattern& getPattern()
		{
			return m_pattern;
		}

		const Pattern& getConstPattern() const
		{
			return m_pattern;
		}

		//find address by pattern
		void scan(Region region = Module::main())
		{
			std::uintptr_t
				i = region.base().as<std::uintptr_t>(),
				end = region.end().as<std::uintptr_t>();

			if (!is_SSE42_Supported())
			{
				for (; i != end; i++) {
					if (considerMatch(i))
					{
						successMatch(i);
						return;
					}
				}
			}
			else {
				__declspec(align(16)) char desiredMask[16] = { 0 };

				for (int i = 0; i < m_size; i++) {
					desiredMask[i / 8] |= ((m_bytes[i] == Pattern::ByteName::MASK_BYTE) ? 0 : 1) << (i % 8);
				}

				__m128i mask = _mm_load_si128(reinterpret_cast<const __m128i*>(desiredMask));
				__m128i comparand = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_bytes));

				for (; i <= end; i++) {

					__m128i value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(i));
					__m128i result = _mm_cmpestrm(value, 16, comparand, (int)m_size, _SIDD_CMP_EQUAL_EACH);

					// As the result can match more bits than the mask contains
					__m128i matches = _mm_and_si128(mask, result);
					__m128i equivalence = _mm_xor_si128(mask, matches);

					if (_mm_test_all_zeros(equivalence, equivalence)) {
						successMatch(i);
						return;
					}
				}
			}

			failMatch();
		}

		Handle& getResult() {
			return m_result;
		}

		void setResult(const Handle& handle) {
			m_result = handle;
		}

		bool hasResult() {
			return m_result.isValid();
		}

		//check next m_size bytes to be match with
		bool considerMatch(std::uintptr_t offset)
		{
			byte* ptr = reinterpret_cast<byte*>(offset);

			for (std::size_t i = 0; i < m_size; i++) {
				if (m_bytes[i] == Pattern::ByteName::MASK_BYTE) {
					continue;
				}

				if (m_bytes[i] != ptr[i]) {
					return false;
				}
			}
			return true;
		}

		//if found success
		void successMatch(std::uintptr_t offset)
		{
			offset += getPattern().getBegin();
			setResult(Handle(offset));
			if (m_handler != NULL)
				m_handler(*this);
		}
	private:
		Pattern m_pattern;
		FoundPattern *m_next = nullptr;
		Handler m_handler = NULL;
		Pattern::Byte *m_bytes = nullptr;
		std::size_t m_size;
		bool m_reverseSearching = false;
		Handle m_result;

		//if found fail
		void failMatch(FoundPattern *next = nullptr)
		{
			if (m_next != nullptr) {
				next = m_next;
				return;
			}
			setResult(Handle());
			if (m_handler != NULL)
				m_handler(*this);
		}

		void transformToBytes()
		{
			m_bytes = new Pattern::Byte[m_size];
			for (std::size_t i = 0; i != m_size; i++) {
				m_bytes[i] = m_pattern.getByte(i);
			}
		}

		bool is_SSE42_Supported()
		{
			int cpuid[4];
			__cpuid(cpuid, 0);

			bool sse42 = false;
			if (m_size <= 16) {

				if (cpuid[0] >= 1) {

					__cpuidex(cpuid, 1, 0);

					sse42 = (cpuid[2] & (1 << 20)) == 1;
				}
			}
			return sse42;
		}
	};



	class FoundPatternList
	{
	public:
		using List = std::list<FoundPattern*>;
		using TableList = std::list<FoundPattern*>;
		using FoundSet = std::set<FoundPattern*>;

		enum TableElem {
			ELEMENT_NOT = 1,
			ELEMENT_HIT = 2
		};

		FoundPatternList(List& patternList)
		{
			m_patternList = patternList;
		}

		~FoundPatternList()
		{
			destroyTable();
		}

		//add a new found pattern
		void add(FoundPattern *pattern)
		{
			m_patternList.push_back(pattern);
		}

		//remove the pattern
		void remove(const FoundPattern& pattern)
		{
			//m_patternList.remove(pattern);
			/*m_patternList.erase(
				std::remove(m_patternList.begin(), m_patternList.end(), &pattern),
				m_patternList.end()
			);*/
		}

		//get count of found patterns
		std::size_t getSize()
		{
			return m_patternList.size();
		}

		//begin search
		void scan(Region region = Module::main())
		{
			if (m_patternList.empty())
				return;

			std::uintptr_t
				begin = region.base().as<std::uintptr_t>(),
				moduleSize = region.size();
			
			//creating a table and its filling to optimize search
			createTable();
			fillTable(false);
			short state = 0;
			byte* ptr = reinterpret_cast<byte*>(begin);
			for (std::size_t i = 0; i != moduleSize; i++) {
				Pattern::Byte byte = ptr[i];
				bool isCompare = false;
				if (check(byte, state, isCompare)) {
					if (isCompare) {
						if (compare(begin + i - state, byte, state)) {
							state = -1;
						}
					}
					if (state == m_tableSize - 1)
						state = 0;
					else state++;
				}
				else {
					i = i - state;
					state = 0;
				}
			}

			//recreate table and repeat for reverse patterns
			destroyTable();
			createTable();
			fillTable(true);
			state = 0;
			for (std::size_t i = moduleSize - 1; i != -1; i--) {
				Pattern::Byte byte = ptr[i];
				bool isCompare = false;
				if (check(byte, state, isCompare)) {
					if (state > 4) {
						int lll = 333;
					}
					if (isCompare) {
						if (compare(begin + i, byte, state)) {
							state = -1;
						}
					}
					if (state == m_tableSize - 1)
						state = 0;
					else state++;
				}
				else {
					i = i + state;
					state = 0;
				}
			}


			//handle not found patterns
			callFailPatternHandles();
		}
	private:
		List m_patternList;
		FoundSet m_found;
		TableList*** m_table = nullptr;
		std::size_t m_tableSize = 0;

		//check if pattern has been found
		bool isPatternFound(FoundPattern* pattern) {
			return pattern->hasResult();
		}

		//call handles of not found patterns
		void callFailPatternHandles()
		{
			auto newList = Memory::FoundPatternList::List();
			for (auto p : m_patternList) {
				if (!isPatternFound(p)) {
					FoundPattern* next = nullptr;
					p->failMatch(next);
					if (next != nullptr) {
						newList.push_back(next);
					}
				}
			}

			if (!newList.empty()) {
				Memory::FoundPatternList newPatternList(newList);
				newPatternList.scan();
				m_found.merge(newPatternList.m_found);
			}
		}

		//compare the byte depending on the current state
		inline bool check(Pattern::Byte &byte, short state, bool &compare)
		{
			bool is_mask_byte = false;
			do
			{
				if (byte == Pattern::ByteName::MASK_BYTE) {
					is_mask_byte = true;
				}

				if (m_table[state][byte] != (TableList*)TableElem::ELEMENT_NOT) {
					if (m_table[state][byte] != (TableList*)TableElem::ELEMENT_HIT) {
						compare = true;
					} else compare = false;
					return true;
				}
				else if (is_mask_byte) {
					return false;
				}

				byte = Pattern::ByteName::MASK_BYTE;
			} while (!is_mask_byte);

			return true;
		}

		//compare all patterns
		inline bool compare(std::uintptr_t beginHit, Pattern::Byte byte, short state)
		{
			for (auto p : *m_table[state][byte]) {
				if (p->considerMatch(beginHit))
				{
					p->successMatch(beginHit);

					m_table[state][byte]->remove(p);
					if (m_table[state][byte]->empty()) {
						delete m_table[state][byte];
						m_table[state][byte] = (TableList*)TableElem::ELEMENT_HIT;
					}
					return true;
				}
			}
			return false;
		}

		std::size_t getMaxPatternSize()
		{
			std::size_t maxSize = 0;
			for (auto p : m_patternList) {
				if (maxSize < p->getPattern().getByteCount()) {
					maxSize = p->getPattern().getByteCount();
				}
			}
			return maxSize;
		}

		void createTable()
		{
			if (m_tableSize != 0) return;

			m_tableSize = getMaxPatternSize();
			m_table = new TableList** [m_tableSize];

			for (int i = 0; i != m_tableSize; i++) {
				m_table[i] = new TableList* [256 + 1];

				for (int j = 0; j != 256 + 1; j++) {
					m_table[i][j] = (TableList*)TableElem::ELEMENT_NOT;
				}
			}
		}

		void fillTable(bool reverse)
		{
			for (auto p : m_patternList) {
				if (p->m_reverseSearching != reverse || isPatternFound(p))
					continue;

				if (reverse) {
					p->getPattern().reverse();
				}

				std::size_t lastIndex = p->getPattern().getByteCount() - 1LL;
				for (std::size_t i = 0; i != lastIndex; i++) {
					Pattern::Byte byte = p->getPattern().getByte(i);
					if (m_table[i][byte] == (TableList*)TableElem::ELEMENT_NOT)
						m_table[i][byte] = (TableList*)TableElem::ELEMENT_HIT;
				}
				
				Pattern::Byte lastByte = p->getPattern().getByte(lastIndex);
				if (m_table[lastIndex][lastByte] == (TableList*)TableElem::ELEMENT_NOT || m_table[lastIndex][lastByte] == (TableList*)TableElem::ELEMENT_HIT) {
					m_table[lastIndex][lastByte] = new TableList;
				}
				m_table[lastIndex][lastByte]->push_back(p);

				if (reverse) {
					p->getPattern().reverse();
				}
			}
		}

		void destroyTable()
		{
			if (m_tableSize == 0) return;

			for (int i = 0; i != m_tableSize; i++) {
				delete[] m_table[i];
			}
			delete[] m_table;
			m_tableSize = 0;
		}
	};
}