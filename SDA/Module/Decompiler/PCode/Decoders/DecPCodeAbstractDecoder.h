#pragma once
#include "../DecRegisterFactory.h"
#include "../../DecWarningContainer.h"

namespace CE::Decompiler::PCode
{
	class AbstractDecoder : public IWarningGenerator
	{
	public:
		AbstractDecoder(WarningContainer* warningContainer)
			: m_warningContainer(warningContainer)
		{}

		void decode(void* addr, int offset, int maxSize = 0x0) {
			m_addr = addr;
			m_curOffset = offset;
			m_curOrderId = 0x0;
			m_curInstrLength = 0x0;
			m_maxSize = maxSize;
			clear();
			tryDecode(addr, offset);
		}

		void clear() {
			m_result.clear();
		}

		std::list<Instruction*>& getDecodedPCodeInstructions() {
			return m_result;
		}

		void deleteDecodedPCodeInstructions() {
			for (auto instr : getDecodedPCodeInstructions()) {
				delete instr;
			}
		}

		int getInstructionLength() {
			return m_curInstrLength;
		}

		WarningContainer* getWarningContainer() override {
			return m_warningContainer;
		}
	protected:
		WarningContainer* m_warningContainer;
		std::list<Instruction*> m_result;
		void* m_addr = nullptr;
		int m_curOffset = 0x0;
		int m_curOrderId = 0;
		int m_curInstrLength = 0x0;
		int m_maxSize = 0x0;

		virtual void tryDecode(void* addr, int offset) = 0;
	};
};