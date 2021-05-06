#pragma once
#include "../PCode/DecPCode.h"
#include "../PCode/DecPCodeConstValueCalc.h"
#include <Utility/Generic.h>

namespace CE::Decompiler
{
	class ImagePCodeGraph;
	class FunctionPCodeGraph;

	// pcode graph for a non-branched block
	class PCodeBlock
	{
		int64_t m_minOffset;
		int64_t m_maxOffset;
		std::list<PCode::Instruction*> m_instructions; // content of the block
		PCodeBlock* m_nextNearBlock = nullptr;
		PCodeBlock* m_nextFarBlock = nullptr;
	public:
		int ID = 0;
		int m_level = 0;
		std::list<PCodeBlock*> m_blocksReferencedTo;

		PCodeBlock() = default;

		PCodeBlock(int64_t minOffset, int64_t maxOffset)
			: m_minOffset(minOffset), m_maxOffset(maxOffset), ID((int)(minOffset >> 8))
		{}

		void removeRefBlock(PCodeBlock* block) {
			m_blocksReferencedTo.remove(block);
		}

		void disconnect() {
			for (auto nextBlock : getNextBlocks()) {
				nextBlock->removeRefBlock(this);
			}
			m_nextNearBlock = m_nextFarBlock = nullptr;
		}

		std::list<PCode::Instruction*>& getInstructions() {
			return m_instructions;
		}

		int64_t getMinOffset() {
			return m_minOffset;
		}

		int64_t getMaxOffset() { // todo: auto-calculated?
			return m_maxOffset;
		}

		void setMaxOffset(int64_t offset) {
			m_maxOffset = offset;
		}

		void removeNextBlock(PCodeBlock* nextBlock) {
			if (nextBlock == m_nextNearBlock)
				m_nextNearBlock = nullptr;
			if (nextBlock == m_nextFarBlock)
				m_nextFarBlock = nullptr;
		}

		void setNextNearBlock(PCodeBlock* nextBlock) {
			m_nextNearBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		void setNextFarBlock(PCodeBlock* nextBlock) {
			m_nextFarBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		PCodeBlock* getNextNearBlock() {
			return m_nextNearBlock;
		}

		PCodeBlock* getNextFarBlock() {
			return m_nextFarBlock;
		}

		std::list<PCodeBlock*> getNextBlocks() {
			std::list<PCodeBlock*> nextBlocks;
			if (m_nextFarBlock) {
				nextBlocks.push_back(m_nextFarBlock);
			}
			if (m_nextNearBlock) {
				nextBlocks.push_back(m_nextNearBlock);
			}
			return nextBlocks;
		}

		PCode::Instruction* getLastInstruction() {
			return *std::prev(m_instructions.end());
		}

		std::string printDebug(void* addr, const std::string& tabStr, bool extraInfo, bool pcode) {
			std::string result;

			ZyanU64 runtime_address = (ZyanU64)addr;
			for (auto instr : m_instructions) {
				std::string prefix = tabStr + "0x" + Generic::String::NumberToHex(runtime_address + instr->getOriginalInstructionOffset());
				if (!instr->m_originalView.empty())
					result += prefix + " " + instr->m_originalView + "\n";
				if (pcode) {
					prefix += ":" + std::to_string(instr->getOrderId()) + "(" + Generic::String::NumberToHex(instr->getOffset()) + ")";
					result += "\t" + prefix + " " + instr->printDebug();
					if (instr->m_id == PCode::InstructionId::UNKNOWN)
						result += " <------------------------------------------------ ";
					result += "\n";
				}
			}

			if (extraInfo) {
				result += "Level: "+ std::to_string(m_level) +"\n";
				if (m_nextNearBlock != nullptr)
					result += "Next near: "+ Generic::String::NumberToHex(m_nextNearBlock->getMinOffset()) +"\n";
				if (m_nextFarBlock != nullptr)
					result += "Next far: " + Generic::String::NumberToHex(m_nextFarBlock->getMinOffset()) + "\n";
			}

			return result;
		}
	};

	// pcode graph (consisted of PCode connected blocks) for a function
	class FunctionPCodeGraph
	{
		ImagePCodeGraph* m_imagePCodeGraph;
		PCodeBlock* m_startBlock = nullptr;
		std::set<PCodeBlock*> m_blocks;
		std::list<FunctionPCodeGraph*> m_nonVirtFuncCalls;
		std::list<FunctionPCodeGraph*> m_virtFuncCalls;
		std::map<PCode::Instruction*, DataValue> m_constValues;
	public:

		FunctionPCodeGraph(ImagePCodeGraph* imagePCodeGraph)
			: m_imagePCodeGraph(imagePCodeGraph)
		{}

		void setStartBlock(PCodeBlock* block) {
			m_startBlock = block;
		}

		auto& getNonVirtFuncCalls() {
			return m_nonVirtFuncCalls;
		}

		auto& getVirtFuncCalls() {
			return m_virtFuncCalls;
		}

		auto& getBlocks() {
			return m_blocks;
		}

		PCodeBlock* getStartBlock() {
			return m_startBlock;
		}

		std::map<PCode::Instruction*, PCode::DataValue>& getConstValues() {
			return m_constValues;
		}

		void printDebug(void* addr) {
			for (auto block : m_blocks) {
				puts(block->printDebug(addr, "", true, true).c_str());
				puts("==================");
			}
		}
	};

	// pcode graph (consisted of NON-connected function graphs in final state) for a whole program
	class ImagePCodeGraph
	{
		std::list<FunctionPCodeGraph*> m_funcGraphList;
		std::map<int64_t, PCodeBlock> m_blocks;
	public:

		ImagePCodeGraph()
		{}

		FunctionPCodeGraph* createFunctionGraph() {
			auto graph = new FunctionPCodeGraph(this);
			m_funcGraphList.push_back(graph);
			return graph;
		}

		PCodeBlock* createBlock(int64_t offset) {
			m_blocks.insert(std::make_pair(offset, PCodeBlock(offset, offset)));
			auto newBlock = &m_blocks[offset];
			return newBlock;
		}

		auto& getFunctionGraphList() {
			return m_funcGraphList;
		}

		FunctionPCodeGraph* getFirstFunctionGraph() {
			return *m_funcGraphList.begin();
		}

		PCodeBlock* getBlockAtOffset(int64_t offset, bool halfInterval = true) {
			auto it = std::prev(m_blocks.upper_bound(offset));
			if (it != m_blocks.end()) {
				bool boundUp = halfInterval ? (offset < it->second.getMaxOffset()) : (offset <= it->second.getMaxOffset());
				if (boundUp && offset >= it->second.getMinOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}
	};
};