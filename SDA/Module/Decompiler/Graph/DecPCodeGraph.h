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
		FunctionPCodeGraph* m_funcGraph;
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

		PCodeBlock(FunctionPCodeGraph* asmGraph, int64_t minOffset, int64_t maxOffset)
			: m_funcGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset), ID((int)(minOffset >> 8))
		{}

		FunctionPCodeGraph* getFuncGraph() {
			return m_funcGraph;
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

		PCode::Instruction* getLastInstruction() {
			return *std::prev(m_instructions.end());
		}

		void printDebug(void* addr, const std::string& tabStr, bool extraInfo, bool pcode) {
			ZydisFormatter formatter;
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

			ZyanU64 runtime_address = (ZyanU64)addr;
			for (auto instr : m_instructions) {
				std::string prefix = tabStr + "0x" + Generic::String::NumberToHex(runtime_address + instr->getOriginalInstructionOffset());
				if (!instr->m_originalView.empty())
					printf("%s %s\n", prefix.c_str(), instr->m_originalView.c_str());
				if (pcode) {
					prefix += ":" + std::to_string(instr->getOrderId()) + "(" + Generic::String::NumberToHex(instr->getOffset()).c_str() + ")";
					printf("\t%s %s", prefix.c_str(), instr->printDebug().c_str());
					if (instr->m_id == PCode::InstructionId::UNKNOWN)
						printf(" <------------------------------------------------ ");
					printf("\n");
				}
			}

			if (extraInfo) {
				printf("Level: %i\n", m_level);
				if (m_nextNearBlock != nullptr)
					printf("Next near: %s\n", Generic::String::NumberToHex(m_nextNearBlock->getMinOffset()).c_str());
				if (m_nextFarBlock != nullptr)
					printf("Next far: %s\n", Generic::String::NumberToHex(m_nextFarBlock->getMinOffset()).c_str());
			}
		}
	};

	// pcode graph (consisted of PCode connected blocks) for a function
	class FunctionPCodeGraph
	{
		ImagePCodeGraph* m_imagePCodeGraph;
		PCodeBlock* m_startBlock = nullptr;
		std::map<int64_t, PCodeBlock*> m_offsetToBlock;
		std::map<PCode::Instruction*, DataValue> m_constValues;
	public:

		FunctionPCodeGraph(ImagePCodeGraph* imagePCodeGraph)
			: m_imagePCodeGraph(imagePCodeGraph)
		{}

		void addBlock(int64_t offset, PCodeBlock* block) {
			m_offsetToBlock[offset] = block;
			if (!m_startBlock)
				m_startBlock = block;
		}

		std::map<int64_t, PCodeBlock*>& getBlocks() {
			return m_offsetToBlock;
		}

		PCodeBlock* getStartBlock() {
			return m_startBlock;
		}

		std::map<PCode::Instruction*, PCode::DataValue>& getConstValues() {
			return m_constValues;
		}

		void printDebug(void* addr) {
			for (auto block : m_offsetToBlock) {
				block.second->printDebug(addr, "", true, true);
				puts("==================");
			}
		}
	};

	// pcode graph (consisted of NON-connected function graphs in final state) for a whole program
	class ImagePCodeGraph
	{
		std::list<FunctionPCodeGraph*> m_funcGraphList;
		std::map<int64_t, PCodeBlock> m_offsetToBlock;
	public:

		ImagePCodeGraph()
		{}

		FunctionPCodeGraph* createFunctionGraph() {
			auto graph = new FunctionPCodeGraph(this);
			m_funcGraphList.push_back(graph);
			return graph;
		}

		PCodeBlock* createBlock(FunctionPCodeGraph* graph, int64_t offset) {
			m_offsetToBlock.insert(std::make_pair(offset, PCodeBlock(graph, offset, offset)));
			auto newBlock = &m_offsetToBlock[offset];
			graph->addBlock(offset, newBlock);
			return newBlock;
		}

		std::list<FunctionPCodeGraph*>& getFunctionGraphList() {
			return m_funcGraphList;
		}

		PCodeBlock* getBlockAtOffset(int64_t offset, bool halfInterval = true) {
			auto it = std::prev(m_offsetToBlock.upper_bound(offset));
			if (it != m_offsetToBlock.end()) {
				bool boundUp = halfInterval ? (offset < it->second.getMaxOffset()) : (offset <= it->second.getMaxOffset());
				if (boundUp && offset >= it->second.getMinOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}
	};
};