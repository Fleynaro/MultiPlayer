#pragma once
#include "DecPCode.h"

namespace CE::Decompiler
{
	using InstructionMapType = std::map<int, ZydisDecodedInstruction>;

	class AsmGraph;
	class AsmGraphBlock
	{
	public:
		int ID = 0;
		int m_level = 0;
		std::list<AsmGraphBlock*> m_blocksReferencedTo;

		AsmGraphBlock(AsmGraph* asmGraph, int64_t minOffset, int64_t maxOffset)
			: m_asmGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset), ID((int)(minOffset >> 8))
		{}

		std::list<PCode::Instruction*>& getInstructions() {
			return m_instructions;
		}

		int64_t getMinOffset() {
			return m_minOffset;
		}

		int64_t getMaxOffset() {
			return m_maxOffset;
		}

		void setNextNearBlock(AsmGraphBlock* nextBlock) {
			m_nextNearBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		void setNextFarBlock(AsmGraphBlock* nextBlock) {
			m_nextFarBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		AsmGraphBlock* getNextNearBlock() {
			return m_nextNearBlock;
		}

		AsmGraphBlock* getNextFarBlock() {
			return m_nextFarBlock;
		}

		PCode::Instruction* getLastInstruction() {
			return *std::prev(m_instructions.end());
		}

		void printDebug(void* addr, const std::string& tabStr, bool extraInfo, bool pcode);
	private:
		AsmGraph* m_asmGraph;
		int64_t m_minOffset;
		int64_t m_maxOffset;
		std::list<PCode::Instruction*> m_instructions;
		AsmGraphBlock* m_nextNearBlock = nullptr;
		AsmGraphBlock* m_nextFarBlock = nullptr;
	};

	class AsmGraph
	{
		friend class AsmGraphBlock;
	public:
		std::map<int64_t, AsmGraphBlock> m_blocks;
		std::list<PCode::Instruction*> m_instructions;

		AsmGraph(std::list<PCode::Instruction*> instructions)
			: m_instructions(instructions)
		{}

		void build() {
			std::map<int64_t, bool> split_offsets;
			std::list<std::pair<int64_t, int64_t>> jump_dirs;

			for (auto instr : m_instructions) {
				if (PCode::Instruction::IsBranching(instr->m_id)) {
					if (auto varnodeOffset = dynamic_cast<PCode::ConstantVarnode*>(instr->m_input0)) {
						auto targetOffset = (int64_t&)varnodeOffset->m_value;
						if (targetOffset >= 0 && targetOffset < getMaxOffset()) {
							auto offset = instr->getOffset();
							split_offsets.insert(std::make_pair(offset, false)); //out
							split_offsets.insert(std::make_pair(targetOffset, true)); //in
							jump_dirs.push_back(std::make_pair(offset, targetOffset));
						}
					}
				}
			}

			int64_t offset = 0;
			for (const auto& it : split_offsets) {
				auto minOffset = offset;
				auto maxOffset = it.first;
				if (!it.second) { //out
					auto instr = getInstructionByOffset(maxOffset);
					maxOffset = instr->getFirstInstrOffsetInNextOrigInstr();
				}
				if (minOffset < maxOffset) {
					createBlockAtOffset(minOffset, maxOffset);
				}
				offset = maxOffset;
			}
			createBlockAtOffset(offset, getMaxOffset());

			for (auto it = m_blocks.begin(); it != std::prev(m_blocks.end()); it++) {
				auto& curBlock = *it;
				auto& nextBlock = *std::next(it);
				auto lastInstr = curBlock.second.getLastInstruction();
				if (lastInstr->m_id._to_index() == PCode::InstructionId::CBRANCH) {
					curBlock.second.setNextNearBlock(&nextBlock.second);
				}
			}

			for (const auto& jmp_dir : jump_dirs) {
				auto curBlock = getBlockAtOffset(jmp_dir.first);
				auto nextFarBlock = getBlockAtOffset(jmp_dir.second);
				curBlock->setNextFarBlock(nextFarBlock);
			}

			std::list<AsmGraphBlock*> path;
			CalculateLevelsForAsmGrapBlocks(getStartBlock(), path);
		}

		AsmGraphBlock* getBlockAtOffset(int64_t offset) {
			auto it = std::prev(m_blocks.upper_bound(offset));
			if (it != m_blocks.end()) {
				if (offset >= it->second.getMinOffset() && offset < it->second.getMaxOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}

		AsmGraphBlock* getStartBlock() {
			return &(m_blocks.begin()->second);
		}

		void printDebug(void* addr) {
			for (auto block : m_blocks) {
				block.second.printDebug(addr, "", true, true);
				puts("==================");
			}
		}
	private:
		PCode::Instruction* getInstructionByOffset(int64_t offset) {
			for (auto instr : m_instructions) {
				if (instr->getOffset() == offset) //todo: binary search
					return instr;
			}
			return nullptr;
		}

		void createBlockAtOffset(int64_t minOffset, int64_t maxOffset) {
			AsmGraphBlock block(this, minOffset, maxOffset);
			for (auto instr : m_instructions) {
				if (instr->getOffset() >= minOffset && instr->getOffset() < maxOffset) {
					block.getInstructions().push_back(instr);
				}
			}
			m_blocks.insert(std::make_pair(minOffset, block));
		}

		int64_t getMaxOffset() {
			auto lastInstr = *std::prev(m_instructions.end());
			return lastInstr->getFirstInstrOffsetInNextOrigInstr();
		}

		static void CalculateLevelsForAsmGrapBlocks(AsmGraphBlock* block, std::list<AsmGraphBlock*>& path) {
			if (block == nullptr)
				return;

			//if that is a loop
			for (auto it = path.rbegin(); it != path.rend(); it++) {
				if (block == *it) {
					return;
				}
			}

			path.push_back(block);
			block->m_level = max(block->m_level, (int)path.size());
			CalculateLevelsForAsmGrapBlocks(block->getNextNearBlock(), path);
			CalculateLevelsForAsmGrapBlocks(block->getNextFarBlock(), path);
			path.pop_back();
		}
	};

	void test();
};
