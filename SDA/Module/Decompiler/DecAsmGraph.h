#pragma once
#include <main.h>
#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

namespace CE::Decompiler
{
	using InstructionMapType = std::map<int, ZydisDecodedInstruction>;

	class AsmGraph;
	class AsmGraphBlock
	{
	public:
		AsmGraphBlock(AsmGraph* asmGraph, int minOffset, int maxOffset)
			: m_asmGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset)
		{}

		std::list<int>& getInstructions() {
			return m_instructions;
		}

		int getMinOffset() {
			return m_minOffset;
		}

		int getMaxOffset() {
			return m_maxOffset;
		}

		void setNextBlock1(AsmGraphBlock* nextBlock) {
			m_nextBlock1 = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		void setNextBlock2(AsmGraphBlock* nextBlock) {
			m_nextBlock2 = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}
	private:
		AsmGraph* m_asmGraph;
		int m_minOffset;
		int m_maxOffset;
		std::list<int> m_instructions;
		std::list<AsmGraphBlock*> m_blocksReferencedTo;
		AsmGraphBlock* m_nextBlock1 = nullptr;
		AsmGraphBlock* m_nextBlock2 = nullptr;
	};

	class AsmGraph
	{
	public:
		struct BuildContext {
			AsmGraphBlock* m_curBlock = nullptr;
			int m_offset = 0;
		};

		AsmGraph(InstructionMapType instructions)
			: m_instructions(instructions)
		{}

		void build() {
			std::map<int, bool> split_offsets;
			std::list<std::pair<int, int>> jump_dirs;

			for (const auto& it : m_instructions) {
				auto offset = it.first;
				auto& instruction = it.second;

				if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR || instruction.meta.category == ZYDIS_CATEGORY_COND_BR) {
					auto& operand = instruction.operands[0];
					if (operand.reg.value == ZYDIS_REGISTER_NONE) {
						if (operand.imm.is_relative) {
							int targetOffset = instruction.length +
								(operand.imm.is_signed ? (offset + operand.imm.value.s) : (offset + operand.imm.value.u));
							split_offsets.insert(std::make_pair(offset, false));
							split_offsets.insert(std::make_pair(targetOffset, true));
							jump_dirs.push_back(std::make_pair(offset, targetOffset));
						}
					}
				}
			}

			int offset = 0;
			for (const auto& it : split_offsets) {
				auto minOffset = offset;
				auto maxOffset = it.first;
				if (!it.second) {
					maxOffset += m_instructions[maxOffset].length;
				}
				if (minOffset < maxOffset) {
					createBlockAtOffset(minOffset, maxOffset);
				}
				offset = maxOffset;
			}
			createBlockAtOffset(offset, getMaxOffset());


			for (const auto& jmp_dir : jump_dirs) {
				auto curBlock = getBlockAtOffset(jmp_dir.first);
				auto nextNearBlock = getBlockAtOffset(jmp_dir.first + m_instructions[jmp_dir.first].length);//jmp
				auto nextFarBlock = getBlockAtOffset(jmp_dir.second);
				curBlock->setNextBlock1(nextNearBlock);
				curBlock->setNextBlock2(nextFarBlock);
				//...
			}
		}

		AsmGraphBlock* getBlockAtOffset(int offset) {
			auto it = --m_blocks.upper_bound(offset);
			if (it != m_blocks.end()) {
				if (offset >= it->second.getMinOffset() && offset < it->second.getMaxOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}
	private:
		InstructionMapType m_instructions;
		std::map<int, AsmGraphBlock> m_blocks;

		void createBlockAtOffset(int minOffset, int maxOffset) {
			AsmGraphBlock block(this, minOffset, maxOffset);
			for (const auto& it : m_instructions) {
				if (it.first >= minOffset && it.first < maxOffset) {
					block.getInstructions().push_back(it.first);
				}
			}
			m_blocks.insert(std::make_pair(minOffset, block));
		}

		int getMaxOffset() {
			auto& lastInstr = *(--m_instructions.end());
			return lastInstr.first + lastInstr.second.length;
		}
	};

	InstructionMapType getInstructionsAtAddress(void* addr, int size) {
		InstructionMapType result;
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

		int curOffset = 0;
		ZyanUSize curSize = (ZyanUSize)size;
		auto curAddress = (ZyanU64)addr;
		ZydisDecodedInstruction curInstruction;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)curAddress, curSize,
			&curInstruction)))
		{
			result.insert(std::make_pair(curOffset, curInstruction));
			curSize -= curInstruction.length;
			curOffset += curInstruction.length;
			curAddress += curInstruction.length;
		}
		return result;
	}






	void func() {
		int a = 5;
		int b = 6;
		if (a < b) {
			a = b;
		}
		else {
			a = 0;
		}
	}

	void test() {
		AsmGraph graph(getInstructionsAtAddress(&func, 50));
		graph.build();

		//print blocks and jmp
	}
};
