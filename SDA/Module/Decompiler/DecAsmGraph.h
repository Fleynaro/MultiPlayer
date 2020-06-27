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
		int ID = 0;
		int m_level = 0;
		std::list<AsmGraphBlock*> m_blocksReferencedTo;

		AsmGraphBlock(AsmGraph* asmGraph, int minOffset, int maxOffset);

		std::list<int>& getInstructions();

		int getMinOffset();

		int getMaxOffset();

		void setNextNearBlock(AsmGraphBlock* nextBlock);

		void setNextFarBlock(AsmGraphBlock* nextBlock);

		AsmGraphBlock* getNextNearBlock();

		AsmGraphBlock* getNextFarBlock();

		ZydisDecodedInstruction& getLastInstruction();

		void printDebug(void* addr, const std::string& tabStr, bool extraInfo);
	private:
		AsmGraph* m_asmGraph;
		int m_minOffset;
		int m_maxOffset;
		std::list<int> m_instructions;
		AsmGraphBlock* m_nextNearBlock = nullptr;
		AsmGraphBlock* m_nextFarBlock = nullptr;
	};

	class AsmGraph
	{
		friend class AsmGraphBlock;
	public:
		std::map<int, AsmGraphBlock> m_blocks;
		InstructionMapType m_instructions;

		AsmGraph(InstructionMapType instructions);

		void build();

		AsmGraphBlock* getBlockAtOffset(int offset);

		AsmGraphBlock* getStartBlock();

		void printDebug(void* addr);
	private:
		void createBlockAtOffset(int minOffset, int maxOffset);

		int getMaxOffset();

		static void CalculateLevelsForAsmGrapBlocks(AsmGraphBlock* block, std::list<AsmGraphBlock*>& path);
	};

	InstructionMapType getInstructionsAtAddress(void* addr, int size);

	void test();
};
