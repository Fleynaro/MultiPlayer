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
		AsmGraphBlock(AsmGraph* asmGraph, int minOffset, int maxOffset);

		std::list<int>& getInstructions();

		int getMinOffset();

		int getMaxOffset();

		void setNextNearBlock(AsmGraphBlock* nextBlock);

		void setNextFarBlock(AsmGraphBlock* nextBlock);

		AsmGraphBlock* getNextNearBlock();

		AsmGraphBlock* getNextFarBlock();

		ZydisDecodedInstruction& getLastInstruction();

		void printDebug(void* addr);
	private:
		AsmGraph* m_asmGraph;
		int m_minOffset;
		int m_maxOffset;
		std::list<int> m_instructions;
		std::list<AsmGraphBlock*> m_blocksReferencedTo;
		AsmGraphBlock* m_nextNearBlock = nullptr;
		AsmGraphBlock* m_nextFarBlock = nullptr;
	};

	class AsmGraph
	{
		friend class AsmGraphBlock;
	public:
		AsmGraph(InstructionMapType instructions);

		void build();

		AsmGraphBlock* getBlockAtOffset(int offset);

		void printDebug(void* addr);
	private:
		InstructionMapType m_instructions;
		std::map<int, AsmGraphBlock> m_blocks;

		void createBlockAtOffset(int minOffset, int maxOffset);

		int getMaxOffset();
	};

	InstructionMapType getInstructionsAtAddress(void* addr, int size);

	void test();
};
