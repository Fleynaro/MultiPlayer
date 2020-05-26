#include "DecAsmGraph.h"

using namespace CE;
using namespace CE::Decompiler;

AsmGraphBlock::AsmGraphBlock(AsmGraph* asmGraph, int minOffset, int maxOffset)
	: m_asmGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset)
{}

std::list<int>& AsmGraphBlock::getInstructions() {
	return m_instructions;
}

int AsmGraphBlock::getMinOffset() {
	return m_minOffset;
}

int AsmGraphBlock::getMaxOffset() {
	return m_maxOffset;
}

void AsmGraphBlock::setNextNearBlock(AsmGraphBlock* nextBlock) {
	m_nextNearBlock = nextBlock;
	nextBlock->m_blocksReferencedTo.push_back(this);
}

void AsmGraphBlock::setNextFarBlock(AsmGraphBlock* nextBlock) {
	m_nextFarBlock = nextBlock;
	nextBlock->m_blocksReferencedTo.push_back(this);
}

AsmGraphBlock* AsmGraphBlock::getNextNearBlock() {
	return m_nextNearBlock;
}

AsmGraphBlock* AsmGraphBlock::getNextFarBlock() {
	return m_nextFarBlock;
}

ZydisDecodedInstruction& AsmGraphBlock::getLastInstruction() {
	return m_asmGraph->m_instructions[*std::prev(m_instructions.end())];
}

void AsmGraphBlock::printDebug(void* addr) {
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZyanU64 runtime_address = (ZyanU64)addr;
	for (auto instr_off : m_instructions) {
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &m_asmGraph->m_instructions[instr_off], buffer, sizeof(buffer),
			runtime_address + instr_off);
		printf("%p(%i): %s\n", (void*)(runtime_address + instr_off), instr_off, buffer);
	}

	if(m_nextNearBlock != nullptr)
		printf("Next near: %i\n", m_nextNearBlock->getMinOffset());
	if (m_nextFarBlock != nullptr)
		printf("Next far: %i\n", m_nextFarBlock->getMinOffset());
}



AsmGraph::AsmGraph(InstructionMapType instructions)
	: m_instructions(instructions)
{}

void AsmGraph::build() {
	std::map<int, bool> split_offsets;
	std::list<std::pair<int, int>> jump_dirs;

	for (const auto& it : m_instructions) {
		auto offset = it.first;
		auto& instruction = it.second;

		if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR || instruction.meta.category == ZYDIS_CATEGORY_COND_BR) {
			auto& operand = instruction.operands[0];
			if (operand.reg.value == ZYDIS_REGISTER_NONE) {
				if (operand.imm.is_relative) {
					int targetOffset = (int)instruction.length +
						(operand.imm.is_signed ? (offset + (int)operand.imm.value.s) : (offset + (unsigned int)operand.imm.value.u));
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

	for (auto it = m_blocks.begin(); it != std::prev(m_blocks.end()); it ++) {
		auto& curBlock = *it;
		auto& nextBlock = *std::next(it);
		auto& instruction = curBlock.second.getLastInstruction();
		if (instruction.meta.category != ZYDIS_CATEGORY_UNCOND_BR) {
			curBlock.second.setNextNearBlock(&nextBlock.second);
		}
	}

	for (const auto& jmp_dir : jump_dirs) {
		auto curBlock = getBlockAtOffset(jmp_dir.first);
		auto nextFarBlock = getBlockAtOffset(jmp_dir.second);
		curBlock->setNextFarBlock(nextFarBlock);
	}
}

AsmGraphBlock* AsmGraph::getBlockAtOffset(int offset) {
	auto it = std::prev(m_blocks.upper_bound(offset));
	if (it != m_blocks.end()) {
		if (offset >= it->second.getMinOffset() && offset < it->second.getMaxOffset()) {
			return &it->second;
		}
	}
	return nullptr;
}

void AsmGraph::printDebug(void* addr) {
	for (auto block : m_blocks) {
		block.second.printDebug(addr);
		puts("==================");
	}
}

void AsmGraph::createBlockAtOffset(int minOffset, int maxOffset) {
	AsmGraphBlock block(this, minOffset, maxOffset);
	for (const auto& it : m_instructions) {
		if (it.first >= minOffset && it.first < maxOffset) {
			block.getInstructions().push_back(it.first);
		}
	}
	m_blocks.insert(std::make_pair(minOffset, block));
}

int AsmGraph::getMaxOffset() {
	auto& lastInstr = *std::prev(m_instructions.end());
	return lastInstr.first + lastInstr.second.length;
}

InstructionMapType CE::Decompiler::getInstructionsAtAddress(void* addr, int size) {
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

		while (a != 0) {
			a--;

			do {
				b--;
			} while (b != 0);

			if (a == 1)
				break;
		}
	}
	else if( a == 1) {
		a = 0;
		return;
	}

	if (b) {
		a = 1;
	}
}

int calculateFunctionSize2(byte* addr) {
	int size = 0;
	while (addr[size] != 0xCC)
		size++;
	return size;
}

void ff() {
	int a = -5;
	uint64_t b = 6;
	b = a;
}


#include "DecAsmInterpreter.h"

void CE::Decompiler::test() {
	byte mem[] = {
		0xba, 0x02, 0x00, 0x00, 0x00,						//MOV EDX,0x2
		0x48, 0x8d, 0x7b, 0x32,								//LEA RDI,[RBX + 0x32]
		0x44, 0x88, 0xab, 0x96, 0x00, 0x00, 0x00,           //MOV byte ptr[RBX + 0x96],R13B
		0x8b, 0x0d, 0x22, 0x8d, 0xd9, 0x01,                 //MOV ECX,dword ptr[DAT_7ff614c12348]
		0x48, 0x8b, 0x04, 0xc8,                             //MOV RAX,qword ptr[RAX + RCX * 0x8]
		0x48, 0x03, 0x9c, 0x28, 0xc0, 0x01, 0x00, 0x00,		//ADD RBX,qword ptr [RAX + RBP*0x1 + 0x1c0]
		0x48, 0x69, 0xdb, 0xa4, 0x00, 0x00, 0x00			//IMUL RBX,RBX,0xa4
	};


	byte sample1[] = { 0xB0, 0x01, 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0xB4, 0x02, 0x88, 0xC3, 0x88, 0xE1, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00, 0x89, 0x04, 0x25, 0x08, 0x10, 0x00, 0x00 };
	byte sample2[] = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x55, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x10, 0x00, 0x88, 0xC1, 0x88, 0xEA, 0x48, 0x29, 0xD8, 0x28, 0xF9, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00 };
	byte sample3[] = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x88, 0xE6, 0x88, 0xF1, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00 };
	byte sample4[] = { 0x67, 0x48, 0x8B, 0x04, 0x95, 0x00, 0x01, 0x00, 0x00, 0x67, 0x03, 0x0C, 0x95, 0x00, 0x02, 0x00, 0x00, 0xBA, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xC2, 0x66, 0xF7, 0xF2, 0x67, 0x88, 0x24, 0xD5, 0x00, 0x01, 0x00, 0x00 };
	byte sample5[] = { 0x67, 0x48, 0x8D, 0x04, 0x95, 0x00, 0x01, 0x00, 0x00, 0x67, 0x88, 0x24, 0xD5, 0x00, 0x00, 0x00, 0x00 };
	byte sample6[] = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x10, 0x0F, 0xBE, 0xC7, 0x48, 0x89, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00 };

	AsmGraph graph(CE::Decompiler::getInstructionsAtAddress(sample6, sizeof(sample6)));
	graph.build();

	Interpreter intrepret;
	ExpressionManager manager;
	ExecutionContext ctx(&manager, 0x0);
	auto treeBlock = new PrimaryTree::Block;

	auto block = graph.getBlockAtOffset(0x0);
	for (auto off : block->getInstructions()) {
		auto instr = graph.m_instructions[off];
		intrepret.execute(treeBlock, &ctx, instr);
	}

	ff();

	printf("%s\n\n", treeBlock->printDebug().c_str());
	graph.printDebug(&func);
}
