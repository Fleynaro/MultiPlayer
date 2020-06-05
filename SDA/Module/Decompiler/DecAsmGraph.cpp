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

bool AsmGraphBlock::isCondition() {
	return m_nextNearBlock != nullptr && m_nextFarBlock != nullptr;
}

bool AsmGraphBlock::isEnd() {
	return m_nextNearBlock == nullptr && m_nextFarBlock == nullptr;
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

	printf("Level: %i\n", m_level);
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
			if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
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

	CountLevelsForAsmGrapBlocks(getStartBlock());
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

AsmGraphBlock* AsmGraph::getStartBlock() {
	return &(m_blocks.begin()->second);
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

void AsmGraph::CountLevelsForAsmGrapBlocks(AsmGraphBlock* block, int level) {
	if (block == nullptr)
		return;
	block->m_level = max(block->m_level, level);
	CountLevelsForAsmGrapBlocks(block->getNextNearBlock(), level + 1);
	CountLevelsForAsmGrapBlocks(block->getNextFarBlock(), level + 1);
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
	while (addr[size] != 0xC3)
		size++;
	return size;
}

void ff() {
	int a = -5;
	uint64_t b = 1;
	b = b * a;
}


#include "Decompiler.h"
#include "Optimization/ExprOptimization.h"

int gVarrrr = 100;

int func11(int a) {
	return a * 2;
}

void func22() {
	int b = 2;
	/*b += func11(10) + func11(5);
	b *= -1;
	gVarrrr %= 21;*/
	if (b > 1) {
		b = 3;
	}
	else {
		b = 5;
	}

	b = 0;
}


void CE::Decompiler::test() {
	/*
		TODO:
		1) символы локальных переменных делать в конце, когда будет граф. помечать из них флагом те, которые €вл€ютс€ параметрами
		2) сделать услови€ и циклы. —делать это близко к си коду, без вс€ких джампов. »бо потом все будет в кеше, не надо повторно вычисл€ть
		3) сделать поддержку векторов и вещественных значений
	*/


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
	byte sample7[] = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x10, 0x48, 0x39, 0xD8, 0x48, 0x0F, 0x44, 0xC3, 0x48, 0x89, 0x44, 0x24, 0x30 };
	byte sample8[] = { 0x45, 0x31, 0xD2, 0x49, 0x89, 0xCB, 0x48, 0x8B, 0x41, 0x40, 0x4C, 0x63, 0xC2, 0x46, 0x0F, 0xB6, 0x0C, 0x00, 0x8B, 0x41, 0x4C, 0x41, 0x81, 0xE1, 0x80, 0x00, 0x00, 0x00, 0x45, 0x89, 0xC8, 0x0F, 0xAF, 0xC2, 0x89, 0x44, 0x24, 0x14, 0x44, 0x89, 0x44, 0x24, 0x14, 0x48, 0x63, 0xC8, 0x48, 0x89, 0x4C, 0x24, 0x18, 0x44, 0x89, 0xC8, 0x48, 0x89, 0x44, 0x24, 0x18, 0x49, 0x03, 0x4B, 0x38, 0x48, 0xF7, 0xD8, 0x4C, 0x09, 0xC0, 0x48, 0xC1, 0xF8, 0x3F, 0x48, 0xF7, 0xD0, 0x48, 0x85, 0xC8, 0x41, 0x0F, 0x95, 0xC2, 0x44, 0x88, 0xD0, 0x88, 0x44, 0x24, 0x11 };
	byte sample9[] = { 0x48, 0x89, 0xE5, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0xE0, 0x48, 0x31, 0xC9, 0x83, 0xC1, 0x10, 0x51, 0xB9, 0x20, 0x00, 0x00, 0x00, 0x5A, 0x89, 0x4C, 0x24, 0x20, 0x89, 0x48, 0x28, 0x89, 0x4D, 0xF8, 0x48, 0x83, 0xC4, 0x30, 0x48, 0x8B, 0x5C, 0x24, 0x08 }; //stack

	void* addr = &func22;
	int size = calculateFunctionSize2((byte*)addr);

	AsmGraph graph(CE::Decompiler::getInstructionsAtAddress(addr, size));
	graph.build();

	{
		graph.printDebug(addr);
		return;
	}

	auto decompiler = new Decompiler(&graph);
	decompiler->m_funcCallInfoCallback = [&](int offset, ExprTree::Node* dst) {
		auto absAddr = (std::intptr_t)addr + offset;
		auto info = ExprTree::GetFunctionCallDefaultInfo();
		*info.m_paramRegisters.begin() = ZYDIS_REGISTER_ECX;
		info.m_resultRegister = ZYDIS_REGISTER_EAX;
		return info;
	};

	InstructionInterpreterDispatcher dispatcher;
	ExecutionBlockContext ctx(decompiler, 0x0);
	auto treeBlock = new PrimaryTree::Block;

	auto block = graph.getBlockAtOffset(0x0);
	for (auto off : block->getInstructions()) {
		auto instr = graph.m_instructions[off];
		dispatcher.execute(treeBlock, &ctx, instr);
	}

	
	printf("%s\n\n\nAfter optimization:\n\n", treeBlock->printDebug().c_str());

	for (auto line : treeBlock->getLines()) {
		Optimization::Optimize(line->m_destAddr);
		Optimization::Optimize(line->m_srcValue);

		/*if (auto expr = dynamic_cast<ExprTree::OperationalNode*>(line->m_destAddr)) {
			printf("1) %s", line->printDebug().c_str());
			Optimization::OptimizeConstExpr(expr);
			printf("2) %s", line->printDebug().c_str());
			Optimization::OptimizeConstPlaceInExpr(expr);
			printf("3) %s", line->printDebug().c_str());
			Optimization::OptimizeRepeatOpInExpr(expr);
			printf("4) %s\n", line->printDebug().c_str());
		}*/
	}

	printf("%s\n\n", treeBlock->printDebug().c_str());
	graph.printDebug(&func);
}
