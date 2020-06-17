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

int AsmGraphBlock::getRefHighBlocksCount() {
	int count = 0;
	for (auto refBlock : m_blocksReferencedTo) {
		if (refBlock->m_level < m_level)
			count++;
	}
	return count;
}

void AsmGraphBlock::printDebug(void* addr = nullptr, const std::string& tabStr = "", bool extraInfo = true) {
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZyanU64 runtime_address = (ZyanU64)addr;
	for (auto instr_off : m_instructions) {
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &m_asmGraph->m_instructions[instr_off], buffer, sizeof(buffer),
			runtime_address + instr_off);
		printf("%s%p(%i): %s\n", tabStr.c_str(), (void*)(runtime_address + instr_off), instr_off, buffer);
	}

	if (extraInfo) {
		printf("Level: %i\n", m_level);
		if (m_nextNearBlock != nullptr)
			printf("Next near: %i\n", m_nextNearBlock->getMinOffset());
		if (m_nextFarBlock != nullptr)
			printf("Next far: %i\n", m_nextFarBlock->getMinOffset());
	}
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

	std::list<AsmGraphBlock*> path;
	CountLevelsForAsmGrapBlocks(getStartBlock(), path);
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

void AsmGraph::CountLevelsForAsmGrapBlocks(AsmGraphBlock* block, std::list<AsmGraphBlock*>& path) {
	if (block == nullptr)
		return;

	//if that is a loop
	for (auto it = path.rbegin(); it != path.rend(); it ++) {
		if (block == *it) {
			return;
		}
	}

	path.push_back(block);
	block->m_level = max(block->m_level, (int)path.size());
	CountLevelsForAsmGrapBlocks(block->getNextNearBlock(), path);
	CountLevelsForAsmGrapBlocks(block->getNextFarBlock(), path);
	path.pop_back();
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
	return size + 1;
}

void ff() {
	int a = -5;
	uint64_t b = 1;
	b = b * a;
}


#include "Decompiler.h"
#include "DecLinearView.h"

int gVarrrr = 100;

int func11(int a) {
	return a * 2;
}

void func22() {
	int b = 2;
	/*b += func11(10) + func11(5);
	b *= -1;
	gVarrrr %= 21;*/
	/*if (b > 1) {
		b = func11(10) % 25;
		if (b == 2) {
			b ++;
		}
	}
	else {
		b = 5;

		if (b == 3 || b == 6) {
			b++;
			if (b == 3) {
				b++;
			}
			else {
				b--;
			}
		}
	}

	if (b == 3 || b == 6) {
		b++;
		if (b == 3) {
			b++;
		}
		else {
			b--;
		}
	}
	b = 0;*/

	while (b < 5) {
		b++;
	}
}


void ShowCode(LinearView::BlockList* blockList, std::map<AsmGraphBlock*, PrimaryTree::Block*>& decompiledBlocks, int level = 0) {
	std::string tabStr = "";
	for (int i = 0; i < level; i++)
		tabStr += "\t";

	for (auto block : blockList->getBlocks()) {
		auto decBlock = decompiledBlocks[block->m_graphBlock];
		printf("%s//block %i (level %i)\n", tabStr.c_str(), block->m_graphBlock->getMinOffset(), block->m_graphBlock->m_level);
		
		block->m_graphBlock->printDebug(nullptr, tabStr, false);
		printf("%s------------\n", tabStr.c_str());
		if (decBlock) {
			decBlock->printDebug(false, tabStr);
		}

		if (auto condition = dynamic_cast<LinearView::Condition*>(block)) {
			if (decBlock) {
				printf("%sif(%s) {\n", tabStr.c_str(), decBlock->m_noJmpCond->printDebug().c_str());
			}
			else {
				printf("%sif(...) {\n", tabStr.c_str());
			}
			ShowCode(condition->m_mainBranch, decompiledBlocks, level + 1);
			if (condition->m_elseBranch->getBlocks().size() > 0) {
				printf("%s} else {\n", tabStr.c_str());
				ShowCode(condition->m_elseBranch, decompiledBlocks, level + 1);
			}
			printf("%s}\n", tabStr.c_str());
		}
	}

	if (blockList->m_goto != nullptr) {
		printf("%s//goto to block on %i\n", tabStr.c_str(), blockList->m_goto->m_graphBlock->getMinOffset());
	}
}

void CE::Decompiler::test() {
	/*
		(�� ���������� ���������)

		TODO:
		1) ������� ��������� ���������� ������ � �����, ����� ����� ����. �������� �� ��� ������ ��, ������� �������� �����������
		2) ������� ������� � �����. ������� ��� ������ � �� ����, ��� ������ �������. ��� ����� ��� ����� � ����, �� ���� �������� ���������
		3) ������� ��������� �������� � ������������ ��������


		TODO:
		1) ������� ����� ������ � ��������� �������������� � ������
		2) ������� ����� �������� � ������ ����������� ������� ���� � ���� � ��������� ������������
		3) �������� �� ����� ��� ������� �����, ����� ����� �� �������������
		4) ���-�� ����� ���� push � pop ��������, �� ��� �� �������� ��������� ������ �������
		5) ������� �������������� ����� � ������� ������� ���� � ����. ����� �����������, ��� ������� ����� ������� �����. ����� ���, ����� �������� ������ ��������.
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

	//if else / register search
	byte sample10[] = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x04, 0x66, 0xB8, 0x02, 0x00, 0x88, 0x44, 0x24, 0x10 };
	byte sample11[] = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x07, 0xB8, 0x00, 0x02, 0x00, 0x00, 0xB0, 0x03, 0x88, 0x44, 0x24, 0x10 };
	byte sample12[] = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x88, 0xEC, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x07, 0xB8, 0x00, 0x02, 0x00, 0x00, 0xB0, 0x03, 0x88, 0x44, 0x24, 0x10 };
	byte sample13[] = { 0xB8, 0x45, 0x23, 0x01, 0x00, 0x88, 0xEC, 0x88, 0xE8, 0x89, 0x44, 0x24, 0x10 };
	byte sample14[] = { 0x48, 0x89, 0xD0, 0xB8, 0x45, 0x23, 0x01, 0x00, 0x88, 0xEC, 0x83, 0xF8, 0x10, 0x75, 0x0A, 0x89, 0xD8, 0xEB, 0x00, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x04, 0x89, 0xC8, 0xB0, 0x03, 0x48, 0x89, 0x44, 0x24, 0x10 };
	byte sample15[] = { 0x48, 0xC7, 0xC0, 0x67, 0x45, 0x23, 0x01, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x09, 0x48, 0xC7, 0xC0, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x48, 0x83, 0xC0, 0x04, 0x48, 0x89, 0x44, 0x24, 0x10 };
	byte sample16[] = { 0x48, 0xC7, 0xC0, 0x67, 0x45, 0x23, 0x01, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x07, 0xB8, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x83, 0xC0, 0x04, 0x89, 0x44, 0x24, 0x10 };
	byte sample17[] = { 0x48, 0xB8, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x07, 0xB8, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x83, 0xC0, 0x04, 0x48, 0x89, 0x44, 0x24, 0x10 };

	//evklid algorithm
	byte sample20[] = { 0x83, 0xF8, 0x00, 0x7D, 0x02, 0xF7, 0xD8, 0x83, 0xFB, 0x00, 0x7D, 0x02, 0xF7, 0xDB, 0x89, 0x04, 0x24, 0x89, 0x1C, 0x24 };
	byte sample25[] = { 0x83, 0xF8, 0x00, 0x7D, 0x02, 0xF7, 0xD8, 0x83, 0xFB, 0x00, 0x7D, 0x02, 0xF7, 0xDB, 0x39, 0xD8, 0x7D, 0x01, 0x93, 0x83, 0xFB, 0x00, 0x74, 0x04, 0x29, 0xD8, 0xEB, 0xF2, 0x89, 0x04, 0x24, 0x89, 0x1C, 0x24 };


	void* addr = sample25; //&func22;
	int size = sizeof(sample25); //calculateFunctionSize2((byte*)addr);

	AsmGraph graph(CE::Decompiler::getInstructionsAtAddress(addr, size));
	graph.build();

	graph.printDebug(addr);
	printf("\n\n");

	auto decompiler = new Decompiler(&graph);
	decompiler->m_funcCallInfoCallback = [&](int offset, ExprTree::Node* dst) {
		auto absAddr = (std::intptr_t)addr + offset;
		auto info = ExprTree::GetFunctionCallDefaultInfo();
		*info.m_paramRegisters.begin() = ZYDIS_REGISTER_ECX;
		info.m_resultRegister = ZYDIS_REGISTER_EAX;
		return info;
	};
	decompiler->start();
	decompiler->optimize();
	//decompiler->printDebug();
	auto decompiledBlocks = decompiler->getResult();
	//decompiledBlocks.clear();

	LinearView::Converter converter(&graph);
	converter.start();
	
	ShowCode(converter.getBlockList(), decompiledBlocks);
}
