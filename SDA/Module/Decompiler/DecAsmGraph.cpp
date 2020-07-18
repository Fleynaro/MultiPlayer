#include "DecAsmGraph.h"

using namespace CE;
using namespace CE::Decompiler;


int calculateFunctionSize2(byte* addr, bool endByRet = false) {
	int size = 0;
	while (!(addr[size] == 0xC3 && addr[size + 1] == 0xCC))
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
#include "Optimization/DecGraphOptimization.h"
#include "TestCodeToDecompile.h"
#include "DecTranslatorX86.h"

ExprTree::FunctionCallInfo GetFunctionCallDefaultInfo() {
	using namespace PCode;
	ExprTree::FunctionCallInfo info;
	info.m_paramRegisters = { Register(ZYDIS_REGISTER_RCX, -1), Register(ZYDIS_REGISTER_RDX, -1), Register(ZYDIS_REGISTER_R8, -1), Register(ZYDIS_REGISTER_R9, -1) };
	info.m_resultRegister = Register(ZYDIS_REGISTER_RAX, -1);
	info.m_resultVectorRegister = Register(ZYDIS_REGISTER_XMM0, 0xFF, true);
	return info;
}

void AsmGraphBlock::printDebug(void* addr = nullptr, const std::string& tabStr = "", bool extraInfo = true, bool pcode = true) {
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZyanU64 runtime_address = (ZyanU64)addr;
	for (auto instr : m_instructions) {
		std::string prefix = tabStr + "0x" + Generic::String::NumberToHex(runtime_address + instr->getOriginalInstructionOffset());
		if (!instr->m_originalView.empty())
			printf("%s %s\n", prefix.c_str(), instr->m_originalView.c_str());
		if (pcode) {
			prefix += ":" + std::to_string(instr->getOrderId()) + "(" + Generic::String::NumberToHex(instr->getOffset()).c_str() + ")";
			printf("\t%s %s\n", prefix.c_str(), instr->printDebug().c_str());
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


#define SHOW_ASM 1
#define SHOW_PCODE 0
void ShowCode(LinearView::BlockList* blockList, std::map<PrimaryTree::Block*, AsmGraphBlock*>& asmBlocks, int level = 0) {
	std::string tabStr = "";
	for (int i = 0; i < level; i++)
		tabStr += "\t";

	for (auto block : blockList->getBlocks()) {
		auto decBlock = block->m_decBlock;
		auto asmBlock = asmBlocks[decBlock];
		printf("%s//block %s (level %i)\n", tabStr.c_str(), Generic::String::NumberToHex(asmBlock->ID).c_str(), decBlock->m_level);
		
		if (SHOW_ASM) {
			asmBlock->printDebug(nullptr, tabStr, false, SHOW_PCODE);
			printf("%s------------\n", tabStr.c_str());
		}
		decBlock->printDebug(false, tabStr);

		if (auto condition = dynamic_cast<LinearView::Condition*>(block)) {
			if (auto whileLoop = dynamic_cast<LinearView::WhileLoop*>(block)) {
				printf("%swhile(%s) {\n", tabStr.c_str(), decBlock->m_noJmpCond ? decBlock->m_noJmpCond->printDebug().c_str() : "");
				ShowCode(condition->m_mainBranch, asmBlocks, level + 1);
				printf("%s}\n", tabStr.c_str());
			}
			else {
				printf("%sif(%s) {\n", tabStr.c_str(), decBlock->m_noJmpCond ? decBlock->m_noJmpCond->printDebug().c_str() : "");
				ShowCode(condition->m_mainBranch, asmBlocks, level + 1);
				if (true || condition->m_elseBranch->getBlocks().size() > 0) {
					printf("%s} else {\n", tabStr.c_str());
					ShowCode(condition->m_elseBranch, asmBlocks, level + 1);
				}
				printf("%s}\n", tabStr.c_str());
			}
		}

		if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
			if (endBlock->m_returnNode != nullptr) {
				printf("%sreturn %s\n", tabStr.c_str(), endBlock->m_returnNode->printDebug().c_str());
			}
		}
	}

	if (blockList->m_goto != nullptr) {
		printf("%s//goto to block %s\n", tabStr.c_str(), Generic::String::NumberToHex(asmBlocks[blockList->m_goto->m_decBlock]->ID).c_str());
	}
	else {
		printf("%s//goto is null\n", tabStr.c_str());
	}
}

void CE::Decompiler::test() {
	//TestFunctionToDecompile1();

	/*
		(����� ���������� ���������)

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
	std::vector<byte> sample25 = { 0x83, 0xF8, 0x00, 0x7D, 0x02, 0xF7, 0xD8, 0x83, 0xFB, 0x00, 0x7D, 0x02, 0xF7, 0xDB, 0x39, 0xD8, 0x7D, 0x01, 0x93, 0x83, 0xFB, 0x00, 0x74, 0x04, 0x29, 0xD8, 0xEB, 0xF2, 0x89, 0x04, 0x24, 0x89, 0x1C, 0x24 };

	//ghidra GTA5
	/* JMP function */ std::vector<byte> sample100 = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xDA, 0x83, 0xFA, 0x0A, 0x7E, 0x10, 0x8D, 0x42, 0xF5, 0x83, 0xF8, 0x0D, 0x77, 0x05, 0x83, 0xC3, 0x19, 0xEB, 0x03, 0x83, 0xEB, 0x0E, 0xE8, 0x46, 0xCA, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x2C, 0x83, 0xFB, 0x31, 0x77, 0x27, 0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43, 0x03, 0x00, 0x48, 0x0F, 0xA3, 0xDA, 0x73, 0x17, 0x48, 0x8B, 0x48, 0x48, 0x4C, 0x8B, 0xC0, 0x8B, 0xD3, 0x48, 0x83, 0xC1, 0x40, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xE9, 0x0D, 0x10, 0x91, 0xFF, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xCC };
	/* RAX request but no EAX */ std::vector<byte> sample101 = { 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x1B, 0xB2, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x0E, 0x48, 0x8B, 0x40, 0x20, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x90, 0x89, 0xED };
	std::vector<byte> sample102 = { 0x48, 0x83, 0xEC, 0x28, 0x8B, 0x44, 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24, 0x40, 0xC7, 0x44, 0x24, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x0F, 0x25, 0xFF, 0xFF, 0xFF, 0x0F, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x50, 0x8F, 0x8B, 0x00, 0x0F, 0xB7, 0x4C, 0x24, 0x40, 0x66, 0x89, 0x4C, 0x24, 0x38, 0x8B, 0x4C, 0x24, 0x38, 0x4C, 0x8B, 0xC0, 0x81, 0xC9, 0x00, 0x00, 0xFF, 0x0F, 0x33, 0xC0, 0x0F, 0xBA, 0xF1, 0x1C, 0x66, 0x81, 0xF9, 0xFF, 0xFF, 0x74, 0x10, 0x4D, 0x85, 0xC0, 0x74, 0x0B, 0x41, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC, 0x54, 0x48 };
	
	//XMM
	std::vector<byte> sample200 = { 0x40, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xA9, 0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x45, 0x17, 0x44, 0x89, 0x45, 0xBF, 0xF2, 0x0F, 0x11, 0x4D, 0x27, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8D, 0x45, 0xD7, 0x4C, 0x8D, 0x4D, 0xF7, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0xE7, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x48, 0x8D, 0x15, 0x5E, 0xC5, 0x6C, 0x01, 0x48, 0x89, 0x44, 0x24, 0x20, 0x0F, 0x29, 0x45, 0x17, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0x07, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x4C, 0x8D, 0x45, 0x37, 0x0F, 0x29, 0x45, 0xD7, 0x0F, 0x10, 0x45, 0xB7, 0xC7, 0x45, 0xBF, 0x01, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x4D, 0x47, 0x0F, 0x29, 0x45, 0xF7, 0x66, 0x0F, 0x6E, 0xC1, 0x48, 0x8D, 0x0D, 0xC8, 0xF4, 0xE2, 0x01, 0xF3, 0x0F, 0xE6, 0xC0, 0xF2, 0x0F, 0x11, 0x45, 0xB7, 0x0F, 0x10, 0x45, 0xB7, 0x0F, 0x29, 0x45, 0x37, 0xE8, 0xAA, 0xDE, 0xFE, 0xFF, 0x48, 0x81, 0xC4, 0xD0, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xCC };


	void* addr;
	int size;
	if (true) {
		addr = &TestFunctionToDecompile1;
		size = calculateFunctionSize2((byte*)addr, 0);
	}
	else {
#define SAMPLE_VAR sample25
		addr = SAMPLE_VAR.data();
		size = (int)SAMPLE_VAR.size();
	}

	PCode::TranslatorX86 translatorX86;
	translatorX86.start(addr, size);
	AsmGraph graph(translatorX86.m_result);
	graph.build();
	graph.printDebug(addr);

	auto info = GetFunctionCallDefaultInfo();
	{
		auto it = info.m_paramRegisters.begin();
		*(it++) = PCode::Register(ZYDIS_REGISTER_RCX, 0xFFFFFFFF);
		*(it++) = PCode::Register(ZYDIS_REGISTER_RDX, 0xFFFFFFFF);
		*(it++) = PCode::Register(ZYDIS_REGISTER_R8, 0xFFFFFFFF);
		info.m_resultRegister = PCode::Register(ZYDIS_REGISTER_RAX, 0xFFFFFFFF);
		info.m_paramRegisters.clear();
	}

	auto decCodeGraph = new DecompiledCodeGraph;
	auto decompiler = new Decompiler(&graph, decCodeGraph, info);
	decompiler->m_funcCallInfoCallback = [&](int offset, ExprTree::Node* dst) {
		auto absAddr = (std::intptr_t)addr + offset;
		return info;
	};
	decompiler->start();
	//decompiler->printDebug();
	Optimization::OptimizeDecompiledGraph(decCodeGraph);

	LinearView::Converter2 converter(decCodeGraph);
	converter.start();
	
	auto asmBlocks = decompiler->getAsmBlocks();
	ShowCode(converter.getBlockList(), asmBlocks);
}
