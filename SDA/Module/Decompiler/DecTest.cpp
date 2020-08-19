#include "DecTest.h"
#include "Decompiler.h"
#include "DecLinearView.h"
#include "Optimization/DecGraphOptimization.h"
#include "SDA/Symbolization/DecGraphSymbolization.h"
#include "TestCodeToDecompile.h"
#include "DecTranslatorX86.h"

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

ExprTree::FunctionCallInfo GetFunctionCallDefaultInfo() {
	using namespace PCode;
	ExprTree::FunctionCallInfo info;
	info.m_knownRegisters = { Register(ZYDIS_REGISTER_RIP, -1), Register(ZYDIS_REGISTER_RSP, -1) };
	info.m_paramRegisters = { Register(ZYDIS_REGISTER_RCX, -1), Register(ZYDIS_REGISTER_RDX, -1), Register(ZYDIS_REGISTER_R8, -1), Register(ZYDIS_REGISTER_R9, -1) };
	info.m_resultRegister = Register(ZYDIS_REGISTER_RAX, -1);
	info.m_resultVectorRegister = Register(ZYDIS_REGISTER_XMM0, 0xFF, Register::Type::Vector);
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


bool g_SHOW_ASM = true;
bool g_SHOW_PCODE = false;
bool g_SHOW_ALL_GOTO = true;
bool g_SHOW_LINEAR_LEVEL_EXT = true;

void ShowBlockCode(AsmGraphBlock* asmBlock, LinearView::Block* block, std::string tabStr) {
	printf("%s//block %s (level: %i, maxHeight: %i, backOrderId: %i, linearLevel: %i, refCount: %i)\n", tabStr.c_str(), Generic::String::NumberToHex(asmBlock->ID).c_str(), block->m_decBlock->m_level, block->m_decBlock->m_maxHeight, block->getBackOrderId(), block->getLinearLevel(), block->m_decBlock->getRefBlocksCount());
	if (g_SHOW_ASM) {
		asmBlock->printDebug(nullptr, tabStr, false, g_SHOW_PCODE);
		printf("%s------------\n", tabStr.c_str());
	}
	block->m_decBlock->printDebug(false, tabStr);
}

void ShowCode(LinearView::BlockList* blockList, std::map<PrimaryTree::Block*, AsmGraphBlock*>& asmBlocks, int level = 0) {
	std::string tabStr = "";
	for (int i = 0; i < level; i++)
		tabStr += "\t";

	for (auto block : blockList->getBlocks()) {
		auto decBlock = block->m_decBlock;
		auto asmBlock = asmBlocks[decBlock];

		if (auto condition = dynamic_cast<LinearView::Condition*>(block)) {
			ShowBlockCode(asmBlock, block, tabStr);
			printf("%sif(%s) {\n", tabStr.c_str(), condition->m_cond ? condition->m_cond->printDebug().c_str() : "");
			ShowCode(condition->m_mainBranch, asmBlocks, level + 1);
			if (g_SHOW_ALL_GOTO || !condition->m_elseBranch->isEmpty()) {
				printf("%s} else {\n", tabStr.c_str());
				ShowCode(condition->m_elseBranch, asmBlocks, level + 1);
			}
			printf("%s}\n", tabStr.c_str());
		}
		else if (auto whileCycle = dynamic_cast<LinearView::WhileCycle*>(block)) {
			if (!whileCycle->m_isDoWhileCycle) {
				ShowBlockCode(asmBlock, block, tabStr);
				printf("%swhile(%s) {\n", tabStr.c_str(), whileCycle->m_cond ? whileCycle->m_cond->printDebug().c_str() : "");
				ShowCode(whileCycle->m_mainBranch, asmBlocks, level + 1);
				printf("%s}\n", tabStr.c_str());
			}
			else {
				printf("%sdo {\n", tabStr.c_str());
				ShowCode(whileCycle->m_mainBranch, asmBlocks, level + 1);
				ShowBlockCode(asmBlock, block, "\t" + tabStr);
				printf("%s} while(%s);\n", tabStr.c_str(), whileCycle->m_cond ? whileCycle->m_cond->printDebug().c_str() : "");
			}
		}
		else {
			ShowBlockCode(asmBlock, block, tabStr);
		}

		if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
			if (endBlock->getReturnNode() != nullptr) {
				printf("%sreturn %s\n", tabStr.c_str(), endBlock->getReturnNode()->printDebug().c_str());
			}
		}
	}

	std::string levelInfo;
	if (g_SHOW_LINEAR_LEVEL_EXT) {
		levelInfo = "backOrderId: " + std::to_string(blockList->getBackOrderId()) + "; minLinLevel: " + std::to_string(blockList->getMinLinearLevel()) + ", maxLinLevel: " + std::to_string(blockList->getMaxLinearLevel()) + "";
	}

	if (blockList->m_goto != nullptr) {
		auto gotoType = blockList->getGotoType();
		if (g_SHOW_ALL_GOTO || gotoType != LinearView::GotoType::None) {
			std::string typeName = "";
			if (gotoType == LinearView::GotoType::None)
				typeName = "[None]";
			else if (gotoType == LinearView::GotoType::Normal)
				typeName = "[!!!Normal!!!]";
			else if (gotoType == LinearView::GotoType::Break)
				typeName = "[break]";
			else if (gotoType == LinearView::GotoType::Continue)
				typeName = "[continue]";
			printf("%s//goto to block %s (%s) %s\n", tabStr.c_str(), Generic::String::NumberToHex(asmBlocks[blockList->m_goto->m_decBlock]->ID).c_str(), levelInfo.c_str(), typeName.c_str());
		}
	}
	else if (g_SHOW_ALL_GOTO) {
		printf("%s//goto is null (%s)\n", tabStr.c_str(), levelInfo.c_str());
	}
}

void initUserSymbolDefsForSamples(CE::ProgramModule* programModule, std::map<int, Symbolization::UserSymbolDef>& userSymbolDefs)
{
	userSymbolDefs[0] = Symbolization::UserSymbolDef(programModule);
}

void testSamples(const std::list<std::pair<int, std::vector<byte>*>>& samples, const std::set<int>& samplesWithXMM, const std::map<int, Symbolization::UserSymbolDef>& userSymbolDefs, bool showAsmBefore = true)
{
	for (auto sample : samples) {
		auto data = sample.second->data();
		auto size = (int)sample.second->size();
		printf("SAMPLE %i <----\n", sample.first);

		PCode::TranslatorX86 translatorX86;
		translatorX86.start(data, size);
		AsmGraph graph(translatorX86.m_result);
		graph.build();
		if (showAsmBefore)
			graph.printDebug(data);

		auto info = GetFunctionCallDefaultInfo();
		if (samplesWithXMM.count(sample.first) == 0)
		{
			auto it = info.m_paramRegisters.begin();
			*(it++) = PCode::Register(ZYDIS_REGISTER_RCX, ExtBitMask(4));
			*(it++) = PCode::Register(ZYDIS_REGISTER_RDX, ExtBitMask(4));
			*(it++) = PCode::Register(ZYDIS_REGISTER_R8, ExtBitMask(4));
			*(it++) = PCode::Register(ZYDIS_REGISTER_R9, ExtBitMask(4));
			info.m_resultRegister = PCode::Register(ZYDIS_REGISTER_RAX, ExtBitMask(4));
		}
		else
		{
			auto it = info.m_paramRegisters.begin();
			*(it++) = PCode::Register(ZYDIS_REGISTER_ZMM0, ExtBitMask(4), PCode::Register::Type::Vector);
			*(it++) = PCode::Register(ZYDIS_REGISTER_ZMM1, ExtBitMask(4), PCode::Register::Type::Vector);
			*(it++) = PCode::Register(ZYDIS_REGISTER_ZMM2, ExtBitMask(4), PCode::Register::Type::Vector);
			*(it++) = PCode::Register(ZYDIS_REGISTER_ZMM3, ExtBitMask(4), PCode::Register::Type::Vector);
			info.m_resultRegister = PCode::Register(ZYDIS_REGISTER_ZMM0, ExtBitMask(4), PCode::Register::Type::Vector);
		}

		auto decCodeGraph = new DecompiledCodeGraph(info);
		auto decompiler = new CE::Decompiler::Decompiler(&graph, decCodeGraph);
		decompiler->m_funcCallInfoCallback = [&](int offset, ExprTree::Node* dst) {
			auto absAddr = (std::intptr_t)data + offset;
			return info;
		};
		decompiler->start();

		auto asmBlocks = decompiler->getAsmBlocks();

		//show code
		printf("********************* BEFORE OPTIMIZATION: *********************\n\n");
		LinearView::Converter converter(decCodeGraph);
		converter.start();
		auto blockList = converter.getBlockList();
		OptimizeBlockList(blockList, false);
		ShowCode(blockList, asmBlocks);

		printf("\n\n\n********************* AFTER OPTIMIZATION: *********************\n\n");
		Optimization::OptimizeDecompiledGraph(decCodeGraph);
		converter = LinearView::Converter(decCodeGraph);
		converter.start();
		blockList = converter.getBlockList();
		OptimizeBlockList(blockList);
		ShowCode(blockList, asmBlocks);

		auto it = userSymbolDefs.find(sample.first);
		if (it != userSymbolDefs.end()) {
			printf("\n\n\n********************* AFTER SYMBOLIZATION: *********************\n\n");
			auto userSymbolDef = it->second;
			Symbolization::SymbolizeWithSDA(decCodeGraph, userSymbolDef);
			converter = LinearView::Converter(decCodeGraph);
			converter.start();
			blockList = converter.getBlockList();
			OptimizeBlockList(blockList);
			ShowCode(blockList, asmBlocks);
		}
		printf("\n\n\n\n\n");
	}
}


void CE::test(CE::ProgramModule* programModule) {
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

	std::vector<byte> sample1 = { 0xB0, 0x01, 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0xB4, 0x02, 0x88, 0xC3, 0x88, 0xE1, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00, 0x89, 0x04, 0x25, 0x08, 0x10, 0x00, 0x00 };
	std::vector<byte> sample2 = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x55, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x10, 0x00, 0x88, 0xC1, 0x88, 0xEA, 0x48, 0x29, 0xD8, 0x28, 0xF9, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00 };
	std::vector<byte> sample3 = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x88, 0xE6, 0x88, 0xF1, 0x88, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00 };
	std::vector<byte> sample4 = { 0x67, 0x48, 0x8B, 0x04, 0x95, 0x00, 0x01, 0x00, 0x00, 0x67, 0x03, 0x0C, 0x95, 0x00, 0x02, 0x00, 0x00, 0xBA, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xC2, 0x66, 0xF7, 0xF2, 0x67, 0x88, 0x24, 0xD5, 0x00, 0x01, 0x00, 0x00 };
	std::vector<byte> sample5 = { 0x67, 0x48, 0x8D, 0x04, 0x95, 0x00, 0x01, 0x00, 0x00, 0x67, 0x88, 0x24, 0xD5, 0x00, 0x00, 0x00, 0x00 };
	std::vector<byte> sample6 = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x10, 0x0F, 0xBE, 0xC7, 0x48, 0x89, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00 };
	std::vector<byte> sample7 = { 0x48, 0xC7, 0xC0, 0x55, 0x55, 0x23, 0x10, 0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x10, 0x48, 0x39, 0xD8, 0x48, 0x0F, 0x44, 0xC3, 0x48, 0x89, 0x44, 0x24, 0x30 };
	std::vector<byte> sample8 = { 0x45, 0x31, 0xD2, 0x49, 0x89, 0xCB, 0x48, 0x8B, 0x41, 0x40, 0x4C, 0x63, 0xC2, 0x46, 0x0F, 0xB6, 0x0C, 0x00, 0x8B, 0x41, 0x4C, 0x41, 0x81, 0xE1, 0x80, 0x00, 0x00, 0x00, 0x45, 0x89, 0xC8, 0x0F, 0xAF, 0xC2, 0x89, 0x44, 0x24, 0x14, 0x44, 0x89, 0x44, 0x24, 0x14, 0x48, 0x63, 0xC8, 0x48, 0x89, 0x4C, 0x24, 0x18, 0x44, 0x89, 0xC8, 0x48, 0x89, 0x44, 0x24, 0x18, 0x49, 0x03, 0x4B, 0x38, 0x48, 0xF7, 0xD8, 0x4C, 0x09, 0xC0, 0x48, 0xC1, 0xF8, 0x3F, 0x48, 0xF7, 0xD0, 0x48, 0x85, 0xC8, 0x41, 0x0F, 0x95, 0xC2, 0x44, 0x88, 0xD0, 0x88, 0x44, 0x24, 0x11 };
	std::vector<byte> sample9 = { 0x48, 0x89, 0xE5, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0xE0, 0x48, 0x31, 0xC9, 0x83, 0xC1, 0x10, 0x51, 0xB9, 0x20, 0x00, 0x00, 0x00, 0x5A, 0x89, 0x4C, 0x24, 0x20, 0x89, 0x48, 0x28, 0x89, 0x4D, 0xF8, 0x48, 0x83, 0xC4, 0x30, 0x48, 0x8B, 0x5C, 0x24, 0x08 }; //stack

	//if else / register search
	std::vector<byte> sample10 = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x04, 0x66, 0xB8, 0x02, 0x00, 0x88, 0x44, 0x24, 0x10 };
	std::vector<byte> sample11 = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x07, 0xB8, 0x00, 0x02, 0x00, 0x00, 0xB0, 0x03, 0x88, 0x44, 0x24, 0x10 };
	std::vector<byte> sample12 = { 0xB8, 0x00, 0x10, 0x00, 0x00, 0x88, 0xEC, 0x83, 0xF8, 0x10, 0x75, 0x06, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x07, 0xB8, 0x00, 0x02, 0x00, 0x00, 0xB0, 0x03, 0x88, 0x44, 0x24, 0x10 };
	std::vector<byte> sample13 = { 0xB8, 0x45, 0x23, 0x01, 0x00, 0x88, 0xEC, 0x88, 0xE8, 0x89, 0x44, 0x24, 0x10 };
	std::vector<byte> sample14 = { 0x48, 0x89, 0xD0, 0xB8, 0x45, 0x23, 0x01, 0x00, 0x88, 0xEC, 0x83, 0xF8, 0x10, 0x75, 0x0A, 0x89, 0xD8, 0xEB, 0x00, 0x66, 0xB8, 0x01, 0x00, 0xEB, 0x04, 0x89, 0xC8, 0xB0, 0x03, 0x48, 0x89, 0x44, 0x24, 0x10 };
	std::vector<byte> sample15 = { 0x48, 0xC7, 0xC0, 0x67, 0x45, 0x23, 0x01, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x09, 0x48, 0xC7, 0xC0, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x48, 0x83, 0xC0, 0x04, 0x48, 0x89, 0x44, 0x24, 0x10 };
	std::vector<byte> sample16 = { 0x48, 0xC7, 0xC0, 0x67, 0x45, 0x23, 0x01, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x07, 0xB8, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x83, 0xC0, 0x04, 0x89, 0x44, 0x24, 0x10 };
	std::vector<byte> sample17 = { 0x48, 0xB8, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0xEB, 0x00, 0xB8, 0x56, 0x34, 0x12, 0x00, 0x66, 0x83, 0xF8, 0x12, 0x75, 0x05, 0x83, 0xC0, 0x02, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x00, 0x66, 0x83, 0xC0, 0x03, 0x3C, 0x01, 0x7D, 0x07, 0xB8, 0x23, 0x00, 0x00, 0x10, 0xEB, 0x01, 0x90, 0x83, 0xC0, 0x04, 0x48, 0x89, 0x44, 0x24, 0x10 };

	//mul/div
	std::vector<byte> sample20 = { 0xF7, 0xE1, 0x45, 0x6B, 0xC1, 0x02, 0x41, 0xF7, 0xF0, 0x44, 0x89, 0x44, 0x24, 0x04, 0x89, 0x44, 0x24, 0x04 };
	std::vector<byte> sample21 = { 0x45, 0x0F, 0xB7, 0x41, 0x08, 0x33, 0xD2, 0x8B, 0xC1, 0x41, 0xF7, 0xF0, 0x48, 0x89, 0x44, 0x24, 0x08 };
	std::vector<byte> sample22 = { 0x4D, 0x0F, 0xB7, 0x41, 0x08, 0x31, 0xD2, 0x89, 0xC8, 0x49, 0xF7, 0xF0, 0x48, 0x89, 0x44, 0x24, 0x08 };
	std::vector<byte> sample23 = { 0xF7, 0xE1, 0x83, 0xC0, 0x05, 0x89, 0x44, 0x24, 0x04 };

	//evklid algorithm
	std::vector<byte> sample25 = { 0x89, 0xC8, 0x89, 0xD3, 0x83, 0xF8, 0x00, 0x7D, 0x02, 0xF7, 0xD8, 0x83, 0xFB, 0x00, 0x7D, 0x02, 0xF7, 0xDB, 0x39, 0xD8, 0x7D, 0x01, 0x93, 0x83, 0xFB, 0x00, 0x74, 0x04, 0x29, 0xD8, 0xEB, 0xF2, 0x89, 0x04, 0x24, 0x89, 0x1C, 0x24 };

	//ghidra GTA5
	/* JMP function */ std::vector<byte> sample100 = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xDA, 0x83, 0xFA, 0x0A, 0x7E, 0x10, 0x8D, 0x42, 0xF5, 0x83, 0xF8, 0x0D, 0x77, 0x05, 0x83, 0xC3, 0x19, 0xEB, 0x03, 0x83, 0xEB, 0x0E, 0xE8, 0x46, 0xCA, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x2C, 0x83, 0xFB, 0x31, 0x77, 0x27, 0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43, 0x03, 0x00, 0x48, 0x0F, 0xA3, 0xDA, 0x73, 0x17, 0x48, 0x8B, 0x48, 0x48, 0x4C, 0x8B, 0xC0, 0x8B, 0xD3, 0x48, 0x83, 0xC1, 0x40, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xE9, 0x0D, 0x10, 0x91, 0xFF, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xCC };
	/* RAX request but no EAX */ std::vector<byte> sample101 = { 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x1B, 0xB2, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x0E, 0x48, 0x8B, 0x40, 0x20, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x90, 0x89, 0xED };
	std::vector<byte> sample102 = { 0x48, 0x83, 0xEC, 0x28, 0x8B, 0x44, 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24, 0x40, 0xC7, 0x44, 0x24, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x0F, 0x25, 0xFF, 0xFF, 0xFF, 0x0F, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x50, 0x8F, 0x8B, 0x00, 0x0F, 0xB7, 0x4C, 0x24, 0x40, 0x66, 0x89, 0x4C, 0x24, 0x38, 0x8B, 0x4C, 0x24, 0x38, 0x4C, 0x8B, 0xC0, 0x81, 0xC9, 0x00, 0x00, 0xFF, 0x0F, 0x33, 0xC0, 0x0F, 0xBA, 0xF1, 0x1C, 0x66, 0x81, 0xF9, 0xFF, 0xFF, 0x74, 0x10, 0x4D, 0x85, 0xC0, 0x74, 0x0B, 0x41, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC, 0x54, 0x48 };

	//memory assigments
	std::vector<byte> sample150 = { 0x8B, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x18, 0x89, 0x4C, 0x24, 0x16, 0x48, 0x01, 0xC2, 0x48, 0x89, 0x54, 0x24, 0x18 };
	std::vector<byte> sample151 = { 0x8B, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x18, 0x89, 0x4C, 0x24, 0x16, 0x48, 0x01, 0xC2, 0xE8, 0x00, 0x90, 0x00, 0x00, 0x48, 0x89, 0x54, 0x24, 0x38 };

	//**** XMM ****
	std::vector<byte> sample200 = { 0x40, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xA9, 0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x45, 0x17, 0x44, 0x89, 0x45, 0xBF, 0xF2, 0x0F, 0x11, 0x4D, 0x27, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8D, 0x45, 0xD7, 0x4C, 0x8D, 0x4D, 0xF7, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0xE7, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x48, 0x8D, 0x15, 0x5E, 0xC5, 0x6C, 0x01, 0x48, 0x89, 0x44, 0x24, 0x20, 0x0F, 0x29, 0x45, 0x17, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0x07, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x4C, 0x8D, 0x45, 0x37, 0x0F, 0x29, 0x45, 0xD7, 0x0F, 0x10, 0x45, 0xB7, 0xC7, 0x45, 0xBF, 0x01, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x4D, 0x47, 0x0F, 0x29, 0x45, 0xF7, 0x66, 0x0F, 0x6E, 0xC1, 0x48, 0x8D, 0x0D, 0xC8, 0xF4, 0xE2, 0x01, 0xF3, 0x0F, 0xE6, 0xC0, 0xF2, 0x0F, 0x11, 0x45, 0xB7, 0x0F, 0x10, 0x45, 0xB7, 0x0F, 0x29, 0x45, 0x37, 0xE8, 0xAA, 0xDE, 0xFE, 0xFF, 0x48, 0x81, 0xC4, 0xD0, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xCC };
	std::vector<byte> sample201 = { 0x0F, 0x28, 0x44, 0x24, 0x30, 0x0F, 0x28, 0x4C, 0x24, 0x50, 0x0F, 0x28, 0xD0, 0x0F, 0x58, 0xD1, 0x0F, 0x59, 0xD1, 0x0F, 0x29, 0x94, 0x24, 0x00, 0x01, 0x00, 0x00 };
	//GET_ENTITY_FORWARD_VECTOR
	std::vector<byte> sample202 = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x10, 0x35, 0x21, 0x46, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x0F, 0x29, 0x7C, 0x24, 0x30, 0xF3, 0x0F, 0x10, 0x3D, 0x15, 0x46, 0xF7, 0x01, 0x8B, 0xCA, 0x44, 0x0F, 0x29, 0x44, 0x24, 0x20, 0xF3, 0x44, 0x0F, 0x10, 0x05, 0x08, 0x46, 0xF7, 0x01, 0xE8, 0x5F, 0xE0, 0xFD, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x14, 0x0F, 0x28, 0x70, 0x70, 0x0F, 0x28, 0xFE, 0x44, 0x0F, 0x28, 0xC6, 0x0F, 0xC6, 0xFE, 0x55, 0x44, 0x0F, 0xC6, 0xC6, 0xAA, 0xF3, 0x0F, 0x11, 0x33, 0x0F, 0x28, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x11, 0x7B, 0x08, 0x0F, 0x28, 0x7C, 0x24, 0x30, 0x48, 0x8B, 0xC3, 0xF3, 0x44, 0x0F, 0x11, 0x43, 0x10, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x50, 0x5B, 0xC3, 0x90, 0x48 };
	//Matrix_FillWithVectorsAndMul
	std::vector<byte> sample203 = { 0x4C, 0x8B, 0xDC, 0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00, 0x0F, 0x28, 0x02, 0x48, 0x8B, 0x94, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x41, 0x0F, 0x29, 0x73, 0xE8, 0x41, 0x0F, 0x29, 0x7B, 0xD8, 0x45, 0x0F, 0x29, 0x43, 0xC8, 0x4D, 0x8D, 0x1B, 0x66, 0x0F, 0x70, 0x22, 0x55, 0x66, 0x0F, 0x70, 0x32, 0xAA, 0x66, 0x0F, 0x70, 0x2A, 0x00, 0x45, 0x0F, 0x29, 0x4B, 0xB8, 0x45, 0x0F, 0x29, 0x53, 0xA8, 0x45, 0x0F, 0x29, 0x5B, 0x98, 0x45, 0x0F, 0x29, 0x63, 0x88, 0x44, 0x0F, 0x29, 0x6C, 0x24, 0x30, 0x44, 0x0F, 0x28, 0x28, 0x48, 0x8B, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00, 0x66, 0x0F, 0x70, 0x08, 0x00, 0x66, 0x0F, 0x70, 0x18, 0xAA, 0x44, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x45, 0x0F, 0x28, 0x30, 0x44, 0x0F, 0x29, 0x7C, 0x24, 0x10, 0x4C, 0x8B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00, 0x66, 0x45, 0x0F, 0x70, 0x00, 0x00, 0x66, 0x41, 0x0F, 0x70, 0x38, 0x55, 0x66, 0x45, 0x0F, 0x70, 0x08, 0xAA, 0x45, 0x0F, 0x28, 0x39, 0x0F, 0x29, 0x04, 0x24, 0x41, 0x0F, 0x28, 0xD6, 0x4C, 0x8B, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00, 0x66, 0x0F, 0x70, 0x00, 0x55, 0x66, 0x45, 0x0F, 0x70, 0x11, 0x00, 0x66, 0x45, 0x0F, 0x70, 0x19, 0x55, 0x0F, 0x59, 0xD0, 0x0F, 0x28, 0x04, 0x24, 0x0F, 0x59, 0xC1, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x59, 0xCB, 0x66, 0x45, 0x0F, 0x70, 0x21, 0xAA, 0x0F, 0x58, 0xD0, 0x41, 0x0F, 0x28, 0xDE, 0x0F, 0x59, 0xDC, 0x0F, 0x28, 0x24, 0x24, 0x0F, 0x28, 0xC4, 0x0F, 0x58, 0xD1, 0x0F, 0x59, 0xC5, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x59, 0xCE, 0x0F, 0x58, 0xD8, 0x41, 0x0F, 0x28, 0x73, 0xE8, 0x0F, 0x28, 0xC4, 0x0F, 0x29, 0x11, 0x41, 0x0F, 0x28, 0xD6, 0x41, 0x0F, 0x59, 0xE2, 0x45, 0x0F, 0x59, 0xF3, 0x0F, 0x58, 0xD9, 0x41, 0x0F, 0x58, 0xE5, 0x45, 0x0F, 0x28, 0x53, 0xA8, 0x45, 0x0F, 0x28, 0x5B, 0x98, 0x44, 0x0F, 0x28, 0x6C, 0x24, 0x30, 0x0F, 0x59, 0xD7, 0x41, 0x0F, 0x59, 0xC0, 0x41, 0x0F, 0x58, 0xE6, 0x0F, 0x58, 0xD0, 0x41, 0x0F, 0x28, 0x7B, 0xD8, 0x45, 0x0F, 0x28, 0x43, 0xC8, 0x44, 0x0F, 0x28, 0x74, 0x24, 0x20, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x29, 0x59, 0x10, 0x45, 0x0F, 0x59, 0xFC, 0x41, 0x0F, 0x59, 0xC9, 0x45, 0x0F, 0x28, 0x4B, 0xB8, 0x45, 0x0F, 0x28, 0x63, 0x88, 0x41, 0x0F, 0x58, 0xE7, 0x0F, 0x58, 0xD1, 0x44, 0x0F, 0x28, 0x7C, 0x24, 0x10, 0x0F, 0x29, 0x61, 0x30, 0x0F, 0x29, 0x51, 0x20, 0x49, 0x8B, 0xE3, 0xC3 };
	//float cmp
	std::vector<byte> sample204 = { 0xF3, 0x0F, 0x10, 0x09, 0xF3, 0x0F, 0x10, 0x02, 0x0F, 0x2F, 0xC8, 0x76, 0x08, 0xF3, 0x0F, 0x11, 0x01, 0xF3, 0x0F, 0x11, 0x0A, 0xF3, 0x0F, 0x10, 0x49, 0x04, 0xF3, 0x0F, 0x10, 0x42, 0x04, 0x0F, 0x2F, 0xC8, 0x76, 0x0A, 0xF3, 0x0F, 0x11, 0x41, 0x04, 0xF3, 0x0F, 0x11, 0x4A, 0x04, 0xF3, 0x0F, 0x10, 0x49, 0x08, 0xF3, 0x0F, 0x10, 0x42, 0x08, 0x0F, 0x2F, 0xC8, 0x76, 0x0A, 0xF3, 0x0F, 0x11, 0x41, 0x08, 0xF3, 0x0F, 0x11, 0x4A, 0x08, 0xC3 };
	//GET_ENTITY_SPEED_VECTOR
	std::vector<byte> sample205 = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x0F, 0x29, 0x70, 0xE8, 0xF3, 0x0F, 0x10, 0x35, 0xB4, 0x35, 0xF7, 0x01, 0x0F, 0x29, 0x78, 0xD8, 0xF3, 0x0F, 0x10, 0x3D, 0xAC, 0x35, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x8B, 0xCA, 0x41, 0x8A, 0xF0, 0x44, 0x0F, 0x29, 0x40, 0xC8, 0x44, 0x0F, 0x29, 0x48, 0xB8, 0xF3, 0x44, 0x0F, 0x10, 0x0D, 0x89, 0x35, 0xF7, 0x01, 0xE8, 0x1C, 0xD0, 0xFD, 0xFF, 0x48, 0x8B, 0xF8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x96, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0xC8, 0xFF, 0x92, 0x68, 0x03, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x10, 0x08, 0xF3, 0x0F, 0x10, 0x70, 0x04, 0xF3, 0x0F, 0x10, 0x78, 0x08, 0x40, 0x84, 0xF6, 0x74, 0x76, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0xCF, 0xFF, 0x90, 0x68, 0x03, 0x00, 0x00, 0x44, 0x0F, 0x28, 0x47, 0x60, 0x0F, 0x28, 0x7F, 0x70, 0x0F, 0x28, 0xAF, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xF6, 0x66, 0x0F, 0x70, 0x08, 0x00, 0x66, 0x0F, 0x70, 0x00, 0x55, 0x66, 0x0F, 0x70, 0x18, 0xAA, 0x41, 0x0F, 0x28, 0xE0, 0x0F, 0x28, 0xD7, 0x0F, 0x15, 0xFE, 0x44, 0x0F, 0x15, 0xC5, 0x0F, 0x14, 0xD6, 0x0F, 0x14, 0xE5, 0x44, 0x0F, 0x14, 0xC7, 0x44, 0x0F, 0x28, 0xCC, 0x44, 0x0F, 0x15, 0xCA, 0x0F, 0x14, 0xE2, 0x44, 0x0F, 0x59, 0xC3, 0x44, 0x0F, 0x59, 0xC8, 0x0F, 0x59, 0xE1, 0x44, 0x0F, 0x58, 0xCC, 0x45, 0x0F, 0x58, 0xC8, 0x41, 0x0F, 0x28, 0xF1, 0x41, 0x0F, 0x28, 0xF9, 0x41, 0x0F, 0xC6, 0xF1, 0x55, 0x41, 0x0F, 0xC6, 0xF9, 0xAA, 0x48, 0x8B, 0x74, 0x24, 0x78, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x30, 0xF3, 0x44, 0x0F, 0x11, 0x0B, 0x44, 0x0F, 0x28, 0x4C, 0x24, 0x20, 0xF3, 0x0F, 0x11, 0x73, 0x08, 0x0F, 0x28, 0x74, 0x24, 0x50, 0xF3, 0x0F, 0x11, 0x7B, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x70, 0x0F, 0x28, 0x7C, 0x24, 0x40, 0x48, 0x83, 0xC4, 0x60, 0x5F, 0xC3 };
	//GET_ANGLE_BETWEEN_2D_VECTORS
	std::vector<byte> sample206 = { 0x48, 0x83, 0xEC, 0x38, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xF0, 0x0F, 0x28, 0xE1, 0xF3, 0x0F, 0x59, 0xC9, 0xF3, 0x0F, 0x59, 0xF6, 0xF3, 0x0F, 0x59, 0xE3, 0x0F, 0x28, 0xEA, 0xF3, 0x0F, 0x58, 0xF1, 0xF3, 0x0F, 0x59, 0xC5, 0x0F, 0x57, 0xD2, 0x0F, 0x2F, 0xF2, 0xF3, 0x0F, 0x58, 0xC4, 0x76, 0x09, 0x0F, 0x57, 0xE4, 0xF3, 0x0F, 0x51, 0xE6, 0xEB, 0x03, 0x0F, 0x28, 0xE2, 0xF3, 0x0F, 0x59, 0xED, 0xF3, 0x0F, 0x59, 0xDB, 0xF3, 0x0F, 0x58, 0xEB, 0x0F, 0x2F, 0xEA, 0x76, 0x09, 0x0F, 0x57, 0xC9, 0xF3, 0x0F, 0x51, 0xCD, 0xEB, 0x03, 0x0F, 0x28, 0xCA, 0xF3, 0x0F, 0x10, 0x1D, 0x59, 0xBF, 0xDF, 0x00, 0xF3, 0x0F, 0x59, 0xCC, 0xF3, 0x0F, 0x5E, 0xC1, 0x0F, 0x2F, 0xC3, 0x73, 0x03, 0x0F, 0x28, 0xC3, 0xF3, 0x0F, 0x10, 0x0D, 0xD5, 0xB5, 0xEB, 0x00, 0x0F, 0x2F, 0xC1, 0x76, 0x03, 0x0F, 0x28, 0xC1, 0x0F, 0x2F, 0xC3, 0x76, 0x0F, 0x0F, 0x2F, 0xC1, 0x73, 0x12, 0xE8, 0x12, 0x4F, 0xCC, 0x00, 0x0F, 0x28, 0xD0, 0xEB, 0x08, 0xF3, 0x0F, 0x10, 0x15, 0xED, 0x18, 0xE0, 0x00, 0xF3, 0x0F, 0x59, 0x15, 0xF1, 0xBE, 0xDF, 0x00, 0x0F, 0x28, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xC2, 0x48, 0x83, 0xC4, 0x38, 0xC3 };


	//SET_ENTITY_ANIM_SPEED (����� return � ������ �� �����, � �� ����)
	std::vector<byte> sample300 = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x4C, 0x89, 0x70, 0x20, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x70, 0xE8, 0x4C, 0x8D, 0x0D, 0x9A, 0xBA, 0xE9, 0x00, 0x49, 0x8B, 0xF0, 0x0F, 0x28, 0xF3, 0x4C, 0x8B, 0xF2, 0x8B, 0xF9, 0xE8, 0x3E, 0xCD, 0x00, 0x00, 0x4C, 0x8B, 0xC8, 0x48, 0x85, 0xC0, 0x74, 0x5A, 0x48, 0x8B, 0x40, 0x10, 0x48, 0x85, 0xC0, 0x74, 0x0E, 0x8A, 0x88, 0x14, 0x02, 0x00, 0x00, 0xC0, 0xE9, 0x06, 0x80, 0xE1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x84, 0xC9, 0x75, 0x3D, 0x8B, 0x05, 0xCB, 0x0B, 0x3C, 0x01, 0xA8, 0x01, 0x75, 0x16, 0x83, 0xC8, 0x01, 0x89, 0x05, 0xBE, 0x0B, 0x3C, 0x01, 0xB8, 0x88, 0xC0, 0x68, 0x7E, 0x89, 0x05, 0xAF, 0x0B, 0x3C, 0x01, 0xEB, 0x06, 0x8B, 0x05, 0xA7, 0x0B, 0x3C, 0x01, 0x48, 0x8D, 0x55, 0xE0, 0x0F, 0x28, 0xD6, 0x49, 0x8B, 0xC9, 0x89, 0x45, 0xE0, 0xE8, 0xE9, 0x9A, 0xE1, 0xFF, 0xE9, 0xC8, 0x00, 0x00, 0x00, 0x41, 0xB0, 0x01, 0x41, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x8B, 0xCF, 0x41, 0x8A, 0xD0, 0xE8, 0x5D, 0xC1, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x45, 0x48, 0x8B, 0xD6, 0x33, 0xC9, 0xE8, 0x47, 0x17, 0x7E, 0x00, 0x49, 0x8B, 0xD6, 0x33, 0xC9, 0x89, 0x45, 0xE0, 0xE8, 0x3A, 0x17, 0x7E, 0x00, 0x4C, 0x8D, 0x4D, 0xEC, 0x89, 0x45, 0xE4, 0x48, 0x8D, 0x45, 0xE8, 0x4C, 0x8D, 0x45, 0xE0, 0x48, 0x8D, 0x55, 0xE4, 0x48, 0x8B, 0xCB, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x62, 0xC0, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x0A, 0x44, 0x8A, 0x4D, 0xE8, 0x44, 0x8B, 0x45, 0xEC, 0xEB, 0x5D, 0x41, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xB2, 0x01, 0x8B, 0xCF, 0xE8, 0xFE, 0xC0, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x4E, 0x48, 0x8B, 0xD6, 0x33, 0xC9, 0xE8, 0xE8, 0x16, 0x7E, 0x00, 0x49, 0x8B, 0xD6, 0x33, 0xC9, 0x89, 0x45, 0xEC, 0xE8, 0xDB, 0x16, 0x7E, 0x00, 0x4C, 0x8D, 0x4D, 0xE0, 0x89, 0x45, 0xE8, 0x48, 0x8D, 0x45, 0xE4, 0x4C, 0x8D, 0x45, 0xEC, 0x48, 0x8D, 0x55, 0xE8, 0x48, 0x8B, 0xCB, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x03, 0xC0, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x13, 0x44, 0x8A, 0x4D, 0xE4, 0x44, 0x8B, 0x45, 0xE0, 0x0F, 0x28, 0xCE, 0x48, 0x8B, 0xCB, 0xE8, 0x74, 0x69, 0x8E, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x60, 0x48, 0x8B, 0x74, 0x24, 0x68, 0x48, 0x8B, 0x7C, 0x24, 0x70, 0x0F, 0x28, 0x74, 0x24, 0x40, 0x4C, 0x8B, 0x74, 0x24, 0x78, 0x48, 0x83, 0xC4, 0x50, 0x5D, 0xC3 };


	//**** Loops ****
	//FUN_7ff612fa55c4
	std::vector<byte> sample1000 = { 0x33, 0xD2, 0x48, 0x8D, 0x05, 0x93, 0xB8, 0xC7, 0x01, 0x39, 0x08, 0x74, 0x16, 0x4C, 0x8D, 0x05, 0x88, 0xBC, 0xC7, 0x01, 0x48, 0x83, 0xC0, 0x20, 0xFF, 0xC2, 0x49, 0x3B, 0xC0, 0x7C, 0xEA, 0x83, 0xC8, 0xFF, 0xC3, 0x8B, 0xC2, 0xC3 };
	//GET_HASH_KEY
	std::vector<byte> sample1001 = { 0x45, 0x33, 0xD2, 0x44, 0x8B, 0xC2, 0x4C, 0x8B, 0xC9, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0x08, 0x01, 0x00, 0x00, 0x80, 0x39, 0x22, 0x75, 0x47, 0x49, 0xFF, 0xC1, 0x41, 0x8A, 0x01, 0x84, 0xC0, 0x0F, 0x84, 0xF2, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x1D, 0xB8, 0x3A, 0x77, 0x00, 0x3C, 0x22, 0x0F, 0x84, 0xE3, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0xC0, 0x49, 0xFF, 0xC1, 0x42, 0x0F, 0xB6, 0x04, 0x18, 0x44, 0x03, 0xC0, 0x45, 0x69, 0xC0, 0x01, 0x04, 0x00, 0x00, 0x41, 0x8B, 0xC0, 0xC1, 0xE8, 0x06, 0x44, 0x33, 0xC0, 0x41, 0x8A, 0x01, 0x84, 0xC0, 0x75, 0xD3, 0xE9, 0xB9, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x1D, 0x7F, 0x3A, 0x77, 0x00, 0xF6, 0xC1, 0x03, 0x0F, 0x85, 0xA2, 0x00, 0x00, 0x00, 0x8B, 0x01, 0xEB, 0x72, 0x41, 0x0F, 0xB6, 0x01, 0x49, 0x83, 0xC1, 0x04, 0x42, 0x0F, 0xB6, 0x04, 0x18, 0x44, 0x03, 0xC0, 0x41, 0x0F, 0xB6, 0x41, 0xFD, 0x42, 0x0F, 0xB6, 0x0C, 0x18, 0x45, 0x69, 0xC0, 0x01, 0x04, 0x00, 0x00, 0x41, 0x8B, 0xC0, 0xC1, 0xE8, 0x06, 0x41, 0x33, 0xC0, 0x03, 0xC8, 0x41, 0x0F, 0xB6, 0x41, 0xFE, 0x42, 0x0F, 0xB6, 0x14, 0x18, 0x69, 0xC9, 0x01, 0x04, 0x00, 0x00, 0x8B, 0xC1, 0xC1, 0xE8, 0x06, 0x33, 0xC1, 0x03, 0xD0, 0x41, 0x0F, 0xB6, 0x41, 0xFF, 0x46, 0x0F, 0xB6, 0x04, 0x18, 0x69, 0xD2, 0x01, 0x04, 0x00, 0x00, 0x8B, 0xC2, 0xC1, 0xE8, 0x06, 0x33, 0xC2, 0x44, 0x03, 0xC0, 0x45, 0x69, 0xC0, 0x01, 0x04, 0x00, 0x00, 0x41, 0x8B, 0xC0, 0xC1, 0xE8, 0x06, 0x44, 0x33, 0xC0, 0x41, 0x8B, 0x01, 0x2D, 0x01, 0x01, 0x01, 0x01, 0xA9, 0x80, 0x80, 0x80, 0x80, 0x74, 0x82, 0xEB, 0x1E, 0x0F, 0xB6, 0xC0, 0x49, 0xFF, 0xC1, 0x42, 0x0F, 0xB6, 0x04, 0x18, 0x44, 0x03, 0xC0, 0x45, 0x69, 0xC0, 0x01, 0x04, 0x00, 0x00, 0x41, 0x8B, 0xC0, 0xC1, 0xE8, 0x06, 0x44, 0x33, 0xC0, 0x41, 0x8A, 0x01, 0x84, 0xC0, 0x75, 0xDB, 0x45, 0x8B, 0xD0, 0x43, 0x8D, 0x04, 0xD2, 0x8B, 0xC8, 0xC1, 0xE9, 0x0B, 0x33, 0xC1, 0x69, 0xC0, 0x01, 0x80, 0x00, 0x00, 0xC3 };
	//FUN_7ff614209f14
	std::vector<byte> sample1002 = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0x05, 0x8C, 0xBF, 0x72, 0x01, 0x48, 0x8B, 0xE9, 0x44, 0x8B, 0x40, 0x20, 0x8B, 0x40, 0x10, 0x41, 0xC1, 0xE0, 0x02, 0x41, 0xC1, 0xF8, 0x02, 0x41, 0x2B, 0xC0, 0x0F, 0x85, 0xD3, 0x00, 0x00, 0x00, 0x84, 0xD2, 0x74, 0x09, 0xF6, 0x81, 0xC0, 0xDF, 0x03, 0x00, 0x04, 0x74, 0x07, 0x32, 0xC0, 0xE9, 0xC1, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x71, 0x28, 0x48, 0x85, 0xF6, 0x0F, 0x84, 0xCF, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x76, 0x08, 0x48, 0x8B, 0x5E, 0x10, 0x4D, 0x85, 0xF6, 0x74, 0x10, 0x49, 0x8B, 0x06, 0x49, 0x8B, 0xCE, 0xFF, 0x90, 0x90, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x08, 0x48, 0x8B, 0xF3, 0x48, 0x85, 0xDB, 0xEB, 0xD5, 0x49, 0x8B, 0x46, 0x10, 0x48, 0x8B, 0xBD, 0xA8, 0xDF, 0x03, 0x00, 0x49, 0x8B, 0xCE, 0x8B, 0x18, 0x49, 0x8B, 0x06, 0xFF, 0x50, 0x08, 0x4C, 0x8D, 0x05, 0x72, 0x19, 0x2B, 0x00, 0x48, 0x8D, 0x15, 0x97, 0xF0, 0x3D, 0x00, 0x48, 0x8B, 0xCF, 0x4C, 0x8B, 0xC8, 0x89, 0x5C, 0x24, 0x20, 0xE8, 0x34, 0x36, 0x46, 0xFF, 0x48, 0x8B, 0x8D, 0xA8, 0xDF, 0x03, 0x00, 0x4C, 0x8D, 0x05, 0x8A, 0xA4, 0x42, 0x00, 0x48, 0x8B, 0x01, 0x48, 0x8D, 0x15, 0xF0, 0x0E, 0x34, 0x00, 0xFF, 0x50, 0x30, 0x49, 0x8B, 0x06, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xCE, 0xFF, 0x10, 0x48, 0x3B, 0x75, 0x28, 0x75, 0x08, 0x48, 0x8B, 0x46, 0x10, 0x48, 0x89, 0x45, 0x28, 0x48, 0x3B, 0x75, 0x30, 0x75, 0x08, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x89, 0x55, 0x30, 0x48, 0x8B, 0xCE, 0xE8, 0x60, 0x1A, 0x00, 0x00, 0x4C, 0x8B, 0x06, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCE, 0x41, 0xFF, 0x10, 0xB0, 0x01, 0x48, 0x8B, 0x5C, 0x24, 0x40, 0x48, 0x8B, 0x6C, 0x24, 0x48, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x8B, 0x7C, 0x24, 0x58, 0x48, 0x83, 0xC4, 0x30, 0x41, 0x5E, 0xC3, 0x48, 0x8B, 0x0D, 0xC2, 0xBE, 0x72, 0x01, 0x48, 0x85, 0xC9, 0x74, 0x08, 0x48, 0x8B, 0x01, 0xB2, 0x01, 0xFF, 0x50, 0x18, 0x33, 0xC9, 0xE8, 0x2A, 0xD1, 0xC6, 0xFF, 0xE9, 0xFD, 0xFE, 0xFF, 0xFF };
	//FUN_7ff612dc2b0c
	std::vector<byte> sample1003 = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8B, 0xCA, 0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xC1, 0x4C, 0x2B, 0xC9, 0xB9, 0x32, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD2, 0x43, 0x8A, 0x04, 0x01, 0x41, 0x88, 0x00, 0x49, 0xFF, 0xC0, 0x48, 0xFF, 0xC9, 0x75, 0xF1, 0x48, 0x8D, 0x4B, 0x32, 0xBA, 0x64, 0x00, 0x00, 0x00, 0x42, 0x8A, 0x04, 0x09, 0x88, 0x01, 0x48, 0xFF, 0xC1, 0x48, 0xFF, 0xCA, 0x75, 0xF2, 0x41, 0x8A, 0x82, 0x96, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8B, 0x9C, 0x00, 0x00, 0x00, 0x88, 0x83, 0x96, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x82, 0x98, 0x00, 0x00, 0x00, 0x89, 0x83, 0x98, 0x00, 0x00, 0x00, 0x45, 0x0F, 0xB7, 0x82, 0xA0, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x92, 0x9C, 0x00, 0x00, 0x00, 0x45, 0x0F, 0xB6, 0xC8, 0x41, 0xC1, 0xE8, 0x08, 0x41, 0x83, 0xE0, 0x7F, 0xE8, 0xB3, 0x88, 0x3C, 0x01, 0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 };
	//**** Other ****

	std::set<int> samplesWithXmm = { 206 };
	std::map<int, Symbolization::UserSymbolDef> userSymbolDefs;
	initUserSymbolDefsForSamples(programModule, userSymbolDefs);

	void* addr = &Test_Array;
	auto size = calculateFunctionSize2((byte*)addr, 0);
	std::vector<byte> sample0((byte*)addr, (byte*)addr + size);

	if (true) {
		testSamples({ std::pair(0, &sample0) }, samplesWithXmm, userSymbolDefs, true);
	}

	if (false) {
		printf("\n\n\n\nOTHER:\n\n");
		testSamples({
			std::pair(0, &sample0),
			std::pair(7, &sample7),
			std::pair(25, &sample25),
			std::pair(100, &sample100),
			std::pair(101, &sample101),
			std::pair(102, &sample102),
			std::pair(202, &sample202),
			std::pair(205, &sample205),
			std::pair(206, &sample206),
			std::pair(300, &sample300),
			std::pair(1000, &sample1000),
			std::pair(1001, &sample1001),
			std::pair(1002, &sample1002),
			std::pair(1003, &sample1003),
			}, samplesWithXmm, userSymbolDefs, false);
	}
}
