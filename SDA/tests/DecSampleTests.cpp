#include "DecSampleTests.h"

TEST(Decompiler, Test_MemLocation)
{
	MemLocation loc1;
	MemLocation loc2;
	loc1.m_type = MemLocation::GLOBAL;
	loc2.m_type = MemLocation::GLOBAL;

	loc1.m_offset = 0x1000;
	loc1.m_valueSize = 0x4;
	loc2.m_offset = 0x1004;
	loc2.m_valueSize = 0x4;
	ASSERT_EQ(loc1.intersect(loc2), false);
	loc1.m_offset = 0x1001;
	ASSERT_EQ(loc1.intersect(loc2), true);
	loc1.m_valueSize = 0x2;
	ASSERT_EQ(loc1.intersect(loc2), false);
}

void ProgramModuleFixtureDecSamples::initSampleTestHashes() {
	m_sampleTestHashes = {
		
	};
}

void ProgramModuleFixtureDecSamples::initSampleTest()
{
	SampleTest* test;
	Signature* sig;
	
	//ignore all tests except
	//m_doTestIdOnly = 1;

	{
		//multidimension stack array like stackArray[1][2][3]
		test = createSampleTest(1, GetFuncBytes(&Test_Array));
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		test->m_symbolization = true;
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test1");
		sig->setReturnType(findType("uint64_t"));

		test->m_userSymbolDef.m_stackMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_STACK_VAR, findType("int32_t", "[2][3][4]"), "stackArray"), -0x68);
		test->m_userSymbolDef.m_funcBodyMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_INSTR_VAR, findType("int64_t", ""), "idx"), 4608);
		test->m_userSymbolDef.m_funcBodyMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_INSTR_VAR, findType("uint32_t", ""), "result"), 19201);
	}

	{
		//hard work with complex data structures
		test = createSampleTest(2, GetFuncBytes(&Test_StructsAndArray));
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test2");
		sig->addParameter("myParam1", findType("uint32_t", "[1]"));
		sig->setReturnType(findType("int32_t"));

		test->m_userSymbolDef.m_funcBodyMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_INSTR_VAR, findType("uint32_t", "[1]"), "someObject"), 9985);
	}

	{
		//get entity and copy his coords to the first param
		test = createSampleTest(100, { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x10, 0x35, 0x21, 0x46, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x0F, 0x29, 0x7C, 0x24, 0x30, 0xF3, 0x0F, 0x10, 0x3D, 0x15, 0x46, 0xF7, 0x01, 0x8B, 0xCA, 0x44, 0x0F, 0x29, 0x44, 0x24, 0x20, 0xF3, 0x44, 0x0F, 0x10, 0x05, 0x08, 0x46, 0xF7, 0x01, 0xE8, 0x5F, 0xE0, 0xFD, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x14, 0x0F, 0x28, 0x70, 0x70, 0x0F, 0x28, 0xFE, 0x44, 0x0F, 0x28, 0xC6, 0x0F, 0xC6, 0xFE, 0x55, 0x44, 0x0F, 0xC6, 0xC6, 0xAA, 0xF3, 0x0F, 0x11, 0x33, 0x0F, 0x28, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x11, 0x7B, 0x08, 0x0F, 0x28, 0x7C, 0x24, 0x30, 0x48, 0x8B, 0xC3, 0xF3, 0x44, 0x0F, 0x11, 0x43, 0x10, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x50, 0x5B, 0xC3, 0x90, 0x48 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test100");
		sig->addParameter("myParam1", findType("uint32_t", "[1]"));
		sig->setReturnType(findType("uint64_t"));

		{
			auto vec3D = typeManager()->createStructure("vec3D", "");
			vec3D->addField(0x0, "x", findType("float", ""));
			vec3D->addField(0x4, "y", findType("float", ""));
			vec3D->addField(0x8, "z", findType("float", ""));
			auto pos = typeManager()->createStructure("Pos", "");
			pos->addField(0x0, "vec", GetUnit(vec3D));
			pos->addField(0xC, "w", findType("uint32_t", ""));
			auto entity = typeManager()->createStructure("Entity", "");
			entity->addField(0x70, "pos", GetUnit(pos));

			auto sig = test->m_functions[0xfffffffffffde098] = typeManager()->createSignature("getEntitySig");
			sig->addParameter("param1", findType("uint32_t"));
			sig->setReturnType(GetUnit(entity, "[1]"));
			test->m_userSymbolDef.m_globalMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(FUNCTION, GetUnit(sig), "getEntity"), 0xfffffffffffde098);
		}
	}

	{
		//GET_ANGLE_BETWEEN_2D_VECTORS
		test = createSampleTest(101, { 0x48, 0x83, 0xEC, 0x38, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xF0, 0x0F, 0x28, 0xE1, 0xF3, 0x0F, 0x59, 0xC9, 0xF3, 0x0F, 0x59, 0xF6, 0xF3, 0x0F, 0x59, 0xE3, 0x0F, 0x28, 0xEA, 0xF3, 0x0F, 0x58, 0xF1, 0xF3, 0x0F, 0x59, 0xC5, 0x0F, 0x57, 0xD2, 0x0F, 0x2F, 0xF2, 0xF3, 0x0F, 0x58, 0xC4, 0x76, 0x09, 0x0F, 0x57, 0xE4, 0xF3, 0x0F, 0x51, 0xE6, 0xEB, 0x03, 0x0F, 0x28, 0xE2, 0xF3, 0x0F, 0x59, 0xED, 0xF3, 0x0F, 0x59, 0xDB, 0xF3, 0x0F, 0x58, 0xEB, 0x0F, 0x2F, 0xEA, 0x76, 0x09, 0x0F, 0x57, 0xC9, 0xF3, 0x0F, 0x51, 0xCD, 0xEB, 0x03, 0x0F, 0x28, 0xCA, 0xF3, 0x0F, 0x10, 0x1D, 0x59, 0xBF, 0xDF, 0x00, 0xF3, 0x0F, 0x59, 0xCC, 0xF3, 0x0F, 0x5E, 0xC1, 0x0F, 0x2F, 0xC3, 0x73, 0x03, 0x0F, 0x28, 0xC3, 0xF3, 0x0F, 0x10, 0x0D, 0xD5, 0xB5, 0xEB, 0x00, 0x0F, 0x2F, 0xC1, 0x76, 0x03, 0x0F, 0x28, 0xC1, 0x0F, 0x2F, 0xC3, 0x76, 0x0F, 0x0F, 0x2F, 0xC1, 0x73, 0x12, 0xE8, 0x12, 0x4F, 0xCC, 0x00, 0x0F, 0x28, 0xD0, 0xEB, 0x08, 0xF3, 0x0F, 0x10, 0x15, 0xED, 0x18, 0xE0, 0x00, 0xF3, 0x0F, 0x59, 0x15, 0xF1, 0xBE, 0xDF, 0x00, 0x0F, 0x28, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xC2, 0x48, 0x83, 0xC4, 0x38, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test101");
		sig->addParameter("X1", findType("float", ""));
		sig->addParameter("Y1", findType("float", ""));
		sig->addParameter("X2", findType("float", ""));
		sig->addParameter("Y2", findType("float", ""));
		sig->setReturnType(findType("float"));
	}
}

bool ProgramModuleFixtureDecSamples::checkHash(int type, std::list<std::pair<int, HS::Value>>& sampleTestHashes, HS::Value hash, SampleTest* sampleTest) {
	auto ID = (sampleTest->m_testId << 1) | type;
	sampleTestHashes.push_back(std::make_pair(ID, hash));
	auto it = m_sampleTestHashes.find(ID);
	if (it != m_sampleTestHashes.end()) {
		return hash == it->second;
	}
	return true;
}

TEST_F(ProgramModuleFixtureDecSamples, Test_Dec_Samples)
{
	std::list<std::pair<int, HS::Value>> sampleTestHashes;
	bool testFail = false;

	if (m_doTestIdOnly) {
		printf("\n\n\n\nONLY ONE TEST ID %i IS ACTIVE\n\n\n", m_doTestIdOnly);
	}

	for (auto sampleTest : m_sampleTests) {
		if (m_doTestIdOnly && m_doTestIdOnly != sampleTest->m_testId)
			continue;
		if (!sampleTest->m_enabled)
			continue;
		m_isOutput = sampleTest->m_showAllCode;

		std::list<Instruction*> decodedInstructions;
		RegisterFactoryX86 registerFactoryX86;
		PCode::DecoderX86 decoder(&registerFactoryX86);
		int offset = 0;
		while (offset < sampleTest->m_content.size()) {
			decoder.decode(sampleTest->m_content.data() + offset, offset, (int)sampleTest->m_content.size());
			if (decoder.getInstructionLength() == 0)
				break;
			decodedInstructions.insert(decodedInstructions.end(), decoder.getDecodedPCodeInstructions().begin(), decoder.getDecodedPCodeInstructions().end());
			offset += decoder.getInstructionLength();
		}

		std::map<PCode::Instruction*, DataValue> constValues;
		PCode::VirtualMachineContext vmCtx;
		PCode::ConstValueCalculating constValueCalculating(&decodedInstructions, &vmCtx, &registerFactoryX86);
		constValueCalculating.start(constValues);

		AsmGraph graph(decodedInstructions, constValues);
		graph.build();
		if (m_isOutput && sampleTest->m_showAsmBefore)
			graph.printDebug(sampleTest->m_content.data());

		auto info = CE::Decompiler::GetFunctionCallInfo(sampleTest->m_userSymbolDef.m_signature);
		auto decCodeGraph = new DecompiledCodeGraph(&graph, info);
		
		auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) {
			if (offset != 0x0) {
				auto it = sampleTest->m_functions.find(offset);
				if (it != sampleTest->m_functions.end())
					return CE::Decompiler::GetFunctionCallInfo(it->second);
			}
			return CE::Decompiler::GetFunctionCallInfo(m_defSignature);
		};
		auto decompiler = new CE::Decompiler::Decompiler(decCodeGraph, &registerFactoryX86, funcCallInfoCallback);
		decompiler->start();

		//show code
		out("********************* BEFORE OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
		auto blockList = buildBlockList(decCodeGraph);
		LinearViewSimpleConsoleOutput output(blockList, decCodeGraph);
		if (m_isOutput) {
			output.show();
		}

		auto clonedDecCodeGraph = decCodeGraph->clone();
		clonedDecCodeGraph->checkOnSingleParents();
		Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);
		clonedDecCodeGraph->checkOnSingleParents();
		if (!checkHash(0, sampleTestHashes, clonedDecCodeGraph->getHash().getHashValue(), sampleTest)) {
			printf("\n\nHERE IS THE TROUBLE:");
			m_isOutput = true;
			testFail = true;
		}
		out("\n\n\n********************* AFTER OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
		blockList = buildBlockList(clonedDecCodeGraph);
		LinearViewSimpleConsoleOutput output2(blockList, clonedDecCodeGraph);
		if (m_isOutput) {
			output2.show();
		}

		if (sampleTest->m_symbolization) {
			m_isOutput |= sampleTest->m_showSymbCode;
			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);
			Symbolization::SymbolizeWithSDA(sdaCodeGraph, sampleTest->m_userSymbolDef);
			
			if (!checkHash(1, sampleTestHashes, sdaCodeGraph->getDecGraph()->getHash().getHashValue(), sampleTest)) {
				printf("\n\nHERE IS THE TROUBLE:");
				m_isOutput = true;
				testFail = true;
			}
			out("\n\n\n********************* AFTER SYMBOLIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			blockList = buildBlockList(sdaCodeGraph->getDecGraph());

			//show all symbols
			sdaCodeGraph->getSdaSymbols().sort([](CE::Symbol::ISymbol* a, CE::Symbol::ISymbol* b) { return a->getName() < b->getName(); });
			for (auto var : sdaCodeGraph->getSdaSymbols()) {
				std::string comment = "//priority: " + std::to_string(var->getDataType()->getPriority());
				//size
				if (var->getDataType()->isArray())
					comment += ", size: " + std::to_string(var->getDataType()->getSize());
				//offsets
				if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(var)) {
					if (!autoSdaSymbol->getInstrOffsets().empty()) {
						comment += ", offsets: ";
						for (auto off : autoSdaSymbol->getInstrOffsets()) {
							comment += std::to_string(off) + ", ";
						}
						comment.pop_back();
						comment.pop_back();
					}
				}
				out("%s %s; %s\n", var->getDataType()->getDisplayName().c_str(), var->getName().c_str(), comment.c_str());
			}
			out("\n");
			LinearViewSimpleConsoleOutput output3(blockList, sdaCodeGraph->getDecGraph());
			output3.setMinInfoToShow();
			if (m_isOutput) {
				output3.show();
			}
			clonedDecCodeGraph->checkOnSingleParents();

			m_isOutput |= sampleTest->m_showFinalResult;
			out("\n\n\n********************* AFTER FINAL OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			Optimization::MakeFinalGraphOptimization(sdaCodeGraph);
			blockList = buildBlockList(sdaCodeGraph->getDecGraph());
			clonedDecCodeGraph->checkOnSingleParents();
			LinearViewSimpleConsoleOutput output4(blockList, sdaCodeGraph->getDecGraph());
			output4.setMinInfoToShow();
			if (m_isOutput) {
				output4.show();
			}
		}
		out("\n\n\n\n\n");
	}

	printf("\nhashes\n{\n");
	int i = 1;
	for (auto pair : sampleTestHashes) {
		printf("std::pair(%i,0x%I64x),", pair.first, pair.second);
		if (i % 6 == 0)
			printf("\n");
		else printf(" ");
	}
	printf("\n}\n\n");

	if (testFail)
		FAIL();
}