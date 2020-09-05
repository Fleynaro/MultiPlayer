#include "DecSampleTests.h"

void ProgramModuleFixtureDecSamples::initSampleTestHashes() {
	m_sampleTestHashes = {

	};
}

void ProgramModuleFixtureDecSamples::initSampleTest()
{
	SampleTest* test;
	Signature* sig;

	{
		//multidimension stack array like stackArray[1][2][3]
		test = createSampleTest(1, GetFuncBytes(&Test_Array));
		test->m_enabled = false;
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test1");

		test->m_userSymbolDef.m_stackMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_STACK_VAR, findType("int32_t", "[2][3][4]"), "stackArray"), -0x68);
		test->m_userSymbolDef.m_funcBodyMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_INSTR_VAR, findType("int64_t", ""), "idx"), 4608);
		test->m_userSymbolDef.m_funcBodyMemoryArea->addSymbol((MemorySymbol*)symbolManager()->createSymbol(LOCAL_INSTR_VAR, findType("uint32_t", ""), "result"), 19201);
	}

	{
		//hard work with complex data structures
		test = createSampleTest(2, GetFuncBytes(&Test_StructsAndArray));
		test->m_enabled = false;
	}

	{
		//get entity and copy his coords to the first param
		test = createSampleTest(100, { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x10, 0x35, 0x21, 0x46, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x0F, 0x29, 0x7C, 0x24, 0x30, 0xF3, 0x0F, 0x10, 0x3D, 0x15, 0x46, 0xF7, 0x01, 0x8B, 0xCA, 0x44, 0x0F, 0x29, 0x44, 0x24, 0x20, 0xF3, 0x44, 0x0F, 0x10, 0x05, 0x08, 0x46, 0xF7, 0x01, 0xE8, 0x5F, 0xE0, 0xFD, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x14, 0x0F, 0x28, 0x70, 0x70, 0x0F, 0x28, 0xFE, 0x44, 0x0F, 0x28, 0xC6, 0x0F, 0xC6, 0xFE, 0x55, 0x44, 0x0F, 0xC6, 0xC6, 0xAA, 0xF3, 0x0F, 0x11, 0x33, 0x0F, 0x28, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x11, 0x7B, 0x08, 0x0F, 0x28, 0x7C, 0x24, 0x30, 0x48, 0x8B, 0xC3, 0xF3, 0x44, 0x0F, 0x11, 0x43, 0x10, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x50, 0x5B, 0xC3, 0x90, 0x48 });
		test->m_enabled = true;
		test->m_showAsm = test->m_showCode = true;
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test200");
		sig->addParameter("myParam1", findType("uint32_t", "[1]"));

		{
			auto vec3D = typeManager()->createStructure("vec3D", "");
			vec3D->addField(0x0, "x", findType("uint32_t", ""));
			vec3D->addField(0x4, "y", findType("uint32_t", ""));
			vec3D->addField(0x8, "z", findType("uint32_t", ""));
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
}

void ProgramModuleFixtureDecSamples::checkHash(int type, std::list<std::pair<int, ObjectHash::Hash>>& sampleTestHashes, ObjectHash::Hash hash, SampleTest* sampleTest) {
	auto ID = (sampleTest->m_testId << 1) | type;
	auto it = m_sampleTestHashes.find(ID);
	if (it != m_sampleTestHashes.end()) {
		ASSERT_EQ(hash, it->second);
	}
	sampleTestHashes.push_back(std::make_pair(ID, hash));
}

TEST_F(ProgramModuleFixtureDecSamples, Test_DecSamples)
{
	std::list<std::pair<int, ObjectHash::Hash>> sampleTestHashes;

	for (auto sampleTest : m_sampleTests) {
		if (!sampleTest->m_enabled)
			continue;
		m_isOutput = sampleTest->m_showCode;

		std::list<Instruction*> decodedInstructions;
		RegisterFactoryX86 registerFactoryX86;
		PCode::DecoderX86 decoder(&registerFactoryX86);
		int offset = 0;
		while (offset < sampleTest->m_content.size()) {
			decoder.decode(sampleTest->m_content.data() + offset, offset, (int)sampleTest->m_content.size());
			if (decoder.getDecodedPCodeInstructions().empty())
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
		if (m_isOutput && sampleTest->m_showAsm)
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
		out("********************* BEFORE OPTIMIZATION: *********************\n\n");
		LinearView::Converter converter(decCodeGraph);
		converter.start();
		auto blockList = converter.getBlockList();
		OptimizeBlockList(blockList, false);
		LinearViewSimpleConsoleOutput output(blockList, decCodeGraph);
		if (m_isOutput) {
			output.show();
		}

		out("\n\n\n********************* AFTER OPTIMIZATION: *********************\n\n");
		auto clonedDecCodeGraph = decCodeGraph->clone();
		clonedDecCodeGraph->checkOnSingleParents();
		Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);
		clonedDecCodeGraph->checkOnSingleParents();
		converter = LinearView::Converter(clonedDecCodeGraph);
		converter.start();
		blockList = converter.getBlockList();
		OptimizeBlockList(blockList);
		LinearViewSimpleConsoleOutput output2(blockList, clonedDecCodeGraph);
		if (m_isOutput) {
			output2.show();
		}

		checkHash(0, sampleTestHashes, clonedDecCodeGraph->getHash(), sampleTest);

		if (sampleTest->m_symbolization) {
			out("\n\n\n********************* AFTER SYMBOLIZATION: *********************\n\n");
			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);
			Symbolization::SymbolizeWithSDA(sdaCodeGraph, sampleTest->m_userSymbolDef);
			clonedDecCodeGraph->checkOnSingleParents();
			converter = LinearView::Converter(sdaCodeGraph->getDecGraph());
			converter.start();
			blockList = converter.getBlockList();
			OptimizeBlockList(blockList);

			//show all symbols
			sdaCodeGraph->getSdaSymbols().sort([](CE::Symbol::AbstractSymbol* a, CE::Symbol::AbstractSymbol* b) { return a->getName() < b->getName(); });
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
			output.setMinInfoToShow();
			if (m_isOutput) {
				output3.show();
			}

			checkHash(1, sampleTestHashes, sdaCodeGraph->getDecGraph()->getHash(), sampleTest);
		}
		out("\n\n\n\n\n");
	}

	out("{");
	int i = 0;
	for (auto pair : sampleTestHashes) {
		out("std::pair(%i,0x%x),", pair.first, pair.second);
		if (i % 10 == 0)
			out("\n");
	}
	out("}");
}