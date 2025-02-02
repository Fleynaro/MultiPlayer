#include "DecSampleTests.h"

// MEMORY LOCATION
TEST(Decompiler, Test_MemLocation)
{
	MemLocation loc1;
	MemLocation loc2;
	loc1.m_type = MemLocation::GLOBAL;
	loc2.m_type = MemLocation::GLOBAL;

	//generic offsets
	loc1.m_offset = 0x1000;
	loc1.m_valueSize = 0x4;
	loc2.m_offset = 0x1004;
	loc2.m_valueSize = 0x4;
	ASSERT_EQ(loc1.intersect(loc2), false);
	ASSERT_EQ(loc2.intersect(loc1), false);
	loc1.m_offset = 0x1001;
	ASSERT_EQ(loc1.intersect(loc2), true);
	ASSERT_EQ(loc2.intersect(loc1), true);
	loc1.m_valueSize = 0x2;
	ASSERT_EQ(loc1.intersect(loc2), false);
	ASSERT_EQ(loc2.intersect(loc1), false);
	//negative offsets
	loc1.m_offset = -160;
	loc1.m_valueSize = 0x4;
	loc2.m_offset = -156;
	loc2.m_valueSize = 0x4;
	ASSERT_EQ(loc2.intersect(loc1), false);
	ASSERT_EQ(loc1.intersect(loc2), false);
	//array
	loc1.m_offset = 0x1000;
	loc1.addArrayDim(0x4, 20);
	loc1.m_valueSize = 0x4;
	loc2.m_offset = 0x1000 + 100;
	loc2.m_valueSize = 0x4;
	ASSERT_EQ(loc2.intersect(loc1), false);
	ASSERT_EQ(loc1.intersect(loc2), false);
	loc1.addArrayDim(0x8, 20);
	ASSERT_EQ(loc2.intersect(loc1), true);
	ASSERT_EQ(loc1.intersect(loc2), true);
}

// IMAGE
TEST_F(ProgramModuleFixtureDecComponent, Test_Image)
{
	return;

	// R:\\Rockstar Games\\Grand Theft Auto V\\GTA5_dump.exe
	char* buffer;
	int size;
	PEImage::LoadPEImage("R:\\Rockstar Games\\Grand Theft Auto V\\GTA5_dump.exe", &buffer, &size);
	
	auto image = new PEImage((byte*)buffer, size);
	auto imageGraph = new ImagePCodeGraph;

	WarningContainer warningContainer;
	PCode::DecoderX86 decoder(&m_registerFactoryX86, &warningContainer);
	PCodeGraphReferenceSearch graphReferenceSearch(m_programModule, &m_registerFactoryX86, image);

	ImageAnalyzer imageAnalyzer(image, imageGraph, &decoder, &m_registerFactoryX86, &graphReferenceSearch);
	imageAnalyzer.start(0x11ea44); //0x9f39d8
	if (warningContainer.hasAnything()) {
		printf("\nTROUBLES:\n%s\n", warningContainer.getAllMessages().c_str());
	}

	if (false) {
		auto programGraph = new ProgramGraph(imageGraph);
		ImagePCodeGraphAnalyzer graphAnalyzer(programGraph, m_programModule, &m_registerFactoryX86);
		graphAnalyzer.start();
	}

	bool showAllInfo = true;

	for (auto graph : imageGraph->getFunctionGraphList())
	{
		if (showAllInfo)
			graph->printDebug(0x0);

		auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return m_defSignature->getCallInfo(); };
		auto decompiler = new CE::Decompiler::Decompiler(graph, funcCallInfoCallback, m_defSignature->getCallInfo().getReturnInfo(), &m_registerFactoryX86);
		decompiler->start();

		auto decCodeGraph = decompiler->getDecGraph();
		showDecGraph(decCodeGraph);

		if(showAllInfo)
			showDecGraph(decCodeGraph);

		auto sdaCodeGraph = new SdaCodeGraph(decCodeGraph);
		auto userSymbolDef = Misc::CreateUserSymbolDef(m_programModule);
		userSymbolDef.m_signature = m_defSignature;
		{

		}

		Symbolization::DataTypeFactory dataTypeFactory(userSymbolDef.m_programModule);
		Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &userSymbolDef, &dataTypeFactory);
		sdaBuilding.start();
		if (showAllInfo) {
			printf(Misc::ShowAllSymbols(sdaCodeGraph).c_str());
			showDecGraph(sdaCodeGraph->getDecGraph());
		}

		Symbolization::SdaDataTypesCalculater sdaDataTypesCalculating(sdaCodeGraph, userSymbolDef.m_signature, &dataTypeFactory);
		sdaDataTypesCalculating.start();
		printf(Misc::ShowAllSymbols(sdaCodeGraph).c_str());
		if (showAllInfo)
			showDecGraph(sdaCodeGraph->getDecGraph());

		Optimization::MakeFinalGraphOptimization(sdaCodeGraph);
		showDecGraph(sdaCodeGraph->getDecGraph(), true);
		printf("+++++++++++++++++\n\n\n\n");
	}
}

// 1) DECODERS
TEST_F(ProgramModuleFixtureDecComponent, Test_Decoder)
{
	if (false) {
		auto instructions = decode({ 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xF8, 0x02, 0x0F, 0x10, 0x44, 0x24, 0x20, 0x75, 0x05, 0x0F, 0x10, 0x44, 0x24, 0x10, 0x0F, 0x11, 0x44, 0x24, 0x10 });
		showInstructions(instructions);
	}
}

// 2) VIRTUAL MACHINE
TEST_F(ProgramModuleFixtureDecComponent, Test_VM)
{
	auto var1 = new SymbolVarnode(4);
	std::list<Instruction*> instructions = {
		new Instruction(InstructionId::INT_ADD, new ConstantVarnode(7, 4), new ConstantVarnode(5, 4), var1, 0, 0, 0), // 7 + 5 = 12
		new Instruction(InstructionId::INT_MULT, new ConstantVarnode(5, 4), var1, var1, 0, 0, 0), // 5 * 12 = 60
		new Instruction(InstructionId::CALL, var1, nullptr, new SymbolVarnode(4), 0, 0, 0)
	};
	auto constValues = executeAndCalcConstValue(instructions);
	ASSERT_EQ((*constValues.begin()).second, 60);

	//showInstructions(instructions);
	//showConstValues(constValues);
}

// 3) EXPR. OPTIMIZATION
TEST_F(ProgramModuleFixtureDecComponent, Test_ExprOptim)
{
	NodeCloneContext exprCloneCtx;
	auto rcx = new CE::Decompiler::Symbol::RegisterVariable(m_registerFactoryX86.createRegister(ZYDIS_REGISTER_RCX, 8));
	auto rdx = new CE::Decompiler::Symbol::RegisterVariable(m_registerFactoryX86.createRegister(ZYDIS_REGISTER_RDX, 8));
	auto expr1 = new OperationalNode(new NumberLeaf((uint64_t)2, 8), new NumberLeaf((uint64_t)0x10, 8), Mul); // 2 * 0x10 = 0x20
	auto expr2 = new OperationalNode(new SymbolLeaf(rcx), expr1, Add); // rcx + 0x20
	auto expr3 = new OperationalNode(new SymbolLeaf(rdx), expr2, Add); // rcx + 0x20 + rdx
	auto expr4 = new OperationalNode(expr3, expr1, Add); // (rcx + 0x20 + rdx) + 0x20
	auto result = new OperationalNode(expr4, new NumberLeaf((uint64_t)0xFFFF, 8), And);
	
	printf("before: %s\n", result->printDebug().c_str());

	auto clone1 = new TopNode(result->clone(&exprCloneCtx));
	optimize(clone1);
	printf("after: %s\n", clone1->getNode()->printDebug().c_str());

	replaceSymbolWithExpr(clone1->getNode(), rcx, new NumberLeaf((uint64_t)0x5, 8)); // rcx -> 0x5
	replaceSymbolWithExpr(clone1->getNode(), rdx, new NumberLeaf((uint64_t)0x5, 8)); // rdx -> 0x5
	auto clone2 = new TopNode(clone1->getNode()->clone(&exprCloneCtx));
	optimize(clone2);
	ASSERT_EQ(dynamic_cast<NumberLeaf*>(clone2->getNode())->getValue(), 0x40 + 0x5 + 0x5);
}

// 4) SYMBOLIZATION
TEST_F(ProgramModuleFixtureDecComponent, Test_Symbolization)
{
	std::list<Instruction*> instructions;
	auto rip = new CE::Decompiler::PCode::RegisterVarnode(m_registerFactoryX86.createInstructionPointerRegister());
	auto rsp = new CE::Decompiler::PCode::RegisterVarnode(m_registerFactoryX86.createStackPointerRegister());
	SymbolVarnode* addr = new SymbolVarnode(8);
	SymbolVarnode* val4 = new SymbolVarnode(4);
	SymbolVarnode* val8 = new SymbolVarnode(8);
	auto userSymbolDef = Misc::CreateUserSymbolDef(m_programModule);
	//userSymbolDef.m_signature = m_defSignature;

	switch (1)
	{
	case 1: {
		SymbolVarnode* playerPos[] = { new SymbolVarnode(4), new SymbolVarnode(4), new SymbolVarnode(4) };
		SymbolVarnode* playerId = new SymbolVarnode(4);
		auto offset = 0.5f;

		{
			auto entity = typeManager()->createStructure("EntityTest", "");
			entity->addField(0x0, "vec", GetUnit(m_vec3D));
			entity->addField(0xC, "id", findType("uint32_t", ""));
			userSymbolDef.m_globalSymbolTable->addSymbol(new GlobalVarSymbol(symbolManager(), 0x100, GetUnit(entity), "entity1"), 0x100);
			userSymbolDef.m_globalSymbolTable->addSymbol(new GlobalVarSymbol(symbolManager(), 0x200, GetUnit(entity), "entity2"), 0x200);
		}

		instructions = {
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0x0, 8), addr),
			new Instruction(InstructionId::STORE, addr, new ConstantVarnode(0, 4), nullptr),

			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0x0, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, playerPos[0]),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0x4, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, playerPos[1]),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0x8, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, playerPos[2]),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0xC, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, playerId),

			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100 + 0x4, 8), addr),
			new Instruction(InstructionId::STORE, addr, new ConstantVarnode(0, 4), nullptr),

			new Instruction(InstructionId::FLOAT_ADD, playerPos[0], new ConstantVarnode((uint32_t&)offset, 4), playerPos[0]),
			new Instruction(InstructionId::FLOAT_ADD, playerPos[1], new ConstantVarnode((uint32_t&)offset, 4), playerPos[1]),
			new Instruction(InstructionId::FLOAT_ADD, playerPos[2], new ConstantVarnode((uint32_t&)offset, 4), playerPos[2]),

			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x1000, 8), addr),
			//new Instruction(InstructionId::CALL, addr, nullptr, nullptr, 15, 1, 1),

			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x200 + 0x0, 8), addr),
			new Instruction(InstructionId::STORE, addr, playerPos[0], nullptr),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x200 + 0x4, 8), addr),
			new Instruction(InstructionId::STORE, addr, playerPos[1], nullptr),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x200 + 0x8, 8), addr),
			new Instruction(InstructionId::STORE, addr, playerPos[2], nullptr),
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x200 + 0xC, 8), addr),
			new Instruction(InstructionId::STORE, addr, playerId, nullptr),
		};
		break;
	}

	case 2: {
		auto rcx = new CE::Decompiler::PCode::RegisterVarnode(m_registerFactoryX86.createRegister(ZYDIS_REGISTER_RCX, 0x8));
		auto rdx = new CE::Decompiler::PCode::RegisterVarnode(m_registerFactoryX86.createRegister(ZYDIS_REGISTER_RDX, 0x8));
		SymbolVarnode* gvar_val = new SymbolVarnode(4);
		SymbolVarnode* stack_val = new SymbolVarnode(4);
		SymbolVarnode* arr_val = new SymbolVarnode(4);

		// TODO: if-else

		{
			//userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), findType("uint32_t", "[1]"), "userVar1"), 2304);
		}

		instructions = {
			// global var
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x100, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, gvar_val),

			// stack var
			new Instruction(InstructionId::INT_ADD, rsp, new ConstantVarnode(0x10, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, stack_val),

			// array
			new Instruction(InstructionId::INT_ADD, rip, new ConstantVarnode(0x10, 8), addr),
			new Instruction(InstructionId::INT_MULT, rdx, new ConstantVarnode(0x4, 8), val8),
			new Instruction(InstructionId::INT_ADD, addr, val8, addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, arr_val),

			// class field 1
			new Instruction(InstructionId::INT_ADD, rcx, new ConstantVarnode(0x10, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, addr),
			new Instruction(InstructionId::INT_ADD, addr, new ConstantVarnode(0x4, 8), addr),
			new Instruction(InstructionId::LOAD, addr, nullptr, val4),
			new Instruction(InstructionId::INT_MULT, val4, new ConstantVarnode(0x2, 8), val4),
			new Instruction(InstructionId::STORE, addr, val4, nullptr),

			// class field 2
			new Instruction(InstructionId::INT_ADD, rcx, new ConstantVarnode(0x20, 8), addr),
			new Instruction(InstructionId::COPY, gvar_val, nullptr, val4),
			new Instruction(InstructionId::INT_ADD, val4, stack_val, val4),
			new Instruction(InstructionId::STORE, addr, val4, nullptr),

			// class field 2
			new Instruction(InstructionId::INT_ADD, rcx, new ConstantVarnode(0x30, 8), addr),
			new Instruction(InstructionId::STORE, addr, arr_val, nullptr),
		};
		break;
	}
	}

	auto imageGraph = new ImagePCodeGraph;
	WarningContainer warningContainer;
	PCode::DecoderX86 decoder(&m_registerFactoryX86, &warningContainer);
	ImageAnalyzer imageAnalyzer(new SimpleBufferImage(nullptr, 0), imageGraph, &decoder, &m_registerFactoryX86);

	std::map<int64_t, PCode::Instruction*> offsetToInstruction;
	int i = 0;
	for (auto instr : instructions) {
		instr->setInfo(i++, 1, 0);
		offsetToInstruction[instr->getOffset()] = instr;
	}
	imageAnalyzer.start(0, offsetToInstruction, true);

	auto graph = *imageGraph->getFunctionGraphList().begin();

	auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return m_defSignature->getCallInfo(); };
	auto decompiler = new CE::Decompiler::Decompiler(graph, funcCallInfoCallback, m_defSignature->getCallInfo().getReturnInfo(), &m_registerFactoryX86);
	decompiler->start();

	auto decCodeGraph = decompiler->getDecGraph();
	showDecGraph(decCodeGraph);

	auto sdaCodeGraph = new SdaCodeGraph(decCodeGraph);
	Symbolization::DataTypeFactory dataTypeFactory(userSymbolDef.m_programModule);
	Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &userSymbolDef, &dataTypeFactory);
	sdaBuilding.start();
	printf(Misc::ShowAllSymbols(sdaCodeGraph).c_str());
	showDecGraph(sdaCodeGraph->getDecGraph());

	Symbolization::SdaDataTypesCalculater sdaDataTypesCalculating(sdaCodeGraph, userSymbolDef.m_signature, &dataTypeFactory);
	sdaDataTypesCalculating.start();
	printf(Misc::ShowAllSymbols(sdaCodeGraph).c_str());
	showDecGraph(sdaCodeGraph->getDecGraph());

	Optimization::SdaGraphMemoryOptimization memoryOptimization(sdaCodeGraph);
	memoryOptimization.start();
	showDecGraph(sdaCodeGraph->getDecGraph(), true);
}

void ProgramModuleFixtureDecSamples::initSampleTestHashes() {
	m_sampleTestHashes = {
		//std::pair(2,0xfca38c5a9a788b9f), std::pair(3,0xbae15d35b166fd57), std::pair(4,0xe6d8ead2524614b), std::pair(5,0x404336cd30597017), std::pair(200,0x2aeebec5a9174a9f), std::pair(201,0x2bd0067104ae1951), std::pair(202,0x89fec5e403906591), std::pair(203,0x801ca3e750c8603b), std::pair(204,0x30d1aba2f2e3b1ed), std::pair(205,0x12c9a420f2b2d5e9), std::pair(206,0xab6d6c780445dfc4), std::pair(207,0x4a74f8192c5513a4), std::pair(208,0xd8c4e8c8df66dfae), std::pair(209,0xd6cc7469ea14af70), std::pair(210,0xacc229f90d6782dd), std::pair(211,0xe9c4c559b552878f), std::pair(212,0xe2b4c3ba6cef5a0b), std::pair(213,0x7c6464398da34687), std::pair(214,0x599a1ccf69d13300), std::pair(215,0x910e4ce3900fd4d1), std::pair(216,0xc48c00f7c3196841), std::pair(217,0xdf80cb704bfab4df), std::pair(218,0x57b02dcbee99fd9d), std::pair(219,0xbd417ce9ff6ad57d),
	};
}

void ProgramModuleFixtureDecSamples::initSampleTest()
{
	SampleTest* test;
	Signature* sig;

	//important: all test function (Test_SimpleFunc, Test_Array, ...) located in another project (TestCodeToDecompile.lib)
	
	//ignore all tests except
	m_doTestIdOnly = 103;

	{
		// TEST
		test = createSampleTest(5, { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x63, 0x41, 0x14, 0x4C, 0x8B, 0x09, 0x4C, 0x8B, 0xD1, 0x49, 0x2B, 0xD1, 0x48, 0x8B, 0xC2, 0x48, 0x99, 0x49, 0xF7, 0xF8, 0x48, 0x63, 0xD8, 0x4C, 0x8B, 0xD8, 0x48, 0x8B, 0xD3, 0x49, 0x0F, 0xAF, 0xD0, 0x42, 0x83, 0x0C, 0x0A, 0xFF, 0x83, 0x79, 0x18, 0xFF, 0x75, 0x03, 0x89, 0x41, 0x18, 0x83, 0x79, 0x1C, 0xFF, 0x75, 0x06, 0x48, 0x8D, 0x41, 0x1C, 0xEB, 0x0C, 0x8B, 0x41, 0x14, 0x0F, 0xAF, 0x41, 0x1C, 0x48, 0x98, 0x48, 0x03, 0x01, 0x44, 0x89, 0x18, 0x48, 0x8B, 0x41, 0x08, 0x44, 0x89, 0x59, 0x1C, 0x80, 0x0C, 0x18, 0x80, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x5C, 0x24, 0x08, 0x8D, 0x48, 0xFF, 0x33, 0xC8, 0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x3F, 0x33, 0xC8, 0x41, 0x89, 0x4A, 0x20, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test10");
	}

	{
		//simple function
		test = createSampleTest(10, GetFuncBytes(&Test_SimpleFunc));
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		test->m_symbolization = true;
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test0");
		sig->addParameter("a", findType("int32_t", ""));
		sig->addParameter("b", findType("int32_t", ""));
		sig->setReturnType(findType("int32_t"));
	}

	{
		//multidimension stack array like stackArray[1][2][3]
		test = createSampleTest(11, GetFuncBytes(&Test_Array));
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		test->m_symbolization = true;
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test1");
		sig->setReturnType(findType("uint64_t"));

		test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0x68, findType("int32_t", "[2][3][4]"), "stackArray"), -0x68);
		test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), findType("int64_t", ""), "idx"), 4608);
		test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), findType("uint32_t", ""), "result"), 19201);
	}

	{
		//hard work with complex data structures
		test = createSampleTest(12, GetFuncBytes(&Test_StructsAndArray));
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test2");
		sig->addParameter("myParam1", findType("uint32_t", "[1]"));
		sig->setReturnType(findType("int32_t"));

		test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), findType("uint32_t", "[1]"), "someObject"), 9985);

		sig = test->m_functions[0xffffffffffffff90] = typeManager()->createSignature("Func1_2");
		sig->addParameter("param1", findType("uint64_t", ""));
		sig->addParameter("param2", findType("uint64_t", ""));
		sig->setReturnType(findType("uint32_t", "[1]"));
		test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), GetUnit(sig), "Func1_2"), 0xffffffffffffff90);
	}

	{
		// idiv (16 bytes operation)
		test = createSampleTest(30, { 0x4C, 0x63, 0x41, 0x14, 0x4C, 0x8B, 0x09, 0x4C, 0x8B, 0xD1, 0x49, 0x2B, 0xD1, 0x48, 0x8B, 0xC2, 0x48, 0x99, 0x49, 0xF7, 0xF8, 0x48, 0x63, 0xD8, 0x4C, 0x8B, 0xD8, 0x48, 0x8B, 0xD3, 0x49, 0x0F, 0xAF, 0xD0, 0x42, 0x83, 0x0C, 0x0A, 0xFF });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test10");
	}

	{
		//xmm registers in incomplete blocks
		test = createSampleTest(50, { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xF8, 0x02, 0x0F, 0x10, 0x44, 0x24, 0x20, 0x75, 0x05, 0x0F, 0x10, 0x44, 0x24, 0x10, 0x0F, 0x11, 0x44, 0x24, 0x10 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test10");
	}

	{
		//get entity and copy his coords to the first param
		test = createSampleTest(100, { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x10, 0x35, 0x21, 0x46, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x0F, 0x29, 0x7C, 0x24, 0x30, 0xF3, 0x0F, 0x10, 0x3D, 0x15, 0x46, 0xF7, 0x01, 0x8B, 0xCA, 0x44, 0x0F, 0x29, 0x44, 0x24, 0x20, 0xF3, 0x44, 0x0F, 0x10, 0x05, 0x08, 0x46, 0xF7, 0x01, 0xE8, 0x5F, 0xE0, 0xFD, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x14, 0x0F, 0x28, 0x70, 0x70, 0x0F, 0x28, 0xFE, 0x44, 0x0F, 0x28, 0xC6, 0x0F, 0xC6, 0xFE, 0x55, 0x44, 0x0F, 0xC6, 0xC6, 0xAA, 0xF3, 0x0F, 0x11, 0x33, 0x0F, 0x28, 0x74, 0x24, 0x40, 0xF3, 0x0F, 0x11, 0x7B, 0x08, 0x0F, 0x28, 0x7C, 0x24, 0x30, 0x48, 0x8B, 0xC3, 0xF3, 0x44, 0x0F, 0x11, 0x43, 0x10, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x50, 0x5B, 0xC3, 0x90, 0x48 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test100");
		sig->addParameter("myParam1", findType("uint32_t", "[1]"));
		sig->addParameter("myParam2", findType("uint32_t"));
		sig->setReturnType(findType("uint64_t"));

		{
			auto pos = typeManager()->createStructure("Pos100", "");
			pos->addField(0x0, "vec", GetUnit(m_vec3D));
			pos->addField(0xC, "w", findType("uint32_t", ""));
			auto entity = typeManager()->createStructure("Entity100", "");
			entity->addField(0x70, "pos", GetUnit(pos));

			auto sig = test->m_functions[0xfffffffffffde098] = typeManager()->createSignature("getEntitySig");
			sig->addParameter("param1", findType("uint32_t"));
			sig->setReturnType(GetUnit(entity, "[1]"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), GetUnit(sig), "getEntity"), 0xfffffffffffde098);
		}
	}

	{
		//GET_ANGLE_BETWEEN_2D_VECTORS
		test = createSampleTest(101, { 0x48, 0x83, 0xEC, 0x38, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xF0, 0x0F, 0x28, 0xE1, 0xF3, 0x0F, 0x59, 0xC9, 0xF3, 0x0F, 0x59, 0xF6, 0xF3, 0x0F, 0x59, 0xE3, 0x0F, 0x28, 0xEA, 0xF3, 0x0F, 0x58, 0xF1, 0xF3, 0x0F, 0x59, 0xC5, 0x0F, 0x57, 0xD2, 0x0F, 0x2F, 0xF2, 0xF3, 0x0F, 0x58, 0xC4, 0x76, 0x09, 0x0F, 0x57, 0xE4, 0xF3, 0x0F, 0x51, 0xE6, 0xEB, 0x03, 0x0F, 0x28, 0xE2, 0xF3, 0x0F, 0x59, 0xED, 0xF3, 0x0F, 0x59, 0xDB, 0xF3, 0x0F, 0x58, 0xEB, 0x0F, 0x2F, 0xEA, 0x76, 0x09, 0x0F, 0x57, 0xC9, 0xF3, 0x0F, 0x51, 0xCD, 0xEB, 0x03, 0x0F, 0x28, 0xCA, 0xF3, 0x0F, 0x10, 0x1D, 0x59, 0xBF, 0xDF, 0x00, 0xF3, 0x0F, 0x59, 0xCC, 0xF3, 0x0F, 0x5E, 0xC1, 0x0F, 0x2F, 0xC3, 0x73, 0x03, 0x0F, 0x28, 0xC3, 0xF3, 0x0F, 0x10, 0x0D, 0xD5, 0xB5, 0xEB, 0x00, 0x0F, 0x2F, 0xC1, 0x76, 0x03, 0x0F, 0x28, 0xC1, 0x0F, 0x2F, 0xC3, 0x76, 0x0F, 0x0F, 0x2F, 0xC1, 0x73, 0x12, 0xE8, 0x12, 0x4F, 0xCC, 0x00, 0x0F, 0x28, 0xD0, 0xEB, 0x08, 0xF3, 0x0F, 0x10, 0x15, 0xED, 0x18, 0xE0, 0x00, 0xF3, 0x0F, 0x59, 0x15, 0xF1, 0xBE, 0xDF, 0x00, 0x0F, 0x28, 0x74, 0x24, 0x20, 0x0F, 0x28, 0xC2, 0x48, 0x83, 0xC4, 0x38, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test101");
		sig->addParameter("X1", findType("float", ""));
		sig->addParameter("Y1", findType("float", ""));
		sig->addParameter("X2", findType("float", ""));
		sig->addParameter("Y2", findType("float", ""));
		sig->setReturnType(findType("float"));
	}

	{
		//Evklid
		test = createSampleTest(102, { 0x89, 0xC8, 0x89, 0xD3, 0x83, 0xF8, 0x00, 0x7D, 0x02, 0xF7, 0xD8, 0x83, 0xFB, 0x00, 0x7D, 0x02, 0xF7, 0xDB, 0x39, 0xD8, 0x7D, 0x01, 0x93, 0x83, 0xFB, 0x00, 0x74, 0x04, 0x29, 0xD8, 0xEB, 0xF2, 0x89, 0x04, 0x24, 0x89, 0x1C, 0x24 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test102");
		sig->addParameter("a", findType("int32_t", ""));
		sig->addParameter("b", findType("int32_t", ""));
		sig->setReturnType(findType("int32_t"));
	}

	{
		//JMP function
		test = createSampleTest(103, { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xDA, 0x83, 0xFA, 0x0A, 0x7E, 0x10, 0x8D, 0x42, 0xF5, 0x83, 0xF8, 0x0D, 0x77, 0x05, 0x83, 0xC3, 0x19, 0xEB, 0x03, 0x83, 0xEB, 0x0E, 0xE8, 0x46, 0xCA, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x2C, 0x83, 0xFB, 0x31, 0x77, 0x27, 0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43, 0x03, 0x00, 0x48, 0x0F, 0xA3, 0xDA, 0x73, 0x17, 0x48, 0x8B, 0x48, 0x48, 0x4C, 0x8B, 0xC0, 0x8B, 0xD3, 0x48, 0x83, 0xC1, 0x40, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xE9, 0x0D, 0x10, 0x91, 0xFF, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xCC });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test103");
		sig->addParameter("param1", findType("int32_t", ""));
		sig->addParameter("param2", findType("int32_t", ""));
		sig->setReturnType(findType("int32_t"));
	}

	{
		//RAX request but no EAX
		test = createSampleTest(104, { 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x1B, 0xB2, 0xFE, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x0E, 0x48, 0x8B, 0x40, 0x20, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x90, 0x89, 0xED });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test104");
		sig->addParameter("param1", findType("int32_t", ""));
		sig->addParameter("param2", findType("int32_t", ""));
		sig->setReturnType(findType("int32_t"));
	}

	{
		//
		test = createSampleTest(105, { 0x48, 0x83, 0xEC, 0x28, 0x8B, 0x44, 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24, 0x40, 0xC7, 0x44, 0x24, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x0F, 0x25, 0xFF, 0xFF, 0xFF, 0x0F, 0x89, 0x44, 0x24, 0x38, 0xE8, 0x50, 0x8F, 0x8B, 0x00, 0x0F, 0xB7, 0x4C, 0x24, 0x40, 0x66, 0x89, 0x4C, 0x24, 0x38, 0x8B, 0x4C, 0x24, 0x38, 0x4C, 0x8B, 0xC0, 0x81, 0xC9, 0x00, 0x00, 0xFF, 0x0F, 0x33, 0xC0, 0x0F, 0xBA, 0xF1, 0x1C, 0x66, 0x81, 0xF9, 0xFF, 0xFF, 0x74, 0x10, 0x4D, 0x85, 0xC0, 0x74, 0x0B, 0x41, 0x0F, 0xB6, 0x80, 0x18, 0x05, 0x00, 0x00, 0x83, 0xE0, 0x1F, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC, 0x54, 0x48 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test105");
		sig->addParameter("param1", findType("int32_t", ""));
		sig->addParameter("param2", findType("int32_t", ""));
		sig->setReturnType(findType("int32_t"));
	}

	{
		//matrix vector coords multiplied
		test = createSampleTest(106, { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x0F, 0x29, 0x70, 0xE8, 0xF3, 0x0F, 0x10, 0x35, 0xB4, 0x35, 0xF7, 0x01, 0x0F, 0x29, 0x78, 0xD8, 0xF3, 0x0F, 0x10, 0x3D, 0xAC, 0x35, 0xF7, 0x01, 0x48, 0x8B, 0xD9, 0x8B, 0xCA, 0x41, 0x8A, 0xF0, 0x44, 0x0F, 0x29, 0x40, 0xC8, 0x44, 0x0F, 0x29, 0x48, 0xB8, 0xF3, 0x44, 0x0F, 0x10, 0x0D, 0x89, 0x35, 0xF7, 0x01, 0xE8, 0x1C, 0xD0, 0xFD, 0xFF, 0x48, 0x8B, 0xF8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x96, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0xC8, 0xFF, 0x92, 0x68, 0x03, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x10, 0x08, 0xF3, 0x0F, 0x10, 0x70, 0x04, 0xF3, 0x0F, 0x10, 0x78, 0x08, 0x40, 0x84, 0xF6, 0x74, 0x76, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0xCF, 0xFF, 0x90, 0x68, 0x03, 0x00, 0x00, 0x44, 0x0F, 0x28, 0x47, 0x60, 0x0F, 0x28, 0x7F, 0x70, 0x0F, 0x28, 0xAF, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xF6, 0x66, 0x0F, 0x70, 0x08, 0x00, 0x66, 0x0F, 0x70, 0x00, 0x55, 0x66, 0x0F, 0x70, 0x18, 0xAA, 0x41, 0x0F, 0x28, 0xE0, 0x0F, 0x28, 0xD7, 0x0F, 0x15, 0xFE, 0x44, 0x0F, 0x15, 0xC5, 0x0F, 0x14, 0xD6, 0x0F, 0x14, 0xE5, 0x44, 0x0F, 0x14, 0xC7, 0x44, 0x0F, 0x28, 0xCC, 0x44, 0x0F, 0x15, 0xCA, 0x0F, 0x14, 0xE2, 0x44, 0x0F, 0x59, 0xC3, 0x44, 0x0F, 0x59, 0xC8, 0x0F, 0x59, 0xE1, 0x44, 0x0F, 0x58, 0xCC, 0x45, 0x0F, 0x58, 0xC8, 0x41, 0x0F, 0x28, 0xF1, 0x41, 0x0F, 0x28, 0xF9, 0x41, 0x0F, 0xC6, 0xF1, 0x55, 0x41, 0x0F, 0xC6, 0xF9, 0xAA, 0x48, 0x8B, 0x74, 0x24, 0x78, 0x44, 0x0F, 0x28, 0x44, 0x24, 0x30, 0xF3, 0x44, 0x0F, 0x11, 0x0B, 0x44, 0x0F, 0x28, 0x4C, 0x24, 0x20, 0xF3, 0x0F, 0x11, 0x73, 0x08, 0x0F, 0x28, 0x74, 0x24, 0x50, 0xF3, 0x0F, 0x11, 0x7B, 0x10, 0x48, 0x8B, 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x70, 0x0F, 0x28, 0x7C, 0x24, 0x40, 0x48, 0x83, 0xC4, 0x60, 0x5F, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test106");
		sig->addParameter("param1", GetUnit(m_vecExt3D, "[1]"));
		sig->addParameter("param2", findType("int32_t", ""));
		sig->addParameter("param3", findType("bool", ""));
		sig->setReturnType(GetUnit(m_vecExt3D, "[1]"));
		test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), GetUnit(m_vec3D, "[1]"), "pos2"), 23042);
		test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), GetUnit(m_vec3D, "[1]"), "pos3"), 31234);

		{
			auto vtable = typeManager()->createStructure("Vtable106", "");
			vtable->addField(0x368, "getPos", findType("void", "[1]"));

			auto entity = typeManager()->createStructure("Entity106", "");
			entity->addField(0, "vtable", GetUnit(vtable, "[1]"));
			entity->addField(96, "matrix", GetUnit(m_matrix4x4));
			test->m_userSymbolDef.m_funcBodySymbolTable->addSymbol(new LocalInstrVarSymbol(symbolManager(), GetUnit(entity, "[1]"), "entity"), 17153);
		}
	}

	{
		//hard stack memory copying
		test = createSampleTest(107, { 0x40, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xA9, 0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x45, 0x17, 0x44, 0x89, 0x45, 0xBF, 0xF2, 0x0F, 0x11, 0x4D, 0x27, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8D, 0x45, 0xD7, 0x4C, 0x8D, 0x4D, 0xF7, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0xE7, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x48, 0x8D, 0x15, 0x5E, 0xC5, 0x6C, 0x01, 0x48, 0x89, 0x44, 0x24, 0x20, 0x0F, 0x29, 0x45, 0x17, 0x0F, 0x10, 0x45, 0xB7, 0xF2, 0x0F, 0x11, 0x4D, 0x07, 0xF2, 0x0F, 0x10, 0x4D, 0xC7, 0x44, 0x89, 0x45, 0xBF, 0x4C, 0x8D, 0x45, 0x37, 0x0F, 0x29, 0x45, 0xD7, 0x0F, 0x10, 0x45, 0xB7, 0xC7, 0x45, 0xBF, 0x01, 0x00, 0x00, 0x00, 0xF2, 0x0F, 0x11, 0x4D, 0x47, 0x0F, 0x29, 0x45, 0xF7, 0x66, 0x0F, 0x6E, 0xC1, 0x48, 0x8D, 0x0D, 0xC8, 0xF4, 0xE2, 0x01, 0xF3, 0x0F, 0xE6, 0xC0, 0xF2, 0x0F, 0x11, 0x45, 0xB7, 0x0F, 0x10, 0x45, 0xB7, 0x0F, 0x29, 0x45, 0x37, 0xE8, 0xAA, 0xDE, 0xFE, 0xFF, 0x48, 0x81, 0xC4, 0xD0, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xCC });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test107");
		sig->addParameter("param1", findType("int32_t", ""));
		
		{
			auto valueUI = typeManager()->createStructure("ValueUI107", "");
			valueUI->addField(0x0, "m_value", findType("uint64_t", ""));
			valueUI->addField(0x8, "m_type", findType("uint32_t", ""));
			valueUI->addField(0xC, "m_unk", findType("uint32_t", ""));
			valueUI->addField(0x10, "m_formatText", findType("uint64_t", ""));
			//todo: test this sample without these definitions
			test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0xA8, GetUnit(valueUI), "value1"), -0xA8);
			test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0x88, GetUnit(valueUI), "value2"), -0x88);
			test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0x68, GetUnit(valueUI), "value3"), -0x68);
			test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0x48, GetUnit(valueUI), "value4"), -0x48);
			test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -0x28, GetUnit(valueUI), "value5"), -0x28);

			auto uiDrawSig = test->m_functions[0xfffffffffffedf50] = typeManager()->createSignature("UI_Draw107");
			uiDrawSig->addParameter("param1", findType("uint64_t", ""));
			uiDrawSig->addParameter("param2", findType("uint64_t", ""));
			uiDrawSig->addParameter("param3", GetUnit(valueUI, "[1]"));
			uiDrawSig->addParameter("param4", GetUnit(valueUI, "[1]"));
			uiDrawSig->addParameter("param5", GetUnit(valueUI, "[1]"));
			uiDrawSig->addParameter("param6", GetUnit(valueUI, "[1]"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), 0xfffffffffffedf50, GetUnit(uiDrawSig), "UI_Draw"), 0xfffffffffffedf50);
		}
	}

	{
		//Matrix_FillWithVectorsAndMul
		test = createSampleTest(108, { 0x4C, 0x8B, 0xDC, 0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00, 0x0F, 0x28, 0x02, 0x48, 0x8B, 0x94, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x41, 0x0F, 0x29, 0x73, 0xE8, 0x41, 0x0F, 0x29, 0x7B, 0xD8, 0x45, 0x0F, 0x29, 0x43, 0xC8, 0x4D, 0x8D, 0x1B, 0x66, 0x0F, 0x70, 0x22, 0x55, 0x66, 0x0F, 0x70, 0x32, 0xAA, 0x66, 0x0F, 0x70, 0x2A, 0x00, 0x45, 0x0F, 0x29, 0x4B, 0xB8, 0x45, 0x0F, 0x29, 0x53, 0xA8, 0x45, 0x0F, 0x29, 0x5B, 0x98, 0x45, 0x0F, 0x29, 0x63, 0x88, 0x44, 0x0F, 0x29, 0x6C, 0x24, 0x30, 0x44, 0x0F, 0x28, 0x28, 0x48, 0x8B, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00, 0x66, 0x0F, 0x70, 0x08, 0x00, 0x66, 0x0F, 0x70, 0x18, 0xAA, 0x44, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x45, 0x0F, 0x28, 0x30, 0x44, 0x0F, 0x29, 0x7C, 0x24, 0x10, 0x4C, 0x8B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00, 0x66, 0x45, 0x0F, 0x70, 0x00, 0x00, 0x66, 0x41, 0x0F, 0x70, 0x38, 0x55, 0x66, 0x45, 0x0F, 0x70, 0x08, 0xAA, 0x45, 0x0F, 0x28, 0x39, 0x0F, 0x29, 0x04, 0x24, 0x41, 0x0F, 0x28, 0xD6, 0x4C, 0x8B, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00, 0x66, 0x0F, 0x70, 0x00, 0x55, 0x66, 0x45, 0x0F, 0x70, 0x11, 0x00, 0x66, 0x45, 0x0F, 0x70, 0x19, 0x55, 0x0F, 0x59, 0xD0, 0x0F, 0x28, 0x04, 0x24, 0x0F, 0x59, 0xC1, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x59, 0xCB, 0x66, 0x45, 0x0F, 0x70, 0x21, 0xAA, 0x0F, 0x58, 0xD0, 0x41, 0x0F, 0x28, 0xDE, 0x0F, 0x59, 0xDC, 0x0F, 0x28, 0x24, 0x24, 0x0F, 0x28, 0xC4, 0x0F, 0x58, 0xD1, 0x0F, 0x59, 0xC5, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x59, 0xCE, 0x0F, 0x58, 0xD8, 0x41, 0x0F, 0x28, 0x73, 0xE8, 0x0F, 0x28, 0xC4, 0x0F, 0x29, 0x11, 0x41, 0x0F, 0x28, 0xD6, 0x41, 0x0F, 0x59, 0xE2, 0x45, 0x0F, 0x59, 0xF3, 0x0F, 0x58, 0xD9, 0x41, 0x0F, 0x58, 0xE5, 0x45, 0x0F, 0x28, 0x53, 0xA8, 0x45, 0x0F, 0x28, 0x5B, 0x98, 0x44, 0x0F, 0x28, 0x6C, 0x24, 0x30, 0x0F, 0x59, 0xD7, 0x41, 0x0F, 0x59, 0xC0, 0x41, 0x0F, 0x58, 0xE6, 0x0F, 0x58, 0xD0, 0x41, 0x0F, 0x28, 0x7B, 0xD8, 0x45, 0x0F, 0x28, 0x43, 0xC8, 0x44, 0x0F, 0x28, 0x74, 0x24, 0x20, 0x41, 0x0F, 0x28, 0xCF, 0x0F, 0x29, 0x59, 0x10, 0x45, 0x0F, 0x59, 0xFC, 0x41, 0x0F, 0x59, 0xC9, 0x45, 0x0F, 0x28, 0x4B, 0xB8, 0x45, 0x0F, 0x28, 0x63, 0x88, 0x41, 0x0F, 0x58, 0xE7, 0x0F, 0x58, 0xD1, 0x44, 0x0F, 0x28, 0x7C, 0x24, 0x10, 0x0F, 0x29, 0x61, 0x30, 0x0F, 0x29, 0x51, 0x20, 0x49, 0x8B, 0xE3, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test108");
		sig->addParameter("pOutMatrix", GetUnit(m_matrix4x4, "[1]"));
		sig->addParameter("leftVec1", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("upVec1", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("forwardVec1", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("translationVec1", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("leftVec2", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("upVec2", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("forwardVec2", GetUnit(m_vec4D, "[1]"));
		sig->addParameter("translationVec2", GetUnit(m_vec4D, "[1]"));
		sig->setReturnType(findType("uint64_t"));

		test->m_userSymbolDef.m_stackSymbolTable->addSymbol(new LocalStackVarSymbol(symbolManager(), -int(0xffffffd0), GetUnit(m_matrix4x4, "[1]"), "matrix"), -int(0xffffffd0));
	}

	{
		//SET_ENTITY_ANIM_SPEED
		/*
			TODO:
			- ��������� backOrderId
			- ��������� localVarb2b: �� �� ������ ���� ������, � ������������ �����, ���� � ��� � ����������

			1. ������� �������� ����������� (�� �������� �������� ������� � ������)
				global_0x13c0c28 = 2120794248
				localVar1b3c = 2120794248 -> global_0x13c0c28
			2. memVar1c59 = *(uint64_t*)(funcVarff9 +.8 0x10)
			3. ������ goto, ������ �������� ����� (����� ������������� ���� �����)
		*/

		test = createSampleTest(109, { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x4C, 0x89, 0x70, 0x20, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x50, 0x0F, 0x29, 0x70, 0xE8, 0x4C, 0x8D, 0x0D, 0x9A, 0xBA, 0xE9, 0x00, 0x49, 0x8B, 0xF0, 0x0F, 0x28, 0xF3, 0x4C, 0x8B, 0xF2, 0x8B, 0xF9, 0xE8, 0x3E, 0xCD, 0x00, 0x00, 0x4C, 0x8B, 0xC8, 0x48, 0x85, 0xC0, 0x74, 0x5A, 0x48, 0x8B, 0x40, 0x10, 0x48, 0x85, 0xC0, 0x74, 0x0E, 0x8A, 0x88, 0x14, 0x02, 0x00, 0x00, 0xC0, 0xE9, 0x06, 0x80, 0xE1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 0x84, 0xC9, 0x75, 0x3D, 0x8B, 0x05, 0xCB, 0x0B, 0x3C, 0x01, 0xA8, 0x01, 0x75, 0x16, 0x83, 0xC8, 0x01, 0x89, 0x05, 0xBE, 0x0B, 0x3C, 0x01, 0xB8, 0x88, 0xC0, 0x68, 0x7E, 0x89, 0x05, 0xAF, 0x0B, 0x3C, 0x01, 0xEB, 0x06, 0x8B, 0x05, 0xA7, 0x0B, 0x3C, 0x01, 0x48, 0x8D, 0x55, 0xE0, 0x0F, 0x28, 0xD6, 0x49, 0x8B, 0xC9, 0x89, 0x45, 0xE0, 0xE8, 0xE9, 0x9A, 0xE1, 0xFF, 0xE9, 0xC8, 0x00, 0x00, 0x00, 0x41, 0xB0, 0x01, 0x41, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x8B, 0xCF, 0x41, 0x8A, 0xD0, 0xE8, 0x5D, 0xC1, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x45, 0x48, 0x8B, 0xD6, 0x33, 0xC9, 0xE8, 0x47, 0x17, 0x7E, 0x00, 0x49, 0x8B, 0xD6, 0x33, 0xC9, 0x89, 0x45, 0xE0, 0xE8, 0x3A, 0x17, 0x7E, 0x00, 0x4C, 0x8D, 0x4D, 0xEC, 0x89, 0x45, 0xE4, 0x48, 0x8D, 0x45, 0xE8, 0x4C, 0x8D, 0x45, 0xE0, 0x48, 0x8D, 0x55, 0xE4, 0x48, 0x8B, 0xCB, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x62, 0xC0, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x0A, 0x44, 0x8A, 0x4D, 0xE8, 0x44, 0x8B, 0x45, 0xEC, 0xEB, 0x5D, 0x41, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xB2, 0x01, 0x8B, 0xCF, 0xE8, 0xFE, 0xC0, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x4E, 0x48, 0x8B, 0xD6, 0x33, 0xC9, 0xE8, 0xE8, 0x16, 0x7E, 0x00, 0x49, 0x8B, 0xD6, 0x33, 0xC9, 0x89, 0x45, 0xEC, 0xE8, 0xDB, 0x16, 0x7E, 0x00, 0x4C, 0x8D, 0x4D, 0xE0, 0x89, 0x45, 0xE8, 0x48, 0x8D, 0x45, 0xE4, 0x4C, 0x8D, 0x45, 0xEC, 0x48, 0x8D, 0x55, 0xE8, 0x48, 0x8B, 0xCB, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x03, 0xC0, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x13, 0x44, 0x8A, 0x4D, 0xE4, 0x44, 0x8B, 0x45, 0xE0, 0x0F, 0x28, 0xCE, 0x48, 0x8B, 0xCB, 0xE8, 0x74, 0x69, 0x8E, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x60, 0x48, 0x8B, 0x74, 0x24, 0x68, 0x48, 0x8B, 0x7C, 0x24, 0x70, 0x0F, 0x28, 0x74, 0x24, 0x40, 0x4C, 0x8B, 0x74, 0x24, 0x78, 0x48, 0x83, 0xC4, 0x50, 0x5D, 0xC3 });
		test->m_enabled = true;
		test->m_showFinalResult = true;
		//test->enableAllAndShowAll();
		sig = test->m_userSymbolDef.m_signature = typeManager()->createSignature("test109");
		sig->addParameter("p1_Entity", findType("int32_t", ""));
		sig->addParameter("p2_AnimDict", findType("char", "[1]"));
		sig->addParameter("p2_AnimName", findType("char", "[1]"));
		sig->addParameter("p4_Speed", findType("float", ""));
		
		{
			sig = test->m_functions[0xc14c] = test->m_functions[0xffffffffffe19b7c] = typeManager()->createSignature("Func1_109");
			sig->addParameter("param1", findType("uint64_t", ""));
			sig->addParameter("param2", findType("uint64_t", ""));
			sig->addParameter("param3", findType("uint64_t", ""));
			sig->addParameter("param4", findType("uint64_t", ""));
			sig->setReturnType(findType("bool"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func1_109"), 0xc14c);
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func2_109"), 0xffffffffffe19b7c);

			sig = test->m_functions[0xcd74] = typeManager()->createSignature("Func2_109");
			sig->addParameter("param1", findType("uint32_t", ""));
			sig->addParameter("param2", findType("char", "[1]"));
			sig->addParameter("param3", findType("char", "[1]"));
			sig->setReturnType(findType("uint64_t"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func3_109"), 0xcd74);

			sig = test->m_functions[0xc208] = typeManager()->createSignature("Func4_109");
			sig->addParameter("param1", findType("uint32_t", ""));
			sig->addParameter("param2", findType("bool", ""));
			sig->addParameter("param3", findType("bool", ""));
			sig->addParameter("param4", findType("uint32_t", ""));
			sig->setReturnType(findType("uint64_t"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func4_109"), 0xc208);

			sig = test->m_functions[0x7e1804] = typeManager()->createSignature("Func5_109");
			sig->addParameter("param1", findType("uint32_t", ""));
			sig->addParameter("param2", findType("uint64_t", ""));
			sig->addParameter("param3", findType("bool", ""));
			sig->addParameter("param4", findType("uint32_t", ""));
			sig->setReturnType(findType("uint32_t"));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func5_109"), 0x7e1804);

			sig = test->m_functions[0xffffffffff8e6ad4] = typeManager()->createSignature("Func6_109");
			sig->addParameter("param1", findType("uint64_t", ""));
			sig->addParameter("param2", findType("uint64_t", ""));
			sig->addParameter("param3", findType("uint32_t", ""));
			sig->addParameter("param4", findType("byte", ""));
			test->m_userSymbolDef.m_globalSymbolTable->addSymbol(new FunctionSymbol(symbolManager(), GetUnit(sig), "Func6_109"), 0xffffffffff8e6ad4);
		}
	}

	if (false) {
		char* buffer;
		int size;
		PEImage::LoadPEImage("R:\\Rockstar Games\\Grand Theft Auto V\\GTA5_dump.exe", &buffer, &size);
		auto gta5_image = new PEImage((byte*)buffer, size);

		{
			//native function with arguments are in a context structure
			test = createSampleTest(1000, gta5_image, 0xA290A8);
			test->m_enabled = true;
			test->m_showFinalResult = true;
			test->enableAllAndShowAll();
			test->m_symbolization = true;

			/*
				TODO:
				1) there have not to be stack_0x40
			*/
		}

		{
			//native function with arguments are in a context structure
			test = createSampleTest(1001, gta5_image, 0xA290E0);
			test->m_enabled = true;
			test->m_showFinalResult = true;
			test->enableAllAndShowAll();
			test->m_symbolization = true;
		}
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
		if (m_doTestIdOnly && m_doTestIdOnly != sampleTest->m_testId) // select only chosen test
			continue;
		if (!sampleTest->m_enabled)
			continue;
		m_isOutput = sampleTest->m_showAllCode;

		// 1) INSTRUCTION DECODNING (from bytes to pCode graph)
		auto imageGraph = new ImagePCodeGraph;
		WarningContainer warningContainer;
		PCode::DecoderX86 decoder(&m_registerFactoryX86, &warningContainer);

		ImageAnalyzer imageAnalyzer(sampleTest->m_image, imageGraph, &decoder, &m_registerFactoryX86);
		imageAnalyzer.start(sampleTest->m_imageOffset, {}, true);
		auto graph = *imageGraph->getFunctionGraphList().begin();

		if (m_isOutput && sampleTest->m_showAsmBefore)
			graph->printDebug(0x0);

		// 4) DECOMPILING (transform the asm graph to decompiled code graph)
		auto info = sampleTest->m_userSymbolDef.m_signature->getCallInfo();
		
		auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) {
			if (offset != 0x0) {
				auto it = sampleTest->m_functions.find(offset);
				if (it != sampleTest->m_functions.end())
					return CE::Decompiler::FunctionCallInfo(it->second->getCallInfo());
			}
			return CE::Decompiler::FunctionCallInfo(m_defSignature->getCallInfo());
		};
		RegisterFactoryX86 registerFactoryX86;

		auto decCodeGraph = new DecompiledCodeGraph(graph);
		auto primaryDecompiler = CE::Decompiler::PrimaryDecompiler(decCodeGraph, &registerFactoryX86, info.getReturnInfo(), funcCallInfoCallback);
		primaryDecompiler.start();

		//show code
		if (m_isOutput) {
			out("\n\n\n********************* BEFORE OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			auto blockList = Misc::BuildBlockList(decCodeGraph);
			LinearViewSimpleOutput output(blockList, decCodeGraph);
			output.show();
		}

		Optimization::ProcessDecompiledGraph(decCodeGraph, &primaryDecompiler);
		decCodeGraph->checkOnSingleParents();

		
		if (!checkHash(0, sampleTestHashes, decCodeGraph->getHash().getHashValue(), sampleTest)) {
			printf("\n\nHERE IS THE TROUBLE:");
			m_isOutput = true;
			testFail = true;
		}

		//show code
		if (m_isOutput) {
			out("\n\n\n********************* AFTER OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			auto blockList = Misc::BuildBlockList(decCodeGraph);
			LinearViewSimpleOutput output(blockList, decCodeGraph);
			output.show();
		}

		// 6) SYMBOLIZATION
		if (sampleTest->m_symbolization) {
			m_isOutput |= sampleTest->m_showSymbCode;
			auto sdaCodeGraph = new SdaCodeGraph(decCodeGraph);
			Symbolization::SymbolizeWithSDA(sdaCodeGraph, sampleTest->m_userSymbolDef);
			
			if (!checkHash(1, sampleTestHashes, sdaCodeGraph->getDecGraph()->getHash().getHashValue(), sampleTest)) {
				printf("\n\nHERE IS THE TROUBLE:");
				m_isOutput = true;
				testFail = true;
			}
			out("\n\n\n********************* AFTER SYMBOLIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			auto blockList = Misc::BuildBlockList(sdaCodeGraph->getDecGraph());

			printf(Misc::ShowAllSymbols(sdaCodeGraph).c_str());
			LinearViewSimpleOutput output3(blockList, sdaCodeGraph->getDecGraph());
			output3.setMinInfoToShow();
			if (m_isOutput) {
				output3.show();
			}
			decCodeGraph->checkOnSingleParents();

			// 7) FINAL OPTIMIZATION
			m_isOutput |= sampleTest->m_showFinalResult;
			out("\n\n\n********************* AFTER FINAL OPTIMIZATION(test id %i): *********************\n\n", sampleTest->m_testId);
			Optimization::MakeFinalGraphOptimization(sdaCodeGraph);
			blockList = Misc::BuildBlockList(sdaCodeGraph->getDecGraph());
			decCodeGraph->checkOnSingleParents();
			LinearViewSimpleOutput output4(blockList, sdaCodeGraph->getDecGraph());
			output4.setMinInfoToShow();
			output4.m_SHOW_BLOCK_HEADER = true;
			if (m_isOutput) {
				output4.show();
			}
		}
		out("\n\n\n\n\n");
	}

	//show hashes
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