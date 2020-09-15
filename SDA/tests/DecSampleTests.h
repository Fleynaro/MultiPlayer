#pragma once
#include "AbstractTest.h"
#include <Decompiler/Decompiler.h>
#include <Decompiler/LinearView/DecLinearView.h>
#include <Decompiler/LinearView/DecLinearViewSimpleOutput.h>
#include <Decompiler/SDA/SdaHelper.h>
#include <Decompiler/Optimization/DecGraphOptimization.h>
#include <Decompiler/SDA/Symbolization/DecGraphSymbolization.h>
#include <Decompiler/SDA/Optimizaton/DecGraphFinalOptimization.h>
#include <Decompiler/PCode/Decoders/DecPCodeDecoderX86.h>
#include <Decompiler/PCode/DecPCodeConstValueCalc.h>
#include <Manager/Managers.h>
#include <TestCodeToDecompile.h>

using namespace CE::Decompiler;
using namespace CE::Symbol;
using namespace CE::DataType;

class ProgramModuleFixtureDecSamples : public ProgramModuleFixture {
public:
	struct SampleTest
	{
		int m_testId;
		std::vector<byte> m_content;
		Symbolization::UserSymbolDef m_userSymbolDef;
		std::map<int64_t, Signature*> m_functions;
		bool m_enabled = true;
		bool m_symbolization = true;
		bool m_showAllCode = false;
		bool m_showSymbCode = false;
		bool m_showAsmBefore = false;
	};

	std::list<SampleTest*> m_sampleTests;
	std::map<int, ObjectHash::Hash> m_sampleTestHashes;
	Signature* m_defSignature;
	bool m_isOutput = true;
	int m_doTestIdOnly = 0;

	ProgramModuleFixtureDecSamples()
		: ProgramModuleFixture(false)
	{
		m_defSignature = createDefSig("defSignature");
		initSampleTestHashes();
		initSampleTest();
	}

	void initSampleTestHashes();

	void initSampleTest();

	bool checkHash(int type, std::list<std::pair<int, ObjectHash::Hash>>& sampleTestHashes, ObjectHash::Hash hash, SampleTest* sampleTest);

	CE::TypeManager* typeManager() {
		return m_programModule->getTypeManager();
	}

	CE::SymbolManager* symbolManager() {
		return m_programModule->getSymbolManager();
	}

	CE::DataTypePtr findType(std::string typeName, std::string typeLevel = "") {
		return DataType::GetUnit(typeManager()->getTypeByName(typeName), typeLevel);
	}

	SampleTest* createSampleTest(int testId, std::vector<byte> content) {
		auto test = new SampleTest;
		test->m_testId = testId;
		test->m_content = content;
		test->m_userSymbolDef = createUserSymbolDef(testId);
		m_sampleTests.push_back(test);
		return test;
	}

	Symbolization::UserSymbolDef createUserSymbolDef(int testId) {
		auto userSymbolDef = Symbolization::UserSymbolDef(m_programModule);
		userSymbolDef.m_signature = m_defSignature;
		userSymbolDef.m_globalMemoryArea = m_programModule->getGlobalMemoryArea();
		userSymbolDef.m_stackMemoryArea = new CE::Symbol::MemoryArea(m_programModule->getMemoryAreaManager(), CE::Symbol::MemoryArea::STACK_SPACE, 100000);
		userSymbolDef.m_funcBodyMemoryArea = new CE::Symbol::MemoryArea(m_programModule->getMemoryAreaManager(), CE::Symbol::MemoryArea::GLOBAL_SPACE, 100000);
		return userSymbolDef;
	}

	Signature* createDefSig(std::string name) {
		auto defSignature = typeManager()->createSignature(name);
		defSignature->addParameter("param1", findType("uint32_t"));
		defSignature->addParameter("param2", findType("uint32_t"));
		defSignature->addParameter("param3", findType("uint32_t"));
		defSignature->addParameter("param4", findType("uint32_t"));
		defSignature->addParameter("param5", findType("uint32_t"));
		defSignature->setReturnType(findType("uint32_t"));
		return defSignature;
	}

	void out(const char* fmt, ...) {
		if (!m_isOutput)
			return;
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}

	static std::vector<byte> GetFuncBytes(void* addr) {
		auto size = CalculateFuncSize((byte*)addr, 0);
		return std::vector<byte>((byte*)addr, (byte*)addr + size);
	}

	static int CalculateFuncSize(byte* addr, bool endByRet = false) {
		int size = 0;
		while (!(addr[size] == 0xC3 && addr[size + 1] == 0xCC))
			size++;
		return size + 1;
	}
};