#pragma once
#include "AbstractTest.h"
#include <TestCodeToDecompile.h>

using namespace CE::Decompiler;
using namespace CE::Symbol;
using namespace CE::DataType;

class ProgramDecSampleTestFixture : public ProgramDecFixture {
public:
	// test unit for some instruction list (asm code) presented as array of bytes
	struct SampleTest
	{
		int m_testId;
		IImage* m_image;
		int m_imageOffset = 0;
		Symbolization::SymbolContext m_symbolCtx;
		std::map<int64_t, FunctionSignature*> m_functions;
		bool m_enabled = true;
		bool m_symbolization = true;
		bool m_showAllCode = false;
		bool m_showSymbCode = false;
		bool m_showAsmBefore = false;
		bool m_showFinalResult = false;

		void enableAllAndShowAll() {
			m_enabled = true;
			m_symbolization = true;
			m_showAllCode = true;
			m_showSymbCode = true;
			m_showAsmBefore = true;
			m_showFinalResult = true;
		}
	};

	std::list<SampleTest*> m_sampleTests;
	std::map<int, HS::Value> m_sampleTestHashes;

	//ignore all tests except
	int m_doTestIdOnly = 0;

	ProgramDecSampleTestFixture()
	{
		initSampleTestHashes();
		initSampleTest();
	}

	void initSampleTestHashes();

	void initSampleTest();

	bool checkHash(int type, std::list<std::pair<int, HS::Value>>& sampleTestHashes, HS::Value hash, SampleTest* sampleTest);

	SampleTest* createSampleTest(int testId, std::vector<byte> content) {
		return createSampleTest(testId, new VectorBufferImage(content));
	}

	SampleTest* createSampleTest(int testId, IImage* image, int offset = 0) {
		auto test = new SampleTest;
		test->m_testId = testId;
		test->m_image = image;
		test->m_imageOffset = offset;
		test->m_symbolCtx = Misc::CreateUserSymbolDef(m_project);
		test->m_symbolCtx.m_signature = m_defSignature;
		m_sampleTests.push_back(test);
		return test;
	}
};