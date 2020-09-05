#pragma once
#include "AbstractTest.h"
#include <Decompiler/Decompiler.h>
#include <Decompiler/LinearView/DecLinearView.h>
#include <Decompiler/SDA/SdaHelper.h>
#include <Decompiler/Optimization/DecGraphOptimization.h>
#include <Decompiler/SDA/Symbolization/DecGraphSymbolization.h>
#include <Decompiler/PCode/Decoders/DecPCodeDecoderX86.h>
#include <Decompiler/PCode/DecPCodeConstValueCalc.h>
#include <Manager/Managers.h>

using namespace CE::Decompiler;

class ProgramModuleFixtureDecSamples : public ProgramModuleFixture {
public:
	struct SampleTest
	{
		int m_testId;
		std::vector<byte> m_content;
		Symbolization::UserSymbolDef m_userSymbolDef;
		std::map<int64_t, CE::DataType::Signature*> m_functions;
	};

	CE::DataType::Signature* m_defSignature;

	ProgramModuleFixtureDecSamples()
		: ProgramModuleFixture(true)
	{
		
	}

};