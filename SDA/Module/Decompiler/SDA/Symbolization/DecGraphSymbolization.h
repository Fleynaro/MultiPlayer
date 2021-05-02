#pragma once
#include "DecGraphSdaBuilding.h"
#include "SdaGraphDataTypeCalc.h"

namespace CE::Decompiler::Symbolization
{
	static void SymbolizeWithSDA(SdaCodeGraph* sdaCodeGraph, UserSymbolDef& userSymbolDef) {
		DataTypeFactory dataTypeFactory(userSymbolDef.m_programModule);
		
		SdaBuilding sdaBuilding(sdaCodeGraph, &userSymbolDef, &dataTypeFactory);
		sdaBuilding.start();

		SdaDataTypesCalculater sdaDataTypesCalculating(sdaCodeGraph, userSymbolDef.m_signature, &dataTypeFactory);
		sdaDataTypesCalculating.start();
	}
};