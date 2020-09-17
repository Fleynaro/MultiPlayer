#pragma once
#include "DecGraphMemoryOptimization.h"
#include "DecGraphUselessLineOptimization.h"

namespace CE::Decompiler::Optimization
{
	static void MakeFinalGraphOptimization(SdaCodeGraph* sdaCodeGraph) {
		Optimization::SdaGraphMemoryOptimization memoryOptimization(sdaCodeGraph);
		memoryOptimization.start();

		Optimization::SdaGraphUselessLineOptimization uselessLineOptimization(sdaCodeGraph);
		uselessLineOptimization.start();
	}
};