#pragma once
#include "Graph/DecGraphCondBlockOptimization.h"
#include "Graph/DecGraphInstructionsForLocalVarsSearch.h"
#include "Graph/DecGraphExprOptimization.h"
#include "Graph/DecGraphLinesExpanding.h"
#include "Graph/DecGraphUselessLineOptimization.h"
#include "Graph/DecGraphLastLineAndConditionOrderFixing.h"

namespace CE::Decompiler::Optimization
{
	static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph)
	{
		GraphCondBlockOptimization graphCondBlockOptimization(decGraph);
		graphCondBlockOptimization.start();
		GraphLastLineAndConditionOrderFixing graphLastLineAndConditionOrderFixing(decGraph);
		graphLastLineAndConditionOrderFixing.start();
		GraphInstructionsForLocalVarsSearch graphInstructionsForLocalVarsSearch(decGraph);
		graphInstructionsForLocalVarsSearch.start();
		GraphExprOptimization graphExprOptimization(decGraph);
		graphExprOptimization.start();
		GraphLinesExpanding graphLinesExpanding(decGraph);
		graphLinesExpanding.start();
		GraphUselessLineDeleting GraphUselessLineDeleting(decGraph);
		GraphUselessLineDeleting.start();
		
		DecompiledCodeGraph::CalculateHeightForDecBlocks(decGraph->getStartBlock());
		decGraph->generateSymbolIds();
	}
};