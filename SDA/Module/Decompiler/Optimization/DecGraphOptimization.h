#pragma once
#include "Graph/DecGraphCondBlockOptimization.h"
#include "Graph/DecGraphInstructionsForLocalVarsSearch.h"
#include "Graph/DecGraphExprOptimization.h"
#include "Graph/DecGraphLinesExpanding.h"
#include "Graph/DecGraphUselessLineOptimization.h"
#include "Graph/DecGraphLastLineAndConditionOrderFixing.h"
#include "Graph/DecGraphViewOptimization.h"

namespace CE::Decompiler::Optimization
{
	// make full optimization of decompiled graph
	static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph)
	{
		GraphCondBlockOptimization graphCondBlockOptimization(decGraph);
		graphCondBlockOptimization.start();
		decGraph->checkOnSingleParents();
		GraphLastLineAndConditionOrderFixing graphLastLineAndConditionOrderFixing(decGraph);
		graphLastLineAndConditionOrderFixing.start();
		GraphInstructionsForLocalVarsSearch graphInstructionsForLocalVarsSearch(decGraph);
		graphInstructionsForLocalVarsSearch.start();
		decGraph->checkOnSingleParents();
		GraphExprOptimization graphExprOptimization(decGraph);
		graphExprOptimization.start();
		decGraph->checkOnSingleParents();
		GraphViewOptimization graphViewOptimization(decGraph);
		graphViewOptimization.start();
		GraphLinesExpanding graphLinesExpanding(decGraph);
		graphLinesExpanding.start();
		GraphUselessLineDeleting GraphUselessLineDeleting(decGraph);
		GraphUselessLineDeleting.start();
		
		DecompiledCodeGraph::CalculateHeightForDecBlocks(decGraph->getStartBlock());
	}
};