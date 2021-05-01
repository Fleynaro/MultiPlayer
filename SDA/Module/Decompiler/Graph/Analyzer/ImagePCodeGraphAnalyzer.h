#pragma once
#include "../DecPCodeGraph.h"

namespace CE::Decompiler
{
	class ImagePCodeGraphAnalyzer
	{
		ImagePCodeGraph* m_imageGraph;
	public:
		ImagePCodeGraphAnalyzer(ImagePCodeGraph* imageGraph)
			: m_imageGraph(imageGraph)
		{}

		void start() {
			doDepthPassAllFuncGraphs(m_imageGraph->getFirstFunctionGraph());
		}

	private:
		void doDepthPassAllFuncGraphs(FunctionPCodeGraph* funcGraph) {
			for (auto nextFuncGraph : funcGraph->getNonVirtFuncCalls())
				doDepthPassAllFuncGraphs(nextFuncGraph);

			auto decCodeGraph = new DecompiledCodeGraph(funcGraph, FunctionCallInfo({}));

			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(decCodeGraph, m_registerFactory, funcCallInfoCallback);
			decompiler.start();

			auto clonedDecCodeGraph = decCodeGraph->clone();
			Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);

			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);
			Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &m_userSymbolDef, &m_dataTypeFactory);
			sdaBuilding.start();
		}
	};
};