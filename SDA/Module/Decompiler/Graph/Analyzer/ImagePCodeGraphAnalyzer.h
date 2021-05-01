#pragma once
#include "../DecPCodeGraph.h"

namespace CE::Decompiler
{
	class ProgramGraph
	{
		struct FuncGraphInfo {
			SdaCodeGraph* m_sdaFuncGraph;
			Symbolization::UserSymbolDef m_userSymbolDef;
		};
		ImagePCodeGraph* m_imageGraph;
		std::map<FunctionPCodeGraph*, FuncGraphInfo> m_sdaFuncGraphs;
	public:
		ProgramGraph(ImagePCodeGraph* imageGraph)
			: m_imageGraph(imageGraph)
		{}

		ImagePCodeGraph* getIamgePCodeGraph() {
			return m_imageGraph;
		}

		auto& getSdaFuncGraphs() {
			return m_sdaFuncGraphs;
		}
	};

	class ImagePCodeGraphAnalyzer
	{
		ProgramGraph* m_programGraph;
		CE::ProgramModule* m_programModule;
		AbstractRegisterFactory* m_registerFactory;
		Symbolization::UserSymbolDef m_userSymbolDef;
		Symbolization::DataTypeFactory m_dataTypeFactory;
	public:
		ImagePCodeGraphAnalyzer(ProgramGraph* programGraph, CE::ProgramModule* programModule, AbstractRegisterFactory* registerFactory)
			: m_programGraph(programGraph), m_programModule(programModule), m_registerFactory(registerFactory), m_dataTypeFactory(programModule)
		{
			m_userSymbolDef = Symbolization::UserSymbolDef(m_programModule);
			m_userSymbolDef.m_globalSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
			m_userSymbolDef.m_stackSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::STACK_SPACE, 100000);
			m_userSymbolDef.m_funcBodySymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
		}

		void start() {
			doDepthPassAllFuncGraphs(m_programGraph->getIamgePCodeGraph()->getFirstFunctionGraph());
		}

	private:
		void doDepthPassAllFuncGraphs(FunctionPCodeGraph* funcGraph) {
			for (auto nextFuncGraph : funcGraph->getNonVirtFuncCalls())
				doDepthPassAllFuncGraphs(nextFuncGraph);

			auto decCodeGraph = new DecompiledCodeGraph(funcGraph);

			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(decCodeGraph, m_registerFactory, ReturnInfo(), funcCallInfoCallback);
			decompiler.start();

			auto clonedDecCodeGraph = decCodeGraph->clone();
			Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);

			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);
			Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &m_userSymbolDef, &m_dataTypeFactory);
			sdaBuilding.start();


		}
	};
};