#pragma once
#include <Decompiler/PCode/Decompiler/Decompiler.h>
#include <Decompiler/Optimization/DecGraphOptimization.h>

namespace CE::Decompiler
{
	// decompiler of pcode with optimization
	class Decompiler {
		FunctionPCodeGraph* m_funcGraph;
		std::function<FunctionCallInfo(int, ExprTree::INode*)> m_funcCallInfoCallback;
		ReturnInfo m_retInfo;
		AbstractRegisterFactory* m_registerFactory;

		DecompiledCodeGraph* m_decompiledCodeGraph = nullptr;
	public:
		Decompiler(FunctionPCodeGraph* funcGraph, std::function<FunctionCallInfo(int, ExprTree::INode*)> funcCallInfoCallback, ReturnInfo retInfo, AbstractRegisterFactory* registerFactory)
			: m_funcGraph(funcGraph), m_funcCallInfoCallback(funcCallInfoCallback), m_retInfo(retInfo), m_registerFactory(registerFactory)
		{}

		void start() {
			m_decompiledCodeGraph = new DecompiledCodeGraph(m_funcGraph);
			auto primaryDecompiler = CE::Decompiler::PrimaryDecompiler(m_decompiledCodeGraph, m_registerFactory, m_retInfo, m_funcCallInfoCallback);
			primaryDecompiler.start();
			Optimization::ProcessDecompiledGraph(m_decompiledCodeGraph, &primaryDecompiler);
			m_decompiledCodeGraph->checkOnSingleParents();
		}

		DecompiledCodeGraph* getDecGraph() {
			return m_decompiledCodeGraph;
		}
	};
};