#pragma once
#include "DecAsmGraph.h"
#include "Interpreter/InstructionInterpreterDispatcher.h"

namespace CE::Decompiler
{
	class Decompiler
	{
	public:
		std::function<ExprTree::FunctionCallInfo(int, ExprTree::Node*)> m_funcCallInfoCallback;

		Decompiler(AsmGraph* graph)
			: m_graph(graph)
		{
			m_intrepret = new InstructionInterpreterDispatcher;
			m_funcCallInfoCallback = [](int offset, ExprTree::Node* dst) {
				return ExprTree::GetFunctionCallDefaultInfo();
			};
		}

		~Decompiler() {
			delete m_intrepret;
		}

		void start() {

		}
	private:
		AsmGraph* m_graph;
		InstructionInterpreterDispatcher* m_intrepret;
	};
};