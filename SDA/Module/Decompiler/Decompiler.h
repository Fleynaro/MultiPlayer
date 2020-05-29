#pragma once
#include "DecAsmGraph.h"
#include "Interpreter/InstructionInterpreterDispatcher.h"

namespace CE::Decompiler
{
	class Decompiler
	{
	public:
		Decompiler(AsmGraph* graph)
			: m_graph(graph)
		{
			m_intrepret = new InstructionInterpreterDispatcher;
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