#pragma once
#include "DecGraphModification.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	class GraphInstructionsForLocalVarsSearch : public GraphModification
	{
	public:
		GraphInstructionsForLocalVarsSearch(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				//traversing over all local vars
				for (auto symbolAssignmentLine : decBlock->getSymbolAssignmentLines()) {
					processSymbolAssignmentLine(symbolAssignmentLine);
				}
			}
		}
	private:
		void processSymbolAssignmentLine(Block::SymbolAssignmentLine* symbolAssignmentLine) {
			auto localVarSymbol = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf());
			if (!localVarSymbol)
				return;
			for (auto instr : symbolAssignmentLine->getAssignmentNode()->getInstructionsRelatedTo()) {
				localVarSymbol->m_instructionsRelatedTo.push_back(instr);
			}
		}
	};
};