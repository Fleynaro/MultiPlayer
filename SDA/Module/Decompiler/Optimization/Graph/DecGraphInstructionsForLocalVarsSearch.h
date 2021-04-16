#pragma once
#include "DecGraphModification.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	// iterate over all local vars in dec. graph and find pCode instructions for them (e.g. check evklid sample)
	class GraphLocalVarsRelToInstructions : public GraphModification
	{
	public:
		GraphLocalVarsRelToInstructions(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				//traversing over all local vars
				for (auto symbolAssignmentLine : decBlock->getSymbolParallelAssignmentLines()) {
					processSymbolAssignmentLine(symbolAssignmentLine);
				}
			}
		}
	private:
		void processSymbolAssignmentLine(Block::SymbolParallelAssignmentLine* symbolAssignmentLine) {
			auto localVarSymbol = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf()->m_symbol);
			if (!localVarSymbol)
				return;
			for (auto instr : symbolAssignmentLine->getAssignmentNode()->getInstructionsRelatedTo()) {
				localVarSymbol->m_instructionsRelatedTo.push_back(instr);
			}
		}
	};
};