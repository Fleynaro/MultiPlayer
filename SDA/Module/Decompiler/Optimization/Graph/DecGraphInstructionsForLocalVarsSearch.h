#pragma once
#include "DecGraphModification.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	// iterate over all local vars in dec. graph and find pCode instructions for them (upd: disabled)
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
			for (auto instr : getInstructionsRelatedTo(symbolAssignmentLine->getAssignmentNode())) {
				localVarSymbol->m_instructionsRelatedTo.push_back(instr);
			}
		}

		// get all pCode instructions from src
		std::list<PCode::Instruction*> getInstructionsRelatedTo(ExprTree::AssignmentNode* assignmentNode) {
			if (!assignmentNode->getInstructionsRelatedTo().empty())
				return assignmentNode->getInstructionsRelatedTo();

			std::list<PCode::Instruction*> list;
			/*if (auto nodeRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(assignmentNode->getDstNode()))
				list = nodeRelToInstr->getInstructionsRelatedTo();*/
			if (auto nodeRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(assignmentNode->getSrcNode())) {
				auto list2 = nodeRelToInstr->getInstructionsRelatedTo();
				list.insert(list.end(), list2.begin(), list2.end());
			}
			return list;
		}
	};
};