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
			auto localVarSymbol = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf()->m_symbol);
			if (!localVarSymbol)
				return;
			for (auto instr : getInstructionsRelatedTo(symbolAssignmentLine->getAssignmentNode())) {
				localVarSymbol->m_instructionsRelatedTo.push_back(instr);
			}
		}

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