#pragma once
#include "DecGraphModification.h"
#include "../ExprOptimization.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	class GraphLastLineAndConditionOrderFixing : public GraphModification
	{
	public:
		GraphLastLineAndConditionOrderFixing(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				if (decBlock->getNoJumpCondition()) {
					processBlock(decBlock);
				}
			}
		}
	private:
		void processBlock(Block* block) {
			std::map<ObjectHash::Hash, Symbol::LocalVariable*> localVars;
			gatherLocalVarsDependedOnItselfFromBlock(block, localVars);
			doSingleFix(block->getNoJumpCondition(), localVars);
		}

		//gather localVars located in something like this: localVar = localVar + 1
		void gatherLocalVarsDependedOnItselfFromBlock(Block* block, std::map<ObjectHash::Hash, Symbol::LocalVariable*>& localVars) {
			for (auto symbolAssignmentLine : block->getSymbolAssignmentLines()) {
				if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf()->m_symbol)) {
					//if localVar expressed through itself (e.g. localVar = localVar + 1)
					if (doesNodeHaveSymbol(symbolAssignmentLine->getSrcNode(), localVar)) {
						CalculateHashes(symbolAssignmentLine->getSrcNode());
						localVars.insert(std::make_pair(symbolAssignmentLine->getSrcNode()->getHash(), localVar));
					}
				}
			}
			CalculateHashes(block->getNoJumpCondition());
		}

		//replace: <localVar = localVar + 1>	=>	 localVar
		bool doSingleFix(INode* node, std::map<ObjectHash::Hash, Symbol::LocalVariable*>& localVars) {
			auto it = localVars.find(node->getHash());
			if (it != localVars.end()) {
				node->replaceWith(new SymbolLeaf(it->second));
				delete node;
				return true;
			}

			bool result = false;
			node->iterateChildNodes([&](INode* childNode) {
				if (!result)
					result = doSingleFix(childNode, localVars);
				});
			return result;
		}
	};
};