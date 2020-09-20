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
			std::map<HS::Value, Symbol::LocalVariable*> localVars;
			gatherLocalVarsDependedOnItselfFromBlock(block, localVars);
			doSingleFix(block->getNoJumpCondition(), localVars);
		}

		//gather localVars located in something like this: localVar = localVar + 1
		void gatherLocalVarsDependedOnItselfFromBlock(Block* block, std::map<HS::Value, Symbol::LocalVariable*>& localVars) {
			for (auto symbolAssignmentLine : block->getSymbolAssignmentLines()) {
				if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf()->m_symbol)) {
					if (!filter(symbolAssignmentLine->getSrcNode())) {
						localVars.insert(std::make_pair(symbolAssignmentLine->getSrcNode()->getHash().getHashValue(), localVar));
					}
				}
			}
		}

		//replace: <localVar + 1> =>	localVar
		//replace: <X*X+Y*Y> =>	dist
		void doSingleFix(INode* node, std::map<HS::Value, Symbol::LocalVariable*>& localVars) {
			if (!filter(node)) {
				auto it = localVars.find(node->getHash().getHashValue());
				if (it != localVars.end()) {
					node->replaceWith(new SymbolLeaf(it->second));
					delete node;
				}
			}

			node->iterateChildNodes([&](INode* childNode) {
				doSingleFix(childNode, localVars);
				});
		}

		bool filter(INode* node) {
			if (dynamic_cast<ILeaf*>(node))
				return true;
			return false;
		}
	};
};