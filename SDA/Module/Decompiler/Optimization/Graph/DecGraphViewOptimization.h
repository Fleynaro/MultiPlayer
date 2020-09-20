#pragma once
#include "DecGraphModification.h"
#include "../ExprOptimization.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	//optimizing the graph to be more understanding by human intelligence
	class GraphViewOptimization : public GraphModification
	{
	public:
		GraphViewOptimization(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				processBlock(decBlock);
			}
		}
	private:
		void processBlock(Block* block) {
			//replacing confused nodes in conditions with more short ones (localVar)
			if (block->getNoJumpCondition()) {
				std::map<HS::Value, Symbol::LocalVariable*> localVars;
				gatherLocalVarsDependedOnItselfFromBlock(block, localVars);
				replaceConfusedNodesWithGatheredLocalVars(block->getNoJumpCondition(), localVars);
			}
		}

		//gather localVars that store nodes according to the filter
		void gatherLocalVarsDependedOnItselfFromBlock(Block* block, std::map<HS::Value, Symbol::LocalVariable*>& localVars) {
			for (auto symbolAssignmentLine : block->getSymbolAssignmentLines()) {
				if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbolLeaf()->m_symbol)) {
					if (!filter(symbolAssignmentLine->getSrcNode())) {
						localVars.insert(std::make_pair(symbolAssignmentLine->getSrcNode()->getHash().getHashValue(), localVar));
					}
				}
			}
		}
		
		void replaceConfusedNodesWithGatheredLocalVars(INode* node, std::map<HS::Value, Symbol::LocalVariable*>& localVars) {
			if (!filter(node)) {
				auto it = localVars.find(node->getHash().getHashValue());
				if (it != localVars.end()) {
					node->replaceWith(new SymbolLeaf(it->second));
					delete node;
				}
			}

			node->iterateChildNodes([&](INode* childNode) {
				replaceConfusedNodesWithGatheredLocalVars(childNode, localVars);
				});
		}

		//filter simple nodes like symbols, numbers, ...
		bool filter(INode* node) {
			if (dynamic_cast<ILeaf*>(node))
				return true;
			return false;
		}
	};
};