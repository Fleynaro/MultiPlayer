#pragma once
#include "../../Graph/DecCodeGraph.h"

namespace CE::Decompiler
{
	using namespace ExprTree;

	// abstract class for some graph modification
	class GraphModification
	{
	public:
		GraphModification(DecompiledCodeGraph* decGraph)
			: m_decGraph(decGraph)
		{}

		// here creating of modification logic
		virtual void start() = 0;

	protected:
		DecompiledCodeGraph* m_decGraph;

		// iterate over all top nodes of the dec. graph (allow to access all expressions)
		void passAllTopNodes(std::function<void(PrimaryTree::Block::BlockTopNode*)> func) {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					func(topNode);
				}
			}
		}

		// get all symbol leafs from the specified {node} according to the specified {symbol}
		void gatherSymbolLeafsFromNode(INode* node, Symbol::Symbol* symbol, std::list<ExprTree::SymbolLeaf*>& symbolLeafs) {
			node->iterateChildNodes([&](INode* childNode) {
				gatherSymbolLeafsFromNode(childNode, symbol, symbolLeafs);
				});

			if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
				if (symbolLeaf->m_symbol == symbol) {
					symbolLeafs.push_back(symbolLeaf);
				}
			}
		}

		// check if the specified {node} has the specified {symbol}
		bool doesNodeHaveSymbol(INode* node, Symbol::Symbol* symbol) {
			std::list<ExprTree::SymbolLeaf*> symbolLeafs;
			gatherSymbolLeafsFromNode(node, symbol, symbolLeafs);
			return !symbolLeafs.empty();
		}
	};
};