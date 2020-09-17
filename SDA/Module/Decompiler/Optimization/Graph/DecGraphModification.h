#pragma once
#include "../../Graph/DecCodeGraph.h"

namespace CE::Decompiler
{
	using namespace ExprTree;

	class GraphModification
	{
	public:
		GraphModification(DecompiledCodeGraph* decGraph)
			: m_decGraph(decGraph)
		{}

		virtual void start() = 0;

	protected:
		DecompiledCodeGraph* m_decGraph;

		void passAllTopNodes(std::function<void(PrimaryTree::Block::BlockTopNode*)> func) {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					func(topNode);
				}
			}
		}

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

		bool doesNodeHaveSymbol(INode* node, Symbol::Symbol* symbol) {
			std::list<ExprTree::SymbolLeaf*> symbolLeafs;
			gatherSymbolLeafsFromNode(node, symbol, symbolLeafs);
			return !symbolLeafs.empty();
		}
	};
};