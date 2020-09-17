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
	};
};