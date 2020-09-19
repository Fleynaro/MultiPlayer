#pragma once
#include "DecGraphModification.h"
#include "../ExprOptimization.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	class GraphExprOptimization : public GraphModification
	{
	public:
		GraphExprOptimization(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				optimize(topNode);
				});
		}
	private:
		void optimize(PrimaryTree::Block::BlockTopNode* topNode) {
			INode::UpdateDebugInfo(topNode->getNode());
			ExprOptimization exprOptimization(topNode);
			exprOptimization.start();
		}
	};
};