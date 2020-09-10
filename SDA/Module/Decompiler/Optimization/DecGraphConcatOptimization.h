#pragma once
#include "ExprOptimization.h"
#include "../Graph/DecCodeGraph.h"

namespace CE::Decompiler::Optimization
{
	class ConcatGraphOptimization
	{
	public:
		ConcatGraphOptimization(DecompiledCodeGraph* decGraph)
			: m_decGraph(decGraph)
		{}

		void start() {
			for (const auto decBlock : m_decGraph->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					auto node = topNode->getNode();
					INode::UpdateDebugInfo(node);
					findConcat(node);
					
				}
			}
		}
	private:
		DecompiledCodeGraph* m_decGraph;

		void findConcat(INode* node) {
			IterateChildNodes(node, [&](INode* childNode) {
				findConcat(childNode);
				});

			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				if (opNode->m_operation == Concat) {

				}
			}
		}
	};
};