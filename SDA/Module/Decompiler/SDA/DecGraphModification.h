#pragma once
#include "DecSdaMisc.h"

namespace CE::Decompiler
{
	using namespace ExprTree;

	class SdaGraphModification
	{
	public:
		SdaGraphModification(SdaCodeGraph* sdaCodeGraph)
			: m_sdaCodeGraph(sdaCodeGraph)
		{}

		virtual void start() = 0;

	protected:
		SdaCodeGraph* m_sdaCodeGraph;

		void passAllTopNodes(std::function<void(PrimaryTree::Block::BlockTopNode*)> func) {
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					func(topNode);
				}
			}
		}
	};
};