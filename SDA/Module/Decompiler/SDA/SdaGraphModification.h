#pragma once
#include "DecSdaMisc.h"
#include "../Optimization/Graph/DecGraphModification.h"

namespace CE::Decompiler
{
	using namespace ExprTree;

	class SdaGraphModification : public GraphModification
	{
	public:
		SdaGraphModification(SdaCodeGraph* sdaCodeGraph)
			: GraphModification(sdaCodeGraph->getDecGraph()), m_sdaCodeGraph(sdaCodeGraph)
		{}

		virtual void start() = 0;

	protected:
		SdaCodeGraph* m_sdaCodeGraph;
	};
};