#pragma once
#include "FunctionBodyIterator.h"

namespace CE {
	class FunctionManager;
};

namespace CE::CallGraph
{
	class CallGraphIterator
	{
	public:
		CallGraphIterator(FunctionManager* funcManager);

		void iterate(const std::function<bool(Node::Node*, CallStack&)>& callback, bool isLeft = true);
	private:
		FunctionManager* m_funcManager;
	};
};