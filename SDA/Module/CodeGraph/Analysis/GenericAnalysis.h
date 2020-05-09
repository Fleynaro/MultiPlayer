#pragma once
#include "../Iterator/FunctionBodyIterator.h"

namespace CE {
	class FunctionManager;
};

namespace CE::CallGraph::Analyser
{
	class GenericAll
	{
	public:
		GenericAll(FunctionManager* funcManager);

		void doAnalyse();
	private:
		FunctionManager* m_funcManager;
		Node::FunctionBody::BasicInfo iterateCallStack(Node::FunctionBody* body, CallStack& stack);
	};
};