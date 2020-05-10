#pragma once
#include "Nodes/BodyNode.h"
#include <Code/Function/AddressRange.h>

namespace CE {
	class FunctionManager;
};

namespace CE::CodeGraph
{
	class FunctionBodyBuilder
	{
	public:
		FunctionBodyBuilder(Node::FunctionBody* body, Function::AddressRangeList addressRangeList, FunctionManager* funcManager);

		void build();
	private:
		Node::FunctionBody* m_funcBody;
		Function::AddressRangeList m_addressRangeList;
		FunctionManager* m_funcManager;

		void build(Function::AddressRange& range);
	};
};