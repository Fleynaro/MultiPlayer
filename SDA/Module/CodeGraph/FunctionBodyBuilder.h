#pragma once
#include "Nodes/BodyNode.h"
#include <Address/AddressRange.h>

namespace CE {
	class FunctionManager;
};

namespace CE::CodeGraph
{
	class FunctionBodyBuilder
	{
	public:
		FunctionBodyBuilder(Node::FunctionBody* body, AddressRangeList addressRangeList, FunctionManager* funcManager);

		void build();
	private:
		Node::FunctionBody* m_funcBody;
		AddressRangeList m_addressRangeList;
		FunctionManager* m_funcManager;

		void build(AddressRange& range);
	};
};