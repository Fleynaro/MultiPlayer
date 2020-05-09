#pragma once
#include "Nodes/BodyNode.h"
#include <Code/Function/FunctionDefinition.h>

namespace CE::CallGraph
{
	class FunctionBodyBuilder
	{
	public:
		FunctionBodyBuilder(Function::Function* function);

		void build();

		Node::FunctionBody* getFunctionBody();
	private:
		Function::Function* m_function;

		void build(Function::AddressRange& range);
	};
};