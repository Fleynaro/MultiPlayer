#pragma once
#include "../Nodes/BodyNode.h"
#include "../CallStack.h"

namespace CE::CodeGraph
{
	class FunctionBodyIterator
	{
	public:
		FunctionBodyIterator(Node::FunctionBody* funcBody, bool isLeft = true);

		enum class Filter : int
		{
			FunctionNode = 1,
			GlobalVarNode = 2,
			FunctionBody = 4,
			All = -1
		};

		void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Filter filter);

		void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback);

		std::list<Node::Node*> getAllNodesInCallTree(Filter filter);
	private:
		Node::FunctionBody* m_funcBody;
		bool m_isLeft;
	};
};