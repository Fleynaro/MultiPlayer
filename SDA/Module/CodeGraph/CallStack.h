#pragma once
#include "Nodes/BodyNode.h"

namespace CE::CodeGraph
{
	class CallStack
	{
	public:
		void push(Node::FunctionBody* body);

		void pop();

		bool empty();

		int size();

		bool has(Node::FunctionBody* body);

		static void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Node::FunctionBody* body, CallStack& stack, bool isLeft = true);
	private:
		std::list<Node::FunctionBody*> m_stack;
	};
};