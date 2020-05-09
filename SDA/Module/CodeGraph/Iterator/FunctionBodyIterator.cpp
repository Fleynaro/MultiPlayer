#include "FunctionBodyIterator.h"

using namespace CE::CallGraph;

FunctionBodyIterator::FunctionBodyIterator(Node::FunctionBody* funcBody, bool isLeft)
	: m_funcBody(funcBody), m_isLeft(isLeft)
{}

void FunctionBodyIterator::iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback)
{
	CallStack stack;
	CallStack::iterateCallStack(callback, m_funcBody, stack);
}

void FunctionBodyIterator::iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Filter filter)
{
	iterateCallStack([&](Node::Node* node, CallStack& stack)
		{
			if ((int)filter & (int)Filter::FunctionNode && dynamic_cast<Node::FunctionNode*>(node)
				|| (int)filter & (int)Filter::GlobalVarNode && dynamic_cast<Node::GlobalVarNode*>(node)
				|| (int)filter & (int)Filter::FunctionBody && dynamic_cast<Node::FunctionBody*>(node)) {
				return callback(node, stack);
			}
			return true;
		});
}

std::list<Node::Node*> FunctionBodyIterator::getAllNodesInCallTree(Filter filter)
{
	std::list<Node::Node*> nodes;
	iterateCallStack([&](Node::Node* node, CallStack& stack)
		{
			nodes.push_back(node);
			return true;
		}, filter);
	return nodes;
}
