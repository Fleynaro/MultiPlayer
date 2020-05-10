#include "CallStack.h"
#include <Code/Function/FunctionDefinition.h>
#include "Iterator/FunctionBodyIterator.h"

using namespace CE;
using namespace CE::CodeGraph;

bool CallStack::has(Node::FunctionBody* body) {
	for (auto it : m_stack) {
		if (it == body) {
			return true;
		}
	}
	return false;
}

int CallStack::size() {
	return static_cast<int>(m_stack.size());
}

bool CallStack::empty() {
	return m_stack.empty();
}

void CallStack::pop() {
	m_stack.pop_front();
}

void CallStack::push(Node::FunctionBody* body) {
	m_stack.push_front(body);
}

void CallStack::iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Node::FunctionBody* body, CallStack& stack, bool isLeft)
{
	stack.push(body);

	FunctionBodyIterator pass(body);
	IterateNodeGroup([&](Node::Node* node)
		{
			if (auto funcNode = dynamic_cast<Node::FunctionNode*>(node)) {
				if (funcNode->isCalculatedFunction()) {
					auto body = funcNode->getFunction()->getBody();
					if (!stack.has(body)) {
						iterateCallStack(callback, body, stack, isLeft);
					}
				}
			}
			return callback(node, stack);
		}, body, isLeft);

	stack.pop();
}