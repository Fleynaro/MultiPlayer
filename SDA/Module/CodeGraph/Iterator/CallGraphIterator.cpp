#include "CallGraphIterator.h"
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::CodeGraph;

CallGraphIterator::CallGraphIterator(FunctionManager* funcManager)
	: m_funcManager(funcManager)
{}

void CallGraphIterator::iterate(const std::function<bool(Node::Node*, CallStack&)>& callback, bool isLeft)
{
	FunctionManager::Iterator it(m_funcManager);
	while (it.hasNext()) {
		auto func = it.next();
		if (func->getBody()->isSourceTop()) {
			FunctionBodyIterator it(func->getBody());
			it.iterateCallStack([&](Node::Node* node, CallStack& stack)
				{
					return callback(node, stack);
				});
		}
	}
}
