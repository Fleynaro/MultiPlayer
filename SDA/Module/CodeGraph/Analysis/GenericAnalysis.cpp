#include "GenericAnalysis.h"
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::CallGraph;
using namespace CE::CallGraph::Analyser;

Node::FunctionBody::BasicInfo GenericAll::iterateCallStack(Node::FunctionBody* body, CallStack& stack)
{
	if (body->getBasicInfo().m_inited) {
		auto info = body->getBasicInfo();
		return info;
	}

	Node::FunctionBody::BasicInfo info;
	info.m_inited = true;
	stack.push(body);

	IterateNodeGroup([&](Node::Node* node)
		{
			if (auto funcNode = dynamic_cast<Node::FunctionNode*>(node)) {
				if (funcNode->isCalculatedFunction()) {
					auto body = funcNode->getFunction()->getBody();
					if (!stack.has(body)) {
						info.join(
							iterateCallStack(body, stack)
						);
					}
					info.m_calculatedFuncCount++;
				}
				else {
					info.m_notCalculatedFuncCount++;
				}
			}

			if (auto vmethodNode = dynamic_cast<Node::VMethodNode*>(node)) {
				info.m_vMethodCount++;
			}

			if (auto gvarNode = dynamic_cast<Node::GlobalVarNode*>(node)) {
				info.m_gVarCount++;
				if (gvarNode->getUse() == Node::GlobalVarNode::Write) {
					info.m_gVarWriteCount++;
				}
			}
			return true;
		}, body);

	info.next();
	body->setBasicInfo(info);

	stack.pop();
	return info;
}

void GenericAll::doAnalyse() {
	{
		FunctionManager::Iterator it(m_funcManager);
		while (it.hasNext()) {
			auto func = it.next();
			func->getBody()->getBasicInfo().m_inited = false;
		}
	}

	{
		FunctionManager::Iterator it(m_funcManager);
		while (it.hasNext()) {
			auto func = it.next();
			if (func->getBody()->isSourceTop()) {
				CallStack stack;
				iterateCallStack(func->getBody(), stack);
			}
		}
	}
}

GenericAll::GenericAll(FunctionManager* funcManager)
	: m_funcManager(funcManager)
{}
