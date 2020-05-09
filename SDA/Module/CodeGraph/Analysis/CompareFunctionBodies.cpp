#include "CompareFunctionBodies.h"

using namespace CE::CallGraph;
using namespace CE::CallGraph::Analyser;

CompareFunctionBodies::CompareFunctionBodies(Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2) {
	m_funcBody[0] = funcBody1;
	m_funcBody[1] = funcBody2;
}

void CompareFunctionBodies::doAnalyse() {
	std::list<Node::Node*> nodesInBody[2];

	for (int i = 0; i <= 1; i++) {
		FunctionBodyIterator it(m_funcBody[i]);
		nodesInBody[i] = it.getAllNodesInCallTree(FunctionBodyIterator::Filter::FunctionBody);
	}

	for (auto node1 : nodesInBody[0]) {
		auto funcBody1 = static_cast<Node::FunctionBody*>(node1);
		for (auto node2 : nodesInBody[1]) {
			auto funcBody2 = static_cast<Node::FunctionBody*>(node2);
			if (funcBody1->getFunction() == funcBody2->getFunction()) {
				m_mutualFuncBodies.push_back(funcBody1);
			}
		}
	}
}

const std::list<Node::FunctionBody*>& CompareFunctionBodies::getMutualFuncBodies() {
	return m_mutualFuncBodies;
}
