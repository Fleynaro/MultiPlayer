#include "ContextDistance.h"
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::CodeGraph;

ContextDistance::ContextDistance(FunctionManager* funcManager, Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2)
	: m_funcManager(funcManager)
{
	m_funcBody[0] = funcBody1;
	m_funcBody[1] = funcBody2;
}

void ContextDistance::doAnalyse() {
	FunctionManager::Iterator it(m_funcManager);
	while (it.hasNext()) {
		auto func = it.next();
		if (func->getBody()->isSourceTop()) {
			iterateCallTree(func->getBody(), 1);
		}
	}
}

std::pair<int, int> ContextDistance::iterateCallTree(Node::FunctionBody* funcBody, int depth) {
	if (funcBody == m_funcBody[0])
		return std::make_pair(depth, m_maxDeepth);
	if (funcBody == m_funcBody[1])
		return std::make_pair(m_maxDeepth, depth);

	std::pair<int, int> result(m_maxDeepth, m_maxDeepth);

	IterateNodeGroup([&](Node::Node* node)
		{
			if (auto funcNode = dynamic_cast<Node::FunctionNode*>(node)) {
				if (!funcNode->isNotCalculated()) {
					auto pair = iterateCallTree(funcNode->getFunction()->getBody(), depth + 1);
					if (pair.first < result.first) {
						result.first = pair.first;
					}
					if (pair.second < result.second) {
						result.second = pair.second;
					}
				}
			}
			return true;
		}, funcBody);

	if (result.first != m_maxDeepth && result.second != m_maxDeepth) {
		auto fromDist = result.first - depth;
		auto toDist = result.second - depth;
		if (fromDist + toDist < m_result.getDist()) {
			m_result = Result(funcBody, fromDist, toDist);
		}
	}

	return result;
}



ContextDistance::Result& ContextDistance::getResult() {
	return m_result;
}

ContextDistance::Result::Result(Node::FunctionBody* topFuncBody, int fromDist, int toDist)
	: m_topFuncBody(topFuncBody), m_fromDist(fromDist), m_toDist(toDist)
{}

int ContextDistance::Result::getDist() {
	return m_fromDist + m_toDist;
}
