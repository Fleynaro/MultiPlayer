#include "CallGraph.h"

using namespace CE;

void CallGraph::Node::NodeGroup::addNode(Node* node) {
	getNodeList().push_back(node);
	node->setParent(this);

	if (node->getGroup() == Type::Function) {
		auto funcNode = static_cast<FunctionNode*>(node);
		if (!funcNode->isNotCalculated()) {
			funcNode->getFunction()->getBody()->addReferenceTo(
				static_cast<FunctionBody*>(getFunctionBody())
			);
		}
	}
	else if (node->getGroup() == Type::GlobalVar) {

	}
}
