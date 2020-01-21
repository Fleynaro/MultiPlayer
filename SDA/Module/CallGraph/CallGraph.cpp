#include "CallGraph.h"

using namespace CE;

void CallGraph::Unit::NodeGroup::addNode(Node* node) {
	getNodeList().push_back(node);
	node->setParent(this);

	if (node->getGroup() == Type::Function) {
		static_cast<FunctionNode*>(node)->getFunction()->getBody()->addReferenceTo(
			static_cast<FunctionBody*>(getFunctionBody())
		);
	}
	else if (node->getGroup() == Type::GlobalVar) {

	}
}
