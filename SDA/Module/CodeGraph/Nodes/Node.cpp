#include "Node.h"
#include "GenericNodes.h"
#include "BodyNode.h"
#include <Code/Function/FunctionDefinition.h>

using namespace CE::CodeGraph::Node;

Type NodeGroup::getGroup() {
	return Type::NodeGroup;
}

NodeGroup::nodeList& NodeGroup::getNodeList() {
	return m_nodes;
}

void NodeGroup::addNode(Node* node) {
	getNodeList().push_back(node);
	node->setParent(this);

	if (auto funcNode = static_cast<FunctionNode*>(node)) {
		if (!funcNode->isNotCalculated()) {
			funcNode->getFunction()->getBody()->addReferenceTo(
				getFunctionBody()
			);
		}
	}
	else if (node->getGroup() == Type::GlobalVar) {

	}
}

NodeGroup* Node::getParent() {
	return m_parent;
}

FunctionBody* Node::getFunctionBody() {
	return static_cast<FunctionBody*>(getFunctionBodyNode());
}

void Node::setParent(NodeGroup* parent) {
	m_parent = parent;
}

Node* Node::getFunctionBodyNode() {
	if (getGroup() == Type::FunctionBody) {
		return this;
	}
	if (m_parent == nullptr) {
		throw std::logic_error("parent of code graph node = nullptr");
	}
	return m_parent;
}

void CE::CodeGraph::IterateNodeGroup(const std::function<bool(Node::Node*)>& callback, Node::Node* node, bool isLeft)
{
	if (isLeft) {
		if (!callback(node))
			return;
	}

	if (auto nodeGroup = dynamic_cast<Node::NodeGroup*>(node)) {
		for (auto node : nodeGroup->getNodeList()) {
			IterateNodeGroup(callback, node);
		}
	}

	if (!isLeft) {
		if (!callback(node))
			return;
	}
}
