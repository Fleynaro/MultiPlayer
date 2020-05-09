#pragma once
#include <main.h>

namespace CE::CallGraph::Node
{
	enum class Type
	{
		Function = 1,
		VMethod,
		GlobalVar,
		NodeGroup = 11,
		Cycle,
		Condition,
		FunctionBody,
		GlobalVarBody
	};

	class FunctionBody;
	class NodeGroup;
	class Node
	{
	public:
		virtual Type getGroup() = 0;

		NodeGroup* getParent();

		FunctionBody* getFunctionBody();

		void setParent(NodeGroup* parent);
	private:
		NodeGroup* m_parent = nullptr;

		Node* getFunctionBodyNode();
	};

	class NodeGroup : public Node
	{
	public:
		using nodeList = std::vector<Node*>;

		Type getGroup() override;

		nodeList& getNodeList();

		void addNode(Node* node);
	private:
		nodeList m_nodes;
	};
};

namespace CE::CallGraph {
	void IterateNodeGroup(const std::function<bool(Node::Node*)>& callback, Node::Node* node, bool isLeft = true);
};