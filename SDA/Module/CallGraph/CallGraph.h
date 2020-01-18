#pragma once
#include <Code/Function/Method.h>

namespace CE
{
	namespace CallGraph
	{
		enum class Type
		{
			Function = 1,
			GlobalVar,
			NodeGroup = 11,
			Cycle,
			Condition,
			FunctionBody
		};

		class NodeGroup;
		class Node
		{
		public:
			Node() = default;

			virtual Type getGroup() = 0;

			NodeGroup* getParent() {
				return m_parent;
			}

			void setParent(NodeGroup* parent) {
				m_parent = parent;
			}
		private:
			NodeGroup* m_parent = nullptr;
		};

		class NodeGroup : public Node
		{
		public:
			using nodeList = std::vector<Node*>;
			NodeGroup() = default;

			Type getGroup() override {
				return Type::NodeGroup;
			}

			nodeList& getNodeList() {
				return m_nodes;
			}

			void addNode(Node* node) {
				getNodeList().push_back(node);
				node->setParent(this);
			}
		private:
			nodeList m_nodes;
		};

		class AbstractNode : public Node
		{
		public:
			AbstractNode(void* addr)
				: m_addr(addr)
			{}

			void* getAddressLocation() {
				return m_addr;
			}
		private:
			void* m_addr;
		};

		class FunctionNode : public AbstractNode
		{
		public:
			FunctionNode(Function::Function* function, void* addr)
				: m_function(function), AbstractNode(addr)
			{}

			FunctionNode(void* addr)
				: AbstractNode(addr)
			{}

			Type getGroup() override {
				return Type::Function;
			}

			bool isNotCalculated() {
				return getFunction() == nullptr;
			}

			Function::Function* getFunction() {
				return m_function;
			}
		private:
			Function::Function* m_function = nullptr;
		};

		class GlobalVarNode : public AbstractNode
		{
		public:
			enum Use {
				Read,
				Write
			};

			GlobalVarNode(Variable::Global* gVar, Use use, void* addr)
				: m_gVar(gVar), m_use(use), AbstractNode(addr)
			{}

			Type getGroup() override {
				return Type::GlobalVar;
			}

			Variable::Global* getGVar() {
				return m_gVar;
			}

			Use getUse() {
				return m_use;
			}
		private:
			Variable::Global* m_gVar;
			Use m_use;
		};

		class Condition : public NodeGroup
		{
		public:
			Condition() = default;

			Type getGroup() override {
				return Type::Condition;
			}
		};

		class Cycle : public NodeGroup
		{
		public:
			Cycle() = default;

			Type getGroup() override {
				return Type::Cycle;
			}
		};

		class FunctionBody : public NodeGroup
		{
		public:
			FunctionBody() = default;

			Type getGroup() override {
				return Type::FunctionBody;
			}
		};

		/*static Node* createGroupNode(Type type)
		{
			switch (type)
			{
			case Type::NodeGroup:
				return new NodeGroup;
			}
		}*/
	};
};