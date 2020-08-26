#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTreeNode.h"

namespace CE::Decompiler::ExprTree
{
	class AbstractSdaNode : public Node
	{
	public:
		virtual DataTypePtr getDataType() = 0;

		virtual std::string printDebugGoar() {
			return "";
		}
	};

	class SdaNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		Node* m_node;
		DataTypePtr m_calcDataType;
		bool m_explicitCast;

		SdaNode(Node* node)
			: m_node(node)
		{}

		~SdaNode() {
			m_node->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_node == node) {
				m_node = newNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_node };
		}

		DataTypePtr getDataType() override {
			return m_calcDataType;
		}

		BitMask64 getMask() override {
			return m_node->getMask();
		}

		bool isFloatingPoint() override {
			return m_node->isFloatingPoint();
		}

		ObjectHash::Hash getHash() override {
			return m_node->getHash();
		}

		Node* clone(NodeCloneContext* ctx) override {
			auto sdaNode = new SdaNode(m_node->clone(ctx));
			sdaNode->m_calcDataType = m_calcDataType;
			sdaNode->m_explicitCast = m_explicitCast;
			return sdaNode;
		}

		std::string printDebug() override {
			auto result = m_node->printDebug();
			if (m_calcDataType != nullptr && m_explicitCast) {
				result = "(" + m_calcDataType->getDisplayName() + ")" + result + "";
			}
			return m_updateDebugInfo = result;
		}
	};
};