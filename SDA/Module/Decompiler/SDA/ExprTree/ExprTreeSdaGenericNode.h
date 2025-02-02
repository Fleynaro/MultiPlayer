#pragma once
#include "ExprTreeSdaNode.h"

namespace CE::Decompiler::ExprTree
{
	class SdaGenericNode : public SdaNode, public INodeAgregator
	{
		DataTypePtr m_calcDataType;
		INode* m_node;
	public:
		SdaGenericNode(INode* node, DataTypePtr calcDataType)
			: m_node(node), m_calcDataType(calcDataType)
		{}

		~SdaGenericNode() {
			m_node->removeBy(this);
		}

		void replaceNode(INode* node, INode* newNode) override {
			if (m_node == node) {
				m_node = newNode;
			}
		}

		std::list<ExprTree::INode*> getNodesList() override {
			return { m_node };
		}

		INode* getNode() {
			return m_node;
		}

		DataTypePtr getSrcDataType() override {
			return m_calcDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_calcDataType = dataType;
		}

		int getSize() override {
			return m_node->getSize();
		}

		bool isFloatingPoint() override {
			return m_node->isFloatingPoint();
		}

		HS getHash() override {
			return m_node->getHash();
		}

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
			auto clonedNode = m_node->clone(ctx);
			auto sdaNode = new SdaGenericNode(clonedNode, CloneUnit(m_calcDataType));
			clonedNode->addParentNode(sdaNode);
			return sdaNode;
		}

		std::string printSdaDebug() override {
			auto result = m_node->printDebug();
			if (auto readValueNode = dynamic_cast<ReadValueNode*>(m_node))
				result = "*" + readValueNode->getAddress()->printDebug();
			return result;
		}
	};
};