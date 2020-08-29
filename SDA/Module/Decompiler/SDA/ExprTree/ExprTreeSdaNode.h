#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTreeNode.h"

namespace CE::Decompiler::ExprTree
{
	class AbstractSdaNode : public Node
	{
	public:
		virtual DataTypePtr getDataType() = 0;

		virtual void setDataType(DataTypePtr dataType) = 0;

		void setDataTypeWithPriority(DataTypePtr dataType) {
			if (getDataType()->getPriority() >= dataType->getPriority())
				return;
			setDataType(dataType);
		}

		virtual std::string printDebugGoar() {
			return "";
		}
	};

	class SdaCastNode : public AbstractSdaNode, public INodeAgregator
	{
		AbstractSdaNode* m_node;
		DataTypePtr m_castDataType;
	public:
		bool m_explicitCast = false;

		SdaCastNode(AbstractSdaNode* node)
			: m_node(node)
		{}

		~SdaCastNode() {
			m_node->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_node == node) {
				m_node = dynamic_cast<AbstractSdaNode*>(newNode);
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_node };
		}

		AbstractSdaNode* getNode() {
			return m_node;
		}

		bool hasCast() {
			return m_castDataType != nullptr;
		}

		DataTypePtr getDataType() override {
			return hasCast() ? m_castDataType : m_node->getDataType();
		}

		void setDataType(DataTypePtr dataType) override {
			m_castDataType = dataType;
		}

		BitMask64 getMask() override {
			return BitMask64(getDataType()->getSize());
		}

		bool isFloatingPoint() override {
			return m_node->isFloatingPoint();
		}

		ObjectHash::Hash getHash() override {
			return m_node->getHash();
		}

		Node* clone(NodeCloneContext* ctx) override {
			auto sdaNode = new SdaCastNode(dynamic_cast<AbstractSdaNode*>(m_node->clone(ctx)));
			sdaNode->m_castDataType = m_castDataType;
			sdaNode->m_explicitCast = m_explicitCast;
			return sdaNode;
		}

		std::string printDebug() override {
			auto result = m_node->printDebug();
			if (m_castDataType != nullptr && m_explicitCast) {
				result = "(" + m_castDataType->getDisplayName() + ")" + result + "";
			}
			return m_updateDebugInfo = result;
		}
	};

	class SdaGenericNode : public AbstractSdaNode, public INodeAgregator
	{
		DataTypePtr m_calcDataType;
		Node* m_node;
	public:
		SdaGenericNode(Node* node, DataTypePtr calcDataType)
			: m_node(node), m_calcDataType(calcDataType)
		{}

		~SdaGenericNode() {
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

		Node* getNode() {
			return m_node;
		}

		DataTypePtr getDataType() override {
			return m_calcDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_calcDataType = dataType;
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
			auto sdaNode = new SdaGenericNode(m_node->clone(ctx), m_calcDataType);
			return sdaNode;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = m_node->printDebug();
		}
	};
};