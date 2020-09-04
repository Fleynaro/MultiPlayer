#pragma once
#include "ExprTreeSdaAbstractNode.h"

namespace CE::Decompiler::ExprTree
{
	class GoarNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		AbstractSdaNode* m_base;

		GoarNode(AbstractSdaNode* base)
			: m_base(base)
		{
			m_base->addParentNode(this);
		}

		~GoarNode() {
			m_base->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			auto newSdaNode = dynamic_cast<AbstractSdaNode*>(newNode);
			if (node == m_base) {
				m_base = newSdaNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_base };
		}

		BitMask64 getMask() override {
			return BitMask64(getSrcDataType()->getSize());
		}

		bool isFloatingPoint() override {
			return false;
		}

		void setDataType(DataTypePtr dataType) override {
		}
	};

	class GoarArrayNode : public GoarNode
	{
	public:
		AbstractSdaNode* m_indexNode;
		DataTypePtr m_outDataType;

		GoarArrayNode(AbstractSdaNode* base, AbstractSdaNode* indexNode, DataTypePtr dataType)
			: GoarNode(base), m_indexNode(indexNode), m_outDataType(dataType)
		{
			m_indexNode->addParentNode(this);
		}

		~GoarArrayNode() {
			m_indexNode->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			GoarNode::replaceNode(node, newNode);
			auto newSdaNode = dynamic_cast<AbstractSdaNode*>(newNode);
			if (node == m_indexNode) {
				m_indexNode = newSdaNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_base, m_indexNode };
		}

		DataTypePtr getSrcDataType() override {
			return m_outDataType;
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new GoarArrayNode(dynamic_cast<AbstractSdaNode*>(m_base->clone()), dynamic_cast<AbstractSdaNode*>(m_indexNode->clone(ctx)), m_outDataType);
		}

		std::string printSdaDebug() override {
			auto str = m_base->printSdaDebug();
			str = str + "[" + m_indexNode->printDebug() + "]";
			return str;
		}
	};

	class GoarFieldNode : public GoarNode
	{
	public:
		DataType::Structure::Field* m_field;

		GoarFieldNode(AbstractSdaNode* base, DataType::Structure::Field* field)
			: GoarNode(base), m_field(field)
		{}

		DataTypePtr getSrcDataType() override {
			return m_field->getDataType();
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new GoarFieldNode(dynamic_cast<AbstractSdaNode*>(m_base->clone()), m_field);
		}

		std::string printSdaDebug() override {
			auto str = m_base->printSdaDebug();
			str += m_base->getDataType()->isPointer() ? "->" : ".";
			str += m_field->getName();
			return str;
		}
	};

	class GoarTopNode : public GoarNode, public IAddressGetting
	{
		bool m_isAddrGetting;
	public:
		GoarTopNode(AbstractSdaNode* base, bool isAddrGetting)
			: GoarNode(base), m_isAddrGetting(isAddrGetting)
		{}

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
				auto dataType = DataType::CloneUnit(m_base->getDataType());
				dataType->addPointerLevelInFront();
				return dataType;
			}
			return m_base->getDataType();
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new GoarTopNode(dynamic_cast<AbstractSdaNode*>(m_base->clone()), m_isAddrGetting);
		}
		
		std::string printSdaDebug() override {
			return m_base->printSdaDebug();
		}
	};
};