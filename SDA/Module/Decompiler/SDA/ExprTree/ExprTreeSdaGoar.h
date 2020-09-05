#pragma once
#include "ExprTreeSdaNode.h"

namespace CE::Decompiler::ExprTree
{
	class GoarNode : public SdaNode, public INodeAgregator
	{
	public:
		ISdaNode* m_base;

		GoarNode(ISdaNode* base)
			: m_base(base)
		{
			m_base->addParentNode(this);
		}

		~GoarNode() {
			m_base->removeBy(this);
		}

		void replaceNode(INode* node, INode* newNode) override {
			auto newSdaNode = dynamic_cast<ISdaNode*>(newNode);
			if (node == m_base) {
				m_base = newSdaNode;
			}
		}

		std::list<ExprTree::INode*> getNodesList() override {
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
		ISdaNode* m_indexNode;
		DataTypePtr m_outDataType;

		GoarArrayNode(ISdaNode* base, ISdaNode* indexNode, DataTypePtr dataType)
			: GoarNode(base), m_indexNode(indexNode), m_outDataType(dataType)
		{
			m_indexNode->addParentNode(this);
		}

		~GoarArrayNode() {
			m_indexNode->removeBy(this);
		}

		void replaceNode(INode* node, INode* newNode) override {
			GoarNode::replaceNode(node, newNode);
			auto newSdaNode = dynamic_cast<ISdaNode*>(newNode);
			if (node == m_indexNode) {
				m_indexNode = newSdaNode;
			}
		}

		std::list<ExprTree::INode*> getNodesList() override {
			return { m_base, m_indexNode };
		}

		DataTypePtr getSrcDataType() override {
			return m_outDataType;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new GoarArrayNode(dynamic_cast<ISdaNode*>(m_base->clone()), dynamic_cast<ISdaNode*>(m_indexNode->clone(ctx)), m_outDataType);
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

		GoarFieldNode(ISdaNode* base, DataType::Structure::Field* field)
			: GoarNode(base), m_field(field)
		{}

		DataTypePtr getSrcDataType() override {
			return m_field->getDataType();
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new GoarFieldNode(dynamic_cast<ISdaNode*>(m_base->clone()), m_field);
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
		GoarTopNode(ISdaNode* base, bool isAddrGetting)
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

		INode* clone(NodeCloneContext* ctx) override {
			return new GoarTopNode(dynamic_cast<ISdaNode*>(m_base->clone()), m_isAddrGetting);
		}
		
		std::string printSdaDebug() override {
			return m_base->printSdaDebug();
		}
	};
};