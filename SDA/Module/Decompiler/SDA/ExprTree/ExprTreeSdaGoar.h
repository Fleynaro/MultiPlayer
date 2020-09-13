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

		ObjectHash::Hash getHash() override {
			return m_base->getHash();
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
		int m_itemsMaxCount;

		GoarArrayNode(ISdaNode* base, ISdaNode* indexNode, DataTypePtr dataType, int itemsMaxCount)
			: GoarNode(base), m_indexNode(indexNode), m_outDataType(dataType), m_itemsMaxCount(itemsMaxCount)
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

		ObjectHash::Hash getHash() override {
			return GoarNode::getHash() + m_indexNode->getHash() * 31;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new GoarArrayNode(dynamic_cast<ISdaNode*>(m_base->clone()), dynamic_cast<ISdaNode*>(m_indexNode->clone(ctx)), m_outDataType, m_itemsMaxCount);
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

	class GoarTopNode : public GoarNode, public IStoredInMemory
	{
		bool m_isAddrGetting;
		ISdaNode* m_mainBase;
		int64_t m_bitOffset;
	public:
		GoarTopNode(ISdaNode* base, ISdaNode* mainBase, int64_t bitOffset, bool isAddrGetting)
			: GoarNode(base), m_mainBase(mainBase), m_bitOffset(bitOffset), m_isAddrGetting(isAddrGetting)
		{}

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		bool tryToGetLocation(Location& location) override {
			if (auto storedInMem = dynamic_cast<IStoredInMemory*>(m_mainBase)) {
				storedInMem->tryToGetLocation(location);
			}
			else {
				location.m_type = Location::IMPLICIT;
				location.m_baseAddrHash = m_mainBase->getHash();
			}
			location.m_offset = m_bitOffset / 0x8;
			location.m_valueSize = m_base->getDataType()->getSize();
			gatherArrDims(m_base, location);
			return true;
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
				return MakePointer(m_base->getDataType());
			}
			return m_base->getDataType();
		}

		ObjectHash::Hash getHash() override {
			return GoarNode::getHash() + m_isAddrGetting * 31;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new GoarTopNode(dynamic_cast<ISdaNode*>(m_base->clone()), m_mainBase, m_bitOffset, m_isAddrGetting);
		}
		
		std::string printSdaDebug() override {
			return m_base->printSdaDebug();
		}

	private:
		void gatherArrDims(INode* node, Location& location) {
			if (auto goarNode = dynamic_cast<GoarNode*>(node)) {
				gatherArrDims(goarNode->m_base, location);
				if (auto goarArrayNode = dynamic_cast<GoarArrayNode*>(node)) {
					Location::ArrayDim arrDim;
					arrDim.m_itemSize = goarArrayNode->getDataType()->getSize();
					arrDim.m_itemsMaxCount = (goarArrayNode->m_itemsMaxCount > 1 ? goarArrayNode->m_itemsMaxCount : -1);
					location.m_arrDims.push_back(arrDim);
				}
			}
		}
	};
};