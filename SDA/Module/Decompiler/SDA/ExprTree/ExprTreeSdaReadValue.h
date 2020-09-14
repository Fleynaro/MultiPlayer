#pragma once
#include "ExprTreeSdaNode.h"

namespace CE::Decompiler::ExprTree
{
	class SdaReadValueNode : public SdaNode, public INodeAgregator, public PCode::IRelatedToInstruction, public IMappedToMemory
	{
	public:
		ReadValueNode* m_readValueNode;
		DataTypePtr m_outDataType;

		SdaReadValueNode(ReadValueNode* readValueNode, DataTypePtr outDataType)
			: m_readValueNode(readValueNode), m_outDataType(outDataType)
		{}

		int getSize() {
			return m_readValueNode->getSize();
		}

		ISdaNode* getAddress() {
			return dynamic_cast<ISdaNode*>(m_readValueNode->getAddress());
		}

		void replaceNode(ExprTree::INode* node, ExprTree::INode* newNode) override {
			if (node == m_readValueNode)
				m_readValueNode = dynamic_cast<ReadValueNode*>(newNode);
		}

		std::list<INode*> getNodesList() override {
			return m_readValueNode->getNodesList();
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return m_readValueNode->getInstructionsRelatedTo();
		}

		BitMask64 getMask() override {
			return m_readValueNode->getMask();
		}

		ObjectHash::Hash getHash() override {
			return m_readValueNode->getHash(); //todo: + term hashes
		}

		INode* clone(NodeCloneContext* ctx) override {
			auto clonedReadValueNode = dynamic_cast<ReadValueNode*>(m_readValueNode->clone(ctx));
			return new SdaReadValueNode(clonedReadValueNode, CloneUnit(m_outDataType));
		}

		DataTypePtr getSrcDataType() override {
			return m_outDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_outDataType = dataType;
		}

		bool isAddrGetting() override {
			return false;
		}

		void setAddrGetting(bool toggle) override {
		}

		void getLocation(MemLocation& location) override {
			if (auto locatableAddrNode = dynamic_cast<ILocatable*>(getAddress())) {
				locatableAddrNode->getLocation(location);
				location.m_valueSize = getSize();
				return;
			}
			throw std::exception("impossible to determine the location");
		}

		std::string printSdaDebug() override {
			auto result = "*" + getAddress()->printDebug();
			return result;
		}
	};
};