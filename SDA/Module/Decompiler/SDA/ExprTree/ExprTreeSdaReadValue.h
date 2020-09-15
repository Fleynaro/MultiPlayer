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

		~SdaReadValueNode() {
			m_readValueNode->removeBy(this);
		}

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

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
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
			else {
				ISdaNode* sdaAddrNode = nullptr;
				int64_t offset = 0x0;
				if (auto symbolLeaf = dynamic_cast<SdaSymbolLeaf*>(getAddress())) {
					sdaAddrNode = symbolLeaf;
				}
				else if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(getAddress())) {
					if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) {
						if (linearExpr->getTerms().size() == 1) {
							if(auto sdaAddrNode = dynamic_cast<ISdaNode*>(*linearExpr->getTerms().begin())) {
								sdaAddrNode = sdaAddrNode;
								offset = linearExpr->getConstTermValue();
							}
						}
					}
				}

				if (sdaAddrNode && sdaAddrNode->getSrcDataType()->getSize() == 0x8) {
					location.m_type = MemLocation::IMPLICIT;
					location.m_baseAddrHash = sdaAddrNode->getHash();
					location.m_offset = offset;
					location.m_valueSize = getSize();
					return;
				}
			}
			throw std::exception("impossible to determine the location");
		}

		std::string printSdaDebug() override {
			auto result = "*" + getAddress()->printDebug();
			return result;
		}
	};
};