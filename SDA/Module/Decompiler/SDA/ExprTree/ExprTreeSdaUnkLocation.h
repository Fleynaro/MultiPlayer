#pragma once
#include "ExprTreeSdaNode.h"
#include "ExprTreeSdaGenericNode.h"
#include "ExprTreeSdaLeaf.h"

namespace CE::Decompiler::ExprTree
{
	class UnknownLocation : public SdaNode, public INodeAgregator, public PCode::IRelatedToInstruction, public IStoredInMemory
	{
	public:
		struct Term {
			ISdaNode* m_node;
			
			INumberLeaf* getMultiplier() {
				if (auto sdaTermGenNode = dynamic_cast<SdaGenericNode*>(m_node)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaTermGenNode->getNode())) {
						if (opNode->m_operation == Mul) {
							return dynamic_cast<INumberLeaf*>(opNode->m_rightNode);
						}
					}
				}
				return nullptr;
			}
		};

		DataTypePtr m_outDataType;
		LinearExpr* m_linearExpr;
		int m_baseNodeIdx;
		bool m_isAddrGetting;

		UnknownLocation(LinearExpr* linearExpr, int baseNodeIdx, bool isAddrGetting)
			: m_linearExpr(linearExpr), m_baseNodeIdx(baseNodeIdx), m_isAddrGetting(isAddrGetting)
		{
			m_outDataType = CloneUnit(getBaseSdaNode()->getDataType());
			m_outDataType->removePointerLevelOutOfFront();
		}

		~UnknownLocation() {
			m_linearExpr->removeBy(this);
		}

		ISdaNode* getBaseSdaNode() {
			int idx = 0;
			for (auto termNode : m_linearExpr->getTerms()) {
				if (idx++ == m_baseNodeIdx)
					return dynamic_cast<ISdaNode*>(termNode);
			}
			return nullptr;
		}

		LinearExpr* getLinearExpr() {
			return m_linearExpr;
		}

		void setConstTermValue(int64_t constTerm) {
			m_linearExpr->setConstTermValue(constTerm);
		}

		int64_t getConstTermValue() {
			return m_linearExpr->getConstTermValue();
		}

		std::list<Term> getArrTerms() {
			std::list<Term> terms;
			int idx = 0;
			for (auto termNode : m_linearExpr->getTerms()) {
				if (idx++ == m_baseNodeIdx)
					continue;
				Term term;
				term.m_node = dynamic_cast<ISdaNode*>(termNode);
				terms.push_back(term);
			}
			return terms;
		}

		void replaceNode(ExprTree::INode* node, ExprTree::INode* newNode) override {
			if (node == m_linearExpr)
				m_linearExpr = dynamic_cast<LinearExpr*>(newNode);
		}

		std::list<INode*> getNodesList() override {
			return m_linearExpr->getNodesList();
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return m_linearExpr->getInstructionsRelatedTo();
		}

		BitMask64 getMask() override {
			return m_linearExpr->getMask();
		}

		ObjectHash::Hash getHash() override {
			return m_linearExpr->getHash(); //todo: + term hashes
		}

		INode* clone(NodeCloneContext* ctx) override {
			auto clonedLinearExpr = dynamic_cast<LinearExpr*>(m_linearExpr->clone(ctx));
			auto newUnknownLocation = new UnknownLocation(clonedLinearExpr, m_baseNodeIdx, m_isAddrGetting);
			return newUnknownLocation;
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
				return MakePointer(m_outDataType);
			}
			return m_outDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_outDataType = dataType;
		}

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		bool tryToGetLocation(Location& location) override {
			if (auto storedInMem = dynamic_cast<IStoredInMemory*>(getBaseSdaNode())) {
				storedInMem->tryToGetLocation(location);
			}
			else {
				location.m_type = Location::IMPLICIT;
				location.m_baseAddrHash = getBaseSdaNode()->getHash();
			}
			location.m_offset = getConstTermValue();
			location.m_valueSize = m_outDataType->getSize();
			for (auto term : getArrTerms()) {
				auto multiplier = term.getMultiplier();
				Location::ArrayDim arrDim;
				arrDim.m_itemSize = multiplier ? (int)multiplier->getValue() : 1;
				location.m_arrDims.push_back(arrDim);
			}
			return true;
		}

		std::string printSdaDebug() override {
			return m_linearExpr->printDebug();
		}
	};
};