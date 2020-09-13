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

		ISdaNode* m_baseAddrNode;
		SdaNumberLeaf* m_constTerm;
		std::list<Term> m_terms;
		bool m_isAddrGetting;

		UnknownLocation(SdaNumberLeaf* constTerm)
			: m_constTerm(constTerm)
		{}

		~UnknownLocation() {
			for (auto& term : m_terms) {
				term.m_node->removeBy(this);
			}
			m_constTerm->removeBy(this);
		}

		void addTerm(ExprTree::ISdaNode* termNode) {
			Term term;
			term.m_node = termNode;
			termNode->addParentNode(this);
			m_terms.push_back(term);
		}

		void setConstTermValue(int64_t constTerm) {
			m_constTerm->setValue((uint64_t)constTerm);
		}

		int64_t getConstTermValue() {
			return (int64_t)m_constTerm->getValue();
		}

		std::list<Term>& getTerms() {
			return m_terms;
		}

		SdaNumberLeaf* getConstTerm() {
			return m_constTerm;
		}

		void replaceNode(ExprTree::INode* node, ExprTree::INode* newNode) override {
			for (auto it = m_terms.begin(); it != m_terms.end(); it++) {
				if (node == it->m_node) {
					it->m_node = dynamic_cast<ISdaNode*>(newNode);
				}
			}
			if(node == m_baseAddrNode)
				m_baseAddrNode = dynamic_cast<ISdaNode*>(newNode);
			if (node == m_constTerm)
				m_constTerm = dynamic_cast<SdaNumberLeaf*>(newNode);
		}

		std::list<INode*> getNodesList() override {
			std::list<INode*> list;
			for (auto& term : m_terms) {
				list.push_back(term.m_node);
			}
			list.push_back(m_baseAddrNode);
			list.push_back(m_constTerm);
			return list;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return {};
		}

		BitMask64 getMask() override {
			return m_baseAddrNode->getMask();
		}

		ObjectHash::Hash getHash() override {
			return m_baseAddrNode->getHash() + 31 * getConstTermValue(); //todo: + term hashes
		}

		INode* clone(NodeCloneContext* ctx) override {
			auto clonedConstTerm = dynamic_cast<SdaNumberLeaf*>(m_constTerm->clone(ctx));
			auto newUnknownLocation = new UnknownLocation(clonedConstTerm);
			for (auto& term : m_terms) {
				newUnknownLocation->addTerm(dynamic_cast<ISdaNode*>(term.m_node->clone(ctx)));
			}
			return newUnknownLocation;
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
				return MakePointer(m_baseAddrNode->getDataType());
			}
			return m_baseAddrNode->getDataType();
		}

		void setDataType(DataTypePtr dataType) override {
			if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(m_baseAddrNode)) {
				autoSdaSymbol->setDataType(dataType);
			}
		}

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		bool tryToGetLocation(Location& location) override {
			
			return true;
		}

		std::string printSdaDebug() override {
			std::string result = "(";
			for (auto it = m_terms.begin(); it != m_terms.end(); it++) {
				result += it->m_node->printDebug();
				if (it != std::prev(m_terms.end()) || m_constTerm->getValue()) {
					result += result += " +" + OperationalNode::getOpSize(getMask().getSize(), false) + " ";
				}
			}

			if (m_constTerm->getValue()) {
				result += m_constTerm->printDebug();
			}

			result += ")";
			return (m_updateDebugInfo = result);
		}
	};
};