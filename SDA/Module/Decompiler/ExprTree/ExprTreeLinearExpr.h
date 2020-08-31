#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class LinearExpr : public Node, public INodeAgregator, public PCode::IRelatedToInstruction
	{
		std::list<Node*> m_terms;
		INumberLeaf* m_constTerm;
	public:
		OperationType m_operation;
		ObjectHash::Hash m_calcHash;

		LinearExpr(INumberLeaf* constTerm, OperationType operation = Add)
			: m_constTerm(constTerm), m_operation(operation)
		{}

		LinearExpr(int64_t constTerm = 0x0, OperationType operation = Add)
			: m_operation(operation)
		{
			auto numberLeaf = new NumberLeaf((uint64_t)constTerm);
			numberLeaf->addParentNode(this);
			m_constTerm = numberLeaf;
		}

		~LinearExpr() {
			for (auto term : m_terms) {
				term->removeBy(this);
			}
			delete dynamic_cast<Node*>(m_constTerm);
		}

		void addTerm(ExprTree::Node* term) {
			term->addParentNode(this);
			m_terms.push_back(term);
		}

		void setConstTermValue(int64_t constTerm) {
			m_constTerm->setValue((uint64_t)constTerm);
		}

		int64_t getConstTermValue() {
			return (int64_t)m_constTerm->getValue();
		}

		std::list<ExprTree::Node*>& getTerms() {
			return m_terms;
		}

		INumberLeaf* getConstTerm() {
			return m_constTerm;
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			for (auto it = m_terms.begin(); it != m_terms.end(); it ++) {
				if (node == *it) {
					*it = newNode;
				}
			}
			if (auto constTermNode = dynamic_cast<INumberLeaf*>(node)) {
				if (constTermNode == m_constTerm)
					m_constTerm = dynamic_cast<INumberLeaf*>(newNode);
			}
		}

		std::list<Node*> getNodesList() override {
			auto list = m_terms;
			if (auto constTermNode = dynamic_cast<Node*>(m_constTerm)) {
				list.push_back(constTermNode);
			}
			return list;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return {};
		}

		BitMask64 getMask() override {
			BitMask64 mask = getConstTerm()->getValue();
			for (auto term : m_terms) {
				mask = mask | term->getMask();
			}
			return mask;
		}

		bool isFloatingPoint() override {
			return IsOperationFloatingPoint(m_operation);
		}

		Node* clone(NodeCloneContext* ctx) override {
			auto clonedConstTerm = dynamic_cast<Node*>(m_constTerm)->clone();
			auto newLinearExpr = new LinearExpr(dynamic_cast<INumberLeaf*>(clonedConstTerm), m_operation);
			for (auto term : m_terms) {
				newLinearExpr->addTerm(term->clone(ctx));
			}
			return newLinearExpr;
		}

		ObjectHash::Hash getHash() override {
			return m_calcHash;
		}

		std::string printDebug() override {
			std::string result = "(";
			for (auto it = m_terms.begin(); it != m_terms.end(); it ++) {
				result += (*it)->printDebug();
				if (it != std::prev(m_terms.end()) || m_constTerm) {
					result += " " + ShowOperation(m_operation) + OperationalNode::getOpSize(getMask().getSize(), isFloatingPoint()) + " ";
				}
			}

			if (m_constTerm->getValue()) {
				result += dynamic_cast<Node*>(m_constTerm)->printDebug();
			}

			result += ")";
			return (m_updateDebugInfo = result);
		}
	};
};