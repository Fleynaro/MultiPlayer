#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class LinearExpr : public Node, public INodeAgregator
	{
	public:
		std::list<ExprTree::Node*> m_terms;
		int64_t m_constTerm;
		OperationType m_operation;
		ObjectHash::Hash m_calcHash;

		LinearExpr(int64_t constTerm = 0x0, OperationType operation = Add)
			: m_constTerm(constTerm), m_operation(operation)
		{}

		~LinearExpr() {
			for (auto term : m_terms) {
				term->removeBy(this);
			}
		}

		void addTerm(ExprTree::Node* term) {
			term->addParentNode(this);
			m_terms.push_back(term);
		}

		void setConstTerm(int64_t constTerm) {
			m_constTerm = constTerm;
		}

		std::list<ExprTree::Node*>& getTerms() {
			return m_terms;
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			for (auto it = m_terms.begin(); it != m_terms.end(); it ++) {
				if (node == *it) {
					*it = newNode;
				}
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return m_terms;
		}

		BitMask64 getMask() override {
			BitMask64 mask;
			for (auto term : m_terms) {
				mask = mask | term->getMask();
			}
			return mask;
		}

		bool isFloatingPoint() override {
			return IsOperationFloatingPoint(m_operation);
		}

		Node* clone() override {
			auto newLinearExpr = new LinearExpr(m_constTerm, m_operation);
			for (auto term : m_terms) {
				newLinearExpr->addTerm(term->clone());
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

			if (m_constTerm) {
				result += NumberLeaf((uint64_t&)m_constTerm).printDebug();
			}

			result += ")";
			return (m_updateDebugInfo = result);
		}
	};
};