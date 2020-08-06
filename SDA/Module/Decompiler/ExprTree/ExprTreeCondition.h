#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class ICondition : public Node, public INumber
	{
	public:
		virtual void inverse() = 0;

		BitMask getMask() override {
			return BitMask((uint64_t)0b1);
		}
	};

	class BooleanValue : public ICondition
	{
	public:
		bool m_value;

		BooleanValue(bool value)
			: m_value(value)
		{}

		void inverse() override {
			m_value ^= true;
		}

		Node* clone() override {
			return new BooleanValue(m_value);
		}

		ObjectHash::Hash getHash() override {
			return m_value ? 0x111 : 0x222;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = (m_value ? "true" : "false");
		}
	};

	class Condition : public ICondition, public INodeAgregator, public IFloatingPoint
	{
	public:
		enum ConditionType
		{
			None,
			Eq,
			Ne,
			Lt,
			Le,
			Gt,
			Ge
		};

		static std::string ShowConditionType(ConditionType condType) {
			switch (condType)
			{
			case Eq: return "==";
			case Ne: return "!=";
			case Lt: return "<";
			case Le: return "<=";
			case Gt: return ">";
			case Ge: return ">=";
			}
			return "_";
		}

		Node* m_leftNode;
		Node* m_rightNode;
		ConditionType m_cond;

		Condition(Node* leftNode, Node* rightNode, ConditionType cond, bool isFloatingPoint = false)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_cond(cond), m_isFloatingPoint(isFloatingPoint)
		{
			leftNode->addParentNode(this);
			rightNode->addParentNode(this);
		}

		~Condition() {
			if (m_leftNode != nullptr)
				m_leftNode->removeBy(this);
			if (m_rightNode != nullptr)
				m_rightNode->removeBy(this);
		}

		void replaceNode(Node* node, Node * newNode) override {
			if (m_leftNode == node) {
				m_leftNode = newNode;
			}
			else if (m_rightNode == node) {
				m_rightNode = newNode;
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { &m_leftNode, &m_rightNode };
		}

		Node* clone() override {
			return new Condition(m_leftNode->clone(), m_rightNode->clone(), m_cond);
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_leftNode->getHash() + m_rightNode->getHash());
			hash.addValue((int)m_cond);
			return hash.getHash();
		}

		bool IsFloatingPoint() override {
			return m_isFloatingPoint;
		}

		void inverse() override {
			switch (m_cond)
			{
			case Eq:
				m_cond = Ne;
				break;
			case Ne:
				m_cond = Eq;
				break;
			case Lt:
				m_cond = Ge;
				break;
			case Le:
				m_cond = Gt;
				break;
			case Gt:
				m_cond = Le;
				break;
			case Ge:
				m_cond = Lt;
				break;
			}
		}

		std::string printDebug() override {
			if (!m_leftNode || !m_rightNode)
				return "";
			return m_updateDebugInfo = ("(" + m_leftNode->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightNode->printDebug() + ")");
		}

	private:
		bool m_isFloatingPoint;
	};

	class CompositeCondition : public ICondition, public INodeAgregator
	{
	public:
		enum CompositeConditionType
		{
			None,
			Not,
			And,
			Or
		};

		static std::string ShowConditionType(CompositeConditionType condType) {
			switch (condType)
			{
			case And: return "&&";
			case Or: return "||";
			}
			return "_";
		}

		ICondition* m_leftCond;
		ICondition* m_rightCond;
		CompositeConditionType m_cond;

		CompositeCondition(ICondition* leftCond, ICondition* rightCond = nullptr, CompositeConditionType cond = None)
			: m_leftCond(leftCond), m_rightCond(rightCond), m_cond(cond)
		{
			leftCond->addParentNode(this);
			if (rightCond != nullptr) {
				rightCond->addParentNode(this);
			}
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (auto cond = dynamic_cast<ICondition*>(node)) {
				if (auto newCond = dynamic_cast<ICondition*>(newNode)) {
					if (m_leftCond == cond)
						m_leftCond = newCond;
					else if (m_rightCond == cond)
						m_rightCond = newCond;
				}
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { (ExprTree::Node**)&m_leftCond, (ExprTree::Node**)&m_rightCond };
		}

		Node* clone() override {
			return new CompositeCondition(dynamic_cast<ICondition*>(m_leftCond->clone()), m_rightCond ? dynamic_cast<ICondition*>(m_rightCond->clone()) : nullptr, m_cond);
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_leftCond->getHash() + (m_rightCond ? m_rightCond->getHash() : 0x0));
			hash.addValue((int)m_cond);
			return hash.getHash();
		}

		void inverse() override {
			if (m_cond == Not) {
				m_cond = None;
				return;
			}
			if (m_cond == None) {
				m_cond = Not;
				return;
			}

			switch (m_cond)
			{
			case And:
				m_cond = Or;
				break;
			case Or:
				m_cond = And;
				break;
			}

			if (m_leftCond)
				m_leftCond->inverse();
			if (m_rightCond)
				m_rightCond->inverse();
		}

		std::string printDebug() override {
			if (!m_leftCond)
				return "";
			if (m_cond == None) {
				return m_updateDebugInfo = m_leftCond->printDebug();
			}
			if (m_cond == Not) {
				return m_updateDebugInfo = ("!(" + m_leftCond->printDebug() + ")");
			}
			return m_updateDebugInfo = ("(" + m_leftCond->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightCond->printDebug() + ")");
		}
	};
};