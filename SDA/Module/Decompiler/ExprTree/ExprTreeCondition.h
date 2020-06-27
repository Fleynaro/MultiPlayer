#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class ICondition : public Node, public IParentNode
	{
	public:
		virtual void inverse() = 0;
	};

	class Condition : public ICondition
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

		Condition(Node* leftNode, Node* rightNode, ConditionType cond)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_cond(cond)
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
			return "(" + m_leftNode->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightNode->printDebug() + ")";
		}
	};

	class CompositeCondition : public ICondition
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

		void inverse() override {
			switch (m_cond)
			{
			case Not:
				m_cond = None;
				break;
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
			if (m_cond == None) {
				return m_leftCond->printDebug();
			}
			if (m_cond == Not) {
				return "!(" + m_leftCond->printDebug() + ")";
			}
			return "(" + m_leftCond->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightCond->printDebug() + ")";
		}
	};

	class TernaryOperationalNode : public OperationalNode
	{
	public:
		ICondition* m_condition;

		TernaryOperationalNode(ICondition* condition, Node* leftNode, Node* rightNode)
			: m_condition(condition), OperationalNode(leftNode, rightNode, ExprTree::None)
		{}

		~TernaryOperationalNode() {
			m_condition->removeBy(this);
		}

		void replaceNode(Node* node, Node * newNode) override {
			OperationalNode::replaceNode(node, newNode);
			if (auto cond = dynamic_cast<ICondition*>(node)) {
				if (auto newCond = dynamic_cast<ICondition*>(newNode)) {
					if (m_condition == cond) {
						m_condition = newCond;
					}
				}
			}
		}

		std::string printDebug() override {
			return "(" + m_condition->printDebug() + ") ? " + "(" + m_leftNode->printDebug() + ") : (" + m_rightNode->printDebug() + ")";
		}
	};
};