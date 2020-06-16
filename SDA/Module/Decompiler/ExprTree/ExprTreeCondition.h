#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class Condition : public Node, public IParentNode
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

		void replaceBy(Node* newNode) override {
			Node::replaceBy(newNode);
			if (auto newParentNode = dynamic_cast<IParentNode*>(newNode)) {
				if (m_leftNode != nullptr)
					m_leftNode->addParentNode(newParentNode);
				if (m_rightNode != nullptr)
					m_rightNode->addParentNode(newParentNode);
			}
		}

		void replaceNode(Node* node, Node * newNode) override {
			if (m_leftNode == node) {
				m_leftNode = newNode;
			}
			else if (m_rightNode == node) {
				m_rightNode = newNode;
			}
		}

		void inverse() {
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

	class CompositeCondition : public Node
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

		Node* m_leftNode;
		Node* m_rightNode;
		CompositeConditionType m_cond;

		CompositeCondition(Node* leftNode, Node* rightNode = nullptr, CompositeConditionType cond = None)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_cond(cond)
		{}

		std::string printDebug() override {
			if (m_cond == None) {
				return m_leftNode->printDebug();
			}
			if (m_cond == Not) {
				return "!(" + m_leftNode->printDebug() + ")";
			}
			return "(" + m_leftNode->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightNode->printDebug() + ")";
		}
	};

	class TernaryOperationalNode : public OperationalNode
	{
	public:
		CompositeCondition* m_condition;

		TernaryOperationalNode(CompositeCondition* condition, Node* leftNode, Node* rightNode)
			: m_condition(condition), OperationalNode(leftNode, rightNode, ExprTree::None)
		{}

		~TernaryOperationalNode() {
			m_condition->removeBy(this);
		}

		void replaceNode(Node* node, Node * newNode) override {
			OperationalNode::replaceNode(node, newNode);
			if (m_condition == node) {
				if (auto cond = dynamic_cast<CompositeCondition*>(newNode)) {
					m_condition = cond;
				}
				else {
					delete this;
				}
			}
		}

		std::string printDebug() override {
			return "(" + m_condition->printDebug() + ") ? " + "(" + m_leftNode->printDebug() + ") : (" + m_rightNode->printDebug() + ")";
		}
	};
};