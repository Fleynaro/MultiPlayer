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

		void removeNode(Node* node) override {
			if (m_leftNode == node) {
				m_leftNode = nullptr;
			}
			else if (m_rightNode == node) {
				m_rightNode = nullptr;
			}
		}

		bool isLeaf() override {
			return false;
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

		bool isLeaf() override {
			return false;
		}

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

		void removeNode(Node* node) override {
			OperationalNode::removeNode(node);
			if (m_condition == node) {
				delete this;
			}
		}

		std::string printDebug() override {
			return "(" + m_condition->printDebug() + ") ? " + "(" + m_leftNode->printDebug() + ") : (" + m_rightNode->printDebug() + ")";
		}
	};
};