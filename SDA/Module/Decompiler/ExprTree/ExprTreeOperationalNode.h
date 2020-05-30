#pragma once
#include "ExprTreeLeaf.h"

namespace CE::Decompiler::ExprTree
{
	enum OperationType
	{
		None,

		//Arithmetic
		Add,
		Sub,
		Mul,
		Div,
		Mod,

		//Logic
		And,
		Or,
		Xor,
		Shr,
		Shl,

		//Memory
		readValue,

		//Flags
		getBits
	};

	static std::string ShowOperation(OperationType opType) {
		switch (opType)
		{
		case Add: return "+";
		case Sub: return "-";
		case Mul: return "*";
		case Div: return "/";
		case And: return "&";
		case Or: return "|";
		case Xor: return "^";
		case Shr: return ">>";
		case Shl: return "<<";
		case readValue: return "&";
		}
		return "_";
	}

	class OperationalNode : public Node, public IParentNode
	{
	public:
		Node* m_leftNode;
		Node* m_rightNode;
		OperationType m_operation;

		OperationalNode(Node* leftNode, Node* rightNode, OperationType operation)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation)
		{
			leftNode->addParentNode(this);
			if (rightNode != nullptr) {
				rightNode->addParentNode(this);
			}
		}

		~OperationalNode() {
			if (m_leftNode != nullptr)
				m_leftNode->removeBy(this);
			if (m_rightNode != nullptr)
				m_rightNode->removeBy(this);
		}

		bool isLeaf() override {
			return false;
		}

		void removeNode(Node* node) override {
			if (m_leftNode == node) {
				m_leftNode = nullptr;
			}
			else if (m_rightNode == node) {
				m_rightNode = nullptr;
			}
		}

		std::string printDebug() override {
			if (m_operation == readValue) {
				return "*(uint_" + std::to_string(8 * static_cast<NumberLeaf*>(m_rightNode)->m_value) + "t*)" + m_leftNode->printDebug();
			}
			if (m_operation == Xor) {
				if (static_cast<NumberLeaf*>(m_rightNode)->m_value == -1) {
					return "~" + m_leftNode->printDebug();
				}
			}
			return "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + " " + m_rightNode->printDebug() + ")";
		}
	};
};