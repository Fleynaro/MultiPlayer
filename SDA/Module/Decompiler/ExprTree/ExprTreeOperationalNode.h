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

	enum class OperationGroup {
		None,
		Arithmetic,
		Logic,
		Memory
	};

	static OperationGroup GetOperationGroup(OperationType opType) {
		if (opType >= Add && opType <= Mod)
			return OperationGroup::Arithmetic;
		if (opType >= And && opType <= Shl)
			return OperationGroup::Logic;
		if(opType == readValue)
			return OperationGroup::Memory;
		return OperationGroup::None;
	}

	static bool IsOperationOverflow(OperationType opType) {
		return opType == Add || opType == Sub || opType == Mul || opType == Shl;
	}

	static bool IsOperationSigned(OperationType opType) {
		return GetOperationGroup(opType) == OperationGroup::Arithmetic && opType != Mod;
	}

	static bool IsOperationManipulatedWithBitVector(OperationType opType) {
		return opType == And || opType == Or || opType == Xor;
	}

	static bool IsOperationUnsupportedToCalculate(OperationType operation) {
		return operation == readValue || operation == getBits;
	}

	static std::string ShowOperation(OperationType opType) {
		switch (opType)
		{
		case Add: return "+";
		case Sub: return "-";
		case Mul: return "*";
		case Div: return "/";
		case Mod: return "%";
		case And: return "&";
		case Or: return "|";
		case Xor: return "^";
		case Shr: return ">>";
		case Shl: return "<<";
		case readValue: return "&";
		}
		return "_";
	}

	class OperationalNode : public Node, public IParentNode, public INumber
	{
	public:
		Node* m_leftNode;
		Node* m_rightNode;
		OperationType m_operation;
		uint64_t m_mask = -1;

		OperationalNode(Node* leftNode, Node* rightNode, OperationType operation)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation)
		{
			leftNode->addParentNode(this);
			if (rightNode != nullptr) {
				rightNode->addParentNode(this);
			}
		}

		~OperationalNode() {
			auto leftNode = m_leftNode;
			if (leftNode != nullptr)
				leftNode->removeBy(this);
			if (m_rightNode != nullptr && m_rightNode != leftNode)
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

		uint64_t getMask() override {
			return m_mask;
		}

		std::string printDebug() override {
			std::string result = "";
			if (m_operation == readValue) {
				result = "*(uint_" + std::to_string(8 * static_cast<NumberLeaf*>(m_rightNode)->m_value) + "t*)" + m_leftNode->printDebug();
			} else if (m_operation == Xor) {
				if (static_cast<NumberLeaf*>(m_rightNode)->m_value == -1) {
					result = "~" + m_leftNode->printDebug();
				}
			}
			else {
				result = "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + " " + m_rightNode->printDebug() + ")";
			}
			return result;// + "<" + std::to_string((uint64_t)this % 100000) + ">";
		}
	};
};