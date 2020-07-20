#pragma once
#include "ExprTreeLeaf.h"
#include "../DecPCode.h"

namespace CE::Decompiler::ExprTree
{
	enum OperationType
	{
		None,

		//Arithmetic
		Add,
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
		ReadValue,

		//Other
		Cast,
		Functional
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
		if(opType == ReadValue)
			return OperationGroup::Memory;
		return OperationGroup::None;
	}

	static bool IsOperationUnsupportedToCalculate(OperationType operation) {
		return operation == ReadValue || operation == Cast || operation == Functional;
	}

	static bool IsOperationWithSingleOperand(OperationType operation) {
		return operation == ReadValue || operation == Cast || operation == Functional;
	}

	static bool IsOperationOverflow(OperationType opType) {
		return (opType == Add || opType == Mul || opType == Shl) && !IsOperationUnsupportedToCalculate(opType);
	}

	static bool IsOperationMoving(OperationType opType) {
		return !(opType == Div || opType == Shr || opType == Shl) && !IsOperationUnsupportedToCalculate(opType);
	}

	static bool IsOperationSigned(OperationType opType) {
		return (GetOperationGroup(opType) == OperationGroup::Arithmetic && opType != Mod) && !IsOperationUnsupportedToCalculate(opType);
	}

	static bool IsOperationManipulatedWithBitVector(OperationType opType) {
		return (opType == And || opType == Or || opType == Xor) && !IsOperationUnsupportedToCalculate(opType);
	}

	static std::string ShowOperation(OperationType opType) {
		switch (opType)
		{
		case Add: return "+";
		case Mul: return "*";
		case Div: return "/";
		case Mod: return "%";
		case And: return "&";
		case Or: return "|";
		case Xor: return "^";
		case Shr: return ">>";
		case Shl: return "<<";
		case ReadValue: return "&";
		}
		return "_";
	}

	class OperationalNode : public Node, public IParentNode, public INumber
	{
	public:
		Node* m_leftNode;
		Node* m_rightNode;
		OperationType m_operation;
		uint64_t m_mask;

		OperationalNode(Node* leftNode, Node* rightNode, OperationType operation, uint64_t mask = 0x0)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation), m_mask(mask)
		{
			leftNode->addParentNode(this);
			if (rightNode != nullptr) {
				rightNode->addParentNode(this);
			}
		}

		OperationalNode(Node* leftNode, Node* rightNode, OperationType operation, int size)
			: OperationalNode(leftNode, rightNode, operation, GetMaskBySize(size))
		{}

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
			if (!m_leftNode || !m_rightNode)
				return "";
			std::string result = "";
			if (m_operation == Xor) {
				if (static_cast<NumberLeaf*>(m_rightNode)->m_value == -1) {
					result = "~" + m_leftNode->printDebug();
				}
			}

			std::string opSize = "";
			if (true) {
				opSize = "."+ std::to_string(GetBitCountOfMask(getMask()) / 8) +"";
			}
			
			if(result.empty())
				result = "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + ""+ opSize +" " + m_rightNode->printDebug() + ")";
			return (m_updateDebugInfo = result);// + "<" + std::to_string((uint64_t)this % 100000) + ">";
		}
	};

	class InstructionOperationalNode : public OperationalNode
	{
	public:
		PCode::Instruction* m_instr;

		InstructionOperationalNode(Node* leftNode, Node* rightNode, OperationType operation, PCode::Instruction* instr)
			: OperationalNode(leftNode, rightNode, operation), m_instr(instr)
		{}

		uint64_t getMask() override {
			return m_instr->m_output->getMask();
		}
	};

	class ReadValueNode : public OperationalNode
	{
	public:
		ReadValueNode(Node* node, int size)
			: OperationalNode(node, new NumberLeaf(size), ReadValue), m_size(size)
		{}

		Node* getAddress() {
			return m_leftNode;
		}

		uint64_t getMask() override {
			return GetMaskBySize(getSize());
		}

		int getSize() {
			return m_size;
		}

		std::string printDebug() override {
			if (!m_leftNode || !m_rightNode)
				return "";
			return m_updateDebugInfo = ("*(uint_" + std::to_string(8 * getSize()) + "t*)" + m_leftNode->printDebug());
		}
	private:
		int m_size;
	};

	//for movsx, imul, idiv, ...
	class CastNode : public OperationalNode
	{
	public:
		CastNode(Node* node, int size, bool isSigned)
			: OperationalNode(node, new NumberLeaf(size), Cast), m_size(size), m_isSigned(isSigned)
		{}

		uint64_t getMask() override {
			return GetMaskBySize(getSize());
		}

		int getSize() {
			return m_size;
		}

		std::string printDebug() override {
			if (!m_leftNode || !m_rightNode)
				return "";
			return m_updateDebugInfo = ("("+ std::string(!m_isSigned ? "u" : "") +"int_" + std::to_string(8 * getSize()) + "t)" + m_leftNode->printDebug());
		}
	private:
		int m_size;
		bool m_isSigned;
	};

	class FunctionalNode : public OperationalNode
	{
	public:
		enum class Id {
			CARRY,
			SCARRY,
			SBORROW
		};
		Id m_funcId;

		FunctionalNode(Node* node1, Node* node2, Id id)
			: OperationalNode(node1, node2, Functional), m_funcId(id)
		{}

		uint64_t getMask() override {
			return 0b1;
		}

		std::string printDebug() override {
			if (!m_leftNode || !m_rightNode)
				return "";
			return m_updateDebugInfo = (std::string(magic_enum::enum_name(m_funcId)) + "(" + m_leftNode->printDebug() + ", " + m_rightNode->printDebug() + ")");
		}
	};
};