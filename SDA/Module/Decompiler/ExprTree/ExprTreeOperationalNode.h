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

		//Floating Point
		fAdd,
		fMul,
		fDiv,
		fFunctional,

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
		return operation == ReadValue || operation == Cast || operation == Functional || operation == fFunctional;
	}

	static bool IsOperationFloatingPoint(OperationType operation) {
		return operation >= fAdd && operation <= fFunctional;
	}

	static bool IsOperationWithSingleOperand(OperationType operation) {
		return operation == ReadValue || operation == Cast || operation == fFunctional;
	}

	static bool IsOperationOverflow(OperationType opType) {
		return (opType == Add || opType == Mul || opType == Shl) && !IsOperationUnsupportedToCalculate(opType);
	}

	static bool IsOperationMoving(OperationType opType) {
		return !(opType == fDiv || opType == Div || opType == Shr || opType == Shl) && !IsOperationUnsupportedToCalculate(opType);
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
		case fAdd: return "+";
		case fMul: return "*";
		case fDiv: return "/";
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

	class OperationalNode : public Node, public INodeAgregator, public INumber, public IFloatingPoint
	{
		BitMask64 m_mask;
	public:
		Node* m_leftNode;
		Node* m_rightNode;
		OperationType m_operation;
		bool m_notChangedMask;
		ObjectHash::Hash m_calcHash;

		OperationalNode(Node* leftNode, Node* rightNode, OperationType operation, BitMask64 mask = BitMask64(0), bool notChangedMask = false)
			: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation), m_mask(mask), m_notChangedMask(notChangedMask)
		{
			leftNode->addParentNode(this);
			if (rightNode != nullptr) {
				rightNode->addParentNode(this);
			}
			else {
				if (!IsOperationWithSingleOperand(operation))
					throw std::logic_error("The second operand is empty in the binary operation.");
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

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { &m_leftNode, &m_rightNode };
		}

		void setMask(BitMask64 mask) {
			if (m_notChangedMask)
				return;
			m_mask = mask;
		}

		BitMask64 getMask() override {
			return m_mask;
		}

		bool IsFloatingPoint() override {
			return IsOperationFloatingPoint(m_operation);
		}

		Node* clone() override {
			return new OperationalNode(m_leftNode->clone(), m_rightNode ? m_rightNode->clone() : nullptr, m_operation, m_mask, m_notChangedMask);
		}

		ObjectHash::Hash getHash() override {
			return m_calcHash;
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
				opSize = "."+ std::to_string(getMask().getSize());
				if (IsFloatingPoint()) {
					opSize += "f";
				}
			}
			
			if(result.empty())
				result = "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + ""+ opSize +" " + m_rightNode->printDebug() + ")";
			return (m_updateDebugInfo = result);
		}
	};

	class InstructionOperationalNode : public OperationalNode
	{
	public:
		PCode::Instruction* m_instr;

		InstructionOperationalNode(Node* leftNode, Node* rightNode, OperationType operation, PCode::Instruction* instr)
			: OperationalNode(leftNode, rightNode, operation, 0, true), m_instr(instr)
		{}

		BitMask64 getMask() override {
			return m_instr->m_output->getMask().getBitMask64().withoutOffset();
		}

		Node* clone() override {
			return new InstructionOperationalNode(m_leftNode->clone(), m_rightNode ? m_rightNode->clone() : nullptr, m_operation, m_instr);
		}
	};

	class ReadValueNode : public OperationalNode
	{
	public:
		ReadValueNode(Node* node, int size)
			: OperationalNode(node, nullptr, ReadValue), m_size(size)
		{}

		Node* getAddress() {
			return m_leftNode;
		}

		BitMask64 getMask() override {
			return BitMask64(getSize());
		}

		int getSize() {
			return m_size;
		}

		Node* clone() override {
			return new ReadValueNode(m_leftNode->clone(), m_size);
		}

		std::string printDebug() override {
			if (!m_leftNode)
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
			: OperationalNode(node, nullptr, Cast), m_size(size), m_isSigned(isSigned)
		{}

		BitMask64 getMask() override {
			return BitMask64(getSize());
		}

		int getSize() {
			return m_size;
		}

		Node* clone() override {
			return new CastNode(m_leftNode->clone(), m_size, m_isSigned);
		}

		std::string printDebug() override {
			if (!m_leftNode)
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
			: OperationalNode(node1, node2, Functional, 0b1, true), m_funcId(id)
		{}

		BitMask64 getMask() override {
			return BitMask64(1);
		}

		Node* clone() override {
			return new FunctionalNode(m_leftNode->clone(), m_rightNode->clone(), m_funcId);
		}

		std::string printDebug() override {
			if (!m_leftNode || !m_rightNode)
				return "";
			return m_updateDebugInfo = (std::string(magic_enum::enum_name(m_funcId)) + "(" + m_leftNode->printDebug() + ", " + m_rightNode->printDebug() + ")");
		}
	};

	class FloatFunctionalNode : public OperationalNode
	{
	public:
		enum class Id {
			FABS,
			FSQRT,
			TRUNC,
			CEIL,
			FLOOR,
			ROUND,
			TOFLOAT,
			TOINT //todo: what is size of the result?
		};
		Id m_funcId;

		FloatFunctionalNode(Node* node1, Id id, int size)
			: OperationalNode(node1, nullptr, fFunctional, BitMask64(size), true), m_funcId(id), m_size(size)
		{}

		int getSize() {
			return m_size;
		}

		BitMask64 getMask() override {
			return BitMask64(m_size);
		}

		bool IsFloatingPoint() override {
			return m_funcId != Id::TOINT;
		}

		Node* clone() override {
			return new FloatFunctionalNode(m_leftNode->clone(), m_funcId, m_size);
		}

		std::string printDebug() override {
			if (!m_leftNode)
				return "";
			return m_updateDebugInfo = (std::string(magic_enum::enum_name(m_funcId)) + "(" + m_leftNode->printDebug() + ")");
		}

	private:
		int m_size;
	};
};