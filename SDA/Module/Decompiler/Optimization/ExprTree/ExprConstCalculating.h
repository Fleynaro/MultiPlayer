#pragma once
#include "ExprModification.h"

namespace CE::Decompiler::Optimization
{
	class ExprConstCalculating : public ExprModification
	{
	public:
		ExprConstCalculating(INode* node)
			: ExprModification(node)
		{}

		static uint64_t Calculate(uint64_t op1, uint64_t op2, OperationType operation, bool isSigned = false) {
			switch (operation)
			{
			case Add:
				return op1 + op2;
			case Mul:
				return op1 * op2;
			case Div:
				return op1 / op2;
			case Mod:
				return op1 % op2;
			case And:
				return op1 & op2;
			case Or:
				return op1 | op2;
			case Xor:
				return op1 ^ op2;
			case Shr:
				return op1 >> op2;
			case Shl:
				return op1 << op2;
			}
			return 0;
		}

		void start() override {
			dispatch(getNode());
		}
	private:
		void dispatch(INode* node) {
			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				if (IsOperationUnsupportedToCalculate(opNode->m_operation))
					return;
				if(!processZeroOpNode(opNode))
					if (!processConstTerms(opNode))
						if (!processEqualAnd(opNode))
							if (!processShl(opNode));
			}
		}

		//[var_2_32] * 0				=>		0
		//[var_2_32] ^ [var_2_32]		=>		0
		//[var_2_32] + 0				=>		[var_2_32]
		//[var_2_32] * 1				=>		[var_2_32]
		bool processZeroOpNode(OperationalNode* opNode) {
			if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(opNode->m_rightNode)) {
				if (opNode->m_operation != Div && opNode->m_operation != Mod) {
					if (rightNumberLeaf->getValue() == 0) {
						if (opNode->m_operation == Mul || opNode->m_operation == And) {
							replace(new NumberLeaf((uint64_t)0));
							return true;
						}
						else {
							auto newExpr = opNode->m_leftNode;
							replace(opNode->m_leftNode);
							return true;
						}
					}
					else {
						if (opNode->m_operation == Or) {
							if ((rightNumberLeaf->getValue() | opNode->getMask().getValue()) == rightNumberLeaf->getValue()) {
								replace(rightNumberLeaf);
								return true;
							}
						}
					}
				}
				else {
					if (rightNumberLeaf->getValue() == 1) {
						auto newExpr = opNode->m_leftNode;
						replace(newExpr);
						return true;
					}
				}
			}
			return false;
		}

		//5 + 2 => 7
		bool processConstTerms(OperationalNode* opNode) {
			if (auto leftNumberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_leftNode)) {
				if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_rightNode)) {
					auto result = Calculate(leftNumberLeaf->getValue(), rightNumberLeaf->getValue(), opNode->m_operation);
					if (opNode->getMask() != 0)
						result &= opNode->getMask().getValue();
					replace(new NumberLeaf(result));
					return true;
				}
			}
			return false;
		}

		//[sym1] & [sym1] => [sym1]
		bool processEqualAnd(OperationalNode* opNode) {
			if (opNode->m_operation == Xor || opNode->m_operation == And || opNode->m_operation == Or) {
				if (opNode->m_leftNode->getHash().getHashValue() == opNode->m_rightNode->getHash().getHashValue()) {
					if (opNode->m_operation == Xor) {
						replace(new NumberLeaf((uint64_t)0));
						return true;
					}
					else {
						auto newExpr = opNode->m_leftNode;
						replace(newExpr);
						return true;
					}
				}
			}
			return false;
		}

		//a << 0x2{2} => a * 4
		bool processShl(OperationalNode* opNode) {
			if (opNode->m_operation == Shl) {
				if (auto numberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_rightNode)) {
					auto value = numberLeaf->getValue();
					if (value >= 1 && value <= 3) {
						opNode->m_operation = Mul;
						numberLeaf->setValue((uint64_t)1 << value);
					}
				}
			}
		}
	};
};