#pragma once
#include "../ExprTree/ExprTreeCondition.h"
#include "../ExprTree/ExprTreeFuncCallContext.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

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

	static std::list<OperationalNode*> GetNextOperationalsNodesToOpimize(Node* node) {
		if (auto operationalNode = dynamic_cast<OperationalNode*>(node)) {
			return { operationalNode };
		}

		if (auto conditionNode = dynamic_cast<Condition*>(node)) {
			auto list1 = GetNextOperationalsNodesToOpimize(conditionNode->m_leftNode);
			auto list2 = GetNextOperationalsNodesToOpimize(conditionNode->m_rightNode);
			list1.insert(list1.end(), list2.begin(), list2.end());
			return list1;
		}

		if (auto compCondition = dynamic_cast<CompositeCondition*>(node)) {
			auto list1 = GetNextOperationalsNodesToOpimize(compCondition->m_leftCond);
			auto list2 = GetNextOperationalsNodesToOpimize(compCondition->m_rightCond);
			list1.insert(list1.end(), list2.begin(), list2.end());
			return list1;
		}

		if (auto ternaryOperationalNode = dynamic_cast<TernaryOperationalNode*>(node)) {
			auto list1 = GetNextOperationalsNodesToOpimize(ternaryOperationalNode->m_condition);
			auto list2 = GetNextOperationalsNodesToOpimize(ternaryOperationalNode->m_leftNode);
			auto list3 = GetNextOperationalsNodesToOpimize(ternaryOperationalNode->m_rightNode);
			list1.insert(list1.end(), list2.begin(), list2.end());
			list1.insert(list1.end(), list3.begin(), list3.end());
			return list1;
		}

		if (auto functionCallCtx = dynamic_cast<FunctionCallContext*>(node)) {
			auto resultList = GetNextOperationalsNodesToOpimize(functionCallCtx->m_destination);
			for (const auto& it : functionCallCtx->m_registerParams) {
				auto list = GetNextOperationalsNodesToOpimize(it.second);
				resultList.insert(resultList.end(), list.begin(), list.end());
			}
			return resultList;
		}

		return {};
	}

	static std::list<OperationalNode*> GetNextOperationalsNodesToOpimize(OperationalNode* expr) {
		auto list1 = GetNextOperationalsNodesToOpimize(expr->m_leftNode);
		if (!IsOperationWithSingleOperand(expr->m_operation)) {
			auto list2 = GetNextOperationalsNodesToOpimize(expr->m_rightNode);
			list1.insert(list1.end(), list2.begin(), list2.end());
		}
		return list1;
	}


	
	static void OptimizeCondition_SBORROW(Condition* condition, ICondition*& newCond) {
		newCond = condition;
		//replace SBORROW condition with normal
		//SBORROW(*(uint_32t*)([reg_rsp_64]), 0x4{4}) == ((*(uint_32t*)([reg_rsp_64]) + 0x3fffffffc{-4}) < 0x0{0}))
		if (auto func = dynamic_cast<FunctionalNode*>(condition->m_leftNode)) {
			if (func->m_funcId == FunctionalNode::Id::SBORROW && (condition->m_cond == Condition::Eq || condition->m_cond == Condition::Ne)) {
				if (auto mainCond = dynamic_cast<Condition*>(condition->m_rightNode)) {
					if (mainCond->m_cond == Condition::Lt) {
						auto newCondType = Condition::Ge;
						if(condition->m_cond == Condition::Ne)
							newCondType = Condition::Lt;
						newCond = new Condition(func->m_leftNode, func->m_rightNode, newCondType);
						condition->replaceWith(newCond);
						delete condition;
					}
				}
			}
		}
	}

	//check negative of expr node
	static bool IsNegative(Node* node, uint64_t mask) {
		if (auto numberLeaf = dynamic_cast<NumberLeaf*>(node)) {
			if ((numberLeaf->m_value >> (GetBitCountOfMask(mask) * 0x8 - 1)) & 0b1)
				return true;
		}
		else if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Mul)
				return IsNegative(opNode->m_rightNode, mask);
		}
		return false;
	}

	//rax + -0x2 < 0		=>		rax < -0x2 * -1
	static void OptimizeCondition_Add(Condition* condition, ICondition*& newCond) {
		newCond = condition;
		auto curExpr = condition->m_leftNode;
		while (curExpr) {
			bool next = false;
			if (auto curAddExpr = dynamic_cast<OperationalNode*>(curExpr)) {
				auto mask = curAddExpr->getMask();
				if (curAddExpr->m_operation == Add) {
					if (dynamic_cast<NumberLeaf*>(curAddExpr->m_rightNode) || IsNegative(curAddExpr->m_rightNode, mask)) {
						//move expr from left node of the condition to the right node being multiplied -1
						auto newPartOfRightExpr = new OperationalNode(curAddExpr->m_rightNode, new NumberLeaf(uint64_t(-1) & GetMask64ByMask(mask)), Mul, mask);
						auto newRightExpr = new OperationalNode(condition->m_rightNode, newPartOfRightExpr, Add);
						newCond = new Condition(curAddExpr->m_leftNode, newRightExpr, condition->m_cond);
						condition->replaceWith(newCond);
						delete condition;
						curExpr = condition->m_leftNode;
						next = true;
					}
				}
			}
			if (!next)
				break;
		}
	}

	//x > 2 && x == 3		=>		x == 3 && x > 2
	static void MakeOrderInCompositeCondition(CompositeCondition* compCond) {
		if (!compCond->m_rightCond)
			return;
		
		bool isSwap = false;
		if (auto cond1 = dynamic_cast<Condition*>(compCond->m_leftCond)) {
			if (auto cond2 = dynamic_cast<Condition*>(compCond->m_rightCond)) {
				if (cond1->m_cond > cond2->m_cond) { //sorting condition
					isSwap = true;
				}
			} else {
				isSwap = true;
			}
		}

		if (isSwap) {
			std::swap(compCond->m_leftCond, compCond->m_rightCond);
		}

		for (auto it : { compCond->m_leftCond, compCond->m_rightCond }) {
			if (auto compCond = dynamic_cast<CompositeCondition*>(it)) {
				MakeOrderInCompositeCondition(compCond);
			}
		}
	}

	//(x < 2 || x == 2)		->		(x <= 2)
	static void OptimizeCompositeCondition(CompositeCondition* compCond, ICondition*& newCond) {
		newCond = compCond;
		if (auto leftSimpleCond = dynamic_cast<Condition*>(compCond->m_leftCond)) {
			if (auto rightSimpleCond = dynamic_cast<Condition*>(compCond->m_rightCond)) {
				if (leftSimpleCond->m_leftNode->getHash() == rightSimpleCond->m_leftNode->getHash() && leftSimpleCond->m_rightNode->getHash() == rightSimpleCond->m_rightNode->getHash()) {
					auto newCondType = Condition::None;
					if (compCond->m_cond == CompositeCondition::Or) {
						if (leftSimpleCond->m_cond == Condition::Eq) {
							if (rightSimpleCond->m_cond == Condition::Gt) {
								newCondType = Condition::Ge;
							}
							else if (rightSimpleCond->m_cond == Condition::Lt) {
								newCondType = Condition::Le;
							}
						}
					}
					else if (compCond->m_cond == CompositeCondition::And) {
						if (leftSimpleCond->m_cond == Condition::Ne) {
							if (rightSimpleCond->m_cond == Condition::Ge) {
								newCondType = Condition::Gt;
							}
							else if (rightSimpleCond->m_cond == Condition::Le) {
								newCondType = Condition::Lt;
							}
						}
					}

					if (newCondType != Condition::None) {
						auto newSimpleCond = new Condition(leftSimpleCond->m_leftNode, leftSimpleCond->m_rightNode, newCondType);
						compCond->replaceWith(newSimpleCond);
						delete compCond;
						newCond = newSimpleCond;
					}
				}
			}
		}
	}

	//!(x == 2)		->		(x != 2)
	static void InverseConditions(CompositeCondition* compCond, ICondition*& newCond) {
		newCond = compCond;
		if (compCond->m_cond == CompositeCondition::Not) {
			auto condClone = compCond->m_leftCond->clone();
			condClone->inverse();
			compCond->replaceWith(condClone);
			delete compCond;
			newCond = condClone;
		}
		else if(compCond->m_cond == CompositeCondition::None) {
			compCond->replaceWith(compCond->m_leftCond);
			delete compCond;
			newCond = compCond->m_leftCond;
		}
	}

	//[var_2_32] * 0				=>		0
	//[var_2_32] ^ [var_2_32]		=>		0
	//[var_2_32] + 0				=>		[var_2_32]
	//[var_2_32] * 1				=>		[var_2_32]
	static void OptimizeZeroInExpr(OperationalNode*& expr) {	
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeZeroInExpr(it);
		}

		if (IsOperationUnsupportedToCalculate(expr->m_operation))
			return;

		if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
			if (expr->m_operation != Div && expr->m_operation != Mod) {
				if (rightNumberLeaf->m_value == 0) {
					if (expr->m_operation == Mul || expr->m_operation == And) {
						expr->replaceWith(new NumberLeaf(0));
						delete expr;
						expr = nullptr;
					}
					else {
						auto newExpr = expr->m_leftNode;
						expr->replaceWith(expr->m_leftNode);
						delete expr;
						expr = dynamic_cast<OperationalNode*>(newExpr);
					}
				}
			}
			else {
				if (rightNumberLeaf->m_value == 1) {
					auto newExpr = expr->m_leftNode;
					expr->replaceWith(newExpr);
					delete expr;
					expr = dynamic_cast<OperationalNode*>(newExpr);
				}
			}
		}
	}


	//5 + 2		=>		7
	static void OptimizeConstExpr(OperationalNode*& expr) {
		Node::UpdateDebugInfo(expr);
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeConstExpr(it);
		}

		if (IsOperationUnsupportedToCalculate(expr->m_operation))
			return;

		//[sym1] & [sym1]	=>	 [sym1]
		if (expr->m_leftNode == expr->m_rightNode) {
			if (expr->m_operation == Xor) {
				expr->replaceWith(new NumberLeaf(0));
				delete expr;
				expr = nullptr;
				return;
			} else if (expr->m_operation == And || expr->m_operation == Or) {
				auto newExpr = expr->m_leftNode;
				expr->replaceWith(newExpr);
				delete expr;
				expr = dynamic_cast<OperationalNode*>(newExpr);
				return;
			}
		}
		
		if (auto leftNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_leftNode)) {
			if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				auto result = Calculate(leftNumberLeaf->m_value, rightNumberLeaf->m_value, expr->m_operation);
				if (expr->getMask())
					result &= GetMask64ByMask(expr->getMask());
				expr->replaceWith(new NumberLeaf(result));
				delete expr;
				expr = nullptr;
				return;
			}
		}

		//a << 0x2{2}		=>		a * 4
		if (expr->m_operation == Shl) {
			if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				auto value = numberLeaf->m_value;
				if (value >= 1 && value <= 3) {
					expr->m_operation = Mul;
					numberLeaf->m_value = (uint64_t)1 << value;
				}
			}
		}
	}

	//a
	//a * 5
	static bool IsLeaf(Node* node) {
		if (node->isLeaf())
			return true;
		if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Mul) {
				if (dynamic_cast<NumberLeaf*>(opNode->m_rightNode) && IsLeaf(opNode->m_leftNode))
					return true;
			}
		}
		return false;
	}


	static bool IsSwap(Node* node1, Node* node2) {
		return dynamic_cast<NumberLeaf*>(node1) && !dynamic_cast<NumberLeaf*>(node2) || IsLeaf(node1) && !IsLeaf(node2);
	}


	//(0x2 + a)		=>		(a + 0x2)	
	static void ChangeLeafPlaceInMovingOperations(OperationalNode*& expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			ChangeLeafPlaceInMovingOperations(it);
		}
		if (IsOperationMoving(expr->m_operation)) {
			if (IsSwap(expr->m_leftNode, expr->m_rightNode)) {
				auto tempNode = expr->m_rightNode;
				expr->m_rightNode = expr->m_leftNode;
				expr->m_leftNode = tempNode;
			}
		}
	}


	//(3x + x)	=>	4x
	static OperationalNode* AddEqualNodes(Node* node1, Node* node2) {
		auto coreNode1 = node1;
		auto coreNode2 = node2;
		uint64_t k1 = 1;
		uint64_t k2 = 1;

		for (auto& it : { std::make_pair(&k1, &coreNode1), std::make_pair(&k2, &coreNode2) }) {
			if (auto opNode = dynamic_cast<OperationalNode*>(*it.second)) {
				if (auto numberLeaf = dynamic_cast<NumberLeaf*>(opNode->m_rightNode)) {
					if (opNode->m_operation == Mul) {
						*it.first = numberLeaf->m_value;
						*it.second = opNode->m_leftNode;
						continue;
					}
				}
			}
		}

		if (coreNode1 != coreNode2)
			return nullptr;
		return new OperationalNode(coreNode1, new NumberLeaf(k1 + k2), Mul);
	}


	//(3x + x) + 5	=>	4x + 5
	static void CalculateAddEqualNodes(OperationalNode*& expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			CalculateAddEqualNodes(it);
		}

		if (expr->m_operation == Add) {
			auto resultExpr = AddEqualNodes(expr->m_leftNode, expr->m_rightNode);
			if (resultExpr != nullptr) {
				expr->replaceWith(resultExpr);
				delete expr;
				expr = resultExpr;
			}
		}
	}


	//((rsp + 0x20) + (rax * 5)) + 0x10				=>		(rsp + 0x30) + (rax * 5)
	//((((rsp & 0xF) + 0x9) + 0x2) + (-0x8))		=>		((rsp & 0xF) + 0x3)
	static int MakeLeafPlaceDeeperAndCalculate(OperationalNode* expr, OperationalNode* prevExpr = nullptr) {
		Node::UpdateDebugInfo(expr);
		Node::UpdateDebugInfo(prevExpr);
		bool isSameOperation = true;
		int isPrevExprRemoved = 0;

		if (prevExpr != nullptr) {
			auto prevOperation = prevExpr->m_operation;
			if (prevOperation != expr->m_operation) {
				isSameOperation = false;
			}
		}

		if (isSameOperation && prevExpr) {
			if (IsOperationMoving(expr->m_operation)) {
				if (IsSwap(prevExpr->m_rightNode, expr->m_rightNode)) {
					OperationalNode* newExpr;
					OperationalNode* newPrevExpr;
					//we should check what type of instruction this node belongs to because of keeping suit
					if (auto instrExpr = dynamic_cast<InstructionOperationalNode*>(expr)) {
						newExpr = new InstructionOperationalNode(expr->m_leftNode, prevExpr->m_rightNode, expr->m_operation, instrExpr->m_instr);
					}
					else {
						newExpr = new OperationalNode(expr->m_leftNode, prevExpr->m_rightNode, expr->m_operation);
					}
					if (auto instrExpr = dynamic_cast<InstructionOperationalNode*>(prevExpr)) {
						newPrevExpr = new InstructionOperationalNode(newExpr, expr->m_rightNode, expr->m_operation, instrExpr->m_instr);
					}
					else {
						newPrevExpr = new OperationalNode(newExpr, expr->m_rightNode, expr->m_operation);
					}

					prevExpr->replaceWith(newPrevExpr);
					delete prevExpr;
					isPrevExprRemoved = 2;
					expr = newExpr;
					prevExpr = newPrevExpr;
					Node::UpdateDebugInfo(expr);
					Node::UpdateDebugInfo(prevExpr);
				}
			}

			if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				if (auto prevNumberLeaf = dynamic_cast<NumberLeaf*>(prevExpr->m_rightNode)) {
					auto result = numberLeaf->m_value;
					switch (expr->m_operation)
					{
					case Shr:
					case Shl:
						result += prevNumberLeaf->m_value;
						break;
					case Div:
						result *= prevNumberLeaf->m_value;
						break;
					default:
						result = Calculate(result, prevNumberLeaf->m_value, expr->m_operation);
					}

					auto mask = expr->getMask() | prevExpr->getMask();
					if (mask)
						result &= GetMask64ByMask(mask);

					auto numberLeaf = new NumberLeaf(result);
					if (auto instrExpr = dynamic_cast<InstructionOperationalNode*>(expr)) {
						expr = new InstructionOperationalNode(expr->m_leftNode, numberLeaf, expr->m_operation, instrExpr->m_instr);
					}
					else {
						expr = new OperationalNode(expr->m_leftNode, numberLeaf, expr->m_operation);
					}
					prevExpr->replaceWith(expr);
					delete prevExpr;
					isPrevExprRemoved = 2;
				}
			}
			else {
				//((y + 3x) + x)	=>	(y + 4x)
				if (expr->m_operation == Add) {
					auto resultExpr = AddEqualNodes(expr, prevExpr);
					if (resultExpr != nullptr) {
						if (auto instrExpr = dynamic_cast<InstructionOperationalNode*>(expr)) {
							expr = new InstructionOperationalNode(expr->m_leftNode, resultExpr, Add, instrExpr->m_instr);
						}
						else {
							expr = new OperationalNode(expr->m_leftNode, resultExpr, Add);
						}
						prevExpr->replaceWith(expr);
						delete prevExpr;
						isPrevExprRemoved = 2;
					}
				}
			}
		}

		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			if (MakeLeafPlaceDeeperAndCalculate(it, expr) >= 1)
				return 1;
		}

		return isPrevExprRemoved;
	}

	//([reg_rbx_64] & 0xffffffff00000000{0} | [var_2_32]) & 0x1f{31}	=>		[var_2_32] & 0x1f{31}
	static void RemoveZeroMaskMulExpr(OperationalNode*& expr, Mask mask) {
		if (!IsOperationManipulatedWithBitVector(expr->m_operation))
			return;

		for (auto& it : {
			std::make_pair(&expr->m_leftNode, expr->m_rightNode),
			std::make_pair(&expr->m_rightNode, expr->m_leftNode) })
		{
			if (auto operand = dynamic_cast<INumber*>(*it.first)) {
				if ((operand->getMask() & mask) == 0x0) {
					//�����, ��� �� ����������� ������� ������� ����������� - ���������� ��� ������ �������
					/*if (auto expr = dynamic_cast<ExprTree::OperationalNode*>(it.second)) {
						RemoveZeroMaskMulExpr(expr, mask);
						if (!expr)
							return;
					}*/

					expr->replaceWith(it.second);
					*it.first = nullptr;
					delete expr;
					expr = nullptr;
					return;
				}
			}
		}

		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			RemoveZeroMaskMulExpr(it, mask);
		}
	}


	static void CalculateMasksAndOptimize(OperationalNode*& expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			CalculateMasksAndOptimize(it);
		}

		if (IsOperationWithSingleOperand(expr->m_operation))
			return;

		if (auto leftNode = dynamic_cast<INumber*>(expr->m_leftNode)) {
			if (auto rightNode = dynamic_cast<INumber*>(expr->m_rightNode)) {
				if (expr->m_operation == And) {
					auto mask1 = leftNode->getMask();
					auto mask2 = rightNode->getMask();
					expr->setMask(mask1 & mask2);

					if (expr->getMask() == 0x0) {
						//[var_2_32] & 0xffffffff00000000{0}		=>		0x0
						expr->replaceWith(new NumberLeaf(0));
						delete expr;
						expr = nullptr;
						return;
					}

					if (mask1 <= 0xFF) {
						if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
							auto mask1_64 = GetMask64ByMask(mask1);
							if ((mask1_64 & numberLeaf->m_value) == mask1_64) {
								//[var_2_32] & 0xffffffff{-1}		=>		 [var_2_32]		
								auto newExpr = expr->m_leftNode;
								expr->replaceWith(newExpr);
								expr->m_leftNode = nullptr;
								delete expr;
								expr = dynamic_cast<OperationalNode*>(newExpr);
							}
							else {
								if (auto leftExpr = dynamic_cast<OperationalNode*>(expr->m_leftNode)) {
									RemoveZeroMaskMulExpr(leftExpr, mask2);
								}
							}
						}
					}
				}
				else if (expr->m_operation == Shl || expr->m_operation == Shr) {
					if (expr->m_operation == Shl) {
						if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
							expr->setMask(leftNode->getMask() << (numberLeaf->m_value / 0x8 + (numberLeaf->m_value % 0x8 == 0 ? 0 : 1)));
							return;
						}
					}
					expr->setMask(leftNode->getMask());
				}
				else {
					expr->setMask(leftNode->getMask() | rightNode->getMask());
				}
			}
		}
	}

	//get list of terms in expr: (5x - 10y) * 2 + 5		=>		x: 10, y: -20, constTerm: 5
	//need mostly for array linear expr
	static void GetTermsInExpr(Node* node, std::map<ObjectHash::Hash, int64_t>& terms, int64_t& constTerm, int64_t k = 1) {
		if (auto numberLeaf = dynamic_cast<NumberLeaf*>(node)) {
			constTerm += (int64_t&)numberLeaf->m_value * k;
			return;
		}

		if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Add) {
				GetTermsInExpr(opNode->m_leftNode, terms, constTerm, k);
				GetTermsInExpr(opNode->m_rightNode, terms, constTerm, k);
				return;
			} else if (opNode->m_operation == Mul) {
				if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(opNode->m_rightNode)) {
					GetTermsInExpr(opNode->m_leftNode, terms, constTerm, k * rightNumberLeaf->m_value);
					return;
				}
			}
		}

		auto hash = node->getHash();
		if (terms.find(hash) == terms.end()) {
			terms[hash] = 0;
		}
		terms[hash] += k;
	}

	static bool AreTermsEqual(std::map<ObjectHash::Hash, int64_t>& terms1, std::map<ObjectHash::Hash, int64_t>& terms2) {
		for (auto termList : { std::pair(&terms1, &terms2), std::pair(&terms2, &terms1) }) {
			for (auto term : *termList.first) {
				if (term.second == 0)
					continue;
				auto it = termList.second->find(term.first);
				if (it == termList.second->end() || term.second != it->second)
					return false;
			}
		}
		return true;
	}

	//TODO: ������� ��������� �������� � ��������� ���-�� ���������������� ���������. ��������� ����������� ���������� � ���� ������� ��� ��������������. �������������� ���� ������ ����� �����������. ���������� �� � �����.
	static void Optimize(Node* node) {
		auto list = GetNextOperationalsNodesToOpimize(node);
		std::set<OperationalNode*> exprs;
		for (auto it : list)
			exprs.insert(it);

		for(auto expr : exprs) {
			Node::UpdateDebugInfo(expr);
			OptimizeConstExpr(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
			ChangeLeafPlaceInMovingOperations(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
			if (MakeLeafPlaceDeeperAndCalculate(expr) == 1)
				continue;
			Node::UpdateDebugInfo(expr);
			OptimizeZeroInExpr(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
			CalculateAddEqualNodes(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
			CalculateMasksAndOptimize(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
			OptimizeZeroInExpr(expr);
			if (!expr) continue;
			Node::UpdateDebugInfo(expr);
		}
	}

	static void OptimizeCondition(ICondition*& cond) {
		if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
			OptimizeCondition(compCond->m_leftCond);
			OptimizeCondition(compCond->m_rightCond);

			Node::UpdateDebugInfo(compCond);
			InverseConditions(compCond, cond);
			if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
				Node::UpdateDebugInfo(compCond);
				MakeOrderInCompositeCondition(compCond);
				Node::UpdateDebugInfo(compCond);
				OptimizeCompositeCondition(compCond, cond);
				Node::UpdateDebugInfo(cond);
				int a = 5;
			}
		}
		else if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
			Node::UpdateDebugInfo(simpleCond);
			OptimizeCondition_SBORROW(simpleCond, cond);
			if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
				Node::UpdateDebugInfo(simpleCond);
				OptimizeCondition_Add(simpleCond, cond);
				if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
					Node::UpdateDebugInfo(simpleCond);
					Optimize(simpleCond);
					Node::UpdateDebugInfo(simpleCond);
					int a = 5;
				}
			}
		}
	}
};