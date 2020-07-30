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

	static void OptimizeConstCondition(ICondition* cond) {
		Node::UpdateDebugInfo(cond);
		ICondition* newCond = nullptr;
		if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
			//[mem_16_32] == NaN		->		false
			if (auto floatNanLeaf = dynamic_cast<FloatNanLeaf*>(simpleCond->m_rightNode)) {
				newCond = new BooleanValue(simpleCond->m_cond == Condition::Ne);
				cond->replaceWith(newCond);
				delete cond;
			}

			if (auto subCond = dynamic_cast<ICondition*>(simpleCond->m_leftNode)) {
				OptimizeConstCondition(subCond);
				if (auto subCond = dynamic_cast<ICondition*>(simpleCond->m_leftNode)) {
					if (auto numberLeaf = dynamic_cast<NumberLeaf*>(simpleCond->m_rightNode)) {
						if (numberLeaf->m_value == 0x0 && (simpleCond->m_cond == Condition::Eq || simpleCond->m_cond == Condition::Ne)) {
							newCond = subCond;
							if (simpleCond->m_cond == Condition::Eq)
								newCond->inverse();
							cond->replaceWith(newCond);
							delete cond;
						}
					}
				}
			}
		}
		else if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
			OptimizeConstCondition(compCond->m_leftCond);
			Node::UpdateDebugInfo(compCond->m_leftCond);

			if (compCond->m_cond == CompositeCondition::Not || compCond->m_cond == CompositeCondition::None) {
				//!false		->		true
				if (auto booleanVal = dynamic_cast<BooleanValue*>(compCond->m_leftCond)) {
					newCond = new BooleanValue(compCond->m_cond == CompositeCondition::None ? booleanVal->m_value : !booleanVal->m_value);
					cond->replaceWith(newCond);
					delete cond;
				}
			}
			else {
				OptimizeConstCondition(compCond->m_rightCond);
				Node::UpdateDebugInfo(compCond->m_rightCond);

				ICondition* conds[2] = { compCond->m_leftCond, compCond->m_rightCond };
				bool val[2] = { false, false };
				bool val_calc[2] = { false, false };
				for (int idx = 0; idx < 2; idx++) {
					if (auto booleanVal = dynamic_cast<BooleanValue*>(conds[idx])) {
						val[idx] = booleanVal->m_value;
						val_calc[idx] = true;
					}
				}

				if (val_calc[0] || val_calc[1]) {
					//true && false		->		false
					if (val_calc[0] && val_calc[1]) {
						bool result = (compCond->m_cond == CompositeCondition::Or ? (val[0] || val[1]) : (val[0] && val[1]));
						newCond = new BooleanValue(result);
					}
					else {
						//cond1	|| true		->		true
						//cond1 || false	->		cond1
						for (int idx = 0; idx < 2; idx++) {
							if (val_calc[idx]) {
								if (compCond->m_cond == CompositeCondition::Or) {
									if (val[idx]) {
										newCond = new BooleanValue(true);
									}
									else {
										newCond = conds[1 - idx];
									}
								}
								else {
									if (!val[idx]) {
										newCond = new BooleanValue(false);
									}
									else {
										newCond = conds[1 - idx];
									}
								}
								break;
							}
						}
					}

					cond->replaceWith(newCond);
					delete cond;
				}
			}
		}
	}
	
	static void OptimizeCondition_SBORROW(Condition* condition) {
		//replace SBORROW condition with normal
		//SBORROW(*(uint_32t*)([reg_rsp_64]), 0x4{4}) == ((*(uint_32t*)([reg_rsp_64]) + 0x3fffffffc{-4}) < 0x0{0}))
		if (auto func = dynamic_cast<FunctionalNode*>(condition->m_leftNode)) {
			if (func->m_funcId == FunctionalNode::Id::SBORROW && (condition->m_cond == Condition::Eq || condition->m_cond == Condition::Ne)) {
				if (auto mainCond = dynamic_cast<Condition*>(condition->m_rightNode)) {
					if (mainCond->m_cond == Condition::Lt) {
						auto newCondType = Condition::Ge;
						if(condition->m_cond == Condition::Ne)
							newCondType = Condition::Lt;
						auto newCond = new Condition(func->m_leftNode, func->m_rightNode, newCondType);
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
	static void OptimizeCondition_Add(Condition* condition) {
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
						auto newCond = new Condition(curAddExpr->m_leftNode, newRightExpr, condition->m_cond);
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
	static void OptimizeCompositeCondition(CompositeCondition* compCond) {
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
					}
				}
			}
		}
	}

	//!(x == 2)		->		(x != 2)
	static void InverseConditions(CompositeCondition* compCond) {
		if (compCond->m_cond == CompositeCondition::Not) {
			compCond->m_leftCond->inverse();
			compCond->replaceWith(compCond->m_leftCond);
			delete compCond;
		}
		else if(compCond->m_cond == CompositeCondition::None) {
			compCond->replaceWith(compCond->m_leftCond);
			delete compCond;
		}
	}

	static void IterateChildNodes(Node* node, std::function<void(Node*)> func) {
		if (auto agregator = dynamic_cast<INodeAgregator*>(node)) {
			auto list = agregator->getNodesList();
			for (auto it : list) {
				func(it);
			}
		}
	}

	//[var_2_32] * 0				=>		0
	//[var_2_32] ^ [var_2_32]		=>		0
	//[var_2_32] + 0				=>		[var_2_32]
	//[var_2_32] * 1				=>		[var_2_32]
	static void OptimizeZeroInExpr(Node* node) {
		IterateChildNodes(node, OptimizeZeroInExpr);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (IsOperationUnsupportedToCalculate(expr->m_operation))
				return;

			if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				if (expr->m_operation != Div && expr->m_operation != Mod) {
					if (rightNumberLeaf->m_value == 0) {
						if (expr->m_operation == Mul || expr->m_operation == And) {
							expr->replaceWith(new NumberLeaf((uint64_t)0));
							delete expr;
						}
						else {
							auto newExpr = expr->m_leftNode;
							expr->replaceWith(expr->m_leftNode);
							delete expr;
						}
					}
				}
				else {
					if (rightNumberLeaf->m_value == 1) {
						auto newExpr = expr->m_leftNode;
						expr->replaceWith(newExpr);
						delete expr;
					}
				}
			}
		}
	}

	//5 + 2		=>		7
	static void OptimizeConstExpr(Node* node) {
		IterateChildNodes(node, OptimizeConstExpr);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (IsOperationUnsupportedToCalculate(expr->m_operation))
				return;

			//[sym1] & [sym1]	=>	 [sym1]
			if (expr->m_operation == Xor || expr->m_operation == And || expr->m_operation == Or) {
				if (expr->m_leftNode->getHash() == expr->m_rightNode->getHash()) {
					if (expr->m_operation == Xor) {
						expr->replaceWith(new NumberLeaf((uint64_t)0));
						delete expr;
						return;
					}
					else {
						auto newExpr = expr->m_leftNode;
						expr->replaceWith(newExpr);
						delete expr;
						return;
					}
				}
			}

			if (auto leftNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_leftNode)) {
				if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
					auto result = Calculate(leftNumberLeaf->m_value, rightNumberLeaf->m_value, expr->m_operation);
					if (expr->getMask())
						result &= GetMask64ByMask(expr->getMask());
					expr->replaceWith(new NumberLeaf(result));
					delete expr;
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
	static void ChangeLeafPlaceInMovingOperations(Node* node) {
		IterateChildNodes(node, ChangeLeafPlaceInMovingOperations);
		
		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (IsOperationMoving(expr->m_operation)) {
				if (IsSwap(expr->m_leftNode, expr->m_rightNode)) {
					auto tempNode = expr->m_rightNode;
					expr->m_rightNode = expr->m_leftNode;
					expr->m_leftNode = tempNode;
				}
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
	static void CalculateAddEqualNodes(Node* node) {
		IterateChildNodes(node, CalculateAddEqualNodes);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (expr->m_operation == Add) {
				auto resultExpr = AddEqualNodes(expr->m_leftNode, expr->m_rightNode);
				if (resultExpr != nullptr) {
					expr->replaceWith(resultExpr);
					delete expr;
				}
			}
		}
	}


	//((rsp + 0x20) + (rax * 5)) + 0x10				=>		(rsp + 0x30) + (rax * 5)
	//((((rsp & 0xF) + 0x9) + 0x2) + (-0x8))		=>		((rsp & 0xF) + 0x3)
	static void MakeLeafPlaceDeeperAndCalculate(Node* node, OperationalNode* prevExpr) {
		Node::UpdateDebugInfo(node);
		Node::UpdateDebugInfo(prevExpr);
		bool isSameOperation = true;

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
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
						}
					}
				}
			}

			Node::UpdateDebugInfo(expr);
			if (expr->m_rightNode) {
				OperationalNode* prevExpr_ = nullptr;
				MakeLeafPlaceDeeperAndCalculate(expr->m_rightNode, prevExpr_);
			}
			MakeLeafPlaceDeeperAndCalculate(expr->m_leftNode, expr);
		}
		else {
			IterateChildNodes(node, [](Node* childNode) {
				OperationalNode* prevExpr_ = nullptr;
				MakeLeafPlaceDeeperAndCalculate(childNode, prevExpr_);
				});
		}
	}

	//([reg_rbx_64] & 0xffffffff00000000{0} | [var_2_32]) & 0x1f{31}	=>		[var_2_32] & 0x1f{31}
	static void RemoveZeroMaskMulExpr(OperationalNode* expr, Mask mask) {
		if (!IsOperationManipulatedWithBitVector(expr->m_operation))
			return;

		for (auto& it : {
			std::make_pair(&expr->m_leftNode, expr->m_rightNode),
			std::make_pair(&expr->m_rightNode, expr->m_leftNode) })
		{
			if (auto operand = dynamic_cast<INumber*>(*it.first)) {
				if ((operand->getMask() & mask) == 0x0) {
					//убрал, ибо не соблюдается главное условие оптимизации - заменяться все должно целиком. updated: теперь можно, ибо клонирование сделано
					/*if (auto expr = dynamic_cast<ExprTree::OperationalNode*>(it.second)) {
						RemoveZeroMaskMulExpr(expr, mask);
						if (!expr)
							return;
					}*/

					expr->replaceWith(it.second);
					*it.first = nullptr;
					delete expr;
					return;
				}
			}
		}

		IterateChildNodes(expr, [mask](Node* childNode) {
			if (auto opNode = dynamic_cast<OperationalNode*>(childNode)) {
				RemoveZeroMaskMulExpr(opNode, mask);
			}
			});
	}


	static void CalculateMasksAndOptimize(Node* node) {
		IterateChildNodes(node, CalculateMasksAndOptimize);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
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
							expr->replaceWith(new NumberLeaf((uint64_t)0));
							delete expr;
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
	}

	//get list of terms in expr: (5x - 10y) * 2 + 5		=>		x: 10, y: -20, constTerm: 5
	//need mostly for array linear expr
	using TermsDict = std::map<ObjectHash::Hash, std::pair<Node*, int64_t>>;
	static void GetTermsInExpr(Node* node, TermsDict& terms, int64_t& constTerm, int64_t k = 1) {
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
			terms[hash] = std::make_pair(node, 0);
		}
		terms[hash] = std::make_pair(node, terms[hash].second + k);
	}

	static Node* GetBaseAddrTerm(TermsDict& terms) {
		for (auto term : terms) {
			if (term.second.second != 1)
				continue;
			if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(term.second.first)) {
				if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbolLeaf->m_symbol)) {
					if (regSymbol->m_register.isPointer()) {
						return symbolLeaf;
					}
				}
			}
		}
		//opNodes...
		return nullptr;
	}

	static bool AreTermsEqual(TermsDict& terms1, TermsDict& terms2) {
		for (auto termList : { std::pair(&terms1, &terms2), std::pair(&terms2, &terms1) }) {
			for (auto term : *termList.first) {
				if (term.second.second == 0)
					continue;
				auto it = termList.second->find(term.first);
				if (it == termList.second->end() || term.second != it->second)
					return false;
			}
		}
		return true;
	}

	//TODO: сделать несколько проходов с возвратом кол-ва оптимизированных выражений. Некоторые оптимизации объединить в одну функцию для быстродействия. Сформулировать ясно каждый метод оптимизации. Объединить всё в класс.
	static void Optimize(Node*& node) {
		Node::UpdateDebugInfo(node);
		OptimizeConstExpr(node);
		Node::UpdateDebugInfo(node);
		ChangeLeafPlaceInMovingOperations(node);
		Node::UpdateDebugInfo(node);
		OperationalNode* prevExpr_ = nullptr;
		MakeLeafPlaceDeeperAndCalculate(node, prevExpr_);
		Node::UpdateDebugInfo(node);
		OptimizeZeroInExpr(node);
		Node::UpdateDebugInfo(node);
		CalculateAddEqualNodes(node);
		Node::UpdateDebugInfo(node);
		CalculateMasksAndOptimize(node);
		Node::UpdateDebugInfo(node);
		OptimizeZeroInExpr(node);
		Node::UpdateDebugInfo(node);
	}

	static void OptimizeCondition(ICondition*& cond) {
		if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
			OptimizeCondition(compCond->m_leftCond);
			OptimizeCondition(compCond->m_rightCond);

			Node::UpdateDebugInfo(compCond);
			InverseConditions(compCond);
			if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
				Node::UpdateDebugInfo(compCond);
				MakeOrderInCompositeCondition(compCond);
				Node::UpdateDebugInfo(compCond);
				OptimizeCompositeCondition(compCond);
				Node::UpdateDebugInfo(cond);
			}
		}
		else if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
			Node::UpdateDebugInfo(simpleCond);
			OptimizeCondition_SBORROW(simpleCond);
			if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
				Node::UpdateDebugInfo(simpleCond);
				OptimizeCondition_Add(simpleCond);
				if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
					Node::UpdateDebugInfo(simpleCond);
					Optimize((Node*&)simpleCond);
					Node::UpdateDebugInfo(simpleCond);
				}
			}
		}
	}
};