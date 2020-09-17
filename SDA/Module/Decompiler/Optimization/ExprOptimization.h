#pragma once
#include "../ExprTree/ExprTree.h"

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

	//get list of terms in expr: (5x - 10y) * 2 + 5		=>		x: 10, y: -20, constTerm: 5
	//need mostly for array linear expr
	using TermsDict = std::map<ObjectHash::Hash, std::pair<INode*, int64_t>>;
	static void GetTermsInExpr(INode* node, TermsDict& terms, int64_t& constTerm, int64_t k = 1) {
		if (auto numberLeaf = dynamic_cast<INumberLeaf*>(node)) {
			constTerm += (int64_t)numberLeaf->getValue() * k;
			return;
		}

		if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Add) {
				GetTermsInExpr(opNode->m_leftNode, terms, constTerm, k);
				GetTermsInExpr(opNode->m_rightNode, terms, constTerm, k);
				return;
			}
			else if (opNode->m_operation == Mul) {
				if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_rightNode)) {
					GetTermsInExpr(opNode->m_leftNode, terms, constTerm, k * rightNumberLeaf->getValue());
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

	static INode* GetBaseAddrTerm(TermsDict& terms) {
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

	static void OptimizeConstCondition(AbstractCondition* cond) {
		INode::UpdateDebugInfo(cond);
		AbstractCondition* newCond = nullptr;
		if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
			//[mem_16_32] == NaN		->		false
			if (auto floatNanLeaf = dynamic_cast<FloatNanLeaf*>(simpleCond->m_rightNode)) {
				newCond = new BooleanValue(simpleCond->m_cond == Condition::Ne);
				cond->replaceWith(newCond);
				delete cond;
			}

			if (auto subCond = dynamic_cast<AbstractCondition*>(simpleCond->m_leftNode)) {
				OptimizeConstCondition(subCond);
				if (auto subCond = dynamic_cast<AbstractCondition*>(simpleCond->m_leftNode)) {
					if (auto numberLeaf = dynamic_cast<INumberLeaf*>(simpleCond->m_rightNode)) {
						if (numberLeaf->getValue() == 0x0 && (simpleCond->m_cond == Condition::Eq || simpleCond->m_cond == Condition::Ne)) {
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
			INode::UpdateDebugInfo(compCond->m_leftCond);

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
				INode::UpdateDebugInfo(compCond->m_rightCond);

				AbstractCondition* conds[2] = { compCond->m_leftCond, compCond->m_rightCond };
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
	static bool IsNegative(INode* node, BitMask64& mask) {
		if (auto numberLeaf = dynamic_cast<INumberLeaf*>(node)) {
			if ((numberLeaf->getValue() >> (mask.getBitsCount() - 1)) & 0b1)
				return true;
		}
		else if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Mul)
				return IsNegative(opNode->m_rightNode, mask);
		}
		return false;
	}

	//rax + -0x2 < 0		=>		rax < -0x2 * -1
	//if(((((([mem_2_32] *.4 0x4{4}) >>.4 0x2{2}) *.4 0xffffffff{-1}) +.4 [mem_3_32]) == 0x0{0}))			->			if(([mem_3_32] == ((([mem_2_32] *.4 0x4{4}) >>.4 0x2{2}) *.4 0x1{1})))
	static void OptimizeCondition_Add(Condition* condition) {
		auto curExpr = condition->m_leftNode;
		while (curExpr) {
			bool next = false;
			if (auto curAddExpr = dynamic_cast<OperationalNode*>(curExpr)) {
				auto mask = curAddExpr->getMask();
				if (curAddExpr->m_operation == Add) {
					auto leftNode = curAddExpr->m_leftNode;
					auto rightNode = curAddExpr->m_rightNode;
					bool isTermMoving = false;
					if (dynamic_cast<NumberLeaf*>(curAddExpr->m_rightNode) || IsNegative(curAddExpr->m_rightNode, mask)) {
						isTermMoving = true;
					}
					else if(IsNegative(curAddExpr->m_leftNode, mask)) {
						std::swap(leftNode, rightNode);
						isTermMoving = true;
					}

					if (isTermMoving) {
						//move expr from left node of the condition to the right node being multiplied -1
						auto newPartOfRightExpr = new OperationalNode(rightNode, new NumberLeaf(uint64_t(-1) & mask.getValue()), Mul, mask);
						auto newRightExpr = new OperationalNode(condition->m_rightNode, newPartOfRightExpr, Add);
						auto newCond = new Condition(leftNode, newRightExpr, condition->m_cond);
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

	static void IterateChildNodes(INode* node, std::function<void(INode*)> func) {
		if (auto agregator = dynamic_cast<INodeAgregator*>(node)) {
			auto list = agregator->getNodesList();
			for (auto node : list) {
				if (node) {
					func(node);
				}
			}
		}
	}

	static void CalculateHashes(INode* node) {
		IterateChildNodes(node, CalculateHashes);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			int64_t contentHash;
			if (expr->m_rightNode) {
				if (IsOperationMoving(expr->m_operation)) {
					contentHash = expr->m_leftNode->getHash() + expr->m_rightNode->getHash();
				}
				else {
					contentHash = expr->m_leftNode->getHash() + expr->m_rightNode->getHash() * 31;
				}
			}
			else {
				contentHash = expr->m_leftNode->getHash();
			}

			ObjectHash hash;
			hash.addValue(contentHash);
			if(auto funcNode = dynamic_cast<FunctionalNode*>(expr))
				hash.addValue((int)funcNode->m_funcId);
			else if (auto fFuncNode = dynamic_cast<FloatFunctionalNode*>(expr))
				hash.addValue((int)fFuncNode->m_funcId);
			else
				hash.addValue((int)expr->m_operation);
			expr->m_calcHash = hash.getHash();
		}
		else if (auto linearExpr = dynamic_cast<LinearExpr*>(node)) {
			ObjectHash::Hash sumHash = 0x0;
			for (auto term : linearExpr->getTerms()) {
				sumHash += term->getHash();
			}
			ObjectHash hash;
			hash.addValue(sumHash);
			hash.addValue((int)linearExpr->m_operation);
			linearExpr->m_calcHash = hash.getHash();
		}
	}

	static void RemoveMirrorNodesInExpr(INode* node) {
		IterateChildNodes(node, RemoveMirrorNodesInExpr);
		if (auto mirrorNode = dynamic_cast<MirrorNode*>(node)) {
			mirrorNode->replaceWith(mirrorNode->m_node);
			delete mirrorNode;
		}
	}

	//[sym1] & 0xFFFF	=>	 (uint16_t)[sym1]	
	static void CreateTruncateCasts(INode* node) {
		IterateChildNodes(node, CreateTruncateCasts);
		
		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (expr->m_operation == And) {
				if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(expr->m_rightNode)) {
					auto truncateSize = 0x0;
					if (rightNumberLeaf->getValue() == 0xFF)
						truncateSize = 0x1;
					else if (rightNumberLeaf->getValue() == 0xFFFF)
						truncateSize = 0x2;
					else if (rightNumberLeaf->getValue() == 0xFFFFFFFF)
						truncateSize = 0x4;
					if (truncateSize != 0x0) {
						expr->replaceWith(new CastNode(expr->m_leftNode, truncateSize, false));
						delete expr;
						return;
					}
				}
			}
		}
	}

	//[var_2_32] * 0				=>		0
	//[var_2_32] ^ [var_2_32]		=>		0
	//[var_2_32] + 0				=>		[var_2_32]
	//[var_2_32] * 1				=>		[var_2_32]
	static void OptimizeZeroInExpr(INode* node) {
		IterateChildNodes(node, OptimizeZeroInExpr);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (IsOperationUnsupportedToCalculate(expr->m_operation))
				return;

			if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				if (expr->m_operation != Div && expr->m_operation != Mod) {
					if (rightNumberLeaf->getValue() == 0) {
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
					else {
						if (expr->m_operation == Or) {
							if ((rightNumberLeaf->getValue() | expr->getMask().getValue()) == rightNumberLeaf->getValue()) {
								expr->replaceWith(rightNumberLeaf);
								delete expr;
							}
						}
					}
				}
				else {
					if (rightNumberLeaf->getValue() == 1) {
						auto newExpr = expr->m_leftNode;
						expr->replaceWith(newExpr);
						delete expr;
					}
				}
			}
		}
	}

	//5 + 2		=>		7
	static void OptimizeConstExpr(INode* node) {
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

			//5 + 2		=>		7
			if (auto leftNumberLeaf = dynamic_cast<INumberLeaf*>(expr->m_leftNode)) {
				if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(expr->m_rightNode)) {
					auto result = Calculate(leftNumberLeaf->getValue(), rightNumberLeaf->getValue(), expr->m_operation);
					if (expr->getMask() != 0)
						result &= expr->getMask().getValue();
					expr->replaceWith(new NumberLeaf(result));
					delete expr;
					return;
				}
			}

			//a << 0x2{2}		=>		a * 4
			if (expr->m_operation == Shl) {
				if (auto numberLeaf = dynamic_cast<INumberLeaf*>(expr->m_rightNode)) {
					auto value = numberLeaf->getValue();
					if (value >= 1 && value <= 3) {
						expr->m_operation = Mul;
						numberLeaf->setValue((uint64_t)1 << value);
					}
				}
			}
		}
	}

	//a
	//a * 5
	static bool IsLeaf(INode* node) {
		if (dynamic_cast<ILeaf*>(node))
			return true;
		if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
			if (opNode->m_operation == Mul) {
				if (dynamic_cast<INumberLeaf*>(opNode->m_rightNode) && IsLeaf(opNode->m_leftNode))
					return true;
			}
		}
		return false;
	}


	static bool IsSwap(INode* node1, INode* node2) {
		return dynamic_cast<INumberLeaf*>(node1) && !dynamic_cast<INumberLeaf*>(node2) || IsLeaf(node1) && !IsLeaf(node2);
	}


	//(0x2 + a)		=>		(a + 0x2)	
	static void ChangeLeafPlaceInMovingOperations(INode* node) {
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


	//((y + 3x) + x) * 2 + 5	=>	(y + 8x) + 5
	static void ExpandLinearExprs(INode* node) {
		TermsDict terms;
		int64_t constTerm = 0;
		GetTermsInExpr(node, terms, constTerm);

		if (terms.size() >= 1 && constTerm != 0x0) {
			auto linearExpr = new LinearExpr();
			for (auto termInfo : terms) {
				auto multiplier = (uint64_t&)termInfo.second.second;
				auto term = (multiplier == 1 ? termInfo.second.first : new OperationalNode(termInfo.second.first, new NumberLeaf(multiplier), Mul));
				linearExpr->addTerm(term);
			}
			linearExpr->setConstTermValue(constTerm);
			node->replaceWith(linearExpr);
			delete node;
			node = linearExpr;
		}

		IterateChildNodes(node, ExpandLinearExprs);
	}


	//((rsp + 0x20) + (rax * 5)) + 0x10				=>		(rsp + 0x30) + (rax * 5)
	//((((rsp & 0xF) + 0x9) + 0x2) + (-0x8))		=>		((rsp & 0xF) + 0x3)
	static void MakeLeafPlaceDeeperAndCalculate(INode* node, OperationalNode* prevExpr) { //TODO: prevExpr should be curExpr
		INode::UpdateDebugInfo(node);
		INode::UpdateDebugInfo(prevExpr);
		bool isSameOperation = true;

		if (auto curExpr = dynamic_cast<OperationalNode*>(node)) {
			if (prevExpr != nullptr) {
				auto prevOperation = prevExpr->m_operation;
				if (prevOperation != curExpr->m_operation) {
					isSameOperation = false;
				}
			}

			if (isSameOperation && prevExpr) {
				if (IsOperationMoving(curExpr->m_operation)) {
					if (IsSwap(prevExpr->m_rightNode, curExpr->m_rightNode)) {
						OperationalNode* newExpr;
						OperationalNode* newPrevExpr;
						newExpr = new OperationalNode(curExpr->m_leftNode, prevExpr->m_rightNode, curExpr->m_operation, curExpr->m_instr);
						newPrevExpr = new OperationalNode(newExpr, curExpr->m_rightNode, curExpr->m_operation, prevExpr->m_instr);

						prevExpr->replaceWith(newPrevExpr);
						delete prevExpr;
						curExpr = newExpr;
						prevExpr = newPrevExpr;
						INode::UpdateDebugInfo(curExpr);
						INode::UpdateDebugInfo(prevExpr);
					}
				}

				auto curNumberLeaf = dynamic_cast<INumberLeaf*>(curExpr->m_rightNode);
				auto prevNumberLeaf = dynamic_cast<INumberLeaf*>(prevExpr->m_rightNode);
				INode* newNode = nullptr;
				if (curNumberLeaf && prevNumberLeaf) {
					auto result = curNumberLeaf->getValue();
					switch (curExpr->m_operation)
					{
					case Shr:
					case Shl:
						result += prevNumberLeaf->getValue();
						break;
					case Div:
						result *= prevNumberLeaf->getValue();
						break;
					default:
						result = Calculate(result, prevNumberLeaf->getValue(), curExpr->m_operation);
					}

					auto mask = curExpr->getMask() | prevExpr->getMask();
					if (mask != 0)
						result &= mask.getValue();

					newNode = new NumberLeaf(result);
					
				}
				else {
					if (auto curRightOpNode = dynamic_cast<OperationalNode*>(curExpr->m_rightNode)) {
						if (curRightOpNode->m_operation == Shl) {
							if (auto shlNumberLeaf = dynamic_cast<INumberLeaf*>(curRightOpNode->m_rightNode)) {
								if (shlNumberLeaf->getValue() % 0x8 == 0) {
									newNode = new OperationalNode(curRightOpNode->m_leftNode, prevExpr->m_rightNode, Concat);
								}
							}
						}
					}
				}

				if (newNode) {
					curExpr = new OperationalNode(curExpr->m_leftNode, newNode, curExpr->m_operation, curExpr->m_instr);
					prevExpr->replaceWith(curExpr);
					delete prevExpr;
				}
			}

			INode::UpdateDebugInfo(curExpr);
			if (curExpr->m_rightNode) {
				OperationalNode* prevExpr_ = nullptr;
				MakeLeafPlaceDeeperAndCalculate(curExpr->m_rightNode, prevExpr_);
			}
			MakeLeafPlaceDeeperAndCalculate(curExpr->m_leftNode, curExpr);
		}
		else {
			IterateChildNodes(node, [](INode* childNode) {
				OperationalNode* prevExpr_ = nullptr;
				MakeLeafPlaceDeeperAndCalculate(childNode, prevExpr_);
				});
		}
	}
	

	static std::pair<INode*, int> GetConcatOperand(INode* node) {
		if (auto curExpr = dynamic_cast<OperationalNode*>(node)) {
			if (curExpr->m_operation == Shl) {
				if (auto shlNumberLeaf = dynamic_cast<INumberLeaf*>(curExpr->m_rightNode)) {
					return std::make_pair(curExpr->m_leftNode, (int)shlNumberLeaf->getValue());
				}
			}
		}
		return std::make_pair(node, 0x0);
	}

	//((([mem_1_16] <<.6 32) |.6 ([mem_2_16] <<.4 16)) |.8 [mem_3_16])		->		([mem_1_16] <<.6 32) |.8 CONCAT([mem_2_16], [mem_3_16])		->		CONCAT([mem_1_16], CONCAT([mem_2_16], [mem_3_16]))
	static void CreateConcatNodes(INode* node) {
		IterateChildNodes(node, CreateConcatNodes);

		if (auto curExpr = dynamic_cast<OperationalNode*>(node)) {
			if (curExpr->m_operation == Or) {
				auto pairOp1 = GetConcatOperand(curExpr->m_rightNode);
				std::pair<INode*, int> pairOp2;
				auto leftOpNode = dynamic_cast<OperationalNode*>(curExpr->m_leftNode);
				INode* leftTail = nullptr;
				if (leftOpNode && leftOpNode->m_operation == Or) {
					pairOp2 = GetConcatOperand(leftOpNode->m_rightNode);
					leftTail = leftOpNode->m_leftNode;
				}
				else {
					pairOp2 = GetConcatOperand(curExpr->m_leftNode);
				}

				if (pairOp1.second || pairOp2.second) {
					if (pairOp2.second < pairOp1.second)
						std::swap(pairOp1, pairOp2);
					if (pairOp2.second - pairOp1.second == pairOp1.first->getMask().getSize() * 0x8) {
						auto sumSize = pairOp1.first->getMask().getSize() + pairOp2.first->getMask().getSize();
						auto newNode = new OperationalNode(pairOp2.first, pairOp1.first, Concat, BitMask64(sumSize));
						if(pairOp1.second)
							newNode = new OperationalNode(newNode, new NumberLeaf((uint64_t)pairOp1.second), Shl, BitMask64(sumSize + pairOp1.second));
						if (leftTail) {
							newNode = new OperationalNode(leftTail, newNode, Or, curExpr->getMask());
						}
						curExpr->replaceWith(newNode);
						delete curExpr;
					}
				}
			}
		}
	}


	//([reg_rbx_64] & 0xffffffff00000000{0} | [var_2_32]) & 0x1f{31}	=>		[var_2_32] & 0x1f{31}
	static void RemoveZeroMaskMulExpr(OperationalNode* expr, BitMask64 mask) {
		if (!IsOperationManipulatedWithBitVector(expr->m_operation))
			return;

		for (auto& it : {
			std::make_pair(&expr->m_leftNode, expr->m_rightNode),
			std::make_pair(&expr->m_rightNode, expr->m_leftNode) })
		{
			if (auto operand = *it.first) {
				if ((operand->getMask() & mask) == 0x0) {
					//убрал, ибо не соблюдается главное условие оптимизации - заменяться все должно целиком. updated: теперь можно, ибо клонирование сделано
					/*if (auto expr = dynamic_cast<ExprTree::OperationalNode*>(it.second)) {
						RemoveZeroMaskMulExpr(expr, mask);
						if (!expr)
							return;
					}*/

					expr->replaceWith(it.second);
					delete expr;
					return;
				}
			}
		}

		IterateChildNodes(expr, [mask](INode* childNode) {
			if (auto opNode = dynamic_cast<OperationalNode*>(childNode)) {
				RemoveZeroMaskMulExpr(opNode, mask);
			}
			});
	}


	static void CalculateMasksAndOptimize(INode* node) {
		IterateChildNodes(node, CalculateMasksAndOptimize);

		if (auto expr = dynamic_cast<OperationalNode*>(node)) {
			if (IsOperationWithSingleOperand(expr->m_operation))
				return;

			if (expr->m_leftNode && expr->m_rightNode) {
				if (expr->m_operation == And) {
					auto mask1 = expr->m_leftNode->getMask();
					auto mask2 = expr->m_rightNode->getMask();
					expr->setMask(mask1 & mask2);

					if (expr->getMask() == 0x0) {
						//[var_2_32] & 0xffffffff00000000{0}		=>		0x0
						expr->replaceWith(new NumberLeaf((uint64_t)0));
						delete expr;
						return;
					}

					if (mask1 <= 0xFF) {
						if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
							auto mask1_64 = mask1;
							if ((mask1_64 & numberLeaf->getValue()) == mask1_64) {
								//[var_2_32] & 0xffffffff{-1}		=>		 [var_2_32]		
								auto newExpr = expr->m_leftNode;
								expr->replaceWith(newExpr);
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
							expr->setMask(expr->m_leftNode->getMask() << (int)numberLeaf->getValue());
							return;
						}
					}
					expr->setMask(expr->m_leftNode->getMask());
				}
				else {
					expr->setMask(expr->m_leftNode->getMask() | expr->m_rightNode->getMask());
				}
			}
		}
	}

	//TODO: сделать несколько проходов с возвратом кол-ва оптимизированных выражений. Некоторые оптимизации объединить в одну функцию для быстродействия. Сформулировать ясно каждый метод оптимизации. Объединить всё в класс. 
	static void Optimize(INode*& node) {
		INode::UpdateDebugInfo(node);
		RemoveMirrorNodesInExpr(node);
		CalculateHashes(node);
		OptimizeConstExpr(node);
		INode::UpdateDebugInfo(node);
		ChangeLeafPlaceInMovingOperations(node);
		INode::UpdateDebugInfo(node);
		OperationalNode* prevExpr_ = nullptr;
		MakeLeafPlaceDeeperAndCalculate(node, prevExpr_);
		INode::UpdateDebugInfo(node);
		OptimizeZeroInExpr(node);
		INode::UpdateDebugInfo(node);
		ExpandLinearExprs(node);
		INode::UpdateDebugInfo(node);
		CalculateMasksAndOptimize(node);
		INode::UpdateDebugInfo(node);
		OptimizeZeroInExpr(node);
		INode::UpdateDebugInfo(node);
		CreateTruncateCasts(node);
		INode::UpdateDebugInfo(node);
		CreateConcatNodes(node);
		INode::UpdateDebugInfo(node);
		CalculateHashes(node);
	}

	static void OptimizeCondition(INode*& cond) {
		if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
			//HERE IS TROUBLE
			INode* leftNode = compCond->m_leftCond;
			INode* rightNode = compCond->m_rightCond;
			OptimizeCondition(leftNode);
			OptimizeCondition(rightNode);

			INode::UpdateDebugInfo(compCond);
			InverseConditions(compCond);
			if (auto compCond = dynamic_cast<CompositeCondition*>(cond)) {
				INode::UpdateDebugInfo(compCond);
				MakeOrderInCompositeCondition(compCond);
				INode::UpdateDebugInfo(compCond);
				OptimizeCompositeCondition(compCond);
				INode::UpdateDebugInfo(cond);
			}
		}
		
		if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
			INode::UpdateDebugInfo(simpleCond);
			OptimizeCondition_SBORROW(simpleCond);
			if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
				INode::UpdateDebugInfo(simpleCond);
				OptimizeCondition_Add(simpleCond);
				if (auto simpleCond = dynamic_cast<Condition*>(cond)) {
					INode::UpdateDebugInfo(simpleCond);
					Optimize(cond);
					INode::UpdateDebugInfo(simpleCond);
				}
			}
		}
	}
};