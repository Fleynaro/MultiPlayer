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
			std::list<OperationalNode*> list;
			if (auto operationalNode = dynamic_cast<OperationalNode*>(conditionNode->m_leftNode)) {
				list.push_back(operationalNode);
			}
			if (auto operationalNode = dynamic_cast<OperationalNode*>(conditionNode->m_rightNode)) {
				list.push_back(operationalNode);
			}
			return list;
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
		auto list2 = GetNextOperationalsNodesToOpimize(expr->m_rightNode);
		list1.insert(list1.end(), list2.begin(), list2.end());
		return list1;
	}


	//[var_2_32] * 0				=>		0
	//[var_2_32] ^ [var_2_32]		=>		0
	//[var_2_32] + 0				=>		[var_2_32]
	//[var_2_32] * 1				=>		[var_2_32]
	static void OptimizeZeroInExpr(OperationalNode* expr) {	
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeZeroInExpr(it);
		}

		if (expr->m_operation == Xor) {
			if (expr->m_leftNode == expr->m_rightNode) {
				expr->replaceWith(new NumberLeaf(0));
				delete expr;
			}
		}

		if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
			if (expr->m_operation != Div && expr->m_operation != Mod) {
				if (rightNumberLeaf->m_value == 0) {
					if (expr->m_operation == Mul || expr->m_operation == And) {
						expr->replaceWith(new NumberLeaf(0));
					}
					else {
						expr->replaceWith(expr->m_leftNode);
					}
					delete expr;
				}
			}
			else {
				if (rightNumberLeaf->m_value == 1) {
					expr->replaceWith(expr->m_leftNode);
					delete expr;
				}
			}
		}
	}


	//5 + 2		=>		7
	static void OptimizeConstExpr(OperationalNode* expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeConstExpr(it);
		}
		
		if (!IsOperationUnsupportedToCalculate(expr->m_operation)) {
			if (auto leftNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_leftNode)) {
				if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
					auto result = Calculate(leftNumberLeaf->m_value, rightNumberLeaf->m_value, expr->m_operation);
					expr->replaceWith(new NumberLeaf(result));
					expr->m_leftNode = nullptr;
					delete expr;
				}
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
	static void ChangeLeafPlaceInMovingOperations(OperationalNode* expr) {
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
	static void CalculateAddEqualNodes(OperationalNode* expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			CalculateAddEqualNodes(it);
		}

		if (expr->m_operation == Add) {
			auto resultExpr = AddEqualNodes(expr->m_leftNode, expr->m_rightNode);
			if (resultExpr != nullptr) {
				expr->replaceWith(resultExpr);
				delete expr;
			}
		}
	}


	//((rsp + 0x20) + (rax * 5)) + 0x10				=>		(rsp + 0x30) + (rax * 5)
	//((((rsp & 0xF) + 0x9) + 0x2) + (-0x8))		=>		((rsp & 0xF) + 0x3)
	static void MakeLeafPlaceDeeperAndCalculate(OperationalNode* expr, OperationalNode* prevExpr = nullptr) {
		Node::UpdateDebugInfo(expr);
		Node::UpdateDebugInfo(prevExpr);
		bool isSameOperation = true;

		if (prevExpr != nullptr) {
			auto prevOperation = prevExpr->m_operation;
			if (prevOperation != expr->m_operation) {
				isSameOperation = false;
			}
		}

		if (isSameOperation && prevExpr) {
			if (IsOperationMoving(expr->m_operation)) {
				if (IsSwap(prevExpr->m_rightNode, expr->m_rightNode)) {
					auto newExpr = new OperationalNode(expr->m_leftNode, prevExpr->m_rightNode, expr->m_operation);
					auto newPrevExpr = new OperationalNode(newExpr, expr->m_rightNode, expr->m_operation);
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
					expr = new OperationalNode(expr->m_leftNode, new NumberLeaf(result), expr->m_operation);
					prevExpr->replaceWith(expr);
					delete prevExpr;
				}
			}
			else {
				//((y + 3x) + x)	=>	(y + 4x)
				if (expr->m_operation == Add) {
					auto resultExpr = AddEqualNodes(expr, prevExpr);
					if (resultExpr != nullptr) {
						expr = new OperationalNode(expr->m_leftNode, resultExpr, Add);
						prevExpr->replaceWith(expr);
						delete prevExpr;
					}
				}
			}
		}

		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			MakeLeafPlaceDeeperAndCalculate(it, expr);
		}
	}

	//([reg_rbx_64] & 0xffffffff00000000{0} | [var_2_32]) & 0x1f{31}	=>		[var_2_32] & 0x1f{31}
	static void RemoveZeroMaskMulExpr(OperationalNode* expr, uint64_t mask) {
		if (!IsOperationManipulatedWithBitVector(expr->m_operation))
			return;

		for (auto& it : {
			std::make_pair(&expr->m_leftNode, expr->m_rightNode),
			std::make_pair(&expr->m_rightNode, expr->m_leftNode) })
		{
			if (auto operand = dynamic_cast<INumber*>(*it.first)) {
				if ((operand->getMask() & mask) == 0x0) {
					expr->replaceWith(it.second);
					*it.first = nullptr;
					delete expr;

					if (auto expr = dynamic_cast<ExprTree::OperationalNode*>(it.second)) {
						RemoveZeroMaskMulExpr(expr, mask);
					}
					return;
				}
			}
		}

		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			RemoveZeroMaskMulExpr(it, mask);
		}
	}


	static void CalculateMasksAndOptimize(OperationalNode* expr) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			CalculateMasksAndOptimize(it);
		}

		if (auto leftNode = dynamic_cast<INumber*>(expr->m_leftNode)) {
			if (auto rightNode = dynamic_cast<INumber*>(expr->m_rightNode)) {
				if (expr->m_operation == And) {
					auto mask1 = leftNode->getMask();
					auto mask2 = rightNode->getMask();
					if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
						if ((mask1 & mask2) == mask1) {
							//[var_2_32] & 0xffffffff{-1}		=>		[var_2_32]		
							expr->replaceWith(expr->m_leftNode);
							expr->m_leftNode = nullptr;
							delete expr;
							return;
						}
						else {
							if (auto leftExpr = dynamic_cast<OperationalNode*>(expr->m_leftNode)) {
								RemoveZeroMaskMulExpr(expr, mask2);
								return;
							}
						}
					}

					expr->m_mask = mask1 & mask2;

					if (expr->m_mask == 0x0) {
						//[var_2_32] & 0xffffffff00000000{0}		=>		0x0
						expr->replaceWith(new NumberLeaf(0));
						delete expr;
					}
				}
				else if (expr->m_operation == Shr) {
					expr->m_mask = leftNode->getMask();
					if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
						expr->m_mask >>= numberLeaf->m_value;
					}
				}
				else if (expr->m_operation == Shl) {
					if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
						expr->m_mask = leftNode->getMask() << numberLeaf->m_value;
					}
				}
				else {
					expr->m_mask = leftNode->getMask() | rightNode->getMask();
				}
			}
		}
	}

	//TODO: сделать несколько проходов с возвратом кол-ва оптимизированных выражений. Некоторые оптимизации объединить в одну функцию для быстродействия. Сформулировать ясно каждый метод оптимизации. Объединить всё в класс.
	static void Optimize(Node* node) {
		auto list = GetNextOperationalsNodesToOpimize(node);
		for(auto expr : list) {
			OptimizeConstExpr(expr);
			ChangeLeafPlaceInMovingOperations(expr);
			MakeLeafPlaceDeeperAndCalculate(expr);
			CalculateAddEqualNodes(expr);
			CalculateMasksAndOptimize(expr);
			OptimizeZeroInExpr(expr);
		}
	}
};