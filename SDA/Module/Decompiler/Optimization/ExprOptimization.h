#pragma once
#include "../ExprTree/ExprTreeCondition.h"

namespace CE::Decompiler::Optimization
{
	static bool IsOperationUnsupportedToCalculate(ExprTree::OperationType operation) {
		using namespace ExprTree;
		return operation == readValue || operation == getBits;
	}

	static uint64_t Calculate(uint64_t op1, uint64_t op2, ExprTree::OperationType operation, bool isSigned = false) {
		using namespace ExprTree;
		switch (operation)
		{
		case Add:
			return op1 + op2;
		case Sub:
			return op1 - op2;
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

	static std::list<ExprTree::OperationalNode*> GetNextOperationalsNodesToOpimize(ExprTree::Node* node) {
		using namespace ExprTree;
		if (auto operationalNode = dynamic_cast<OperationalNode*>(node)) {
			return { operationalNode };
		}

		if (auto conditionNode = dynamic_cast<Condition*>(node)) {
			std::list<ExprTree::OperationalNode*> list;
			if (auto operationalNode = dynamic_cast<OperationalNode*>(conditionNode->m_leftNode)) {
				list.push_back(operationalNode);
			}
			if (auto operationalNode = dynamic_cast<OperationalNode*>(conditionNode->m_rightNode)) {
				list.push_back(operationalNode);
			}
			return list;
		}

		if (auto compCondition = dynamic_cast<CompositeCondition*>(node)) {
			auto list1 = GetNextOperationalsNodesToOpimize(compCondition->m_leftNode);
			auto list2 = GetNextOperationalsNodesToOpimize(compCondition->m_rightNode);
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

		return {};
	}

	static std::list<ExprTree::OperationalNode*> GetNextOperationalsNodesToOpimize(ExprTree::OperationalNode* expr) {
		auto list1 = GetNextOperationalsNodesToOpimize(expr->m_leftNode);
		auto list2 = GetNextOperationalsNodesToOpimize(expr->m_rightNode);
		list1.insert(list1.end(), list2.begin(), list2.end());
		return list1;
	}


	static void OptimizeZeroInExpr(ExprTree::OperationalNode* expr) {
		using namespace ExprTree;
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeZeroInExpr(it);
		}

		if (expr->m_operation == Xor) {
			if (expr->m_leftNode == expr->m_rightNode) {
				expr->replaceBy(new NumberLeaf(0));
				delete expr;
			}
		}
	}


	static void OptimizeConstExpr(ExprTree::OperationalNode* expr) {
		using namespace ExprTree;
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeConstExpr(it);
		}
		
		if (!IsOperationUnsupportedToCalculate(expr->m_operation)) {
			if (auto leftNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_leftNode)) {
				if (auto rightNumberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
					leftNumberLeaf->m_value = Calculate(leftNumberLeaf->m_value, rightNumberLeaf->m_value, expr->m_operation);
					expr->replaceBy(expr->m_leftNode);
					expr->m_leftNode = nullptr;
					delete expr;
				}
			}
		}
	}


	//(0x8 - (((rsp & 0xF) + 0x9) + 0x2))
	//((0x2 - ((rsp & 0xF) + 0x9)) - 0x8)
	static void OptimizeConstPlaceInExpr(ExprTree::OperationalNode* expr) {
		using namespace ExprTree;
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeConstPlaceInExpr(it);
		}
		if (!IsOperationUnsupportedToCalculate(expr->m_operation) && (expr->m_operation != Div && expr->m_operation != Shr && expr->m_operation != Shl)) {
			if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
				if (expr->m_operation == Sub) {
					expr->m_operation = Add;
					numberLeaf->m_value *= -1;
				}
			} else if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_leftNode)) {
				auto tempNode = expr->m_rightNode;
				expr->m_rightNode = numberLeaf;
				expr->m_leftNode = tempNode;

				if (expr->m_operation == Sub) {
					expr->m_operation = Add;
					expr->m_leftNode->removeParentNode(expr);
					expr->m_leftNode = new OperationalNode(expr->m_leftNode, new NumberLeaf(-1), Mul);
				}
			}
		}
	}

	//((((rsp & 0xF) + 0x9) + 0x2) - ((0x8 - 0x2) + 0x2))		=>			((((rsp & 0xF) + 0x9) + 0x2) + (-0x8))		=>		((rsp & 0xF) + 0x3)
	static void OptimizeRepeatOpInExpr(ExprTree::OperationalNode* expr, ExprTree::OperationalNode* prevOperationalNode = nullptr) {
		using namespace ExprTree;
		bool isSameOperation = true;

		if (prevOperationalNode != nullptr) {
			auto prevOperation = prevOperationalNode->m_operation;
			if (prevOperation != expr->m_operation) {
				isSameOperation = false;
			}
		}

		auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode);
		if (numberLeaf && isSameOperation) {
			if (prevOperationalNode != nullptr) {
				if (auto prevNumberLeaf = dynamic_cast<NumberLeaf*>(prevOperationalNode->m_rightNode)) {
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
					prevOperationalNode->replaceBy(expr);
					delete prevOperationalNode;
				}
			}
		}

		prevOperationalNode = expr;

		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			OptimizeRepeatOpInExpr(it, prevOperationalNode);
		}
	}

	static void Optimize(ExprTree::Node* node) {
		auto list = GetNextOperationalsNodesToOpimize(node);
		for(auto expr : list) {
			OptimizeZeroInExpr(expr);
			OptimizeConstExpr(expr);
			OptimizeConstPlaceInExpr(expr);
			OptimizeRepeatOpInExpr(expr);
		}
	}
};