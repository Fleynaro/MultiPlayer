#pragma once
#include "../ExprTree/ExprTreeCondition.h"

namespace CE::Decompiler::Optimization
{
	uint64_t Calculate(uint64_t op1, uint64_t op2, ExprTree::OperationType operation, bool isSigned = false) {
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

	struct CalcConstExprContext {
		bool m_isCalculated = false;
		uint64_t m_result = 0x0;
		//zmm vector result...

		CalcConstExprContext() = default;

		CalcConstExprContext(uint64_t result)
			: m_result(result), m_isCalculated(true)
		{}
	};

	static CalcConstExprContext CalculateConstExpr(ExprTree::Node* expr) {
		using namespace ExprTree;
		if (auto operationalNode = dynamic_cast<OperationalNode*>(expr)) {
			CalcConstExprContext leftOperand = CalculateConstExpr(operationalNode->m_leftNode);
			if (!leftOperand.m_isCalculated)
				return CalcConstExprContext();
			CalcConstExprContext rightOperand = CalculateConstExpr(operationalNode->m_rightNode);
			if (!rightOperand.m_isCalculated)
				return CalcConstExprContext();

			return CalcConstExprContext(Calculate(leftOperand.m_result, rightOperand.m_result, operationalNode->m_operation));
		}
		else if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr)) {
			return CalcConstExprContext(numberLeaf->m_value);
		}
		//condition
		return CalcConstExprContext();
	}


	struct OptRepeatOpExprContext {
		std::list<ExprTree::OperationalNode*> m_operationalNodes;
	};

	//((((rsp & 0xF) + 0x9) + 0x2) - ((0x8 - 0x2) + 0x2))		=>			((((rsp & 0xF) + 0x9) + 0x2) - 0x8)		=>		((rsp & 0xF) + 0x3)
	//((((rsp & 0xF) + 0x9) + (0x2 + rsp)) - 0x8)
	static void OptimizeRepeatOpExpr(ExprTree::OperationalNode* expr, OptRepeatOpExprContext& ctx) {
		using namespace ExprTree;
		bool isSameOperation = true;

		if (ctx.m_operationalNodes.size() > 0) {
			auto prevOperation = ctx.m_operationalNodes.back()->m_operation;
			if (prevOperation != expr->m_operation) {
				isSameOperation = false;
			}

			switch (prevOperation)
			{
			case Add:
			case Sub:
				if (expr->m_operation == Add || expr->m_operation == Sub)
					isSameOperation = true;
				break;
				
			//todo: операции без переместительного закона
			case Shr:	//>> 5) >> 6		>> 11
			case Shl:
			case Div:	// / 5 ) / 6		/ 30
				isSameOperation = false;
				break;
			}
		}

		if (!isSameOperation || !(dynamic_cast<OperationalNode*>(expr->m_leftNode) && dynamic_cast<NumberLeaf*>(expr->m_rightNode) ||
			dynamic_cast<NumberLeaf*>(expr->m_leftNode) && dynamic_cast<OperationalNode*>(expr->m_rightNode))) {
			ctx.m_operationalNodes.clear();

			if (auto operationalNode = dynamic_cast<OperationalNode*>(expr->m_leftNode)) {
				OptimizeRepeatOpExpr(operationalNode, ctx);
			}
			if (auto operationalNode = dynamic_cast<OperationalNode*>(expr->m_rightNode)) {
				OptimizeRepeatOpExpr(operationalNode, ctx);
			}
		}
		else {
			OperationalNode* operationalNode;
			if (operationalNode = dynamic_cast<OperationalNode*>(expr->m_leftNode)) {
				operationalNode = dynamic_cast<OperationalNode*>(expr->m_rightNode);
			}

			ctx.m_operationalNodes.push_back(operationalNode);

			if (ctx.m_operationalNodes.size() >= 2) {
				auto prevOperation = ctx.m_operationalNodes.back()->m_operation;
				if (prevOperation == Sub)
					prevOperation = Add;

				uint64_t result = 0;
				for (auto operationalNode : ctx.m_operationalNodes) {
					if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
						result = Calculate(result, numberLeaf->m_value, operationalNode->m_operation);
					}
					else if (auto numberLeaf = dynamic_cast<NumberLeaf*>(expr->m_rightNode)) {
						result = Calculate(numberLeaf->m_value, result, operationalNode->m_operation);
					}
				}
				auto resultOperationalNode = new OperationalNode(expr, new NumberLeaf(result), prevOperation);
				expr->replaceBy(resultOperationalNode);
				ctx.m_operationalNodes.clear();
			}

			OptimizeRepeatOpExpr(operationalNode, ctx);
		}
	}
};