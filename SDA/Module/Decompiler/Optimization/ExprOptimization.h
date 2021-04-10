#pragma once
#include "ExprTree/ExprUnification.h"
#include "ExprTree/ExprConstCalculating.h"
#include "ExprTree/ExprExpandingToLinearExpr.h"
#include "ExprTree/ExprConcatAndSubpieceBuilding.h"
#include "ExprTree/ExprSimpleCondOptimization.h"
#include "ExprTree/ExprCompositeCondOptimization.h"
#include "ExprTree/ExprConstCondCalculating.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;
	class ExprOptimization
	{
		TopNode* m_topNode;
	public:
		ExprOptimization(TopNode* node)
			: m_topNode(node)
		{}

		void start() {
			linearExprToOpNodes(m_topNode->getNode()); // remove linear expressions
			optimizeGenerally(m_topNode->getNode());
			opNodesToLinearExpr(m_topNode->getNode()); // create linear expressions
		}

	private:
		void optimizeGenerally(INode* node) {
			node->iterateChildNodes([&](INode* childNode) {
				optimizeGenerally(childNode);
				});

			ExprUnification exprUnification(node);
			exprUnification.start();
			node = exprUnification.getNode();
			
			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				ExprConstCalculating exprConstCalculating(opNode);
				exprConstCalculating.start();
				node = exprConstCalculating.getNode();
			}

			ExprConcatAndSubpieceBuilding exprConcatAndSubpieceBuilding(node);
			exprConcatAndSubpieceBuilding.start();
			node = exprConcatAndSubpieceBuilding.getNode();

			if (auto cond = dynamic_cast<AbstractCondition*>(node)) {
				ExprConstConditionCalculating exprConstConditionCalculating(cond);
				exprConstConditionCalculating.start();
				node = exprConstConditionCalculating.getNode();
			}

			if (auto cond = dynamic_cast<Condition*>(node)) {
				ExprSimpleConditionOptimization exprSimpleConditionOptimization(cond);
				exprSimpleConditionOptimization.start();
				node = exprSimpleConditionOptimization.getNode();
			}
			else if (auto compCond = dynamic_cast<CompositeCondition*>(node)) {
				ExprCompositeConditionOptimization exprCompositeConditionOptimization(compCond);
				exprCompositeConditionOptimization.start();
				node = exprCompositeConditionOptimization.getNode();
			}
		}

		void linearExprToOpNodes(INode* node) {
			node->iterateChildNodes([&](INode* childNode) {
				linearExprToOpNodes(childNode);
				});

			if (auto linearExpr = dynamic_cast<LinearExpr*>(node)) {
				node = linearExpr->getConstTerm();
				for (auto term : linearExpr->getTerms()) {
					node = new OperationalNode(node, term, linearExpr->m_operation);
				}
				linearExpr->replaceWith(node);
				delete linearExpr;
			}
		}

		void opNodesToLinearExpr(INode* node) {
			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				ExprExpandingToLinearExpr exprExpandingToLinearExpr(opNode);
				exprExpandingToLinearExpr.start();
				node = exprExpandingToLinearExpr.getNode();
			}

			node->iterateChildNodes([&](INode* childNode) {
				opNodesToLinearExpr(childNode);
				});
		}
	};
};