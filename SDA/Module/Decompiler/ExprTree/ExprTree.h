#pragma once
#include "ExprTreeFunctionCall.h"
#include "ExprTreeCondition.h"
#include "ExprTreeLinearExpr.h"
#include "ExprTreeAssignmentNode.h"
#include "ExprTreeMirrorNode.h"

namespace CE::Decompiler::ExprTree
{
	// get all symbol leafs from the specified {node} according to the specified {symbol}
	static void GatherSymbolLeafsFromNode(INode* node, std::list<ExprTree::SymbolLeaf*>& symbolLeafs, Symbol::Symbol* symbol = nullptr) {
		node->iterateChildNodes([&](INode* childNode) {
			GatherSymbolLeafsFromNode(childNode, symbolLeafs, symbol);
			});

		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (!symbol || symbolLeaf->m_symbol == symbol) {
				symbolLeafs.push_back(symbolLeaf);
			}
		}
	}

	// check if the specified {node} has the specified {symbol}
	static bool DoesNodeHaveSymbol(INode* node, Symbol::Symbol* symbol) {
		std::list<ExprTree::SymbolLeaf*> symbolLeafs;
		GatherSymbolLeafsFromNode(node, symbolLeafs, symbol);
		return !symbolLeafs.empty();
	}
};