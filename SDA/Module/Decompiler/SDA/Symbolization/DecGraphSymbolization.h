#pragma once
#include "../ExprTree/ExprTreeGOAR.h"
#include "../../ExprTree/ExprTree.h"
#include "../../DecCodeGraph.h"
#include "../../Optimization/ExprOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace CE::Decompiler::Symbolization
{
	using namespace Optimization;

	struct UserSymbolDef {
		CE::Symbol::MemoryArea* m_globalMemoryArea;
		CE::Symbol::MemoryArea* m_stackMemoryArea;
		CE::Symbol::MemoryArea* m_funcBodyMemoryArea;
	};

	static DataTypePtr CalculateDataType(DataTypePtr type1, DataTypePtr type2) {

	}

	static void CalculateTypesForExpr(Node* node, UserSymbolDef& userSymbolDef) {
		IterateChildNodes(node, [&](Node* childNode) {
			CalculateTypesForExpr(childNode, userSymbolDef);
			});


	}

	static void SymbolizeWithSDA(DecompiledCodeGraph* decGraph, UserSymbolDef& userSymbolDef) {

	}
};