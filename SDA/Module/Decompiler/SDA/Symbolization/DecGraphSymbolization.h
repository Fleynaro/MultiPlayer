#pragma once
#include "../ExprTree/ExprTreeSda.h"
#include "../../ExprTree/ExprTree.h"
#include "../../Optimization/DecGraphOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
#include <Manager/ProgramModule.h>
#include <Manager/TypeManager.h>

namespace CE::Decompiler::Symbolization
{
	using namespace Optimization;

	struct UserSymbolDef {
		CE::ProgramModule* m_programModule;
		CE::Symbol::MemoryArea* m_globalMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_stackMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_funcBodyMemoryArea = nullptr;

		UserSymbolDef(CE::ProgramModule* programModule = nullptr)
			: m_programModule(programModule)
		{}
	};

	struct CalcTypeContext {
		UserSymbolDef* m_userSymbolDef;
		std::map<Symbol::Symbol*, DataTypePtr> m_symbolTypes;

		DataTypePtr getSymbolType(Symbol::Symbol* symbol) {
			auto it = m_symbolTypes.find(symbol);
			if(it != m_symbolTypes.end())
				return it->second;
			return m_symbolTypes[symbol] = getDefaultType(symbol->getSize());
		}

		DataTypePtr getDefaultType(Node* node) {
			return getDefaultType(node->getMask().getSize());
		}

		DataTypePtr getDefaultType(int size) {
			std::string sizeStr = "64";
			if (size != 0)
				sizeStr = std::to_string(size * 0x8);
			return DataType::GetUnit(m_userSymbolDef->m_programModule->getTypeManager()->getTypeByName("uint" + sizeStr + "_t"));
		}
	};

	static Node* BuildSdaNodes(Node* node) {
		IterateChildNodes(node, BuildSdaNodes);

		auto sdaNode = new SdaNode(node);
		node->replaceWith(sdaNode);
		node->addParentNode(sdaNode);
		return sdaNode;
	}

	static DataTypePtr CalculateDataType(DataTypePtr type1, DataTypePtr type2) {
		if (type1->isPointer())
			return type1;
		if (type2->isPointer())
			return type2;
		if (type1->getSize() > type2->getSize())
			return type1;
		if (type1->getSize() < type2->getSize())
			return type2;
		if (type1->isSigned())
			return type2;
		return type1;
	}

	static void CalculateTypesAndBuildGoarForExpr(Node* node, CalcTypeContext& ctx) {
		IterateChildNodes(node, [&](Node* childNode) {
			CalculateTypesAndBuildGoarForExpr(childNode, ctx);
			});

		if (auto sdaNode = dynamic_cast<SdaNode*>(node)) {
			auto symbolLeaf = dynamic_cast<SymbolLeaf*>(sdaNode->m_node);
			auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node);
			if (symbolLeaf || linearExpr) {

			}

			if (symbolLeaf) {
				sdaNode->m_calcDataType = ctx.getSymbolType(symbolLeaf->m_symbol);
			}
			else if (auto opNode = dynamic_cast<OperationalNode*>(sdaNode->m_node)) {
				if (auto sdaLeftNode = dynamic_cast<SdaNode*>(opNode->m_leftNode)) {
					if (auto sdaRightNode = dynamic_cast<SdaNode*>(opNode->m_rightNode)) {
						sdaNode->m_calcDataType = CalculateDataType(sdaLeftNode->getDataType(), sdaRightNode->getDataType());
					}
				}
			}

			if (sdaNode->m_calcDataType == nullptr) {
				sdaNode->m_calcDataType = ctx.getDefaultType(sdaNode->m_node);
			}
			sdaNode->m_explicitCast = true;
		}
	}

	static void SymbolizeWithSDA(DecompiledCodeGraph* decGraph, UserSymbolDef& userSymbolDef) {
		CalcTypeContext ctx;
		ctx.m_userSymbolDef = &userSymbolDef;
		
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto topNode : decBlock->getAllTopNodes()) {
				auto sdaTopNode = BuildSdaNodes(topNode);
				CalculateTypesAndBuildGoarForExpr(sdaTopNode, ctx);
			}
		}
	}
};