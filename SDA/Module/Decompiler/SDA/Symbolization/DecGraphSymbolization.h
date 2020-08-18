#pragma once
#include "../AutoSdaSymbol.h"
#include "../ExprTree/ExprTreeSda.h"
#include "../../ExprTree/ExprTree.h"
#include "../../Optimization/DecGraphOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
#include <Code/Type/FunctionSignature.h>
#include <Manager/ProgramModule.h>
#include <Manager/TypeManager.h>

namespace CE::Decompiler::Symbolization
{
	using namespace Optimization;
	using namespace DataType;

	struct UserSymbolDef {
		CE::ProgramModule* m_programModule;
		Signature* m_signature = nullptr;
		CE::Symbol::MemoryArea* m_globalMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_stackMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_funcBodyMemoryArea = nullptr;
		int m_offset;

		UserSymbolDef(CE::ProgramModule* programModule = nullptr)
			: m_programModule(programModule)
		{}
	};

	class SdaSymbolBuilding
	{
	public:
		SdaSymbolBuilding()
		{}

		void buildSdaSymbols(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				buildSdaSymbols(childNode);
				});

			if (auto sdaNode = dynamic_cast<SdaNode*>(node)) {
				if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(sdaNode->m_node)) {

				}
				if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node)) {

				}
			}
		}

	private:
		UserSymbolDef* m_userSymbolDef;
		std::map<Symbol::Symbol*, CE::Symbol::AbstractSymbol*> m_symbolsToSymbols;
		std::map<int, CE::Symbol::AbstractSymbol*> m_stackToSymbols;
		std::map<int, CE::Symbol::AbstractSymbol*> m_globalToSymbols;

		CE::Symbol::AbstractSymbol* findOrCreateSymbol(Symbol::Symbol* symbol, int size, int& offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.getGenericId() == ZYDIS_REGISTER_RSP) {
					auto it = m_stackToSymbols.find(offset);
					if (it != m_stackToSymbols.end())
						return it->second;
				} else if (reg.getGenericId() == ZYDIS_REGISTER_RIP) {
					auto it = m_globalToSymbols.find(offset);
					if (it != m_globalToSymbols.end())
						return it->second;
				}
			}

			auto it = m_symbolsToSymbols.find(symbol);
			if (it != m_symbolsToSymbols.end())
				return it->second;
			
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				int paramIdx = 0;
				auto& reg = regSymbol->m_register;
				auto signature = m_userSymbolDef->m_signature;
				if (signature->getCallingConvetion() == Signature::FASTCALL) {
					if (reg.getGenericId() == ZYDIS_REGISTER_RSP) {
						if (offset >= 0x8 && offset % 0x8 == 0) {
							paramIdx = 4 + offset / 0x8;
						}
					}
					else {
						static std::map<PCode::RegisterId, int> regToParams = {
							std::pair(ZYDIS_REGISTER_RCX, 1),
							std::pair(ZYDIS_REGISTER_RDX, 2),
							std::pair(ZYDIS_REGISTER_R8, 3),
							std::pair(ZYDIS_REGISTER_R9, 4)
						};
						auto it = regToParams.find(reg.getGenericId());
						if (it != regToParams.end()) {
							paramIdx = it->second;
						}
					}
				}

				if (paramIdx == 0) {
					for (auto storage : signature->getCustomStorages()) {
						if (storage->getType() == Storage::STORAGE_REGISTER && reg.getGenericId() == storage->getRegisterId() || (offset == storage->getOffset() &&
								(storage->getType() == Storage::STORAGE_STACK && reg.getGenericId() == ZYDIS_REGISTER_RSP ||
									storage->getType() == Storage::STORAGE_GLOBAL && reg.getGenericId() == ZYDIS_REGISTER_RIP)) ) {
							paramIdx = storage->getIndex();
							break;
						}
					}
				}

				if (paramIdx != 0) {
					auto& funcParams = signature->getParameters();
					if (paramIdx <= funcParams.size()) {
						auto sdaSymbol = funcParams[paramIdx - 1];
						storeSdaSymbol(sdaSymbol, symbol, size, offset);
						return sdaSymbol;
					}
					auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::FUNC_PARAMETER, "param" + std::to_string(paramIdx), paramIdx, size);
					storeSdaSymbol(sdaSymbol, symbol, size, offset);
					return sdaSymbol;
				}

				if (reg.getGenericId() == ZYDIS_REGISTER_RSP)
					return createMemorySymbol(m_userSymbolDef->m_stackMemoryArea, CE::Symbol::LOCAL_STACK_VAR, "stack", symbol, offset, size);
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP)
					return createMemorySymbol(m_userSymbolDef->m_globalMemoryArea, CE::Symbol::GLOBAL_VAR, "global", symbol, offset, size);

				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, "in_" + reg.printDebug(), 0, size);
				storeSdaSymbol(sdaSymbol, symbol, size, offset);
				return sdaSymbol;
			}



			return nullptr;
		}

		CE::Symbol::AbstractSymbol* createMemorySymbol(CE::Symbol::MemoryArea* memoryArea, CE::Symbol::Type type, const std::string& name, Symbol::Symbol* symbol, int& offset, int size) {
			auto symbolPair = memoryArea->getSymbolAt(offset);
			if (symbolPair.second != nullptr) {
				offset -= symbolPair.first;
				auto sdaSymbol = symbolPair.second;
				storeSdaSymbol(sdaSymbol, symbol, size, symbolPair.first);
				return sdaSymbol;
			}
			auto sdaSymbol = createAutoSdaSymbol(type, name + "_0x" + Generic::String::NumberToHex((uint32_t)-offset), offset, size);
			storeSdaSymbol(sdaSymbol, symbol, size, offset);
			return sdaSymbol;
		}

		CE::Symbol::AutoSdaSymbol* createAutoSdaSymbol(CE::Symbol::Type type, const std::string& name, int value, int size) {
			auto dataType = getDefaultType(size);
			return new CE::Symbol::AutoSdaSymbol(type, value, m_userSymbolDef->m_programModule->getSymbolManager(), dataType, name);
		}

		void storeSdaSymbol(CE::Symbol::AbstractSymbol* sdaSymbol, Symbol::Symbol* symbol, int size, int offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.getGenericId() == ZYDIS_REGISTER_RSP) {
					m_stackToSymbols[offset] = sdaSymbol;
					return;
				}
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP) {
					m_globalToSymbols[offset] = sdaSymbol;
					return;
				}
			}
			m_symbolsToSymbols[symbol] = sdaSymbol;
		}

		DataTypePtr getDefaultType(int size) {
			std::string sizeStr = "64";
			if (size != 0)
				sizeStr = std::to_string(size * 0x8);
			return DataType::GetUnit(m_userSymbolDef->m_programModule->getTypeManager()->getTypeByName("uint" + sizeStr + "_t"));
		}

		int toGlobalOffset(int offset) {
			return m_userSymbolDef->m_offset + offset;
		}

		int toLocalOffset(int offset) {
			return offset - m_userSymbolDef->m_offset;
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

	/*static void CalculateTypesAndBuildGoarForExpr(Node* node, CalcTypeContext& ctx) {
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
	}*/

	static void SymbolizeWithSDA(DecompiledCodeGraph* decGraph, UserSymbolDef& userSymbolDef) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto topNode : decBlock->getAllTopNodes()) {
				auto sdaTopNode = BuildSdaNodes(topNode);
				//CalculateTypesAndBuildGoarForExpr(sdaTopNode, ctx);
			}
		}
	}
};