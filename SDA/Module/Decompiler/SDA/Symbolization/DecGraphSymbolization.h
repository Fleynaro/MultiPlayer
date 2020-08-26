#pragma once
#include "../SdaCodeGraph.h"
#include "../../Optimization/DecGraphOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
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

	class DataTypeFactory
	{
	public:
		DataTypeFactory(UserSymbolDef* userSymbolDef)
			: m_userSymbolDef(userSymbolDef)
		{}

		DataTypePtr getDefaultType(int size) {
			std::string sizeStr = "64";
			if (size != 0)
				sizeStr = std::to_string(size * 0x8);
			return DataType::GetUnit(m_userSymbolDef->m_programModule->getTypeManager()->getTypeByName("uint" + sizeStr + "_t"));
		}
	private:
		UserSymbolDef* m_userSymbolDef;
	};

	class SdaSymbolBuilding
	{
	public:
		SdaSymbolBuilding(SdaCodeGraph* sdaCodeGraph, UserSymbolDef* userSymbolDef, DataTypeFactory* dataTypeFactory)
			: m_sdaCodeGraph(sdaCodeGraph), m_userSymbolDef(userSymbolDef), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() {
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					buildSdaSymbols(topNode->getNode());
				}
			}
		}
	private:
		SdaCodeGraph* m_sdaCodeGraph;
		UserSymbolDef* m_userSymbolDef;
		DataTypeFactory* m_dataTypeFactory;
		std::map<Symbol::Symbol*, CE::Symbol::AbstractSymbol*> m_symbolsToSymbols;
		std::map<int64_t, CE::Symbol::AbstractSymbol*> m_stackToSymbols;
		std::map<int64_t, CE::Symbol::AbstractSymbol*> m_globalToSymbols;
		std::map<ObjectHash::Hash, std::shared_ptr<SdaFunctionNode::TypeContext>> m_funcTypeContexts;

		void buildSdaSymbols(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				buildSdaSymbols(childNode);
				});

			if (auto sdaNode = dynamic_cast<SdaNode*>(node)) {
				if (auto funcCall = dynamic_cast<FunctionCall*>(sdaNode->m_node)) {
					std::shared_ptr<SdaFunctionNode::TypeContext> typeContext;
					auto keyHash = funcCall->getDestination()->getHash();
					auto it = m_funcTypeContexts.find(keyHash);
					if (it == m_funcTypeContexts.end()) {
						std::vector<DataTypePtr> paramTypes;
						DataTypePtr returnType;
						for (auto paramNode : funcCall->getParamNodes()) {
							paramTypes.push_back(m_dataTypeFactory->getDefaultType(paramNode->getMask().getSize()));
						}
						returnType = m_dataTypeFactory->getDefaultType(funcCall->getMask().getSize());
						m_funcTypeContexts[keyHash] = std::make_shared<SdaFunctionNode::TypeContext>(new SdaFunctionNode::TypeContext(paramTypes, returnType));
					}
					else {
						typeContext = it->second;
					}

					auto functionNode = new SdaFunctionNode(funcCall, typeContext);
					sdaNode->replaceWith(functionNode);
					delete sdaNode;
					return;
				}

				//find symbol and offset
				Symbol::Symbol* symbol = nullptr;
				int64_t offset;
				ExprTree::SdaNode* sdaNodeToReplace = sdaNode;
				bool isOneOfTerm = false;

				if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(sdaNode->m_node)) {
					symbol = symbolLeaf->m_symbol;
					offset = 0x0;
				}
				else if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node)) {
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTerm = dynamic_cast<SdaNode*>(term)) {
							if (auto termSymbolLeaf = dynamic_cast<SymbolLeaf*>(sdaTerm->m_node)) {
								if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(termSymbolLeaf->m_symbol)) {
									if (regSymbol->m_register.isPointer()) {
										symbol = regSymbol;
										if (linearExpr->getTerms().size() != 1) {
											isOneOfTerm = true;
											sdaNodeToReplace = sdaTerm;
										}
										break;
									}
								}
							}
						}
					}
					offset = linearExpr->m_constTerm;
				}
				if (!symbol)
					return;

				//calculate size
				int size = 0x0;
				bool transformToLocalOffset = false;
				bool isStackOrGlobal = false;
				bool isGettingAddr = true;
				if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
					if (regSymbol->m_register.isPointer()) {
						//handle later anyway
						if (dynamic_cast<LinearExpr*>(sdaNode->getParentNode()))
							return;
						//if reading presence
						if (auto readValueNode = dynamic_cast<ReadValueNode*>(sdaNode->getParentNode())) {
							size = readValueNode->getSize();
							if (!isOneOfTerm) {
								if (auto sdaNode = dynamic_cast<SdaNode*>(readValueNode->getParentNode())) {
									sdaNodeToReplace = sdaNode;
									isGettingAddr = false;
								}
							}
						}
						//transform to global offset
						if (regSymbol->m_register.getGenericId() == ZYDIS_REGISTER_RIP) {
							offset = toGlobalOffset(offset);
							transformToLocalOffset = true;
						}
						isStackOrGlobal = true;
					}
				}
				if (size == 0x0) {
					size = symbol->getSize();
				}

				//find symbol or create it
				auto sdaSymbol = findOrCreateSymbol(symbol, size, offset);
				if (isStackOrGlobal) {
					sdaNodeToReplace->replaceWith(new SdaSymbolLeaf(sdaSymbol, isGettingAddr));
					delete sdaNodeToReplace;
				}
				else {
					//replace all symbol leafs
					for (auto symbolLeaf : symbol->m_symbolLeafs) {
						symbolLeaf->replaceWith(new SdaSymbolLeaf(sdaSymbol, false));
						delete symbolLeaf;
					}
				}

				//change offset
				if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node)) {
					if (transformToLocalOffset)
						offset = toLocalOffset(offset);
					linearExpr->m_constTerm = offset;
				}
			}
		}

		CE::Symbol::AbstractSymbol* findOrCreateSymbol(Symbol::Symbol* symbol, int size, int64_t& offset) {
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
				auto paramInfos = m_sdaCodeGraph->getDecGraph()->getFunctionCallInfo().getParamInfos();
				for (auto paramInfo : paramInfos) {
					auto& storage = paramInfo.m_storage;
					if (storage.getType() == Storage::STORAGE_REGISTER && reg.getGenericId() == storage.getRegisterId() || (offset == storage.getOffset() &&
							(storage.getType() == Storage::STORAGE_STACK && reg.getGenericId() == ZYDIS_REGISTER_RSP ||
								storage.getType() == Storage::STORAGE_GLOBAL && reg.getGenericId() == ZYDIS_REGISTER_RIP)) ) {
						paramIdx = storage.getIndex();
						break;
					}
				}

				if (paramIdx != 0) {
					auto& funcParams = m_userSymbolDef->m_signature->getParameters();
					if (paramIdx <= funcParams.size()) {
						auto sdaSymbol = funcParams[paramIdx - 1];
						storeSdaSymbol(sdaSymbol, symbol, offset);
						return sdaSymbol;
					}
					auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::FUNC_PARAMETER, "param" + std::to_string(paramIdx), paramIdx, size);
					storeSdaSymbol(sdaSymbol, symbol, offset);
					return sdaSymbol;
				}

				if (reg.getGenericId() == ZYDIS_REGISTER_RSP)
					return createMemorySymbol(m_userSymbolDef->m_stackMemoryArea, CE::Symbol::LOCAL_STACK_VAR, "stack", symbol, offset, size);
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP)
					return createMemorySymbol(m_userSymbolDef->m_globalMemoryArea, CE::Symbol::GLOBAL_VAR, "global", symbol, offset, size);

				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, "in_" + reg.printDebug(), 0, size);
				storeSdaSymbol(sdaSymbol, symbol, offset);
				return sdaSymbol;
			}

			std::list<int64_t> instrOffsets;
			if (auto symbolRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(symbol)) {
				for (auto instr : symbolRelToInstr->getInstructionsRelatedTo()) {
					instrOffsets.push_back(instr->getOffset());
				}

				if (!instrOffsets.empty()) {
					for (auto instrOffset : instrOffsets) {
						auto symbolPair = m_userSymbolDef->m_funcBodyMemoryArea->getSymbolAt(instrOffset);
						if (symbolPair.second != nullptr) {
							auto sdaSymbol = symbolPair.second;
							storeSdaSymbol(sdaSymbol, symbol, offset);
							return sdaSymbol;
						}
					}
				}
			}

			if (auto symbolWithId = dynamic_cast<Symbol::SymbolWithId*>(symbol)) {
				std::string suffix = "local";
				if (dynamic_cast<Symbol::MemoryVariable*>(symbol))
					suffix = "mem";
				else if (dynamic_cast<Symbol::FunctionResultVar*>(symbol))
					suffix = "func";
				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, suffix + "Var" + std::to_string(symbolWithId->getId()), 0, size, instrOffsets);
				storeSdaSymbol(sdaSymbol, symbol, offset);
				return sdaSymbol;
			}

			return nullptr;
		}

		CE::Symbol::AbstractSymbol* createMemorySymbol(CE::Symbol::MemoryArea* memoryArea, CE::Symbol::Type type, const std::string& name, Symbol::Symbol* symbol, int64_t& offset, int size) {
			auto symbolPair = memoryArea->getSymbolAt(offset);
			if (symbolPair.second != nullptr) {
				offset -= symbolPair.first;
				auto sdaSymbol = symbolPair.second;
				storeSdaSymbol(sdaSymbol, symbol, symbolPair.first);
				return sdaSymbol;
			}
			auto sdaSymbol = createAutoSdaSymbol(type, name + "_0x" + Generic::String::NumberToHex((uint32_t)-offset), offset, size);
			storeSdaSymbol(sdaSymbol, symbol, offset);
			offset = (type == CE::Symbol::GLOBAL_VAR ? toGlobalOffset(0x0) : 0x0);
			return sdaSymbol;
		}

		CE::Symbol::AutoSdaSymbol* createAutoSdaSymbol(CE::Symbol::Type type, const std::string& name, int64_t value, int size, std::list<int64_t> instrOffsets = {}) {
			auto dataType = m_dataTypeFactory->getDefaultType(size);
			return new CE::Symbol::AutoSdaSymbol(type, value, instrOffsets, m_userSymbolDef->m_programModule->getSymbolManager(), dataType, name);
		}

		void storeSdaSymbol(CE::Symbol::AbstractSymbol* sdaSymbol, Symbol::Symbol* symbol, int64_t offset) {
			m_sdaCodeGraph->getSdaSymbols().push_back(sdaSymbol);
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

		int64_t toGlobalOffset(int64_t offset) {
			return m_userSymbolDef->m_offset + offset;
		}

		int64_t toLocalOffset(int64_t offset) {
			return offset - m_userSymbolDef->m_offset;
		}
	};

	class SdaDataTypesCalculating
	{
	public:
		SdaDataTypesCalculating(SdaCodeGraph* sdaCodeGraph, DataTypeFactory* dataTypeFactory)
			: m_sdaCodeGraph(sdaCodeGraph), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() {
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					calculateDataTypes(topNode->getNode());
				}
			}
		}
	private:
		SdaCodeGraph* m_sdaCodeGraph;
		DataTypeFactory* m_dataTypeFactory;

		bool buildGoar(AbstractSdaNode*& sdaNode, int64_t& bitOffset, std::list<AbstractSdaNode*>& terms) {
			auto dataType = sdaNode->getDataType();
			auto ptrLevels = dataType->getPointerLevels();
			if (ptrLevels.empty())
				return;
			if (*ptrLevels.begin() != 1)
				return;
			ptrLevels.pop_front();

			auto baseDataType = dataType->getBaseType();
			if (ptrLevels.empty()) {
				if (auto structure = dynamic_cast<DataType::Structure*>(baseDataType)) {
					auto field = structure->getField(bitOffset);
					auto dataType = DataType::CloneUnit(field->getDataType());
					dataType->addPointerLevelInFront();
					sdaNode = new GoarNode(dataType, sdaNode, field->getAbsBitOffset(), nullptr, 0x0);
					bitOffset -= field->getAbsBitOffset();
					return true;
				}
			}
			
			auto frontArrDim = *ptrLevels.begin();
			if (frontArrDim != 1)
				ptrLevels.pop_front();
			auto arrItemDataType = DataType::GetUnit(baseDataType, ptrLevels);
			auto arrItemSize = arrItemDataType->getSize();

			AbstractSdaNode* indexNode = nullptr;
			for (auto it = terms.begin(); it != terms.end(); it ++) {
				int64_t defMultiplier = 1;
				int64_t* multiplier = &defMultiplier;
				if (auto sdaTermNode = dynamic_cast<SdaNode*>(*it)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaTermNode->m_node)) {
						if (auto numberLeaf = dynamic_cast<NumberLeaf*>(opNode->m_rightNode)) {
							if (opNode->m_operation == Mul) {
								multiplier = (int64_t*)&numberLeaf->m_value;
							}
						}
					}
				}
				if (*multiplier % arrItemSize == 0x0) {
					*multiplier /= arrItemSize;
					if (indexNode) {
						auto indexNodeDataType = indexNode->getDataType();
						indexNode = new SdaNode(new OperationalNode(indexNode, *it, Add));
						indexNode->setDataType(indexNodeDataType); //todo: linear expr, another type
					}
					else {
						indexNode = *it;
					}
					terms.erase(it);
				}
			}

			if (bitOffset % (arrItemSize * 0x8) == 0x0) {
				bitOffset = 0x0;
				auto constIndexNode = new SdaNode(new NumberLeaf(uint64_t(bitOffset / (arrItemSize * 0x8))));
				constIndexNode->setDataType(m_dataTypeFactory->getDefaultType(0x4));
				if (indexNode) {
					auto indexNodeDataType = indexNode->getDataType();
					indexNode = new SdaNode(new OperationalNode(indexNode, constIndexNode, Add));
					indexNode->setDataType(indexNodeDataType);
				}
				else {
					indexNode = constIndexNode;
				}
			}

			if (indexNode) {
				arrItemDataType->addPointerLevelInFront();
				sdaNode = new GoarNode(arrItemDataType, sdaNode, 0x0, indexNode, 0x0);
				return true;
			}
			return false;
		}

		void buildGoar(AbstractSdaNode* node) {
			AbstractSdaNode* baseSdaNode = node;
			int64_t bitOffset = 0x0;
			std::list<AbstractSdaNode*> terms;
			if (auto sdaNode = dynamic_cast<SdaNode*>(node)) {
				if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node)) {
					baseSdaNode = nullptr;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTerm = dynamic_cast<AbstractSdaNode*>(term)) {
							if (!baseSdaNode && sdaTerm->getDataType()->isPointer()) {
								baseSdaNode = sdaTerm;
							}
							else {
								terms.push_back(sdaTerm);
							}
						}
					}
					bitOffset = linearExpr->m_constTerm * 0x8;
				}
			}

			if (baseSdaNode) {
				auto resultGoarNode = baseSdaNode;
				while (buildGoar(resultGoarNode, bitOffset, terms));
				if (resultGoarNode != baseSdaNode) {
					if (bitOffset != 0x0 || !terms.empty()) {
						//remaining offset and terms
						auto linearExpr = new LinearExpr(bitOffset / 0x8);
						for (auto term : terms) {
							linearExpr->addTerm(term);
						}
						resultGoarNode = new SdaNode(linearExpr);
						resultGoarNode->setDataType(node->getDataType());
					}
					node->replaceWith(resultGoarNode);
					delete node;
				}
			}
		}
		
		void calculateDataTypes(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				calculateDataTypes(childNode);
				});

			if (auto sdaNode = dynamic_cast<SdaNode*>(node)) {
				auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode->m_node);
				auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode->m_node);

				if (sdaSymbolLeaf || linearExpr) {
					AbstractSdaNode* baseSdaNode = nullptr;
					int bitOffset = 0x0;

				}
				else if (auto opNode = dynamic_cast<OperationalNode*>(sdaNode->m_node)) {
					if (auto sdaLeftNode = dynamic_cast<AbstractSdaNode*>(opNode->m_leftNode)) {
						if (auto sdaRightNode = dynamic_cast<AbstractSdaNode*>(opNode->m_rightNode)) {
							sdaNode->m_calcDataType = CalculateDataType(sdaLeftNode->getDataType(), sdaRightNode->getDataType());
						}
					}
				}
				else if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaNode->m_node)) {
					if (auto dstNode = dynamic_cast<AbstractSdaNode*>(assignmentNode->getDstNode())) {
						sdaNode->m_calcDataType = dstNode->getDataType();
					}
				}

				if (sdaNode->m_calcDataType == nullptr) {
					sdaNode->m_calcDataType = m_dataTypeFactory->getDefaultType(sdaNode->m_node->getMask().getSize());
				}
				sdaNode->m_explicitCast = false;
			}
			else if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(sdaNode->m_node)) {
				if (auto dstNode = dynamic_cast<AbstractSdaNode*>(sdaFunctionNode->getDestination())) {
					if (auto signature = dynamic_cast<DataType::Signature*>(dstNode->getDataType()->getType())) {
						if (!sdaFunctionNode->getSignature()) {
							sdaFunctionNode->setSignature(signature);
						}
						int paramIdx = 1;
						for (auto paramNode : sdaFunctionNode->getParamNodes()) {
							if (auto sdaNode = dynamic_cast<AbstractSdaNode*>(paramNode)) {
								sdaFunctionNode->getTypeContext()->setParamDataType(paramIdx, sdaNode->getDataType());
							}
							paramIdx++;
						}
					}
				}
			}

			if (auto sdaNode = dynamic_cast<AbstractSdaNode*>(node)) {
				buildGoar(sdaNode);
			}
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
	};

	static void BuildSdaNodes(Node* node) {
		IterateChildNodes(node, BuildSdaNodes);

		if (dynamic_cast<Block::JumpTopNode*>(node->getParentNode()))
			return;

		auto sdaNode = new SdaNode(node);
		node->replaceWith(sdaNode);
		node->addParentNode(sdaNode);
	}

	static void SymbolizeWithSDA(SdaCodeGraph* sdaCodeGraph, UserSymbolDef& userSymbolDef) {
		for (const auto decBlock : sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
			for (auto topNode : decBlock->getAllTopNodes()) {
				BuildSdaNodes(topNode->getNode());
			}
		}

		DataTypeFactory dataTypeFactory(&userSymbolDef);
		
		SdaSymbolBuilding sdaSymbolBuilding(sdaCodeGraph, &userSymbolDef, &dataTypeFactory);
		sdaSymbolBuilding.start();

		SdaDataTypesCalculating sdaDataTypesCalculating(sdaCodeGraph, &dataTypeFactory);
		sdaDataTypesCalculating.start();
	}
};