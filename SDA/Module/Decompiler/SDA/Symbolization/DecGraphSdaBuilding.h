#pragma once
#include "../DecGraphModification.h"

namespace CE::Decompiler::Symbolization
{
	class SdaBuilding : public SdaGraphModification
	{
	public:
		SdaBuilding(SdaCodeGraph* sdaCodeGraph, UserSymbolDef* userSymbolDef, DataTypeFactory* dataTypeFactory)
			: SdaGraphModification(sdaCodeGraph), m_userSymbolDef(userSymbolDef), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() override {
			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				auto node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				buildSdaNodes(node);
				node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				node = nullptr;
				});

			addSdaSymbols();
		}
	private:
		UserSymbolDef* m_userSymbolDef;
		DataTypeFactory* m_dataTypeFactory;
		std::map<Symbol::Symbol*, SdaSymbolLeaf*> m_replacedSymbols;
		std::map<int64_t, CE::Symbol::ISymbol*> m_stackToSymbols;
		std::map<int64_t, CE::Symbol::ISymbol*> m_globalToSymbols;
		std::set<CE::Symbol::ISymbol*> m_autoSymbols;
		std::set<CE::Symbol::ISymbol*> m_userDefinedSymbols;
		std::map<ObjectHash::Hash, std::shared_ptr<SdaFunctionNode::TypeContext>> m_funcTypeContexts;

		void addSdaSymbols() {
			for (auto sdaSymbol : m_autoSymbols) {
				m_sdaCodeGraph->getSdaSymbols().push_back(sdaSymbol);
			}

			for (auto sdaSymbol : m_userDefinedSymbols) {
				m_sdaCodeGraph->getSdaSymbols().push_back(sdaSymbol);
			}
		}

		SdaFunctionNode* buildSdaFunctionNode(FunctionCall* funcCall) {
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
				typeContext = std::make_shared<SdaFunctionNode::TypeContext>(paramTypes, returnType);
				m_funcTypeContexts[keyHash] = typeContext;
			}
			else {
				typeContext = it->second;
			}

			return new SdaFunctionNode(funcCall, typeContext);
		}

		SdaNumberLeaf* buildSdaNumberLeaf(NumberLeaf* numberLeaf) {
			auto dataType = m_dataTypeFactory->getDataTypeByNumber(numberLeaf->getValue());
			auto sdaNumberLeaf = new SdaNumberLeaf(numberLeaf->getValue(), dataType);
			return sdaNumberLeaf;
		}

		SdaReadValueNode* buildReadValueNode(ReadValueNode* readValueNode) {
			auto dataType = m_dataTypeFactory->getDefaultType(readValueNode->getSize());
			return new SdaReadValueNode(readValueNode, dataType);
		}

		void buildSdaNodes(INode* node) {
			IterateChildNodes(node, [&](INode* childNode) {
				buildSdaNodes(childNode);
				});

			if (dynamic_cast<SdaSymbolLeaf*>(node))
				return;

			if (auto readValueNode = dynamic_cast<ReadValueNode*>(node)) {
				auto sdaReadValueNode = buildReadValueNode(readValueNode);
				readValueNode->replaceWith(sdaReadValueNode);
				readValueNode->addParentNode(sdaReadValueNode);
				return;
			}

			if (auto funcCall = dynamic_cast<FunctionCall*>(node)) {
				auto functionNode = buildSdaFunctionNode(funcCall);
				funcCall->replaceWith(functionNode);
				funcCall->addParentNode(functionNode);
				return;
			}

			if (auto numberLeaf = dynamic_cast<NumberLeaf*>(node)) {
				auto sdaNumberLeaf = buildSdaNumberLeaf(numberLeaf);
				numberLeaf->replaceWith(sdaNumberLeaf);
				delete numberLeaf;
				return;
			}

			auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node);
			auto linearExpr = dynamic_cast<LinearExpr*>(node);
			if (symbolLeaf || linearExpr) {
				//find symbol and offset
				int64_t offset;
				ExprTree::SymbolLeaf* sdaSymbolLeafToReplace = nullptr;

				if (symbolLeaf) {
					sdaSymbolLeafToReplace = symbolLeaf;
					offset = 0x0;
				}
				else if (linearExpr) {
					for (auto term : linearExpr->getTerms()) {
						if (auto termSymbolLeaf = dynamic_cast<SymbolLeaf*>(term)) {
							if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(termSymbolLeaf->m_symbol)) {
								if (regSymbol->m_register.isPointer()) {
									sdaSymbolLeafToReplace = termSymbolLeaf;
									offset = linearExpr->getConstTermValue();
									break;
								}
							}
						}
					}
				}

				if (sdaSymbolLeafToReplace)
				{
					bool transformToLocalOffset = false;
					bool isStackOrGlobal = false;
					//check to see if it is [rsp] or [rip]
					if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(sdaSymbolLeafToReplace->m_symbol)) {
						//if [rip] or [rsp] register
						if (regSymbol->m_register.isPointer()) {
							//transform to global offset
							if (regSymbol->m_register.getGenericId() == ZYDIS_REGISTER_RIP) {
								transformToLocalOffset = true;
							}
							isStackOrGlobal = true;
						}
					}

					//not to find repeatly
					if (!isStackOrGlobal) {
						auto it = m_replacedSymbols.find(sdaSymbolLeafToReplace->m_symbol);
						if (it != m_replacedSymbols.end()) {
							NodeCloneContext ctx;
							sdaSymbolLeafToReplace->replaceWith(it->second->clone(&ctx));
							delete sdaSymbolLeafToReplace;
							return;
						}
					}

					//default size
					auto size = sdaSymbolLeafToReplace->m_symbol->getSize();
					//calculate size
					if (isStackOrGlobal) {
						//handle later anyway
						if (dynamic_cast<LinearExpr*>(node->getParentNode()))
							return;
						//if reading presence
						if (auto readValueNode = dynamic_cast<ReadValueNode*>(node->getParentNode())) {
							size = readValueNode->getSize();
						}
					}

					//before findOrCreateSymbol
					if (transformToLocalOffset)
						offset = toGlobalOffset(offset);

					//find symbol or create it
					auto sdaSymbol = findOrCreateSymbol(sdaSymbolLeafToReplace->m_symbol, size, offset);

					//after findOrCreateSymbol
					if (transformToLocalOffset)
						offset = toLocalOffset(offset);

					//replace
					SdaSymbolLeaf* newSdaSymbolLeaf;
					if (auto memSymbol = dynamic_cast<CE::Symbol::IMemorySymbol*>(sdaSymbol)) {
						newSdaSymbolLeaf = new SdaMemSymbolLeaf(memSymbol, sdaSymbolLeafToReplace->m_symbol, true);
					}
					else {
						newSdaSymbolLeaf = new SdaSymbolLeaf(sdaSymbol, sdaSymbolLeafToReplace->m_symbol);
						m_replacedSymbols[sdaSymbolLeafToReplace->m_symbol] = newSdaSymbolLeaf;
					}
					sdaSymbolLeafToReplace->replaceWith(newSdaSymbolLeaf);
					delete sdaSymbolLeafToReplace;

					if (symbolLeaf)
						return;
					if (linearExpr) {
						//if it is not array with offset is zero
						if (offset == 0x0 && linearExpr->getTerms().size() == 1) {
							linearExpr->replaceWith(newSdaSymbolLeaf);
							delete linearExpr;
							return;
						}
						//change offset
						linearExpr->setConstTermValue(offset);
					}
				}
			}

			if (dynamic_cast<Block::JumpTopNode*>(node->getParentNode()))
				return;

			//otherwise create generic sda node
			auto sdaNode = new SdaGenericNode(node, m_dataTypeFactory->getDefaultType(node->getMask().getSize()));
			node->replaceWith(sdaNode);
			node->addParentNode(sdaNode);
		}

		CE::Symbol::ISymbol* findOrCreateSymbol(Symbol::Symbol* symbol, int size, int64_t& offset) {
			if (auto sdaSymbol = loadMemSdaSymbol(symbol, offset))
				return sdaSymbol;

			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				int paramIdx = 0;
				auto& reg = regSymbol->m_register;
				auto paramInfos = m_sdaCodeGraph->getDecGraph()->getFunctionCallInfo().getParamInfos();
				for (auto paramInfo : paramInfos) {
					auto& storage = paramInfo.m_storage;
					if (storage.getType() == Storage::STORAGE_REGISTER && reg.getGenericId() == storage.getRegisterId() || (offset == storage.getOffset() &&
						(storage.getType() == Storage::STORAGE_STACK && reg.getGenericId() == ZYDIS_REGISTER_RSP ||
							storage.getType() == Storage::STORAGE_GLOBAL && reg.getGenericId() == ZYDIS_REGISTER_RIP))) {
						paramIdx = storage.getIndex();
						break;
					}
				}

				if (paramIdx != 0) {
					auto& funcParams = m_userSymbolDef->m_signature->getParameters();
					if (paramIdx <= funcParams.size()) {
						auto sdaSymbol = funcParams[paramIdx - 1];
						storeMemSdaSymbol(sdaSymbol, symbol, offset);
						m_userDefinedSymbols.insert(sdaSymbol);
						return sdaSymbol;
					}
					auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::FUNC_PARAMETER, "param" + std::to_string(paramIdx), paramIdx, size);
					storeMemSdaSymbol(sdaSymbol, symbol, offset);
					return sdaSymbol;
				}

				//memory symbol with offset possibly to be changed
				if (reg.getGenericId() == ZYDIS_REGISTER_RSP)
					return createMemorySymbol(m_userSymbolDef->m_stackMemoryArea, CE::Symbol::LOCAL_STACK_VAR, "stack", symbol, offset, size);
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP)
					return createMemorySymbol(m_userSymbolDef->m_globalMemoryArea, CE::Symbol::GLOBAL_VAR, "global", symbol, offset, size);

				//not memory symbol (unknown registers)
				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, "in_" + reg.printDebug(), 0, size);
				return sdaSymbol;
			}

			//try find user defined symbol associated with some instruction
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
							m_userDefinedSymbols.insert(sdaSymbol);
							return sdaSymbol;
						}
					}
				}
			}

			//otherwise create auto sda symbol
			if (auto symbolWithId = dynamic_cast<Symbol::SymbolWithId*>(symbol)) {
				std::string suffix = "local";
				if (dynamic_cast<Symbol::MemoryVariable*>(symbol))
					suffix = "mem";
				else if (dynamic_cast<Symbol::FunctionResultVar*>(symbol))
					suffix = "func";
				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, suffix + "Var" + std::to_string(symbolWithId->getId()), 0, size, instrOffsets);
				return sdaSymbol;
			}
			return nullptr;
		}

		CE::Symbol::ISymbol* createMemorySymbol(CE::Symbol::MemoryArea* memoryArea, CE::Symbol::Type type, const std::string& name, Symbol::Symbol* symbol, int64_t& offset, int size) {
			auto symbolPair = memoryArea->getSymbolAt(offset);
			if (symbolPair.second != nullptr) {
				offset -= symbolPair.first;
				auto sdaSymbol = symbolPair.second;
				m_userDefinedSymbols.insert(sdaSymbol);
				return sdaSymbol;
			}

			uint64_t offsetView = offset;
			if (memoryArea->getType() == CE::Symbol::MemoryArea::STACK_SPACE)
				offsetView = (uint32_t)-offset;

			auto sdaSymbol = createAutoSdaSymbol(type, name + "_0x" + Generic::String::NumberToHex(offsetView), offset, size);
			storeMemSdaSymbol(sdaSymbol, symbol, offset);
			return sdaSymbol;
		}

		CE::Symbol::AutoSdaSymbol* createAutoSdaSymbol(CE::Symbol::Type type, const std::string& name, int64_t value, int size, std::list<int64_t> instrOffsets = {}) {
			auto dataType = m_dataTypeFactory->getDefaultType(size);
			auto symbolManager = m_userSymbolDef->m_programModule->getSymbolManager();
			CE::Symbol::AutoSdaSymbol* sdaSymbol;
			if (type == CE::Symbol::LOCAL_STACK_VAR || type == CE::Symbol::GLOBAL_VAR) {
				sdaSymbol = new CE::Symbol::AutoSdaMemSymbol(type, value, instrOffsets, symbolManager, dataType, name);
			}
			else {
				sdaSymbol = new CE::Symbol::AutoSdaSymbol(type, value, instrOffsets, symbolManager, dataType, name);
			}
			m_autoSymbols.insert(sdaSymbol);
			return sdaSymbol;
		}

		CE::Symbol::ISymbol* loadMemSdaSymbol(Symbol::Symbol* symbol, int64_t& offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.getGenericId() == ZYDIS_REGISTER_RSP) {
					auto it = m_stackToSymbols.find(offset);
					if (it != m_stackToSymbols.end()) {
						offset = 0x0;
						return it->second;
					}
				}
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP) {
					auto it = m_globalToSymbols.find(offset);
					if (it != m_globalToSymbols.end()) {
						offset = toGlobalOffset(0x0);
						return it->second;
					}
				}
			}
			return nullptr;
		}

		void storeMemSdaSymbol(CE::Symbol::ISymbol* sdaSymbol, Symbol::Symbol* symbol, int64_t& offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.getGenericId() == ZYDIS_REGISTER_RSP) {
					m_stackToSymbols[offset] = sdaSymbol;
					offset = 0x0;
					return;
				}
				else if (reg.getGenericId() == ZYDIS_REGISTER_RIP) {
					m_globalToSymbols[offset] = sdaSymbol;
					offset = toGlobalOffset(0x0);
					return;
				}
			}
		}

		int64_t toGlobalOffset(int64_t offset) {
			return m_userSymbolDef->m_offset + offset;
		}

		int64_t toLocalOffset(int64_t offset) {
			return offset - m_userSymbolDef->m_offset;
		}
	};
};