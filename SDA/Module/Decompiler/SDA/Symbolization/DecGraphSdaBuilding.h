#pragma once
#include "DecSdaMisc.h"

namespace CE::Decompiler::Symbolization
{
	class SdaBuilding
	{
	public:
		SdaBuilding(SdaCodeGraph* sdaCodeGraph, UserSymbolDef* userSymbolDef, DataTypeFactory* dataTypeFactory)
			: m_sdaCodeGraph(sdaCodeGraph), m_userSymbolDef(userSymbolDef), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() {
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					Node::UpdateDebugInfo(topNode->getNode());
					buildSdaNodes(topNode->getNode());
				}
			}

			addSdaSymbols();
		}
	private:
		SdaCodeGraph* m_sdaCodeGraph;
		UserSymbolDef* m_userSymbolDef;
		DataTypeFactory* m_dataTypeFactory;
		std::map<int64_t, CE::Symbol::AbstractSymbol*> m_stackToSymbols;
		std::map<int64_t, CE::Symbol::AbstractSymbol*> m_globalToSymbols;
		std::set<CE::Symbol::AbstractSymbol*> m_autoSymbols;
		std::set<CE::Symbol::AbstractSymbol*> m_userDefinedSymbols;
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

		void buildSdaNodes(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				buildSdaNodes(childNode);
				});

			if (dynamic_cast<SdaSymbolLeaf*>(node))
				return;

			if (auto funcCall = dynamic_cast<FunctionCall*>(node)) {
				auto functionNode = buildSdaFunctionNode(funcCall);
				funcCall->replaceWith(functionNode);
				funcCall->addParentNode(functionNode);
				return;
			}

			if (auto numberLeaf = dynamic_cast<NumberLeaf*>(node)) {
				auto sdaNumberLeaf = new SdaNumberLeaf(numberLeaf->getValue(), m_dataTypeFactory->getDataTypeByNumber(numberLeaf->getValue()));
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
					//calculate size
					int size = 0x0;
					bool transformToLocalOffset = false;
					bool isStackOrGlobal = false;
					if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(sdaSymbolLeafToReplace->m_symbol)) {
						//if [rip] or [rsp] register
						if (regSymbol->m_register.isPointer()) {
							//transform to global offset
							if (regSymbol->m_register.getGenericId() == ZYDIS_REGISTER_RIP) {
								offset = toGlobalOffset(offset);
								transformToLocalOffset = true;
							}
							isStackOrGlobal = true;
						}
					}
					if (isStackOrGlobal) {
						//handle later anyway
						if (dynamic_cast<LinearExpr*>(node->getParentNode()))
							return;
						//if reading presence
						if (auto readValueNode = dynamic_cast<ReadValueNode*>(node->getParentNode())) {
							size = readValueNode->getSize();
						}
					}
					if (size == 0x0) {
						size = sdaSymbolLeafToReplace->m_symbol->getSize();
					}

					//find symbol or create it
					auto sdaSymbol = findOrCreateSymbol(sdaSymbolLeafToReplace->m_symbol, size, offset);
					if (transformToLocalOffset)
						offset = toLocalOffset(offset);

					if (isStackOrGlobal) {
						sdaSymbolLeafToReplace->replaceWith(new SdaSymbolLeaf(sdaSymbol, true));
						delete sdaSymbolLeafToReplace;
					}
					else {
						//replace all symbol leafs including the current
						for (auto symbolLeaf : sdaSymbolLeafToReplace->m_symbol->m_symbolLeafs) {
							symbolLeaf->replaceWith(new SdaSymbolLeaf(sdaSymbol));
							delete symbolLeaf;
						}
					}
					if (symbolLeaf)
						return;
					if (linearExpr) {
						//change offset
						linearExpr->setConstTermValue(offset);
					}
				}
			}

			if (auto readValueNode = dynamic_cast<ReadValueNode*>(node)) {
				if (auto addrGenNode = dynamic_cast<SdaGenericNode*>(readValueNode->getAddress())) {
					if (auto linearExpr = dynamic_cast<LinearExpr*>(addrGenNode->getNode())) {
						//if it is not array with offset is zero
						if (linearExpr->getConstTermValue() == 0x0 && linearExpr->getTerms().size() == 1) {
							if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(*linearExpr->getTerms().begin())) {
								sdaSymbolLeaf->m_isGettingAddr = false;
								readValueNode->replaceWith(sdaSymbolLeaf);
								delete readValueNode;
								return;
							}
						}
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

		CE::Symbol::AbstractSymbol* findOrCreateSymbol(Symbol::Symbol* symbol, int size, int64_t& offset) {
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

		CE::Symbol::AbstractSymbol* createMemorySymbol(CE::Symbol::MemoryArea* memoryArea, CE::Symbol::Type type, const std::string& name, Symbol::Symbol* symbol, int64_t& offset, int size) {
			auto symbolPair = memoryArea->getSymbolAt(offset);
			if (symbolPair.second != nullptr) {
				offset -= symbolPair.first;
				auto sdaSymbol = symbolPair.second;
				m_userDefinedSymbols.insert(sdaSymbol);
				return sdaSymbol;
			}
			auto sdaSymbol = createAutoSdaSymbol(type, name + "_0x" + Generic::String::NumberToHex((uint32_t)-offset), offset, size);
			storeMemSdaSymbol(sdaSymbol, symbol, offset);
			return sdaSymbol;
		}

		CE::Symbol::AutoSdaSymbol* createAutoSdaSymbol(CE::Symbol::Type type, const std::string& name, int64_t value, int size, std::list<int64_t> instrOffsets = {}) {
			auto dataType = m_dataTypeFactory->getDefaultType(size);
			auto sdaSymbol = new CE::Symbol::AutoSdaSymbol(type, value, instrOffsets, m_userSymbolDef->m_programModule->getSymbolManager(), dataType, name);
			m_autoSymbols.insert(sdaSymbol);
			return sdaSymbol;
		}

		CE::Symbol::AbstractSymbol* loadMemSdaSymbol(Symbol::Symbol* symbol, int64_t& offset) {
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

		void storeMemSdaSymbol(CE::Symbol::AbstractSymbol* sdaSymbol, Symbol::Symbol* symbol, int64_t& offset) {
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