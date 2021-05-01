#pragma once
#include "../SdaGraphModification.h"

namespace CE::Decompiler::Symbolization
{
	// Transformation from untyped raw graph to typed one (creating sda nodes)
	class SdaBuilding : public SdaGraphModification
	{
		UserSymbolDef* m_userSymbolDef;
		DataTypeFactory* m_dataTypeFactory;
		Signature::CallingConvetion m_callingConvention;
		std::map<Symbol::Symbol*, SdaSymbolLeaf*> m_replacedSymbols; //for cache purposes
		std::map<int64_t, CE::Symbol::ISymbol*> m_stackToSymbols; //stackVar1
		std::map<int64_t, CE::Symbol::ISymbol*> m_globalToSymbols; //globalVar1
		std::set<CE::Symbol::AutoSdaSymbol*> m_autoSymbols; // auto-created symbols which are not defined by user (e.g. funcVar1)
		std::set<CE::Symbol::ISymbol*> m_userDefinedSymbols; // defined by user (e.g. playerObj)
		std::map<HS::Value, std::shared_ptr<SdaFunctionNode::TypeContext>> m_funcTypeContexts; //for cache purposes
	public:

		SdaBuilding(SdaCodeGraph* sdaCodeGraph, UserSymbolDef* userSymbolDef, DataTypeFactory* dataTypeFactory, Signature::CallingConvetion callingConvention = Signature::FASTCALL)
			: SdaGraphModification(sdaCodeGraph), m_userSymbolDef(userSymbolDef), m_dataTypeFactory(dataTypeFactory), m_callingConvention(callingConvention)
		{}

		void start() override {
			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				auto node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				buildSdaNodesAndReplace(node);
				node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				node = nullptr;
				});

			addSdaSymbols();
		}

		auto& getAutoSymbols() {
			return m_autoSymbols;
		}

		auto& getUserDefinedSymbols() {
			return m_userDefinedSymbols;
		}
	private:

		// join auto symbols and user symbols together
		void addSdaSymbols() {
			for (auto sdaSymbol : m_autoSymbols) {
				m_sdaCodeGraph->getSdaSymbols().push_back(sdaSymbol);
			}

			for (auto sdaSymbol : m_userDefinedSymbols) {
				m_sdaCodeGraph->getSdaSymbols().push_back(sdaSymbol);
			}
		}

		// build high-level sda analog of low-level function node
		SdaFunctionNode* buildSdaFunctionNode(FunctionCall* funcCall) {
			std::shared_ptr<SdaFunctionNode::TypeContext> typeContext;
			/*
				TODO:
				1. Унаследовать от IMemorySymbol от FunctionSymbol(он должен содержать функцию) => будет создаваться SdaMemSymbolLeaf => будет учитываться offset
				2. Для виртуальных вызовов вычислять обычный хеш(или не вычислять вообще!)
				То есть лучше не по хешу, а по оффсету (но в общем случае dst - выражение, а не число)
			*/
			auto keyHash = funcCall->getDestination()->getHash().getHashValue();
			auto it = m_funcTypeContexts.find(keyHash);
			if (true || it == m_funcTypeContexts.end()) {
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

		// build high-level sda analog of low-level number leaf
		SdaNumberLeaf* buildSdaNumberLeaf(NumberLeaf* numberLeaf) {
			auto dataType = m_dataTypeFactory->calcDataTypeForNumber(numberLeaf->getValue());
			auto sdaNumberLeaf = new SdaNumberLeaf(numberLeaf->getValue(), dataType);
			return sdaNumberLeaf;
		}

		// build high-level sda analog of low-level read value node
		SdaReadValueNode* buildReadValueNode(ReadValueNode* readValueNode) {
			auto dataType = m_dataTypeFactory->getDefaultType(readValueNode->getSize());
			return new SdaReadValueNode(readValueNode, dataType);
		}

		// replace {node} and its childs with high-level sda analog
		void buildSdaNodesAndReplace(INode* node) {
			// first process all childs
			node->iterateChildNodes([&](INode* childNode) {
				buildSdaNodesAndReplace(childNode);
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

			// linear expr. or some symbol leaf
			auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node);
			auto linearExpr = dynamic_cast<LinearExpr*>(node);
			if (symbolLeaf || linearExpr) {
				//find symbol and offset
				int64_t offset;
				ExprTree::SymbolLeaf* sdaSymbolLeafToReplace = nullptr;

				if (symbolLeaf) {
					sdaSymbolLeafToReplace = symbolLeaf; // symbol found!
					offset = 0x0;
				}
				else if (linearExpr) {
					for (auto term : linearExpr->getTerms()) { // finding symbol among terms
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

				// if symbol has been found
				if (sdaSymbolLeafToReplace)
				{
					bool transformToGlobalOffset = false;
					bool isStackOrGlobal = false;
					//check to see if this symbol is register
					if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(sdaSymbolLeafToReplace->m_symbol)) {
						//if [rip] or [rsp] register
						if (regSymbol->m_register.isPointer()) {
							//transform to global offset
							if (regSymbol->m_register.m_type == Register::Type::InstructionPointer) {
								transformToGlobalOffset = true;
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
						//if reading presence (*(float)*{[rsp] + 0x10} -> localStackVar with size of 4 bytes, not 8)
						if (auto readValueNode = dynamic_cast<ReadValueNode*>(node->getParentNode())) {
							size = readValueNode->getSize();
						}
					}

					//before findOrCreateSymbol
					if (transformToGlobalOffset)
						offset = toGlobalOffset(offset);

					//find symbol or create it
					auto sdaSymbol = findOrCreateSymbol(sdaSymbolLeafToReplace->m_symbol, size, offset);

					//after findOrCreateSymbol
					if (transformToGlobalOffset)
						offset = toLocalOffset(offset);

					// creating sda symbol leaf (memory or normal)
					SdaSymbolLeaf* newSdaSymbolLeaf = nullptr;
					if (auto memSymbol = dynamic_cast<CE::Symbol::IMemorySymbol*>(sdaSymbol)) {
						auto storage = memSymbol->getStorage();
						if (storage.getType() == Storage::STORAGE_STACK || storage.getType() == Storage::STORAGE_GLOBAL) {
							// stackVar or globalVar
							newSdaSymbolLeaf = new SdaMemSymbolLeaf(memSymbol, sdaSymbolLeafToReplace->m_symbol, storage.getOffset(), true);
						}
					}

					if(!newSdaSymbolLeaf) {
						// localVar
						newSdaSymbolLeaf = new SdaSymbolLeaf(sdaSymbol, sdaSymbolLeafToReplace->m_symbol);
						m_replacedSymbols[sdaSymbolLeafToReplace->m_symbol] = newSdaSymbolLeaf;
					}

					//replace
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
			auto sdaNode = new SdaGenericNode(node, m_dataTypeFactory->getDefaultType(node->getMask().getSize(), false, node->isFloatingPoint()));
			node->replaceWith(sdaNode);
			node->addParentNode(sdaNode);
		}

		CE::Symbol::ISymbol* findOrCreateSymbol(Symbol::Symbol* symbol, int size, int64_t& offset) {
			if (auto sdaSymbol = loadMemSdaSymbol(symbol, offset))
				return sdaSymbol;

			//try to find corresponding function parameter if {symbol} is register (RCX -> param1, RDX -> param2)
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				int paramIdx = 0;

				if (m_userSymbolDef->m_signature) {
					paramIdx = m_userSymbolDef->m_signature->getCallInfo().findIndex(reg, offset);
					if (paramIdx > 0) {
						auto& funcParams = m_userSymbolDef->m_signature->getParameters();
						if (paramIdx <= funcParams.size()) {
							//USER-DEFINED func. parameter
							auto sdaSymbol = funcParams[paramIdx - 1];
							storeMemSdaSymbol(sdaSymbol, symbol, offset);
							m_userDefinedSymbols.insert(sdaSymbol);
							return sdaSymbol;
						}
					}
				}
				else {
					if (m_callingConvention == Signature::FASTCALL) {
						paramIdx = GetIndex_FASTCALL(reg, offset);
					}
				}

				if (paramIdx > 0) {
					//auto func. parameter
					auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::FUNC_PARAMETER, "param" + std::to_string(paramIdx), paramIdx, size);
					storeMemSdaSymbol(sdaSymbol, symbol, offset);
					return sdaSymbol;
				}

				//MEMORY symbol with offset (e.g. globalVar1)
				if (reg.m_type == Register::Type::StackPointer)
					return createMemorySymbol(m_userSymbolDef->m_stackSymbolTable, CE::Symbol::LOCAL_STACK_VAR, "stack", symbol, offset, size);
				else if (reg.m_type == Register::Type::InstructionPointer)
					return createMemorySymbol(m_userSymbolDef->m_globalSymbolTable, CE::Symbol::GLOBAL_VAR, "global", symbol, offset, size);

				//NOT-MEMORY symbol (unknown registers)
				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, "in_" + reg.printDebug(), 0, size);
				return sdaSymbol;
			}

			//try to find USER-DEFINED symbol associated with some instruction
			std::list<int64_t> instrOffsets; //instruction offsets helps to identify user-defined symbols
			if (auto symbolRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(symbol)) {
				for (auto instr : symbolRelToInstr->getInstructionsRelatedTo()) {
					instrOffsets.push_back(instr->getOffset());
				}

				if (!instrOffsets.empty()) {
					for (auto instrOffset : instrOffsets) {
						auto symbolPair = m_userSymbolDef->m_funcBodySymbolTable->getSymbolAt(instrOffset);
						if (symbolPair.second != nullptr) {
							auto sdaSymbol = symbolPair.second;
							m_userDefinedSymbols.insert(sdaSymbol);
							return sdaSymbol;
						}
					}
				}
			}

			//otherwise create AUTO sda not-memory symbol (e.g. funcVar1)
			if (auto symbolWithId = dynamic_cast<Symbol::AbstractVariable*>(symbol)) {
				std::string suffix = "local";
				if (dynamic_cast<Symbol::MemoryVariable*>(symbol))
					suffix = "mem";
				else if (dynamic_cast<Symbol::FunctionResultVar*>(symbol))
					suffix = "func";
				auto sdaSymbol = createAutoSdaSymbol(CE::Symbol::LOCAL_INSTR_VAR, suffix + "Var" + Generic::String::NumberToHex(symbolWithId->getId()), 0, size, instrOffsets);
				return sdaSymbol;
			}
			return nullptr;
		}

		CE::Symbol::ISymbol* createMemorySymbol(CE::Symbol::SymbolTable* memoryArea, CE::Symbol::Type type, const std::string& name, Symbol::Symbol* symbol, int64_t& offset, int size) {
			//try to find USER-DEFINED symbol in mem. area
			auto symbolPair = memoryArea->getSymbolAt(offset);
			if (symbolPair.second != nullptr) {
				offset -= symbolPair.first;
				auto sdaSymbol = symbolPair.second;
				m_userDefinedSymbols.insert(sdaSymbol);
				return sdaSymbol;
			}

			uint64_t offsetView = offset;
			if (memoryArea->getType() == CE::Symbol::SymbolTable::STACK_SPACE)
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

		// load stack or global memory symbol by decompiler symbol (RSP/RIP) and offset
		CE::Symbol::ISymbol* loadMemSdaSymbol(Symbol::Symbol* symbol, int64_t& offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.m_type == Register::Type::StackPointer) {
					auto it = m_stackToSymbols.find(offset);
					if (it != m_stackToSymbols.end()) {
						offset = 0x0;
						return it->second;
					}
				}
				else if (reg.m_type == Register::Type::InstructionPointer) {
					auto it = m_globalToSymbols.find(offset);
					if (it != m_globalToSymbols.end()) {
						offset = toGlobalOffset(0x0);
						return it->second;
					}
				}
			}
			return nullptr;
		}

		// store stack or global memory symbol by decompiler symbol (RSP/RIP) and offset
		void storeMemSdaSymbol(CE::Symbol::ISymbol* sdaSymbol, Symbol::Symbol* symbol, int64_t& offset) {
			if (auto regSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbol)) {
				auto& reg = regSymbol->m_register;
				if (reg.m_type == Register::Type::StackPointer) {
					m_stackToSymbols[offset] = sdaSymbol;
					offset = 0x0;
					return;
				}
				else if (reg.m_type == Register::Type::InstructionPointer) {
					m_globalToSymbols[offset] = sdaSymbol;
					offset = toGlobalOffset(0x0);
					return;
				}
				//todo: for other...
			}
		}

		int64_t toGlobalOffset(int64_t offset) {
			return m_userSymbolDef->m_startOffset + offset;
		}

		int64_t toLocalOffset(int64_t offset) {
			return offset - m_userSymbolDef->m_startOffset;
		}
	};
};