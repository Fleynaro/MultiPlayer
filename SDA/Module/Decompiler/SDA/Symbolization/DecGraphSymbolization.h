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
		DataTypeFactory(CE::ProgramModule* programModule)
			: m_programModule(programModule)
		{}

		DataTypePtr getType(DB::Id id) {
			return DataType::GetUnit(m_programModule->getTypeManager()->getTypeById(id));
		}

		DataTypePtr getDefaultType(int size, bool sign = false) {
			if (size == 0x1)
				return getType(sign ? SystemType::Char : SystemType::Byte);
			if (size == 0x2)
				return getType(sign ? SystemType::Int16 : SystemType::UInt16);
			if (size == 0x4)
				return getType(sign ? SystemType::Int32 : SystemType::UInt32);
			if (size == 0x8)
				return getType(sign ? SystemType::Int64 : SystemType::UInt64);
			return nullptr;
		}

		DataTypePtr getDataTypeByNumber(uint64_t value) {
			return getDataTypeByMask(value | uint64_t(0xFFFFFFFF));
		}

		DataTypePtr getDataTypeByMask(BitMask64 mask) {
			static BitMask64 checkMaskList[8] = {
				uint64_t(0xEF), uint64_t(0xFF),
				uint64_t(0xEFFF), uint64_t(0xFFFF),
				uint64_t(0xEFFFFFFF), uint64_t(0xFFFFFFFF),
				uint64_t(0xEFFFFFFFFFFFFFFF), uint64_t(0xFFFFFFFFFFFFFFFF)
			};

			for (int i = 0, size = 1; i < 8; i++) {
				if ((mask & ~checkMaskList[i]).getValue() == 0) {
					return getDefaultType(size, (i % 2) != 0);
				}
				if ((i % 2) != 0)
					size *= 2;
			}
			return nullptr;
		}
	private:
		CE::ProgramModule* m_programModule;
	};

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
				auto sdaNumberLeaf = new SdaNumberLeaf(numberLeaf->m_value, m_dataTypeFactory->getDataTypeByNumber(numberLeaf->m_value));
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
									offset = linearExpr->m_constTerm;
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
						linearExpr->m_constTerm = offset;
					}
				}
			}

			if (auto readValueNode = dynamic_cast<ReadValueNode*>(node)) {
				if (auto addrGenNode = dynamic_cast<SdaGenericNode*>(readValueNode->getAddress())) {
					if (auto linearExpr = dynamic_cast<LinearExpr*>(addrGenNode->getNode())) {
						//if it is not array with offset is zero
						if (linearExpr->m_constTerm == 0x0 && linearExpr->getTerms().size() == 1) {
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
								storage.getType() == Storage::STORAGE_GLOBAL && reg.getGenericId() == ZYDIS_REGISTER_RIP)) ) {
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
			//check to see if the data type is a pointer
			if (ptrLevels.empty())
				return false;
			if (*ptrLevels.begin() != 1)
				return false;
			ptrLevels.pop_front();

			//remove the pointer and see what we have
			auto baseDataType = dataType->getBaseType();
			if (ptrLevels.empty()) {
				//try making a field
				if (auto structure = dynamic_cast<DataType::Structure*>(baseDataType)) {
					auto field = structure->getField((int)bitOffset);
					auto dataType = DataType::CloneUnit(field->getDataType());
					dataType->addPointerLevelInFront();
					sdaNode = new GoarNode(dataType, sdaNode, field->getAbsBitOffset(), nullptr, 0x0);
					bitOffset -= field->getAbsBitOffset();
					return true;
				}
				return false;
			}
			
			//try making an array
			//important: array is like a structure with stored items can be linearly addressed
			//if it is array, not pointer (like a structure, an array item like a field)
			if (*ptrLevels.begin() != 1)
				ptrLevels.pop_front();
			auto arrItemDataType = DataType::GetUnit(baseDataType, ptrLevels);
			auto arrItemSize = arrItemDataType->getSize();

			AbstractSdaNode* indexNode = nullptr;
			int indexSize = 0x4; //todo: long long(8 bytes) index?
			for (auto it = terms.begin(); it != terms.end(); it ++) {
				auto sdaNode = *it;
				int64_t defMultiplier = 1;
				int64_t* multiplier = &defMultiplier;
				if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
						if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(opNode->m_rightNode)) {
							if (opNode->m_operation == Mul) {
								multiplier = (int64_t*)&sdaNumberLeaf->m_value;
							}
						}
					}
				}
				if (*multiplier % arrItemSize == 0x0) {
					*multiplier /= arrItemSize;
					if (*multiplier == 1) {
						//optimization: remove operational node (add)
						if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
							if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
								if (auto leftSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_leftNode)) {
									sdaGenTermNode->replaceWith(sdaNode = leftSdaNode);
									delete sdaGenTermNode;
								}
							}
						}
					}

					if (indexNode) {
						auto indexNodeDataType = indexNode->getDataType();
						indexNode = new SdaGenericNode(new OperationalNode(indexNode, sdaNode, Add, BitMask64(indexSize)), indexNodeDataType); //todo: linear expr, another type
					}
					else {
						indexNode = sdaNode;
					}
					terms.erase(it);
				}
			}

			if (bitOffset != 0x0) {
				auto arrItemBitSize = arrItemSize * 0x8;
				auto constIndex = bitOffset / arrItemBitSize;
				if (constIndex != 0x0 || !indexNode) {
					bitOffset = bitOffset % arrItemBitSize;
					auto constIndexNode = new SdaNumberLeaf(uint64_t(constIndex));
					constIndexNode->setDataType(m_dataTypeFactory->getDefaultType(indexSize)); //need?
					if (indexNode) {
						auto indexNodeDataType = indexNode->getDataType();
						indexNode = new SdaGenericNode(new OperationalNode(indexNode, constIndexNode, Add, BitMask64(indexSize)), indexNodeDataType);
					}
					else {
						indexNode = constIndexNode;
					}
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
			std::list<AbstractSdaNode*> sdaTerms;
			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(node)) {
				if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) {
					baseSdaNode = nullptr;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTerm = dynamic_cast<AbstractSdaNode*>(term)) {
							if (!baseSdaNode && sdaTerm->getDataType()->isPointer()) {
								baseSdaNode = sdaTerm;
							}
							else {
								sdaTerms.push_back(sdaTerm);
							}
						}
					}
					bitOffset = linearExpr->m_constTerm * 0x8;
				}
			}

			if (baseSdaNode) {
				auto resultSdaNode = baseSdaNode;
				while (buildGoar(resultSdaNode, bitOffset, sdaTerms));
				if (auto resultGoarNode = dynamic_cast<GoarNode*>(resultSdaNode)) {
					if (bitOffset != 0x0 || !sdaTerms.empty()) {
						//remaining offset and terms (maybe only in case of node being as LinearExpr)
						auto linearExpr = new LinearExpr(bitOffset / 0x8);
						for (auto castTerm : sdaTerms) {
							linearExpr->addTerm(castTerm);
						}
						resultSdaNode = new SdaGenericNode(linearExpr, node->getDataType());
					}
					
					node->replaceWith(resultSdaNode);
					delete node;
				}
			}
		}
		
		void calculateDataTypes(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				calculateDataTypes(childNode);
				});

			auto sdaNode = dynamic_cast<AbstractSdaNode*>(node);
			if (!sdaNode)
				return;
			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(sdaNode))
			{
				if (auto castNode = dynamic_cast<CastNode*>(sdaGenNode->getNode())) {
					if (auto srcSdaNode = dynamic_cast<AbstractSdaNode*>(castNode->getNode())) {
						auto srcDataType = srcSdaNode->getDataType();
						auto srcBaseDataType = srcDataType->getBaseType();
						auto castDataType = m_dataTypeFactory->getDefaultType(castNode->getSize(), castNode->isSigned());
						sdaGenNode->setDataType(castDataType);
						if (srcDataType->isPointer() || castNode->isSigned() != srcBaseDataType->isSigned() || castNode->getSize() != srcBaseDataType->getSize()) {
							srcSdaNode->setCastDataType(
								castDataType, isExplicitCast(srcDataType, castDataType));
						}
					}
				}
				else if (auto readValueNode = dynamic_cast<ReadValueNode*>(sdaGenNode->getNode())) {
					if (auto addrSdaNode = dynamic_cast<AbstractSdaNode*>(readValueNode->getAddress())) {
						auto addrDataType = addrSdaNode->getDataType();
						if (addrDataType->isPointer() && readValueNode->getSize() == addrDataType->getBaseType()->getSize()) {
							auto resultDataType = DataType::CloneUnit(addrDataType);
							resultDataType->removePointerLevelOutOfFront();
							if (auto addrGoarNode = dynamic_cast<GoarNode*>(addrSdaNode)) {
								addrGoarNode->m_isReading = true;
								addrGoarNode->setDataType(resultDataType);
								sdaGenNode->replaceWith(addrGoarNode);
								delete sdaGenNode;
								return;
							}
							else {
								sdaGenNode->setDataType(resultDataType);
							}
						} else {
							auto defPtrDataType = m_dataTypeFactory->getDefaultType(readValueNode->getSize());
							defPtrDataType->addPointerLevelInFront();
							addrSdaNode->setCastDataType(
								defPtrDataType, isExplicitCast(addrDataType, defPtrDataType));
							sdaGenNode->setDataType(defPtrDataType);
						}
					}
				}
				else if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenNode->getNode())) {
					auto maskSize = opNode->getMask().getSize();
					if (auto sdaLeftSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_leftNode)) {
						if (auto sdaRightSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_rightNode)) {
							DataTypePtr leftNodeDataType = sdaLeftSdaNode->getDataType();
							DataTypePtr rightNodeDataType;
							if (opNode->m_operation == Shr || opNode->m_operation == Shl) {
								rightNodeDataType = leftNodeDataType;
							}
							else {
								rightNodeDataType = sdaRightSdaNode->getDataType();
							}
							auto calcDataType = getDataTypeToCastTo(sdaLeftSdaNode->getDataType(), sdaRightSdaNode->getDataType());
							if (maskSize != calcDataType->getSize())
								calcDataType = m_dataTypeFactory->getDefaultType(maskSize);
							sdaLeftSdaNode->setCastDataType(
								calcDataType, isExplicitCast(leftNodeDataType, calcDataType));
							sdaRightSdaNode->setCastDataType(
								calcDataType, isExplicitCast(rightNodeDataType, calcDataType));
							sdaGenNode->setDataType(calcDataType);
						}
					}
				}
				else if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) {
					auto maskSize = linearExpr->getMask().getSize();
					DataTypePtr calcDataType = m_dataTypeFactory->getDataTypeByNumber((uint64_t&)linearExpr->m_constTerm);
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<AbstractSdaNode*>(term)) {
							calcDataType = getDataTypeToCastTo(calcDataType, sdaTermNode->getDataType());
						}
					}
					if (maskSize != calcDataType->getSize())
						calcDataType = m_dataTypeFactory->getDefaultType(maskSize);

					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<AbstractSdaNode*>(term)) {
							sdaTermNode->setCastDataType(
								calcDataType, isExplicitCast(sdaTermNode->getDataType(), calcDataType));
						}
					}
					sdaGenNode->setDataType(calcDataType);
				}
				else if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
					if (auto dstSdaNode = dynamic_cast<AbstractSdaNode*>(assignmentNode->getDstNode())) {
						if (auto srcSdaNode = dynamic_cast<AbstractSdaNode*>(assignmentNode->getSrcNode())) {
							auto dstNodeDataType = dstSdaNode->getDataType();
							auto srcNodeDataType = srcSdaNode->getDataType();
							
							bool autoSdaSymbolDataTypeChanged = false;
							if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(dstSdaNode)) {
								if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
									if (dstNodeDataType->getSize() == srcNodeDataType->getSize() && dstNodeDataType->getPriority() < srcNodeDataType->getPriority()) {
										autoSdaSymbol->setDataType(srcNodeDataType);
										autoSdaSymbolDataTypeChanged = true;
									}
								}
							}
							if (!autoSdaSymbolDataTypeChanged) {
								srcSdaNode->setCastDataType(
									dstNodeDataType, isExplicitCast(srcNodeDataType, dstNodeDataType));
								sdaGenNode->setDataType(dstNodeDataType);
							}
						}
					}
				}
				else if (auto condNode = dynamic_cast<ICondition*>(sdaGenNode->getNode())) {
					auto boolType = m_dataTypeFactory->getType(SystemType::Bool);
					sdaGenNode->setDataType(boolType);
				}
			}
			else if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(sdaNode)) {
				if (auto dstCastNode = dynamic_cast<AbstractSdaNode*>(sdaFunctionNode->getDestination())) {
					if (auto signature = dynamic_cast<DataType::Signature*>(dstCastNode->getDataType()->getType())) {
						if (!sdaFunctionNode->getSignature()) {
							sdaFunctionNode->setSignature(signature);
						}
					}
				}

				int paramIdx = 1;
				for (auto paramNode : sdaFunctionNode->getParamNodes()) {
					if (auto paramCastNode = dynamic_cast<AbstractSdaNode*>(paramNode)) {
						auto paramNodeDataType = paramCastNode->getDataType();
						if (sdaFunctionNode->getSignature()) {
							auto paramNodeProperDataType = sdaFunctionNode->getParamDataType(paramIdx);
							paramCastNode->setCastDataType(
								paramNodeProperDataType, isExplicitCast(paramNodeDataType, paramNodeProperDataType));
						}
						sdaFunctionNode->getTypeContext()->setParamDataTypeWithPriority(paramIdx, paramNodeDataType);
					}
					paramIdx++;
				}
			}
			else if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(sdaNode)) {
				auto valueMask = sdaNumberLeaf->getMask();
				sdaNumberLeaf->setDataType(m_dataTypeFactory->getDataTypeByNumber(sdaNumberLeaf->m_value));
			}
			else if (auto goarNode = dynamic_cast<GoarNode*>(sdaNode)) {
				//...
			}

			if (!dynamic_cast<LinearExpr*>(sdaNode->getParentNode())) {
				if (sdaNode->getDataType()->isPointer()) {
					buildGoar(sdaNode);
				}
			}
		}

		bool isExplicitCast(DataTypePtr fromType, DataTypePtr toType) {
			auto fromBaseType = fromType->getBaseType();
			auto toBaseType = toType->getBaseType();
			if (auto fromSysType = dynamic_cast<SystemType*>(fromBaseType)) {
				if (auto toSysType = dynamic_cast<SystemType*>(toBaseType)) {
					if (fromSysType->isSigned() != toSysType->isSigned())
						return true;
					if (fromBaseType->getSize() > toBaseType->getSize())
						return true;
				}
			}
			auto ptrList1 = fromType->getPointerLevels();
			auto ptrList2 = toType->getPointerLevels();
			if (!ptrList1.empty() && !ptrList2.empty())
				return false;
			if (fromBaseType != toBaseType)
				return true;
			return !Unit::EqualPointerLvls(ptrList1, ptrList2);
		}

		DataTypePtr getDataTypeToCastTo(DataTypePtr type1, DataTypePtr type2) {
			auto priority1 = type1->getConversionPriority();
			auto priority2 = type2->getConversionPriority();
			if (priority1 == 0 && priority2 == 0)
				return m_dataTypeFactory->getType(SystemType::Int32);
			if (priority2 > priority1)
				return type2;
			return type1;
		}
	};

	static void SymbolizeWithSDA(SdaCodeGraph* sdaCodeGraph, UserSymbolDef& userSymbolDef) {
		DataTypeFactory dataTypeFactory(userSymbolDef.m_programModule);
		
		SdaBuilding sdaBuilding(sdaCodeGraph, &userSymbolDef, &dataTypeFactory);
		sdaBuilding.start();

		SdaDataTypesCalculating sdaDataTypesCalculating(sdaCodeGraph, &dataTypeFactory);
		sdaDataTypesCalculating.start();
	}
};