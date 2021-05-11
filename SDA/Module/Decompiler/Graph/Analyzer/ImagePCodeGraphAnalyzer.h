#pragma once
#include "../../SDA/Symbolization/DecGraphSdaBuilding.h"
#include "../../SDA/Symbolization/SdaGraphDataTypeCalc.h"


namespace CE::Decompiler
{
	class ProgramGraph
	{
	public:
		struct FuncGraphInfo {
			SdaCodeGraph* m_sdaFuncGraph;
			Symbolization::UserSymbolDef m_userSymbolDef;
		};

	private:
		ImagePCodeGraph* m_imageGraph;
		std::map<FunctionPCodeGraph*, FuncGraphInfo> m_sdaFuncGraphs;

	public:
		ProgramGraph(ImagePCodeGraph* imageGraph)
			: m_imageGraph(imageGraph)
		{}

		ImagePCodeGraph* getIamgePCodeGraph() {
			return m_imageGraph;
		}

		auto& getSdaFuncGraphs() {
			return m_sdaFuncGraphs;
		}
	};

	class ImagePCodeGraphAnalyzer
	{
		class StructureFinder : public Symbolization::SdaDataTypesCalculater
		{
			ImagePCodeGraphAnalyzer* m_imagePCodeGraphAnalyzer;
		public:
			class RawStructure : public DataType::Type
			{
			public:
				std::map<int64_t, DataTypePtr> m_fields;
				std::set<int64_t> m_arrayBegins;

				RawStructure()
					: DataType::Type("RawStructure")
				{}

				DB::Id getId() override {
					return 100000;
				}

				std::string getDisplayName() override {
					return "RawStructure";
				}

				Group getGroup() override {
					return Structure;
				}

				int getSize() override {
					return 0x100;
				}

				bool isUserDefined() override {
					return false;
				}
			};

			StructureFinder(SdaCodeGraph* sdaCodeGraph, ImagePCodeGraphAnalyzer* imagePCodeGraphAnalyzer)
				: Symbolization::SdaDataTypesCalculater(sdaCodeGraph, nullptr, &imagePCodeGraphAnalyzer->m_dataTypeFactory), m_imagePCodeGraphAnalyzer(imagePCodeGraphAnalyzer)
			{}

		private:
			bool isArrayIndexNode(ISdaNode* sdaNode) {
				if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
						if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(opNode->m_rightNode)) {
							if (opNode->m_operation == Mul) {
								return true;
							}
						}
					}
				}
				return false;
			}

			void calculateDataTypes(INode* node) override {
				Symbolization::SdaDataTypesCalculater::calculateDataTypes(node);
				if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(node)) {
					auto addrSdaNode = sdaReadValueNode->getAddress();

					ISdaNode* sdaPointerNode = nullptr;
					if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(addrSdaNode)) {
						if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode)) {
							for (auto term : linearExpr->getTerms()) {
								if (auto sdaTermNode = dynamic_cast<ISdaNode*>(term)) {
									if (sdaTermNode->getMask().getSize() == 0x8 && !isArrayIndexNode(sdaTermNode)) {
										if (!sdaPointerNode) {
											sdaPointerNode = nullptr;
											break;
										}
										sdaPointerNode = sdaTermNode;
									}
								}
							}
						}
						
					}
					else if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(addrSdaNode)) {
						sdaPointerNode = sdaSymbolLeaf;
					}

					if (sdaPointerNode) {
						auto rawStructure = new RawStructure;
						m_imagePCodeGraphAnalyzer->m_rawStructures.push_back(rawStructure);
						sdaPointerNode->setDataType(DataType::GetUnit(rawStructure, "[1]"));
						m_nextPassRequired = true;
					}
				}
			}

			void handleUnknownLocation(UnknownLocation* unknownLoc) override {
				if (auto readValueNode = dynamic_cast<ReadValueNode*>(unknownLoc->getParentNode())) {
					if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(readValueNode->getParentNode()))
					{
						auto baseSdaNode = unknownLoc->getBaseSdaNode();
						if (auto rawStructure = dynamic_cast<RawStructure*>(baseSdaNode->getSrcDataType()->getType())) {
							auto offset = unknownLoc->getConstTermValue();
							auto newFieldDataType = sdaReadValueNode->getDataType();
							auto it = rawStructure->m_fields.find(offset);
							if (it == rawStructure->m_fields.end() || it->second->getPriority() < newFieldDataType->getPriority()) {
								rawStructure->m_fields[offset] = newFieldDataType;
								if (unknownLoc->getArrTerms().size() > 0) {
									rawStructure->m_arrayBegins.insert(offset);
								}
							}
						}
					}
				}
			}
		};

		ProgramGraph* m_programGraph;
		CE::ProgramModule* m_programModule;
		AbstractRegisterFactory* m_registerFactory;
		Symbolization::DataTypeFactory m_dataTypeFactory;
		CE::Symbol::SymbolTable* m_globalSymbolTable;
		std::list<StructureFinder::RawStructure*> m_rawStructures;
	public:
		ImagePCodeGraphAnalyzer(ProgramGraph* programGraph, CE::ProgramModule* programModule, AbstractRegisterFactory* registerFactory)
			: m_programGraph(programGraph), m_programModule(programModule), m_registerFactory(registerFactory), m_dataTypeFactory(programModule)
		{
			m_globalSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
		}

		void start() {
			auto firstGraph = m_programGraph->getIamgePCodeGraph()->getFirstFunctionGraph();

			doPassToDefineReturnValues(firstGraph);
			doPassToFindStructures(firstGraph);
		}

	private:
		struct ReturnValueStatInfo {
			Register m_register;
			int m_score;
		};
		std::map<FunctionPCodeGraph*, std::list<ReturnValueStatInfo>> m_retValueScores;

		void doPassToDefineReturnValues(FunctionPCodeGraph* funcGraph) {
			for (auto nextFuncGraph : funcGraph->getNonVirtFuncCalls())
				doPassToDefineReturnValues(nextFuncGraph);

			DecompiledCodeGraph decompiledCodeGraph(funcGraph);
			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::PrimaryDecompiler(&decompiledCodeGraph, m_registerFactory, ReturnInfo(), funcCallInfoCallback);
			decompiler.start();

			ExecContext execContext(&decompiler);
			for (auto& pair : decompiler.m_decompiledBlocks) {
				auto& decBlockInfo = pair.second;
				if (auto block = dynamic_cast<PrimaryTree::EndBlock*>(decBlockInfo.m_decBlock)) {
					execContext.join(decBlockInfo.m_execCtx);
				}
			}

			// iterate over all return registers
			auto retRegIds = { ZYDIS_REGISTER_RAX << 8, ZYDIS_REGISTER_ZMM0 << 8 };
			std::list<ReturnValueStatInfo> retValueScores;
			for (auto regId : retRegIds) {
				auto& registers = execContext.m_registerExecCtx.m_registers;
				auto it = registers.find(regId);
				if (it == registers.end())
					continue;
				auto& regList = it->second;

				// select min register (AL inside EAX)
				BitMask64 minMask(8);
				RegisterExecContext::RegisterInfo* minRegInfo = nullptr;
				for (auto& regInfo : regList) {
					if (minMask.getValue() == -1 || regInfo.m_register.m_valueRangeMask < minMask) {
						minMask = regInfo.m_register.m_valueRangeMask;
						minRegInfo = &regInfo;
					}
				}

				if (minRegInfo) {
					ReturnValueStatInfo retValueStatInfo;
					retValueStatInfo.m_register = minRegInfo->m_register;
					retValueStatInfo.m_score ++;
					retValueScores.push_back(retValueStatInfo);
				}
			}

			m_retValueScores[funcGraph] = retValueScores;
		}

		void doPassToFindStructures(FunctionPCodeGraph* funcGraph) {
			for (auto nextFuncGraph : funcGraph->getNonVirtFuncCalls())
				doPassToFindStructures(nextFuncGraph);


			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(funcGraph, funcCallInfoCallback, ReturnInfo(), m_registerFactory);
			decompiler.start();

			auto decCodeGraph = decompiler.getDecGraph();
			auto sdaCodeGraph = new SdaCodeGraph(decCodeGraph);

			Symbolization::UserSymbolDef userSymbolDef;
			userSymbolDef.m_globalSymbolTable = m_globalSymbolTable;
			userSymbolDef.m_stackSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::STACK_SPACE, 100000);
			userSymbolDef.m_funcBodySymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);

			ProgramGraph::FuncGraphInfo funcGraphInfo;
			funcGraphInfo.m_sdaFuncGraph = sdaCodeGraph;
			funcGraphInfo.m_userSymbolDef = userSymbolDef;
			m_programGraph->getSdaFuncGraphs().insert(std::pair(funcGraph, funcGraphInfo));

			Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &userSymbolDef, &m_dataTypeFactory);
			sdaBuilding.start();

			for (auto symbol : sdaBuilding.getAutoSymbols()) {
				if (auto memSymbol = dynamic_cast<CE::Symbol::AutoSdaMemSymbol*>(symbol)) {
					if (symbol->getType() == CE::Symbol::GLOBAL_VAR) {
						userSymbolDef.m_globalSymbolTable->addSymbol(memSymbol, memSymbol->getStorage().getOffset());
					}
					else if (symbol->getType() == CE::Symbol::LOCAL_STACK_VAR) {
						userSymbolDef.m_stackSymbolTable->addSymbol(memSymbol, memSymbol->getStorage().getOffset());
					}
				}
				else {
					if (symbol->getType() == CE::Symbol::LOCAL_INSTR_VAR) {
						for(auto offset : symbol->getInstrOffsets())
							userSymbolDef.m_funcBodySymbolTable->addSymbol(symbol, offset);
					}
				}
				delete symbol;
			}

			StructureFinder structureFinder(sdaCodeGraph, this);
			structureFinder.start();

		}
	};
};