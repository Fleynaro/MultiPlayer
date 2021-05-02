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

		class StructureFinder : public Symbolization::SdaDataTypesCalculater
		{
			ImagePCodeGraphAnalyzer* m_imagePCodeGraphAnalyzer;
		public:
			StructureFinder(SdaCodeGraph* sdaCodeGraph, ImagePCodeGraphAnalyzer* imagePCodeGraphAnalyzer)
				: Symbolization::SdaDataTypesCalculater(sdaCodeGraph, nullptr, &imagePCodeGraphAnalyzer->m_dataTypeFactory), m_imagePCodeGraphAnalyzer(imagePCodeGraphAnalyzer)
			{}

		private:
			void calculateDataTypes(INode* node) override {
				Symbolization::SdaDataTypesCalculater::calculateDataTypes(node);
				if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(node)) {

				}
			}

			// никаких локаций изначально нет, ибо нет указателей. лучше обработку вести с SdaReadValueNode для выражений типа: p + 0x10, p + 0x4 * i, ...
			// после на след. проходах появятся локации. нужно создать свою ноду-символ, которая будет впитывать тип
			void handleUnknownLocation(UnknownLocation* unknownLoc) override {
				auto baseSdaNode = unknownLoc->getBaseSdaNode();
				if (auto readValueNode = dynamic_cast<ReadValueNode*>(baseSdaNode->getParentNode())) {
					if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(readValueNode->getParentNode())) {
						auto rawStructure = dynamic_cast<RawStructure*>(baseSdaNode->getDataType()->getType());
						if (!rawStructure) {
							rawStructure = new RawStructure;
							m_imagePCodeGraphAnalyzer->m_rawStructures.push_back(rawStructure);
							baseSdaNode->setDataType(DataType::GetUnit(rawStructure, "[1]"));
						}

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
		};

		ProgramGraph* m_programGraph;
		CE::ProgramModule* m_programModule;
		AbstractRegisterFactory* m_registerFactory;
		Symbolization::DataTypeFactory m_dataTypeFactory;
		CE::Symbol::SymbolTable* m_globalSymbolTable;
		std::list<RawStructure*> m_rawStructures;
	public:
		ImagePCodeGraphAnalyzer(ProgramGraph* programGraph, CE::ProgramModule* programModule, AbstractRegisterFactory* registerFactory)
			: m_programGraph(programGraph), m_programModule(programModule), m_registerFactory(registerFactory), m_dataTypeFactory(programModule)
		{
			m_globalSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
		}

		void start() {
			doDepthPassAllFuncGraphs(m_programGraph->getIamgePCodeGraph()->getFirstFunctionGraph());
		}

	private:
		void doDepthPassAllFuncGraphs(FunctionPCodeGraph* funcGraph) {
			for (auto nextFuncGraph : funcGraph->getNonVirtFuncCalls())
				doDepthPassAllFuncGraphs(nextFuncGraph);

			auto decCodeGraph = new DecompiledCodeGraph(funcGraph);

			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(decCodeGraph, m_registerFactory, ReturnInfo(), funcCallInfoCallback);
			decompiler.start();

			auto clonedDecCodeGraph = decCodeGraph->clone();
			delete decCodeGraph;
			Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);

			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);

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