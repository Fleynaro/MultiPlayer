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
			// check if it is [rcx] * 0x4
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

				// only reading from memory is a trigger to define structures
				if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(node)) {
					auto addrSdaNode = sdaReadValueNode->getAddress();

					// for {[rcx] + [rdx] * 0x5 + 0x10} the {sdaPointerNode} is [rcx] with the size of 8, no [rdx] * 0x5 (ambigious in the case of [rcx] + [rdx])
					ISdaNode* sdaPointerNode = nullptr;
					if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(addrSdaNode)) {
						if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode)) {
							for (auto term : linearExpr->getTerms()) {
								if (auto sdaTermNode = dynamic_cast<ISdaNode*>(term)) {
									if (sdaTermNode->getSize() == 0x8 && !isArrayIndexNode(sdaTermNode)) {
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
						// for *param1
						sdaPointerNode = sdaSymbolLeaf;
					}

					// create a raw structure
					if (sdaPointerNode) {
						auto rawStructure = new RawStructure;
						m_imagePCodeGraphAnalyzer->m_rawStructures.push_back(rawStructure);
						sdaPointerNode->setDataType(DataType::GetUnit(rawStructure, "[1]"));
						m_nextPassRequired = true;
					}
				}
			}

			void handleUnknownLocation(UnknownLocation* unknownLoc) override {
				// define fields of structures using the parent node: SdaReadValueNode
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

								// if it is an array
								if (unknownLoc->getArrTerms().size() > 0) {
									rawStructure->m_arrayBegins.insert(offset);
								}
							}
						}
					}
				}
			}
		};

		class PrimaryDecompilerForAnalysis : public PrimaryDecompiler
		{
			class MarkerNode : public Node
			{
			public:
				MarkerNode()
				{}
			};

			ImagePCodeGraphAnalyzer* m_imagePCodeGraphAnalyzer = nullptr;
		public:
			using PrimaryDecompiler::PrimaryDecompiler;

			void setImagePCodeGraphAnalyzer(ImagePCodeGraphAnalyzer* imagePCodeGraphAnalyzer) {
				m_imagePCodeGraphAnalyzer = imagePCodeGraphAnalyzer;
			}
		protected:
			void onInstructionHandled(DecompiledBlockInfo& blockInfo, PCode::Instruction* instr) override {
				if (instr->m_id == PCode::InstructionId::CALL || instr->m_id == PCode::InstructionId::CALLIND) {
					auto& constValues = m_decompiledGraph->getFuncGraph()->getConstValues();
					auto it = constValues.find(instr);
					if (it != constValues.end()) {
						auto dstLocOffset = (int)it->second;

					}
				}
			}

			void onFinal() {

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

		/*
			TODO:
			1) Создание маркеров, модификация Decompiler/Interpterer, распознавание маркеров, выставление оценкци, создание варнингов (если один маркер перезаписал другой)
			2) Сделать 2 итерации по 2 прохода(1 - retValue, 2 - типы и структуры) графа программы сначала без виртуальных вызовов, потом с вирт. вызовами.
			3) Реализовать getAllFuncCalls = getNonVirtFuncCalls + getVirtFuncCalls
		*/

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
			auto decompiler = PrimaryDecompilerForAnalysis(&decompiledCodeGraph, m_registerFactory, ReturnInfo(), funcCallInfoCallback);
			decompiler.setImagePCodeGraphAnalyzer(this);
			decompiler.start();

			// gather all end blocks (where RET command) joining them into one context
			ExecContext execContext(&decompiler);
			for (auto& pair : decompiler.m_decompiledBlocks) {
				auto& decBlockInfo = pair.second;
				if (auto block = dynamic_cast<PrimaryTree::EndBlock*>(decBlockInfo.m_decBlock)) {
					execContext.join(decBlockInfo.m_execCtx);
				}
			}

			// iterate over all return registers within {execContext}
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

				// give scores to the register
				if (minRegInfo) {
					ReturnValueStatInfo retValueStatInfo;
					retValueStatInfo.m_register = minRegInfo->m_register;
					switch (minRegInfo->m_using)
					{
					case RegisterExecContext::RegisterInfo::REGISTER_NOT_USING:
						retValueStatInfo.m_score += 5;
						break;
					case RegisterExecContext::RegisterInfo::REGISTER_PARTIALLY_USING:
						retValueStatInfo.m_score += 2;
						break;
					case RegisterExecContext::RegisterInfo::REGISTER_FULLY_USING:
						retValueStatInfo.m_score += 1;
						break;
					}
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

			// create symbol tables for the func. graph
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

			// gather all new symbols (only after parameters of all function will be defined)
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