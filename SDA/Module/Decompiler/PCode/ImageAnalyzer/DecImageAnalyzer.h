#pragma once
#include <Module/Image/PEImage.h>
#include "../../Graph/DecPCodeGraph.h"
#include "../Decoders/DecPCodeDecoderX86.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
#include <Manager/TypeManager.h>

namespace CE::Decompiler
{
	class PCodeGraphReferenceSearch
	{
		CE::ProgramModule* m_programModule;
		AbstractRegisterFactory* m_registerFactory;
		IImage* m_image;
		Symbolization::DataTypeFactory m_dataTypeFactory;
		Symbolization::UserSymbolDef m_userSymbolDef;
	public:
		PCodeGraphReferenceSearch(CE::ProgramModule* programModule, AbstractRegisterFactory* registerFactory, IImage* image)
			: m_programModule(programModule), m_registerFactory(registerFactory), m_image(image), m_dataTypeFactory(programModule)
		{
			m_userSymbolDef = Symbolization::UserSymbolDef(m_programModule);
			m_userSymbolDef.m_globalSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
			m_userSymbolDef.m_stackSymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::STACK_SPACE, 100000);
			m_userSymbolDef.m_funcBodySymbolTable = new CE::Symbol::SymbolTable(m_programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
		}

		~PCodeGraphReferenceSearch() {
			delete m_userSymbolDef.m_globalSymbolTable;
			delete m_userSymbolDef.m_stackSymbolTable;
			delete m_userSymbolDef.m_funcBodySymbolTable;
		}

		void findNewFunctionOffsets(FunctionPCodeGraph* funcGraph, std::list<int>& nonVirtFuncOffsets, std::list<int>& otherOffsets) {
			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(funcGraph, funcCallInfoCallback, ReturnInfo(), m_registerFactory);
			decompiler.start();

			auto decCodeGraph = decompiler.getDecGraph();
			auto sdaCodeGraph = new SdaCodeGraph(decCodeGraph);
			Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &m_userSymbolDef, &m_dataTypeFactory);
			sdaBuilding.start();

			for (auto symbol : sdaBuilding.getAutoSymbols()) {
				if (auto memSymbol = dynamic_cast<CE::Symbol::AutoSdaMemSymbol*>(symbol)) {
					auto storage = memSymbol->getStorage();
					auto offset = (int)storage.getOffset();
					if (storage.getType() == Storage::STORAGE_GLOBAL) {
						if (m_image->defineSegment(offset) == IImage::CODE_SEGMENT) {
							nonVirtFuncOffsets.push_back(offset);
						}
					}
				}
				delete symbol;
			}

			delete decCodeGraph;
			delete sdaCodeGraph;
		}
	};

	// Analysis of an image of some program (.exe or .dll)
	class ImageAnalyzer
	{
		IImage* m_image;
		ImagePCodeGraph* m_imageGraph = nullptr;
		PCodeGraphReferenceSearch* m_graphReferenceSearch;

		AbstractRegisterFactory* m_registerFactory;
		PCode::AbstractDecoder* m_decoder;
	public:
		ImageAnalyzer(IImage* image, ImagePCodeGraph* imageGraph, PCode::AbstractDecoder* decoder, AbstractRegisterFactory* registerFactory, PCodeGraphReferenceSearch* graphReferenceSearch = nullptr)
			: m_image(image), m_imageGraph(imageGraph), m_decoder(decoder), m_registerFactory(registerFactory), m_graphReferenceSearch(graphReferenceSearch)
		{}

		void start(int startOffset, const std::map<int64_t, PCode::Instruction*>& offsetToInstruction = {}, bool onceFunc = false) {
			std::set<int64_t> visitedOffsets;
			std::list<int> nextOffsetsToVisitLater = { startOffset };
			std::list<std::pair<FunctionPCodeGraph*, std::list<int>>> nonVirtFuncOffsetsForGraphs;
			std::map<int, FunctionPCodeGraph*> offsetsToFuncGraphs;
			std::list<PCodeBlock*> blocksToReconnect;

			// generate an image graph
			while (!nextOffsetsToVisitLater.empty()) {
				auto startInstrOffset = (int64_t)nextOffsetsToVisitLater.back() << 8;
				if (visitedOffsets.find(startInstrOffset) != visitedOffsets.end())
					continue;
				visitedOffsets.insert(startInstrOffset);
				nextOffsetsToVisitLater.pop_back();

				auto funcGraph = m_imageGraph->createFunctionGraph();
				auto block = m_imageGraph->getBlockAtOffset(startInstrOffset);
				if (block == nullptr) {
					auto startBlock = m_imageGraph->createBlock(startInstrOffset);
					funcGraph->setStartBlock(startBlock);
					createPCodeBlocksAtOffset(startInstrOffset, funcGraph, offsetToInstruction);
					offsetsToFuncGraphs[(int)(startInstrOffset >> 8)] = funcGraph;
					
					if (!onceFunc) {
						std::list<int> nonVirtFuncOffsets;
						std::list<int> otherOffsets;
						PrepareFuncGraph(funcGraph);
						m_graphReferenceSearch->findNewFunctionOffsets(funcGraph, nonVirtFuncOffsets, otherOffsets);
						nextOffsetsToVisitLater.insert(nextOffsetsToVisitLater.end(), nonVirtFuncOffsets.begin(), nonVirtFuncOffsets.end());
						nextOffsetsToVisitLater.insert(nextOffsetsToVisitLater.end(), otherOffsets.begin(), otherOffsets.end());
						nonVirtFuncOffsetsForGraphs.push_back(std::make_pair(funcGraph, nonVirtFuncOffsets));
					}
				}
				else {
					// if the function call references to a block of the existing graph
					funcGraph->setStartBlock(block);
					offsetsToFuncGraphs[(int)(startInstrOffset >> 8)] = funcGraph;
					blocksToReconnect.push_back(block);
				}
			}

			// associate function graphs with other function graphs through non-virtual calls
			for (auto pair : nonVirtFuncOffsetsForGraphs) {
				auto graph = pair.first;
				auto offsets = pair.second;
				for (auto offset : offsets) {
					auto it = offsetsToFuncGraphs.find(offset);
					if (it != offsetsToFuncGraphs.end()) {
						graph->getNonVirtFuncCalls().push_back(it->second);
					}
				}
			}

			// other
			reconnectBlocksAndReplaceJmpByCall(blocksToReconnect);
			prepareFuncGraphs();
		}

	private:
		// reconnect all blocks that are referenced by function calls
		void reconnectBlocksAndReplaceJmpByCall(std::list<PCodeBlock*> blocks) {
			for (auto block : blocks) {
				for (auto refBlock : block->m_blocksReferencedTo) {
					auto lastInstr = refBlock->getLastInstruction();
					if (PCode::Instruction::IsBranching(lastInstr->m_id)) {
						// replace JMP with CALL
						lastInstr->m_id = PCode::InstructionId::CALL;
						// add RET
						auto retInstr = new Instruction(PCode::InstructionId::RETURN, nullptr, nullptr, nullptr, (int)(lastInstr->getFirstInstrOffsetInNextOrigInstr() >> 8), 1, 0);
						refBlock->getInstructions().push_back(retInstr);
					}
					refBlock->removeNextBlock(block);
				}
				block->m_blocksReferencedTo.clear();
			}
		}

		// calculate levels and gather PCode blocks for each function graph
		void prepareFuncGraphs() {
			for (auto funcGraph : m_imageGraph->getFunctionGraphList()) {
				PrepareFuncGraph(funcGraph);
			}
		}

		// fill {funcGraph} with PCode blocks
		void createPCodeBlocksAtOffset(int64_t startInstrOffset, FunctionPCodeGraph* funcGraph, std::map<int64_t, PCode::Instruction*> offsetToInstruction) {
			std::set<int64_t> visitedOffsets;
			std::list<int64_t> nextOffsetsToVisitLater;
			
			auto offset = startInstrOffset;
			while (true) {
				auto byteOffset = (int)(offset >> 8);
				auto instrOrder = offset & 0xFF;
				PCode::Instruction* instr = nullptr;
				PCodeBlock* curBlock = nullptr;

				if (offset != -1 && visitedOffsets.find(offset) == visitedOffsets.end()) {
					// any offset have to be assoicated with some existing block
					curBlock = m_imageGraph->getBlockAtOffset(offset, false);
					if (curBlock != nullptr) {
						// try to get an instruction by the offset
						auto it = offsetToInstruction.find(offset);
						if (it != offsetToInstruction.end()) {
							instr = it->second;
						}
						else {
							if (byteOffset < m_image->getSize()) {
								m_decoder->decode(m_image->getData() + m_image->toImageOffset(byteOffset), byteOffset, m_image->getSize());
								for (auto instr : m_decoder->getDecodedPCodeInstructions()) {
									offsetToInstruction[instr->getOffset()] = instr;
								}
							}

							it = offsetToInstruction.find(offset);
							if (it != offsetToInstruction.end()) {
								instr = it->second;
							}
						}

						visitedOffsets.insert(offset);
					}
				}

				if (instr == nullptr) {
					// select the next new block to visit
					offset = -1;
					while (!nextOffsetsToVisitLater.empty()) {
						offset = nextOffsetsToVisitLater.back();
						nextOffsetsToVisitLater.pop_back();
						if (visitedOffsets.find(offset) == visitedOffsets.end())
							break;
						offset = -1;
					}

					// visit a new offset
					if (offset != -1)
						continue;

					// if no new offsets then exit
					break;
				}

				curBlock->getInstructions().push_back(instr);
				// calculate offset of the next instruction
				auto nextInstrOffset = instr->getOffset() + 1;
				auto it2 = offsetToInstruction.find(nextInstrOffset);
				if (it2 == offsetToInstruction.end() || byteOffset != it2->second->getOriginalInstructionOffset())
					nextInstrOffset = instr->getFirstInstrOffsetInNextOrigInstr();
				// extend size of the current block
				curBlock->setMaxOffset(nextInstrOffset);

				// create a new block
				if (PCode::Instruction::IsBranching(instr->m_id)) {
					PCode::VirtualMachineContext vmCtx;
					PCode::ConstValueCalculating constValueCalculating(curBlock->getInstructions(), &vmCtx, m_registerFactory);
					constValueCalculating.start(funcGraph->getConstValues());

					int64_t targetOffset = -1;
					if (auto varnodeConst = dynamic_cast<PCode::ConstantVarnode*>(instr->m_input0)) {
						// if this input contains hardcoded constant
						targetOffset = varnodeConst->m_value;
					}
					else {
						// if this input could be constantly calculated by pcode virtual machine
						auto it = funcGraph->getConstValues().find(instr);
						if (it != funcGraph->getConstValues().end())
							targetOffset = it->second << 8;
					}

					if (targetOffset == -1 || m_image->defineSegment((int)(targetOffset >> 8)) != IImage::CODE_SEGMENT) {
						offset = -1;
						m_decoder->getWarningContainer()->addWarning("rva "+ std::to_string(targetOffset >> 8) +" is not correct in the jump instruction "+ instr->m_originalView +" (at 0x"+ Generic::String::NumberToHex(instr->getOriginalInstructionOffset()) +")");
						continue;
					}

					// far block
					PCodeBlock* nextFarBlock = nullptr;
					auto alreadyExistingBlock = m_imageGraph->getBlockAtOffset(targetOffset);
					if (alreadyExistingBlock != nullptr) {
						// split the already existing block into 2 non-empty blocks 
						if (targetOffset > alreadyExistingBlock->getMinOffset() && targetOffset < alreadyExistingBlock->getMaxOffset() - 1) {
							auto block1 = alreadyExistingBlock;
							auto block2 = m_imageGraph->createBlock(targetOffset);

							std::list<PCode::Instruction*> instrOfBlock1;
							std::list<PCode::Instruction*> instrOfBlock2;
							for (auto instr : alreadyExistingBlock->getInstructions()) {
								if (instr->getOffset() < targetOffset)
									instrOfBlock1.push_back(instr);
								else instrOfBlock2.push_back(instr);
							}
							block1->getInstructions() = instrOfBlock1;
							block2->getInstructions() = instrOfBlock2;

							block2->setMaxOffset(alreadyExistingBlock->getMaxOffset());
							block1->setMaxOffset(targetOffset);

							if(block1->getNextNearBlock())
								block2->setNextNearBlock(block1->getNextNearBlock());
							if (block1->getNextFarBlock())
								block2->setNextFarBlock(block1->getNextFarBlock());
							block1->disconnect();
							block1->setNextNearBlock(block2);

							if (curBlock == alreadyExistingBlock)
								alreadyExistingBlock = curBlock = block2;
						}
						curBlock->setNextFarBlock(alreadyExistingBlock);
					}
					else {
						nextFarBlock = m_imageGraph->createBlock(targetOffset);
						curBlock->setNextFarBlock(nextFarBlock);
					}

					// near block
					PCodeBlock* nextNearBlock = nullptr;
					if (instr->m_id == PCode::InstructionId::CBRANCH) {
						if (m_imageGraph->getBlockAtOffset(nextInstrOffset) == nullptr) {
							nextNearBlock = m_imageGraph->createBlock(nextInstrOffset);
							curBlock->setNextNearBlock(nextNearBlock);
						}
					}

					// calculate the next offset (selecting the next following block if possible)
					if (nextNearBlock) {
						offset = nextNearBlock->getMinOffset();
						if (nextFarBlock) {
							nextOffsetsToVisitLater.push_back(nextFarBlock->getMinOffset());
						}
					}
					else if (nextFarBlock) {
						offset = nextFarBlock->getMinOffset();
					}
					else {
						offset = -1;
					}
				}
				else {
					// calculate the next offset
					if (instr->m_id != PCode::InstructionId::RETURN) {
						auto nextBlock = m_imageGraph->getBlockAtOffset(nextInstrOffset, false);
						if (curBlock != nextBlock)
							curBlock->setNextNearBlock(nextBlock);
						offset = nextInstrOffset;
					}
					else {
						offset = -1;
					}
				}
			}
		}


		// prepare a function graph
		static void PrepareFuncGraph(FunctionPCodeGraph* funcGraph) {
			std::list<PCodeBlock*> path;
			CalculateLevelsForPCodeBlocks(funcGraph->getStartBlock(), path);

			std::set<PCodeBlock*> blocks;
			GatherPCodeBlocks(funcGraph->getStartBlock(), blocks);
			funcGraph->getBlocks() = blocks;
		}

		// pass pcode graph and calculate max distance from root to each node (pcode block)
		static void CalculateLevelsForPCodeBlocks(PCodeBlock* block, std::list<PCodeBlock*>& path) {
			if (block == nullptr)
				return;

			//check if there's a loop
			for (auto it = path.rbegin(); it != path.rend(); it++) {
				if (block == *it) {
					return;
				}
			}

			path.push_back(block);
			block->m_level = max(block->m_level, (int)path.size());
			CalculateLevelsForPCodeBlocks(block->getNextNearBlock(), path);
			CalculateLevelsForPCodeBlocks(block->getNextFarBlock(), path);
			path.pop_back();
		}

		// pass pcode graph and gather its blocks
		static void GatherPCodeBlocks(PCodeBlock* block, std::set<PCodeBlock*>& gatheredBlocks) {
			if (block == nullptr || gatheredBlocks.find(block) != gatheredBlocks.end())
				return;
			gatheredBlocks.insert(block);
			GatherPCodeBlocks(block->getNextNearBlock(), gatheredBlocks);
			GatherPCodeBlocks(block->getNextFarBlock(), gatheredBlocks);
		}
	};
};