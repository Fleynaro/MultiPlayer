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
			: m_programModule(programModule), m_registerFactory(registerFactory), m_image(image), m_dataTypeFactory(m_programModule)
		{
			m_userSymbolDef = Symbolization::UserSymbolDef(m_programModule);
			m_userSymbolDef.m_globalMemoryArea = new CE::Symbol::MemoryArea(m_programModule->getMemoryAreaManager(), CE::Symbol::MemoryArea::GLOBAL_SPACE, 100000);
			m_userSymbolDef.m_stackMemoryArea = new CE::Symbol::MemoryArea(m_programModule->getMemoryAreaManager(), CE::Symbol::MemoryArea::STACK_SPACE, 100000);
			m_userSymbolDef.m_funcBodyMemoryArea = new CE::Symbol::MemoryArea(m_programModule->getMemoryAreaManager(), CE::Symbol::MemoryArea::GLOBAL_SPACE, 100000);
		}

		~PCodeGraphReferenceSearch() {
			delete m_userSymbolDef.m_globalMemoryArea;
			delete m_userSymbolDef.m_stackMemoryArea;
			delete m_userSymbolDef.m_funcBodyMemoryArea;
		}

		std::list<int> findNewFunctionOffsets(FunctionPCodeGraph* funcGraph) {
			auto decCodeGraph = new DecompiledCodeGraph(funcGraph, FunctionCallInfo({}));

			auto funcCallInfoCallback = [&](int offset, ExprTree::INode* dst) { return FunctionCallInfo({}); };
			auto decompiler = CE::Decompiler::Decompiler(decCodeGraph, m_registerFactory, funcCallInfoCallback);
			decompiler.start();

			auto clonedDecCodeGraph = decCodeGraph->clone();
			Optimization::OptimizeDecompiledGraph(clonedDecCodeGraph);

			auto sdaCodeGraph = new SdaCodeGraph(clonedDecCodeGraph);
			Symbolization::SdaBuilding sdaBuilding(sdaCodeGraph, &m_userSymbolDef, &m_dataTypeFactory);
			sdaBuilding.start();

			std::list<int> offsets;
			for (auto symbol : sdaBuilding.getAutoSymbols()) {
				if (auto memSymbol = dynamic_cast<CE::Symbol::AutoSdaMemSymbol*>(symbol)) {
					for (auto& storage : memSymbol->getStorages()) {
						if (storage.getType() == Storage::STORAGE_GLOBAL) {
							if (m_image->defineSegment(storage.getOffset()) == IImage::CODE_SEGMENT) {
								offsets.push_back(storage.getOffset());
							}
						}
					}
				}
				delete symbol;
			}

			delete clonedDecCodeGraph;
			delete decCodeGraph;
			delete sdaCodeGraph;
			return offsets;
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

		void start(int startOffset, const std::map<int64_t, PCode::Instruction*>& offsetToInstruction = {}) {
			std::list<int> nextOffsetsToVisitLater = { startOffset };
			std::set<PCodeBlock*> mutualBlocks;

			while (!nextOffsetsToVisitLater.empty()) {
				auto startInstrOffset = (int64_t)nextOffsetsToVisitLater.back() << 8;
				nextOffsetsToVisitLater.pop_back();

				auto block = m_imageGraph->getBlockAtOffset(startInstrOffset);
				if (block == nullptr) {
					auto funcGraph = m_imageGraph->createFunctionGraph();
					buildGraphAtOffset(startInstrOffset, funcGraph, offsetToInstruction);

					auto newOffsets = m_graphReferenceSearch->findNewFunctionOffsets(funcGraph);
					nextOffsetsToVisitLater.insert(nextOffsetsToVisitLater.end(), newOffsets.begin(), newOffsets.end());

					std::list<PCodeBlock*> path;
					CalculateLevelsForPCodeBlocks(funcGraph->getStartBlock(), path);
				}
				else {
					mutualBlocks.insert(block);
				}
			}

			findMutualSubgraphs(mutualBlocks);
		}

		void startOnce(int startOffset, const std::map<int64_t, PCode::Instruction*>& offsetToInstruction = {}) {
			auto curFuncGraph = m_imageGraph->createFunctionGraph();
			buildGraphAtOffset((int64_t)startOffset << 8, curFuncGraph, offsetToInstruction);

			std::list<PCodeBlock*> path;
			CalculateLevelsForPCodeBlocks(curFuncGraph->getStartBlock(), path);
		}

	private:
		void findMutualSubgraphs(std::set<PCodeBlock*> mutualBlocks) {

		}

		// fill {funcGraph} with PCode blocks
		void buildGraphAtOffset(int64_t startInstrOffset, FunctionPCodeGraph* funcGraph, std::map<int64_t, PCode::Instruction*> offsetToInstruction) {
			m_imageGraph->createBlock(funcGraph, startInstrOffset);
			std::set<int64_t> visitedOffsets;
			std::list<int64_t> nextOffsetsToVisitLater;
			
			auto offset = startInstrOffset;

			while (true) {
				auto byteOffset = offset >> 8;
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

					if (targetOffset == -1 || m_image->defineSegment(targetOffset >> 8) != IImage::CODE_SEGMENT) {
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
							auto block1 = m_imageGraph->createBlock(alreadyExistingBlock->getFuncGraph(), targetOffset);
							auto block2 = alreadyExistingBlock;
							std::list<PCode::Instruction*> instrOfBlock1;
							std::list<PCode::Instruction*> instrOfBlock2;
							for (auto instr : alreadyExistingBlock->getInstructions()) {
								if (instr->getOffset() < targetOffset)
									instrOfBlock1.push_back(instr);
								else instrOfBlock2.push_back(instr);
							}
							block1->getInstructions() = instrOfBlock1;
							block2->getInstructions() = instrOfBlock2;
							block1->setMaxOffset(targetOffset);
							block2->setMaxOffset(alreadyExistingBlock->getMaxOffset());
							block1->setNextNearBlock(block2);
							nextFarBlock = block2;
						}
						curBlock->setNextFarBlock(alreadyExistingBlock);
					}
					else {
						nextFarBlock = m_imageGraph->createBlock(funcGraph, targetOffset);
						curBlock->setNextFarBlock(nextFarBlock);
					}

					// near block
					PCodeBlock* nextNearBlock = nullptr;
					if (instr->m_id == PCode::InstructionId::CBRANCH) {
						if (m_imageGraph->getBlockAtOffset(nextInstrOffset) == nullptr) {
							nextNearBlock = m_imageGraph->createBlock(funcGraph, nextInstrOffset);
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
	};
};