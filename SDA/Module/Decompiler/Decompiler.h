#pragma once
#include "DecAsmGraph.h"
#include "DecInstructionInterpreter.h"
#include "DecCodeGraph.h"

namespace CE::Decompiler
{
	class Decompiler
	{
		struct DecompiledBlockInfo {
			AsmGraphBlock* m_asmBlock = nullptr;
			PrimaryTree::Block* m_decBlock = nullptr;
			ExecutionBlockContext* m_execBlockCtx = nullptr;

			DecompiledBlockInfo() = default;

			bool isDecompiled() {
				return m_decBlock != nullptr;
			}
		};
	public:
		DecompiledCodeGraph* m_decompiledGraph;
		std::function<ExprTree::FunctionCallInfo(int, ExprTree::Node*)> m_funcCallInfoCallback;

		Decompiler(AsmGraph* graph, DecompiledCodeGraph* decompiledGraph)
			: m_asmGraph(graph), m_decompiledGraph(decompiledGraph)
		{
			m_instructionInterpreter = new PCode::InstructionInterpreter;
			m_funcCallInfoCallback = [](int offset, ExprTree::Node* dst) {
				return ExprTree::GetFunctionCallDefaultInfo();
			};
		}

		~Decompiler() {
			delete m_instructionInterpreter;

			for (auto& it : m_decompiledBlocks) {
				delete it.second.m_execBlockCtx;
			}
		}

		void start() {
			decompileAllBlocks();
			setAllBlocksLinks();
			buildDecompiledGraph();

			auto startBlock = m_decompiledGraph->getStartBlock();
			std::multiset<PrimaryTree::Block*> visitedBlocks;
			resolveExternalSymbols(startBlock, visitedBlocks);
			createSymbolAssignments();
		}

		void buildDecompiledGraph();

		std::map<PrimaryTree::Block*, AsmGraphBlock*> getAsmBlocks() {
			std::map<PrimaryTree::Block*, AsmGraphBlock*> result;
			for (auto& it : m_decompiledBlocks) {
				result[it.second.m_decBlock] = it.second.m_asmBlock;
			}
			return result;
		}
	private:
		AsmGraph* m_asmGraph;
		PCode::InstructionInterpreter* m_instructionInterpreter;

		std::map<AsmGraphBlock*, PrimaryTree::Block*> m_asmToDecBlocks;
		std::map<PrimaryTree::Block*, DecompiledBlockInfo> m_decompiledBlocks;
		
		void decompileAllBlocks() {
			for (auto& it : m_asmGraph->m_blocks) {
				auto asmBlock = &it.second;
				DecompiledBlockInfo decompiledBlock;
				decompiledBlock.m_asmBlock = asmBlock;
				if (!asmBlock->getNextNearBlock() && !asmBlock->getNextFarBlock()) {
					decompiledBlock.m_decBlock = new PrimaryTree::EndBlock(asmBlock->m_level);
				}
				else {
					decompiledBlock.m_decBlock = new PrimaryTree::Block(asmBlock->m_level);
				}
				decompiledBlock.m_execBlockCtx = new ExecutionBlockContext(this);

				for (auto instr : asmBlock->getInstructions()) {
					m_instructionInterpreter->execute(decompiledBlock.m_decBlock, decompiledBlock.m_execBlockCtx, instr);
				}

				m_asmToDecBlocks[asmBlock] = decompiledBlock.m_decBlock;
				m_decompiledBlocks[decompiledBlock.m_decBlock] = decompiledBlock;
			}
		}

		void setAllBlocksLinks() {
			for (const auto& it : m_decompiledBlocks) {
				auto& decBlockInfo = it.second;

				for (const auto& link : {
					std::make_pair(&decBlockInfo.m_decBlock->m_nextNearBlock, decBlockInfo.m_asmBlock->getNextNearBlock()),
					std::make_pair(&decBlockInfo.m_decBlock->m_nextFarBlock, decBlockInfo.m_asmBlock->getNextFarBlock()) })
				{
					if (!link.second)
						continue;
					auto block = *link.first = m_asmToDecBlocks[link.second];
					block->m_blocksReferencedTo.push_back(decBlockInfo.m_decBlock);
				}
			}
		}

		void resolveExternalSymbols(PrimaryTree::Block* block, std::multiset<PrimaryTree::Block*>& visitedBlocks) {
			if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
				auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
				for (auto it = ctx->m_externalSymbols.begin(); it != ctx->m_externalSymbols.end(); it ++) {
					auto& externalSymbol = **it;
					auto regId = externalSymbol.m_reg.getGenericId(); //ah/al and xmm?
					if (m_registersToSymbol.find(regId) == m_registersToSymbol.end()) {
						m_registersToSymbol[regId] = RegSymbol(externalSymbol.m_reg.isVector());
					}
					m_curRegSymbol = &m_registersToSymbol[regId];
					m_curRegSymbol->requiestId++;

					auto regParts = externalSymbol.m_regParts;
					auto mask = externalSymbol.m_needReadMask;
					requestRegisterParts(block, externalSymbol.m_reg, mask, regParts, false);
					if (mask != externalSymbol.m_needReadMask || !regParts.empty()) { //mask should be 0 to continue(because requiared register has built well) but special cases could be [1], that's why we check change
						auto expr = CreateExprFromRegisterParts(regParts, externalSymbol.m_reg.m_valueRangeMask, externalSymbol.m_reg.isVector());
						externalSymbol.m_symbol->replaceWith(expr);
						delete externalSymbol.m_symbol->m_symbol;
						delete externalSymbol.m_symbol;
						ctx->m_externalSymbols.erase(it);
					}
				}
				
				for (auto nextBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
					if (nextBlock == nullptr)
						continue;
					if(nextBlock->m_level <= block->m_level)
						continue;
					visitedBlocks.insert(nextBlock);
					resolveExternalSymbols(nextBlock, visitedBlocks);
				}
			}
		}

		struct BlockRegSymbol {
			uint64_t canReadMask = 0x0;
			RegisterParts regParts;
			int symbolId = 0;
			int prevSymbolId = 0;
		};

		struct RegSymbol {
			bool isVector;
			std::map<PrimaryTree::Block*, BlockRegSymbol> blocks;
			std::list<std::pair<int, ExprTree::SymbolLeaf*>> symbols;
			int requiestId = 0;

			RegSymbol(bool isVector = false)
				: isVector(isVector)
			{}
		};

		std::map<PCode::RegisterId, RegSymbol> m_registersToSymbol;
		RegSymbol* m_curRegSymbol = nullptr;

		void requestRegisterParts(PrimaryTree::Block* block, const PCode::Register& reg, uint64_t& mask, RegisterParts& outRegParts, bool isFound = true) {
			if (isFound) {
				auto it = m_decompiledBlocks.find(block);
				if (it != m_decompiledBlocks.end()) {
					auto ctx = it->second.m_execBlockCtx;
					auto regParts = ctx->getRegisterParts(reg, mask);
					outRegParts.insert(outRegParts.begin(), regParts.begin(), regParts.end());
					if (!mask) {
						return;
					}
				}
			}
			
			auto parentsCount = (int)block->m_blocksReferencedTo.size();
			if (parentsCount == 0) {
				return;
			}
			else if (parentsCount == 1) {
				auto parentBlock = *block->m_blocksReferencedTo.begin();
				requestRegisterParts(parentBlock, reg, mask, outRegParts);
				return;
			}


			uint64_t needReadMask = 0x0;
			uint64_t hasReadMask = 0x0;
			std::map<PrimaryTree::Block*, uint64_t> blockPressure;
			PrimaryTree::Block* nextBlock = nullptr;
			auto isSuccess = gatherBlocksWithRegisters(block, reg, mask, needReadMask, hasReadMask, nextBlock);
			if (needReadMask) {
				//todo: we should create symbol anyway [1]: e.g. loop with simple 2 branches (if() mov eax, 1 else mov eax, 2)
				auto symbol = createSymbolForRequest(reg, needReadMask); //after gatherBlocksWithRegisters we need to create a new symbols for gathered blocks with incremented symbol's id
				if ((mask & ~needReadMask) != mask) {
					auto regPart = new RegisterPart(needReadMask, mask & needReadMask, symbol);
					outRegParts.push_back(regPart);
					mask = mask & ~needReadMask;
					if (!mask) {
						return;
					}
				}
			}
			if (nextBlock) {
				requestRegisterParts(nextBlock, reg, mask, outRegParts);
			}
		}

		ExprTree::Node* createSymbolForRequest(const PCode::Register& reg, uint64_t needReadMask) {
			auto& regSymbol = *m_curRegSymbol;
			std::set<int> prevSymbolIds;
			for (auto& it : regSymbol.blocks) {
				if (it.second.prevSymbolId) {
					if (prevSymbolIds.find(it.second.prevSymbolId) == prevSymbolIds.end()) {
						for (auto& it2 : regSymbol.blocks) { //if sets intersect
							if (it2.second.symbolId == it.second.prevSymbolId) {
								it2.second.symbolId = it.second.symbolId;
							}
						}
					}
					prevSymbolIds.insert(it.second.prevSymbolId);
					it.second.prevSymbolId = 0;
				}
			}

			/*if (prevSymbolIds.size() == 1) {
				for (auto& it : regSymbol.symbols) {
					if (prevSymbolIds.count(it.first) != 0) {
						it.first = regSymbol.requiestId;
						return it.second;
					}
				}
			}*/

			auto symbol = new Symbol::LocalVariable(GetBitCountOfMask(needReadMask) / (regSymbol.isVector ? 1 : 8));
			auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
			regSymbol.symbols.push_back(std::make_pair(regSymbol.requiestId, symbolLeaf));

			if (!prevSymbolIds.empty()) {
				for (auto it = regSymbol.symbols.begin(); it != regSymbol.symbols.end(); it ++) {
					auto prevSymbolId = it->first;
					auto prevSymbolLeaf = it->second;
					if (prevSymbolIds.find(prevSymbolId) != prevSymbolIds.end()) {
						it->second->replaceWith(symbolLeaf);
						delete prevSymbolLeaf->m_symbol;
						delete prevSymbolLeaf;
						regSymbol.symbols.erase(it);
					}
				}
			}

			return symbolLeaf;
		}

		void createSymbolAssignments() {
			for (const auto& it : m_registersToSymbol) {
				auto& regSymbol = it.second;
				for (auto symbol : regSymbol.symbols) {
					for (const auto& it2 : regSymbol.blocks) {
						auto decBlock = it2.first;
						auto& blockRegSymbol = it2.second;
						if (symbol.first == blockRegSymbol.symbolId) {
							auto symbolLeaf = symbol.second;
							auto regParts = blockRegSymbol.regParts;

							//to avoide equal assignments: a = a, b = b, ....
							if (false && regParts.size() == 1 && (*regParts.begin())->m_expr == symbolLeaf)
								continue;
							
							auto symbolMask = GetMaskBySize(symbolLeaf->m_symbol->getSize(), regSymbol.isVector);
							auto maskToChange = symbolMask & ~blockRegSymbol.canReadMask;

							if (maskToChange != 0) {
								regParts.push_back(new RegisterPart(symbolMask, maskToChange, symbolLeaf));
							}

							auto expr = CreateExprFromRegisterParts(regParts, symbolMask, regSymbol.isVector);
							decBlock->addSymbolAssignmentLine(symbolLeaf, expr);
						}
					}
				}
			}
		}

		void gatherRegisterPartsInBlock(PrimaryTree::Block* block, const PCode::Register& reg, uint64_t requestMask, uint64_t& needReadMask, uint64_t& hasReadMask, uint64_t pressure) {
			auto remainToReadMask = needReadMask & ~hasReadMask;
			int prevSymbolId = 0;

			auto it = m_curRegSymbol->blocks.find(block);
			if (it != m_curRegSymbol->blocks.end()) {
				auto& blockRegSymbol = it->second;
				if ((requestMask & blockRegSymbol.canReadMask) == 0) {
					blockRegSymbol.prevSymbolId = blockRegSymbol.symbolId;
					blockRegSymbol.symbolId = m_curRegSymbol->requiestId;
					if (pressure == 0x1000000000000000) {
						hasReadMask = ~(remainToReadMask & ~blockRegSymbol.canReadMask);
					}
					else {
						needReadMask |= blockRegSymbol.canReadMask;
					}
					return;
				}
				else {
					prevSymbolId = blockRegSymbol.symbolId;
				}
			}
			
			auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
			auto mask = (pressure == 0x1000000000000000) ? remainToReadMask : requestMask;
			auto regParts = ctx->getRegisterParts(reg, mask, pressure != 0x1000000000000000);

			//think about that more ???
			if (pressure == 0x1000000000000000) { //to symbols assignments be less
				for (auto it = regParts.begin(); it != regParts.end(); it++) {
					if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>((*it)->m_expr)) {
						if (auto symbol = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol)) {
							mask |= (*it)->m_maskToChange;
							regParts.erase(it);
						}
					}
				}
			}

			if (!regParts.empty()) {
				uint64_t canReadMask = 0x0;
				for (auto regPart : regParts) {
					canReadMask |= regPart->m_maskToChange;
				}

				if (pressure == 0x1000000000000000) {
					hasReadMask = ~mask;
				}
				else {
					needReadMask |= canReadMask;
				}

				BlockRegSymbol blockRegSymbol;
				blockRegSymbol.regParts = regParts;
				blockRegSymbol.canReadMask = canReadMask; //that is what read
				blockRegSymbol.symbolId = m_curRegSymbol->requiestId;
				blockRegSymbol.prevSymbolId = prevSymbolId;
				m_curRegSymbol->blocks[block] = blockRegSymbol;
			}
		}

		bool gatherBlocksWithRegisters(PrimaryTree::Block* startBlock, const PCode::Register& reg, uint64_t requestMask, uint64_t& needReadMask, uint64_t& hasReadMask, PrimaryTree::Block*& nextBlock) {
			std::map<PrimaryTree::Block*, uint64_t> blockPressures;
			std::set<PrimaryTree::Block*> handledBlocks;
			blockPressures[startBlock] = 0x1000000000000000;
			bool isStartBlock = true;

			while (true)
			{
				int maxLevel = 0;
				for (auto it : blockPressures) {
					auto block = it.first;
					if (block->m_level > maxLevel) {
						maxLevel = it.first->m_level;
					}
				}

				int nextBlocksCount = 0;
				for (auto it : blockPressures) {
					auto block = it.first;
					auto pressure = it.second;
					if (block->m_level == maxLevel) //find blocks with the highest level down
					{
						bool isLoop = true;
						if (!isStartBlock) {
							if (handledBlocks.find(block) == handledBlocks.end()) {
								gatherRegisterPartsInBlock(block, reg, requestMask, needReadMask, hasReadMask, pressure);

								if (pressure == 0x1000000000000000 && (needReadMask & ~hasReadMask) == 0) {
									nextBlock = block;
									return true;
								}

								handledBlocks.insert(block);
								if(block == startBlock)
									isLoop = false;
							}
							else {
								isLoop = false;
							}
						}
						else {
							isStartBlock = false;
						}

						auto parentsCount = isLoop ? (int)block->m_blocksReferencedTo.size() : block->getRefHighBlocksCount();
						if (parentsCount == 0)
							continue;
						auto bits = (int)ceil(log2((double)parentsCount));
						auto addPressure = pressure >> bits;
						auto restAddPressure = addPressure * ((1 << bits) % parentsCount);
						blockPressures[block] = 0x0;

						for (auto parentBlock : block->m_blocksReferencedTo) {
							if (!isLoop && parentBlock->m_level >= block->m_level)
								continue;

							if (blockPressures.find(parentBlock) == blockPressures.end()) {
								blockPressures[parentBlock] = 0x0;
							}
							blockPressures[parentBlock] += addPressure + restAddPressure;
							restAddPressure = 0;
							nextBlocksCount++;
						}

						if (blockPressures[block] == 0x0) {
							blockPressures.erase(block);
						}
					}
				}

				if (nextBlocksCount == 0)
					break;
			}
			return false;
		}
	};
};