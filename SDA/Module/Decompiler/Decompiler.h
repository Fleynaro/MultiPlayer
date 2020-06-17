#pragma once
#include "DecAsmGraph.h"
#include "Interpreter/InstructionInterpreterDispatcher.h"
#include "Optimization/ExprOptimization.h"

namespace CE::Decompiler
{
	struct DecompiledBlockInfo {
		PrimaryTree::Block* m_treeBlock = nullptr;
		ExecutionBlockContext* m_execBlockCtx = nullptr;
		
		DecompiledBlockInfo() = default;

		bool isDecompiled() {
			return m_treeBlock != nullptr;
		}
	};

	class Decompiler
	{
	public:
		std::function<ExprTree::FunctionCallInfo(int, ExprTree::Node*)> m_funcCallInfoCallback;

		Decompiler(AsmGraph* graph)
			: m_asmGraph(graph)
		{
			m_instructionInterpreterDispatcher = new InstructionInterpreterDispatcher;
			m_funcCallInfoCallback = [](int offset, ExprTree::Node* dst) {
				return ExprTree::GetFunctionCallDefaultInfo();
			};
		}

		~Decompiler() {
			delete m_instructionInterpreterDispatcher;

			for (auto& it : m_decompiledBlocks) {
				delete it.second.m_execBlockCtx;
			}
		}

		void start() {
			auto startBlock = m_asmGraph->getStartBlock();
			std::multiset<AsmGraphBlock*> visitedBlocks;
			decompileAllBlocks();
			resolveExternalSymbols(startBlock, visitedBlocks);
			createSymbolAssignments();
		}

		void optimize() {
			for (auto& it : m_decompiledBlocks) {
				auto treeBlock = it.second.m_treeBlock;
				for (auto line : treeBlock->getLines()) {
					Optimization::Optimize(line->m_destAddr);
					Optimization::Optimize(line->m_srcValue);
				}

				if (treeBlock->m_noJmpCond != nullptr) {
					Optimization::Optimize(treeBlock->m_noJmpCond);
				}
			}
		}

		std::map<AsmGraphBlock*, PrimaryTree::Block*> getResult() {
			std::map<AsmGraphBlock*, PrimaryTree::Block*> result;
			for (auto& it : m_decompiledBlocks) {
				result.insert(std::make_pair(it.first, it.second.m_treeBlock));
			}
			return result;
		}

		void printDebug() {
			for (auto& it : m_asmGraph->m_blocks) {
				auto block = &it.second;
				m_decompiledBlocks[block].m_treeBlock->printDebug();
				printf("Level %i\n================\n", block->m_level);
			}
		}
	private:
		AsmGraph* m_asmGraph;
		InstructionInterpreterDispatcher* m_instructionInterpreterDispatcher;

		std::map<AsmGraphBlock*, DecompiledBlockInfo> m_decompiledBlocks;
		
		void decompileAllBlocks() {
			for (auto& it : m_asmGraph->m_blocks) {
				auto block = &it.second;
				DecompiledBlockInfo decompiledBlock;
				decompiledBlock.m_treeBlock = new PrimaryTree::Block;
				decompiledBlock.m_execBlockCtx = new ExecutionBlockContext(this, block->getMinOffset());

				for (auto off : block->getInstructions()) {
					auto instr = m_asmGraph->m_instructions[off];
					m_instructionInterpreterDispatcher->execute(decompiledBlock.m_treeBlock, decompiledBlock.m_execBlockCtx, instr);
				}

				m_decompiledBlocks[block] = decompiledBlock;
			}
		}

		void resolveExternalSymbols(AsmGraphBlock* block, std::multiset<AsmGraphBlock*>& visitedBlocks) {
			if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
				auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
				for (auto it = ctx->m_externalSymbols.begin(); it != ctx->m_externalSymbols.end(); it ++) {
					auto& externalSymbol = **it;
					auto regId = externalSymbol.m_reg.getId();
					if (m_registersToSymbol.find(regId) == m_registersToSymbol.end()) {
						m_registersToSymbol[regId] = RegSymbol();
					}
					m_curRegSymbol = &m_registersToSymbol[regId];
					m_curRegSymbol->requiestId++;

					auto regParts = externalSymbol.m_regParts;
					auto mask = externalSymbol.m_needReadMask;
					requestRegisterParts(block, externalSymbol.m_reg, mask, regParts, false);
					if (!regParts.empty()) { //regParts.size() > externalSymbol.m_regParts.size()
						auto expr = Register::CreateExprFromRegisterParts(regParts, externalSymbol.m_reg.m_mask);
						externalSymbol.m_symbol->replaceBy(expr);
						delete externalSymbol.m_symbol->m_symbol;
						delete externalSymbol.m_symbol;
						ctx->m_externalSymbols.erase(it);
					}
				}
				
				for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
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
			std::map<AsmGraphBlock*, BlockRegSymbol> blocks;
			std::list<std::pair<int, ExprTree::SymbolLeaf*>> symbols;
			int requiestId = 0;
		};

		std::map<int, RegSymbol> m_registersToSymbol;
		RegSymbol* m_curRegSymbol = nullptr;

		void requestRegisterParts(AsmGraphBlock* block, const Register& reg, uint64_t& mask, RegisterParts& outRegParts, bool isFound = true) {
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
			std::map<AsmGraphBlock*, uint64_t> blockPressure;
			AsmGraphBlock* nextBlock = nullptr;
			if (gatherBlocksWithRegisters(block, reg, needReadMask, hasReadMask, nextBlock, 0x1000000000000000, blockPressure)) {
				auto symbol = createSymbolForRequest(reg, needReadMask);
				if ((mask & ~needReadMask) != mask) {
					auto regPart = new RegisterPart(needReadMask, mask & needReadMask, symbol);
					outRegParts.push_back(regPart);
					mask = mask & ~needReadMask;
					if (!mask) {
						return;
					}
				}

				requestRegisterParts(nextBlock, reg, mask, outRegParts);
			}
		}

		ExprTree::Node* createSymbolForRequest(const Register& reg, uint64_t needReadMask) {
			auto& regSymbol = *m_curRegSymbol;
			std::set<int> prevSymbolIds;
			bool hasNewBlocks = false;
			for (auto& it : regSymbol.blocks) {
				if (it.second.prevSymbolId) {
					prevSymbolIds.insert(it.second.prevSymbolId);
					it.second.prevSymbolId = 0;
				}
				else {
					hasNewBlocks = true;
				}
			}

			if (hasNewBlocks && prevSymbolIds.size() == 1) {
				for (auto& it : regSymbol.symbols) {
					if (prevSymbolIds.count(it.first) != 0) {
						it.first = regSymbol.requiestId;
						return it.second;
					}
				}
			}

			auto symbol = new Symbol::LocalStackVar(rand(), Register::GetBitCountOfMask(needReadMask) / 8);
			auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
			regSymbol.symbols.push_back(std::pair(regSymbol.requiestId, symbolLeaf));

			if (!prevSymbolIds.empty()) {
				for (auto it = regSymbol.symbols.begin(); it != regSymbol.symbols.end(); it ++) {
					if (prevSymbolIds.count(it->first) != 0) {
						it->second->replaceBy(symbolLeaf);
						delete it->second->m_symbol;
						delete it->second;
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
						auto block = it2.first;
						auto& decompiledBlock = m_decompiledBlocks[block];
						auto& blockRegSymbol = it2.second;
						if (symbol.first == blockRegSymbol.symbolId) {
							auto symbolLeaf = symbol.second;
							auto regParts = blockRegSymbol.regParts;
							auto symbolMask = Register::GetMaskBySize(symbolLeaf->m_symbol->getSize());
							auto maskToChange = symbolMask & ~blockRegSymbol.canReadMask;
							
							if (maskToChange != 0) {
								regParts.push_back(new RegisterPart(symbolMask, maskToChange, symbolLeaf));
							}

							auto expr = Register::CreateExprFromRegisterParts(regParts, symbolMask);
							decompiledBlock.m_treeBlock->addLine(symbolLeaf, expr);
						}
					}
				}
			}
		}

		void gatherRegisterPartsInBlock(AsmGraphBlock* block, const Register& reg, uint64_t& needReadMask, uint64_t& hasReadMask, uint64_t pressure) {
			auto remainToReadMask = needReadMask & ~hasReadMask;
			auto it = m_curRegSymbol->blocks.find(block);
			if (it != m_curRegSymbol->blocks.end()) {
				auto& blockRegSymbol = it->second;
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
			
			auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
			auto mask = (pressure == 0x1000000000000000) ? remainToReadMask : -1;
			auto regParts = ctx->getRegisterParts(reg, mask);

			for (auto it = regParts.begin(); it != regParts.end(); it++) {
				if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>((*it)->m_expr)) {
					if (auto symbol = dynamic_cast<Symbol::LocalStackVar*>(symbolLeaf->m_symbol)) {
						mask |= (*it)->m_maskToChange;
						regParts.erase(it);
					}
				}
			}

			if (!regParts.empty()) {
				uint64_t canReadMask = 0x0;
				for (auto regPart : regParts) {
					canReadMask |= regPart->m_regMask;
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
				m_curRegSymbol->blocks[block] = blockRegSymbol;
			}
		}

		bool gatherBlocksWithRegisters(AsmGraphBlock* block, const Register& reg, uint64_t& needReadMask, uint64_t& hasReadMask, AsmGraphBlock*& nextBlock, uint64_t incomingPressure, std::map<AsmGraphBlock*, uint64_t>& blockPressure) {
			auto parentsCount = block->getRefHighBlocksCount();
			if (parentsCount == 0)
				return false;

			auto bits = (int)ceil(log2((double)parentsCount));
			auto addPressure = incomingPressure >> bits;
			auto restAddPressure = addPressure * ((1 << bits) % parentsCount);

			for (auto parentBlock : block->m_blocksReferencedTo) {
				if (parentBlock->m_level >= block->m_level)
					break;

				auto isConditionOnce = false;
				auto pressure = addPressure + restAddPressure;
				restAddPressure = 0;

				if (parentBlock->isCondition()) {
					if (blockPressure.find(parentBlock) != blockPressure.end()) {
						pressure += blockPressure[parentBlock];
						blockPressure[parentBlock] = 0x0;
					}
					else {
						isConditionOnce = true;
						blockPressure[parentBlock] = pressure;
					}
				}

				if (!isConditionOnce) {
					gatherRegisterPartsInBlock(parentBlock, reg, needReadMask, hasReadMask, pressure);

					if (pressure == 0x1000000000000000 && (needReadMask & ~hasReadMask) == 0) {
						nextBlock = parentBlock;
						return true;
					}

					if (gatherBlocksWithRegisters(parentBlock, reg, needReadMask, hasReadMask, nextBlock, pressure, blockPressure))
						return true;
				}
			}

			//if condition blocks remain with some pressure
			if (incomingPressure == 0x1000000000000000) {
				do {
					int maxLevel = 0;
					auto blockOnMinLevelIt = blockPressure.end();

					for (auto it = blockPressure.begin(); it != blockPressure.end(); it++) {
						if (it->second != 0x0) {
							if (it->first->m_level > maxLevel) {
								blockOnMinLevelIt = it;
								maxLevel = it->first->m_level;
							}
						}
					}

					if (blockOnMinLevelIt != blockPressure.end()) {
						auto remainPressure = blockOnMinLevelIt->second;
						blockOnMinLevelIt->second = 0;
						gatherRegisterPartsInBlock(blockOnMinLevelIt->first, reg, needReadMask, hasReadMask, remainPressure);
						if (gatherBlocksWithRegisters(blockOnMinLevelIt->first, reg, needReadMask, hasReadMask, nextBlock, remainPressure, blockPressure))
							return true;
						
					}
					else {
						break;
					}
				} while (true);
			}

			return false;
		}
	};
};