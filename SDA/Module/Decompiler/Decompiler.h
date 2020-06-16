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
			decompile(startBlock, visitedBlocks);
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

		ExprTree::Node* requestRegister(const Register& reg) {
			std::list<RegisterPart> regParts;
			auto mask = reg.m_mask;

			if (m_registersToSymbol.find(reg.getId()) == m_registersToSymbol.end()) {
				m_registersToSymbol[reg.getId()] = RegSymbol();
			}
			m_curRegSymbol = &m_registersToSymbol[reg.getId()];
			m_curRegSymbol->requiestId++;

			requestRegisterParts(m_curBlock, reg, mask, regParts);
			return createExprFromRegisterParts(regParts, reg.m_mask);
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

		AsmGraphBlock* m_curBlock = nullptr;
		std::map<AsmGraphBlock*, DecompiledBlockInfo> m_decompiledBlocks;
		
		void decompile(AsmGraphBlock* block, std::multiset<AsmGraphBlock*>& visitedBlocks) {
			m_curBlock = block;

			if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
				if (m_decompiledBlocks.find(block) == m_decompiledBlocks.end()) {
					m_decompiledBlocks.insert(std::make_pair(block, DecompiledBlockInfo()));
				}
				auto& decompiledBlock = m_decompiledBlocks[block];
				decompiledBlock.m_treeBlock = new PrimaryTree::Block;
				decompiledBlock.m_execBlockCtx = new ExecutionBlockContext(this, block->getMinOffset());

				for (auto off : block->getInstructions()) {
					auto instr = m_asmGraph->m_instructions[off];
					m_instructionInterpreterDispatcher->execute(decompiledBlock.m_treeBlock, decompiledBlock.m_execBlockCtx, instr);
				}

				for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
					if (nextBlock == nullptr)
						continue;
					if(nextBlock->m_level <= block->m_level)
						continue;
					visitedBlocks.insert(nextBlock);
					decompile(nextBlock, visitedBlocks);
				}
			}
		}

		ExprTree::Node* createExprFromRegisterParts(std::list<RegisterPart> regParts, uint64_t requestRegMask) {
			ExprTree::Node* resultExpr = nullptr;

			regParts.sort([](const RegisterPart& a, const RegisterPart& b) {
				return a.regMask > b.regMask;
				});

			for (auto regPart : regParts) {
				auto sameRegExpr = regPart.expr;
				int bitShift = Register::GetShiftValueOfMask(regPart.regMask | ~requestRegMask);

				if (resultExpr) {
					//for signed register operations and etc...
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(regPart.regMask >> bitShift), ExprTree::And);
				}

				if (bitShift != 0) {
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(bitShift), ExprTree::Shl);
				}
				
				if (resultExpr) {
					resultExpr = new ExprTree::OperationalNode(resultExpr, new ExprTree::NumberLeaf(~regPart.maskToChange), ExprTree::And);
					resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
				}
				else {
					resultExpr = sameRegExpr;
				}
			}
			return resultExpr;
		}

		struct BlockRegSymbol {
			uint64_t canReadMask = 0x0;
			std::list<RegisterPart> regParts;
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

		void requestRegisterParts(AsmGraphBlock* block, const Register& reg, uint64_t& mask, std::list<RegisterPart>& outRegParts) {
			auto it = m_decompiledBlocks.find(block);
			if (it != m_decompiledBlocks.end()) {
				auto ctx = it->second.m_execBlockCtx;
				auto regParts = ctx->getRegisterParts(reg, mask);
				outRegParts.insert(outRegParts.begin(), regParts.begin(), regParts.end());
				if (!mask) {
					return;
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
			if (gatherBlocksWithRegisters(block, reg, mask, needReadMask, hasReadMask, nextBlock, 0x1000000000000000, blockPressure)) {
				bool isFound = true;
				if (needReadMask) {
					RegisterPart info;
					info.regMask = needReadMask;
					info.maskToChange = mask & needReadMask;
					info.expr = createSymbolForRegister(reg);
					outRegParts.push_back(info);
					mask = mask & ~needReadMask;
					if (!mask) {
						return;
					}
				}

				requestRegisterParts(nextBlock, reg, mask, outRegParts);
			}
		}

		ExprTree::Node* createSymbolForRegister(const Register& reg) {
			auto& regSymbol = *m_curRegSymbol;
			for (auto& it : regSymbol.blocks) {
				if (it.second.prevSymbolId) {
					for (auto& symbol : regSymbol.symbols) {
						symbol.first = it.second.symbolId;
					}
					it.second.prevSymbolId = 0;
				}
			}


			if (!regSymbol.symbol) {
				auto symbol = new Symbol::LocalStackVar(rand()); //указать размер временного символа, не использовать маски при чтении
				regSymbol.symbol = new ExprTree::SymbolLeaf(symbol);
			}

			for (const auto& blockInfo : blockInfos) {
				auto& decompiledBlock = m_decompiledBlocks[blockInfo.block];

				BlockRegSymbol blockRegSymbol;
				blockRegSymbol.regParts = blockInfo.regParts;
				regSymbol.blocks[blockInfo.block] = blockRegSymbol;
			}

			return regSymbol.symbol;
		}

		void gatherRegisterPartsInBlock(AsmGraphBlock* block, const Register& reg, uint64_t checkMask, uint64_t& needReadMask, uint64_t& hasReadMask, uint64_t pressure) {
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
					/*if (Register::GetBitCountOfMask(blockRegSymbol.canReadMask) > Register::GetBitCountOfMask(needReadMask)) {
						needReadMask = blockRegSymbol.canReadMask;
					}*/
					needReadMask |= blockRegSymbol.canReadMask;
				}

				return;
			}
			
			auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
			BlockRegSymbol blockRegSymbol;

			if (pressure == 0x1000000000000000) {
				auto mask = remainToReadMask;
				blockRegSymbol.regParts = ctx->getRegisterParts(reg, mask);
				hasReadMask = ~mask;
			}
			else {
				auto mask = (uint64_t)-1;
				//TODO: передавать маску дальше по линейному списку, чтобы не делать много символов, ибо регистры могут перезаписаться (снаружи цикла это уже сделано, надо внутри)
				blockRegSymbol.regParts = ctx->getRegisterParts(reg, mask);
			}

			uint64_t canReadMask = 0x0;
			for (auto regPart : blockRegSymbol.regParts) {
				canReadMask |= regPart.regMask;
			}

			if (pressure != 0x1000000000000000) {
				/*if (Register::GetBitCountOfMask(canReadMask) > Register::GetBitCountOfMask(needReadMask)) {
					needReadMask = canReadMask;
				}*/
				needReadMask |= blockRegSymbol.canReadMask;
			}

			blockRegSymbol.canReadMask = canReadMask; //that is what read
			blockRegSymbol.symbolId = m_curRegSymbol->requiestId;
			m_curRegSymbol->blocks[block] = blockRegSymbol;
		}

		bool gatherBlocksWithRegisters(AsmGraphBlock* block, const Register& reg, uint64_t checkMask, uint64_t& needReadMask, uint64_t& hasReadMask, AsmGraphBlock*& nextBlock, uint64_t incomingPressure, std::map<AsmGraphBlock*, uint64_t>& blockPressure) {
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
					gatherRegisterPartsInBlock(parentBlock, reg, checkMask, needReadMask, hasReadMask, pressure);

					if (pressure == 0x1000000000000000 && needReadMask & ~hasReadMask == 0) {
						nextBlock = parentBlock;
						return true;
					}

					if (gatherBlocksWithRegisters(parentBlock, reg, checkMask, needReadMask, hasReadMask, nextBlock, pressure, blockPressure))
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
						gatherRegisterPartsInBlock(blockOnMinLevelIt->first, reg, checkMask, needReadMask, hasReadMask, remainPressure);
						if (gatherBlocksWithRegisters(blockOnMinLevelIt->first, reg, checkMask, needReadMask, hasReadMask, nextBlock, remainPressure, blockPressure))
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