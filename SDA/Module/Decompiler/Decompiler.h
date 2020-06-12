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

		ExprTree::Node* requestRegister(ZydisRegister reg) {
			std::list<RegisterPart> regParts;
			auto regInfo = Register::GetRegInfo(reg);
			auto mask = regInfo.m_mask;
			requestRegisterParts(m_curBlock, regInfo, mask, regParts);
			return createExprFromRegisterParts(regParts);
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

			if (visitedBlocks.count(block) == block->m_blocksReferencedTo.size()) {
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
					visitedBlocks.insert(nextBlock);
					decompile(nextBlock, visitedBlocks);
				}
			}
		}

		ExprTree::Node* createExprFromRegisterParts(const std::list<RegisterPart>& regParts) {
			ExprTree::Node* resultExpr = nullptr;

			//sort

			for (auto regPart : regParts) {
				auto sameRegExpr = regPart.expr;
				int leftBitShift = Register::GetShiftValueOfMask(regPart.regMask);
				if (leftBitShift != 0) {
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(leftBitShift), ExprTree::Shr);
				}
				//for signed register operations and etc...
				sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(regPart.mulMask), ExprTree::And);
				if (resultExpr) {
					resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
				}
				else {
					resultExpr = sameRegExpr;
				}
			}
			return resultExpr;
		}

		struct BlockInfo {
			AsmGraphBlock* block = nullptr;
			std::list<RegisterPart> regParts;
		};

		void requestRegisterParts(AsmGraphBlock* block, const Register::RegInfo& regInfo, uint64_t& mask, std::list<RegisterPart>& regParts, bool isFound = true) {
			if (isFound) {
				auto it = m_decompiledBlocks.find(block);
				if (it != m_decompiledBlocks.end()) {
					auto ctx = it->second.m_execBlockCtx;
					regParts = ctx->getRegisterParts(regInfo, mask);
					if (!mask) {
						return;
					}
				}
			}
			
			auto parentsCount = block->m_blocksReferencedTo.size();
			if (parentsCount == 0) {
				
			}
			else if (parentsCount == 1) {
				auto parentBlock = *block->m_blocksReferencedTo.begin();
				requestRegisterParts(parentBlock, regInfo, mask, regParts);
				if (!mask) {
					return;
				}
			}


			uint64_t maskInLoop = 0x0;
			uint64_t maskOutLoop = 0x0;
			std::map<AsmGraphBlock*, uint64_t> blockPressure;
			std::list<BlockInfo> blocks;
			if (gatherBlocksWithRegisters(block, regInfo, mask, maskInLoop, maskOutLoop, blocks, 0x1000000000000000, blockPressure)) {
				if (maskInLoop) {
					RegisterPart info;
					info.regMask = maskInLoop;
					info.mulMask = mask & maskInLoop;
					info.expr = createSymbolForRegister(blocks);
					regParts.push_back(info);
					mask = mask & ~maskInLoop;
					if (!mask) {
						return;
					}
				}

				requestRegisterParts(blocks.rbegin()->block, regInfo, mask, regParts, false);
			}
		}

		ExprTree::Node* createSymbolForRegister(std::list<BlockInfo>& blockInfos) {
			Symbol::Symbol* symbol = new Symbol::LocalStackVar(rand());
			auto symbolNode = new ExprTree::SymbolLeaf(symbol);
			
			for (const auto& blockInfo : blockInfos) {
				auto& decompiledBlock = m_decompiledBlocks[blockInfo.block];
				auto expr = createExprFromRegisterParts(blockInfo.regParts);
				decompiledBlock.m_treeBlock->addLine(symbolNode, expr);
			}
			return symbolNode;
		}

		bool gatherBlocksWithRegisters(AsmGraphBlock* block, const Register::RegInfo& regInfo, uint64_t checkMask, uint64_t& maskInLoop, uint64_t& maskOutLoop, std::list<BlockInfo>& blocks, uint64_t incomingPressure, std::map<AsmGraphBlock*, uint64_t>& blockPressure) {
			auto parentsCount = (int)block->m_blocksReferencedTo.size();
			if (parentsCount == 0)
				return false;

			auto bits = (int)ceil(log2((double)parentsCount));
			auto addPressure = incomingPressure >> bits;
			auto restAddPressure = addPressure * ((1 << bits) % parentsCount);

			for (auto parentBlock : block->m_blocksReferencedTo) {
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
					auto ctx = m_decompiledBlocks[parentBlock].m_execBlockCtx;
					BlockInfo info;
					info.block = parentBlock;

					if (pressure == 0x1000000000000000) {
						auto mask = maskInLoop & ~maskOutLoop;
						info.regParts = ctx->getRegisterParts(regInfo, mask);
						maskOutLoop = mask;
					}
					else {
						auto mask = checkMask | (1 << 63);
						//TODO: передавать маску дальше по линейному списку, чтобы не делать много символов, ибо регистры могут перезаписаться (снаружи цикла это уже сделано, надо внутри)
						info.regParts = ctx->getRegisterParts(regInfo, mask);
						//find max mask
						for (auto regPart : info.regParts) {
							if (Register::GetBitCountOfMask(regPart.regMask) > Register::GetBitCountOfMask(maskInLoop)) {
								maskInLoop = regPart.regMask;
							}
						}
					}
					blocks.push_back(info);

					if (!maskOutLoop) {
						//create symbol on blocks further
						return true;
					}

					if (gatherBlocksWithRegisters(parentBlock, regInfo, checkMask, maskInLoop, maskOutLoop, blocks, pressure, blockPressure))
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
						if (gatherBlocksWithRegisters(blockOnMinLevelIt->first, regInfo, checkMask, maskInLoop, maskOutLoop, blocks, remainPressure, blockPressure))
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