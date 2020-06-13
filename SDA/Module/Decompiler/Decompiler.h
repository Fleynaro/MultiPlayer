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
			return createExprFromRegisterParts(regParts, regInfo.m_mask);
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

		struct BlockInfo {
			AsmGraphBlock* block = nullptr;
			std::list<RegisterPart> regParts;
		};

		void requestRegisterParts(AsmGraphBlock* block, const Register::RegInfo& regInfo, uint64_t& mask, std::list<RegisterPart>& outRegParts) {
			auto it = m_decompiledBlocks.find(block);
			if (it != m_decompiledBlocks.end()) {
				auto ctx = it->second.m_execBlockCtx;
				auto regParts = ctx->getRegisterParts(regInfo, mask);
				outRegParts.insert(outRegParts.begin(), regParts.begin(), regParts.end());
				if (!mask) {
					return;
				}
			}
			
			auto parentsCount = block->m_blocksReferencedTo.size();
			if (parentsCount == 0) {
				return;
			}
			else if (parentsCount == 1) {
				auto parentBlock = *block->m_blocksReferencedTo.begin();
				requestRegisterParts(parentBlock, regInfo, mask, outRegParts);
				return;
			}


			uint64_t maxMaskInLoop = 0x0;
			uint64_t maskOutLoop = 0x0;
			std::map<AsmGraphBlock*, uint64_t> blockPressure;
			std::list<BlockInfo> blocks;
			if (gatherBlocksWithRegisters(block, regInfo, mask, maxMaskInLoop, maskOutLoop, blocks, 0x1000000000000000, blockPressure)) {
				bool isFound = true;
				if (maxMaskInLoop) {
					RegisterPart info;
					info.regMask = maxMaskInLoop;
					info.maskToChange = mask & maxMaskInLoop;
					info.expr = createSymbolForRegister(blocks, maxMaskInLoop);
					outRegParts.push_back(info);
					mask = mask & ~maxMaskInLoop;
					if (!mask) {
						return;
					}
				}

				requestRegisterParts(blocks.rbegin()->block, regInfo, mask, outRegParts);
			}
		}

		ExprTree::Node* createSymbolForRegister(std::list<BlockInfo>& blockInfos, uint64_t requestRegMask) {
			Symbol::Symbol* symbol = new Symbol::LocalStackVar(rand());
			auto symbolNode = new ExprTree::SymbolLeaf(symbol);
			
			for (const auto& blockInfo : blockInfos) {
				auto& decompiledBlock = m_decompiledBlocks[blockInfo.block];

				auto regParts = blockInfo.regParts;
				auto maskToChange = requestRegMask;
				for (auto regPart : regParts) {
					maskToChange &= ~regPart.maskToChange;
				}
				if (maskToChange) {
					RegisterPart symbolPart;
					symbolPart.expr = symbolNode;
					symbolPart.regMask = requestRegMask;
					symbolPart.maskToChange = maskToChange;
					regParts.push_back(symbolPart);
				}

				auto expr = createExprFromRegisterParts(regParts, requestRegMask);
				decompiledBlock.m_treeBlock->addLine(symbolNode, expr);
			}
			return symbolNode;
		}

		void gatherRegisterPartsInBlock(AsmGraphBlock* block, const Register::RegInfo& regInfo, uint64_t checkMask, uint64_t& maskInLoop, uint64_t& maskOutLoop, std::list<BlockInfo>& blocks, uint64_t pressure) {
			auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
			BlockInfo info;
			info.block = block;

			if (pressure == 0x1000000000000000) {
				auto mask = maskInLoop & ~maskOutLoop;
				info.regParts = ctx->getRegisterParts(regInfo, mask);
				maskOutLoop = mask;
				blocks.push_back(info);
			}
			else {
				auto mask = (uint64_t)-1;// checkMask | ((uint64_t)1 << 63);
				//TODO: передавать маску дальше по линейному списку, чтобы не делать много символов, ибо регистры могут перезаписаться (снаружи цикла это уже сделано, надо внутри)
				info.regParts = ctx->getRegisterParts(regInfo, mask);
				//find max mask
				for (auto regPart : info.regParts) {
					if (Register::GetBitCountOfMask(regPart.regMask) > Register::GetBitCountOfMask(maskInLoop)) {
						maskInLoop = regPart.regMask;
					}
				}

				if (!info.regParts.empty())
					blocks.push_back(info);
			}
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
					gatherRegisterPartsInBlock(parentBlock, regInfo, checkMask, maskInLoop, maskOutLoop, blocks, pressure);

					if (pressure == 0x1000000000000000 && !maskOutLoop) {
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
						gatherRegisterPartsInBlock(blockOnMinLevelIt->first, regInfo, checkMask, maskInLoop, maskOutLoop, blocks, remainPressure);
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