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
			std::list<AsmGraphBlock*> blocks;
			return requestRegister(m_curBlock, reg, blocks);
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

		ExprTree::Node* createRegisterExprFromBlock(AsmGraphBlock* block, ZydisRegister reg, uint64_t& resultMask) {
			auto ctx = m_decompiledBlocks[block].m_execBlockCtx;
			auto regInfo = Register::GetRegInfo(reg);
			uint64_t mask = regInfo.m_mask;

			struct sameRegInfo {
				uint64_t mask = -1;
				ZydisRegister reg = ZYDIS_REGISTER_NONE;
				ExprTree::Node* expr = nullptr;
			};
			std::list<sameRegInfo> sameRegisters;

			for (auto sameReg : regInfo.m_sameRegisters) {
				auto reg = sameReg.first;
				auto regExpr = ctx->getRegister(reg);
				auto sameRegMask = sameReg.second;
				if (regExpr != nullptr) {
					auto maskToChange = mask & ~sameRegMask;
					if (maskToChange != mask) {
						sameRegInfo info;
						info.mask = mask & sameRegMask;
						info.reg = reg;
						info.expr = regExpr;
						sameRegisters.push_back(info);
						mask = maskToChange;
					}
				}

				if (mask == 0)
					break;
			}

			resultMask = mask;
			ExprTree::Node* resultExpr = nullptr;
			if (mask != regInfo.m_mask) {
				for (auto it = sameRegisters.rbegin(); it != sameRegisters.rend(); it ++) {
					auto sameReg = *it;
					auto sameRegExpr = sameReg.expr;
					int leftBitShift = Register::GetShiftValueOfMask(sameReg.mask);
					if (leftBitShift != 0) {
						sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(leftBitShift), ExprTree::Shr);
					}
					//for signed register operations and etc...
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(sameReg.mask), ExprTree::And);
					if (resultExpr) {
						resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
					}
					else {
						resultExpr = sameRegExpr;
					}
				}
			}
			return resultExpr;
		}

		struct RegPartInfo {
			uint64_t mask = -1;
			ExprTree::Node* expr = nullptr;
		};

		struct BlockInLoopInfo {
			AsmGraphBlock* block = nullptr;
			uint64_t mask = -1;
			ZydisRegister reg = ZYDIS_REGISTER_NONE;
			ExprTree::Node* expr = nullptr;
		};

		void requestRegisters(AsmGraphBlock* block, Register::RegInfo& regInfo, uint64_t& mask, std::list<RegPartInfo>& registerParts, std::list<BlockInLoopInfo>& blocksInLoop) {
			auto it = m_decompiledBlocks.find(block);
			if (it != m_decompiledBlocks.end()) {
				auto ctx = it->second.m_execBlockCtx;

				if (blocksInLoop.empty()) {
					for (auto sameReg : regInfo.m_sameRegisters) {
						auto reg = sameReg.first;
						auto regExpr = ctx->getRegister(reg);
						auto sameRegMask = sameReg.second;
						if (regExpr != nullptr) {
							auto maskToChange = mask & ~sameRegMask;
							if (maskToChange != mask) {
								RegPartInfo info;
								info.mask = mask & sameRegMask;
								info.expr = regExpr;
								registerParts.push_back(info);
								mask = maskToChange;
							}
						}

						if (mask == 0)
							return;
					}
				}
				else {

				}

				/*auto& registers = m_decompiledBlocks[block].m_execBlockCtx->m_registers;
				if (registers.find(reg) != registers.end()) {
					if (!blocksInLoop.empty()) {
						blocksInLoop.push_back(block);
						return createSymbolForRegister(reg, blocksInLoop);
					}
					else {
						return registers[reg];
					}
				}*/
			}
			
			auto parentsCount = block->m_blocksReferencedTo.size();
			if (parentsCount == 0) {
				if (!blocksInLoop.empty()) {
					return createSymbolForRegister(reg, blocksInLoop);
				}
				return nullptr;
			}
			else if (parentsCount == 1) {
				auto parentBlock = *block->m_blocksReferencedTo.begin();
				return requestRegisters(parentBlock, regInfo, mask, registerParts, blocksInLoop);
			}


			std::map<AsmGraphBlock*, uint64_t> blockPressure;
			auto highestBlockInLoop = getMostUpBlockInJoinedLoop(block, reg, blocksInLoop, 0x1000000000000000, blockPressure);
			if (highestBlockInLoop != nullptr) {
				return requestRegister(highestBlockInLoop, reg, blocksInLoop);
			}

			return nullptr;
		}

		AsmGraphBlock* getMostUpBlockInJoinedLoop(AsmGraphBlock* block, ZydisRegister reg, std::list<AsmGraphBlock*>& blocksInLoop, uint64_t incomingPressure, std::map<AsmGraphBlock*, uint64_t>& blockPressure) {
			auto parentsCount = (int)block->m_blocksReferencedTo.size();
			if (parentsCount == 0)
				return nullptr;

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
					if (pressure == 0x1000000000000000) {
						return parentBlock;
					}
					auto& registers = m_decompiledBlocks[parentBlock].m_execBlockCtx->m_registers;
					if (registers.find(reg) != registers.end()) {
						blocksInLoop.push_back(parentBlock);
					}
					auto block = getMostUpBlockInJoinedLoop(parentBlock, reg, blocksInLoop, pressure, blockPressure);
					if (block != nullptr) {
						return block;
					}
				}
			}

			//if condition blocks remain stored some pressure
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
						auto block = getMostUpBlockInJoinedLoop(blockOnMinLevelIt->first, reg, blocksInLoop, remainPressure, blockPressure);
						if (block != nullptr) {
							return block;
						}
					}
					else {
						break;
					}
				} while (true);
			}

			return nullptr;
		}

		ExprTree::Node* createSymbolForRegister(ZydisRegister reg, std::list<AsmGraphBlock*>& blocksInLoop) {
			Symbol::Symbol* symbol = new Symbol::LocalStackVar(rand());
			auto symbolNode = new ExprTree::SymbolLeaf(symbol);
			//m_decompiledBlocks[m_curBlock].m_execBlockCtx->m_registers[reg] = symbolNode;

			for (auto block : blocksInLoop) {
				auto& decompiledBlock = m_decompiledBlocks[block];
				decompiledBlock.m_treeBlock->addLine(symbolNode, decompiledBlock.m_execBlockCtx->m_registers[reg]);
			}
			return symbolNode;
		}
	};
};