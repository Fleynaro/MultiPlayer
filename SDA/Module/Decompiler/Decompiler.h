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

				if (treeBlock->m_jmpCond != nullptr) {
					Optimization::Optimize(treeBlock->m_jmpCond);
				}
			}
		}

		ExprTree::Node* requestRegister(ZydisRegister reg) {
			std::list<AsmGraphBlock*> blocks;
			return requestRegister(m_curBlock, reg, blocks);
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

			if (m_decompiledBlocks.find(block) == m_decompiledBlocks.end()) {
				m_decompiledBlocks.insert(std::make_pair(block, DecompiledBlockInfo()));
			}
			auto& decompiledBlock = m_decompiledBlocks[block];

			if (visitedBlocks.count(block) == block->m_blocksReferencedTo.size()) {
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

		ExprTree::Node* requestRegister(AsmGraphBlock* block, ZydisRegister reg, std::list<AsmGraphBlock*>& blocksInLoop) {
			if (m_decompiledBlocks.find(block) != m_decompiledBlocks.end()) {
				auto& registers = m_decompiledBlocks[block].m_execBlockCtx->m_registers;
				if (registers.find(reg) != registers.end()) {
					if (!blocksInLoop.empty()) {
						blocksInLoop.push_back(block);
						return createSymbolForRegister(reg, blocksInLoop);
					}
					else {
						return registers[reg];
					}
				}
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
				return requestRegister(parentBlock, reg, blocksInLoop);
			}


			std::map<AsmGraphBlock*, uint64_t> blockPressure = { std::make_pair(block, 0x1000000000000000) };
			auto highestBlockInLoop = getMostUpBlockInJoinedLoop(block, reg, blocksInLoop, blockPressure);
			if (highestBlockInLoop != nullptr) {
				return requestRegister(highestBlockInLoop, reg, blocksInLoop);
			}

			return nullptr;
		}

		AsmGraphBlock* getMostUpBlockInJoinedLoop(AsmGraphBlock* block, ZydisRegister reg, std::list<AsmGraphBlock*>& blocksInLoop, std::map<AsmGraphBlock*, uint64_t>& blockPressure) {
			auto parentsCount = (int)block->m_blocksReferencedTo.size();
			if (parentsCount == 0)
				return nullptr;

			auto bits = (int)ceil(log2((double)parentsCount));
			auto addPressure = blockPressure[block] >> bits;
			auto restAddPressure = addPressure * ((1 << bits) % parentsCount);

			for (auto parentBlock : block->m_blocksReferencedTo) {
				auto isConditionOnce = false;
				auto pressure = addPressure + restAddPressure;
				restAddPressure = 0;
				if (blockPressure.find(parentBlock) != blockPressure.end()) {
					pressure += blockPressure[parentBlock];
				} else {
					if (parentBlock->isCondition()) {
						isConditionOnce = true;
					}
				}

				blockPressure[parentBlock] = pressure;

				if (!isConditionOnce) {
					if (pressure == 0x1000000000000000) {
						return parentBlock;
					}
					auto& registers = m_decompiledBlocks[parentBlock].m_execBlockCtx->m_registers;
					if (registers.find(reg) != registers.end()) {
						blocksInLoop.push_back(parentBlock);
					}
					auto block = getMostUpBlockInJoinedLoop(parentBlock, reg, blocksInLoop, blockPressure);
					if (block != nullptr) {
						return block;
					}
				}
			}

			return nullptr;
		}

		ExprTree::Node* createSymbolForRegister(ZydisRegister reg, std::list<AsmGraphBlock*>& blocksInLoop) {
			Symbol::Symbol* symbol = new Symbol::LocalStackVar(rand());
			auto symbolNode = new ExprTree::SymbolLeaf(symbol);
			m_decompiledBlocks[m_curBlock].m_execBlockCtx->m_registers[reg] = symbolNode;

			for (auto block : blocksInLoop) {
				auto& decompiledBlock = m_decompiledBlocks[block];
				decompiledBlock.m_treeBlock->addLine(symbolNode, decompiledBlock.m_execBlockCtx->m_registers[reg]);
			}
			return symbolNode;
		}
	};
};