#pragma once
#include "DecAsmGraph.h"
#include "Interpreter/InstructionInterpreterDispatcher.h"
#include "Optimization/ExprOptimization.h"

namespace CE::Decompiler
{
	struct DecompiledBlockInfo {
		PrimaryTree::Block* m_treeBlock = nullptr;
		ExecutionBlockContext* m_execBlockCtx = nullptr;
		std::set<AsmGraphBlock*> m_comingInBlocks;

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
			: m_graph(graph)
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
			auto startBlock = m_graph->getStartBlock();
			decompile(startBlock);
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
			std::list<DecompiledBlockInfo*> list;
			return requestRegister(m_curBlock, reg, list);
		}

		void printDebug() {
			for (auto& it : m_graph->m_blocks) {
				auto block = &it.second;
				m_decompiledBlocks[block].m_treeBlock->printDebug();
				printf("Level %i\n================\n", block->m_level);
			}
		}
	private:
		AsmGraph* m_graph;
		InstructionInterpreterDispatcher* m_instructionInterpreterDispatcher;

		AsmGraphBlock* m_curBlock = nullptr;
		std::map<AsmGraphBlock*, DecompiledBlockInfo> m_decompiledBlocks;
		std::list<AsmGraphBlock*> m_curGraphPath; //need?
		std::stack<AsmGraphBlock*> m_beginLoopBlocks;
		std::list<std::pair<AsmGraphBlock*, AsmGraphBlock*>> m_blockLoops; //list?
		
		void decompile(AsmGraphBlock* block) {
			m_curBlock = block;
			if (block == nullptr)
				return;

			if (m_decompiledBlocks.find(block) == m_decompiledBlocks.end()) {
				m_decompiledBlocks.insert(std::make_pair(block, DecompiledBlockInfo()));
			}
			auto decompiledBlock = &m_decompiledBlocks[block];

			if (!m_curGraphPath.empty()) {
				auto parentBlock = m_curGraphPath.back();
				decompiledBlock->m_comingInBlocks.insert(parentBlock);
			}
			m_curGraphPath.push_back(block);

			//end of some loop
			if (decompiledBlock->m_comingInBlocks.size() >= 2) {
				m_blockLoops.push_back(std::make_pair(m_beginLoopBlocks.top(), block));
				m_beginLoopBlocks.pop();
			}

			if (block->m_blocksReferencedTo.size() == decompiledBlock->m_comingInBlocks.size()) {
				decompiledBlock->m_treeBlock = new PrimaryTree::Block;
				decompiledBlock->m_execBlockCtx = new ExecutionBlockContext(this, block->getMinOffset());

				for (auto off : block->getInstructions()) {
					auto instr = m_graph->m_instructions[off];
					m_instructionInterpreterDispatcher->execute(decompiledBlock->m_treeBlock, decompiledBlock->m_execBlockCtx, instr);
				}

				auto block1 = block->getNextNearBlock();
				auto block2 = block->getNextFarBlock();
				if (block->isCondition() && block2->m_level < block1->m_level) {
					std::swap(block1, block2);
				}

				decompile(block1);
				if (block->isCondition()) {
					m_beginLoopBlocks.push(block);
				}
				decompile(block2);
			}

			m_curGraphPath.pop_back();
		}

		ExprTree::Node* requestRegister(AsmGraphBlock* block, ZydisRegister reg, std::list<DecompiledBlockInfo*>& blocksInLoop) {
			if (m_decompiledBlocks.find(block) != m_decompiledBlocks.end()) {
				auto& registers = m_decompiledBlocks[block].m_execBlockCtx->m_registers;
				if (registers.find(reg) != registers.end()) {
					if (!blocksInLoop.empty()) {
						blocksInLoop.push_back(&m_decompiledBlocks[block]);
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

			auto highestBlockInLoop = getMostUpBlockInJoinedLoop(block);
			if (highestBlockInLoop != nullptr) {
				for (auto& it : m_decompiledBlocks) {
					if (it.first->m_level > highestBlockInLoop->m_level && it.first->m_level < block->m_level) {
						auto& registers = it.second.m_execBlockCtx->m_registers;
						if (registers.find(reg) != registers.end()) { //перезапись регистра, лишние(временные) не учитывать
							blocksInLoop.push_back(&it.second);
						}
					}
				}
				return requestRegister(highestBlockInLoop, reg, blocksInLoop);
			}

			return nullptr; //continue
		}

		ExprTree::Node* createSymbolForRegister(ZydisRegister reg, std::list<DecompiledBlockInfo*>& blocksInLoop) {
			Symbol::Symbol* symbol = new Symbol::LocalStackVar(rand());
			auto symbolNode = new ExprTree::SymbolLeaf(symbol);
			m_decompiledBlocks[m_curBlock].m_execBlockCtx->m_registers[reg] = symbolNode;

			for (auto blockInfo : blocksInLoop) {
				blockInfo->m_treeBlock->addLine(symbolNode, blockInfo->m_execBlockCtx->m_registers[reg]);
			}
			return symbolNode;
		}

		AsmGraphBlock* getMostUpBlockInJoinedLoop(AsmGraphBlock* block) {
			auto highestBlock = block;
			for (auto loop : m_blockLoops) {
				if (loop.second->m_level == block->m_level && loop.first->m_level < highestBlock->m_level) {
					highestBlock = loop.first;
				}
			}

			if (highestBlock != block)
				return getMostUpBlockInJoinedLoopNext(highestBlock);
			return nullptr;
		}

		AsmGraphBlock* getMostUpBlockInJoinedLoopNext(AsmGraphBlock* block) {
			auto highestBlock = block;
			for (auto loop : m_blockLoops) {
				if (loop.second->m_level > block->m_level && loop.first->m_level < highestBlock->m_level) {
					highestBlock = loop.first;
				}
			}

			if (highestBlock != block)
				return getMostUpBlockInJoinedLoopNext(highestBlock);
			return highestBlock;
		}
	};
};