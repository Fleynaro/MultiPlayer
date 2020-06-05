#pragma once
#include "DecAsmGraph.h"
#include "Interpreter/InstructionInterpreterDispatcher.h"

namespace CE::Decompiler
{
	struct DecompiledBlockInfo {
		PrimaryTree::Block* m_treeBlock = nullptr;
		ExecutionBlockContext* m_execBlockCtx = nullptr;
		std::map<AsmGraphBlock*, std::list<AsmGraphBlock*>> m_passedBlocks;

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

		}
	private:
		AsmGraph* m_graph;
		InstructionInterpreterDispatcher* m_instructionInterpreterDispatcher;

		std::map<AsmGraphBlock*, DecompiledBlockInfo> m_decompiledBlocks;
		std::list<AsmGraphBlock*> m_curGraphPath;
		std::set<AsmGraphBlock*> m_passedBlocksInLastLoop;
		AsmGraphBlock* m_beginLoopBlock = nullptr;
		std::stack<AsmGraphBlock*> m_beginLoopBlocks;
		std::map<AsmGraphBlock*, AsmGraphBlock*> m_blockLoops;

		void decompile(AsmGraphBlock* block) {
			if (block == nullptr)
				return;

			if (m_decompiledBlocks.find(block) != m_decompiledBlocks.end()) {
				m_decompiledBlocks.insert(std::make_pair(block, DecompiledBlockInfo()));
			}
			auto& decompiledBlock = m_decompiledBlocks[block];

			if (!m_curGraphPath.empty()) {
				auto parentBlock = m_curGraphPath.back();
				auto curPath = std::list<AsmGraphBlock*>();
				if (block->m_blocksReferencedTo.size() > 1) {
					curPath = m_curGraphPath;
				}
				decompiledBlock.m_passedBlocks.insert(std::make_pair(parentBlock, curPath));
			}
			m_curGraphPath.push_back(block);

			if (block->m_blocksReferencedTo.size() == decompiledBlock.m_passedBlocks.size()) {
				//end possible loop
				if (block->m_blocksReferencedTo.size() >= 2) {
					m_blockLoops.insert(std::make_pair(m_beginLoopBlock, block));

					m_passedBlocksInLastLoop.clear();
					for (auto& it : decompiledBlock.m_passedBlocks) {
						for (auto block : it.second) {
							m_passedBlocksInLastLoop.insert(block);
						}
					}
				}

				decompiledBlock.m_treeBlock = new PrimaryTree::Block;
				decompiledBlock.m_execBlockCtx = new ExecutionBlockContext(this, block->getMinOffset());

				for (auto off : block->getInstructions()) {
					auto instr = m_graph->m_instructions[off];
					m_instructionInterpreterDispatcher->execute(decompiledBlock.m_treeBlock, decompiledBlock.m_execBlockCtx, instr);
				}

				decompile(block->getNextNearBlock());
				if (block->isCondition()) {
					m_beginLoopBlock = block;
				}
				decompile(block->getNextFarBlock());
			}

			m_curGraphPath.pop_back();
		}
	};
};