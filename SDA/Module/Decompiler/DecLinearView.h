#pragma once
#include "DecAsmGraph.h"

namespace CE::Decompiler::LinearView
{
	class BlockList;
	class Block
	{
	public:
		BlockList* m_blockList;
	};

	class Condition;
	class BlockList
	{
	public:
		Condition* m_condition;

		BlockList()
		{}

		void addBlock(Block* block) {
			block->m_blockList = this;
			m_blocks.push_back(block);
		}

		std::list<Block*>& getBlocks() {
			return m_blocks;
		}
	private:
		std::list<Block*> m_blocks;
	};

	class AsmBlock : public Block
	{
	public:
		AsmGraphBlock* m_graphBlock;

		AsmBlock(AsmGraphBlock* graphBlock)
			: m_graphBlock(graphBlock)
		{}
	};

	class Condition : public Block
	{
	public:
		BlockList* m_mainBranch;
		BlockList* m_elseBranch;
		Block* m_mainBranchGoto = nullptr;
		Block* m_elseBranchGoto = nullptr;

		Condition(BlockList* mainBranch, BlockList* elseBranch = nullptr)
			: m_mainBranch(mainBranch), m_elseBranch(elseBranch)
		{
			m_mainBranch->m_condition = this;
			if (m_elseBranch != nullptr) {
				m_elseBranch->m_condition = this;
			}
		}
	};

	class WhileLoop : public Condition
	{
	public:

	};

	class Converter
	{
	public:
		struct Loop {
			std::list<AsmGraphBlock*> m_blocks;
		};

		struct VisitedBlockInfo {
			int m_enterCount = 0;
			std::list<AsmGraphBlock*> m_passedBlocks;
		};

		Converter(AsmGraph* asmGraph)
			: m_asmGraph(asmGraph)
		{}

		void start() {
			auto startBlock = m_asmGraph->getStartBlock();
			std::map<AsmGraphBlock*, VisitedBlockInfo> visitedBlocks;
			std::list<AsmGraphBlock*> passedBlocks;
			findAllLoops(startBlock, visitedBlocks, passedBlocks);
		}
	private:
		AsmGraph* m_asmGraph;
		std::map<AsmGraphBlock*, Loop> m_loops;

		void findAllLoops(AsmGraphBlock* block, std::map<AsmGraphBlock*, VisitedBlockInfo>& visitedBlocks, std::list<AsmGraphBlock*>& passedBlocks) {
			bool goNext = true;
			if (block->m_blocksReferencedTo.size() >= 2) {
				if (visitedBlocks.find(block) == visitedBlocks.end()) {
					visitedBlocks.insert(std::make_pair(block, VisitedBlockInfo()));
				}
				auto& visitedBlock = visitedBlocks[block];
				
				visitedBlock.m_enterCount++;
				if (visitedBlock.m_enterCount < block->m_blocksReferencedTo.size()) {
					goNext = false;
				}

				auto& blocks = visitedBlock.m_passedBlocks;
				blocks.insert(blocks.end(), passedBlocks.begin(), passedBlocks.end());

				if (visitedBlock.m_enterCount >= 2) {
					blocks.sort([](const AsmGraphBlock* block1, const AsmGraphBlock* block2) {
						return block1->m_level < block2->m_level && block1 != block2;
						});

					//detect a loop and remove duplicates
					auto startLoopBlockIt = blocks.end();
					for (auto it = std::next(blocks.begin()); it != blocks.end(); it++) {
						auto prevBlockIt = std::prev(it);
						if (*it == *prevBlockIt) {
							startLoopBlockIt = it;
							blocks.erase(prevBlockIt);
						}
					}

					//if a loop detected
					if (startLoopBlockIt != blocks.end()) {
						Loop loop;
						loop.m_blocks.insert(loop.m_blocks.begin(), startLoopBlockIt, blocks.end());
						loop.m_blocks.push_back(block);
						m_loops.insert(std::make_pair(*startLoopBlockIt, loop));
					}

					if (goNext) {
						passedBlocks = blocks;
					}
				}
			}

			if (goNext) {
				passedBlocks.push_back(block);

				for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
					if (nextBlock == nullptr)
						continue;
					
					findAllLoops(nextBlock, visitedBlocks, passedBlocks);
				}

				for (auto it = passedBlocks.begin(); it != passedBlocks.end(); it++) {
					if (*it == block) {
						passedBlocks.erase(it, passedBlocks.end());
						break;
					}
				}
			}
		}
	};
};