#pragma once
#include "DecAsmGraph.h"

namespace CE::Decompiler::LinearView
{
	class BlockList;
	class Block
	{
	public:
		BlockList* m_blockList = nullptr;
	};

	class Condition;
	class BlockList
	{
	public:
		Condition* m_condition = nullptr;

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
			AsmGraphBlock* m_startBlock;
			AsmGraphBlock* m_endBlock;
			std::set<AsmGraphBlock*> m_blocks;

			Loop(AsmGraphBlock* startBlock, AsmGraphBlock* endBlock)
				: m_startBlock(startBlock), m_endBlock(endBlock)
			{}
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

			for (auto& it : m_loops) {
				fillLoop(&it.second);
			}

			m_blockList = new BlockList;
			std::set<AsmGraphBlock*> usedBlocks;
			convert(m_blockList, startBlock, usedBlocks);
		}
	private:
		AsmGraph* m_asmGraph;
		std::map<AsmGraphBlock*, Loop> m_loops;
		BlockList* m_blockList;

		void convert(BlockList* blockList, AsmGraphBlock* block, std::set<AsmGraphBlock*>& usedBlocks) {
			while (block != nullptr) {
				if (block->isCondition()) {
					auto it = m_loops.find(block);
					if (it != m_loops.end()) {
						auto& loop = it->second;
						for (auto it : loop.m_blocks) {
							if (usedBlocks.count(it) != 0) {

							}
						}

					}
				}
				else {
					blockList->addBlock(new AsmBlock(block));
					for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
						if (nextBlock != nullptr)
							block = nextBlock;
					}
				}
			}
		}

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
						return block1->m_level < block2->m_level&& block1 < block2;
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
						Loop loop(*startLoopBlockIt, block);
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

		void fillLoop(Loop* loop) {
			fillLoop(loop->m_startBlock, loop);
			loop->m_blocks.insert(loop->m_endBlock);
		}

		void fillLoop(AsmGraphBlock* block, Loop* loop) {
			loop->m_blocks.insert(block);
			for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
				if (nextBlock == nullptr || nextBlock->m_level >= loop->m_endBlock->m_level || nextBlock->m_level <= block->m_level)
					continue;
				fillLoop(nextBlock, loop);
			}
		}
	};
};