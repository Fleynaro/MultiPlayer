#pragma once
#include "DecCodeGraph.h"

namespace CE::Decompiler::LinearView
{
	class BlockList;
	class Block
	{
	public:
		PrimaryTree::Block* m_decBlock;
		BlockList* m_blockList = nullptr;

		Block(PrimaryTree::Block* decBlock)
			: m_decBlock(decBlock)
		{}

		virtual ~Block() {}
	};

	class Condition;
	class BlockList
	{
	public:
		Condition* m_condition;
		Block* m_goto = nullptr;

		BlockList(Condition* condition = nullptr)
			: m_condition(condition)
		{}

		void addBlock(Block* block) {
			block->m_blockList = this;
			m_blocks.push_back(block);
		}

		std::list<Block*>& getBlocks() {
			return m_blocks;
		}

		Block* findBlock(PrimaryTree::Block* decBlock);
	private:
		std::list<Block*> m_blocks;
	};

	class Condition : public Block
	{
	public:
		BlockList* m_mainBranch;
		BlockList* m_elseBranch;

		Condition(PrimaryTree::Block* decBlock)
			: Block(decBlock)
		{
			m_mainBranch = new BlockList(this);
			m_elseBranch = new BlockList(this);
		}

		~Condition() {
			delete m_mainBranch;
			delete m_elseBranch;
		}
	};

	class WhileLoop : public Condition
	{
	public:

	};


	class Converter
	{
	public:
		Converter(DecompiledCodeGraph* decCodeGraph)
			: m_decCodeGraph(decCodeGraph)
		{}

		void start() {
			auto startBlock = m_decCodeGraph->getStartBlock();
			
			m_blockList = new BlockList;
			std::set<PrimaryTree::Block*> usedBlocks;
			convert(m_blockList, startBlock, usedBlocks);

			for (auto it : m_goto) {
				auto block = m_blockList->findBlock(it.second);
				if (block != nullptr) {
					it.first->m_goto = block;
				}
			}
		}

		BlockList* getBlockList() {
			return m_blockList;
		}
	private:
		DecompiledCodeGraph* m_decCodeGraph;
		std::list<std::pair<BlockList*, PrimaryTree::Block*>> m_goto;
		BlockList* m_blockList;

		void convert(BlockList* blockList, PrimaryTree::Block* block, std::set<PrimaryTree::Block*>& usedBlocks) {
			while (block != nullptr) {
				if (usedBlocks.count(block) != 0) {
					m_goto.push_back(std::make_pair(blockList, block));
					break;
				}
				PrimaryTree::Block* nextBlock = nullptr;

				if (block->isCondition()) {
					blockList->addBlock(new Condition(block));

					auto endBlock = getEndBlockOfLoop(block);
					if (endBlock != nullptr)
						nextBlock = endBlock;
				}
				else {
					blockList->addBlock(new Block(block));
					for (auto it : { block->m_nextNearBlock, block->m_nextFarBlock }) {
						if (it == nullptr)
							continue;
						if (it->m_level - block->m_level != 1) {
							m_goto.push_back(std::make_pair(blockList, it));
							continue;
						}

						nextBlock = it;
						break;
					}
				}

				usedBlocks.insert(block);
				block = nextBlock;
			}

			for (auto it : blockList->getBlocks()) {
				if (auto condition = dynamic_cast<Condition*>(it)) {
					convert(condition->m_mainBranch, condition->m_decBlock->m_nextNearBlock, usedBlocks);
					convert(condition->m_elseBranch, condition->m_decBlock->m_nextFarBlock, usedBlocks);
				}
			}
		}

		struct VisitInfo {
			uint64_t pressure = 0x0;
			int visitedCount = 0;
		};

		PrimaryTree::Block* getEndBlockOfLoop(PrimaryTree::Block* startBlock) {
			//std::map<AsmGraphBlock*, VisitInfo> visitedBlocks;
			//return getEndBlockOfLoop(startBlock, 0x1000000000000000, visitedBlocks);
			std::map<PrimaryTree::Block*, uint64_t> blockPressures;
			blockPressures[startBlock] = 0x1000000000000000;

			while (true)
			{
				int minLevel = 100000;
				for (auto it : blockPressures) {
					auto block = it.first;
					if (block->m_level < minLevel) {
						minLevel = it.first->m_level;
					}
				}

				int filledUpBlocksCount = 0;
				for (auto it : blockPressures) {
					auto block = it.first;
					auto pressure = it.second;
					if (block->m_level == minLevel) //find blocks with the lowest level up
					{
						std::list<PrimaryTree::Block*> nextBlocks;
						for (auto nextBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
							if (nextBlock == nullptr)
								continue;
							if (nextBlock->m_level <= block->m_level)
								continue;
							nextBlocks.push_back(nextBlock);
						}

						blockPressures.erase(block);
						if (nextBlocks.empty())
							continue;

						auto addPressure = pressure;
						if (nextBlocks.size() == 2)
							addPressure >>= 1;

						for (auto nextBlock : nextBlocks) {
							if (blockPressures.find(nextBlock) == blockPressures.end()) {
								blockPressures[nextBlock] = 0x0;
							}
							blockPressures[nextBlock] += addPressure;
							if (blockPressures[nextBlock] == 0x1000000000000000) {
								return nextBlock;
							}
							filledUpBlocksCount++;
						}
					}
				}

				if (filledUpBlocksCount == 0)
					break;
			}

			return nullptr;
		}
	};


	//class Converter2
	//{
	//public:
	//	struct Loop {
	//		AsmGraphBlock* m_startBlock;
	//		AsmGraphBlock* m_endBlock;
	//		std::set<AsmGraphBlock*> m_blocks;

	//		Loop(AsmGraphBlock* startBlock, AsmGraphBlock* endBlock)
	//			: m_startBlock(startBlock), m_endBlock(endBlock)
	//		{}
	//	};

	//	struct VisitedBlockInfo {
	//		int m_enterCount = 0;
	//		std::list<AsmGraphBlock*> m_passedBlocks;
	//	};

	//	Converter2(AsmGraph* asmGraph)
	//		: m_asmGraph(asmGraph)
	//	{}

	//	void start() {
	//		auto startBlock = m_asmGraph->getStartBlock();
	//		std::map<AsmGraphBlock*, VisitedBlockInfo> visitedBlocks;
	//		std::list<AsmGraphBlock*> passedBlocks;
	//		findAllLoops(startBlock, visitedBlocks, passedBlocks);

	//		for (auto& it : m_loops) {
	//			fillLoop(&it.second);
	//		}

	//		m_blockList = new BlockList;
	//		std::set<AsmGraphBlock*> usedBlocks;
	//		convert(m_blockList, startBlock, usedBlocks);

	//		for (auto it : m_goto) {
	//			auto block = m_blockList->findBlock(it.second);
	//			if (block != nullptr) {
	//				it.first->m_goto = block;
	//			}
	//		}
	//	}

	//	BlockList* getBlockList() {
	//		return m_blockList;
	//	}
	//private:
	//	AsmGraph* m_asmGraph;
	//	std::map<AsmGraphBlock*, Loop> m_loops;
	//	std::list<std::pair<BlockList*, AsmGraphBlock*>> m_goto;
	//	BlockList* m_blockList;

	//	void convert(BlockList* blockList, AsmGraphBlock* block, std::set<AsmGraphBlock*>& usedBlocks) {
	//		while (block != nullptr) {
	//			if (usedBlocks.count(block) != 0) {
	//				m_goto.push_back(std::make_pair(blockList, block));
	//				break;
	//			}
	//			AsmGraphBlock* nextBlock = nullptr;

	//			if (block->isCondition()) {
	//				blockList->addBlock(new Condition(block));

	//				auto it = m_loops.find(block);
	//				if (it != m_loops.end()) {
	//					auto& loop = it->second;
	//					for (auto it : loop.m_blocks) {
	//						if (usedBlocks.count(it) != 0) {
	//							break;
	//						}
	//					}

	//					nextBlock = loop.m_endBlock;
	//				}
	//			}
	//			else {
	//				blockList->addBlock(new Block(block));
	//				for (auto it : { block->getNextNearBlock(), block->getNextFarBlock() }) {
	//					if (it != nullptr)
	//						nextBlock = it;
	//				}
	//			}

	//			usedBlocks.insert(block);
	//			block = nextBlock;
	//		}

	//		for (auto it : blockList->getBlocks()) {
	//			if (auto condition = dynamic_cast<Condition*>(it)) {
	//				convert(condition->m_mainBranch, condition->m_graphBlock->getNextNearBlock(), usedBlocks);
	//				convert(condition->m_elseBranch, condition->m_graphBlock->getNextFarBlock(), usedBlocks);
	//			}
	//		}
	//	}

	//	void findAllLoops(AsmGraphBlock* block, std::map<AsmGraphBlock*, VisitedBlockInfo>& visitedBlocks, std::list<AsmGraphBlock*>& passedBlocks) {
	//		bool goNext = true;
	//		if (block->getRefHighBlocksCount() >= 2) {
	//			if (visitedBlocks.find(block) == visitedBlocks.end()) {
	//				visitedBlocks.insert(std::make_pair(block, VisitedBlockInfo()));
	//			}
	//			auto& visitedBlock = visitedBlocks[block];
	//			
	//			visitedBlock.m_enterCount++;
	//			if (visitedBlock.m_enterCount < block->getRefHighBlocksCount()) {
	//				goNext = false;
	//			}

	//			auto& blocks = visitedBlock.m_passedBlocks;
	//			blocks.insert(blocks.end(), passedBlocks.begin(), passedBlocks.end());

	//			if (visitedBlock.m_enterCount >= 2) {
	//				blocks.sort([](const AsmGraphBlock* block1, const AsmGraphBlock* block2) {
	//					return block1->m_level < block2->m_level&& block1 < block2;
	//					});

	//				//detect a loop and remove duplicates
	//				auto startLoopBlockIt = blocks.end();
	//				for (auto it = std::next(blocks.begin()); it != blocks.end(); it++) {
	//					auto prevBlockIt = std::prev(it);
	//					if (*it == *prevBlockIt) {
	//						startLoopBlockIt = it;
	//						blocks.erase(prevBlockIt);
	//					}
	//				}

	//				//if a loop detected
	//				if (startLoopBlockIt != blocks.end()) {
	//					Loop loop(*startLoopBlockIt, block);
	//					m_loops.insert(std::make_pair(*startLoopBlockIt, loop));
	//				}

	//				if (goNext) {
	//					passedBlocks = blocks;
	//				}
	//			}
	//		}

	//		if (goNext) {
	//			passedBlocks.push_back(block);

	//			for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
	//				if (nextBlock == nullptr)
	//					continue;
	//				if (nextBlock->m_level <= block->m_level)
	//					continue;
	//				findAllLoops(nextBlock, visitedBlocks, passedBlocks);
	//			}

	//			for (auto it = passedBlocks.begin(); it != passedBlocks.end(); it++) {
	//				if (*it == block) {
	//					passedBlocks.erase(it, passedBlocks.end());
	//					break;
	//				}
	//			}
	//		}
	//	}

	//	void fillLoop(Loop* loop) {
	//		fillLoop(loop->m_startBlock, loop);
	//		loop->m_blocks.insert(loop->m_endBlock);
	//	}

	//	void fillLoop(AsmGraphBlock* block, Loop* loop) {
	//		loop->m_blocks.insert(block);
	//		for (auto nextBlock : { block->getNextNearBlock(), block->getNextFarBlock() }) {
	//			if (nextBlock == nullptr || nextBlock->m_level >= loop->m_endBlock->m_level || nextBlock->m_level <= block->m_level)
	//				continue;
	//			fillLoop(nextBlock, loop);
	//		}
	//	}
	//};
};