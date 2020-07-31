#pragma once
#include "DecCodeGraph.h"

namespace CE::Decompiler::LinearView
{
	class BlockList;
	class Block
	{
	public:
		int m_backOrderId = 0;
		int m_linearLevel = 0;
		PrimaryTree::Block* m_decBlock;
		BlockList* m_blockList = nullptr;

		Block(PrimaryTree::Block* decBlock)
			: m_decBlock(decBlock)
		{}

		virtual ~Block() {}

		int getBackOrderId() {
			return m_backOrderId;
		}

		int getLinearLevel() {
			return m_linearLevel;
		}
	};

	class Condition;
	class BlockList
	{
	public:
		int m_backOrderId = 0;
		int m_minLinearLevel = 0;
		int m_maxLinearLevel = 0;
		Condition* m_condition;
		Block* m_goto = nullptr;

		BlockList(Condition* condition = nullptr)
			: m_condition(condition)
		{}

		void addBlock(Block* block) {
			block->m_blockList = this;
			m_blocks.push_back(block);
		}

		void removeBlock(Block* block) {
			block->m_blockList = nullptr;
			m_blocks.remove(block);
		}

		std::list<Block*>& getBlocks() {
			return m_blocks;
		}

		Block* findBlock(PrimaryTree::Block* decBlock);

		bool hasGoto() {
			return m_goto && (m_goto->getBackOrderId() != getBackOrderId() && m_goto->getLinearLevel() > getMaxLinearLevel());
		}

		bool isEmpty() {
			return getBlocks().size() == 0 && !hasGoto();
		}

		int getBackOrderId() {
			return m_backOrderId;
		}

		int getMinLinearLevel() {
			return m_minLinearLevel;
		}

		int getMaxLinearLevel() {
			return m_maxLinearLevel;
		}
	private:
		std::list<Block*> m_blocks;
	};

	class IBlockListAgregator
	{
	public:
		virtual std::list<BlockList*> getBlockLists() = 0;
	};

	class Condition : public Block, public IBlockListAgregator
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

		std::list<BlockList*> getBlockLists() override {
			return { m_mainBranch, m_elseBranch };
		}
	};

	class WhileLoop : public Condition
	{
	public:
		WhileLoop(PrimaryTree::Block* decBlock)
			: Condition(decBlock)
		{}
	};

	static void CalculateBackOrderIdsForBlockList(BlockList* blockList, int orderId = 1) {
		for (auto it = blockList->getBlocks().rbegin(); it != blockList->getBlocks().rend(); it++) {
			auto block = *it;
			if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(block)) {
				for (auto blockList : blockListAgregator->getBlockLists()) {
					blockList->m_backOrderId = orderId;
					CalculateBackOrderIdsForBlockList(blockList, orderId);
				}
			}
			else {
				orderId ++;
			}
			block->m_backOrderId = orderId;
		}
	}

	static void CalculateLinearLevelForBlockList(BlockList* blockList, int& level) {
		blockList->m_minLinearLevel = level;
		for (auto block : blockList->getBlocks()) {
			block->m_linearLevel = level++;
			if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(block)) {
				for (auto blockList : blockListAgregator->getBlockLists()) {
					CalculateLinearLevelForBlockList(blockList, level);
				}
			}
		}
		blockList->m_maxLinearLevel = level;
	}

	static void OptimizeBlockOrderBlockList(BlockList* blockList) {
		auto farBlock = blockList->m_goto;
		if (farBlock) {
			auto farBlockList = farBlock->m_blockList;
			if (blockList->getMinLinearLevel() > farBlock->getLinearLevel()) {
				farBlockList->removeBlock(farBlock);
				blockList->addBlock(farBlock);
				blockList->m_goto = farBlockList->m_goto;
				farBlockList->m_goto = farBlock;
			}
		}

		for (auto block : blockList->getBlocks()) {
			if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(block)) {
				for (auto blockList : blockListAgregator->getBlockLists()) {
					OptimizeBlockOrderBlockList(blockList);
				}
			}
		}
	}

	static void OptimizeBlockList(BlockList* blockList) {
		int level = 1;
		CalculateLinearLevelForBlockList(blockList, level);
		//OptimizeBlockOrderBlockList(blockList);
		level = 1;
		CalculateLinearLevelForBlockList(blockList, level);
		CalculateBackOrderIdsForBlockList(blockList);
	}

	class Converter
	{
	public:
		struct Loop {
			PrimaryTree::Block* m_startBlock;
			PrimaryTree::Block* m_endBlock;
			std::set<PrimaryTree::Block*> m_blocks;

			Loop(PrimaryTree::Block* startBlock, PrimaryTree::Block* endBlock)
				: m_startBlock(startBlock), m_endBlock(endBlock)
			{}
		};

		struct VisitedBlockInfo {
			int m_enterCount = 0;
			std::list<PrimaryTree::Block*> m_passedBlocks;
		};

		Converter(DecompiledCodeGraph* asmGraph)
			: m_decCodeGraph(asmGraph)
		{}

		void start() {
			auto startBlock = m_decCodeGraph->getStartBlock();
			std::map<PrimaryTree::Block*, VisitedBlockInfo> visitedBlocks;
			std::list<PrimaryTree::Block*> passedBlocks;
			findAllLoops(startBlock, visitedBlocks, passedBlocks);

			for (auto& it : m_loops) {
				fillLoop(&it.second);
			}

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
		std::map<PrimaryTree::Block*, Loop> m_loops;
		std::list<std::pair<BlockList*, PrimaryTree::Block*>> m_goto;
		BlockList* m_blockList;

		void convert(BlockList* blockList, PrimaryTree::Block* decBlock, std::set<PrimaryTree::Block*>& usedBlocks) {
			std::list<Condition*> conditions;
			
			while (decBlock != nullptr) {
				if (usedBlocks.count(decBlock) != 0) {
					m_goto.push_back(std::make_pair(blockList, decBlock));
					break;
				}
				PrimaryTree::Block* nextBlock = nullptr;

				if (decBlock->isCondition()) {
					Condition* cond;
					if (false && decBlock->isWhile()) {
						cond = new WhileLoop(decBlock);
					}
					else {
						cond = new Condition(decBlock);
					}
					blockList->addBlock(cond);
					conditions.push_back(cond);

					auto it = m_loops.find(decBlock);
					if (it != m_loops.end()) {
						auto& loop = it->second;
						for (auto it : loop.m_blocks) {
							if (usedBlocks.count(it) != 0) {
								break;
							}
						}

						nextBlock = loop.m_endBlock;
					}
				}
				else {
					blockList->addBlock(new Block(decBlock));
					for (auto it : { decBlock->m_nextNearBlock, decBlock->m_nextFarBlock }) {
						if (it != nullptr)
							nextBlock = it;
					}
				}

				usedBlocks.insert(decBlock);
				decBlock = nextBlock;
			}

			for (auto condition : conditions) {
				convert(condition->m_mainBranch, condition->m_decBlock->m_nextNearBlock, usedBlocks);
				auto elseBranch = condition->m_elseBranch;
				if (auto whileLoop = dynamic_cast<WhileLoop*>(condition)) {
					elseBranch = blockList;
				}
				convert(elseBranch, condition->m_decBlock->m_nextFarBlock, usedBlocks);
			}
		}

		void findAllLoops(PrimaryTree::Block* block, std::map<PrimaryTree::Block*, VisitedBlockInfo>& visitedBlocks, std::list<PrimaryTree::Block*>& passedBlocks) {
			bool goNext = true;
			auto refHighBlocksCount = block->getRefHighBlocksCount();
			if (refHighBlocksCount >= 2) {
				if (visitedBlocks.find(block) == visitedBlocks.end()) {
					visitedBlocks.insert(std::make_pair(block, VisitedBlockInfo()));
				}
				auto& visitedBlock = visitedBlocks[block];
				
				visitedBlock.m_enterCount++;
				if (visitedBlock.m_enterCount < refHighBlocksCount) {
					goNext = false;
				}

				auto& blocks = visitedBlock.m_passedBlocks;
				blocks.insert(blocks.end(), passedBlocks.begin(), passedBlocks.end());

				if (visitedBlock.m_enterCount >= 2) {
					blocks.sort([](const PrimaryTree::Block* block1, const PrimaryTree::Block* block2) {
						return block1->m_level < block2->m_level && block1 != block2; //todo: here there are some issues
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

				for (auto nextBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
					if (nextBlock == nullptr)
						continue;
					if (nextBlock->m_level <= block->m_level)
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

		void fillLoop(PrimaryTree::Block* block, Loop* loop) {
			loop->m_blocks.insert(block);
			for (auto nextBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
				if (nextBlock == nullptr || nextBlock->m_level >= loop->m_endBlock->m_level || nextBlock->m_level <= block->m_level)
					continue;
				fillLoop(nextBlock, loop);
			}
		}
	};
};