#pragma once
#include "DecCodeGraph.h"

namespace CE::Decompiler::LinearView
{
	enum class GotoType {
		None,
		Normal,
		Continue,
		Break
	};

	class BlockList;
	class WhileCycle;

	class IBlockListAgregator
	{
	public:
		virtual std::list<BlockList*> getBlockLists() = 0;

		virtual bool isInversed() {
			return false;
		}
	};

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

		virtual WhileCycle* getWhileCycle();
	};

	class BlockList
	{
	public:
		int m_backOrderId = 0;
		int m_minLinearLevel = 0;
		int m_maxLinearLevel = 0;
		IBlockListAgregator* m_parent;
		Block* m_goto = nullptr;

		BlockList(IBlockListAgregator* parent = nullptr)
			: m_parent(parent)
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

		GotoType getGotoType();

		WhileCycle* getWhileCycle();

		bool isEmpty() {
			return getBlocks().size() == 0 && getGotoType() == GotoType::None;
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

	class Condition : public Block, public IBlockListAgregator
	{
	public:
		BlockList* m_mainBranch;
		BlockList* m_elseBranch;
		ExprTree::ICondition* m_cond;

		Condition(PrimaryTree::Block* decBlock)
			: Block(decBlock)
		{
			m_mainBranch = new BlockList(this);
			m_elseBranch = new BlockList(this);
			m_cond = decBlock->m_noJmpCond ? dynamic_cast<ExprTree::ICondition*>(decBlock->m_noJmpCond->clone()) : nullptr;
		}

		~Condition() {
			delete m_mainBranch;
			delete m_elseBranch;
		}

		std::list<BlockList*> getBlockLists() override {
			return { m_mainBranch, m_elseBranch };
		}

		void inverse() {
			m_cond->inverse();
			std::swap(m_mainBranch, m_elseBranch);
		}
	};

	class WhileCycle : public Block, public IBlockListAgregator
	{
	public:
		BlockList* m_mainBranch;
		ExprTree::ICondition* m_cond;
		bool m_isDoWhileCycle;
		bool m_isInfinite;

		WhileCycle(PrimaryTree::Block* decBlock, bool isDoWhileCycle = false, bool isInfinite = false)
			: Block(decBlock), m_isDoWhileCycle(isDoWhileCycle), m_isInfinite(isInfinite)
		{
			m_mainBranch = new BlockList(this);
			if (m_isInfinite) {
				m_cond = new ExprTree::BooleanValue(true);
			}
			else {
				m_cond = dynamic_cast<ExprTree::ICondition*>(decBlock->m_noJmpCond->clone());
				if (isDoWhileCycle) {
					m_cond->inverse();
				}
			}
		}

		~WhileCycle() {
			delete m_mainBranch;
		}

		Block* getFirstBlock() {
			if (!m_isDoWhileCycle) {
				return this;
			}
			return *m_mainBranch->getBlocks().begin();
		}

		std::list<BlockList*> getBlockLists() override {
			return { m_mainBranch };
		}

		bool isInversed() override {
			return m_isDoWhileCycle;
		}

		WhileCycle* getWhileCycle() override {
			return this;
		}
	};

	static void CalculateBackOrderIdsForBlockList(BlockList* blockList, int orderId = 1) {
		for (auto it = blockList->getBlocks().rbegin(); it != blockList->getBlocks().rend(); it++) {
			auto block = *it;
			orderId++;
			if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(block)) {
				if (blockListAgregator->isInversed()) {
					auto blockList = *blockListAgregator->getBlockLists().begin();
					block->m_backOrderId = blockList->m_backOrderId = orderId;
					CalculateBackOrderIdsForBlockList(blockList, orderId);
					if (!blockList->getBlocks().empty()) {
						orderId = (*blockList->getBlocks().begin())->m_backOrderId;
					}
				}
				else {
					block->m_backOrderId = orderId;
					for (auto blockList : blockListAgregator->getBlockLists()) {
						CalculateBackOrderIdsForBlockList(blockList, orderId - 1);
						blockList->m_backOrderId = orderId - 1;
					}
				}
			}
			else {
				block->m_backOrderId = orderId;
			}
		}
	}

	static void CalculateLinearLevelForBlockList(BlockList* blockList, int& level) {
		blockList->m_minLinearLevel = level;
		for (auto block : blockList->getBlocks()) {
			block->m_linearLevel = level++;
			if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(block)) {
				if (blockListAgregator->isInversed()) {
					level--;
				}
				for (auto blockList : blockListAgregator->getBlockLists()) {
					CalculateLinearLevelForBlockList(blockList, level);
				}
				if (blockListAgregator->isInversed()) {
					block->m_linearLevel = level++;
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

	static void OptimizeBlockList(BlockList* blockList, bool optimize = true) {
		int level = 1;
		CalculateLinearLevelForBlockList(blockList, level);
		if (optimize) {
			//OptimizeBlockOrderBlockList(blockList);
		}
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

		struct Cycle {
			PrimaryTree::Block* m_startBlock;
			PrimaryTree::Block* m_endBlock;
			std::set<PrimaryTree::Block*> m_blocks;

			Cycle(PrimaryTree::Block* startBlock = nullptr, PrimaryTree::Block* endBlock = nullptr)
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

			/*for (auto& it : m_loops) {
				fillLoop(&it.second);
			}*/

			m_blockList = new BlockList;
			std::set<PrimaryTree::Block*> usedBlocks;
			std::set<PrimaryTree::Block*> createdCycleBlocks;
			convert(m_blockList, startBlock, usedBlocks, createdCycleBlocks);

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
		std::map<PrimaryTree::Block*, Cycle> m_cycles;
		std::list<std::pair<BlockList*, PrimaryTree::Block*>> m_goto;
		BlockList* m_blockList;

		void convert(BlockList* blockList, PrimaryTree::Block* decBlock, std::set<PrimaryTree::Block*>& usedBlocks, std::set<PrimaryTree::Block*>& createdCycleBlocks) {
			std::list<std::pair<BlockList*, PrimaryTree::Block*>> nextBlocksToFill;
			
			auto curDecBlock = decBlock;
			while (curDecBlock != nullptr) {
				if (usedBlocks.count(curDecBlock) != 0) {
					m_goto.push_back(std::make_pair(blockList, curDecBlock));
					break;
				}
				PrimaryTree::Block* nextBlock = nullptr;

				if (createdCycleBlocks.count(curDecBlock) == 0 && curDecBlock->isCycle()) {
					auto it = m_cycles.find(curDecBlock);
					if (it != m_cycles.end()) {
						auto& cycle = it->second;
						auto startCycleBlock = cycle.m_startBlock;
						auto endCycleBlock = cycle.m_endBlock;

						if (startCycleBlock->isCondition() && startCycleBlock->hasNoCode() && cycle.m_blocks.count(startCycleBlock->m_nextFarBlock) == 0) {
							WhileCycle* whileCycle = new WhileCycle(startCycleBlock, false);
							blockList->addBlock(whileCycle);
							nextBlocksToFill.push_front(std::make_pair(whileCycle->m_mainBranch, startCycleBlock->m_nextNearBlock));
							nextBlock = startCycleBlock->m_nextFarBlock;
							createdCycleBlocks.insert(curDecBlock);
						}
						else {
							WhileCycle* whileCycle;
							if (endCycleBlock->isCondition()) {
								whileCycle = new WhileCycle(endCycleBlock, true);
								nextBlock = endCycleBlock->m_nextNearBlock;
							}
							else {
								whileCycle = new WhileCycle(endCycleBlock, true, true);
								for (auto cycleBlock : cycle.m_blocks) {
									if (cycleBlock->m_nextFarBlock && cycle.m_blocks.count(cycleBlock->m_nextFarBlock) == 0) {
										nextBlock = cycleBlock->m_nextFarBlock;
										break;
									}
								}
							}
							blockList->addBlock(whileCycle);
							nextBlocksToFill.push_front(std::make_pair(whileCycle->m_mainBranch, startCycleBlock));
							createdCycleBlocks.insert(curDecBlock);
							curDecBlock = endCycleBlock;
						}
					}
				}
				else if (curDecBlock->isCondition()) {
					auto it = m_loops.find(curDecBlock);
					if (it != m_loops.end()) {
						auto& loop = it->second;
						nextBlock = loop.m_endBlock;
						for (auto it : loop.m_blocks) {
							if (usedBlocks.count(it) != 0) {
								nextBlock = nullptr;
								break;
							}
						}
					}

					auto cond = new Condition(curDecBlock);
					blockList->addBlock(cond);
					if (nextBlock) {
						nextBlocksToFill.push_back(std::make_pair(cond->m_mainBranch, curDecBlock->m_nextNearBlock));
						nextBlocksToFill.push_back(std::make_pair(cond->m_elseBranch, curDecBlock->m_nextFarBlock));
					}
					else {
						auto blockInCond = curDecBlock->m_nextNearBlock;
						auto blockBelowCond = curDecBlock->m_nextFarBlock;
						if (blockInCond->m_maxHeight > blockBelowCond->m_maxHeight || usedBlocks.count(blockInCond) != 0) {
							std::swap(blockInCond, blockBelowCond);
							cond->m_cond->inverse();
						}
						nextBlocksToFill.push_back(std::make_pair(cond->m_mainBranch, blockInCond));
						nextBlocksToFill.push_back(std::make_pair(blockList, blockBelowCond));
						m_goto.push_back(std::make_pair(cond->m_elseBranch, blockBelowCond));
					}
				}
				else {
					blockList->addBlock(new Block(curDecBlock));
					for (auto it : { curDecBlock->m_nextNearBlock, curDecBlock->m_nextFarBlock }) {
						if (it != nullptr)
							nextBlock = it;
					}
				}

				if (curDecBlock) {
					usedBlocks.insert(curDecBlock);
				}
				curDecBlock = nextBlock;
			}

			for (auto block : nextBlocksToFill) {
				convert(block.first, block.second, usedBlocks, createdCycleBlocks);
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
						for (auto it = startLoopBlockIt; it != blocks.end(); it++) {
							loop.m_blocks.insert(*it);
						}
						loop.m_blocks.insert(block);
						m_loops.insert(std::make_pair(*startLoopBlockIt, loop));
						//todo: blocks inside the loop but are not refering to the end of the loop are ignoring, the loop is not entire
					}

					if (goNext) {
						passedBlocks = blocks;
					}
				}
			}

			if (goNext) {
				passedBlocks.push_back(block);

				PrimaryTree::Block* startCycleBlock = nullptr;
				for (auto nextBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
					if (nextBlock == nullptr)
						continue;
					if (nextBlock->m_level <= block->m_level) {
						startCycleBlock = nextBlock;
						continue;
					}
					findAllLoops(nextBlock, visitedBlocks, passedBlocks);
				}

				if (startCycleBlock)
				{
					if (m_cycles.find(startCycleBlock) == m_cycles.end()) {
						Cycle cycle(startCycleBlock, block);
						m_cycles.insert(std::make_pair(startCycleBlock, cycle));
					}
					auto& cycle = m_cycles[startCycleBlock];
					cycle.m_endBlock = max(cycle.m_endBlock, block);
					bool isBlockInCycle = false;
					for (auto passedBlock : passedBlocks) {
						if (passedBlock == cycle.m_startBlock)
							isBlockInCycle = true;
						if (isBlockInCycle) {
							cycle.m_blocks.insert(passedBlock);
						}
					}
				}

				for (auto it = passedBlocks.begin(); it != passedBlocks.end(); it++) {
					if (*it == block) {
						passedBlocks.erase(it, passedBlocks.end());
						break;
					}
				}
			}
		}

		/*void fillLoop(Loop* loop) {
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
		}*/
	};
};