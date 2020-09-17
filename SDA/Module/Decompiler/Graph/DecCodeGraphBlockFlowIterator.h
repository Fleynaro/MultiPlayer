#pragma once
#include "DecCodeGraphBlock.h"

namespace CE::Decompiler
{
	class BlockFlowIterator
	{
		const static uint64_t MaxPressure = 0x1000000000000000;
	public:
		struct BlockInfo {
			PrimaryTree::Block* m_block;
			uint64_t m_pressure = 0x0;
			ExtBitMask m_notNeedToReadMask; //it may happens that dont need reading from the block because its child blocks have been already read
			BlockInfo() = default;
			BlockInfo(PrimaryTree::Block* block, uint64_t pressure, ExtBitMask notNeedToReadMask)
				: m_block(block), m_pressure(pressure), m_notNeedToReadMask(notNeedToReadMask)
			{}

			bool hasMaxPressure() {
				return m_pressure == MaxPressure;
			}
		};

	private:
		std::map<PrimaryTree::Block*, BlockInfo> blockInfos;
		std::list<BlockInfo> m_blocksOnOneLevel;
		int m_iterCount = 0;

	public:
		bool m_considerLoop = true;
		ExtBitMask m_notNeedToReadMask;

		BlockFlowIterator(PrimaryTree::Block* startBlock)
		{
			addBlockInfo(startBlock, MaxPressure, ExtBitMask(0)); //set the start block
		}

		bool isStartBlock() {
			return m_iterCount == 1;
		}

		bool hasNext() {
			BlockInfo* curBlockInfo = nullptr;
			//remove the first block from the current list
			if (!m_blocksOnOneLevel.empty()) {
				curBlockInfo = &(*m_blocksOnOneLevel.begin());
				m_blocksOnOneLevel.pop_front();
			}

			//if the list is empty then fill it up with new blocks
			if (m_blocksOnOneLevel.empty()) {
				if (curBlockInfo) {
					distributePressure(*curBlockInfo, m_notNeedToReadMask, m_considerLoop);
				}
				defineBlocksOnOneLevel();
			}

			//restore the default values
			m_considerLoop = true;
			m_notNeedToReadMask = ExtBitMask();
			m_iterCount++;
			return !m_blocksOnOneLevel.empty();
		}

		BlockInfo& next() {
			return *m_blocksOnOneLevel.begin();
		}

		void passThisBlockRepeatly() {
			m_blocksOnOneLevel.push_back(next());
		}

	private:
		void addBlockInfo(PrimaryTree::Block* block, uint64_t pressure, ExtBitMask notNeedToReadMask) {
			blockInfos[block] = BlockInfo(block, pressure, notNeedToReadMask);
		}

		void defineBlocksOnOneLevel() {
			auto highestLevel = getHighestLevel();
			for (auto it : blockInfos) {
				auto block = it.first;
				auto& blockInfo = it.second;
				if (block->m_level == highestLevel) { //find blocks with the highest level down
					m_blocksOnOneLevel.push_back(blockInfo);
				}
			}
		}

		int getHighestLevel() {
			int highestLevel = 0;
			for (auto it : blockInfos) {
				auto block = it.first;
				if (block->m_level > highestLevel) {
					highestLevel = it.first->m_level;
				}
			}
			return highestLevel;
		}

		void distributePressure(BlockInfo& blockInfo, ExtBitMask notNeedToReadMask, bool considerLoop) {
			auto block = blockInfo.m_block;
			blockInfos.erase(block);
			//if the start block is cycle then distribute the pressure for all referenced blocks. Next time don't it.
			auto parentsCount = considerLoop ? block->getRefBlocksCount() : block->getRefHighBlocksCount();
			if (parentsCount > 0) {
				//calculate pressure for next blocks
				auto bits = (int)ceil(log2((double)parentsCount));
				auto addPressure = blockInfo.m_pressure >> bits;
				auto restAddPressure = addPressure * ((1 << bits) % parentsCount);

				//distribute the calculated pressure for each next block
				auto mask = blockInfo.m_notNeedToReadMask | notNeedToReadMask;
				for (auto parentBlock : block->getBlocksReferencedTo()) {
					if (!considerLoop && parentBlock->m_level >= block->m_level)
						continue;

					if (blockInfos.find(parentBlock) == blockInfos.end()) {
						addBlockInfo(parentBlock, 0x0, mask);
					}
					blockInfos[parentBlock].m_pressure += addPressure + restAddPressure;
					blockInfos[parentBlock].m_notNeedToReadMask = blockInfos[parentBlock].m_notNeedToReadMask & mask;
					restAddPressure = 0;
				}
			}
		}
	};
};