#pragma once
#include "PrimaryTree/PrimaryTreeBlock.h"
#include "Optimization/ExprOptimization.h"

namespace CE::Decompiler
{
	class DecompiledCodeGraph
	{
	public:
		DecompiledCodeGraph()
		{}

		PrimaryTree::Block* getStartBlock() {
			return *getDecompiledBlocks().begin();
		}

		std::list<PrimaryTree::Block*>& getDecompiledBlocks() {
			return m_decompiledBlocks;
		}

		static void CalculateLevelsForDecBlocks(PrimaryTree::Block* block, std::list<PrimaryTree::Block*>& path) {
			if (block == nullptr)
				return;

			//if that is a loop
			for (auto it = path.rbegin(); it != path.rend(); it++) {
				if (block == *it) {
					return;
				}
			}

			path.push_back(block);
			block->m_level = max(block->m_level, (int)path.size());
			CalculateLevelsForDecBlocks(block->m_nextNearBlock, path);
			CalculateLevelsForDecBlocks(block->m_nextFarBlock, path);
			path.pop_back();
		}
	private:
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
	};

	namespace Optimization
	{
		using namespace PrimaryTree;

		static void OptimizeConditionDecBlock(Block* block) {
			if (!block->isCondition())
				return;
			auto delta = block->m_nextNearBlock->m_level - block->m_level;
			if (delta >= 1 && delta < block->m_nextFarBlock->m_level - block->m_level)
				return;
			std::swap(block->m_nextNearBlock, block->m_nextFarBlock);
			block->m_noJmpCond->inverse();
		}

		static Block* JoinCondition(Block* block) {
			if (!block->isCondition())
				return nullptr;

			auto removedBlock = block->m_nextNearBlock;
			auto mutualBlock = block->m_nextFarBlock;
			if (!removedBlock->hasNoCode() || !removedBlock->isCondition() || removedBlock->m_blocksReferencedTo.size() != 1)
				return nullptr;

			Block* targetBlock = nullptr;
			auto removedBlockNoJmpCond = removedBlock->m_noJmpCond;
			if (removedBlock->m_nextNearBlock == mutualBlock) {
				targetBlock = removedBlock->m_nextFarBlock;
				removedBlockNoJmpCond->inverse();
			}
			else if (removedBlock->m_nextFarBlock == mutualBlock) {
				targetBlock = removedBlock->m_nextNearBlock;
			}
			if (!targetBlock)
				return nullptr;

			block->setJumpCondition(new ExprTree::CompositeCondition(block->m_noJmpCond, removedBlockNoJmpCond, ExprTree::CompositeCondition::And));
			block->m_nextNearBlock = targetBlock;
			removedBlock->m_blocksReferencedTo.remove(block);
			return removedBlock;
		}

		static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph) {
			//join conditions and remove useless blocks
			for (auto it = decGraph->getDecompiledBlocks().rbegin(); it != decGraph->getDecompiledBlocks().rend(); it++) {
				auto block = *it;
				while (auto removedBlock = JoinCondition(block)) {
					OptimizeConditionDecBlock(block);
					decGraph->getDecompiledBlocks().remove(removedBlock);
					delete removedBlock;
				}
			}

			//recalculate levels because some blocks can be removed
			for (const auto decBlock : decGraph->getDecompiledBlocks()) {
				decBlock->m_level = 0;
			}
			std::list<PrimaryTree::Block*> path;
			DecompiledCodeGraph::CalculateLevelsForDecBlocks(decGraph->getStartBlock(), path);

			//optimize expressions
			for (const auto decBlock : decGraph->getDecompiledBlocks()) {
				for (auto line : decBlock->getLines()) {
					Optimization::Optimize(line->m_destAddr);
					Optimization::Optimize(line->m_srcValue);
				}

				if (decBlock->m_noJmpCond != nullptr) {
					Optimization::Optimize(decBlock->m_noJmpCond);
				}
			}
		}
	};
};