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
	private:
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
	};

	namespace Optimization
	{
		using namespace PrimaryTree;

		static void OptimizeConditionDecBlock(Block* block) {
			if (!block->isCondition())
				return;
			if (block->m_nextNearBlock->m_level > block->m_nextFarBlock->m_level) {
				std::swap(block->m_nextNearBlock, block->m_nextFarBlock);
				block->m_noJmpCond->inverse();
			}
		}

		static Block* JoinCondition(Block* block) {
			if (!block->isCondition())
				return nullptr;

			auto removedBlock = block->m_nextNearBlock;
			auto mutualBlock = block->m_nextFarBlock;
			if (!removedBlock->hasNoCode() || !removedBlock->isCondition() || removedBlock->m_blocksReferencedTo.size() != 1)
				return nullptr;

			Block* targetBlock = nullptr;
			if (removedBlock->m_nextNearBlock == mutualBlock)
				targetBlock = removedBlock->m_nextFarBlock;
			else if (removedBlock->m_nextFarBlock == mutualBlock)
				targetBlock = removedBlock->m_nextNearBlock;
			if (!targetBlock)
				return nullptr;

			block->setJumpCondition(new ExprTree::CompositeCondition(block->m_noJmpCond, removedBlock->m_noJmpCond, ExprTree::CompositeCondition::And));
			block->m_nextNearBlock = targetBlock;
			removedBlock->m_blocksReferencedTo.remove(block);
			OptimizeConditionDecBlock(block);
			return removedBlock;
		}

		static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph) {
			for (const auto decBlock : decGraph->getDecompiledBlocks()) {
				OptimizeConditionDecBlock(decBlock);
			}

			for (auto it = decGraph->getDecompiledBlocks().rbegin(); it != decGraph->getDecompiledBlocks().rend(); it++) {
				while (auto removedBlock = JoinCondition(*it)) {
					return;
				}
			}

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