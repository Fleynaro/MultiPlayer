#pragma once
#include "ExprOptimization.h"
#include "../DecCodeGraph.h"

namespace CE::Decompiler::Optimization
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

		block->setNoJumpCondition(new CompositeCondition(block->m_noJmpCond, removedBlockNoJmpCond, CompositeCondition::And));
		block->m_nextNearBlock = targetBlock;
		removedBlock->m_blocksReferencedTo.remove(block);
		return removedBlock;
	}

	static void OptimizeExprInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		//optimize expressions
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto line : decBlock->getSeqLines()) {
				Node::UpdateDebugInfo(line->m_destAddr);
				Node::UpdateDebugInfo(line->m_srcValue);
				Optimization::Optimize(line->m_destAddr);
				Optimization::Optimize(line->m_srcValue);
			}
			for (auto line : decBlock->getSymbolAssignmentLines()) {
				Node::UpdateDebugInfo(line->m_srcValue);
				Optimization::Optimize(line->m_srcValue);
			}
			if (decBlock->m_noJmpCond != nullptr) {
				Node::UpdateDebugInfo(decBlock->m_noJmpCond);
				Optimization::Optimize(decBlock->m_noJmpCond);
			}
			if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
				if (endBlock->m_returnNode != nullptr) {
					Node::UpdateDebugInfo(endBlock->m_returnNode);
					Optimization::Optimize(endBlock->m_returnNode);
				}
			}
		}
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

		OptimizeExprInDecompiledGraph(decGraph);

		//MemorySymbolization memorySymbolization(decGraph);
		//memorySymbolization.start();
		//optimize expressions again after memory symbolization
		//OptimizeExprInDecompiledGraph(decGraph);
	}
};