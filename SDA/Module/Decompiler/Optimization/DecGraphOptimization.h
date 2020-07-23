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
				Node::UpdateDebugInfo(decBlock->m_noJmpCond);
				Optimization::OptimizeCondition(decBlock->m_noJmpCond);
			}
			if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
				if (endBlock->m_returnNode != nullptr) {
					Node::UpdateDebugInfo(endBlock->m_returnNode);
					Optimization::Optimize(endBlock->m_returnNode);
				}
			}
		}
	}

	static bool IsMemLocIntersected(ReadValueNode* memValueNode1, ReadValueNode* memValueNode2) {
		std::map<ObjectHash::Hash, int64_t> terms1;
		std::map<ObjectHash::Hash, int64_t> terms2;
		int64_t constTerm1 = 0;
		int64_t constTerm2 = 0;
		GetTermsInExpr(memValueNode1->getAddress(), terms1, constTerm1);
		GetTermsInExpr(memValueNode2->getAddress(), terms2, constTerm2);
		if (!AreTermsEqual(terms1, terms2))
			return true;
		auto delta = constTerm2 - constTerm1;
		return !(delta >= memValueNode1->getSize() || -delta >= memValueNode2->getSize());
	}

	static void GetReadValueNodes(OperationalNode* expr, std::list<ReadValueNode*>& readValueNodes) {
		auto list = GetNextOperationalsNodesToOpimize(expr);
		for (auto it : list) {
			GetReadValueNodes(it, readValueNodes);
		}
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(expr)) {
			readValueNodes.push_back(readValueNode);
		}
	}

	static void GetReadValueNodes(PrimaryTree::SeqLine* line, std::list<ReadValueNode*>& readValueNodes) {
		auto destAddr = line->m_destAddr;
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(line->m_destAddr)) {
			destAddr = readValueNode->getAddress();
		}
		auto list1 = GetNextOperationalsNodesToOpimize(destAddr);
		auto list2 = GetNextOperationalsNodesToOpimize(line->m_srcValue);
		list1.insert(list1.end(), list2.begin(), list2.end());
		for (auto it : list1) {
			GetReadValueNodes(it, readValueNodes);
		}
	}

	static bool AreSeqLinesInterconnected(PrimaryTree::SeqLine* line1, PrimaryTree::SeqLine* line2) {
		for (auto linePair : { std::pair(line1, line2), std::pair(line2, line1) }) {
			if (auto writeValueNode = dynamic_cast<ReadValueNode*>(linePair.first->m_destAddr)) {
				std::list<ReadValueNode*> readValueNodes;
				GetReadValueNodes(linePair.second, readValueNodes);

				for (auto readValueNode : readValueNodes) {
					if (IsMemLocIntersected(readValueNode, writeValueNode)) {
						return true;
					}
				}
			}
		}

		auto writeValueNode1 = dynamic_cast<ReadValueNode*>(line1->m_destAddr);
		auto writeValueNode2 = dynamic_cast<ReadValueNode*>(line2->m_destAddr);
		if (!writeValueNode1 || !writeValueNode2) {
			return false;
		}

		return IsMemLocIntersected(writeValueNode1, writeValueNode2);
	}

	static bool DoesLineHavePathToOtherLine(std::list<SeqLine*>::iterator lineIt, std::list<SeqLine*>& lines, bool isTop = true) {
		if (!isTop && lineIt == prev(lines.end()))
			return false;
		while (lineIt != (isTop ? prev(prev(lines.end())) : prev(lines.end()))) {
			auto curLineIt = lineIt;
			auto nextLineIt = ++lineIt;

			if (AreSeqLinesInterconnected(*curLineIt, *nextLineIt) && !DoesLineHavePathToOtherLine(nextLineIt, lines, false))
				return false;
			std::iter_swap(curLineIt, nextLineIt);
		}
		if (!isTop) {
			lines.pop_back();
		}
		return true;
	}

	static bool DoesLineHavePathToOtherLine(std::list<SeqLine*>::iterator lineIt1, std::list<SeqLine*>::iterator lineIt2) {
		std::list<SeqLine*> lines;
		for (auto it = lineIt1; it != std::next(lineIt2); it++) {
			Node::UpdateDebugInfo((*it)->m_destAddr);
			Node::UpdateDebugInfo((*it)->m_srcValue);
			lines.push_back(*it);
		}

		auto result = DoesLineHavePathToOtherLine(lines.begin(), lines);
		return result;
	}

	static void OptimizeSeqLinesOrderInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		auto firstBlock = *decGraph->getDecompiledBlocks().begin();
		auto lineIt1 = firstBlock->getSeqLines().begin();
		auto lineIt2 = std::next(std::next(std::next(std::next(lineIt1))));

		if (auto destAddr = dynamic_cast<ReadValueNode*>((*lineIt1)->m_destAddr)) {
			if (auto opNode = dynamic_cast<OperationalNode*>(destAddr->m_leftNode)) {
				if (auto num = dynamic_cast<NumberLeaf*>(opNode->m_rightNode)) {
					num->m_value -= 148;
				}
			}
		}

		auto result = DoesLineHavePathToOtherLine(lineIt1, lineIt2);
		result = result;
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
		OptimizeSeqLinesOrderInDecompiledGraph(decGraph);

		//MemorySymbolization memorySymbolization(decGraph);
		//memorySymbolization.start();
		//optimize expressions again after memory symbolization
		//OptimizeExprInDecompiledGraph(decGraph);
	}
};