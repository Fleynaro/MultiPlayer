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
		//case 1: function call
		if (dynamic_cast<FunctionCallContext*>(line1->m_srcValue) || dynamic_cast<FunctionCallContext*>(line2->m_srcValue)) {
			return true;
		}
		
		//case 2: read-write or write-read
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

		//case 3: write-write
		auto writeValueNode1 = dynamic_cast<ReadValueNode*>(line1->m_destAddr);
		auto writeValueNode2 = dynamic_cast<ReadValueNode*>(line2->m_destAddr);
		if (!writeValueNode1 || !writeValueNode2) {
			return false;
		}
		return IsMemLocIntersected(writeValueNode1, writeValueNode2);
	}

	static bool DoesLineHavePathToOtherLine(std::list<SeqLine*>::iterator lineIt, std::list<SeqLine*>& lines, std::list<SeqLine*>& pushedOutLines, bool isTop = true) {
		if (!isTop && lineIt == prev(lines.end()))
			return false;
		while (lineIt != (isTop ? prev(prev(lines.end())) : prev(lines.end()))) {
			auto curLineIt = lineIt;
			auto nextLineIt = std::next(lineIt);

			bool areSeqLinesInterconnected = AreSeqLinesInterconnected(*curLineIt, *nextLineIt);
			if (areSeqLinesInterconnected) {
				if (DoesLineHavePathToOtherLine(nextLineIt, lines, pushedOutLines, false)) {
					continue;
				}
				else {
					return false;
				}
			}

			//move wall further
			std::iter_swap(curLineIt, nextLineIt);
			lineIt++;
		}
		if (!isTop) {
			pushedOutLines.push_back(*std::prev(lines.end()));
			lines.pop_back();
		}
		return true;
	}

	static bool DoesLineHavePathToOtherLine(SeqLine* firstSeqLine, std::list<SeqLine*>::iterator lineIt1, std::list<SeqLine*>::iterator lineIt2, std::list<SeqLine*>& pushedOutLines) {
		std::list<SeqLine*> lines;
		lines.push_back(firstSeqLine);
		for (auto it = lineIt1; it != std::next(lineIt2); it++) {
			Node::UpdateDebugInfo((*it)->m_destAddr);
			Node::UpdateDebugInfo((*it)->m_srcValue);
			lines.push_back(*it);
		}

		auto result = DoesLineHavePathToOtherLine(lines.begin(), lines, pushedOutLines);
		return result;
	}

	static void GetConstantParentsOfNode(Node* node, std::list<IParentNode*>& parentNodes) {
		for (auto it : node->getParentNodes()) {
			if (auto parentNode = dynamic_cast<Node*>(it)) {
				GetConstantParentsOfNode(parentNode, parentNodes);
			}
			if (dynamic_cast<SeqLine*>(it) || dynamic_cast<SymbolAssignmentLine*>(it) || dynamic_cast<Block*>(it)) {
				parentNodes.push_back(it);
			}
		}
	}

	static void OptimizeSeqLinesOrderInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it1 = decBlock->getSeqLines().begin(); it1 != decBlock->getSeqLines().end(); it1 ++) {
				if (auto memSymbolLeaf = dynamic_cast<SymbolLeaf*>((*it1)->m_destAddr)) {
					if (auto memVariable = dynamic_cast<Symbol::MemoryVariable*>(memSymbolLeaf->m_symbol))
					{
						std::list<IParentNode*> parentNodes;
						std::list<SeqLine*> seqLinesWithMemVar;
						GetConstantParentsOfNode(memSymbolLeaf, parentNodes);
						for (auto parentNode : parentNodes) {
							if (auto seqLineWithMemVar = dynamic_cast<SeqLine*>(parentNode)) {
								if (seqLineWithMemVar->m_block == decBlock && seqLineWithMemVar != *it1) {
									seqLinesWithMemVar.push_back(seqLineWithMemVar);
								}
							}
						}

						//mem var must be in seq lines only of the same block
						if (seqLinesWithMemVar.size() == parentNodes.size() - 1)
						{
							//store pushed out of the bound wall lines that are in conflict with *it1
							std::list<std::pair<std::list<SeqLine*>::iterator, std::list<SeqLine*>>> pushedOutlines;

							bool isRemove = true;
							auto curNextSeqLineIt = std::next(it1);
							for (auto it2 = std::next(it1); it2 != decBlock->getSeqLines().end() && !seqLinesWithMemVar.empty(); it2++) {
								bool isSuit = false;
								for (auto seqLineIt = seqLinesWithMemVar.begin(); seqLineIt != seqLinesWithMemVar.end(); seqLineIt++) {
									if (*it2 == *seqLineIt) {
										isSuit = true;
										seqLinesWithMemVar.erase(seqLineIt);
										break;
									}
								}

								if (isSuit) {
									std::list<SeqLine*> pushedOutLines_;
									if (!DoesLineHavePathToOtherLine(*it1, curNextSeqLineIt, it2, pushedOutLines_)) {
										isRemove = false;
										break;
									}
									if (!pushedOutLines_.empty()) {
										pushedOutlines.push_back(std::pair(it2, pushedOutLines_));
									}
									curNextSeqLineIt = std::next(it2);
								}
							}

							if (isRemove) {
								for (auto it : pushedOutlines) {
									auto boundLineIt = it.first;
									for (auto pushedOutline : it.second) {
										decBlock->getSeqLines().remove(pushedOutline);
										boundLineIt = decBlock->getSeqLines().insert(std::next(boundLineIt), pushedOutline);
									}
								}

								memSymbolLeaf->replaceWith((*it1)->m_srcValue);
								decBlock->getSeqLines().erase(it1);
								delete* it1;
							}
						}
					}
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
		OptimizeSeqLinesOrderInDecompiledGraph(decGraph);

		//MemorySymbolization memorySymbolization(decGraph);
		//memorySymbolization.start();
		//optimize expressions again after memory symbolization
		//OptimizeExprInDecompiledGraph(decGraph);
	}
};