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

	static void CloneExprInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		//optimize expressions
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto line : decBlock->getSeqLines()) {
				for (auto exprPtr : { &line->m_destAddr, &line->m_srcValue }) {
					auto newExpr = (*exprPtr)->clone();
					newExpr->addParentNode(line);
					(*exprPtr)->removeBy(line);
					*exprPtr = newExpr;
				}
			}
			for (auto line : decBlock->getSymbolAssignmentLines()) {
				auto newExpr = line->m_srcValue->clone();
				newExpr->addParentNode(line);
				line->m_srcValue->removeBy(line);
				line->m_srcValue = newExpr;
			}
			if (decBlock->m_noJmpCond != nullptr) {
				auto newCond = dynamic_cast<ICondition*>(decBlock->m_noJmpCond->clone());
				newCond->addParentNode(decBlock);
				decBlock->m_noJmpCond->removeBy(decBlock);
				decBlock->m_noJmpCond = newCond;
			}
			if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
				if (endBlock->m_returnNode != nullptr) {
					auto newExpr = endBlock->m_returnNode->clone();
					newExpr->addParentNode(endBlock);
					endBlock->m_returnNode->removeBy(endBlock);
					endBlock->m_returnNode = newExpr;
				}
			}
		}
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
				Optimization::Optimize((Node*&)decBlock->m_noJmpCond);
				Node::UpdateDebugInfo(decBlock->m_noJmpCond);
				Optimization::OptimizeConstCondition(decBlock->m_noJmpCond);
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
		TermsDict terms1;
		TermsDict terms2;
		int64_t constTerm1 = 0;
		int64_t constTerm2 = 0;
		GetTermsInExpr(memValueNode1->getAddress(), terms1, constTerm1);
		GetTermsInExpr(memValueNode2->getAddress(), terms2, constTerm2);
		if (!AreTermsEqual(terms1, terms2))
			return true;
		auto delta = constTerm2 - constTerm1;
		return !(delta >= memValueNode1->getSize() || -delta >= memValueNode2->getSize());
	}


	static void GetReadValueNodes(Node* node, std::list<ReadValueNode*>& readValueNodes) {
		IterateChildNodes(node, [&](Node* childNode) {
			GetReadValueNodes(childNode, readValueNodes);
			});
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(node)) {
			readValueNodes.push_back(readValueNode);
		}
	}

	static void GetReadValueNodes(PrimaryTree::SeqLine* line, std::list<ReadValueNode*>& readValueNodes) {
		auto destAddr = line->m_destAddr;
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(line->m_destAddr)) {
			destAddr = readValueNode->getAddress();
		}
		GetReadValueNodes(destAddr, readValueNodes);
		GetReadValueNodes(line->m_srcValue, readValueNodes);
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

	static void GetConstantParentsOfNode(Node* node, std::list<INodeAgregator*>& parentNodes) {
		for (auto it : node->getParentNodes()) {
			if (auto parentNode = dynamic_cast<Node*>(it)) {
				GetConstantParentsOfNode(parentNode, parentNodes);
			}
			if (dynamic_cast<SeqLine*>(it) || dynamic_cast<Block*>(it)) {
				parentNodes.push_back(it);
			}
		}
	}

	static void RemoveSeqLinesWithNotUsedMemVarDecompiledGraph(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it = decBlock->getSeqLines().begin(); it != decBlock->getSeqLines().end(); it++) {
				if (auto memSymbolLeaf = dynamic_cast<SymbolLeaf*>((*it)->m_destAddr)) {
					if (auto memVariable = dynamic_cast<Symbol::MemoryVariable*>(memSymbolLeaf->m_symbol))
					{
						std::list<INodeAgregator*> parentNodes;
						for (auto symbolLeaf : memVariable->m_symbolLeafs) {
							GetConstantParentsOfNode(symbolLeaf, parentNodes);
						}

						//mem var must be in seq lines only of the same block
						if (parentNodes.size() == 1)
						{
							decBlock->getSeqLines().erase(it);
							delete* it;
						}
					}
				}
			}
		}
	}

	static void OptimizeSeqLinesOrderInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it1 = decBlock->getSeqLines().begin(); it1 != decBlock->getSeqLines().end(); it1 ++) {
				if (auto memSymbolLeaf = dynamic_cast<SymbolLeaf*>((*it1)->m_destAddr)) {
					if (auto memVariable = dynamic_cast<Symbol::MemoryVariable*>(memSymbolLeaf->m_symbol))
					{
						std::list<INodeAgregator*> parentNodes;
						std::list<SeqLine*> seqLinesWithMemVar;
						for (auto symbolLeaf : memVariable->m_symbolLeafs) {
							if (symbolLeaf == memSymbolLeaf)
								continue;
							GetConstantParentsOfNode(symbolLeaf, parentNodes);
						}
						
						for (auto parentNode : parentNodes) {
							if (auto seqLineWithMemVar = dynamic_cast<SeqLine*>(parentNode)) {
								if (seqLineWithMemVar->m_block == decBlock && seqLineWithMemVar != *it1) {
									seqLinesWithMemVar.push_back(seqLineWithMemVar);
								}
							}
						}

						//mem var must be in seq lines only of the same block
						if (seqLinesWithMemVar.size() == parentNodes.size())
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

								for (auto symbolLeaf : memVariable->m_symbolLeafs) {
									if (symbolLeaf == memSymbolLeaf)
										continue;
									symbolLeaf->replaceWith((*it1)->m_srcValue);
								}
								decBlock->getSeqLines().erase(it1);
								delete* it1;
							}
						}
					}
				}
			}
		}
	}

	static bool HasUndefinedRegister(Node* node, ExprTree::FunctionCallInfo& funcCallInfo) {
		IterateChildNodes(node, [&](Node* childNode) {
			HasUndefinedRegister(childNode, funcCallInfo);
			});

		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (auto regVar = dynamic_cast<Symbol::RegisterVariable*>(symbolLeaf->m_symbol)) {
				bool isFound = false;
				for (auto list : { funcCallInfo.m_paramRegisters, funcCallInfo.m_knownRegisters }) {
					for (auto paramReg : list) {
						if (regVar->m_register.getGenericId() == paramReg.getGenericId()) {
							isFound = true;
							break;
						}
					}
				}
				if (!isFound) {
					return true;
				}
			}
		}
		return false;
	}

	static void RemoveSeqLinesWithUndefinedRegisters(DecompiledCodeGraph* decGraph) {
		auto& funcCallInfo = decGraph->getFunctionCallInfo();
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it = decBlock->getSeqLines().begin(); it != decBlock->getSeqLines().end(); it++) {
				auto seqLine = *it;
				if (HasUndefinedRegister(seqLine->m_destAddr, funcCallInfo) || HasUndefinedRegister(seqLine->m_srcValue, funcCallInfo)) {
					decBlock->getSeqLines().erase(it);
					delete seqLine;
				}
			}
		}
	}

	static void GetSymbolLeafs(Node* node, Symbol::Symbol* symbol, std::list<ExprTree::SymbolLeaf*>& symbolLeafs) {
		IterateChildNodes(node, [&](Node* childNode) {
			GetSymbolLeafs(childNode, symbol, symbolLeafs);
			});

		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (symbolLeaf->m_symbol == symbol) {
				symbolLeafs.push_back(symbolLeaf);
			}
		}
	}

	static void ExpandSymbolAssignmentLines(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			std::list<SeqLine*> newSeqLines;
			for (auto symbolAssignmentLine : decBlock->getSymbolAssignmentLines()) {
				newSeqLines.push_back(new SeqLine(symbolAssignmentLine->m_destAddr, symbolAssignmentLine->m_srcValue, decBlock));
				delete symbolAssignmentLine;
			}
			decBlock->getSymbolAssignmentLines().clear();

			for (auto it = newSeqLines.begin(); it != newSeqLines.end(); it ++) {
				auto seqLine = *it;
				auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>(seqLine->m_destAddr);
				
				ExprTree::SymbolLeaf* tempVarSymbolLeaf = nullptr;
				for (auto it2 = std::next(it); it2 != newSeqLines.end(); it2++) {
					auto otherSeqLine = *it2;
					std::list<ExprTree::SymbolLeaf*> symbolLeafs;
					GetSymbolLeafs(otherSeqLine->m_srcValue, symbolLeaf->m_symbol, symbolLeafs);
					if (!symbolLeafs.empty()) {
						if (!tempVarSymbolLeaf) {
							tempVarSymbolLeaf = new ExprTree::SymbolLeaf(new Symbol::LocalVariable(symbolLeaf->m_symbol->getSize()));
						}
						for (auto symbolLeaf : symbolLeafs) {
							symbolLeaf->replaceWith(tempVarSymbolLeaf);
							delete symbolLeaf;
						}
					}
				}

				if (tempVarSymbolLeaf) {
					decBlock->addSeqLine(tempVarSymbolLeaf, symbolLeaf);
				}
				decBlock->getSeqLines().push_back(seqLine);
			}
		}
	}

	static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph) {
		CloneExprInDecompiledGraph(decGraph);

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
		ExpandSymbolAssignmentLines(decGraph);
		RemoveSeqLinesWithUndefinedRegisters(decGraph);
		//RemoveSeqLinesWithNotUsedMemVarDecompiledGraph(decGraph);

		//MemorySymbolization memorySymbolization(decGraph);
		//memorySymbolization.start();
		//optimize expressions again after memory symbolization
		//OptimizeExprInDecompiledGraph(decGraph);
	}
};